/* SPDX-License-Identifier: GPL-3.0-or-later */
/* DNS 报文处理只操作 wire 格式：解析时检查边界，修改时保留问题段和压缩偏移。
 * 域名匹配使用规范化的小写文本；RR 中不参与匹配的名称允许二进制标签。 */
#include "mosdns.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef MD_DNS_COUNT_PASSES
/* 仅测试构建：[0]/[1] 请求的问题段/整包 RR 遍历，[2]/[3] 响应的同类计数，
 * [4] view 构建次数（其内部的 [2]/[3] 也会计入），[5] name() 调用次数。 */
_Atomic unsigned long md_dns_passes[6];
#define COUNT(i) atomic_fetch_add_explicit(&md_dns_passes[i], 1, memory_order_relaxed)
#define IS_RESPONSE(p) ((p) && (p)->len >= 4 && ((p)->data[2] & 0x80))
static void __attribute__((destructor)) report_passes(void) {
    fprintf(stderr, "MD_DNS_PASSES query_question=%lu query_records=%lu response_question=%lu "
            "response_records=%lu view_builds=%lu name_calls=%lu\n",
            (unsigned long)md_dns_passes[0], (unsigned long)md_dns_passes[1], (unsigned long)md_dns_passes[2],
            (unsigned long)md_dns_passes[3], (unsigned long)md_dns_passes[4], (unsigned long)md_dns_passes[5]);
}
#else
#define COUNT(i) ((void)0)
#define IS_RESPONSE(p) 0
#endif

/* 用字节读写网络字节序，避免未对齐访问和主机端序对报文的影响。 */
uint16_t md_read16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
uint32_t md_read32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}
void md_write16(uint8_t *p, uint16_t n) { p[0] = (uint8_t)(n >> 8); p[1] = (uint8_t)n; }
void md_write32(uint8_t *p, uint32_t n) {
    p[0] = (uint8_t)(n >> 24); p[1] = (uint8_t)(n >> 16);
    p[2] = (uint8_t)(n >> 8); p[3] = (uint8_t)n;
}

static int fail(char *err, const char *s) {
    if (err) snprintf(err, MD_ERROR_SIZE, "%s", s);
    return -1;
}

/* RFC 1035 compression references a previous occurrence. Requiring backward
 * pointers also ensures that removing a terminal OPT cannot invalidate any
 * surviving name. Expanded names, pointer chains, and original bytes are all
 * bounded independently. Binary names are accepted for RRs; questions use the
 * printable, unambiguous dotted representation used by domain/cache matching. */
/* end 指向原始名称编码后的字节；遇到压缩指针后，展开位置与 end 分开推进。
 * 指针只能向后（target < at），所以纯指针链严格递减；带标签的环每圈至少
 * 增加 2 字节展开长度，会被 255 字节上限截断。hops 再给指针链一个固定上限，
 * 取代原先每次调用都清零的 8 KiB visited 位图（MIPS 上开销明显）。 */
#define MD_NAME_MAX_HOPS 255
/* 名称起点位图：每次整包解析一块，按报文长度清零（不是固定 8 KiB）。name()
 * 在名称的原始编码部分把每个标签/指针/结束字节的偏移标记为“可作名称起点”；
 * 压缩指针只能指向已标记的偏移，并且首跳必须落在当前名称起点之前。于是指向
 * 问题段 QTYPE/QCLASS、任何 RR 的 TYPE/CLASS/TTL/RDLENGTH、不透明 RDATA
 * （A/AAAA/TXT/OPT/未知类型、MX/SRV/SOA 的定长字段）或标签内部的指针全部
 * 被拒绝，整包按格式错误处理。可作目标的 RDATA 名称仅限 RFC 3597 §4 列出的
 * RFC 1035 类型（见 rdata()）。之前若允许指入 TTL，TTL 规范化会改写被引用的
 * 字节，使名称在缓存/nft 处理时变成另一个（例如根名 "."）。 */
typedef struct { uint8_t bits[(MD_MAX_PACKET + 7) / 8]; } name_marks;
static void marks_reset(name_marks *m, const md_packet *p) {
    size_t n = p && p->len <= MD_MAX_PACKET ? (p->len + 7) / 8 : sizeof(m->bits);
    memset(m->bits, 0, n);
}
#define MARK(m, o) ((m)->bits[(o) >> 3] |= (uint8_t)(1u << ((o) & 7)))
#define MARKED(m, o) (((m)->bits[(o) >> 3] >> ((o) & 7)) & 1u)
static int name(const md_packet *p, name_marks *m, bool mark, size_t start, size_t *end, char *out, char *err) {
    size_t at = start, wire = 1, used = 0;
    unsigned hops = 0;
    bool jumped = false;
    COUNT(5);
    for (;;) {
        if (at >= p->len) return fail(err, "DNS name exceeds packet");
        unsigned n = p->data[at];
        if (!jumped && mark) MARK(m, at);
        if ((n & 0xc0) == 0xc0) {
            if (at + 2 > p->len) return fail(err, "short DNS compression pointer");
            size_t target = ((size_t)(n & 0x3f) << 8) | p->data[at + 1];
            if (target < 12 || target >= (jumped ? at : start) || !MARKED(m, target))
                return fail(err, "invalid DNS compression target");
            if (++hops > MD_NAME_MAX_HOPS) return fail(err, "DNS compression cycle");
            if (!jumped) { *end = at + 2; jumped = true; }
            at = target;
            continue;
        }
        if (n & 0xc0) return fail(err, "unsupported DNS label encoding");
        if (!n) {
            if (!jumped) *end = at + 1;
            if (out) { if (!used) out[used++] = '.'; out[used] = '\0'; }
            return 0;
        }
        if (at + 1 + n > p->len || wire + n + 1 > 255)
            return fail(err, "invalid DNS label length");
        wire += n + 1;
        if (out) {
            if (used) out[used++] = '.';
            for (unsigned i = 0; i < n; i++) {
                unsigned c = p->data[at + 1 + i];
                if (c < 33 || c > 126 || c == '.' || c == '\\')
                    return fail(err, "unsupported binary question name");
                out[used++] = (char)(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c);
            }
        }
        at += n + 1;
    }
}

/* 本实现仅支持标准 QUERY 操作码和单问题报文；默认 UDP 限制为 512，OPT 扫描后再覆盖。 */
static int question(const md_packet *p, name_marks *m, md_question *q, char *err) {
    COUNT(IS_RESPONSE(p) ? 2 : 0);
    if (!p || p->len < 12 || p->len > MD_MAX_PACKET)
        return fail(err, "short DNS header");
    if (md_read16(p->data + 4) != 1) return fail(err, "DNS requires one question");
    memset(q, 0, sizeof(*q));
    q->flags = md_read16(p->data + 2);
    if (q->flags & 0x7800) return fail(err, "unsupported DNS opcode");
    if (name(p, m, true, 12, &q->end, q->name, err)) return -1;
    if (q->end + 4 > p->len) return fail(err, "short DNS question");
    q->type = md_read16(p->data + q->end);
    q->class_ = md_read16(p->data + q->end + 2);
    q->end += 4;
    q->udp_size = 512;
    return 0;
}

/* 压缩名称可以引用记录外的旧字节，但此处名称的原始编码必须完整位于 RDATA 内。 */
static int rdata_name(const md_packet *p, name_marks *m, bool mark, size_t at, size_t limit, size_t *end, char *err) {
    if (at >= limit || name(p, m, mark, at, end, NULL, err)) return -1;
    if (*end > limit) return fail(err, "DNS RDATA name exceeds record");
    return 0;
}

/* 显式支持的 RR 类型校验其内部结构；其他类型把 RDATA 当作不透明字节串。 */
static int rdata(const md_packet *p, name_marks *m, const md_rr *rr, char *err) {
    size_t at = rr->data_offset, end = at + rr->data_len, next;
    switch (rr->type) {
    case 1: if (rr->data_len != 4) return fail(err, "invalid DNS A length"); break;
    case 28: if (rr->data_len != 16) return fail(err, "invalid DNS AAAA length"); break;
    /* RFC 3597 §4: only the RFC 1035 types NS MD MF CNAME SOA MB MG MR PTR
     * MINFO MX may carry compressed names. Their RDATA names are validated and
     * marked as legal compression targets. SRV (RFC 2782: target "MUST NOT"
     * be compressed) and DNAME (RFC 6672) names are validated and, for
     * interoperability, may still contain pointers, but are NOT marked as
     * targets: an RFC 3597 compressor never points into them. RP, AFSDB, NAPTR
     * and other later types stay opaque (no parse, never targets). */
    case 2: case 3: case 4: case 5: case 7: case 8: case 9: case 12:
        if (rdata_name(p, m, true, at, end, &next, err) || next != end)
            return fail(err, "invalid DNS name record");
        break;
    case 39:
        if (rdata_name(p, m, false, at, end, &next, err) || next != end)
            return fail(err, "invalid DNS name record");
        break;
    case 15:
        if (rr->data_len < 3 || rdata_name(p, m, true, at + 2, end, &next, err) || next != end)
            return fail(err, "invalid DNS MX record");
        break;
    case 14: /* MINFO: RMAILBX, EMAILBX. */
        if (rdata_name(p, m, true, at, end, &next, err) ||
            rdata_name(p, m, true, next, end, &next, err) || next != end)
            return fail(err, "invalid DNS MINFO record");
        break;
    case 6:
        if (rdata_name(p, m, true, at, end, &next, err) ||
            rdata_name(p, m, true, next, end, &next, err) || next + 20 != end)
            return fail(err, "invalid DNS SOA record");
        break;
    case 33:
        if (rr->data_len < 7 || rdata_name(p, m, false, at + 6, end, &next, err) || next != end)
            return fail(err, "invalid DNS SRV record");
        break;
    case 16: /* One or more length-prefixed TXT strings. */
        if (at == end) return fail(err, "empty DNS TXT record");
        while (at < end) { unsigned n = p->data[at++]; if (n > end - at) return fail(err, "short DNS TXT string"); at += n; }
        break;
    case 41:
        while (at < end) {
            if (end - at < 4) return fail(err, "short EDNS option");
            unsigned n = md_read16(p->data + at + 2); at += 4;
            if (n > end - at) return fail(err, "short EDNS option data");
            at += n;
        }
        break;
    default: break; /* Unknown RR RDATA is opaque under RFC 3597. */
    }
    return 0;
}

/* 顺序扫描 answer、authority、additional，并要求计数恰好覆盖整个报文。
 * OPT 只允许一个且必须在 additional；TTL 字段在 OPT 中承载 EDNS 标志而非生存时间。 */
static int records(const md_packet *p, name_marks *m, md_question *q, md_rr_fn fn, void *arg,
                   size_t *opt_start, size_t *opt_end, md_dns_view *view, char *err) {
    size_t at = q->end;
    bool have_opt = false;
    COUNT(IS_RESPONSE(p) ? 3 : 1);
    for (unsigned section = 0; section < 3; section++) {
        unsigned count = md_read16(p->data + 6 + section * 2);
        for (unsigned i = 0; i < count; i++) {
            size_t start = at, owner_end;
            if (name(p, m, true, at, &owner_end, NULL, err)) return -1;
            at = owner_end;
            if (p->len - at < 10) return fail(err, "short DNS resource record");
            md_rr rr = { .type = md_read16(p->data + at),
                .class_ = md_read16(p->data + at + 2), .ttl_offset = at + 4,
                .ttl = md_read32(p->data + at + 4), .data_len = md_read16(p->data + at + 8),
                .data_offset = at + 10, .section = section };
            at += 10;
            if (rr.data_len > p->len - at) return fail(err, "short DNS resource data");
            at += rr.data_len;
            if (rdata(p, m, &rr, err)) return -1;
            if (rr.type == 41) {
                size_t root_end;
                char owner[256];
                if (section != 2 || have_opt || name(p, m, true, start, &root_end, owner, err) || strcmp(owner, "."))
                    return fail(err, "invalid or duplicate DNS OPT");
                have_opt = true;
                q->udp_size = rr.class_ < 512 ? 512 : rr.class_;
                q->do_bit = (rr.ttl & 0x8000u) != 0;
                if (opt_start) *opt_start = start;
                if (opt_end) *opt_end = at;
            }
            if (view) {
                if (view->count >= MD_DNS_VIEW_MAX_RR) return fail(err, "too many DNS records");
                md_dns_view_rr *d = &view->rr[view->count++];
                d->owner_offset = (uint16_t)start; d->ttl_offset = (uint16_t)rr.ttl_offset;
                d->data_offset = (uint16_t)rr.data_offset; d->type = rr.type;
                d->class_ = rr.class_; d->data_len = rr.data_len; d->section = (uint8_t)section;
                if (rr.type == 250 || (rr.type == 24 && section == 2)) view->signed_ = true;
                if (!section && rr.class_ == 1 && (rr.type == 1 || rr.type == 28)) view->addresses++;
                if (rr.type == 41) { view->has_opt = true; view->opt_start = start; view->opt_end = at; view->opt_ttl = rr.ttl; }
            }
            if (fn && fn(p, &rr, arg)) return fail(err, "DNS record callback failed");
        }
    }
    if (at != p->len) return fail(err, "trailing DNS packet bytes");
    return 0;
}

/* 名为 question 的公共入口仍验证后续所有记录，因此下游不能仅凭问题段绕过校验。 */
int md_dns_question(const md_packet *p, md_question *q, char *err) {
    name_marks m;
    if (!q) return fail(err, "missing DNS question output");
    marks_reset(&m, p);
    if (question(p, &m, q, err)) return -1;
    return records(p, &m, q, NULL, NULL, NULL, NULL, NULL, err);
}
/* 两次扫描把校验与副作用分开：只有整个报文有效时才调用记录回调。 */
int md_dns_records(const md_packet *p, md_rr_fn fn, void *arg, char *err) {
    md_question q;
    name_marks m;
    marks_reset(&m, p);
    if (question(p, &m, &q, err)) return -1;
    /* Validate before callbacks so a malformed late RR has no partial effects. */
    if (records(p, &m, &q, NULL, NULL, NULL, NULL, NULL, err)) return -1;
    return fn ? records(p, &m, &q, fn, arg, NULL, NULL, NULL, err) : 0;
}
/* 事务 ID、QR 方向和问题三元组必须一致；同时拒绝结构不完整的响应。 */
bool md_dns_response_matches(const md_packet *q, const md_packet *r) {
    md_question a, b;
    if (md_dns_question(q, &a, NULL) || md_dns_question(r, &b, NULL)) return false;
    return !(a.flags & 0x8000u) && (b.flags & 0x8000u) &&
        md_read16(q->data) == md_read16(r->data) && a.type == b.type &&
        a.class_ == b.class_ && !strcmp(a.name, b.name);
}
/* 能解析的问题会原样保留；无法解析时生成无问题的最小错误头。
 * memmove 允许请求与响应使用同一个报文对象。 */
static int error_with(const md_packet *q, md_packet *r, unsigned rcode, bool valid, size_t len) {
    if (!valid) len = 12;
    uint16_t id = q->len >= 2 ? md_read16(q->data) : 0;
    uint16_t flags = q->len >= 4 ? md_read16(q->data + 2) : 0;
    if (valid) memmove(r->data, q->data, len); else memset(r->data, 0, 12);
    r->len = len;
    md_write16(r->data, id);
    md_write16(r->data + 2, (uint16_t)(0x8080u | (flags & 0x0110u) | rcode));
    md_write16(r->data + 4, valid ? 1 : 0);
    memset(r->data + 6, 0, 6);
    return 0;
}
int md_dns_error(const md_packet *q, md_packet *r, unsigned rcode) {
    md_question parsed;
    name_marks m;
    if (!q || !r || rcode > 15) return -1;
    marks_reset(&m, q);
    bool valid = question(q, &m, &parsed, NULL) == 0;
    return error_with(q, r, rcode, valid, valid ? parsed.end : 12);
}
/* 已完整解析的请求必然有合法问题区，与 md_dns_error 的结果相同。 */
int md_dns_error_q(const md_packet *q, const md_dns_query *qv, md_packet *r, unsigned rcode) {
    if (!md_dns_query_ok(q, qv)) return md_dns_error(q, r, rcode);
    if (!r || rcode > 15) return -1;
    return error_with(q, r, rcode, true, qv->q.end);
}
/* 只删除末尾 OPT，避免移动后续记录而破坏报文内的绝对压缩指针。 */
int md_dns_strip_opt(md_packet *p) {
    md_question q;
    size_t start = 0, end = 0;
    name_marks m;
    marks_reset(&m, p);
    if (question(p, &m, &q, NULL) || records(p, &m, &q, NULL, NULL, &start, &end, NULL, NULL)) return -1;
    if (!end) return 0;
    /* Moving later RRs would alter compression offsets. Reject non-terminal OPT
     * rather than emit a corrupt packet or silently remove ordinary records. */
    if (end != p->len) return -1;
    p->len = start;
    md_write16(p->data + 10, (uint16_t)(md_read16(p->data + 10) - 1));
    return 0;
}
/* 超过客户端 EDNS 限制时保留完整问题，置 TC 并清空三个 RR 区段；
 * 不在任意字节处截断记录，客户端可据此改用 TCP 查询。 */
static void limit_udp(const md_packet *q, const md_dns_query *qv, size_t limit, md_packet *r) {
    md_question b;
    if (r->len <= limit) return;
    name_marks m;
    marks_reset(&m, r);
    if (question(r, &m, &b, NULL)) { md_dns_error_q(q, qv, r, 2); return; }
    r->len = b.end;
    md_write16(r->data + 2, (uint16_t)(md_read16(r->data + 2) | 0x0200u));
    memset(r->data + 6, 0, 6);
}
void md_dns_limit_udp(const md_packet *q, md_packet *r) {
    md_question a;
    limit_udp(q, NULL, md_dns_question(q, &a, NULL) ? 512 : a.udp_size, r);
}
void md_dns_limit_udp_q(const md_packet *q, const md_dns_query *qv, md_packet *r) {
    if (!md_dns_query_ok(q, qv)) { md_dns_limit_udp(q, r); return; }
    limit_udp(q, qv, qv->q.udp_size, r);
}
/* 请求一次解析：与 md_dns_question 相同的 question+records 校验，回调只收集
 * 缓存键的 EDNS 条件（等价于旧 cache make_key 里的第二次 md_dns_records）。 */
typedef struct { unsigned opts; bool unsafe; } query_opts;
static int query_record(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p;
    query_opts *o = arg;
    if (rr->type != 41 || rr->section != 2 || ++o->opts > 1 || rr->data_len ||
        (rr->ttl & UINT32_C(0xffff0000))) o->unsafe = true;
    return 0;
}
int md_dns_query_parse(const md_packet *p, md_dns_query *v, char *err) {
    if (!v) return fail(err, "missing DNS query output");
    v->valid = v->cache_edns_ok = false; v->len = 0; v->route = -1; v->cache_memo = -1;
    v->stats_rcode = v->stats_error = v->stats_cache = 0; v->stats_coalesced = false;
    query_opts o = {0};
    name_marks m;
    marks_reset(&m, p);
    if (question(p, &m, &v->q, err) || records(p, &m, &v->q, query_record, &o, NULL, NULL, NULL, err))
        return -1;
    v->cache_edns_ok = !o.unsafe; v->len = p->len; v->valid = true;
    return 0;
}
bool md_dns_query_ok(const md_packet *p, const md_dns_query *v) {
    return p && v && v->valid && v->len == p->len;
}

/* Validate before mutation; don't invalidate transaction signatures by silently
 * rewriting a TSIG/SIG(0) packet. DNSSEC RRSIG original-TTL data stays intact. */
typedef struct { md_packet *packet; bool changed, signed_, write; } ttl_policy;
static int normalize_ttl_record(const md_packet *p, const md_rr *rr, void *opaque) {
    (void)p;
    ttl_policy *v = opaque;
    if (rr->type == 250 || (rr->type == 24 && rr->section == 2)) v->signed_ = true;
    if (rr->type != 41 && rr->ttl != md_dns_ttl(rr->ttl)) {
        v->changed = true;
        if (v->write) md_write32(v->packet->data + rr->ttl_offset, md_dns_ttl(rr->ttl));
    }
    return 0;
}
int md_dns_normalize_ttl(md_packet *p, char *err) {
    ttl_policy v = {.packet = p};
    if (md_dns_records(p, normalize_ttl_record, &v, err)) return -1;
    if (!v.changed) return 0;
    if (v.signed_) {
        if (err) snprintf(err, MD_ERROR_SIZE, "signed DNS response exceeds TTL policy");
        return -1;
    }
    v.write = true;
    return md_dns_records(p, normalize_ttl_record, &v, err);
}

/* ---- 一次解析的响应索引（md_dns_view）----
 * view_parse 与 md_dns_question+md_dns_records 执行完全相同的校验（共用
 * question/records/name/rdata），只多记录每条 RR 的偏移；之后的匹配、
 * extended RCODE、TTL 规范化、nft 收集和缓存写入都只遍历这个数组。
 * TTL 不缓存在索引里，每次从报文的 ttl_offset 现读，原地改 TTL 或事务 ID
 * 后索引仍有效；改变长度的操作须重新解析（len 不符时 view 接口直接失败）。 */
int md_dns_view_parse(const md_packet *p, md_dns_view *v, char *err) {
    if (!v) return fail(err, "missing DNS view output");
    v->len = 0; v->valid = false; v->count = 0; v->addresses = 0;
    v->has_opt = v->signed_ = false; v->opt_start = v->opt_end = 0; v->opt_ttl = 0;
    COUNT(4);
    name_marks m;
    marks_reset(&m, p);
    if (question(p, &m, &v->q, err) || records(p, &m, &v->q, NULL, NULL, NULL, NULL, v, err)) {
        v->count = 0; return -1;
    }
    v->len = p->len; v->valid = true;
    return 0;
}
static int view_ok(const md_packet *p, const md_dns_view *v, char *err) {
    if (!p || !v || !v->valid || v->len != p->len) return fail(err, "stale or invalid DNS view");
    return 0;
}
int md_dns_view_each(const md_packet *p, const md_dns_view *v, md_rr_fn fn, void *arg, char *err) {
    if (view_ok(p, v, err)) return -1;
    for (unsigned i = 0; fn && i < v->count; i++) {
        const md_dns_view_rr *d = &v->rr[i];
        md_rr rr = { .type = d->type, .class_ = d->class_, .ttl_offset = d->ttl_offset,
            .ttl = md_read32(p->data + d->ttl_offset), .data_len = d->data_len,
            .data_offset = d->data_offset, .section = d->section };
        if (fn(p, &rr, arg)) return fail(err, "DNS record callback failed");
    }
    return 0;
}
void md_dns_view_copy(md_dns_view *dst, const md_dns_view *src) {
    memcpy(dst, src, offsetof(md_dns_view, rr));
    memcpy(dst->rr, src->rr, src->count * sizeof(src->rr[0]));
}
/* 与 md_dns_response_matches 等价：qq 为已完整校验的请求问题段（含 flags）。 */
bool md_dns_view_matches(const md_packet *q, const md_question *qq, const md_packet *r, const md_dns_view *rv) {
    if (!q || !qq || q->len < 12 || view_ok(r, rv, NULL)) return false;
    return !(qq->flags & 0x8000u) && (rv->q.flags & 0x8000u) &&
        md_read16(q->data) == md_read16(r->data) && qq->type == rv->q.type &&
        qq->class_ == rv->q.class_ && !strcmp(qq->name, rv->q.name);
}
unsigned md_dns_view_rcode(const md_packet *p, const md_dns_view *v) {
    unsigned rcode = md_read16(p->data + 2) & 15;
    if (v->has_opt) rcode |= (v->opt_ttl >> 24) << 4;
    return rcode;
}
/* 改写后重新解析一次（只在 TTL 超出策略时发生）。压缩指针已不能指进 TTL
 * 字节（见 name_marks），这次重解析只是防御性的；失败时 view 标记无效，
 * 后续 nft/缓存不会使用它。 */
int md_dns_normalize_ttl_view(md_packet *p, md_dns_view *v, char *err) {
    if (view_ok(p, v, err)) return -1;
    bool changed = false;
    for (unsigned i = 0; i < v->count && !changed; i++) {
        if (v->rr[i].type == 41) continue;
        uint32_t ttl = md_read32(p->data + v->rr[i].ttl_offset);
        changed = ttl != md_dns_ttl(ttl);
    }
    if (!changed) return 0;
    if (v->signed_) return fail(err, "signed DNS response exceeds TTL policy");
    for (unsigned i = 0; i < v->count; i++) {
        if (v->rr[i].type == 41) continue;
        uint8_t *t = p->data + v->rr[i].ttl_offset;
        md_write32(t, md_dns_ttl(md_read32(t)));
    }
    return md_dns_view_parse(p, v, err);
}
/* 每线程一块堆上 scratch view（约 83 KiB），线程退出时释放；不放在可能只有
 * 128 KiB 的栈上（musl / RLIMIT_STACK）。失败返回 NULL，调用方退回旧路径。 */
static pthread_key_t view_key;
static pthread_once_t view_once = PTHREAD_ONCE_INIT;
static bool view_key_ok;
static void view_key_init(void) { view_key_ok = pthread_key_create(&view_key, free) == 0; }
md_dns_view *md_dns_view_scratch(void) {
    pthread_once(&view_once, view_key_init);
    if (!view_key_ok) return NULL;
    md_dns_view *v = pthread_getspecific(view_key);
    if (!v && (v = malloc(sizeof(*v)))) {
        v->valid = false; v->count = 0;
        if (pthread_setspecific(view_key, v)) { free(v); return NULL; }
    }
    return v;
}
