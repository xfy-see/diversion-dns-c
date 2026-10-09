/* SPDX-License-Identifier: GPL-3.0-or-later */
/* DNS 报文处理只操作 wire 格式：解析时检查边界，修改时保留问题段和压缩偏移。
 * 域名匹配使用规范化的小写文本；RR 中不参与匹配的名称允许二进制标签。 */
#include "mosdns.h"
#include <stdio.h>
#include <string.h>

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
 * visited 防循环，wire 限制展开长度，包边界限制实际读取，三者分别校验。 */
static int name(const md_packet *p, size_t start, size_t *end, char *out, char *err) {
    uint8_t visited[(MD_MAX_PACKET + 7) / 8] = {0};
    size_t at = start, wire = 1, used = 0;
    bool jumped = false;
    for (;;) {
        if (at >= p->len) return fail(err, "DNS name exceeds packet");
        if (visited[at / 8] & (uint8_t)(1u << (at % 8)))
            return fail(err, "DNS compression cycle");
        visited[at / 8] |= (uint8_t)(1u << (at % 8));
        unsigned n = p->data[at];
        if ((n & 0xc0) == 0xc0) {
            if (at + 2 > p->len) return fail(err, "short DNS compression pointer");
            size_t target = ((size_t)(n & 0x3f) << 8) | p->data[at + 1];
            if (target < 12 || target >= at) return fail(err, "invalid DNS compression target");
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
static int question(const md_packet *p, md_question *q, char *err) {
    if (!p || p->len < 12 || p->len > MD_MAX_PACKET)
        return fail(err, "short DNS header");
    if (md_read16(p->data + 4) != 1) return fail(err, "DNS requires one question");
    memset(q, 0, sizeof(*q));
    q->flags = md_read16(p->data + 2);
    if (q->flags & 0x7800) return fail(err, "unsupported DNS opcode");
    if (name(p, 12, &q->end, q->name, err)) return -1;
    if (q->end + 4 > p->len) return fail(err, "short DNS question");
    q->type = md_read16(p->data + q->end);
    q->class_ = md_read16(p->data + q->end + 2);
    q->end += 4;
    q->udp_size = 512;
    return 0;
}

/* 压缩名称可以引用记录外的旧字节，但此处名称的原始编码必须完整位于 RDATA 内。 */
static int rdata_name(const md_packet *p, size_t at, size_t limit, size_t *end, char *err) {
    if (at >= limit || name(p, at, end, NULL, err)) return -1;
    if (*end > limit) return fail(err, "DNS RDATA name exceeds record");
    return 0;
}

/* 显式支持的 RR 类型校验其内部结构；其他类型把 RDATA 当作不透明字节串。 */
static int rdata(const md_packet *p, const md_rr *rr, char *err) {
    size_t at = rr->data_offset, end = at + rr->data_len, next;
    switch (rr->type) {
    case 1: if (rr->data_len != 4) return fail(err, "invalid DNS A length"); break;
    case 28: if (rr->data_len != 16) return fail(err, "invalid DNS AAAA length"); break;
    case 2: case 5: case 12: case 39:
        if (rdata_name(p, at, end, &next, err) || next != end)
            return fail(err, "invalid DNS name record");
        break;
    case 15:
        if (rr->data_len < 3 || rdata_name(p, at + 2, end, &next, err) || next != end)
            return fail(err, "invalid DNS MX record");
        break;
    case 6:
        if (rdata_name(p, at, end, &next, err) ||
            rdata_name(p, next, end, &next, err) || next + 20 != end)
            return fail(err, "invalid DNS SOA record");
        break;
    case 33:
        if (rr->data_len < 7 || rdata_name(p, at + 6, end, &next, err) || next != end)
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
static int records(const md_packet *p, md_question *q, md_rr_fn fn, void *arg,
                   size_t *opt_start, size_t *opt_end, char *err) {
    size_t at = q->end;
    bool have_opt = false;
    for (unsigned section = 0; section < 3; section++) {
        unsigned count = md_read16(p->data + 6 + section * 2);
        for (unsigned i = 0; i < count; i++) {
            size_t start = at, owner_end;
            if (name(p, at, &owner_end, NULL, err)) return -1;
            at = owner_end;
            if (p->len - at < 10) return fail(err, "short DNS resource record");
            md_rr rr = { .type = md_read16(p->data + at),
                .class_ = md_read16(p->data + at + 2), .ttl_offset = at + 4,
                .ttl = md_read32(p->data + at + 4), .data_len = md_read16(p->data + at + 8),
                .data_offset = at + 10, .section = section };
            at += 10;
            if (rr.data_len > p->len - at) return fail(err, "short DNS resource data");
            at += rr.data_len;
            if (rdata(p, &rr, err)) return -1;
            if (rr.type == 41) {
                size_t root_end;
                char owner[256];
                if (section != 2 || have_opt || name(p, start, &root_end, owner, err) || strcmp(owner, "."))
                    return fail(err, "invalid or duplicate DNS OPT");
                have_opt = true;
                q->udp_size = rr.class_ < 512 ? 512 : rr.class_;
                q->do_bit = (rr.ttl & 0x8000u) != 0;
                if (opt_start) *opt_start = start;
                if (opt_end) *opt_end = at;
            }
            if (fn && fn(p, &rr, arg)) return fail(err, "DNS record callback failed");
        }
    }
    if (at != p->len) return fail(err, "trailing DNS packet bytes");
    return 0;
}

/* 名为 question 的公共入口仍验证后续所有记录，因此下游不能仅凭问题段绕过校验。 */
int md_dns_question(const md_packet *p, md_question *q, char *err) {
    if (!q) return fail(err, "missing DNS question output");
    if (question(p, q, err)) return -1;
    return records(p, q, NULL, NULL, NULL, NULL, err);
}
/* 两次扫描把校验与副作用分开：只有整个报文有效时才调用记录回调。 */
int md_dns_records(const md_packet *p, md_rr_fn fn, void *arg, char *err) {
    md_question q;
    if (question(p, &q, err)) return -1;
    /* Validate before callbacks so a malformed late RR has no partial effects. */
    if (records(p, &q, NULL, NULL, NULL, NULL, err)) return -1;
    return fn ? records(p, &q, fn, arg, NULL, NULL, err) : 0;
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
int md_dns_error(const md_packet *q, md_packet *r, unsigned rcode) {
    md_question parsed;
    if (!q || !r || rcode > 15) return -1;
    bool valid = question(q, &parsed, NULL) == 0;
    size_t len = valid ? parsed.end : 12;
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
/* 只删除末尾 OPT，避免移动后续记录而破坏报文内的绝对压缩指针。 */
int md_dns_strip_opt(md_packet *p) {
    md_question q;
    size_t start = 0, end = 0;
    if (question(p, &q, NULL) || records(p, &q, NULL, NULL, &start, &end, NULL)) return -1;
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
void md_dns_limit_udp(const md_packet *q, md_packet *r) {
    md_question a, b;
    size_t limit = md_dns_question(q, &a, NULL) ? 512 : a.udp_size;
    if (r->len <= limit) return;
    if (question(r, &b, NULL)) { md_dns_error(q, r, 2); return; }
    r->len = b.end;
    md_write16(r->data + 2, (uint16_t)(md_read16(r->data + 2) | 0x0200u));
    memset(r->data + 6, 0, 6);
}
