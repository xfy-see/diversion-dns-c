/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 共享 DNS 缓存由一个互斥锁保护哈希索引、LRU 链及刷新占位表。
 * 所有 now 参数都应使用同一单调时钟的秒数，避免系统时间调整改变 TTL。
 * 过期项在被访问或被容量淘汰时释放，没有后台清扫线程或独立到期队列。
 * 统计计数用 relaxed 原子量，不额外持锁。 */
#include "mosdns.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 262
#define GHOST_SLOTS 4096
/* Fixed per-entry accounting overhead for cache_max_bytes, so the byte limit is
 * platform independent (struct padding differs between mipsel and x86_64). */
#define ENTRY_OVERHEAD 96
/* expires 是原始 TTL 的到期点，retained 是允许留存的最终截止点。
 * 旧 cache_lazy_ttl 从 stored 起算总留存；新 cache_stale_ttl 在 expires 之后追加。 */
typedef struct cache_entry {
    struct cache_entry *hash_next, *prev, *next;
    uint64_t hash, stored, expires, retained, tick, retry_after, generation;
    size_t key_len, response_len, ttl_count, cost;
    uint32_t hits, prefetch_left; /* prefetch_left: remaining-TTL threshold, 0 = never */
    unsigned char group, refresh_failures; bool positive, claimed;
    /* exact question key, then a validated DNS response without OPT, then
     * ttl_count big-endian 16-bit TTL offsets (all RRs) recorded at put time,
     * so a hit adjusts TTLs without re-parsing the stored response. */
    uint8_t bytes[];
} cache_entry;
/* 刷新占位与缓存数据分离：同一问题只能有一个后台刷新任务，
 * 缓存项即使被替换或淘汰，刷新任务仍需成对调用 begin/end。 */
typedef struct refresh_entry {
    struct refresh_entry *next;
    /* Pin the answer generation, so an old failed refresh cannot delay/count
     * a newer foreground answer inserted while that refresh was in flight. */
    uint64_t hash, generation; size_t key_len;
    uint8_t key[];
} refresh_entry;
struct md_cache {
    pthread_mutex_t lock;
    size_t capacity, count, bucket_count, refresh_count, group_count[2];
    uint64_t bytes[2], tick, seed, generation;
    md_cache_options o;
    cache_entry **buckets, *head[2], *tail[2];
    refresh_entry **refreshes;
    /* Ghost ring of recently removed keys: hash with the low bit replaced by
     * the removal reason (1 capacity eviction, 0 expiry). Classifies misses. */
    uint64_t ghost[GHOST_SLOTS];
    _Atomic uint64_t stats[2][MD_CS_COUNT];
};
const char *const md_cache_stat_names[MD_CS_COUNT] = {
    "fresh_hit", "stale_hit", "miss_cold", "miss_evicted", "miss_expired", "bypass",
    "refresh_ok", "refresh_fail", "refresh_kept_old", "prefetch", "evictions", "warm"
};

static uint64_t hash_key(const uint8_t *key, size_t len) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < len; ++i) h = (h ^ key[i]) * UINT64_C(1099511628211);
    return h;
}
/* key = AD/CD/DO 位 + 原始 QNAME/QTYPE/QCLASS 字节，保留名称大小写。
 * 事务 ID 不参与 key；仅缓存标准 IN 查询，压缩问题不能直接复制成 key。
 * 缓存不解释 EDNS 选项：只接受至多一个无选项、版本为 0 且 extended RCODE
 * 为 0 的 OPT（qv->cache_edns_ok，解析请求时同一遍得出）；带 ECS 等选项或
 * 其他记录的查询直接绕过。返回 0 表示此问题不适合缓存。
 * qv 是 q 的一次解析结果；这里只做 O(QNAME) 的标签检查，不再解析整包。 */
static size_t make_key_q(const md_packet *q, const md_dns_query *qv, uint8_t key[KEY_SIZE]) {
    if (!md_dns_query_ok(q, qv)) return 0;
    const md_question *qp = &qv->q;
    if (qp->class_ != 1 || (qp->flags & 0xf800) || md_read16(q->data + 6) || md_read16(q->data + 8) ||
        qp->end < 17 || qp->end - 12 + 1 > KEY_SIZE) return 0;
    /* Keep the key independent of header IDs: bypass compressed questions. */
    size_t pos = 12;
    while (pos < qp->end) {
        uint8_t len = q->data[pos++];
        if (len > 63) return 0;
        if (!len) break;
        if (len > qp->end - pos) return 0;
        pos += len;
    }
    if (pos + 4 != qp->end || !qv->cache_edns_ok) return 0;
    key[0] = (uint8_t)(((qp->flags & 0x20) ? 1 : 0) |
                       ((qp->flags & 0x10) ? 2 : 0) | (qp->do_bit ? 4 : 0));
    memcpy(key + 1, q->data + 12, qp->end - 12);
    return qp->end - 12 + 1;
}
/* 兼容入口用：qv 未解析/不匹配时自行解析一次（结果写入 *local）。 */
static const md_dns_query *query_view(const md_packet *q, const md_dns_query *qv, md_dns_query *local) {
    if (md_dns_query_ok(q, qv)) return qv;
    if (!q || md_dns_query_parse(q, local, NULL)) return NULL;
    return local;
}
static cache_entry *find_entry(md_cache *c, const uint8_t *key, size_t len, uint64_t hash) {
    for (cache_entry *e = c->buckets[hash & (c->bucket_count - 1)]; e; e = e->hash_next)
        if (e->hash == hash && e->key_len == len && !memcmp(e->bytes, key, len)) return e;
    return NULL;
}
static void stat_add(md_cache *c, unsigned group, unsigned counter) {
    if (group < 2 && counter < MD_CS_COUNT) atomic_fetch_add_explicit(&c->stats[group][counter], 1, memory_order_relaxed);
}
static void ghost_put(md_cache *c, uint64_t hash, unsigned reason) {
    c->ghost[(hash >> 1) & (GHOST_SLOTS - 1)] = (hash & ~UINT64_C(1)) | reason | UINT64_C(2);
}
static unsigned ghost_reason(const md_cache *c, uint64_t hash) {
    uint64_t g = c->ghost[(hash >> 1) & (GHOST_SLOTS - 1)];
    if (!g || ((g ^ (hash | UINT64_C(2))) & ~UINT64_C(1))) return MD_CS_COLD;
    return (g & 1) ? MD_CS_EVICTED : MD_CS_EXPIRED;
}
/* 以下哈希和 LRU 辅助函数由持锁的调用方执行；每个组一条 LRU 链，head 最近
 * 使用；tick 是全局使用序号，跨组比较 tail 即等价于一条全局 LRU。 */
static void unlink_lru(md_cache *c, cache_entry *e) {
    if (e->prev) e->prev->next = e->next; else c->head[e->group] = e->next;
    if (e->next) e->next->prev = e->prev; else c->tail[e->group] = e->prev;
}
static void push_front(md_cache *c, cache_entry *e) {
    e->prev = NULL; e->next = c->head[e->group];
    if (c->head[e->group]) c->head[e->group]->prev = e; else c->tail[e->group] = e;
    c->head[e->group] = e; e->tick = ++c->tick;
}
static void remove_entry(md_cache *c, cache_entry *e) {
    size_t i = e->hash & (c->bucket_count - 1);
    cache_entry **p = &c->buckets[i];
    while (*p != e) p = &(*p)->hash_next;
    *p = e->hash_next; unlink_lru(c, e); --c->count; --c->group_count[e->group];
    c->bytes[e->group] -= e->cost; free(e);
}
/* TTL 加法采用饱和运算，极端时间值不会因整数溢出变成过去的到期点。 */
static uint64_t deadline(uint64_t now, uint64_t ttl) {
    return now > UINT64_MAX - ttl ? UINT64_MAX : now + ttl;
}
static uint64_t next_random(md_cache *c) {
    uint64_t x = c->seed ? c->seed : UINT64_C(0x9e3779b97f4a7c15);
    x ^= x << 13; x ^= x >> 7; x ^= x << 17; return c->seed = x;
}
/* foreign 份额未超过 reserve 时，CN 一侧的淘汰不触及 foreign 条目。 */
static bool foreign_protected(const md_cache *c) {
    unsigned r = c->o.foreign_reserve_percent;
    if (!r || !c->tail[0]) return false;
    if ((uint64_t)c->group_count[1] * 100 > (uint64_t)c->capacity * r) return false;
    if (c->o.max_bytes && c->bytes[1] > c->o.max_bytes / 100 * r) return false;
    return true;
}
static cache_entry *victim(const md_cache *c) {
    cache_entry *t0 = c->tail[0], *t1 = c->tail[1];
    if (!t0) return t1;
    if (!t1 || foreign_protected(c)) return t0;
    return t0->tick <= t1->tick ? t0 : t1;
}
static void evict(md_cache *c, cache_entry *e, uint64_t now) {
    bool dead = now >= e->retained;
    ghost_put(c, e->hash, dead ? 0 : 1);
    if (!dead) stat_add(c, e->group, MD_CS_EVICTIONS);
    remove_entry(c, e);
}
/* 容量为条目数（及可选字节数）；桶数向上取 2 的幂，与哈希掩码保持一致。
 * 构造阶段失败释放已分配的资源，成功后由 md_cache_free 独占销毁。 */
md_cache *md_cache_new(size_t capacity, uint32_t lazy_ttl) {
    md_cache_options o = {0}; o.lazy_ttl = lazy_ttl;
    return md_cache_new_ex(capacity, &o);
}
md_cache *md_cache_new_ex(size_t capacity, const md_cache_options *o) {
    if (!capacity) capacity = 1024;
    if (capacity > SIZE_MAX / 2) return NULL;
    if (o && (o->foreign_reserve_percent > 90 || o->prefetch_percent > 90)) return NULL;
    size_t buckets = 16;
    while (buckets < capacity && buckets <= SIZE_MAX / 2) buckets *= 2;
    if (buckets < capacity || buckets > SIZE_MAX / sizeof(cache_entry *)) return NULL;
    md_cache *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->buckets = calloc(buckets, sizeof(*c->buckets));
    c->refreshes = calloc(buckets, sizeof(*c->refreshes));
    if (!c->buckets || !c->refreshes || pthread_mutex_init(&c->lock, NULL)) {
        free(c->buckets); free(c->refreshes); free(c); return NULL;
    }
    c->capacity = capacity; c->bucket_count = buckets;
    if (o) c->o = *o;
    if (!c->o.stale_answer_ttl) c->o.stale_answer_ttl = c->o.lazy_ttl ? 5 : 30;
    c->seed = (uint64_t)(uintptr_t)c ^ UINT64_C(0x2545f4914f6cdd1d);
    for (unsigned g = 0; g < 2; ++g) for (unsigned i = 0; i < MD_CS_COUNT; ++i) atomic_init(&c->stats[g][i], 0);
    return c;
}
/* 返回 0 未命中、1 新鲜、2 stale。持锁期间复制完整报文并更新 LRU；
 * TTL 按写入时记录的偏移在副本上扣减（OPT 已在写入时去除，条目内容不可变），
 * 不再整包解析。stale 响应的记录统一返回 stale_answer_ttl（旧 lazy 模式 5 秒，
 * cache_stale_ttl 模式默认 30 秒，RFC 8767）。 */
int md_cache_get_view(md_cache *c, const md_packet *q, md_packet *r, md_dns_view *rv, uint64_t now) {
    return md_cache_get_ex(c, q, NULL, r, rv, now, MD_CACHE_CN, 0, NULL);
}
int md_cache_get_q(md_cache *c, const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv, uint64_t now) {
    return md_cache_get_ex(c, q, qv, r, rv, now, MD_CACHE_CN, 0, NULL);
}
int md_cache_get_ex(md_cache *c, const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv,
                    uint64_t now, unsigned group, unsigned flags, md_cache_hit *info) {
    if (info) info->prefetch_due = false;
    if (!c || !r) return 0;
    if (group > 1) group = 1;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) { if (flags & MD_CACHE_COUNT) stat_add(c, group, MD_CS_BYPASS); return 0; }
    uint64_t h = hash_key(key, len); int hit = 0; unsigned reason = MD_CS_COLD; bool due = false;
    pthread_mutex_lock(&c->lock);
    cache_entry *e = find_entry(c, key, len, h);
    if (e && now >= e->retained) { ghost_put(c, e->hash, 0); remove_entry(c, e); e = NULL; reason = MD_CS_EXPIRED; }
    else if (!e) reason = ghost_reason(c, h);
    if (e) {
        hit = now >= e->expires ? 2 : 1;
        uint64_t age = now >= e->stored ? now - e->stored : 0;
        memcpy(r->data, e->bytes + e->key_len, e->response_len); r->len = e->response_len;
        const uint8_t *offsets = e->bytes + e->key_len + e->response_len;
        for (size_t i = 0; i < e->ttl_count; i++) {
            uint8_t *t = r->data + md_read16(offsets + 2 * i);
            uint32_t ttl = md_dns_ttl(md_read32(t));
            md_write32(t, hit == 2 ? c->o.stale_answer_ttl : age < ttl ? ttl - (uint32_t)age : 0);
        }
        if ((flags & MD_CACHE_COUNT) && e->hits < UINT32_MAX) e->hits++;
        /* Prefetch only for reused entries (>=2 hits) and once per stored answer. */
        if (hit == 1 && e->prefetch_left && !e->claimed && now >= e->retry_after &&
            e->hits >= 2 && e->expires - now <= e->prefetch_left) {
            due = true;
            if (flags & MD_CACHE_CLAIM) e->claimed = true;
        }
        unlink_lru(c, e); push_front(c, e);
    }
    pthread_mutex_unlock(&c->lock);
    if (flags & MD_CACHE_COUNT) stat_add(c, group, hit == 1 ? MD_CS_FRESH : hit == 2 ? MD_CS_STALE : reason);
    if (info) info->prefetch_due = due;
    if (!hit) return 0;
    if (!rv) { r->len = 0; return hit; } /* probe: hit state only, no response */
    md_write16(r->data, md_read16(q->data));
    /* 唯一一次解析：改写后的副本必须仍是合法报文（指针可能指进 TTL 字节）。 */
    if (md_dns_view_parse(r, rv, NULL)) { r->len = 0; return 0; }
    return hit;
}
int md_cache_get(md_cache *c, const md_packet *q, md_packet *r, uint64_t now) {
    md_dns_view *v = malloc(sizeof(*v));
    int hit = v ? md_cache_get_view(c, q, r, v, now) : 0;
    free(v); return hit;
}
/* 先验证完整响应与原始问题一致，再决定保留时长；截断、签名（TSIG/SIG(0)）、
 * 不支持的 RCODE 或不安全的问题不会缓存。插入失败仅放弃缓存，
 * 不影响调用方已经取得的上游响应。rv 必须是 r 当前内容的 view。 */
void md_cache_put_view(md_cache *c, const md_packet *q, const md_packet *r, const md_dns_view *rv, uint64_t now) {
    (void)md_cache_put_ex(c, q, NULL, r, rv, now, NULL);
}
void md_cache_put_q(md_cache *c, const md_packet *q, const md_dns_query *qv, const md_packet *r, const md_dns_view *rv, uint64_t now) {
    (void)md_cache_put_ex(c, q, qv, r, rv, now, NULL);
}
/* A validated, matching NOERROR/NXDOMAIN answer supersedes the old answer even
 * when it cannot be stored. Never use this path for a malformed/truncated or
 * transient-error response: those do not establish that the old data changed. */
static void revoke_answer(md_cache *c, const uint8_t *key, size_t len, uint64_t hash) {
    pthread_mutex_lock(&c->lock);
    cache_entry *old = find_entry(c, key, len, hash);
    if (old) { ghost_put(c, hash, 0); remove_entry(c, old); }
    pthread_mutex_unlock(&c->lock);
}
bool md_cache_put_ex(md_cache *c, const md_packet *q, const md_dns_query *qv, const md_packet *r,
                     const md_dns_view *rv, uint64_t now, const md_cache_put_opts *po) {
    if (!c || !r || !rv || r->len < 12 || (md_read16(r->data + 2) & 0x0200)) return false;
    unsigned group = po && po->group ? 1 : 0; bool refresh = po && po->refresh;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len || !md_dns_view_matches(q, &qv->q, r, rv)) return false;
    if (rv->q.end - 12 != len - 1 || memcmp(r->data + 12, key + 1, len - 1)) return false;
    if (rv->signed_) return false;
    uint32_t minimum = 0; bool found = false; size_t ttl_count = 0;
    for (unsigned i = 0; i < rv->count; i++) {
        if (rv->rr[i].type == 41) continue;
        uint32_t ttl = md_dns_ttl(md_read32(r->data + rv->rr[i].ttl_offset));
        if (!found || ttl < minimum) minimum = ttl;
        found = true; ttl_count++;
    }
    unsigned rcode = md_dns_view_rcode(r, rv);
    uint32_t ttl; uint64_t retention; bool positive = false;
    /* NXDOMAIN 留存 30 秒，SERVFAIL 留存 5 秒；无答案的 NOERROR
     * 最多留存 300 秒，且不延长 stale。正向答案可按配置留存 stale：
     * 旧 lazy_ttl 是自写入起的总留存；stale_ttl 是 TTL 到期后追加的秒数。 */
    if (rcode == 3) ttl = 30, retention = 30;
    else if (rcode == 2) ttl = 5, retention = 5;
    else if (!rcode) {
        ttl = found ? minimum : 0;
        if (!md_read16(r->data + 6)) { if (ttl > 300) ttl = 300; retention = ttl; }
        else {
            positive = true;
            int64_t stale = po && po->stale_ttl >= 0 ? po->stale_ttl : (int64_t)c->o.stale_ttl[group];
            if (c->o.lazy_ttl) retention = c->o.lazy_ttl;
            else retention = (uint64_t)ttl + (uint64_t)(stale > 0 ? stale : 0);
        }
    } else return false;
    uint64_t hash = hash_key(key, len);
    if (!ttl || !retention) goto not_stored;
    /* 与 md_dns_strip_opt 相同：只去除末尾 OPT，非末尾 OPT 不缓存。 */
    size_t response_len = r->len;
    if (rv->has_opt) { if (rv->opt_end != r->len) goto not_stored; response_len = rv->opt_start; }
    size_t cost = ENTRY_OVERHEAD + len + response_len + 2 * ttl_count;
    if (c->o.max_bytes && cost > c->o.max_bytes) goto not_stored;
    cache_entry *e = malloc(sizeof(*e) + len + response_len + 2 * ttl_count);
    if (!e) goto not_stored;
    e->hash = hash; e->key_len = len; e->response_len = response_len; e->ttl_count = ttl_count;
    e->stored = now; e->expires = deadline(now, ttl); e->retained = deadline(now, retention);
    e->cost = cost; e->hits = 0; e->claimed = false; e->group = (unsigned char)group; e->positive = positive;
    e->prefetch_left = 0; e->retry_after = 0; e->refresh_failures = 0;
    memcpy(e->bytes, key, len); memcpy(e->bytes + len, r->data, response_len);
    uint8_t *stored = e->bytes + len, *offsets = stored + response_len;
    if (rv->has_opt) md_write16(stored + 10, (uint16_t)(md_read16(stored + 10) - 1));
    for (unsigned i = 0, j = 0; i < rv->count; i++)
        if (rv->rr[i].type != 41) md_write16(offsets + 2 * j++, rv->rr[i].ttl_offset);
    /* 报文检查和分配放在锁外；持锁后一次性替换同 key 条目并执行
     * LRU 容量淘汰，其他读者只能看到完整的旧项或完整的新项。 */
    pthread_mutex_lock(&c->lock);
    cache_entry *old = find_entry(c, key, len, e->hash);
    /* 后台刷新得到 SERVFAIL 时，硬截止前保留仍有效的正向旧答案；
     * NXDOMAIN、NODATA 与地址变化是合法新答案，正常替换。 */
    if (refresh && old && old->positive && rcode == 2 && now < old->retained) {
        pthread_mutex_unlock(&c->lock); free(e); return false;
    }
    if (positive && c->o.prefetch_percent && ttl >= 2) {
        /* threshold = TTL * percent, jittered by 0.75..1.25, at least 1 s, below TTL. */
        uint64_t base = (uint64_t)ttl * c->o.prefetch_percent;
        uint64_t jitter = 75 + next_random(c) % 51;
        uint64_t left = base * jitter / 10000;
        if (!left) left = 1;
        if (left >= ttl) left = ttl - 1;
        e->prefetch_left = (uint32_t)left;
    }
    if (old) remove_entry(c, old);
    while (c->count && (c->count >= c->capacity ||
           (c->o.max_bytes && c->bytes[0] + c->bytes[1] + cost > c->o.max_bytes))) {
        cache_entry *v = victim(c);
        if (!v) break;
        evict(c, v, now);
    }
    size_t i = e->hash & (c->bucket_count - 1);
    e->generation = ++c->generation;
    e->hash_next = c->buckets[i]; c->buckets[i] = e; push_front(c, e);
    ++c->count; ++c->group_count[group]; c->bytes[group] += cost;
    pthread_mutex_unlock(&c->lock);
    return true;
not_stored:
    if (rcode == 0 || rcode == 3) revoke_answer(c, key, len, hash);
    return false;
}
/* 兼容入口：自行解析一次 r（堆上 view，避免占用小线程栈）。 */
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now) {
    if (!c || !r) return;
    md_dns_view *v = malloc(sizeof(*v));
    if (v && !md_dns_view_parse(r, v, NULL)) md_cache_put_view(c, q, r, v, now);
    free(v);
}
void md_cache_count(md_cache *c, unsigned group, unsigned counter) {
    if (c) stat_add(c, group > 1 ? 1 : group, counter);
}
void md_cache_get_stats(md_cache *c, md_cache_stats *s) {
    if (!s) return;
    memset(s, 0, sizeof(*s));
    if (!c) return;
    for (unsigned g = 0; g < 2; ++g)
        for (unsigned i = 0; i < MD_CS_COUNT; ++i) s->v[g][i] = atomic_load_explicit(&c->stats[g][i], memory_order_relaxed);
    pthread_mutex_lock(&c->lock);
    for (unsigned g = 0; g < 2; ++g) { s->entries[g] = c->group_count[g]; s->bytes[g] = c->bytes[g]; }
    pthread_mutex_unlock(&c->lock);
}
/* 名称只允许 LDH、下划线和星号，其他字节（含点和空白）不导出，
 * 保证预热文件是安全的一行一项文本。 */
static bool key_name(const uint8_t *key, size_t len, char *out, size_t out_size, uint16_t *type) {
    size_t pos = 1, used = 0;
    while (pos < len) {
        uint8_t n = key[pos++];
        if (!n) break;
        if (n > 63 || pos + n > len) return false;
        if (used && used + 1 < out_size) out[used++] = '.';
        for (uint8_t i = 0; i < n; ++i) {
            unsigned char ch = key[pos + i];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '*')) return false;
            if (used + 1 >= out_size) return false;
            out[used++] = (char)ch;
        }
        pos += n;
    }
    if (!used || pos + 4 != len) return false;
    out[used] = 0; *type = md_read16(key + pos); return true;
}
size_t md_cache_hot_names(md_cache *c, char *out, size_t out_size, size_t max) {
    if (!c || !out || !out_size) return 0;
    out[0] = 0; size_t used = 0, lines = 0;
    pthread_mutex_lock(&c->lock);
    cache_entry *at[2] = {c->head[0], c->head[1]};
    /* Merge both group lists by recency so the newest hot names win. */
    while (lines < max && (at[0] || at[1])) {
        unsigned g = !at[0] ? 1 : !at[1] ? 0 : at[0]->tick >= at[1]->tick ? 0 : 1;
        cache_entry *e = at[g]; at[g] = e->next;
        char name[256]; uint16_t type;
        if (!e->hits || !key_name(e->bytes, e->key_len, name, sizeof(name), &type) || (type != 1 && type != 28)) continue;
        int n = snprintf(out + used, out_size - used, "%u %u %s\n", (unsigned)(e->bytes[0] & 7), (unsigned)type, name);
        if (n < 0 || (size_t)n >= out_size - used) { out[used] = 0; break; }
        used += (size_t)n; ++lines;
    }
    pthread_mutex_unlock(&c->lock);
    return lines;
}
/* 只有成功取得占位的调用方才可启动刷新；达到容量或分配失败时拒绝。
 * 所有结束路径（含任务启动失败）都须调用 refresh_end 释放占位。 */
bool md_cache_refresh_begin(md_cache *c, const md_packet *q) { return md_cache_refresh_begin_q(c, q, NULL); }
static bool refresh_begin(md_cache *c, const md_packet *q, const md_dns_query *qv, uint64_t now, bool timed) {
    if (!c) return false;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) return false;
    uint64_t h = hash_key(key, len); size_t i = h & (c->bucket_count - 1); bool ok = false;
    pthread_mutex_lock(&c->lock);
    cache_entry *cached = find_entry(c, key, len, h);
    if (timed && cached && now < cached->retained && now < cached->retry_after) goto done;
    for (refresh_entry *e = c->refreshes[i]; e; e = e->next)
        if (e->hash == h && e->key_len == len && !memcmp(e->key, key, len)) goto done;
    if (c->refresh_count < c->capacity) {
        refresh_entry *e = malloc(sizeof(*e) + len);
        if (e) { e->hash = h; e->key_len = len; e->generation = cached ? cached->generation : 0; memcpy(e->key, key, len);
            e->next = c->refreshes[i]; c->refreshes[i] = e; ++c->refresh_count; ok = true; }
    }
done:
    pthread_mutex_unlock(&c->lock); return ok;
}
bool md_cache_refresh_begin_q(md_cache *c, const md_packet *q, const md_dns_query *qv) {
    return refresh_begin(c, q, qv, 0, false);
}
bool md_cache_refresh_begin_at(md_cache *c, const md_packet *q, const md_dns_query *qv, uint64_t now) {
    return refresh_begin(c, q, qv, now, true);
}
/* 使用与 begin 相同的问题重建 key；不存在占位时安全返回。 */
void md_cache_refresh_end(md_cache *c, const md_packet *q) { md_cache_refresh_end_q(c, q, NULL); }
static void refresh_end(md_cache *c, const md_packet *q, const md_dns_query *qv, uint64_t now, bool finished, bool success) {
    if (!c) return;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) return;
    uint64_t h = hash_key(key, len); size_t i = h & (c->bucket_count - 1);
    pthread_mutex_lock(&c->lock);
    refresh_entry **p = &c->refreshes[i];
    while (*p) {
        refresh_entry *e = *p;
        if (e->hash == h && e->key_len == len && !memcmp(e->key, key, len)) {
            uint64_t generation = e->generation;
            *p = e->next; free(e); --c->refresh_count;
            cache_entry *cached = find_entry(c, key, len, h);
            if (finished && cached && cached->positive && now < cached->retained) {
                if (success) { cached->retry_after = 0; cached->refresh_failures = 0; }
                else if (cached->generation == generation) {
                    cached->claimed = false;
                    if (cached->refresh_failures < 4) ++cached->refresh_failures;
                    unsigned delay = cached->refresh_failures == 4 ? 30 : 5u << (cached->refresh_failures - 1);
                    cached->retry_after = deadline(now, delay);
                    if (cached->retry_after > cached->retained) cached->retry_after = cached->retained;
                    stat_add(c, cached->group, MD_CS_REFRESH_KEPT);
                }
            }
            break;
        }
        p = &e->next;
    }
    pthread_mutex_unlock(&c->lock);
}
void md_cache_refresh_end_q(md_cache *c, const md_packet *q, const md_dns_query *qv) {
    refresh_end(c, q, qv, 0, false, false);
}
void md_cache_refresh_finish(md_cache *c, const md_packet *q, const md_dns_query *qv, uint64_t now, bool success) {
    refresh_end(c, q, qv, now, true, success);
}
/* Admission failure is not a completed prefetch. Re-arm only if no refresh
 * owns the key; never let a rejected duplicate cancel another live worker. */
void md_cache_prefetch_cancel(md_cache *c, const md_packet *q, const md_dns_query *qv) {
    if (!c) return;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) return;
    uint64_t h = hash_key(key, len); size_t i = h & (c->bucket_count - 1);
    pthread_mutex_lock(&c->lock);
    for (refresh_entry *e = c->refreshes[i]; e; e = e->next)
        if (e->hash == h && e->key_len == len && !memcmp(e->key, key, len)) goto done;
    cache_entry *cached = find_entry(c, key, len, h);
    if (cached) cached->claimed = false;
done:
    pthread_mutex_unlock(&c->lock);
}
void md_cache_free(md_cache *c) {
    if (!c) return;
    /* The owning engine must join its refresh workers before destruction. */
    for (unsigned g = 0; g < 2; ++g) {
        cache_entry *e = c->head[g];
        while (e) { cache_entry *next = e->next; free(e); e = next; }
    }
    for (size_t i = 0; i < c->bucket_count; ++i) {
        refresh_entry *r = c->refreshes[i];
        while (r) { refresh_entry *next = r->next; free(r); r = next; }
    }
    pthread_mutex_destroy(&c->lock); free(c->buckets); free(c->refreshes); free(c);
}
