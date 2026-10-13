/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 共享 DNS 缓存由一个互斥锁保护哈希索引、LRU 链及刷新占位表。
 * 所有 now 参数都应使用同一单调时钟的秒数，避免系统时间调整改变 TTL。
 * 过期项在被访问或被容量淘汰时释放，没有后台清扫线程或独立到期队列。 */
#include "mosdns.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define KEY_SIZE 262
/* expires 是原始 TTL 的到期点，retained 是允许留存的最终截止点；
 * lazy_ttl 从 stored 起算，而不是在 expires 后再追加一段时间。 */
typedef struct cache_entry {
    struct cache_entry *hash_next, *prev, *next;
    uint64_t hash, stored, expires, retained;
    size_t key_len, response_len, ttl_count;
    /* exact question key, then a validated DNS response without OPT, then
     * ttl_count big-endian 16-bit TTL offsets (all RRs) recorded at put time,
     * so a hit adjusts TTLs without re-parsing the stored response. */
    uint8_t bytes[];
} cache_entry;
/* 刷新占位与缓存数据分离：同一问题只能有一个后台刷新任务，
 * 缓存项即使被替换或淘汰，刷新任务仍需成对调用 begin/end。 */
typedef struct refresh_entry {
    struct refresh_entry *next;
    uint64_t hash; size_t key_len;
    uint8_t key[];
} refresh_entry;
struct md_cache {
    pthread_mutex_t lock;
    size_t capacity, count, bucket_count, refresh_count;
    uint32_t lazy_ttl;
    cache_entry **buckets, *head, *tail;
    refresh_entry **refreshes;
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
/* 以下哈希和 LRU 辅助函数由持锁的调用方执行；head 最近使用，tail
 * 最久未使用。删除节点必须同时从两个索引摘除后才能释放内存。 */
static void unlink_lru(md_cache *c, cache_entry *e) {
    if (e->prev) e->prev->next = e->next; else c->head = e->next;
    if (e->next) e->next->prev = e->prev; else c->tail = e->prev;
}
static void push_front(md_cache *c, cache_entry *e) {
    e->prev = NULL; e->next = c->head;
    if (c->head) c->head->prev = e; else c->tail = e;
    c->head = e;
}
static void remove_entry(md_cache *c, cache_entry *e) {
    size_t i = e->hash & (c->bucket_count - 1);
    cache_entry **p = &c->buckets[i];
    while (*p != e) p = &(*p)->hash_next;
    *p = e->hash_next; unlink_lru(c, e); --c->count; free(e);
}
/* TTL 加法采用饱和运算，极端时间值不会因整数溢出变成过去的到期点。 */
static uint64_t deadline(uint64_t now, uint32_t ttl) {
    return now > UINT64_MAX - ttl ? UINT64_MAX : now + ttl;
}
/* 容量为条目数而非字节数；桶数向上取 2 的幂，与哈希掩码保持一致。
 * 构造阶段失败释放已分配的资源，成功后由 md_cache_free 独占销毁。 */
md_cache *md_cache_new(size_t capacity, uint32_t lazy_ttl) {
    if (!capacity) capacity = 1024;
    if (capacity > SIZE_MAX / 2) return NULL;
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
    c->capacity = capacity; c->bucket_count = buckets; c->lazy_ttl = lazy_ttl;
    return c;
}
/* 返回 0 未命中、1 新鲜、2 stale。持锁期间复制完整报文并更新 LRU；
 * TTL 按写入时记录的偏移在副本上扣减（OPT 已在写入时去除，条目内容不可变），
 * 不再整包解析。stale 响应的记录统一返回 5 秒 TTL。 */
int md_cache_get_view(md_cache *c, const md_packet *q, md_packet *r, md_dns_view *rv, uint64_t now) {
    return md_cache_get_q(c, q, NULL, r, rv, now);
}
int md_cache_get_q(md_cache *c, const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv, uint64_t now) {
    if (!c || !r) return 0;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) return 0;
    uint64_t h = hash_key(key, len); int hit = 0;
    pthread_mutex_lock(&c->lock);
    cache_entry *e = find_entry(c, key, len, h);
    if (e && now >= e->retained) { remove_entry(c, e); e = NULL; }
    if (e) {
        hit = now >= e->expires ? 2 : 1;
        uint64_t age = now >= e->stored ? now - e->stored : 0;
        memcpy(r->data, e->bytes + e->key_len, e->response_len); r->len = e->response_len;
        const uint8_t *offsets = e->bytes + e->key_len + e->response_len;
        for (size_t i = 0; i < e->ttl_count; i++) {
            uint8_t *t = r->data + md_read16(offsets + 2 * i);
            uint32_t ttl = md_dns_ttl(md_read32(t));
            md_write32(t, hit == 2 ? 5 : age < ttl ? ttl - (uint32_t)age : 0);
        }
        unlink_lru(c, e); push_front(c, e);
    }
    pthread_mutex_unlock(&c->lock);
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
    md_cache_put_q(c, q, NULL, r, rv, now);
}
void md_cache_put_q(md_cache *c, const md_packet *q, const md_dns_query *qv, const md_packet *r, const md_dns_view *rv, uint64_t now) {
    if (!c || !r || !rv || r->len < 12 || (md_read16(r->data + 2) & 0x0200)) return;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len || !md_dns_view_matches(q, &qv->q, r, rv)) return;
    if (rv->q.end - 12 != len - 1 || memcmp(r->data + 12, key + 1, len - 1)) return;
    if (rv->signed_) return;
    uint32_t minimum = 0; bool found = false; size_t ttl_count = 0;
    for (unsigned i = 0; i < rv->count; i++) {
        if (rv->rr[i].type == 41) continue;
        uint32_t ttl = md_dns_ttl(md_read32(r->data + rv->rr[i].ttl_offset));
        if (!found || ttl < minimum) minimum = ttl;
        found = true; ttl_count++;
    }
    unsigned rcode = md_dns_view_rcode(r, rv);
    uint32_t ttl, retention;
    /* NXDOMAIN 留存 30 秒，SERVFAIL 留存 5 秒；无答案的 NOERROR
     * 最多留存 300 秒，且不延长到 lazy_ttl。正向答案可按配置留存 stale。 */
    if (rcode == 3) ttl = retention = 30;
    else if (rcode == 2) ttl = retention = 5;
    else if (!rcode) {
        ttl = found ? minimum : 0;
        if (!md_read16(r->data + 6)) { if (ttl > 300) ttl = 300; retention = ttl; }
        else retention = c->lazy_ttl ? c->lazy_ttl : ttl;
    } else return;
    if (!ttl || !retention) return;
    /* 与 md_dns_strip_opt 相同：只去除末尾 OPT，非末尾 OPT 不缓存。 */
    size_t response_len = r->len;
    if (rv->has_opt) { if (rv->opt_end != r->len) return; response_len = rv->opt_start; }
    cache_entry *e = malloc(sizeof(*e) + len + response_len + 2 * ttl_count);
    if (!e) return;
    e->hash = hash_key(key, len); e->key_len = len; e->response_len = response_len; e->ttl_count = ttl_count;
    e->stored = now; e->expires = deadline(now, ttl); e->retained = deadline(now, retention);
    memcpy(e->bytes, key, len); memcpy(e->bytes + len, r->data, response_len);
    uint8_t *stored = e->bytes + len, *offsets = stored + response_len;
    if (rv->has_opt) md_write16(stored + 10, (uint16_t)(md_read16(stored + 10) - 1));
    for (unsigned i = 0, j = 0; i < rv->count; i++)
        if (rv->rr[i].type != 41) md_write16(offsets + 2 * j++, rv->rr[i].ttl_offset);
    /* 报文检查和分配放在锁外；持锁后一次性替换同 key 条目并执行
     * LRU 容量淘汰，其他读者只能看到完整的旧项或完整的新项。 */
    pthread_mutex_lock(&c->lock);
    cache_entry *old = find_entry(c, key, len, e->hash);
    if (old) remove_entry(c, old);
    while (c->count >= c->capacity) remove_entry(c, c->tail);
    size_t i = e->hash & (c->bucket_count - 1);
    e->hash_next = c->buckets[i]; c->buckets[i] = e; push_front(c, e); ++c->count;
    pthread_mutex_unlock(&c->lock);
}
/* 兼容入口：自行解析一次 r（堆上 view，避免占用小线程栈）。 */
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now) {
    if (!c || !r) return;
    md_dns_view *v = malloc(sizeof(*v));
    if (v && !md_dns_view_parse(r, v, NULL)) md_cache_put_view(c, q, r, v, now);
    free(v);
}
/* 只有成功取得占位的调用方才可启动刷新；达到容量或分配失败时拒绝。
 * 所有结束路径（含任务启动失败）都须调用 refresh_end 释放占位。 */
bool md_cache_refresh_begin(md_cache *c, const md_packet *q) { return md_cache_refresh_begin_q(c, q, NULL); }
bool md_cache_refresh_begin_q(md_cache *c, const md_packet *q, const md_dns_query *qv) {
    if (!c) return false;
    md_dns_query local; qv = query_view(q, qv, &local);
    uint8_t key[KEY_SIZE]; size_t len = qv ? make_key_q(q, qv, key) : 0;
    if (!len) return false;
    uint64_t h = hash_key(key, len); size_t i = h & (c->bucket_count - 1); bool ok = false;
    pthread_mutex_lock(&c->lock);
    for (refresh_entry *e = c->refreshes[i]; e; e = e->next)
        if (e->hash == h && e->key_len == len && !memcmp(e->key, key, len)) goto done;
    if (c->refresh_count < c->capacity) {
        refresh_entry *e = malloc(sizeof(*e) + len);
        if (e) { e->hash = h; e->key_len = len; memcpy(e->key, key, len);
            e->next = c->refreshes[i]; c->refreshes[i] = e; ++c->refresh_count; ok = true; }
    }
done:
    pthread_mutex_unlock(&c->lock); return ok;
}
/* 使用与 begin 相同的问题重建 key；不存在占位时安全返回。 */
void md_cache_refresh_end(md_cache *c, const md_packet *q) { md_cache_refresh_end_q(c, q, NULL); }
void md_cache_refresh_end_q(md_cache *c, const md_packet *q, const md_dns_query *qv) {
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
            *p = e->next; free(e); --c->refresh_count; break;
        }
        p = &e->next;
    }
    pthread_mutex_unlock(&c->lock);
}
void md_cache_free(md_cache *c) {
    if (!c) return;
    /* The owning engine must join its refresh workers before destruction. */
    cache_entry *e = c->head;
    while (e) { cache_entry *next = e->next; free(e); e = next; }
    for (size_t i = 0; i < c->bucket_count; ++i) {
        refresh_entry *r = c->refreshes[i];
        while (r) { refresh_entry *next = r->next; free(r); r = next; }
    }
    pthread_mutex_destroy(&c->lock); free(c->buckets); free(c->refreshes); free(c);
}
