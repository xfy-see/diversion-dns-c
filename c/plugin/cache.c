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
    size_t key_len, response_len;
    uint8_t bytes[]; /* exact question key followed by a DNS response */
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
typedef struct { unsigned opts; bool unsafe; } key_options;
/* 缓存不解释 EDNS 选项：只接受至多一个无选项、版本为 0 且
 * extended RCODE 为 0 的 OPT；带 ECS 等选项或其他记录的查询直接绕过。 */
static int inspect_query_record(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p;
    key_options *v = arg;
    if (rr->type != 41 || rr->section != 2 || ++v->opts > 1 || rr->data_len ||
        (rr->ttl & UINT32_C(0xffff0000))) v->unsafe = true;
    return 0;
}
/* key = AD/CD/DO 位 + 原始 QNAME/QTYPE/QCLASS 字节，保留名称大小写。
 * 事务 ID 不参与 key；仅缓存标准 IN 查询，压缩问题不能直接复制成 key。
 * 返回 0 表示此问题不适合缓存，调用方应继续常规解析流程。 */
static size_t make_key(const md_packet *q, uint8_t key[KEY_SIZE]) {
    md_question question; char err[MD_ERROR_SIZE];
    if (!q || md_dns_question(q, &question, err) || question.class_ != 1 ||
        (question.flags & 0xf800) || md_read16(q->data + 6) || md_read16(q->data + 8) ||
        question.end < 17 || question.end - 12 + 1 > KEY_SIZE) return 0;
    /* Keep the key independent of header IDs: bypass compressed questions. */
    size_t pos = 12;
    while (pos < question.end) {
        uint8_t len = q->data[pos++];
        if (len > 63) return 0;
        if (!len) break;
        if (len > question.end - pos) return 0;
        pos += len;
    }
    if (pos + 4 != question.end) return 0;
    key_options opts = {0};
    if (md_dns_records(q, inspect_query_record, &opts, err) || opts.unsafe) return 0;
    key[0] = (uint8_t)(((question.flags & 0x20) ? 1 : 0) |
                       ((question.flags & 0x10) ? 2 : 0) | (question.do_bit ? 4 : 0));
    memcpy(key + 1, q->data + 12, question.end - 12);
    return question.end - 12 + 1;
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
typedef struct { md_packet *packet; uint64_t age; bool stale; } adjust_ttl;
/* OPT 的 TTL 字段承载 EDNS 标志，不能当 TTL 扣减；stale 响应的普通
 * 记录统一返回 5 秒 TTL，避免客户端继续长期保存过期答案。 */
static int subtract_ttl(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p; adjust_ttl *v = arg;
    if (rr->type != 41) md_write32(v->packet->data + rr->ttl_offset,
        v->stale ? 5 : v->age < rr->ttl ? rr->ttl - (uint32_t)v->age : 0);
    return 0;
}
/* 返回 0 未命中、1 新鲜、2 stale。持锁期间复制完整报文并更新 LRU，
 * 解锁后才在独立副本上扣 TTL、改事务 ID，不把条目指针暴露给调用方。 */
int md_cache_get(md_cache *c, const md_packet *q, md_packet *r, uint64_t now) {
    if (!c || !r) return 0;
    uint8_t key[KEY_SIZE]; size_t len = make_key(q, key);
    if (!len) return 0;
    uint64_t h = hash_key(key, len); int hit = 0; uint64_t age = 0;
    pthread_mutex_lock(&c->lock);
    cache_entry *e = find_entry(c, key, len, h);
    if (e && now >= e->retained) { remove_entry(c, e); e = NULL; }
    if (e) {
        hit = now >= e->expires ? 2 : 1;
        age = now >= e->stored ? now - e->stored : 0;
        memcpy(r->data, e->bytes + e->key_len, e->response_len); r->len = e->response_len;
        unlink_lru(c, e); push_front(c, e);
    }
    pthread_mutex_unlock(&c->lock);
    if (hit) {
        adjust_ttl adjustment = {r, age, hit == 2}; char err[MD_ERROR_SIZE];
        if (md_dns_records(r, subtract_ttl, &adjustment, err)) return 0;
        md_write16(r->data, md_read16(q->data));
    }
    return hit;
}
typedef struct { uint32_t minimum; unsigned extended_rcode; bool found, signed_; } ttl_minimum;
/* 各 section 的普通记录共同决定最小 TTL；识别 TSIG/SIG(0)，
 * 这些签名报文不能在缓存命中时改写 ID、TTL 或去除 OPT。 */
static int find_minimum_ttl(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p; ttl_minimum *v = arg;
    if (rr->type != 41) {
        if (!v->found || rr->ttl < v->minimum) v->minimum = rr->ttl;
        v->found = true;
        if (rr->type == 250 || (rr->type == 24 && rr->section == 2)) v->signed_ = true;
    } else v->extended_rcode = rr->ttl >> 24;
    return 0;
}
/* 先验证完整响应与原始问题一致，再决定保留时长；截断、签名、
 * 不支持的 RCODE 或不安全的问题不会缓存。插入失败仅放弃缓存，
 * 不影响调用方已经取得的上游响应。 */
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now) {
    if (!c || !r || r->len < 12 || (md_read16(r->data + 2) & 0x0200) ||
        !md_dns_response_matches(q, r)) return;
    uint8_t key[KEY_SIZE]; size_t len = make_key(q, key);
    if (!len) return;
    md_question rq; char err[MD_ERROR_SIZE];
    if (md_dns_question(r, &rq, err) || rq.end - 12 != len - 1 ||
        memcmp(r->data + 12, key + 1, len - 1)) return;
    ttl_minimum min = {0};
    if (md_dns_records(r, find_minimum_ttl, &min, err)) return;
    if (min.signed_) return;
    unsigned rcode = (md_read16(r->data + 2) & 15) | (min.extended_rcode << 4);
    uint32_t ttl, retention;
    /* NXDOMAIN 留存 30 秒，SERVFAIL 留存 5 秒；无答案的 NOERROR
     * 最多留存 300 秒，且不延长到 lazy_ttl。正向答案可按配置留存 stale。 */
    if (rcode == 3) ttl = retention = 30;
    else if (rcode == 2) ttl = retention = 5;
    else if (!rcode) {
        ttl = min.found ? min.minimum : 0;
        if (!md_read16(r->data + 6)) { if (ttl > 300) ttl = 300; retention = ttl; }
        else retention = c->lazy_ttl ? c->lazy_ttl : ttl;
    } else return;
    if (!ttl || !retention) return;
    /* strip_opt mutates its packet. Keep a bounded local copy without a
     * maximum-size heap allocation for every cold cache insertion. */
    md_packet copy;
    copy.len = r->len; memcpy(copy.data, r->data, r->len);
    if (md_dns_strip_opt(&copy)) return;
    cache_entry *e = malloc(sizeof(*e) + len + copy.len);
    if (!e) return;
    e->hash = hash_key(key, len); e->key_len = len; e->response_len = copy.len;
    e->stored = now; e->expires = deadline(now, ttl); e->retained = deadline(now, retention);
    memcpy(e->bytes, key, len); memcpy(e->bytes + len, copy.data, copy.len);
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
/* 只有成功取得占位的调用方才可启动刷新；达到容量或分配失败时拒绝。
 * 所有结束路径（含任务启动失败）都须调用 refresh_end 释放占位。 */
bool md_cache_refresh_begin(md_cache *c, const md_packet *q) {
    if (!c) return false;
    uint8_t key[KEY_SIZE]; size_t len = make_key(q, key);
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
void md_cache_refresh_end(md_cache *c, const md_packet *q) {
    if (!c) return;
    uint8_t key[KEY_SIZE]; size_t len = make_key(q, key);
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
