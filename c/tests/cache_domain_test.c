/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MD_REGEX_POSIX
#define PCRE2_CODE_UNIT_WIDTH 8
#endif
/* 用人为指定的单调秒数验证 TTL，不依赖真实等待；同时覆盖域名和 nft 参数解析。 */
#include "mosdns.h"
#ifndef MD_REGEX_POSIX
#include <pcre2.h>
#endif
#include <locale.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void query(md_packet *q, const char *name, uint16_t flags, uint16_t class_) {
    memset(q, 0, sizeof(*q));
    md_write16(q->data, 0x1234); md_write16(q->data + 2, flags); md_write16(q->data + 4, 1);
    q->len = 12;
    const char *s = name;
    while (*s) {
        const char *dot = strchr(s, '.'); size_t n = dot ? (size_t)(dot - s) : strlen(s);
        assert(n && n <= 63); q->data[q->len++] = (uint8_t)n;
        memcpy(q->data + q->len, s, n); q->len += n;
        if (!dot) break;
        s = dot + 1;
    }
    q->data[q->len++] = 0;
    md_write16(q->data + q->len, 1); md_write16(q->data + q->len + 2, class_); q->len += 4;
}
static void add_a(md_packet *r, uint32_t ttl, unsigned section) {
    uint8_t rr[] = {0xc0,12,0,1,0,1,0,0,0,0,0,4,192,0,2,1};
    md_write32(rr + 6, ttl);
    memcpy(r->data + r->len, rr, sizeof(rr)); r->len += sizeof(rr);
    size_t at = 6 + section * 2; md_write16(r->data + at, (uint16_t)(md_read16(r->data + at) + 1));
}
static void add_opt(md_packet *p, bool do_bit, bool options) {
    uint8_t rr[] = {0,0,41,4,208,0,0,0,0,0,0,0,10,0,0};
    if (do_bit) rr[7] = 0x80;
    if (options) md_write16(rr + 9, 4);
    size_t len = options ? sizeof(rr) : 11;
    memcpy(p->data + p->len, rr, len); p->len += len;
    md_write16(p->data + 10, (uint16_t)(md_read16(p->data + 10) + 1));
}
typedef struct { uint32_t wanted; unsigned count; } ttl_check;
static int check_ttl(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p; ttl_check *v = arg;
    assert(rr->type != 41 && rr->ttl == v->wanted); ++v->count; return 0;
}
static void assert_ttl(md_packet *r, uint32_t ttl) {
    ttl_check v = {ttl, 0}; char err[MD_ERROR_SIZE];
    assert(!md_dns_records(r, check_ttl, &v, err)); assert(v.count);
}
static void positive(md_packet *q, md_packet *r, uint32_t ttl) {
    assert(!md_dns_error(q, r, 0)); add_a(r, ttl, 0);
}
/* 分别验证键隔离、TTL/负缓存、lazy 到期和 LRU 淘汰，不把过期命中当新鲜数据。 */
static void cache_tests(void) {
    md_packet q, other, response, hit; char err[MD_ERROR_SIZE];
    md_cache *c = md_cache_new(2, 100); assert(c);
    query(&q, "Example.test", 0x0100, 1); positive(&q, &response, 10); add_opt(&response, false, false);
    md_cache_put(c, &q, &response, 100);
    assert(md_cache_get(c, &q, &hit, 100) == 1); assert_ttl(&hit, 10); assert(!md_read16(hit.data + 10));
    md_write16(q.data, 0x4321);
    assert(md_cache_get(c, &q, &hit, 104) == 1); assert_ttl(&hit, 6); assert(md_read16(hit.data) == 0x4321);
    assert(md_cache_get(c, &q, &hit, 110) == 2); assert_ttl(&hit, 5);
    assert(md_cache_refresh_begin(c, &q)); assert(!md_cache_refresh_begin(c, &q));
    md_cache_refresh_end(c, &q); assert(md_cache_refresh_begin(c, &q)); md_cache_refresh_end(c, &q);
    assert(md_cache_get(c, &q, &hit, 199) == 2); assert(md_cache_get(c, &q, &hit, 200) == 0);

    positive(&q, &response, 20); md_cache_put(c, &q, &response, 300);
    query(&other, "example.test", 0x0100, 1); assert(!md_cache_get(c, &other, &hit, 300));
    other = q; md_write16(other.data + 2, 0x0130); assert(!md_cache_get(c, &other, &hit, 300));
    other = q; add_opt(&other, true, false); assert(!md_cache_get(c, &other, &hit, 300));
    positive(&other, &response, 20); md_cache_put(c, &other, &response, 300);
    assert(md_cache_get(c, &other, &hit, 300) == 1); assert(md_cache_get(c, &q, &hit, 300) == 1);
    md_cache_free(c);

    c = md_cache_new(8, 1000); assert(c);
    query(&q, "negative.test", 0x0100, 1); assert(!md_dns_error(&q, &response, 3));
    md_cache_put(c, &q, &response, 100);
    assert(md_cache_get(c, &q, &hit, 129) == 1 && (md_read16(hit.data + 2) & 15) == 3);
    assert(!md_cache_get(c, &q, &hit, 130));
    assert(!md_dns_error(&q, &response, 2)); md_cache_put(c, &q, &response, 200);
    assert(md_cache_get(c, &q, &hit, 204) == 1); assert(!md_cache_get(c, &q, &hit, 205));
    assert(!md_dns_error(&q, &response, 0)); add_a(&response, 500, 1); md_cache_put(c, &q, &response, 300);
    assert(md_cache_get(c, &q, &hit, 599) == 1); assert(!md_cache_get(c, &q, &hit, 600));
    positive(&q, &response, 0); md_cache_put(c, &q, &response, 700); assert(!md_cache_get(c, &q, &hit, 700));
    positive(&q, &response, 30); md_write16(response.data + 2, (uint16_t)(md_read16(response.data + 2) | 0x0200));
    md_cache_put(c, &q, &response, 700); assert(!md_cache_get(c, &q, &hit, 700));
    query(&q, "chaos.test", 0x0100, 3); positive(&q, &response, 30); md_cache_put(c, &q, &response, 700);
    assert(!md_cache_get(c, &q, &hit, 700));
    query(&q, "edns.test", 0x0100, 1); add_opt(&q, false, true);
    assert(!md_dns_question(&q, &(md_question){0}, err)); positive(&q, &response, 30); md_cache_put(c, &q, &response, 700);
    assert(!md_cache_get(c, &q, &hit, 700));
    query(&q, "extended-rcode.test", 0x0100, 1); positive(&q, &response, 30); add_opt(&response, false, false);
    response.data[response.len - 6] = 1; /* OPT extended RCODE=1, full RCODE=16. */
    md_cache_put(c, &q, &response, 700); assert(!md_cache_get(c, &q, &hit, 700));
    query(&q, "minimum.test", 0x0100, 1); positive(&q, &response, 30); add_a(&response, 10, 1);
    md_cache_put(c, &q, &response, 800); assert(md_cache_get(c, &q, &hit, 809) == 1);
    assert(md_read32(hit.data + q.len + 6) == 21); /* answer retains its larger TTL */
    assert(md_read32(hit.data + q.len + 16 + 6) == 1);
    assert(md_cache_get(c, &q, &hit, 810) == 2); assert_ttl(&hit, 5);
    md_cache_free(c);

    c = md_cache_new(4, 0); assert(c);
    query(&q, "ttl-cap.test", 0x0100, 1); positive(&q, &response, 0x7fffffff);
    md_cache_put(c, &q, &response, 100);
    assert(md_cache_get(c, &q, &hit, 100) == 1); assert_ttl(&hit, 86400);
    assert(!md_cache_get(c, &q, &hit, 86500));
    assert(!md_dns_normalize_ttl(&response, err)); assert_ttl(&response, 86400);
    query(&q, "ttl-high.test", 0x0100, 1); positive(&q, &response, UINT32_MAX);
    md_cache_put(c, &q, &response, 100); assert(!md_cache_get(c, &q, &hit, 100));
    assert(!md_dns_normalize_ttl(&response, err)); assert_ttl(&response, 0);
    positive(&q, &response, 0x80000000); add_opt(&response, true, false);
    uint32_t opt = md_read32(response.data + response.len - 6);
    assert(!md_dns_normalize_ttl(&response, err));
    assert(md_read32(response.data + q.len + 6) == 0);
    assert(md_read32(response.data + response.len - 6) == opt);
    md_cache_free(c);

    c = md_cache_new(2, 0); assert(c);
    query(&q, "one.test", 0x0100, 1); positive(&q, &response, 30); md_cache_put(c, &q, &response, 1);
    query(&other, "two.test", 0x0100, 1); positive(&other, &response, 30); md_cache_put(c, &other, &response, 1);
    assert(md_cache_get(c, &q, &hit, 2) == 1);
    md_packet third; query(&third, "three.test", 0x0100, 1); positive(&third, &response, 30); md_cache_put(c, &third, &response, 1);
    assert(!md_cache_get(c, &other, &hit, 2)); assert(md_cache_get(c, &q, &hit, 2) == 1);
    assert(!md_cache_get(c, &q, &hit, 31)); md_cache_free(c);
    c = md_cache_new(1, 5); positive(&q, &response, 60); md_cache_put(c, &q, &response, 1);
    assert(md_cache_get(c, &q, &hit, 5) == 1); assert(!md_cache_get(c, &q, &hit, 6)); md_cache_free(c);
}

/* ---- policy: stale_ttl, refresh SERVFAIL, counters, bytes, reserve, prefetch, warm names ---- */
static bool put_g(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now, unsigned group, int64_t stale, bool refresh) {
    md_dns_view *v = malloc(sizeof(*v)); char err[MD_ERROR_SIZE]; assert(v && !md_dns_view_parse(r, v, err));
    md_cache_put_opts o = {group, stale, refresh}; bool ok = md_cache_put_ex(c, q, NULL, r, v, now, &o);
    free(v); return ok;
}
static int get_g(md_cache *c, const md_packet *q, md_packet *hit, uint64_t now, unsigned group, unsigned flags, bool *due) {
    md_dns_view *v = malloc(sizeof(*v)); md_cache_hit info; assert(v);
    int rc = md_cache_get_ex(c, q, NULL, hit, v, now, group, flags, &info); free(v);
    if (due) *due = info.prefetch_due;
    return rc;
}
static uint64_t stat_of(md_cache *c, unsigned group, unsigned counter) {
    md_cache_stats st; md_cache_get_stats(c, &st); return st.v[group][counter];
}
static void stale_and_refresh_tests(void) {
    md_packet q, r, hit; md_cache_options o = {0};
    o.stale_ttl[MD_CACHE_FOREIGN] = 60;
    md_cache *c = md_cache_new_ex(16, &o); assert(c);
    /* cache_stale_ttl counts AFTER expiry (legacy cache_lazy_ttl counts from insertion). */
    query(&q, "stale.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(get_g(c, &q, &hit, 109, 1, 0, NULL) == 1); assert_ttl(&hit, 1);
    assert(get_g(c, &q, &hit, 110, 1, 0, NULL) == 2); assert_ttl(&hit, 30); /* RFC 8767 stale TTL */
    assert(get_g(c, &q, &hit, 169, 1, 0, NULL) == 2);
    assert(get_g(c, &q, &hit, 170, 1, MD_CACHE_COUNT, NULL) == 0); assert(stat_of(c, 1, MD_CS_EXPIRED) == 1);
    assert(get_g(c, &q, &hit, 171, 1, MD_CACHE_COUNT, NULL) == 0); assert(stat_of(c, 1, MD_CS_EXPIRED) == 2);
    /* CN group default stays 0 (no stale); per-domain override shortens/disables. */
    query(&q, "cn-stale.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 0, -1, false));
    assert(get_g(c, &q, &hit, 110, 0, 0, NULL) == 0);
    query(&q, "ddns.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, 0, false));
    assert(get_g(c, &q, &hit, 110, 1, 0, NULL) == 0);
    query(&q, "short.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, 5, false));
    assert(get_g(c, &q, &hit, 114, 1, 0, NULL) == 2); assert(get_g(c, &q, &hit, 115, 1, 0, NULL) == 0);
    /* negative answers never become stale */
    query(&q, "nx-stale.test", 0x0100, 1); assert(!md_dns_error(&q, &r, 3)); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(get_g(c, &q, &hit, 129, 1, 0, NULL) == 1); assert(get_g(c, &q, &hit, 130, 1, 0, NULL) == 0);

    /* (b) background refresh SERVFAIL keeps the old positive answer until the hard deadline */
    query(&q, "keep.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    md_packet fail; assert(!md_dns_error(&q, &fail, 2));
    assert(md_cache_refresh_begin_at(c, &q, NULL, 105));
    assert(!put_g(c, &q, &fail, 105, 1, -1, true));
    md_cache_refresh_finish(c, &q, NULL, 105, false); assert(stat_of(c, 1, MD_CS_REFRESH_KEPT) == 1);
    assert(get_g(c, &q, &hit, 106, 1, 0, NULL) == 1 && !(md_read16(hit.data + 2) & 15) && md_read16(hit.data + 6) == 1);
    assert(md_cache_refresh_begin_at(c, &q, NULL, 112));
    assert(!put_g(c, &q, &fail, 112, 1, -1, true));
    md_cache_refresh_finish(c, &q, NULL, 112, false); assert(stat_of(c, 1, MD_CS_REFRESH_KEPT) == 2);
    assert(get_g(c, &q, &hit, 112, 1, 0, NULL) == 2 && !(md_read16(hit.data + 2) & 15));
    /* legitimate NXDOMAIN replaces */
    md_packet nx; assert(!md_dns_error(&q, &nx, 3)); assert(put_g(c, &q, &nx, 113, 1, -1, true));
    assert(get_g(c, &q, &hit, 113, 1, 0, NULL) == 1 && (md_read16(hit.data + 2) & 15) == 3);
    /* address change replaces */
    query(&q, "move.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 200, 1, -1, false));
    positive(&q, &r, 10); r.data[r.len - 1] = 77; assert(put_g(c, &q, &r, 205, 1, -1, true));
    assert(get_g(c, &q, &hit, 206, 1, 0, NULL) == 1 && hit.data[hit.len - 1] == 77);
    /* NODATA replaces too */
    md_packet nodata; assert(!md_dns_error(&q, &nodata, 0)); add_a(&nodata, 60, 1); assert(put_g(c, &q, &nodata, 207, 1, -1, true));
    assert(get_g(c, &q, &hit, 207, 1, 0, NULL) == 1 && !md_read16(hit.data + 6));
    /* after the hard deadline a SERVFAIL is stored normally; foreground SERVFAIL also replaces */
    query(&q, "late.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(!md_dns_error(&q, &fail, 2)); assert(put_g(c, &q, &fail, 170, 1, -1, true));
    assert(get_g(c, &q, &hit, 170, 1, 0, NULL) == 1 && (md_read16(hit.data + 2) & 15) == 2);
    query(&q, "fore.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(!md_dns_error(&q, &fail, 2)); assert(put_g(c, &q, &fail, 101, 1, -1, false));
    assert(get_g(c, &q, &hit, 101, 1, 0, NULL) == 1 && (md_read16(hit.data + 2) & 15) == 2);
    md_cache_free(c);
    /* legacy lazy mode keeps its 5 s stale TTL; custom stale answer TTL */
    o = (md_cache_options){0}; o.stale_ttl[1] = 60; o.stale_answer_ttl = 7; c = md_cache_new_ex(4, &o); assert(c);
    query(&q, "answer.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(get_g(c, &q, &hit, 111, 1, 0, NULL) == 2); assert_ttl(&hit, 7); md_cache_free(c);
    o = (md_cache_options){0}; assert(!(o.foreign_reserve_percent = 91, md_cache_new_ex(4, &o)));
}
static void positive_family(md_packet *q, md_packet *r, uint32_t ttl, bool ipv6) {
    if (!ipv6) { positive(q, r, ttl); return; }
    md_write16(q->data + q->len - 4, 28);
    assert(!md_dns_error(q, r, 0));
    uint8_t rr[] = {0xc0,12,0,28,0,1,0,0,0,0,0,16,0x20,1,0xd,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    md_write32(rr + 6, ttl); memcpy(r->data + r->len, rr, sizeof(rr)); r->len += sizeof(rr);
    md_write16(r->data + 6, 1);
}
/* A newer valid answer revokes old data even when the answer cannot be cached.
 * Check A/AAAA, fresh/stale old answers and both foreground/background writes. */
static void replacement_revocation_tests(void) {
    md_packet q, r, hit;
    for (unsigned family = 0; family < 2; ++family) for (unsigned stale = 0; stale < 2; ++stale)
        for (unsigned background = 0; background < 2; ++background) for (unsigned kind = 0; kind < 4; ++kind) {
            md_cache_options o = {0}; o.stale_ttl[1] = 60; o.max_bytes = 200;
            md_cache *c = md_cache_new_ex(4, &o); assert(c);
            query(&q, "revoke.test", 0x0100, 1); positive_family(&q, &r, 10, family != 0);
            assert(put_g(c, &q, &r, 100, 1, -1, false));
            uint64_t now = stale ? 110 : 105;
            assert(get_g(c, &q, &hit, now, 1, 0, NULL) == (stale ? 2 : 1));
            if (kind == 0) positive_family(&q, &r, 0, family != 0);
            else if (kind == 1) assert(!md_dns_error(&q, &r, 0)); /* no SOA, no cache TTL */
            else {
                assert(!md_dns_error(&q, &r, kind == 3 ? 3 : 0));
                for (unsigned j = 0; j < 12; ++j) add_a(&r, 60, kind == 3 ? 1 : 0);
            }
            assert(!put_g(c, &q, &r, now, 1, -1, background != 0));
            assert(!get_g(c, &q, &hit, now, 1, 0, NULL));
            md_cache_stats s; md_cache_get_stats(c, &s); assert(!s.entries[1] && !s.bytes[1]);
            md_cache_free(c);
        }
    /* Case-insensitive DNS identity still supersedes old data when the wire
     * question differs. It remains uncacheable under the byte-exact key policy. */
    for (unsigned family = 0; family < 2; ++family) for (unsigned empty = 0; empty < 2; ++empty) {
        md_cache_options policy = {0}; policy.stale_ttl[1] = 60;
        md_cache *cache = md_cache_new_ex(4, &policy); assert(cache);
        query(&q, "Case.test", 0x0100, 1); positive_family(&q, &r, 10, family != 0);
        assert(put_g(cache, &q, &r, 100, 1, -1, false));
        if (empty) assert(!md_dns_error(&q, &r, 0));
        else positive_family(&q, &r, 0, family != 0);
        assert(r.data[13] == 'C'); r.data[13] = 'c';
        assert(md_dns_response_matches(&q, &r));
        assert(!put_g(cache, &q, &r, 110, 1, -1, true));
        assert(!get_g(cache, &q, &hit, 110, 1, 0, NULL));
        md_cache_free(cache);
    }
    /* Invalid/incomplete/mismatched responses and transient errors cannot revoke. */
    md_cache_options o = {0}; o.stale_ttl[1] = 60;
    md_cache *c = md_cache_new_ex(4, &o); assert(c);
    query(&q, "protect.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    for (unsigned kind = 0; kind < 6; ++kind) {
        positive(&q, &r, 0);
        if (kind == 0) md_write16(r.data, 0x4321); /* unrelated transaction */
        if (kind == 1) r.data[13] = 'z'; /* unrelated question */
        if (kind == 2) md_write16(r.data + 2, (uint16_t)(md_read16(r.data + 2) | 0x0200));
        if (kind == 3) { add_opt(&r, false, false); r.data[r.len - 6] = 1; } /* extended RCODE */
        if (kind == 4) assert(!md_dns_error(&q, &r, 5)); /* REFUSED */
        if (kind == 5) assert(!md_dns_error(&q, &r, 2)); /* SERVFAIL */
        assert(!put_g(c, &q, &r, 110, 1, -1, true));
        assert(get_g(c, &q, &hit, 110, 1, 0, NULL) == 2 && hit.data[hit.len - 1] == 1);
    }
    positive(&q, &r, 0); --r.len; md_cache_put(c, &q, &r, 110); /* malformed RDATA */
    assert(get_g(c, &q, &hit, 110, 1, 0, NULL) == 2);
    md_cache_free(c);
}
static void refresh_backoff_tests(void) {
    md_packet q, other, r, hit; md_cache_options o = {0}; o.stale_ttl[1] = 300;
    md_cache *c = md_cache_new_ex(4, &o); assert(c);
    query(&q, "backoff.test", 0x0100, 1); positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    query(&other, "other.test", 0x0100, 1); positive(&other, &r, 10); assert(put_g(c, &other, &r, 100, 1, -1, false));
    const unsigned delays[] = {5, 10, 20, 30, 30}; uint64_t now = 110;
    for (size_t i = 0; i < sizeof(delays) / sizeof(delays[0]); ++i) {
        assert(md_cache_refresh_begin_at(c, &q, NULL, now));
        assert(!md_cache_refresh_begin_at(c, &q, NULL, now));
        md_cache_refresh_finish(c, &q, NULL, now, false);
        md_cache_refresh_finish(c, &q, NULL, now, false); /* duplicate completion is harmless */
        assert(stat_of(c, 1, MD_CS_REFRESH_KEPT) == i + 1);
        assert(!md_cache_refresh_begin_at(c, &q, NULL, now + delays[i] - 1));
        assert(get_g(c, &q, &hit, now + delays[i] - 1, 1, 0, NULL) == 2);
        assert(md_cache_refresh_begin_at(c, &other, NULL, now)); md_cache_refresh_end_q(c, &other, NULL);
        now += delays[i];
    }
    /* Successful refresh resets the exponent; cancelled work neither delays nor counts. */
    assert(md_cache_refresh_begin_at(c, &q, NULL, now)); md_cache_refresh_finish(c, &q, NULL, now, true);
    assert(md_cache_refresh_begin_at(c, &q, NULL, now)); md_cache_refresh_end_q(c, &q, NULL);
    assert(md_cache_refresh_begin_at(c, &q, NULL, now)); md_cache_refresh_finish(c, &q, NULL, now, false);
    assert(!md_cache_refresh_begin_at(c, &q, NULL, now + 4));
    assert(md_cache_refresh_begin_at(c, &q, NULL, now + 5));
    /* A failed older refresh cannot back off a new foreground answer. */
    positive(&q, &r, 20); r.data[r.len - 1] = 77; assert(put_g(c, &q, &r, now + 5, 1, -1, false));
    uint64_t kept = stat_of(c, 1, MD_CS_REFRESH_KEPT);
    md_cache_refresh_finish(c, &q, NULL, now + 5, false);
    assert(stat_of(c, 1, MD_CS_REFRESH_KEPT) == kept);
    assert(md_cache_refresh_begin_at(c, &q, NULL, now + 5)); md_cache_refresh_end_q(c, &q, NULL);
    assert(get_g(c, &q, &hit, now + 5, 1, 0, NULL) == 1 && hit.data[hit.len - 1] == 77);
    md_cache_free(c);

    /* Neither failures nor retry deadlines extend the positive answer's hard deadline. */
    o.stale_ttl[1] = 60; c = md_cache_new_ex(4, &o); assert(c);
    positive(&q, &r, 10); assert(put_g(c, &q, &r, 100, 1, -1, false));
    assert(md_cache_refresh_begin_at(c, &q, NULL, 169)); md_cache_refresh_finish(c, &q, NULL, 169, false);
    assert(!md_cache_refresh_begin_at(c, &q, NULL, 169));
    assert(get_g(c, &q, &hit, 169, 1, 0, NULL) == 2);
    assert(!get_g(c, &q, &hit, 170, 1, 0, NULL));
    assert(md_cache_refresh_begin_at(c, &q, NULL, 170)); md_cache_refresh_finish(c, &q, NULL, 170, false);
    assert(stat_of(c, 1, MD_CS_REFRESH_KEPT) == 1);
    md_cache_free(c);
}
static void logical_hit_tests(void) {
    md_packet q, r, hit; bool due; md_cache_options o = {0}; o.prefetch_percent = 10;
    md_cache *c = md_cache_new_ex(4, &o); assert(c);
    query(&q, "probe.test", 0x0100, 1); positive(&q, &r, 100); assert(put_g(c, &q, &r, 100, 0, -1, false));
    for (unsigned i = 0; i < 3; ++i) assert(get_g(c, &q, &hit, 195, 0, 0, &due) == 1 && !due);
    char names[128]; assert(!md_cache_hot_names(c, names, sizeof(names), 10));
    assert(get_g(c, &q, &hit, 195, 0, MD_CACHE_COUNT | MD_CACHE_CLAIM, &due) == 1 && !due);
    for (unsigned i = 0; i < 3; ++i) assert(get_g(c, &q, &hit, 195, 0, 0, &due) == 1 && !due);
    assert(stat_of(c, 0, MD_CS_FRESH) == 1);
    assert(get_g(c, &q, &hit, 195, 0, MD_CACHE_COUNT | MD_CACHE_CLAIM, &due) == 1 && due);
    assert(stat_of(c, 0, MD_CS_FRESH) == 2 && stat_of(c, 0, MD_CS_PREFETCH) == 0);
    md_cache_free(c);

    /* Rejected admission can retry; a duplicate cannot cancel an in-flight
     * claim, and failure re-arms only after the retry deadline. */
    o.prefetch_percent = 50; o.stale_ttl[0] = 60; c = md_cache_new_ex(4, &o); assert(c);
    positive(&q, &r, 100); assert(put_g(c, &q, &r, 100, 0, -1, false));
    assert(get_g(c, &q, &hit, 170, 0, MD_CACHE_COUNT | MD_CACHE_CLAIM, &due) == 1 && !due);
    assert(get_g(c, &q, &hit, 170, 0, MD_CACHE_COUNT | MD_CACHE_CLAIM, &due) == 1 && due);
    md_cache_prefetch_cancel(c, &q, NULL);
    assert(get_g(c, &q, &hit, 170, 0, MD_CACHE_CLAIM, &due) == 1 && due);
    assert(md_cache_refresh_begin_at(c, &q, NULL, 170));
    md_cache_prefetch_cancel(c, &q, NULL);
    assert(get_g(c, &q, &hit, 170, 0, MD_CACHE_CLAIM, &due) == 1 && !due);
    md_cache_refresh_finish(c, &q, NULL, 170, false);
    md_cache_prefetch_cancel(c, &q, NULL); /* cannot bypass the failure deadline */
    assert(get_g(c, &q, &hit, 174, 0, MD_CACHE_CLAIM, &due) == 1 && !due);
    assert(!md_cache_refresh_begin_at(c, &q, NULL, 174));
    assert(get_g(c, &q, &hit, 175, 0, MD_CACHE_CLAIM, &due) == 1 && due);
    assert(md_cache_refresh_begin_at(c, &q, NULL, 175));
    md_cache_refresh_end_q(c, &q, NULL);
    assert(stat_of(c, 0, MD_CS_PREFETCH) == 0 && stat_of(c, 0, MD_CS_REFRESH_KEPT) == 1);
    md_cache_free(c);
}
static void counter_capacity_tests(void) {
    md_packet q, r, hit, m1, m2, m3, m4;
    md_cache *c = md_cache_new_ex(2, &(md_cache_options){0}); assert(c);
    query(&m1, "m1.test", 0x0100, 1); query(&m2, "m2.test", 0x0100, 1); query(&m3, "m3.test", 0x0100, 1); query(&m4, "m4.test", 0x0100, 1);
    assert(!get_g(c, &m1, &hit, 1, 1, MD_CACHE_COUNT, NULL)); assert(stat_of(c, 1, MD_CS_COLD) == 1);
    positive(&m1, &r, 30); assert(put_g(c, &m1, &r, 1, 1, -1, false));
    positive(&m2, &r, 30); assert(put_g(c, &m2, &r, 1, 1, -1, false));
    positive(&m3, &r, 30); assert(put_g(c, &m3, &r, 1, 1, -1, false));
    assert(stat_of(c, 1, MD_CS_EVICTIONS) == 1);
    assert(!get_g(c, &m1, &hit, 2, 1, MD_CACHE_COUNT, NULL)); assert(stat_of(c, 1, MD_CS_EVICTED) == 1);
    assert(get_g(c, &m3, &hit, 2, 1, MD_CACHE_COUNT, NULL) == 1); assert(stat_of(c, 1, MD_CS_FRESH) == 1);
    positive(&m4, &r, 5); assert(put_g(c, &m4, &r, 2, 1, -1, false)); /* evicts m2 */
    assert(!get_g(c, &m4, &hit, 10, 1, MD_CACHE_COUNT, NULL)); assert(stat_of(c, 1, MD_CS_EXPIRED) == 1);
    query(&q, "ecs.test", 0x0100, 1); add_opt(&q, false, true);
    assert(!get_g(c, &q, &hit, 10, 1, MD_CACHE_COUNT, NULL)); assert(stat_of(c, 1, MD_CS_BYPASS) == 1);
    md_cache_stats st; md_cache_get_stats(c, &st); assert(st.entries[1] == 1 && !st.entries[0] && !st.v[0][MD_CS_COLD]);
    md_cache_free(c);

    /* byte budget: each "bN.test" entry accounts 96 + 14 + 41 + 2 = 153 bytes */
    md_cache_options o = {0}; o.max_bytes = 320; c = md_cache_new_ex(100, &o); assert(c);
    query(&m1, "b1.test", 0x0100, 1); query(&m2, "b2.test", 0x0100, 1); query(&m3, "b3.test", 0x0100, 1);
    positive(&m1, &r, 30); assert(put_g(c, &m1, &r, 1, 1, -1, false));
    positive(&m2, &r, 30); assert(put_g(c, &m2, &r, 1, 1, -1, false));
    md_cache_get_stats(c, &st); assert(st.bytes[1] == 306 && st.entries[1] == 2);
    positive(&m3, &r, 30); assert(put_g(c, &m3, &r, 1, 1, -1, false));
    md_cache_get_stats(c, &st); assert(st.bytes[1] == 306 && st.entries[1] == 2 && st.v[1][MD_CS_EVICTIONS] == 1);
    assert(!get_g(c, &m1, &hit, 1, 1, 0, NULL) && get_g(c, &m3, &hit, 1, 1, 0, NULL) == 1);
    md_cache_free(c);
    o.max_bytes = 100; c = md_cache_new_ex(100, &o); assert(c);
    positive(&m1, &r, 30); assert(!put_g(c, &m1, &r, 1, 1, -1, false)); md_cache_free(c);

    /* foreign reserve: CN churn cannot evict foreign entries while under the reserve */
    for (unsigned reserve = 0; reserve <= 50; reserve += 50) {
        o = (md_cache_options){0}; o.foreign_reserve_percent = reserve; c = md_cache_new_ex(4, &o); assert(c);
        const char *names[] = {"fa.test", "fb.test", "ca.test", "cb.test", "cc.test", "cd.test"};
        md_packet p[6];
        for (unsigned i = 0; i < 6; ++i) { query(&p[i], names[i], 0x0100, 1); positive(&p[i], &r, 30); assert(put_g(c, &p[i], &r, 1, i < 2, -1, false)); }
        bool kept = reserve != 0;
        assert((get_g(c, &p[0], &hit, 2, 1, 0, NULL) == 1) == kept && (get_g(c, &p[1], &hit, 2, 1, 0, NULL) == 1) == kept);
        assert((get_g(c, &p[2], &hit, 2, 0, 0, NULL) == 1) == !kept && (get_g(c, &p[3], &hit, 2, 0, 0, NULL) == 1) == !kept);
        assert(get_g(c, &p[4], &hit, 2, 0, 0, NULL) == 1 && get_g(c, &p[5], &hit, 2, 0, 0, NULL) == 1);
        md_cache_free(c);
    }
    /* above the reserve normal LRU applies again */
    o = (md_cache_options){0}; o.foreign_reserve_percent = 25; c = md_cache_new_ex(4, &o); assert(c);
    md_packet f1, f2, c1, c2, c3; query(&f1, "f1.test", 0x0100, 1); query(&f2, "f2.test", 0x0100, 1);
    query(&c1, "c1.test", 0x0100, 1); query(&c2, "c2.test", 0x0100, 1); query(&c3, "c3.test", 0x0100, 1);
    positive(&f1, &r, 30); assert(put_g(c, &f1, &r, 1, 1, -1, false));
    positive(&f2, &r, 30); assert(put_g(c, &f2, &r, 1, 1, -1, false));
    positive(&c1, &r, 30); assert(put_g(c, &c1, &r, 1, 0, -1, false));
    positive(&c2, &r, 30); assert(put_g(c, &c2, &r, 1, 0, -1, false));
    positive(&c3, &r, 30); assert(put_g(c, &c3, &r, 1, 0, -1, false));
    assert(!get_g(c, &f1, &hit, 2, 1, 0, NULL) && get_g(c, &f2, &hit, 2, 1, 0, NULL) == 1);
    md_cache_free(c);
}
static void prefetch_and_warm_tests(void) {
    md_packet q, r, hit; bool due; md_cache_options o = {0}; o.prefetch_percent = 10;
    md_cache *c = md_cache_new_ex(16, &o); assert(c);
    query(&q, "pf.test", 0x0100, 1); positive(&q, &r, 100); assert(put_g(c, &q, &r, 1000, 1, -1, false));
    unsigned use = MD_CACHE_COUNT | MD_CACHE_CLAIM;
    assert(get_g(c, &q, &hit, 1001, 1, use, &due) == 1 && !due);   /* first use: not reused yet */
    assert(get_g(c, &q, &hit, 1050, 1, use, &due) == 1 && !due);   /* 50 s left > threshold (7..12) */
    assert(get_g(c, &q, &hit, 1095, 1, use, &due) == 1 && due);    /* 5 s left: claim */
    assert(get_g(c, &q, &hit, 1096, 1, use, &due) == 1 && !due);   /* deduped: once per answer */
    assert(stat_of(c, 1, MD_CS_PREFETCH) == 0); /* engine counts only an actually started refresh */
    positive(&q, &r, 100); assert(put_g(c, &q, &r, 1096, 1, -1, true));       /* refreshed answer re-arms */
    assert(get_g(c, &q, &hit, 1190, 1, use, &due) == 1 && !due);
    assert(get_g(c, &q, &hit, 1191, 1, use, &due) == 1 && due);
    /* jittered threshold stays within 0.75..1.25 of 10% */
    query(&q, "edge.test", 0x0100, 1); positive(&q, &r, 100); assert(put_g(c, &q, &r, 1000, 1, -1, false));
    assert(get_g(c, &q, &hit, 1000, 1, MD_CACHE_COUNT, &due) == 1 && !due);
    assert(get_g(c, &q, &hit, 1087, 1, MD_CACHE_COUNT, &due) == 1 && !due);     /* 13 s left */
    assert(get_g(c, &q, &hit, 1093, 1, 0, &due) == 1 && due);                 /* 7 s left, peek only */
    assert(get_g(c, &q, &hit, 1093, 1, 0, &due) == 1 && due);
    query(&q, "once.test", 0x0100, 1); positive(&q, &r, 100); assert(put_g(c, &q, &r, 1000, 1, -1, false));
    assert(get_g(c, &q, &hit, 1095, 1, use, &due) == 1 && !due);
    query(&q, "tiny.test", 0x0100, 1); positive(&q, &r, 1); assert(put_g(c, &q, &r, 1000, 1, -1, false));
    assert(get_g(c, &q, &hit, 1000, 1, MD_CACHE_CLAIM, &due) == 1 && !due);
    assert(get_g(c, &q, &hit, 1000, 1, MD_CACHE_CLAIM, &due) == 1 && !due);
    md_cache_free(c);
    /* prefetch disabled by default */
    c = md_cache_new(4, 0); query(&q, "off.test", 0x0100, 1); positive(&q, &r, 100); md_cache_put(c, &q, &r, 1000);
    for (unsigned i = 0; i < 3; ++i) assert(get_g(c, &q, &hit, 1099, 1, MD_CACHE_CLAIM, &due) == 1 && !due);
    md_cache_free(c);

    /* warm names: reused entries only, names never addresses, newest first */
    c = md_cache_new(8, 0); md_packet a, b, d;
    query(&a, "hot.test", 0x0100, 1); positive(&a, &r, 60); md_cache_put(c, &a, &r, 1);
    query(&b, "cold.test", 0x0100, 1); positive(&b, &r, 60); md_cache_put(c, &b, &r, 1);
    query(&d, "dnssec.test", 0x0100, 1); add_opt(&d, true, false); positive(&d, &r, 60); md_cache_put(c, &d, &r, 1);
    assert(get_g(c, &a, &hit, 2, 0, MD_CACHE_COUNT, NULL) == 1); assert(get_g(c, &d, &hit, 3, 0, MD_CACHE_COUNT, NULL) == 1);
    char out[512]; assert(md_cache_hot_names(c, out, sizeof(out), 10) == 2);
    assert(!strcmp(out, "4 1 dnssec.test\n0 1 hot.test\n"));
    assert(!strstr(out, "192.0.2") && !strstr(out, "cold"));
    assert(md_cache_hot_names(c, out, sizeof(out), 1) == 1 && !strcmp(out, "4 1 dnssec.test\n"));
    assert(md_cache_hot_names(c, out, 8, 10) == 0 && !out[0]);
    md_cache_free(c);
}
typedef struct { md_cache *cache; const md_packet *query; bool began; } refresh_test;
static void *refresh_thread(void *arg) {
    refresh_test *v = arg; v->began = md_cache_refresh_begin(v->cache, v->query); return NULL;
}
static void *read_write_thread(void *arg) {
    refresh_test *v = arg; md_packet r, hit;
    positive((md_packet *)v->query, &r, 60);
    for (unsigned i = 0; i < 500; ++i) {
        md_cache_put(v->cache, v->query, &r, 1);
        assert(md_cache_get(v->cache, v->query, &hit, 2) == 1); assert_ttl(&hit, 59);
    }
    return NULL;
}
/* 并发刷新必须只有一个获得标记；并行 put/get 应始终返回独立且一致的报文。 */
static void concurrency_tests(void) {
    md_cache *c = md_cache_new(2, 100); assert(c); md_packet q;
    query(&q, "concurrent.test", 0x0100, 1);
    pthread_t threads[8]; refresh_test args[8]; unsigned count = 0;
    for (unsigned i = 0; i < 8; ++i) { args[i] = (refresh_test){c, &q, false}; assert(!pthread_create(&threads[i], NULL, refresh_thread, &args[i])); }
    for (unsigned i = 0; i < 8; ++i) { assert(!pthread_join(threads[i], NULL)); count += args[i].began; }
    assert(count == 1); md_cache_refresh_end(c, &q);
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_create(&threads[i], NULL, read_write_thread, &args[i]));
    for (unsigned i = 0; i < 8; ++i) assert(!pthread_join(threads[i], NULL));
    md_cache_free(c);
}

/* Keep the complete PCRE2 contract when building the default backend. */
#ifndef MD_REGEX_POSIX
/* 检查依赖实际关闭 Unicode/JIT，并验证字节模式和必须失败的 Unicode 指令。 */
static void regex_profile_tests(void) {
    uint32_t enabled = 1;
    assert(!pcre2_config(PCRE2_CONFIG_UNICODE, &enabled));
    if (enabled) { fputs("test profile requires PCRE2 without Unicode support\n", stderr); abort(); }
    assert(!pcre2_config(PCRE2_CONFIG_JIT, &enabled));
    if (enabled) { fputs("test profile requires PCRE2 without JIT support\n", stderr); abort(); }

    const char *unsupported[] = {
        "regexp:(*UTF)^example\\.test$", "regexp:(*UCP)^example\\.test$",
        "regexp:^\\p{L}+\\.test$", "regexp:^\\P{L}+\\.test$", "regexp:^\\X\\.test$"
    };
    char err[MD_ERROR_SIZE], path[] = "/tmp/mosdns-c-regex-XXXXXX";
    int fd = mkstemp(path); assert(fd >= 0); assert(!close(fd));
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i) {
        md_domain *d = md_domain_new(); assert(d);
        assert(md_domain_add(d, unsupported[i], err));
        assert(strstr(err, "invalid PCRE2 regexp at "));
        assert(!md_domain_match(d, "example.test"));
        FILE *f = fopen(path, "w"); assert(f);
        assert(fprintf(f, "# profile rejection\nfull:before.test\n\n%s\nfull:after.test\n", unsupported[i]) > 0);
        assert(!fclose(f));
        assert(md_domain_load(d, path, err));
        assert(strstr(err, path) && strstr(err, "line 4:") && strstr(err, "invalid PCRE2 regexp at "));
        assert(md_domain_match(d, "before.test"));
        assert(!md_domain_match(d, "after.test")); /* Fail at the bad rule; never skip it. */
        md_domain_free(d);
    }
    assert(!unlink(path));

    md_domain *d = md_domain_new(); assert(d);
    assert(!md_domain_add(d, "regexp:^asset-\\d+\\.\\w+$", err));
    assert(md_domain_match(d, "ASSET-123.A_B."));
    assert(!md_domain_match(d, "asset-a.test"));
    assert(!md_domain_match(d, "asset-\xd9\xa1.test")); /* Arabic-Indic digit is not ASCII \\d. */
    assert(!md_domain_match(d, "asset-1.\xc3\xa9")); /* UTF-8 bytes are not ASCII \\w. */
    md_domain_free(d);
    d = md_domain_new(); assert(d);
    assert(!md_domain_add(d, "regexp:^..\\.bytes$", err));
    assert(md_domain_match(d, "ab.bytes"));
    assert(md_domain_match(d, "\xc3\xa9.bytes")); /* Library matcher counts bytes, not code points. */
    assert(!md_domain_match(d, "a.bytes"));
    assert(!md_domain_match(d, "\xe4\xb8\xad.bytes"));
    md_domain_free(d);
}

#include "regex_budget_profile.h"
#else
#include "regex_posix_profile.h"
#endif

/* 固定八条 cn-site 正则的正例、反例和后缀攻击，保护实际规则的锚定语义。 */
static void direct_list_regex_tests(void) {
    /* All eight regexp lines, unchanged, from Loyalsoldier/v2ray-rules-dat:
     * https://github.com/Loyalsoldier/v2ray-rules-dat/blob/99f994716ed6323595c9ba5ff6dc36b6a1fe27c7/direct-list.txt#L111725-L111732
     * Verified source blob: 7f1511773bce814fa841dcab4ff2a6314bd8575b.
     * Test each rule alone so another rule cannot mask an incorrect result. */
    const struct { const char *rule; const char *yes[4], *no[4]; } cases[] = {
        {"regexp:.+\\.awsdns-cn-[0-9][0-9]\\.(biz|com|net|top)$",
         {"a.awsdns-cn-00.biz", "a.b.awsdns-cn-12.com", "A.AWSDNS-CN-99.NET.", "a.awsdns-cn-42.top"},
         {"awsdns-cn-00.biz", "a.awsdns-cn-1.com", "a.awsdns-cn-1a.net", "a.awsdns-cn-12.top.evil"}},
        {"regexp:.+\\.awsdns-cn-[0-9][a-e0-9]\\.cn$",
         {"a.awsdns-cn-0a.cn", "a.b.awsdns-cn-9e.cn", "A.AWSDNS-CN-00.CN.", "a.awsdns-cn-99.cn"},
         {"awsdns-cn-0a.cn", "a.awsdns-cn-1f.cn", "a.awsdns-cn-aa.cn", "a.awsdns-cn-1a.cn.evil"}},
        {"regexp:^(.+\\.)*zh\\.okaapps\\.com$",
         {"zh.okaapps.com", "a.zh.okaapps.com", "a.b.zh.okaapps.com", "ZH.OKAAPPS.COM."},
         {"okaapps.com", "prefixzh.okaapps.com", "zh.okaapps.com.evil", "zhxokaapps.com"}},
        {"regexp:^.+-mihayo\\.akamaized\\.net$",
         {"a-mihayo.akamaized.net", "a-b-mihayo.akamaized.net", "a.b-mihayo.akamaized.net", "A-MIHAYO.AKAMAIZED.NET."},
         {"-mihayo.akamaized.net", "a-mihoyo.akamaized.net", "a-mihayo.akamaized.net.evil", "a-mihayoxakamaized.net"}},
        {"regexp:^cdn\\d-epicgames-\\d+\\.file\\.myqcloud\\.com$",
         {"cdn0-epicgames-0.file.myqcloud.com", "cdn9-epicgames-123.file.myqcloud.com", "cdn1-epicgames-00.file.myqcloud.com", "CDN2-EPICGAMES-9.FILE.MYQCLOUD.COM."},
         {"cdn12-epicgames-1.file.myqcloud.com", "cdna-epicgames-1.file.myqcloud.com", "cdn1-epicgames-.file.myqcloud.com", "cdn1-epicgames-1.file.myqcloud.com.evil"}},
        {"regexp:^epicgames-download\\d-\\d+\\.file\\.myqcloud\\.com$",
         {"epicgames-download0-0.file.myqcloud.com", "epicgames-download9-123.file.myqcloud.com", "epicgames-download1-00.file.myqcloud.com", "EPICGAMES-DOWNLOAD2-9.FILE.MYQCLOUD.COM."},
         {"epicgames-download12-1.file.myqcloud.com", "epicgames-downloada-1.file.myqcloud.com", "epicgames-download1-.file.myqcloud.com", "epicgames-download1-1.file.myqcloud.com.evil"}},
        {"regexp:^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.googlevideo\\.com$",
         {"r1---sn-2x3abc_9.googlevideo.com", "rr123.sn-ni5a0b1c.googlevideo.com", "r9---sn-j5o12345.googlevideo.com", "R1.SN-2X3ABCDE.GOOGLEVIDEO.COM."},
         {"r1--sn-2x3abcde.googlevideo.com", "r1---sn-xxxabcde.googlevideo.com", "r1---sn-2x3abcd.googlevideo.com", "r1---sn-2x3abc-e.googlevideo.com"}},
        {"regexp:^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.xn--ngstr-lra8j\\.com$",
         {"r1---sn-2x3abc_9.xn--ngstr-lra8j.com", "rr123.sn-ni5a0b1c.xn--ngstr-lra8j.com", "r9---sn-j5o12345.xn--ngstr-lra8j.com", "R1.SN-2X3ABCDE.XN--NGSTR-LRA8J.COM."},
         {"r1--sn-2x3abcde.xn--ngstr-lra8j.com", "r1---sn-xxxabcde.xn--ngstr-lra8j.com", "r1---sn-2x3abcdef.xn--ngstr-lra8j.com", "r1---sn-2x3abc-e.xn--ngstr-lra8j.com"}}
    };
    assert(sizeof(cases) / sizeof(cases[0]) == 8);
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        char err[MD_ERROR_SIZE]; md_domain *d = md_domain_new(); assert(d);
        assert(!md_domain_add(d, cases[i].rule, err));
        for (size_t j = 0; j < 4; ++j) {
            assert(md_domain_match(d, cases[i].yes[j]));
            assert(!md_domain_match(d, cases[i].no[j]));
        }
        char suffix[256];
        assert(snprintf(suffix, sizeof(suffix), "%s.evil", cases[i].yes[0]) > 0);
        assert(!md_domain_match(d, suffix));
        md_domain_free(d);
    }
}

#include "regex_concurrency.h"

static void domain_tests(void) {
    char err[MD_ERROR_SIZE]; md_domain *d = md_domain_new(); assert(d);
    const char *rules[] = {"domain:EXAMPLE.com.", "full:only.test", "keyword:needle", "regexp:^asset-[0-9]+\\.test$", ":default.test"};
    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); ++i) assert(!md_domain_add(d, rules[i], err));
    assert(md_domain_match(d, "www.ExAmPlE.CoM.")); assert(!md_domain_match(d, "badexample.com"));
    assert(md_domain_match(d, "only.test")); assert(!md_domain_match(d, "sub.only.test"));
    assert(md_domain_match(d, "a.NEEDLE.b")); assert(md_domain_match(d, "asset-123.test."));
    assert(!md_domain_match(d, "asset-a.test")); assert(md_domain_match(d, "a.default.test"));
    assert(md_domain_add(d, "unknown:example.com", err)); assert(md_domain_add(d, "regexp:[", err));
    md_domain_free(d);
    d = md_domain_new(); assert(!md_domain_add(d, "domain:example.com..", err));
    assert(md_domain_match(d, "example.com")); assert(md_domain_match(d, "example.com..")); assert(!md_domain_match(d, "example.com..."));
    md_domain_free(d);
    d = md_domain_new(); assert(!md_domain_add(d, "domain:.", err)); assert(md_domain_match(d, "unmatched.test")); assert(md_domain_match(d, ".")); md_domain_free(d);
    d = md_domain_new(); assert(!md_domain_add(d, "keyword:", err)); assert(md_domain_match(d, "")); md_domain_free(d);
    d = md_domain_new();
    for (unsigned i = 0; i < 100000; ++i) { char rule[80]; snprintf(rule, sizeof(rule), "host-%u.group-%u.test", i, i % 103); assert(!md_domain_add(d, rule, err)); }
    for (unsigned i = 0; i < 100000; i += 137) { char name[100]; snprintf(name, sizeof(name), "cdn.host-%u.group-%u.test.", i, i % 103); assert(md_domain_match(d, name)); }
    assert(!md_domain_match(d, "cdn.not-in-list.test")); md_domain_free(d);
    char path[] = "/tmp/mosdns-c-domain-XXXXXX"; int fd = mkstemp(path); assert(fd >= 0);
    FILE *f = fdopen(fd, "w"); assert(f);
    fputs("# comment\r\n\n domain:EXAMPLE.com. # inline\nfull:only.test\nregexp:^asset:[0-9]+$\n", f); assert(!fclose(f));
    d = md_domain_new(); assert(!md_domain_load(d, path, err)); assert(md_domain_match(d, "www.example.com")); assert(md_domain_match(d, "asset:123"));
    f = fopen(path, "w"); assert(f); fputs("good.test\nfull:bad.test extra\n", f); fclose(f);
    assert(md_domain_load(d, path, err)); assert(strstr(err, "line 2:")); assert(md_domain_match(d, "good.test"));
    unlink(path); md_domain_free(d);
}

/* 这里验证配置解析及非 Linux 错误；不操作目标机集合，也不证明真实内核更新。 */
static void nft_tests(void) {
    char err[MD_ERROR_SIZE];
    md_nft *n = md_nft_new("inet,filter,cn4,ipv4_addr,24 ip6,filter,cn6,ipv6_addr,48", err); assert(n);
#ifndef __linux__
    md_packet q, r; query(&q, "example.test", 0x0100, 1); positive(&q, &r, 60);
    assert(md_nft_apply(n, &r, err)); assert(strstr(err, "only on Linux"));
#endif
    md_nft_free(n);
    const char *bad[] = {"inet,t,s,ipv4_addr,33", "inet,t,s,ipv6_addr,129", "bridge,t,s,ipv4_addr,24",
                        "inet,t,s;flush,ipv4_addr,24", "inet,t,s,ipv4_addr,-1", "inet,t,s,ipv4_addr,24x",
                        "inet,9table,s,ipv4_addr,24", "inet,t,9set,ipv4_addr,24", "inet,-table,s,ipv4_addr,24",
                        "inet,t,\"set\",ipv4_addr,24", "inet,t,s/path,ipv4_addr,24", "inet,t,s\\path,ipv4_addr,24",
                        "inet,t,s,invalid,24", "inet,t,s,ipv4_addr", "inet,t,s,ipv4_addr,1,2"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) assert(!md_nft_new(bad[i], err));
}
/* Cross many arena blocks and hash resizes, then recheck early pointers.
 * Both backends run this under native and ASan/UBSan CI builds. */
static void domain_storage_tests(void) {
    char err[MD_ERROR_SIZE], rule[128], name[128];
    for (unsigned cycle = 0; cycle < 2; ++cycle) {
        md_domain *d = md_domain_new(); assert(d);
        for (unsigned i = 0; i < 112000; ++i) {
            snprintf(rule, sizeof(rule), "%s:n%u.storage.test", i & 1 ? "full" : "domain", i);
            assert(!md_domain_add(d, rule, err));
            if (!(i % 997)) assert(!md_domain_add(d, rule, err));
        }
        for (unsigned i = 0; i < 112000; ++i) {
            snprintf(name, sizeof(name), "N%u.STORAGE.TEST.", i);
            assert(md_domain_match(d, name));
            snprintf(name, sizeof(name), "sub.n%u.storage.test", i);
            assert(md_domain_match(d, name) == !(i & 1));
            snprintf(name, sizeof(name), "badn%u.storage.test", i);
            assert(!md_domain_match(d, name));
        }
        /* One allocation larger than the usual block, then another small node. */
        char *large = malloc(65536); assert(large);
        memset(large, 'a', 65534); large[65534] = '\0';
        assert(!md_domain_add(d, large, err));
        assert(md_domain_match(d, large));
        free(large);
        assert(!md_domain_add(d, "domain:after-large.test", err));
        assert(md_domain_match(d, "child.after-large.test"));
        assert(md_domain_add(d, "unsupported:bad.test", err));
        assert(md_domain_match(d, "n0.storage.test"));
        assert(!md_domain_match(d, "n112000.storage.test"));
        md_domain_free(d);
    }
}

#include "domain_storage_fault.h"

int main(void) {
#ifndef MD_REGEX_POSIX
    regex_budget_tests();
#endif
    regex_profile_tests(); direct_list_regex_tests(); regex_concurrency_tests(); domain_tests(); domain_storage_tests(); domain_storage_fault_tests(); cache_tests(); stale_and_refresh_tests(); replacement_revocation_tests(); refresh_backoff_tests(); logical_hit_tests(); counter_capacity_tests(); prefetch_and_warm_tests(); concurrency_tests(); nft_tests();
    puts("domain/cache/nftset parser tests passed"); return 0;
}
