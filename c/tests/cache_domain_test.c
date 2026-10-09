/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
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
int main(void) {
    domain_tests(); cache_tests(); concurrency_tests(); nft_tests();
    puts("domain/cache/nftset parser tests passed"); return 0;
}
