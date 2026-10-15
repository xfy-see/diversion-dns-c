/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Portable link-independent doubles: production DNS/domain/cache/nft parsing,
 * with only forwarding, nft I/O and the monotonic clock substituted. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "mosdns.h"
#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int test_forward(const md_upstream *, size_t, unsigned, const md_packet *, md_packet *, char *);
static int test_nft_apply(md_nft *, const md_packet *, char *);
static uint64_t test_now(void);
static int test_forward_q(const md_upstream *, size_t, unsigned, const md_packet *, const md_dns_query *, md_packet *, md_dns_view *, char *);
static int test_nft_apply_view(md_nft *, const md_packet *, const md_dns_view *, char *);
#define md_forward test_forward
#define md_forward_q test_forward_q
#define md_nft_apply test_nft_apply
#define md_nft_apply_view test_nft_apply_view
#define md_now test_now
#include "../coremain/engine.c"
#undef md_forward
#undef md_forward_view
#undef md_nft_apply
#undef md_nft_apply_view
#undef md_now

static char test_directory[256], test_rules[512], test_config[512];
static atomic_uint_fast64_t test_clock;
static pthread_mutex_t test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_ready = PTHREAD_COND_INITIALIZER;
static unsigned test_calls[2], test_nft_calls, test_nft_v4, test_nft_v6;
static unsigned test_last_concurrent[2];
static size_t test_last_count[2];
static uint32_t test_last_mark[2], test_ttl;
static unsigned test_rcode; static uint8_t test_addr = 9;
static unsigned test_forward_advance, test_nft_advance;
static char test_last_device[2][64];
static bool test_forward_fails, test_nft_fails, test_refresh_block, test_refresh_entered;
static md_packet test_last_nft;

static uint64_t test_now(void) { return atomic_load(&test_clock); }
static void test_reset(void) {
    atomic_store(&test_clock, 100);
    memset(test_calls, 0, sizeof(test_calls)); test_nft_calls = test_nft_v4 = test_nft_v6 = 0;
    memset(test_last_concurrent, 0, sizeof(test_last_concurrent));
    memset(test_last_count, 0, sizeof(test_last_count)); memset(test_last_mark, 0, sizeof(test_last_mark));
    memset(test_last_device, 0, sizeof(test_last_device));
    test_forward_fails = test_nft_fails = test_refresh_block = test_refresh_entered = false;
    test_ttl = 60; test_rcode = 0; test_addr = 9; test_last_nft.len = 0; test_forward_advance = test_nft_advance = 0;
}
static void test_write(const char *path, const char *text) {
    FILE *f = fopen(path, "wb"); assert(f); assert(fwrite(text, 1, strlen(text), f) == strlen(text)); assert(!fclose(f));
}
static md_engine *test_engine(const char *extra, bool nft) {
    char text[8192], err[MD_ERROR_SIZE] = {0};
    int n = snprintf(text, sizeof(text), "listen_udp=127.0.0.1:5300\nlisten_tcp=127.0.0.1:5300\ncn_domain_file=%s\ncn_upstream=127.0.0.1:5301\nforeign_upstream=127.0.0.1:5302\n%s%s",
        test_rules, nft ? "nftset_ipv4=inet,dns,cn4,ipv4_addr,32\nnftset_ipv6=inet,dns,cn6,ipv6_addr,128\n" : "", extra);
    assert(n > 0 && (size_t)n < sizeof(text)); test_write(test_config, text);
    md_engine *e = md_engine_load(test_config, false, err);
    if (!e) { fprintf(stderr, "test config: %s\n", err); abort(); }
    assert(!md_engine_start(e, err));
    assert(md_engine_listener_count(e) == 2);
    assert(md_engine_listener(e, 0)->entry == 0 && md_engine_listener(e, 1)->entry == 0);
    return e;
}
static size_t test_name(uint8_t *wire, const char *name) {
    size_t used = 0;
    for (const char *p = name; *p;) {
        const char *dot = strchr(p, '.'); size_t n = dot ? (size_t)(dot-p) : strlen(p); assert(n && n <= 63);
        wire[used++] = (uint8_t)n; memcpy(wire + used, p, n); used += n;
        if (!dot) break;
        p = dot + 1;
    }
    wire[used++] = 0; return used;
}
static md_packet test_question(const char *name, uint16_t type, uint16_t flags) {
    md_packet q = {0}; md_write16(q.data, 1234); md_write16(q.data+2, flags); md_write16(q.data+4, 1);
    q.len = 12 + test_name(q.data+12, name); md_write16(q.data+q.len, type); md_write16(q.data+q.len+2, 1); q.len += 4;
    return q;
}
static void test_opt(md_packet *q, bool dnssec) {
    const uint8_t opt[] = {0,0,41,4,208,0,0,0,0,0,0};
    memcpy(q->data + q->len, opt, sizeof(opt)); if (dnssec) q->data[q->len + 7] = 0x80;
    q->len += sizeof(opt); md_write16(q->data+10, 1);
}
static void test_add_record(md_packet *r, uint16_t type, const uint8_t *data, size_t length, uint32_t ttl) {
    assert(length <= UINT16_MAX && r->len + 12 + length < sizeof(r->data));
    uint8_t *out = r->data + r->len; out[0] = 0xc0; out[1] = 12;
    md_write16(out+2, type); md_write16(out+4, 1); md_write32(out+6, ttl); md_write16(out+10, (uint16_t)length);
    memcpy(out+12, data, length); r->len += 12 + length; md_write16(r->data+6, (uint16_t)(md_read16(r->data+6)+1));
}
static int test_forward(const md_upstream *us, size_t count, unsigned concurrent, const md_packet *q, md_packet *r, char *err) {
    assert(us && count); assert(us[0].address.ss_family == AF_INET);
    unsigned port = ntohs(((const struct sockaddr_in *)&us[0].address)->sin_port);
    unsigned group = port == 5301 ? 0 : 1; assert(port == 5301 || port == 5302);
    pthread_mutex_lock(&test_lock);
    ++test_calls[group]; test_last_count[group] = count; test_last_concurrent[group] = concurrent;
    for (size_t i = 0; i < count; ++i) {
        assert(us[i].so_mark == us[0].so_mark); assert(!strcmp(us[i].bind_device, us[0].bind_device));
    }
    test_last_mark[group] = us[0].so_mark; strcpy(test_last_device[group], us[0].bind_device);
    if (test_refresh_block) {
        test_refresh_entered = true; pthread_cond_broadcast(&test_ready);
        while (test_refresh_block) pthread_cond_wait(&test_ready, &test_lock);
    }
    bool failed = test_forward_fails; uint32_t ttl = test_ttl; unsigned forced = test_rcode; uint8_t addr = test_addr; pthread_mutex_unlock(&test_lock);
    if (failed) { r->len = 0; snprintf(err, MD_ERROR_SIZE, "injected upstream transport failure"); return -1; }
    md_question parsed; assert(!md_dns_question(q, &parsed, err));
    unsigned rcode = forced ? forced : !strncmp(parsed.name, "nx.", 3) ? 3 : 0; assert(!md_dns_error(q, r, rcode));
    if (rcode) return 0;
    size_t target_offset = 0;
    if (!strncmp(parsed.name, "alias.", 6)) {
        target_offset = r->len + 12;
        uint8_t target[256]; size_t length = test_name(target, group ? "target.cn" : "target.foreign.test");
        test_add_record(r, 5, target, length, ttl);
    }
    size_t address_offset = r->len;
    if (parsed.type == 28) {
        const uint8_t ip6[] = {0x20,0x01,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,9};
        test_add_record(r, 28, ip6, sizeof(ip6), ttl);
    } else {
        const uint8_t cn[] = {192,0,2,addr}, foreign[] = {203,0,113,addr};
        test_add_record(r, 1, group ? foreign : cn, sizeof(cn), ttl);
    }
    if (target_offset) md_write16(r->data + address_offset, (uint16_t)(0xc000 | target_offset));
    assert(md_dns_response_matches(q, r)); atomic_fetch_add(&test_clock, test_forward_advance); return 0;
}
/* The engine now hands forward/nft the single parsed view; the doubles keep
 * their packet-only bodies and the view must describe the exact bytes. */
/* The engine also hands forward the request's single parse: it must be valid
 * for exactly these query bytes (no re-parse needed downstream). */
static int test_forward_q(const md_upstream *us, size_t count, unsigned concurrent, const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *v, char *err) {
    md_dns_query fresh;
    assert(md_dns_query_ok(q, qv) && !md_dns_query_parse(q, &fresh, err));
    assert(!memcmp(&fresh.q, &qv->q, sizeof(fresh.q)) && fresh.cache_edns_ok == qv->cache_edns_ok);
    int rc = test_forward(us, count, concurrent, q, r, err);
    if (r->len) assert(!md_dns_view_parse(r, v, err));
    return rc;
}
static int test_nft_apply_view(md_nft *n, const md_packet *r, const md_dns_view *v, char *err) {
    assert(v && v->valid && v->len == r->len);
    return test_nft_apply(n, r, err);
}
static int test_nft_record(const md_packet *packet, const md_rr *rr, void *unused) {
    (void)packet; (void)unused;
    if (rr->section == 0 && rr->class_ == 1) {
        if (rr->type == 1 && rr->data_len == 4) ++test_nft_v4;
        if (rr->type == 28 && rr->data_len == 16) ++test_nft_v6;
    }
    return 0;
}
static int test_nft_apply(md_nft *nft, const md_packet *r, char *err) {
    assert(nft); md_question parsed; assert(!md_dns_question(r, &parsed, err));
    pthread_mutex_lock(&test_lock); ++test_nft_calls; test_last_nft = *r;
    assert(!md_dns_records(r, test_nft_record, NULL, err)); bool failed = test_nft_fails;
    pthread_mutex_unlock(&test_lock);
    if (failed) { snprintf(err, MD_ERROR_SIZE, "injected nft update failure"); return -1; }
    atomic_fetch_add(&test_clock, test_nft_advance); return 0;
}
static md_packet test_resolve(md_engine *e, md_packet *q) {
    md_packet r = {0}; char err[MD_ERROR_SIZE] = {0};
    if (md_engine_query(e, 0, q, &r, err)) { fprintf(stderr, "query failed: %s\n", err); abort(); }
    assert(md_dns_response_matches(q, &r)); return r;
}
static void test_split_and_cnames(void) {
    test_reset(); md_engine *e = test_engine("", true);
    const char *names[] = {"www.cn", "exact.test", "sub.exact.test", "badcn", "a-needle.test", "asset-12.test", "alias.cn", "alias.foreign.test"};
    const bool cn[] = {true,true,false,false,true,true,true,false};
    for (size_t i = 0; i < sizeof(names)/sizeof(names[0]); ++i) {
        unsigned before[2] = {test_calls[0], test_calls[1]}, nft_before = test_nft_calls;
        md_packet q = test_question(names[i], 1, 0x0100), r = test_resolve(e, &q);
        assert(r.data[r.len-4] == (cn[i] ? 192 : 203));
        assert(test_calls[cn[i] ? 0 : 1] == before[cn[i] ? 0 : 1]+1);
        assert(test_calls[cn[i] ? 1 : 0] == before[cn[i] ? 1 : 0]);
        assert(test_nft_calls == nft_before + (cn[i] ? 1u : 0u));
        if (!strncmp(names[i], "alias.", 6)) assert(md_read16(r.data+6) == 2);
    }
    assert(test_last_concurrent[0] == 1 && test_last_concurrent[1] == 1);
    md_engine_free(e);
}
static void test_cache_keeps_nft(void) {
    test_reset(); md_engine *e = test_engine("", true);
    for (unsigned ipv6 = 0; ipv6 < 2; ++ipv6) {
        md_packet q = test_question(ipv6 ? "cache-v6.cn" : "cache-v4.cn", ipv6 ? 28 : 1, 0x0100);
        md_packet r = test_resolve(e, &q); assert(r.len);
        unsigned before = test_calls[0], nft_before = test_nft_calls;
        atomic_store(&test_clock, 104); md_write16(q.data, 4321);
        r.len = 999; assert(!md_engine_cached_query(e, 0, &q, &r) && !r.len);
        r = test_resolve(e, &q); assert(test_calls[0] == before && test_nft_calls == nft_before+1);
        assert(md_read16(test_last_nft.data) == 4321); assert(test_last_nft.len == r.len);
        assert(!memcmp(test_last_nft.data, r.data, r.len));
        md_question parsed; char err[MD_ERROR_SIZE]; assert(!md_dns_question(&r, &parsed, err));
        assert(md_read32(r.data + parsed.end + 6) == (ipv6 ? 60 : 56));
    }
    assert(test_nft_v4 == 2 && test_nft_v6 == 2);
    md_packet foreign = test_question("foreign.cache.test", 1, 0x0100); (void)test_resolve(e, &foreign); (void)test_resolve(e, &foreign);
    assert(test_calls[1] == 1 && test_nft_calls == 4);
    /* H1 dispatch: only a fresh foreign hit is answered by the event loop;
     * CN hits keep nft in the cached lane and misses go to their group's lane. */
    md_packet *d = calloc(1, sizeof(*d)); assert(d);
    md_write16(foreign.data, 777);
    assert(md_engine_dispatch(e, 0, &foreign, d) == MD_LANE_REPLY && md_read16(d->data) == 777);
    assert(md_dns_response_matches(&foreign, d) && md_engine_cached_query(e, 0, &foreign, d) && d->len);
    md_packet q = test_question("cache-v4.cn", 1, 0x0100);
    assert(md_engine_dispatch(e, 0, &q, d) == MD_LANE_CACHED && !d->len && !md_engine_cached_query(e, 0, &q, d));
    q = test_question("lane-miss.cn", 1, 0x0100); assert(md_engine_dispatch(e, 0, &q, d) == MD_LANE_CN && !d->len);
    q = test_question("lane-miss.test", 1, 0x0100); assert(md_engine_dispatch(e, 0, &q, d) == MD_LANE_FOREIGN && !d->len);
    assert(md_engine_dispatch(e, 1, &q, d) == MD_LANE_CACHED && !d->len);
    assert(test_calls[0] == 2 && test_calls[1] == 1 && test_nft_calls == 4);
    free(d); md_engine_free(e);
}
static void test_negative_and_isolation(void) {
    test_reset(); md_engine *e = test_engine("", true);
    md_packet q = test_question("nx.cn", 1, 0x0100), r = test_resolve(e, &q);
    assert((md_read16(r.data+2)&15) == 3 && !md_read16(r.data+6));
    md_write16(q.data, 2222); r = test_resolve(e, &q);
    assert(test_calls[0] == 1 && test_nft_calls == 2 && !test_nft_v4 && !test_nft_v6);
    assert(md_read16(r.data) == 2222); atomic_store(&test_clock, 131); (void)test_resolve(e, &q); assert(test_calls[0] == 2);
    unsigned before = test_calls[0];
    const uint16_t flags[] = {0x0100,0x0120,0x0110};
    for (size_t i = 0; i < sizeof(flags)/sizeof(flags[0]); ++i) {
        q = test_question("flags.cn", 1, flags[i]); (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    }
    q = test_question("flags.cn", 1, 0x0100); test_opt(&q, true); (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    q = test_question("flags.cn", 28, 0x0100); (void)test_resolve(e, &q);
    q = test_question("FLAGS.cn", 1, 0x0100); (void)test_resolve(e, &q);
    assert(test_calls[0] == before + 6);
    q = test_question("flags.cn", 1, 0x0100); md_write16(q.data+q.len-2, 3); (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    assert(test_calls[0] == before+8); md_engine_free(e);
    e = test_engine("", true); q = test_question("flags.cn", 1, 0x0100); (void)test_resolve(e, &q);
    assert(test_calls[0] == before+9); md_engine_free(e);
}
static void test_disabled_cache_and_group_options(void) {
    test_reset(); md_engine *e = test_engine("cache_size=0\ncn_mark=0xffffffff\nforeign_mark=42\ncn_interface=cn0\nforeign_interface=foreign0\ncn_concurrent=3\nforeign_concurrent=2\ncn_upstream=tcp://127.0.0.1:5311\nforeign_upstream=127.0.0.1:5312\n", true);
    md_packet q = test_question("twice.cn", 1, 0x0100); (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    assert(test_calls[0] == 2 && test_nft_calls == 2);
    q = test_question("twice.foreign.test", 1, 0x0100); (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    assert(test_calls[1] == 2 && test_nft_calls == 2);
    assert(test_last_count[0] == 2 && test_last_count[1] == 2);
    assert(test_last_concurrent[0] == 3 && test_last_concurrent[1] == 2);
    assert(test_last_mark[0] == UINT32_MAX && test_last_mark[1] == 42);
    assert(!strcmp(test_last_device[0], "cn0") && !strcmp(test_last_device[1], "foreign0")); md_engine_free(e);
}
static void test_failures_and_entry(void) {
    test_reset(); md_engine *e = test_engine("", true); char err[MD_ERROR_SIZE];
    md_packet q = test_question("failure.cn", 1, 0x0100), r = {0};
    test_forward_fails = true; assert(md_engine_query(e, 0, &q, &r, err)); assert(strstr(err, "upstream"));
    assert(!r.len && test_calls[0] == 1 && !test_calls[1] && !test_nft_calls);
    test_forward_fails = false; test_nft_fails = true;
    assert(md_engine_query(e, 0, &q, &r, err)); assert(strstr(err, "nft")); assert(test_calls[0] == 2 && test_nft_calls == 1);
    /* A cached response must retry failed nft finalization on every delivery. */
    assert(md_engine_query(e, 0, &q, &r, err)); assert(test_calls[0] == 2 && test_nft_calls == 2);
    test_nft_fails = false; (void)test_resolve(e, &q); assert(test_calls[0] == 2 && test_nft_calls == 3);
    assert(md_engine_query(e, 1, &q, &r, err) && !r.len);
    assert(md_engine_query(e, SIZE_MAX, &q, &r, err) && !r.len);
    q.len = 3; assert(md_engine_query(e, 0, &q, &r, err) && !r.len);
    assert(test_calls[0] == 2 && !test_calls[1]); md_engine_free(e);
    e = test_engine("", false); q = test_question("no-nft.cn", 1, 0x0100); (void)test_resolve(e, &q);
    unsigned before = test_nft_calls; (void)test_resolve(e, &q); assert(test_nft_calls == before); md_engine_free(e);
    e = md_engine_load(test_config, true, err); assert(e); assert(md_engine_query(e, 0, &q, &r, err) && !r.len); md_engine_free(e);
}
static void test_deadlines_and_null_errors(void) {
    test_reset(); md_engine *e = test_engine("", true); char err[MD_ERROR_SIZE];
    md_packet q = test_question("forward-deadline.cn", 1, 0x0100), r = {0};
    test_forward_advance = 5;
    assert(md_engine_query(e, 0, &q, &r, err)); assert(strstr(err, "deadline"));
    assert(r.len && test_calls[0] == 1 && !test_nft_calls);
    test_forward_advance = 0; md_write16(q.data, 9001); r = test_resolve(e, &q);
    assert(md_read16(r.data) == 9001 && test_calls[0] == 1 && test_nft_calls == 1);
    q = test_question("nft-deadline.cn", 1, 0x0100); test_nft_advance = 5;
    assert(md_engine_query(e, 0, &q, &r, err)); assert(strstr(err, "deadline"));
    assert(r.len && test_calls[0] == 2 && test_nft_calls == 2);
    test_nft_advance = 0; r = test_resolve(e, &q);
    assert(r.len && test_calls[0] == 2 && test_nft_calls == 3);
    test_nft_advance = 5; assert(md_engine_query(e, 0, &q, &r, NULL));
    test_nft_advance = 0; (void)test_resolve(e, &q);
    assert(test_calls[0] == 2 && test_nft_calls == 5);
    assert(md_engine_query(NULL, 0, &q, &r, NULL) && !r.len);
    assert(md_engine_query(e, 0, NULL, &r, NULL) && !r.len);
    assert(md_engine_query(e, 1, &q, &r, NULL) && !r.len);
    assert(md_engine_query(e, 0, &q, NULL, NULL));
    q.len = 3; assert(md_engine_query(e, 0, &q, &r, NULL) && !r.len);
    assert(!md_engine_load(NULL, true, NULL));
    assert(!md_engine_load("/definitely/missing/fixed-test.conf", true, NULL));
    md_engine_free(e);
}
static void test_lazy_refresh(void) {
    test_reset(); test_ttl = 1; md_engine *e = test_engine("cache_lazy_ttl=30\n", true);
    md_packet q = test_question("lazy.cn", 1, 0x0100); (void)test_resolve(e, &q);
    atomic_store(&test_clock, 102); pthread_mutex_lock(&test_lock); test_refresh_block = true; pthread_mutex_unlock(&test_lock);
    md_packet r = test_resolve(e, &q);
    struct timespec deadline; assert(!clock_gettime(CLOCK_REALTIME, &deadline)); deadline.tv_sec += 5;
    pthread_mutex_lock(&test_lock);
    while (!test_refresh_entered) assert(!pthread_cond_timedwait(&test_ready, &test_lock, &deadline));
    pthread_mutex_unlock(&test_lock);
    for (unsigned i = 0; i < 4; ++i) {
        md_write16(q.data, (uint16_t)(5000+i)); r = test_resolve(e, &q);
        md_question parsed; char err[MD_ERROR_SIZE]; assert(!md_dns_question(&r, &parsed, err));
        assert(md_read32(r.data+parsed.end+6) == 5);
    }
    pthread_mutex_lock(&test_lock);
    assert(test_calls[0] == 2 && !test_calls[1]); assert(test_nft_calls == 6);
    test_refresh_block = false; pthread_cond_broadcast(&test_ready); pthread_mutex_unlock(&test_lock);
    /* Free joins the blocked refresh before destroying cache or nft resources. */
    md_engine_free(e); assert(test_calls[0] == 2 && test_nft_calls == 7);
}
/* ---- cache policy: stale/refresh failure, prefetch, counters, override, warm-up ---- */
static unsigned test_stat(md_engine *e, unsigned group, unsigned counter) {
    md_cache_stats st; md_cache_get_stats(e->cache, &st); return (unsigned)st.v[group][counter];
}
/* Background refresh threads run on real time; wait until a counter reaches n. */
static void test_wait_stat(md_engine *e, unsigned group, unsigned counter, unsigned n) {
    for (unsigned i = 0; i < 5000 && test_stat(e, group, counter) < n; ++i) {
        struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL);
    }
    assert(test_stat(e, group, counter) >= n);
}
static uint32_t test_answer_ttl(const md_packet *r) {
    md_question parsed; char err[MD_ERROR_SIZE]; assert(!md_dns_question(r, &parsed, err));
    return md_read32(r->data + parsed.end + 6);
}
static void test_stale_refresh_failure(void) {
    test_reset(); test_ttl = 10; md_engine *e = test_engine("cache_stale_ttl=60\n", true);
    md_packet q = test_question("keep.foreign.test", 1, 0x0100), r = test_resolve(e, &q);
    assert(test_calls[1] == 1 && r.data[r.len-1] == 9 && test_answer_ttl(&r) == 10);
    /* SERVFAIL refresh: old positive kept, served stale with TTL 30 */
    atomic_store(&test_clock, 112); test_rcode = 2;
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9 && test_answer_ttl(&r) == 30 && !(md_read16(r.data+2) & 15));
    test_wait_stat(e, 1, MD_CS_REFRESH_FAIL, 1); assert(test_stat(e, 1, MD_CS_REFRESH_KEPT) == 1);
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9 && !(md_read16(r.data+2) & 15));
    assert(test_calls[1] == 2 && test_stat(e, 1, MD_CS_REFRESH_FAIL) == 1);
    atomic_store(&test_clock, 116); (void)test_resolve(e, &q); assert(test_calls[1] == 2);
    atomic_store(&test_clock, 117); (void)test_resolve(e, &q);
    test_wait_stat(e, 1, MD_CS_REFRESH_FAIL, 2);
    /* Second failure waits 10 s; transport timeout then also keeps old data. */
    test_rcode = 0; test_forward_fails = true; atomic_store(&test_clock, 120);
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9 && test_answer_ttl(&r) == 30);
    assert(test_calls[1] == 3);
    atomic_store(&test_clock, 127); (void)test_resolve(e, &q);
    test_wait_stat(e, 1, MD_CS_REFRESH_FAIL, 3);
    assert(test_stat(e, 1, MD_CS_REFRESH_KEPT) == 3);
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9 && test_calls[1] == 4);
    /* legitimate NXDOMAIN replaces */
    test_forward_fails = false; test_rcode = 3; atomic_store(&test_clock, 147);
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9); test_wait_stat(e, 1, MD_CS_REFRESH_OK, 1);
    r = test_resolve(e, &q); assert((md_read16(r.data+2) & 15) == 3);
    /* address change replaces */
    test_rcode = 0; q = test_question("move.foreign.test", 1, 0x0100); r = test_resolve(e, &q); assert(r.data[r.len-1] == 9);
    atomic_store(&test_clock, 158); test_addr = 77;
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 9); test_wait_stat(e, 1, MD_CS_REFRESH_OK, 2);
    r = test_resolve(e, &q); assert(r.data[r.len-1] == 77 && test_answer_ttl(&r) == 10);
    /* A failure retry deadline cannot extend the original hard cache deadline. */
    unsigned before = test_calls[1]; q = test_question("deadline.foreign.test", 1, 0x0100);
    atomic_store(&test_clock, 200); (void)test_resolve(e, &q);
    test_rcode = 2; atomic_store(&test_clock, 269); (void)test_resolve(e, &q); test_wait_stat(e, 1, MD_CS_REFRESH_FAIL, 4);
    atomic_store(&test_clock, 270); r = test_resolve(e, &q); assert((md_read16(r.data+2) & 15) == 2);
    assert(test_calls[1] == before + 3);
    /* CN group has no stale by default: expiry is a miss */
    test_rcode = 0; q = test_question("nostale.cn", 1, 0x0100); before = test_calls[0];
    (void)test_resolve(e, &q); atomic_store(&test_clock, 280); (void)test_resolve(e, &q); assert(test_calls[0] == before + 2);
    md_engine_free(e);
}
static void test_stale_override(void) {
    test_reset(); test_ttl = 10;
    char rules[600], extra[1400]; snprintf(rules, sizeof(rules), "%s/ddns.txt", test_directory);
    test_write(rules, "full:ddns.foreign.test\n");
    snprintf(extra, sizeof(extra), "cache_stale_ttl=60\ncache_stale_ttl_cn=30\ncache_stale_answer_ttl=20\ncache_stale_override=0:%s\n", rules);
    md_engine *e = test_engine(extra, true);
    md_packet d = test_question("ddns.foreign.test", 1, 0x0100), n = test_question("normal.foreign.test", 1, 0x0100), c = test_question("stale.cn", 1, 0x0100);
    (void)test_resolve(e, &d); (void)test_resolve(e, &n); (void)test_resolve(e, &c);
    atomic_store(&test_clock, 111); pthread_mutex_lock(&test_lock); test_refresh_block = true; pthread_mutex_unlock(&test_lock);
    unsigned cn_nft = test_nft_calls;
    md_packet r = test_resolve(e, &n); assert(test_answer_ttl(&r) == 20);
    r = test_resolve(e, &c); assert(test_answer_ttl(&r) == 20 && test_nft_calls == cn_nft + 1); /* stale CN still writes nft */
    pthread_mutex_lock(&test_lock); test_refresh_block = false; pthread_cond_broadcast(&test_ready); pthread_mutex_unlock(&test_lock);
    test_wait_stat(e, 1, MD_CS_REFRESH_OK, 1); test_wait_stat(e, 0, MD_CS_REFRESH_OK, 1);
    unsigned before = test_calls[1]; r = test_resolve(e, &d); assert(test_calls[1] == before + 1 && test_answer_ttl(&r) == 10);
    md_engine_free(e); assert(!unlink(rules));
}
static void test_prefetch(void) {
    test_reset(); test_ttl = 100; md_engine *e = test_engine("cache_prefetch_percent=10\ncache_prefetch_max=1\n", true);
    md_packet q = test_question("pf.foreign.test", 1, 0x0100), *d = calloc(1, sizeof(*d)), r; char err[MD_ERROR_SIZE];
    assert(d); (void)test_resolve(e, &q); assert(test_calls[1] == 1);
    md_dns_query qv = { .valid = false };
    atomic_store(&test_clock, 101); assert(md_engine_dispatch_q(e, 0, &q, &qv, d) == MD_LANE_REPLY);
    /* 5 s left (threshold 7..12): a reused fresh hit leaves the event loop for a worker */
    atomic_store(&test_clock, 195); qv = (md_dns_query){ .valid = false };
    assert(md_engine_dispatch_q(e, 0, &q, &qv, d) == MD_LANE_CACHED && qv.cache_memo == 1);
    assert(!md_engine_query_q(e, 0, &q, &qv, &r, err) && r.len && test_answer_ttl(&r) == 5);
    test_wait_stat(e, 1, MD_CS_REFRESH_OK, 1); assert(test_calls[1] == 2 && test_stat(e, 1, MD_CS_PREFETCH) == 1);
    /* refreshed in the background: answered from the event loop again with a full TTL */
    qv = (md_dns_query){ .valid = false };
    assert(md_engine_dispatch_q(e, 0, &q, &qv, d) == MD_LANE_REPLY && test_answer_ttl(d) == 100);
    /* counters: each request counted once across dispatch + worker */
    assert(test_stat(e, 1, MD_CS_COLD) == 1 && test_stat(e, 1, MD_CS_FRESH) == 3);
    md_engine_free(e);

    /* concurrency cap: second due prefetch is refused while one is in flight; CN prefetch writes nft */
    test_reset(); test_ttl = 100; e = test_engine("cache_prefetch_percent=10\ncache_prefetch_max=1\n", true);
    md_packet a = test_question("a.cn", 1, 0x0100), b = test_question("b.foreign.test", 1, 0x0100);
    (void)test_resolve(e, &a); (void)test_resolve(e, &b); (void)test_resolve(e, &a); (void)test_resolve(e, &b);
    assert(test_calls[0] == 1 && test_calls[1] == 1 && test_nft_calls == 2);
    atomic_store(&test_clock, 195); pthread_mutex_lock(&test_lock); test_refresh_block = true; pthread_mutex_unlock(&test_lock);
    (void)test_resolve(e, &a);
    struct timespec deadline; assert(!clock_gettime(CLOCK_REALTIME, &deadline)); deadline.tv_sec += 5;
    pthread_mutex_lock(&test_lock);
    while (!test_refresh_entered) assert(!pthread_cond_timedwait(&test_ready, &test_lock, &deadline));
    pthread_mutex_unlock(&test_lock);
    (void)test_resolve(e, &b); (void)test_resolve(e, &a);          /* capped / deduped: no new upstream query */
    pthread_mutex_lock(&test_lock); test_refresh_block = false; pthread_cond_broadcast(&test_ready); pthread_mutex_unlock(&test_lock);
    md_engine_free(e);
    assert(test_calls[0] == 2 && test_calls[1] == 1);
    assert(test_nft_calls == 5); /* a.cn: miss + hit + 2 hits at 195 + 1 prefetch resolve */
    free(d);
}
static void test_counters_and_bypass(void) {
    test_reset(); md_engine *e = test_engine("", true); char err[MD_ERROR_SIZE];
    md_packet *d = calloc(1, sizeof(*d)), r; assert(d);
    md_packet q = test_question("count.cn", 1, 0x0100); md_dns_query qv = { .valid = false };
    assert(md_engine_dispatch_q(e, 0, &q, &qv, d) == MD_LANE_CN); assert(!md_engine_query_q(e, 0, &q, &qv, &r, err));
    qv = (md_dns_query){ .valid = false };
    assert(md_engine_dispatch_q(e, 0, &q, &qv, d) == MD_LANE_CACHED); assert(!md_engine_query_q(e, 0, &q, &qv, &r, err));
    assert(test_stat(e, 0, MD_CS_COLD) == 1 && test_stat(e, 0, MD_CS_FRESH) == 1 && !test_stat(e, 1, MD_CS_COLD));
    q = test_question("ecs.foreign.test", 1, 0x0100);
    const uint8_t opt[] = {0,0,41,4,208,0,0,0,0,0,11,0,8,0,7,0,1,24,0,192,0,2};
    memcpy(q.data + q.len, opt, sizeof(opt)); q.len += sizeof(opt); md_write16(q.data+10, 1);
    (void)test_resolve(e, &q); (void)test_resolve(e, &q);
    assert(test_stat(e, 1, MD_CS_BYPASS) == 2 && test_calls[1] == 2);
    free(d); md_engine_free(e);
}
static size_t test_read_file(const char *path, char *out, size_t size) {
    FILE *f = fopen(path, "rb"); assert(f); size_t n = fread(out, 1, size - 1, f); out[n] = 0; assert(!fclose(f)); return n;
}
static void test_warm_file(void) {
    test_reset(); char warm[600], extra[1400], text[8192];
    snprintf(warm, sizeof(warm), "%s/warm.txt", test_directory);
    snprintf(extra, sizeof(extra), "cache_warm_file=%s\ncache_warm_qps=100\n", warm);
    md_engine *e = test_engine(extra, true);
    md_packet w1 = test_question("w1.foreign.test", 1, 0x0100), w2 = test_question("w2.cn", 28, 0x0100), once = test_question("once.foreign.test", 1, 0x0100);
    (void)test_resolve(e, &w1); (void)test_resolve(e, &w1); (void)test_resolve(e, &w2); (void)test_resolve(e, &w2); (void)test_resolve(e, &once);
    md_engine_free(e);
    test_read_file(warm, text, sizeof(text));
    assert(strstr(text, "0 1 w1.foreign.test\n") && strstr(text, "0 28 w2.cn\n") && !strstr(text, "once"));
    assert(!strstr(text, "203.0.113") && !strstr(text, "2001:db8"));
    /* junk lines are skipped; valid names are prewarmed through the resolver (CN via nft) */
    size_t n = strlen(text); snprintf(text + n, sizeof(text) - n, "bad\n0 1 a..b\n9 1 x.test\n0 5 x.test\n0 1 sp ace\n0 1 e\\x.test\n");
    test_write(warm, text);
    test_reset(); e = test_engine(extra, true);
    for (unsigned i = 0; i < 5000; ++i) {
        pthread_mutex_lock(&test_lock); unsigned total = test_calls[0] + test_calls[1]; pthread_mutex_unlock(&test_lock);
        if (total >= 2 && test_stat(e, 0, MD_CS_WARM) + test_stat(e, 1, MD_CS_WARM) >= 2) break;
        struct timespec ts = {0, 1000000}; nanosleep(&ts, NULL);
    }
    assert(test_stat(e, 1, MD_CS_WARM) == 1 && test_stat(e, 0, MD_CS_WARM) == 1);
    assert(test_nft_calls == 1 && test_nft_v6 == 1);
    unsigned before = test_calls[0] + test_calls[1];
    (void)test_resolve(e, &w1); (void)test_resolve(e, &w2);
    assert(test_calls[0] + test_calls[1] == before);
    assert(test_calls[0] + test_calls[1] == 2); /* only the two valid names were prewarmed */
    md_engine_free(e); assert(!unlink(warm));
}
static void test_warm_lifecycle(void) {
    test_reset(); char warm[600], extra[1400], text[8192], err[MD_ERROR_SIZE];
    snprintf(warm, sizeof(warm), "%s/warm-lifecycle.txt", test_directory);
    snprintf(extra, sizeof(extra), "cache_warm_file=%s\ncache_warm_qps=100\n", warm);
    /* Obtain a complete valid configuration, then leave its next engine in the
     * pre-listener stage, as when bind/worker setup fails. */
    md_engine *e = test_engine(extra, false); md_engine_free(e);
    const char *original = "# saved by an earlier run\n0 1 retained.foreign.test\n";
    test_write(warm, original);
    e = md_engine_load(test_config, false, err); assert(e && !e->runtime_started && !e->maintenance_running);
    md_engine_free(e); test_read_file(warm, text, sizeof(text)); assert(!strcmp(text, original));
    assert(!test_calls[0] && !test_calls[1]);
    /* Config validation may allocate a cache before a later option fails. */
    FILE *f = fopen(test_config, "a"); assert(f); assert(fputs("udp_sport_reuse=2\n", f) >= 0); assert(!fclose(f));
    assert(!md_engine_load(test_config, false, err));
    test_read_file(warm, text, sizeof(text)); assert(!strcmp(text, original));
    assert(!unlink(warm));
}
int main(void) {
    strcpy(test_directory, "/tmp/mosdns-fixed-engine-XXXXXX"); assert(mkdtemp(test_directory));
    snprintf(test_rules, sizeof(test_rules), "%s/cn.txt", test_directory);
    snprintf(test_config, sizeof(test_config), "%s/config.conf", test_directory);
    test_write(test_rules, "domain:cn\nfull:exact.test\nkeyword:needle\nregexp:^asset-[0-9]+\\.test$\n");
    test_split_and_cnames(); test_cache_keeps_nft(); test_negative_and_isolation();
    test_disabled_cache_and_group_options(); test_failures_and_entry(); test_deadlines_and_null_errors(); test_lazy_refresh();
    test_stale_refresh_failure(); test_stale_override(); test_prefetch(); test_counters_and_bypass(); test_warm_file(); test_warm_lifecycle();
    assert(!unlink(test_config)); assert(!unlink(test_rules)); assert(!rmdir(test_directory));
    assert(!pthread_cond_destroy(&test_ready)); assert(!pthread_mutex_destroy(&test_lock));
    puts("fixed engine: QNAME split, CNAME, cache+nft, A/AAAA, errors and lazy refresh passed"); return 0;
}
