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
#define md_forward test_forward
#define md_nft_apply test_nft_apply
#define md_now test_now
#include "../coremain/engine.c"
#undef md_forward
#undef md_nft_apply
#undef md_now

static char test_directory[256], test_rules[512], test_config[512];
static atomic_uint_fast64_t test_clock;
static pthread_mutex_t test_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t test_ready = PTHREAD_COND_INITIALIZER;
static unsigned test_calls[2], test_nft_calls, test_nft_v4, test_nft_v6;
static unsigned test_last_concurrent[2];
static size_t test_last_count[2];
static uint32_t test_last_mark[2], test_ttl;
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
    test_ttl = 60; test_last_nft.len = 0; test_forward_advance = test_nft_advance = 0;
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
    bool failed = test_forward_fails; uint32_t ttl = test_ttl; pthread_mutex_unlock(&test_lock);
    if (failed) { r->len = 0; snprintf(err, MD_ERROR_SIZE, "injected upstream transport failure"); return -1; }
    md_question parsed; assert(!md_dns_question(q, &parsed, err));
    unsigned rcode = !strncmp(parsed.name, "nx.", 3) ? 3 : 0; assert(!md_dns_error(q, r, rcode));
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
        const uint8_t cn[] = {192,0,2,9}, foreign[] = {203,0,113,9};
        test_add_record(r, 1, group ? foreign : cn, sizeof(cn), ttl);
    }
    if (target_offset) md_write16(r->data + address_offset, (uint16_t)(0xc000 | target_offset));
    assert(md_dns_response_matches(q, r)); atomic_fetch_add(&test_clock, test_forward_advance); return 0;
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
    assert(test_calls[1] == 1 && test_nft_calls == 4); md_engine_free(e);
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
int main(void) {
    strcpy(test_directory, "/tmp/mosdns-fixed-engine-XXXXXX"); assert(mkdtemp(test_directory));
    snprintf(test_rules, sizeof(test_rules), "%s/cn.txt", test_directory);
    snprintf(test_config, sizeof(test_config), "%s/config.conf", test_directory);
    test_write(test_rules, "domain:cn\nfull:exact.test\nkeyword:needle\nregexp:^asset-[0-9]+\\.test$\n");
    test_split_and_cnames(); test_cache_keeps_nft(); test_negative_and_isolation();
    test_disabled_cache_and_group_options(); test_failures_and_entry(); test_deadlines_and_null_errors(); test_lazy_refresh();
    assert(!unlink(test_config)); assert(!unlink(test_rules)); assert(!rmdir(test_directory));
    assert(!pthread_cond_destroy(&test_ready)); assert(!pthread_mutex_destroy(&test_lock));
    puts("fixed engine: QNAME split, CNAME, cache+nft, A/AAAA, errors and lazy refresh passed"); return 0;
}
