/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Fixed key=value configuration contract. No listeners or nft writes are made. */
#define _POSIX_C_SOURCE 200809L
#define _DARWIN_C_SOURCE
#include "mosdns.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char test_dir[256], config_path[512], rules_path[512], valid[2048];

static void write_bytes(const char *path, const void *data, size_t size) {
    FILE *f = fopen(path, "wb"); assert(f);
    assert(fwrite(data, 1, size, f) == size); assert(!fclose(f));
}
static md_engine *load_bytes(const void *text, size_t size, bool check, char *err) {
    write_bytes(config_path, text, size);
    return md_engine_load(config_path, check, err);
}
static md_engine *load_text(const char *text, bool check, char *err) {
    return load_bytes(text, strlen(text), check, err);
}
static void expect_error(const void *text, size_t size, const char *source) {
    for (unsigned check = 0; check < 2; ++check) {
        char err[MD_ERROR_SIZE] = {0};
        md_engine *e = load_bytes(text, size, check != 0, err);
        if (e) { md_engine_free(e); fprintf(stderr, "invalid config accepted: %.*s\n", (int)(size < 400 ? size : 400), (const char *)text); abort(); }
        const char *where = strstr(err, source ? source : config_path);
        if (!where || where[strlen(source ? source : config_path)] != ':') {
            fprintf(stderr, "missing file:line in configuration error: %s\n", err); abort();
        }
        where += strlen(source ? source : config_path) + 1;
        assert(*where >= '0' && *where <= '9');
    }
}
static void reject(const char *extra) {
    char text[8192]; int n = snprintf(text, sizeof(text), "%s%s", valid, extra);
    assert(n > 0 && (size_t)n < sizeof(text)); expect_error(text, (size_t)n, NULL);
}
static void accept_config(const char *extra) {
    char text[8192], err[MD_ERROR_SIZE] = {0};
    int n = snprintf(text, sizeof(text), "%s%s", valid, extra); assert(n > 0 && (size_t)n < sizeof(text));
    md_engine *e = load_text(text, true, err);
    if (!e) { fprintf(stderr, "valid config rejected: %s\n%s", err, text); abort(); }
    md_engine_free(e);
}

static void basic_contract(void) {
    char err[MD_ERROR_SIZE] = {0};
    md_engine *e = load_text(valid, true, err); assert(e);
    assert(md_engine_listener_count(e) == 1);
    const md_listener *listener = md_engine_listener(e, 0); assert(listener);
    assert(!listener->tcp && listener->entry == 0 && listener->idle_timeout == 30);
    assert(!strcmp(listener->listen, "127.0.0.1:5300"));
    assert(!md_engine_listener(e, 1));
    const md_server_limits *limits = md_engine_server_limits(e); assert(limits);
    assert(limits->queue_timeout_ms == 2000 && limits->tcp_read_timeout == 5 && limits->tcp_write_timeout == 10);
    assert(limits->tcp_max_connections == 128 && limits->tcp_max_connections_per_ip == 32);
    assert(!md_engine_server_limits(NULL)); md_engine_free(e);
    accept_config("listen_tcp=[::1]:5300\ntcp_idle_timeout=86400\n");
    accept_config("# whole-line comment\n\n  # indented comment\ncache_size = 0\n");
    accept_config("cache_size=10000000\ncache_lazy_ttl=4294967295\ncn_mark=0xffffffff\nforeign_mark=4294967295\ncn_concurrent=3\nforeign_concurrent=3\n");
    accept_config("cn_mark=0\nforeign_mark=0x0\ncn_concurrent=1\nforeign_concurrent=1\ntcp_idle_timeout=1\n");
    accept_config("cn_interface=eth0.100\nforeign_interface=wg-test_0\n");
    accept_config("queue_timeout_ms=0\ntcp_read_timeout=1\ntcp_write_timeout=1\ntcp_max_connections=1\ntcp_max_connections_per_ip=1\n");
    accept_config("queue_timeout_ms=60000\ntcp_read_timeout=300\ntcp_write_timeout=300\ntcp_max_connections=1024\ntcp_max_connections_per_ip=1024\n");
    accept_config("nftset_fast=1\nnftset_ipv4=inet,dns,cn4,ipv4_addr,32\nnftset_ipv6=inet,dns,cn6,ipv6_addr,128\n");
    accept_config("nftset_ipv4=ip,dns,cn4,ipv4_addr,1\nnftset_ipv6=ip6,dns,cn6,ipv6_addr,1\n");
    accept_config("nftset_hit_window_ms=0\nnftset_ipv4=inet,dns,cn4,ipv4_addr,32\n");
    accept_config("nftset_hit_window_ms=10000\nnftset_fast=1\nnftset_ipv4=inet,dns,cn4,ipv4_addr,32\n");
    accept_config("udp_sport_reuse=0\n");
    accept_config("udp_sport_reuse=1\nudp_sport_reuse_max_uses=16\nudp_sport_reuse_ttl_ms=2000\nudp_sport_reuse_pool=2\n");
    accept_config("udp_sport_reuse=1\nudp_sport_reuse_max_uses=1\nudp_sport_reuse_ttl_ms=100\nudp_sport_reuse_pool=1\n");
    accept_config("udp_sport_reuse=1\nudp_sport_reuse_max_uses=256\nudp_sport_reuse_ttl_ms=60000\nudp_sport_reuse_pool=4\n");
    accept_config("cn_upstream=tcp://[::1]:5353\nforeign_upstream=udp://127.0.0.1:5353\n");
    accept_config("cn_upstream_hedge_ms=100\ncn_upstream_timeout_ms=1000\nforeign_upstream_hedge_ms=250\nforeign_upstream_timeout_ms=1500\n");
    reject("cn_upstream_hedge_ms=2001\n");
    reject("foreign_upstream_timeout_ms=99\n");
    reject("cn_upstream_timeout_ms=5001\n");
    reject("foreign_upstream_hedge_ms=500\nforeign_upstream_timeout_ms=500\n");
    /* Final newline is optional and CRLF is accepted. */
    accept_config("cache_size=1"); accept_config("cache_size=1\r\n");
    const char *missing[] = {"", "# comments only\n", "listen_udp=127.0.0.1:5300\n", "cn_domain_file=/missing\n"};
    for (size_t i = 0; i < sizeof(missing)/sizeof(missing[0]); ++i)
        expect_error(missing[i], strlen(missing[i]), NULL);
    const char *keys[] = {"listen_udp", "cn_domain_file", "cn_upstream", "foreign_upstream"};
    for (size_t i = 0; i < sizeof(keys)/sizeof(keys[0]); ++i) {
        char text[2048]; strcpy(text, valid);
        char *start = strstr(text, keys[i]); assert(start); char *end = strchr(start, '\n'); assert(end);
        memmove(start, end + 1, strlen(end + 1) + 1);
        expect_error(text, strlen(text), NULL);
    }
}
static void malformed_contract(void) {
    const char *bad[] = {
        "plugins=[]\n", "include=other.conf\n", "unknown_key=1\n", "cache_size\n", "=1\n", "cache_size=\n",
        "cache_size=-1\n", "cache_size=+1\n", "cache_size=1.0\n", "cache_size=0x20\n", "cache_size=10000001\n",
        "cache_size=0\ncache_lazy_ttl=1\n", "cache_lazy_ttl=4294967296\n", "cache_lazy_ttl=-1\n", "cache_lazy_ttl=1x\n",
        "cn_mark=4294967296\n", "foreign_mark=0x100000000\n", "cn_mark=0x\n", "cn_mark=-1\n", "cn_mark=+1\n", "cn_mark=1e2\n",
        "cn_concurrent=0\n", "cn_concurrent=4\n", "foreign_concurrent=-1\n", "foreign_concurrent=4294967296\n",
        "tcp_idle_timeout=0\n", "tcp_idle_timeout=86401\n", "tcp_idle_timeout=-1\n",
        "queue_timeout_ms=60001\n", "queue_timeout_ms=-1\n", "queue_timeout_ms=2s\n",
        "tcp_read_timeout=0\n", "tcp_read_timeout=301\n", "tcp_write_timeout=0\n", "tcp_write_timeout=301\n",
        "tcp_max_connections=0\n", "tcp_max_connections=1025\n",
        "tcp_max_connections_per_ip=0\n", "tcp_max_connections_per_ip=1025\n",
        "cn_interface=eth/0\n", "foreign_interface=eth\\0\n", "cn_interface=eth 0\n", "foreign_interface=eth\t0\n", "cn_interface=eth\0010\n",
        "nftset_fast=1\n", "nftset_fast=2\n", "nftset_fast=1\nnftset_ipv4=inet,t,s,ipv4_addr,24\n",
        "udp_sport_reuse=2\n", "udp_sport_reuse_max_uses=0\n", "udp_sport_reuse_max_uses=257\n",
        "udp_sport_reuse_ttl_ms=99\n", "udp_sport_reuse_ttl_ms=60001\n",
        "udp_sport_reuse_pool=0\n", "udp_sport_reuse_pool=5\n",
        "nftset_hit_window_ms=1000\n", "nftset_hit_window_ms=10001\nnftset_ipv4=inet,t,s,ipv4_addr,32\n",
        "nftset_hit_window_ms=-1\nnftset_ipv4=inet,t,s,ipv4_addr,32\n",
        "cache_size=10 # inline comments are not supported\n", "cache_size='10'\n", "cache_size=\"10\"\n", "cache_size=${CACHE_SIZE}\n",
        "listen_udp=localhost:53\n", "listen_tcp=127.0.0.1:65536\n", "listen_udp=udp://127.0.0.1:53\n",
        "cn_upstream=https://1.1.1.1/dns-query\n", "foreign_upstream=tls://1.1.1.1\n", "cn_upstream=resolver.test\n", "cn_upstream=127.0.0.1:0\n",
        "nftset_ipv4=inet,t,s,ipv6_addr,32\n", "nftset_ipv6=inet,t,s,ipv4_addr,32\n",
        "nftset_ipv4=ip6,t,s,ipv4_addr,32\n", "nftset_ipv6=ip,t,s,ipv6_addr,128\n",
        "nftset_ipv4=bridge,t,s,ipv4_addr,32\n", "nftset_ipv4=inet,t,s,ipv4_addr,0\n", "nftset_ipv6=inet,t,s,ipv6_addr,0\n",
        "nftset_ipv4=inet,t,s,ipv4_addr,33\n", "nftset_ipv6=inet,t,s,ipv6_addr,129\n", "nftset_ipv4=inet,t,s,ipv4_addr,-1\n",
        "nftset_ipv4=inet,t,s,ipv4_addr,32,extra\n", "nftset_ipv4=inet,t,s,ipv4_addr\n", "nftset_ipv4=inet,,s,ipv4_addr,32\n",
        "nftset_ipv4=inet,t,s,ipv4_addr,32 inet,t,z,ipv4_addr,32\n", "nftset_ipv4=inet,t,bad;set,ipv4_addr,32\n"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) reject(bad[i]);
    const char *single[] = {"cache_size=1", "cache_lazy_ttl=0", "cn_mark=0", "foreign_mark=0",
        "cn_interface=lo", "foreign_interface=lo", "cn_concurrent=1", "foreign_concurrent=1", "tcp_idle_timeout=30",
        "queue_timeout_ms=2000", "tcp_read_timeout=5", "tcp_write_timeout=10", "tcp_max_connections=128",
        "tcp_max_connections_per_ip=32",
        "nftset_ipv4=inet,t,s,ipv4_addr,32", "nftset_ipv6=inet,t,s,ipv6_addr,128",
        "udp_sport_reuse=0", "udp_sport_reuse_max_uses=16", "udp_sport_reuse_ttl_ms=2000",
        "udp_sport_reuse_pool=2", "nftset_hit_window_ms=1000"};
    for (size_t i = 0; i < sizeof(single)/sizeof(single[0]); ++i) {
        char extra[1024]; snprintf(extra, sizeof(extra), "%s\n%s\n", single[i], single[i]); reject(extra);
    }
    char interface[128]; strcpy(interface, "cn_interface="); memset(interface + strlen(interface), 'a', 63);
    interface[strlen("cn_interface=") + 63] = '\0'; accept_config(interface);
    strcat(interface, "a"); reject(interface);
    char embedded[4096]; size_t n = strlen(valid); memcpy(embedded, valid, n);
    memcpy(embedded + n, "cache_size=1\0trailing\n", sizeof("cache_size=1\0trailing\n") - 1);
    expect_error(embedded, n + sizeof("cache_size=1\0trailing\n") - 1, NULL);
}
static void repeat_limits(void) {
    const char *keys[] = {"cn_domain_file", "cn_upstream", "foreign_upstream"};
    const char *values[] = {rules_path, "127.0.0.1:5301", "tcp://127.0.0.1:5302"};
    char text[65536], err[MD_ERROR_SIZE] = {0};
    for (unsigned mode = 0; mode < 3; ++mode) {
        size_t used = 0;
        for (unsigned k = 0; k < 64; ++k) {
            const char *key = mode == 0 || (mode == 2 && k < 32) ? "listen_udp" : "listen_tcp";
            used += (size_t)snprintf(text + used, sizeof(text) - used, "%s=127.0.0.1:%u\n", key, 5300+k);
        }
        for (size_t i = 0; i < 3; ++i)
            for (unsigned k = 0; k < 64; ++k)
                used += (size_t)snprintf(text + used, sizeof(text) - used, "%s=%s\n", keys[i], values[i]);
        assert(used < sizeof(text)); md_engine *e = load_text(text, true, err);
        if (!e) { fprintf(stderr, "64 repeat limit rejected: %s\n", err); abort(); }
        assert(md_engine_listener_count(e) == 64); md_engine_free(e);
        size_t n = (size_t)snprintf(text + used, sizeof(text) - used, "listen_udp=127.0.0.1:5400\n");
        expect_error(text, used+n, NULL);
        n = (size_t)snprintf(text + used, sizeof(text) - used, "listen_tcp=127.0.0.1:5400\n");
        expect_error(text, used+n, NULL);
        for (size_t i = 0; i < 3; ++i) {
            n = (size_t)snprintf(text + used, sizeof(text) - used, "%s=%s\n", keys[i], values[i]);
            expect_error(text, used+n, NULL);
        }
    }
    reject("listen_udp=127.0.0.1:5300\n");
    reject("listen_udp=127.0.0.1:05300\n");
    reject("listen_tcp=127.0.0.1:0\n");
}
static void byte_limits(void) {
    size_t base = strlen(valid); char *text = malloc(1024 * 1024 + 2); assert(text);
    memcpy(text, valid, base); text[base] = '#'; memset(text + base + 1, 'x', 4095); text[base + 4096] = '\n';
    char err[MD_ERROR_SIZE] = {0}; md_engine *e = load_bytes(text, base + 4097, true, err); assert(e); md_engine_free(e);
    text[base + 4096] = 'x'; text[base + 4097] = '\n'; expect_error(text, base + 4098, NULL);
    size_t used = base;
    while (used < 1024 * 1024) {
        size_t left = 1024 * 1024 - used, line = left < 4096 ? left : 4096;
        text[used] = '#'; if (line > 1) memset(text + used + 1, 'x', line - 1);
        if (line > 1) text[used + line - 1] = '\n';
        used += line;
    }
    e = load_bytes(text, used, true, err);
    if (!e) { fprintf(stderr, "exact 1 MiB config rejected: %s\n", err); abort(); }
    md_engine_free(e); text[used] = '\n'; expect_error(text, used + 1, NULL); free(text);
}
static void literal_value_characters(void) {
    char path[512], text[4096], err[MD_ERROR_SIZE] = {0};
    snprintf(path, sizeof(path), "%s/cn#literal;equals=.txt", test_dir);
    const char *rules = "full:literal.test\n";
    write_bytes(path, rules, strlen(rules));
    snprintf(text, sizeof(text), "%scn_domain_file=%s\n", valid, path);
    md_engine *e = load_text(text, true, err);
    if (!e) { fprintf(stderr, "literal #/;/= path rejected: %s\n", err); abort(); }
    md_engine_free(e); assert(!unlink(path));
}
static void actual_rules_are_checked(void) {
    char text[4096]; snprintf(text, sizeof(text), "%scn_domain_file=%s/missing.txt\n", valid, test_dir);
    expect_error(text, strlen(text), NULL);
    const char *bad = "# valid first line\nfull:valid.test\nregexp:[\n";
    write_bytes(rules_path, bad, strlen(bad)); expect_error(valid, strlen(valid), NULL);
    /* Both diagnostics retain the config location and the rule source location. */
    char err[MD_ERROR_SIZE] = {0}; md_engine *e = load_text(valid, true, err); assert(!e);
    assert(strstr(err, rules_path)); assert(strstr(err, "3"));
    const char *good = "domain:cn\nfull:exact.test\n"; write_bytes(rules_path, good, strlen(good));
}
static void cache_policy_contract(void) {
    char extra[2048];
    accept_config("cache_stale_ttl=0\n"); accept_config("cache_stale_ttl=86400\ncache_stale_ttl_cn=30\ncache_stale_answer_ttl=300\n");
    accept_config("cache_prefetch_percent=10\ncache_prefetch_max=64\ncache_max_bytes=4096\ncache_foreign_reserve_percent=90\n");
    accept_config("cache_max_bytes=0\ncache_prefetch_percent=0\n");
    snprintf(extra, sizeof(extra), "cache_stale_ttl=60\ncache_stale_override=0:%s\ncache_stale_override=10:%s\n", rules_path, rules_path); accept_config(extra);
    snprintf(extra, sizeof(extra), "cache_warm_file=%s/warm.txt\ncache_warm_max=10000\ncache_warm_qps=100\ncache_warm_save_interval=30\n", test_dir); accept_config(extra);
    const char *bad[] = {
        "cache_stale_ttl=86401\n", "cache_stale_ttl=-1\n", "cache_stale_ttl_cn=86401\n", "cache_stale_answer_ttl=0\n", "cache_stale_answer_ttl=301\n",
        "cache_prefetch_percent=51\n", "cache_prefetch_max=0\n", "cache_prefetch_max=65\ncache_prefetch_percent=10\n", "cache_prefetch_max=8\n",
        "cache_max_bytes=4095\n", "cache_max_bytes=4294967296\n", "cache_foreign_reserve_percent=91\n",
        "cache_lazy_ttl=30\ncache_stale_ttl=30\n", "cache_lazy_ttl=30\ncache_stale_ttl_cn=30\n",
        "cache_size=0\ncache_stale_ttl=30\n", "cache_size=0\ncache_prefetch_percent=10\n",
        "cache_warm_max=10\n", "cache_warm_qps=10\n", "cache_warm_save_interval=60\n",
        "cache_warm_file=/tmp/x\ncache_warm_qps=0\n", "cache_warm_file=/tmp/x\ncache_warm_qps=101\n",
        "cache_warm_file=/tmp/x\ncache_warm_save_interval=29\n", "cache_warm_file=/tmp/x\ncache_warm_max=0\n",
        "cache_stale_override=60\n", "cache_stale_override=60:\n", "cache_stale_override=x:/tmp/r\n", "cache_stale_override=86401:/tmp/r\n",
        "cache_stale_override=0:/definitely/missing/stale.txt\n"
    };
    for (size_t i = 0; i < sizeof(bad)/sizeof(bad[0]); ++i) reject(bad[i]);
    snprintf(extra, sizeof(extra), "cache_lazy_ttl=30\ncache_stale_override=0:%s\n", rules_path); reject(extra);
    size_t used = 0;
    for (unsigned i = 0; i < 9; ++i) used += (size_t)snprintf(extra + used, sizeof(extra) - used, "cache_stale_override=1:%s\n", rules_path);
    assert(used < sizeof(extra)); reject(extra);
    const char *single[] = {"cache_stale_ttl=1", "cache_stale_ttl_cn=1", "cache_stale_answer_ttl=1", "cache_prefetch_percent=1",
        "cache_max_bytes=0", "cache_foreign_reserve_percent=1", "cache_warm_file=/tmp/x"};
    for (size_t i = 0; i < sizeof(single)/sizeof(single[0]); ++i) {
        snprintf(extra, sizeof(extra), "%s\n%s\n", single[i], single[i]); reject(extra);
    }
}
int main(void) {
    strcpy(test_dir, "/tmp/mosdns-fixed-config-XXXXXX"); assert(mkdtemp(test_dir));
    snprintf(config_path, sizeof(config_path), "%s/config.conf", test_dir);
    snprintf(rules_path, sizeof(rules_path), "%s/cn.txt", test_dir);
    const char *rules = "domain:cn\nfull:exact.test\n"; write_bytes(rules_path, rules, strlen(rules));
    snprintf(valid, sizeof(valid), "listen_udp=127.0.0.1:5300\ncn_domain_file=%s\ncn_upstream=127.0.0.1:5301\nforeign_upstream=127.0.0.1:5302\n", rules_path);
    basic_contract(); malformed_contract(); repeat_limits(); byte_limits(); literal_value_characters(); actual_rules_are_checked(); cache_policy_contract();
    assert(!unlink(config_path)); assert(!unlink(rules_path)); assert(!rmdir(test_dir));
    puts("fixed config: strict keys, bounds, lists, diagnostics and rules preflight passed"); return 0;
}
