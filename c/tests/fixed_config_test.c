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
    assert(!md_engine_listener(e, 1)); md_engine_free(e);
    accept_config("listen_tcp=[::1]:5300\ntcp_idle_timeout=86400\n");
    accept_config("# whole-line comment\n\n  # indented comment\ncache_size = 0\n");
    accept_config("cache_size=10000000\ncache_lazy_ttl=4294967295\ncn_mark=0xffffffff\nforeign_mark=4294967295\ncn_concurrent=3\nforeign_concurrent=3\n");
    accept_config("cn_mark=0\nforeign_mark=0x0\ncn_concurrent=1\nforeign_concurrent=1\ntcp_idle_timeout=1\n");
    accept_config("cn_interface=eth0.100\nforeign_interface=wg-test_0\n");
    accept_config("nftset_ipv4=inet,dns,cn4,ipv4_addr,32\nnftset_ipv6=inet,dns,cn6,ipv6_addr,128\n");
    accept_config("nftset_ipv4=ip,dns,cn4,ipv4_addr,1\nnftset_ipv6=ip6,dns,cn6,ipv6_addr,1\n");
    accept_config("cn_upstream=tcp://[::1]:5353\nforeign_upstream=udp://127.0.0.1:5353\n");
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
        "cn_interface=eth/0\n", "foreign_interface=eth\\0\n", "cn_interface=eth 0\n", "foreign_interface=eth\t0\n", "cn_interface=eth\0010\n",
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
        "nftset_ipv4=inet,t,s,ipv4_addr,32", "nftset_ipv6=inet,t,s,ipv6_addr,128"};
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
int main(void) {
    strcpy(test_dir, "/tmp/mosdns-fixed-config-XXXXXX"); assert(mkdtemp(test_dir));
    snprintf(config_path, sizeof(config_path), "%s/config.conf", test_dir);
    snprintf(rules_path, sizeof(rules_path), "%s/cn.txt", test_dir);
    const char *rules = "domain:cn\nfull:exact.test\n"; write_bytes(rules_path, rules, strlen(rules));
    snprintf(valid, sizeof(valid), "listen_udp=127.0.0.1:5300\ncn_domain_file=%s\ncn_upstream=127.0.0.1:5301\nforeign_upstream=127.0.0.1:5302\n", rules_path);
    basic_contract(); malformed_contract(); repeat_limits(); byte_limits(); literal_value_characters(); actual_rules_are_checked();
    assert(!unlink(config_path)); assert(!unlink(rules_path)); assert(!rmdir(test_dir));
    puts("fixed config: strict keys, bounds, lists, diagnostics and rules preflight passed"); return 0;
}
