/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 专用 CN/国外分流：配置只描述资源，执行顺序不是可配置的插件图。
 * 原始 QNAME 选择唯一上游组；包括缓存命中在内的 CN 响应均经过 nft。
 * DNS、缓存、规则、上游和 nft 的实现复用原有模块。 */
#define _POSIX_C_SOURCE 200809L
#include "mosdns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

#define CONFIG_LINE_MAX 4096
#define CONFIG_FILE_MAX (1024 * 1024)
#define CONFIG_LIST_MAX 64

typedef enum {
    LISTEN_UDP, LISTEN_TCP, CN_FILE, CN_UPSTREAM, FOREIGN_UPSTREAM,
    CACHE_SIZE, CACHE_LAZY, CN_MARK, FOREIGN_MARK, CN_INTERFACE, FOREIGN_INTERFACE,
    CN_CONCURRENT, FOREIGN_CONCURRENT, TCP_IDLE, NFT4, NFT6, NFT_FAST,
    QUEUE_TIMEOUT, TCP_READ, TCP_WRITE, TCP_MAX, TCP_MAX_IP,
    UDP_SPORT_REUSE, UDP_SPORT_REUSE_MAX_USES, UDP_SPORT_REUSE_TTL_MS, UDP_SPORT_REUSE_POOL,
    NFT_HIT_WINDOW,
    CACHE_STALE, CACHE_STALE_CN, CACHE_STALE_ANSWER, CACHE_STALE_OVERRIDE,
    CACHE_PREFETCH, CACHE_PREFETCH_MAX, CACHE_MAX_BYTES, CACHE_FOREIGN_RESERVE,
    CACHE_WARM_FILE, CACHE_WARM_MAX, CACHE_WARM_QPS, CACHE_WARM_SAVE,
    KEY_COUNT
} config_key;
static const char *const key_names[KEY_COUNT] = {
    "listen_udp", "listen_tcp", "cn_domain_file", "cn_upstream", "foreign_upstream",
    "cache_size", "cache_lazy_ttl", "cn_mark", "foreign_mark", "cn_interface", "foreign_interface",
    "cn_concurrent", "foreign_concurrent", "tcp_idle_timeout", "nftset_ipv4", "nftset_ipv6", "nftset_fast",
    "queue_timeout_ms", "tcp_read_timeout", "tcp_write_timeout", "tcp_max_connections", "tcp_max_connections_per_ip",
    "udp_sport_reuse", "udp_sport_reuse_max_uses", "udp_sport_reuse_ttl_ms", "udp_sport_reuse_pool",
    "nftset_hit_window_ms",
    "cache_stale_ttl", "cache_stale_ttl_cn", "cache_stale_answer_ttl", "cache_stale_override",
    "cache_prefetch_percent", "cache_prefetch_max", "cache_max_bytes", "cache_foreign_reserve_percent",
    "cache_warm_file", "cache_warm_max", "cache_warm_qps", "cache_warm_save_interval"
};
/* 可重复（列表）键；其余键只能出现一次。 */
static bool list_key(size_t k) { return k <= FOREIGN_UPSTREAM || k == CACHE_STALE_OVERRIDE; }
#define STALE_OVERRIDE_MAX 8
typedef struct { char *text; size_t line; } config_value;
typedef struct { config_value values[CONFIG_LIST_MAX]; size_t count; } config_values;
typedef struct { config_values keys[KEY_COUNT]; size_t last_line; } config;
typedef struct refresh_job refresh_job;
typedef struct { md_upstream *items; size_t count; unsigned concurrent; } upstream_group;
typedef struct { uint32_t seconds; md_domain *domains; } stale_override;
struct md_engine {
    md_domain *cn;
    md_cache *cache;
    md_nft *nft;
    upstream_group upstreams[2]; /* 0 CN, 1 foreign */
    md_listener *listeners; size_t listener_count;
    md_server_limits limits;
    bool check, stopping;
    pthread_mutex_t lock;
    pthread_cond_t wake; bool wake_ok;
    refresh_job *jobs;
    stale_override overrides[STALE_OVERRIDE_MAX]; size_t override_count;
    uint32_t prefetch_max, warm_max, warm_qps, warm_save, stats_interval;
    char *warm_file;
    pthread_t maintenance; bool maintenance_running;
};
struct refresh_job {
    pthread_t thread;
    md_engine *engine;
    md_packet query;
    md_dns_query qv; /* 前台请求解析结果的副本，刷新线程不再解析请求 */
    bool cn, done, prefetch;
    refresh_job *next;
};

static int fail(char *err, const char *format, ...) {
    if (err) {
        va_list ap; va_start(ap, format); vsnprintf(err, MD_ERROR_SIZE, format, ap); va_end(ap);
    }
    return -1;
}
static int config_error(char *err, const char *path, size_t line, const char *detail) {
    char copy[MD_ERROR_SIZE];
    snprintf(copy, sizeof(copy), "%s", detail);
    return fail(err, "%s:%zu: %s", path, line, copy);
}
static bool space(unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f'; }
static char *trim(char *text) {
    while (space((unsigned char)*text)) text++;
    size_t n = strlen(text);
    while (n && space((unsigned char)text[n-1])) text[--n] = 0;
    return text;
}
static void config_free(config *c) {
    for (size_t k = 0; k < KEY_COUNT; k++)
        for (size_t i = 0; i < c->keys[k].count; i++) free(c->keys[k].values[i].text);
}
static int parse_line(config *c, char *text, const char *path, size_t line, char *err) {
    char *key = trim(text);
    if (!*key || *key == '#') return 0;
    char *equal = strchr(key, '=');
    if (!equal) return config_error(err, path, line, "expected key=value");
    *equal = 0; key = trim(key); char *value = trim(equal + 1);
    if (!*value) return config_error(err, path, line, "empty value");
    size_t k;
    for (k = 0; k < KEY_COUNT; k++) if (!strcmp(key, key_names[k])) break;
    if (k == KEY_COUNT) return config_error(err, path, line, "unknown configuration key");
    config_values *v = &c->keys[k];
    if ((!list_key(k) && v->count) || v->count == CONFIG_LIST_MAX)
        return config_error(err, path, line, !list_key(k) ? "duplicate single-value key" : "list exceeds 64 entries");
    char *copy = strdup(value);
    if (!copy) return config_error(err, path, line, "out of memory");
    v->values[v->count++] = (config_value){copy, line};
    return 0;
}
/* Bounded byte reader: no getline allocation and no strlen before NUL validation.
 * Only whole-line comments; '#' and ';' inside a value remain literal bytes. */
static int config_read(config *c, const char *path, char *err) {
    FILE *f = fopen(path, "rb");
    if (!f) { char detail[MD_ERROR_SIZE]; snprintf(detail, sizeof(detail), "read config: %s", strerror(errno)); return config_error(err, path, 1, detail); }
    char line[CONFIG_LINE_MAX + 1]; size_t used = 0, total = 0, number = 1;
    int ch, rc = -1;
    while ((ch = fgetc(f)) != EOF) {
        if (++total > CONFIG_FILE_MAX) { config_error(err, path, number, "configuration exceeds 1 MiB"); goto done; }
        if (!ch) { config_error(err, path, number, "embedded NUL"); goto done; }
        if (ch == '\n') {
            line[used] = 0;
            if (parse_line(c, line, path, number, err)) goto done;
            used = 0; number++; continue;
        }
        if ((ch < 32 && !space((unsigned char)ch)) || ch == 127) { config_error(err, path, number, "invalid control character"); goto done; }
        if (used == CONFIG_LINE_MAX) { config_error(err, path, number, "line exceeds 4096 bytes"); goto done; }
        line[used++] = (char)ch;
    }
    if (ferror(f)) { config_error(err, path, number, "configuration read failed"); goto done; }
    line[used] = 0;
    if (used && parse_line(c, line, path, number, err)) goto done;
    c->last_line = number; rc = 0;
done:
    fclose(f); return rc;
}
static const char *value(const config *c, config_key key) {
    return c->keys[key].count ? c->keys[key].values[0].text : "";
}
static size_t key_line(const config *c, config_key key) {
    return c->keys[key].count ? c->keys[key].values[0].line : c->last_line;
}
/* No signs, octal, trailing garbage, or unchecked integer overflow. Hex marks
 * only; decimal leading zeros remain decimal. */
static int number(const char *s, uint32_t max, bool hex, uint32_t *out) {
    unsigned base = 10; uint32_t result = 0;
    if (hex && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) { base = 16; s += 2; }
    if (!*s) return -1;
    for (; *s; s++) {
        unsigned char ch = (unsigned char)*s; unsigned digit;
        if (ch >= '0' && ch <= '9') digit = ch - '0';
        else if (base == 16 && ch >= 'a' && ch <= 'f') digit = ch - 'a' + 10;
        else if (base == 16 && ch >= 'A' && ch <= 'F') digit = ch - 'A' + 10;
        else return -1;
        if (digit >= base || digit > max || result > (max-digit)/base) return -1;
        result = result * base + digit;
    }
    *out = result; return 0;
}
static int config_number(const config *c, config_key key, uint32_t fallback, uint32_t min, uint32_t max, bool hex, uint32_t *out, const char *path, char *err) {
    if (!c->keys[key].count) { *out = fallback; return 0; }
    if (number(value(c, key), max, hex, out) || *out < min) {
        char detail[160]; snprintf(detail, sizeof(detail), "invalid number for %s (range %u..%u)", key_names[key], min, max);
        return config_error(err, path, key_line(c, key), detail);
    }
    return 0;
}
static int build_upstreams(md_engine *e, const config *c, bool foreign, const char *path, char *err) {
    config_key addresses = foreign ? FOREIGN_UPSTREAM : CN_UPSTREAM;
    config_key mark_key = foreign ? FOREIGN_MARK : CN_MARK;
    config_key device_key = foreign ? FOREIGN_INTERFACE : CN_INTERFACE;
    config_key concurrent_key = foreign ? FOREIGN_CONCURRENT : CN_CONCURRENT;
    const char *device = value(c, device_key); uint32_t mark, concurrent;
    if (config_number(c, mark_key, 0, 0, UINT32_MAX, true, &mark, path, err) ||
        config_number(c, concurrent_key, 1, 1, 3, false, &concurrent, path, err)) return -1;
    if (strlen(device) >= 64 || strpbrk(device, " /\\\t\r\n\v\f"))
        return config_error(err, path, key_line(c, device_key), "invalid interface (1..63 bytes, no whitespace or slash)");
    for (const unsigned char *p = (const unsigned char *)device; *p; p++)
        if (*p < 33 || *p > 126) return config_error(err, path, key_line(c, device_key), "interface must use printable ASCII");
    upstream_group *group = &e->upstreams[foreign ? 1 : 0];
    group->count = c->keys[addresses].count; group->concurrent = concurrent;
    group->items = calloc(group->count, sizeof(*group->items));
    if (!group->items) return config_error(err, path, key_line(c, addresses), "out of memory");
    for (size_t i = 0; i < group->count; i++) {
        const config_value *v = &c->keys[addresses].values[i];
        if (md_upstream_init(&group->items[i], v->text, NULL, mark, device, err))
            return config_error(err, path, v->line, err);
    }
    return 0;
}
static int build_listeners(md_engine *e, const config *c, const char *path, char *err) {
    uint32_t idle;
    if (config_number(c, TCP_IDLE, 30, 1, 86400, false, &idle, path, err)) return -1;
    e->listener_count = c->keys[LISTEN_UDP].count + c->keys[LISTEN_TCP].count;
    if (e->listener_count > 64) return config_error(err, path, c->last_line, "combined UDP/TCP listener count exceeds 64");
    e->listeners = calloc(e->listener_count, sizeof(*e->listeners));
    if (!e->listeners) return config_error(err, path, c->last_line, "out of memory");
    size_t n = 0;
    for (unsigned kind = LISTEN_UDP; kind <= LISTEN_TCP; kind++) {
        for (size_t i = 0; i < c->keys[kind].count; i++) {
            const config_value *v = &c->keys[kind].values[i];
            struct sockaddr_storage addr; socklen_t len;
            if (strlen(v->text) >= sizeof(e->listeners[n].listen) ||
                (v->text[0] == ':' && !strchr(v->text+1, ':')) ||
                md_parse_address(v->text, 53, &addr, &len, err))
                return config_error(err, path, v->line, "invalid numeric listener address");
            if ((addr.ss_family == AF_INET && !((struct sockaddr_in *)&addr)->sin_port) ||
                (addr.ss_family == AF_INET6 && !((struct sockaddr_in6 *)&addr)->sin6_port))
                return config_error(err, path, v->line, "listener port must be nonzero");
            for (size_t j = 0; j < n; j++) if (e->listeners[j].tcp == (kind == LISTEN_TCP)) {
                struct sockaddr_storage previous; socklen_t previous_len;
                if (!md_parse_address(e->listeners[j].listen, 53, &previous, &previous_len, err) &&
                    len == previous_len && !memcmp(&addr, &previous, len))
                    return config_error(err, path, v->line, "duplicate listener address");
            }
            strcpy(e->listeners[n].listen, v->text);
            e->listeners[n].tcp = kind == LISTEN_TCP; e->listeners[n].idle_timeout = idle;
            e->listeners[n++].entry = 0;
        }
    }
    /* 排队超过 queue_timeout_ms 的任务不再访问上游；TCP 一帧须在读期限内收完，
     * 一个回复须在写期限内写完；连接数超限时淘汰最久无活动的空闲连接。 */
    uint32_t queue, read, write, total, per_ip;
    if (config_number(c, QUEUE_TIMEOUT, 2000, 0, 60000, false, &queue, path, err) ||
        config_number(c, TCP_READ, 5, 1, 300, false, &read, path, err) ||
        config_number(c, TCP_WRITE, 10, 1, 300, false, &write, path, err) ||
        config_number(c, TCP_MAX, 128, 1, 1024, false, &total, path, err) ||
        config_number(c, TCP_MAX_IP, 32, 1, 1024, false, &per_ip, path, err)) return -1;
    e->limits = (md_server_limits){queue, read, write, total, per_ip};
    return 0;
}
/* Validate one address family per key rather than permitting the generic nft
 * parser's second specification/last-wins behavior or zero-mask shorthand. */
static int validate_nft(const char *s, bool ipv6, char *err) {
    char copy[512];
    if (strlen(s) >= sizeof(copy) || strpbrk(s, " \t\r\n\v\f")) return fail(err, "invalid nftset specification");
    strcpy(copy, s); char *parts[5], *p = copy;
    for (unsigned i = 0; i < 5; i++) {
        parts[i] = p; char *comma = strchr(p, ',');
        if ((i < 4 && !comma) || (i == 4 && comma)) return fail(err, "nftset requires family,table,set,address_type,mask");
        if (comma) { *comma = 0; p = comma + 1; }
    }
    uint32_t mask;
    if ((strcmp(parts[0], "inet") && strcmp(parts[0], ipv6 ? "ip6" : "ip")) ||
        strcmp(parts[3], ipv6 ? "ipv6_addr" : "ipv4_addr") ||
        number(parts[4], ipv6 ? 128 : 32, false, &mask) || !mask)
        return fail(err, "nftset family/type/mask does not match key");
    md_nft *test = md_nft_new(s, err);
    if (!test) return -1;
    md_nft_free(test); return 0;
}
/* 缓存策略键：新键全部默认关闭/不改变旧行为（见 docs/fixed-splitter.md）。 */
static int build_cache(md_engine *e, const config *c, uint32_t capacity, uint32_t lazy, const char *path, char *err) {
    uint32_t stale, stale_cn, answer, prefetch, prefetch_max, max_bytes, reserve, warm_max, warm_qps, warm_save;
    if (config_number(c, CACHE_STALE, 0, 0, 86400, false, &stale, path, err) ||
        config_number(c, CACHE_STALE_CN, 0, 0, 86400, false, &stale_cn, path, err) ||
        config_number(c, CACHE_STALE_ANSWER, 0, 1, 300, false, &answer, path, err) ||
        config_number(c, CACHE_PREFETCH, 0, 0, 50, false, &prefetch, path, err) ||
        config_number(c, CACHE_PREFETCH_MAX, 8, 1, 64, false, &prefetch_max, path, err) ||
        config_number(c, CACHE_MAX_BYTES, 0, 0, UINT32_MAX, false, &max_bytes, path, err) ||
        config_number(c, CACHE_FOREIGN_RESERVE, 0, 0, 90, false, &reserve, path, err) ||
        config_number(c, CACHE_WARM_MAX, 512, 1, 10000, false, &warm_max, path, err) ||
        config_number(c, CACHE_WARM_QPS, 10, 1, 100, false, &warm_qps, path, err) ||
        config_number(c, CACHE_WARM_SAVE, 600, 30, 86400, false, &warm_save, path, err)) return -1;
    for (config_key k = CACHE_STALE; k <= CACHE_WARM_SAVE; k++)
        if (c->keys[k].count && !capacity) {
            char detail[128]; snprintf(detail, sizeof(detail), "%s requires nonzero cache_size", key_names[k]);
            return config_error(err, path, key_line(c, k), detail);
        }
    if (lazy && (c->keys[CACHE_STALE].count || c->keys[CACHE_STALE_CN].count || c->keys[CACHE_STALE_OVERRIDE].count))
        return config_error(err, path, key_line(c, CACHE_LAZY), "cache_lazy_ttl (legacy total retention) cannot be combined with cache_stale_ttl/cache_stale_ttl_cn/cache_stale_override");
    if (max_bytes && max_bytes < 4096)
        return config_error(err, path, key_line(c, CACHE_MAX_BYTES), "cache_max_bytes must be 0 or at least 4096");
    for (config_key k = CACHE_WARM_MAX; k <= CACHE_WARM_SAVE; k++)
        if (c->keys[k].count && !c->keys[CACHE_WARM_FILE].count) {
            char detail[128]; snprintf(detail, sizeof(detail), "%s requires cache_warm_file", key_names[k]);
            return config_error(err, path, key_line(c, k), detail);
        }
    if (c->keys[CACHE_PREFETCH_MAX].count && !prefetch)
        return config_error(err, path, key_line(c, CACHE_PREFETCH_MAX), "cache_prefetch_max requires cache_prefetch_percent");
    const config_values *ov = &c->keys[CACHE_STALE_OVERRIDE];
    if (ov->count > STALE_OVERRIDE_MAX) return config_error(err, path, ov->values[STALE_OVERRIDE_MAX].line, "cache_stale_override exceeds 8 entries");
    for (size_t i = 0; i < ov->count; i++) {
        char copy[CONFIG_LINE_MAX + 1]; snprintf(copy, sizeof(copy), "%s", ov->values[i].text);
        char *colon = strchr(copy, ':'); uint32_t sec;
        if (!colon || !colon[1]) return config_error(err, path, ov->values[i].line, "cache_stale_override expects <seconds>:<domain file>");
        *colon = 0;
        if (number(copy, 86400, false, &sec)) return config_error(err, path, ov->values[i].line, "invalid cache_stale_override seconds (range 0..86400)");
        stale_override *o = &e->overrides[e->override_count];
        if (!(o->domains = md_domain_new())) return config_error(err, path, ov->values[i].line, "out of memory");
        o->seconds = sec; e->override_count++;
        if (md_domain_load(o->domains, colon + 1, err)) return config_error(err, path, ov->values[i].line, err);
    }
    const char *warm = value(c, CACHE_WARM_FILE);
    if (*warm && (strlen(warm) > 1000 || strpbrk(warm, "\t\r\n")))
        return config_error(err, path, key_line(c, CACHE_WARM_FILE), "invalid cache_warm_file path");
    if (*warm && !(e->warm_file = strdup(warm))) return config_error(err, path, key_line(c, CACHE_WARM_FILE), "out of memory");
    e->prefetch_max = prefetch_max; e->warm_max = warm_max; e->warm_qps = warm_qps; e->warm_save = warm_save;
    md_cache_options o = {0};
    o.lazy_ttl = lazy; o.stale_ttl[MD_CACHE_CN] = stale_cn; o.stale_ttl[MD_CACHE_FOREIGN] = stale;
    o.stale_answer_ttl = answer; o.max_bytes = max_bytes; o.foreign_reserve_percent = reserve; o.prefetch_percent = prefetch;
    if (capacity && !e->check && !(e->cache = md_cache_new_ex(capacity, &o)))
        return config_error(err, path, key_line(c, CACHE_SIZE), "cannot allocate cache");
    return 0;
}
static int build_config(md_engine *e, const config *c, const char *path, char *err) {
    if (!c->keys[LISTEN_UDP].count && !c->keys[LISTEN_TCP].count)
        return config_error(err, path, c->last_line, "at least one listen_udp or listen_tcp is required");
    for (config_key k = CN_FILE; k <= FOREIGN_UPSTREAM; k++) if (!c->keys[k].count) {
        char detail[128]; snprintf(detail, sizeof(detail), "%s is required", key_names[k]);
        return config_error(err, path, c->last_line, detail);
    }
    uint32_t capacity, lazy;
    if (config_number(c, CACHE_SIZE, 1024, 0, 10000000, false, &capacity, path, err) ||
        config_number(c, CACHE_LAZY, 0, 0, UINT32_MAX, false, &lazy, path, err)) return -1;
    if (!capacity && lazy) return config_error(err, path, key_line(c, CACHE_LAZY), "cache_lazy_ttl requires nonzero cache_size");
    if (build_upstreams(e, c, false, path, err) || build_upstreams(e, c, true, path, err) ||
        build_listeners(e, c, path, err)) return -1;
    char nft[1025] = "";
    for (config_key k = NFT4; k <= NFT6; k++) if (c->keys[k].count) {
        if (validate_nft(value(c, k), k == NFT6, err)) return config_error(err, path, key_line(c, k), err);
        if (*nft) strcat(nft, " ");
        strcat(nft, value(c, k));
    }
    if (*nft && !(e->nft = md_nft_new(nft, err))) return config_error(err, path, key_line(c, NFT4), err);
    uint32_t fast;
    if (config_number(c, NFT_FAST, 0, 0, 1, false, &fast, path, err)) return -1;
    if (fast && (!e->nft || md_nft_enable_fast(e->nft, err)))
        return config_error(err, path, key_line(c, NFT_FAST), e->nft ? err : "nftset_fast requires a target");
    /* 热命中跳过窗口：默认 1000 ms，0 关闭（每次 CN 命中都核对/写入内核）。 */
    uint32_t hit_window;
    if (config_number(c, NFT_HIT_WINDOW, 1000, 0, 10000, false, &hit_window, path, err)) return -1;
    if (c->keys[NFT_HIT_WINDOW].count && !e->nft)
        return config_error(err, path, key_line(c, NFT_HIT_WINDOW), "nftset_hit_window_ms requires a target");
    if (e->nft) md_nft_set_hit_window(e->nft, hit_window);
    /* Read-only GETSET: warn (never fail) about interval targets lacking auto-merge. */
    md_nft_audit(e->nft);
    e->cn = md_domain_new();
    if (!e->cn) return config_error(err, path, key_line(c, CN_FILE), "out of memory");
    /* check reads actual rule files and compiles PCRE2, but never opens a
     * listener/upstream connection or changes kernel state; the only nft access
     * is the read-only metadata warning above.
     * A named IPv6 scope is resolved against the host interface list. */
    for (size_t i = 0; i < c->keys[CN_FILE].count; i++) {
        const config_value *v = &c->keys[CN_FILE].values[i];
        if (md_domain_load(e->cn, v->text, err)) return config_error(err, path, v->line, err);
    }
    if (build_cache(e, c, capacity, lazy, path, err)) return -1;
    /* Opt-in UDP source-port reuse. Default off keeps M4 per-query new ports.
     * Applied only after the rest of the config succeeds so a failed load cannot
     * leave a previous process-wide setting from a partial parse. */
    uint32_t reuse, max_uses, ttl_ms, pool;
    if (config_number(c, UDP_SPORT_REUSE, 0, 0, 1, false, &reuse, path, err) ||
        config_number(c, UDP_SPORT_REUSE_MAX_USES, 16, 1, 256, false, &max_uses, path, err) ||
        config_number(c, UDP_SPORT_REUSE_TTL_MS, 2000, 100, 60000, false, &ttl_ms, path, err) ||
        config_number(c, UDP_SPORT_REUSE_POOL, 2, 1, 4, false, &pool, path, err)) return -1;
    md_udp_sport_reuse sport = { reuse, max_uses, ttl_ms, pool };
    md_forward_set_udp_sport_reuse(&sport);
    return 0;
}

/* view 是 response 当前内容的整包校验结果（上游接收或缓存命中时各解析一次）；
 * TTL 规范化只原地改 TTL，view 仍然有效，随后 nft 与缓存写入共用它。 */
static int finalize(md_engine *e, bool cn, md_packet *response, md_dns_view *view, uint64_t deadline, char *err) {
    if (md_now() >= deadline) return fail(err, "query execution deadline exceeded");
    if (response->len && md_dns_normalize_ttl_view(response, view, err)) return -1;
    md_trace_mark(MD_T_NFT0);
    int rc = cn && e->nft && response->len ? md_nft_apply_view(e->nft, response, view, err) : 0;
    md_trace_mark(MD_T_NFT1);
    if (!rc && md_now() >= deadline) rc = fail(err, "query execution deadline exceeded");
    return rc;
}
/* A forwarding error never crosses from CN to foreign or vice versa. Store
 * otherwise valid answers even if nft finalization fails, as before. */
/* 按域名覆盖 stale 秒数（首个匹配生效）；-1 使用组默认值。只在写入缓存时匹配。 */
static bool route_cn(md_engine *e, md_dns_query *qv);
static int64_t stale_for(const md_engine *e, const md_dns_query *qv) {
    for (size_t i = 0; i < e->override_count; i++)
        if (md_domain_match(e->overrides[i].domains, qv->q.name)) return e->overrides[i].seconds;
    return -1;
}
static int resolve_ex(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv, md_packet *response, uint64_t deadline, bool refresh, char *err);
static int resolve(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv, md_packet *response, uint64_t deadline, char *err) {
    return resolve_ex(e, cn, query, qv, response, deadline, false, err);
}
/* refresh=true：后台刷新/prefetch/预热。CN 答案同样经 finalize 写 nft，
 * 使新地址在客户端使用前进入集合；SERVFAIL 不会覆盖仍有效的正向旧答案。 */
static int resolve_ex(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv, md_packet *response, uint64_t deadline, bool refresh, char *err) {
    if (md_now() >= deadline) return fail(err, "query execution deadline exceeded");
    upstream_group *group = &e->upstreams[cn ? 0 : 1];
    md_dns_view *view = md_dns_view_scratch();
    if (!view) return fail(err, "out of memory for DNS view");
    md_trace_mark(MD_T_UP_SEND);
    int rc = md_forward_q(group->items, group->count, group->concurrent, query, qv, response, view, err);
    md_trace_mark(MD_T_UP_RECV);
    /* md_forward_view 只交出已校验的响应；防御性地在 view 缺失时重新解析。 */
    if (response->len && (!view->valid || view->len != response->len) && md_dns_view_parse(response, view, err)) {
        response->len = 0; return -1;
    }
    if (!rc) rc = finalize(e, cn, response, view, deadline, err);
    if (response->len && e->cache) {
        md_cache_put_opts po = { cn ? MD_CACHE_CN : MD_CACHE_FOREIGN, e->override_count ? stale_for(e, qv) : -1, refresh };
        (void)md_cache_put_ex(e->cache, query, qv, response, view, md_now(), &po);
    }
    return rc;
}
static void *refresh_thread(void *opaque) {
    refresh_job *job = opaque;
    md_packet *response = calloc(1, sizeof(*response)); char err[MD_ERROR_SIZE] = {0};
    md_trace tr; memset(&tr, 0, sizeof(tr));
    if (md_trace_enabled) { tr.flags = MD_TF_REFRESH_JOB; tr.t[MD_T_ENGINE0] = md_now_ns(); md_trace_cur = &tr; }
    int rc = -1;
    bool ok = false;
    if (response) {
        rc = resolve_ex(job->engine, job->cn, &job->query, &job->qv, response, md_now() + 5, true, err);
        ok = response->len >= 12 && (md_read16(response->data + 2) & 15) != 2;
        free(response);
    }
    if (md_trace_enabled) {
        md_trace_cur = NULL; tr.t[MD_T_ENGINE1] = md_now_ns();
        if (rc) tr.flags |= MD_TF_ERROR;
        md_trace_emit(&tr, &job->query);
    }
    md_cache_refresh_end_q(job->engine->cache, &job->query, &job->qv);
    /* 计数在释放去重占位之后：观察到计数即可再次发起同 key 刷新。 */
    md_cache_count(job->engine->cache, job->cn ? MD_CACHE_CN : MD_CACHE_FOREIGN, ok ? MD_CS_REFRESH_OK : MD_CS_REFRESH_FAIL);
    pthread_mutex_lock(&job->engine->lock); job->done = true; pthread_mutex_unlock(&job->engine->lock);
    return NULL;
}
/* stale 刷新与 prefetch 共用去重占位（同一 key 只有一个在途刷新）；
 * 总线程上限 64，prefetch 另受 cache_prefetch_max 限制。 */
static void refresh_start(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv, bool prefetch) {
    pthread_mutex_lock(&e->lock);
    refresh_job **link = &e->jobs; size_t active = 0, prefetching = 0;
    while (*link) {
        refresh_job *job = *link;
        if (job->done) { *link = job->next; pthread_join(job->thread, NULL); free(job); }
        else { active++; prefetching += job->prefetch; link = &job->next; }
    }
    if (e->stopping || active >= 64 || (prefetch && prefetching >= e->prefetch_max) ||
        !md_cache_refresh_begin_q(e->cache, query, qv)) {
        pthread_mutex_unlock(&e->lock); return;
    }
    refresh_job *job = calloc(1, sizeof(*job));
    if (!job) { md_cache_refresh_end_q(e->cache, query, qv); pthread_mutex_unlock(&e->lock); return; }
    job->engine = e; job->query = *query; job->qv = *qv; job->cn = cn; job->prefetch = prefetch; job->next = e->jobs;
    if (md_thread_create(&job->thread, refresh_thread, job)) { md_cache_refresh_end_q(e->cache, query, qv); free(job); }
    else { e->jobs = job; md_trace_flag(MD_TF_REFRESH_START); }
    pthread_mutex_unlock(&e->lock);
}
/* ---- restart warm-up (names only, never addresses) ---- */
static void print_cache_stats(md_engine *e) {
    md_cache_stats st; md_cache_get_stats(e->cache, &st);
    static const char *const groups[2] = {"cn", "foreign"};
    for (unsigned g = 0; g < 2; ++g) {
        char line[1024]; int used = snprintf(line, sizeof(line), "cache stats %s: entries=%zu bytes=%llu", groups[g], st.entries[g], (unsigned long long)st.bytes[g]);
        for (unsigned i = 0; i < MD_CS_COUNT && used > 0 && (size_t)used < sizeof(line); ++i)
            used += snprintf(line + used, sizeof(line) - (size_t)used, " %s=%llu", md_cache_stat_names[i], (unsigned long long)st.v[g][i]);
        fprintf(stderr, "%s\n", line);
    }
}
/* 原子写：同目录临时文件 + fsync + rename；失败只告警，不影响服务。 */
static int warm_save(md_engine *e) {
    if (!e->warm_file || !e->cache) return 0;
    size_t size = (size_t)e->warm_max * 272 + 64; char *buf = malloc(size);
    if (!buf) return -1;
    int head = snprintf(buf, size, "# diversion-dns cache warm v1 (names only)\n");
    size_t lines = md_cache_hot_names(e->cache, buf + head, size - (size_t)head, e->warm_max); (void)lines;
    size_t len = strlen(buf);
    char tmp[1100]; snprintf(tmp, sizeof(tmp), "%s.tmp.%ld", e->warm_file, (long)getpid());
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600), rc = -1;
    if (fd >= 0) {
        size_t off = 0;
        while (off < len) { ssize_t n = write(fd, buf + off, len - off); if (n <= 0) { if (n < 0 && errno == EINTR) continue; break; } off += (size_t)n; }
        if (off == len && !fsync(fd)) rc = 0;
        if (close(fd)) rc = -1;
        if (!rc && rename(tmp, e->warm_file)) rc = -1;
        if (rc) unlink(tmp);
    }
    if (rc) fprintf(stderr, "cache warm: cannot save %s: %s\n", e->warm_file, strerror(errno));
    free(buf); return rc;
}
static bool warm_label_char(unsigned char ch) {
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '*';
}
/* "<keyflags> <qtype> <name>" -> 与原客户端同一缓存 key 的查询（AD/CD/DO 位还原）。 */
static int warm_query(const char *line, md_packet *q) {
    unsigned flags, type; char name[256], extra;
    if (sscanf(line, "%u %u %255s %c", &flags, &type, name, &extra) != 3 || flags > 7 || (type != 1 && type != 28)) return -1;
    memset(q, 0, sizeof(*q));
    md_write16(q->data, (uint16_t)(rand() & 0xffff));
    md_write16(q->data + 2, (uint16_t)(0x0100 | ((flags & 1) ? 0x20 : 0) | ((flags & 2) ? 0x10 : 0)));
    md_write16(q->data + 4, 1); size_t len = 12, label = 0;
    for (const char *p = name;; ++p) {
        if (*p == '.' || !*p) {
            size_t n = (size_t)(p - name) - label;
            if (!n || n > 63) return -1;
            q->data[len++] = (uint8_t)n; memcpy(q->data + len, name + label, n); len += n; label = (size_t)(p - name) + 1;
            if (!*p) break;
        } else if (!warm_label_char((unsigned char)*p)) return -1;
        if (len > 250) return -1;
    }
    q->data[len++] = 0; md_write16(q->data + len, (uint16_t)type); md_write16(q->data + len + 2, 1); len += 4;
    if (flags & 4) {
        const uint8_t opt[] = {0,0,41,4,208,0,0,0x80,0,0,0};
        memcpy(q->data + len, opt, sizeof(opt)); len += sizeof(opt); md_write16(q->data + 10, 1);
    }
    q->len = len; return 0;
}
/* 可被 stopping 打断的实时等待；返回 true 表示应退出。 */
static bool maintenance_wait(md_engine *e, uint64_t ms) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += (time_t)(ms / 1000); ts.tv_nsec += (long)(ms % 1000) * 1000000L;
    if (ts.tv_nsec >= 1000000000L) { ts.tv_sec++; ts.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&e->lock);
    while (!e->stopping && pthread_cond_timedwait(&e->wake, &e->lock, &ts) != ETIMEDOUT) {}
    bool stop = e->stopping; pthread_mutex_unlock(&e->lock); return stop;
}
/* 启动预热：顺序、限速（cache_warm_qps）、单线程，经正常 resolve 路径，
 * 所以 CN 答案照常经 nft finalize 学习集合；已在缓存中的名称跳过。 */
static void warm_load(md_engine *e) {
    FILE *f = fopen(e->warm_file, "rb");
    if (!f) return;
    md_packet *q = malloc(sizeof(*q)), *r = malloc(sizeof(*r)), *probe = malloc(sizeof(*probe));
    char line[400]; uint32_t done = 0; uint64_t pace = 1000 / e->warm_qps;
    while (q && r && probe && done < e->warm_max && fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || warm_query(line, q)) continue;
        md_dns_query qv; char err[MD_ERROR_SIZE];
        if (md_dns_query_parse(q, &qv, err)) continue;
        bool cn = route_cn(e, &qv);
        if (md_cache_get_ex(e->cache, q, &qv, probe, NULL, md_now(), cn ? 0 : 1, 0, NULL) == 1) continue;
        if (maintenance_wait(e, pace)) break;
        r->len = 0; ++done;
        (void)resolve_ex(e, cn, q, &qv, r, md_now() + 5, true, err);
        md_cache_count(e->cache, cn ? MD_CACHE_CN : MD_CACHE_FOREIGN, MD_CS_WARM);
    }
    free(q); free(r); free(probe); fclose(f);
    fprintf(stderr, "cache warm: prewarmed %u names from %s\n", (unsigned)done, e->warm_file);
}
static void *maintenance_thread(void *opaque) {
    md_engine *e = opaque;
    if (e->warm_file) warm_load(e);
    uint64_t since_save = 0, since_stats = 0;
    while (!maintenance_wait(e, 1000)) {
        if (e->warm_file && ++since_save >= e->warm_save) { since_save = 0; (void)warm_save(e); }
        if (e->stats_interval && ++since_stats >= e->stats_interval) { since_stats = 0; print_cache_stats(e); }
    }
    return NULL;
}
md_engine *md_engine_load(const char *path, bool check, char *err) {
    char scratch_error[MD_ERROR_SIZE] = {0};
    if (!err) err = scratch_error;
    if (!path) { fail(err, "<config>:1: configuration path is required"); return NULL; }
    md_engine *e = calloc(1, sizeof(*e));
    if (!e) { config_error(err, path, 1, "out of memory"); return NULL; }
    e->check = check;
    if (pthread_mutex_init(&e->lock, NULL)) { free(e); config_error(err, path, 1, "cannot initialize engine mutex"); return NULL; }
    config c = {0};
    int rc = config_read(&c, path, err);
    if (!rc) rc = build_config(e, &c, path, err);
    config_free(&c);
    if (!rc && !pthread_cond_init(&e->wake, NULL)) e->wake_ok = true;
    else if (!rc) rc = config_error(err, path, 1, "cannot initialize engine condition");
    if (!rc && !check && e->cache) {
        const char *env = getenv("DIVERSION_CACHE_STATS");
        unsigned long n = env ? strtoul(env, NULL, 10) : 0;
        e->stats_interval = n >= 5 && n <= 86400 ? (uint32_t)n : 0;
        if ((e->warm_file || e->stats_interval) && !md_thread_create(&e->maintenance, maintenance_thread, e))
            e->maintenance_running = true;
    }
    if (rc) { md_engine_free(e); return NULL; }
    return e;
}
size_t md_engine_listener_count(const md_engine *e) { return e ? e->listener_count : 0; }
const md_listener *md_engine_listener(const md_engine *e, size_t i) { return e && i < e->listener_count ? &e->listeners[i] : NULL; }
const md_server_limits *md_engine_server_limits(const md_engine *e) { return e ? &e->limits : NULL; }
/* 只有国外组的新鲜缓存命中在事件循环直接回复：它不写 nft、不触发刷新，
 * finalize 只做 TTL 规范化，与 worker 路径结果相同。CN 命中仍须经 nft，
 * stale 命中须启动刷新，二者都进入不访问上游的缓存 lane；其余按上游组分 lane，
 * 一个上游组卡住不会占满另一组或缓存命中的 worker 与排队配额。 */
/* 分流备忘：同一请求在 dispatch 与 worker 中只做一次域名匹配。 */
static bool route_cn(md_engine *e, md_dns_query *qv) {
    if (qv->route < 0) qv->route = md_domain_match(e->cn, qv->q.name) ? 1 : 0;
    return qv->route == 1;
}
unsigned md_engine_dispatch(md_engine *e, size_t entry, const md_packet *q, md_packet *r) {
    md_dns_query qv = { .valid = false };
    return md_engine_dispatch_q(e, entry, q, &qv, r);
}
unsigned md_engine_dispatch_q(md_engine *e, size_t entry, const md_packet *q, md_dns_query *qv, md_packet *r) {
    if (r) r->len = 0;
    /* Invalid input fails fast in md_engine_query without upstream I/O. */
    if (!e || !q || !r || !qv || entry || e->check) return MD_LANE_CACHED;
    char err[MD_ERROR_SIZE];
    if (!md_dns_query_ok(q, qv) && md_dns_query_parse(q, qv, err)) return MD_LANE_CACHED;
    bool cn = route_cn(e, qv);
    /* 只有国外新鲜命中在此回复：才需要解析（一次，finalize 复用）；
     * CN 命中仅探测状态，由 worker 的 md_engine_query 解析唯一一次。 */
    md_dns_view *view = cn ? NULL : md_dns_view_scratch();
    if (!cn && !view) return MD_LANE_CACHED;
    /* 每个请求在此计数一次（命中/未命中原因）并认领 prefetch，结果记入
     * qv->cache_memo，worker 不重复计数。需要 prefetch 的国外新鲜命中转入
     * 缓存 lane，由 worker 启动后台刷新，事件循环不创建线程。 */
    md_cache_hit info;
    int hit = md_cache_get_ex(e->cache, q, qv, r, view, md_now(), cn ? MD_CACHE_CN : MD_CACHE_FOREIGN,
                              MD_CACHE_COUNT | MD_CACHE_CLAIM, &info);
    if (e->cache) qv->cache_memo = info.prefetch_due ? 1 : 0;
    if (hit == 1 && !cn && !info.prefetch_due && !finalize(e, false, r, view, md_now() + 5, err)) { md_trace_flag(MD_TF_HIT_FRESH); return MD_LANE_REPLY; }
    r->len = 0;
    if (hit) return MD_LANE_CACHED;
    return cn ? MD_LANE_CN : MD_LANE_FOREIGN;
}
bool md_engine_cached_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r) {
    return md_engine_dispatch(e, entry, q, r) == MD_LANE_REPLY;
}
int md_engine_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r, char *err) {
    md_dns_query qv = { .valid = false };
    return md_engine_query_q(e, entry, q, &qv, r, err);
}
int md_engine_query_q(md_engine *e, size_t entry, const md_packet *q, md_dns_query *qv, md_packet *r, char *err) {
    char scratch_error[MD_ERROR_SIZE] = {0};
    if (!err) err = scratch_error;
    if (!r) return fail(err, "response is required");
    r->len = 0;
    if (!e || !q || !qv || entry) return fail(err, "invalid fixed splitter entry/query");
    if (e->check) return fail(err, "checked configuration cannot execute queries");
    uint64_t deadline = md_now() + 5;
    if (!md_dns_query_ok(q, qv) && md_dns_query_parse(q, qv, err)) return -1;
    bool cn = route_cn(e, qv);
    md_dns_view *view = md_dns_view_scratch();
    if (!view) return fail(err, "out of memory for DNS view");
    md_trace_mark(MD_T_ENGINE0);
    md_cache_hit info; bool counted = qv->cache_memo >= 0;
    int hit = md_cache_get_ex(e->cache, q, qv, r, view, md_now(), cn ? MD_CACHE_CN : MD_CACHE_FOREIGN,
                              counted ? 0u : MD_CACHE_COUNT | MD_CACHE_CLAIM, &info);
    bool prefetch = counted ? qv->cache_memo == 1 : info.prefetch_due;
    qv->cache_memo = 0; /* a re-run with the same qv must not prefetch again */
    if (hit == 2) { md_trace_flag(MD_TF_HIT_STALE); refresh_start(e, cn, q, qv, false); }
    else if (hit) { md_trace_flag(MD_TF_HIT_FRESH); if (prefetch) refresh_start(e, cn, q, qv, true); }
    int rc = hit ? finalize(e, cn, r, view, deadline, err) : resolve(e, cn, q, qv, r, deadline, err);
    md_trace_mark(MD_T_ENGINE1);
    if (hit) return rc;
    if (!rc && !r->len) return fail(err, "upstream completed without a response");
    return rc;
}
/* Stop foreground queries first. Joining refreshers before freeing immutable
 * routing resources/cache prevents use-after-free during shutdown. */
void md_engine_free(md_engine *e) {
    if (!e) return;
    pthread_mutex_lock(&e->lock); e->stopping = true;
    if (e->wake_ok) pthread_cond_broadcast(&e->wake);
    pthread_mutex_unlock(&e->lock);
    if (e->maintenance_running) pthread_join(e->maintenance, NULL);
    pthread_mutex_lock(&e->lock); refresh_job *jobs = e->jobs; e->jobs = NULL; pthread_mutex_unlock(&e->lock);
    while (jobs) { refresh_job *next = jobs->next; pthread_join(jobs->thread, NULL); free(jobs); jobs = next; }
    /* 退出时保存热点名称（仅名称）；DIVERSION_CACHE_STATS 打印命中/未命中原因计数。 */
    if (e->cache && !e->check) {
        if (e->warm_file) (void)warm_save(e);
        if (getenv("DIVERSION_CACHE_STATS")) print_cache_stats(e);
    }
    md_trace_close();
    /* 契约测试/诊断：DIVERSION_NFT_STATS=1 时退出前打印 nft 写入计数（默认不打印）。 */
    if (e->nft && getenv("DIVERSION_NFT_STATS")) {
        md_nft_stats st; md_nft_get_stats(&st);
        fprintf(stderr, "nftset stats: applies=%llu skipped=%llu transactions=%llu\n",
                (unsigned long long)st.applies, (unsigned long long)st.skipped, (unsigned long long)st.transactions);
    }
    for (size_t i = 0; i < e->override_count; i++) md_domain_free(e->overrides[i].domains);
    free(e->warm_file); if (e->wake_ok) pthread_cond_destroy(&e->wake);
    md_domain_free(e->cn); md_cache_free(e->cache); md_nft_free(e->nft);
    free(e->upstreams[0].items); free(e->upstreams[1].items); free(e->listeners);
    pthread_mutex_destroy(&e->lock); free(e);
}
