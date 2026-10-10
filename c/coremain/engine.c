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

#define CONFIG_LINE_MAX 4096
#define CONFIG_FILE_MAX (1024 * 1024)
#define CONFIG_LIST_MAX 64

typedef enum {
    LISTEN_UDP, LISTEN_TCP, CN_FILE, CN_UPSTREAM, FOREIGN_UPSTREAM,
    CACHE_SIZE, CACHE_LAZY, CN_MARK, FOREIGN_MARK, CN_INTERFACE, FOREIGN_INTERFACE,
    CN_CONCURRENT, FOREIGN_CONCURRENT, TCP_IDLE, NFT4, NFT6, NFT_FAST, KEY_COUNT
} config_key;
static const char *const key_names[KEY_COUNT] = {
    "listen_udp", "listen_tcp", "cn_domain_file", "cn_upstream", "foreign_upstream",
    "cache_size", "cache_lazy_ttl", "cn_mark", "foreign_mark", "cn_interface", "foreign_interface",
    "cn_concurrent", "foreign_concurrent", "tcp_idle_timeout", "nftset_ipv4", "nftset_ipv6", "nftset_fast"
};
typedef struct { char *text; size_t line; } config_value;
typedef struct { config_value values[CONFIG_LIST_MAX]; size_t count; } config_values;
typedef struct { config_values keys[KEY_COUNT]; size_t last_line; } config;
typedef struct refresh_job refresh_job;
typedef struct { md_upstream *items; size_t count; unsigned concurrent; } upstream_group;
struct md_engine {
    md_domain *cn;
    md_cache *cache;
    md_nft *nft;
    upstream_group upstreams[2]; /* 0 CN, 1 foreign */
    md_listener *listeners; size_t listener_count;
    bool check, stopping;
    pthread_mutex_t lock;
    refresh_job *jobs;
};
struct refresh_job {
    pthread_t thread;
    md_engine *engine;
    md_packet query;
    bool cn, done;
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
    if ((k > FOREIGN_UPSTREAM && v->count) || v->count == CONFIG_LIST_MAX)
        return config_error(err, path, line, k > FOREIGN_UPSTREAM ? "duplicate single-value key" : "list exceeds 64 entries");
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
    e->cn = md_domain_new();
    if (!e->cn) return config_error(err, path, key_line(c, CN_FILE), "out of memory");
    /* check reads actual rule files and compiles PCRE2, but never opens a
     * listener/upstream connection, probes nft, or changes kernel state.
     * A named IPv6 scope is resolved against the host interface list. */
    for (size_t i = 0; i < c->keys[CN_FILE].count; i++) {
        const config_value *v = &c->keys[CN_FILE].values[i];
        if (md_domain_load(e->cn, v->text, err)) return config_error(err, path, v->line, err);
    }
    if (capacity && !e->check && !(e->cache = md_cache_new(capacity, lazy)))
        return config_error(err, path, key_line(c, CACHE_SIZE), "cannot allocate cache");
    return 0;
}

static int finalize(md_engine *e, bool cn, md_packet *response, uint64_t deadline, char *err) {
    if (md_now() >= deadline) return fail(err, "query execution deadline exceeded");
    int rc = cn && e->nft && response->len ? md_nft_apply(e->nft, response, err) : 0;
    if (!rc && md_now() >= deadline) rc = fail(err, "query execution deadline exceeded");
    return rc;
}
/* A forwarding error never crosses from CN to foreign or vice versa. Store
 * otherwise valid answers even if nft finalization fails, as before. */
static int resolve(md_engine *e, bool cn, const md_packet *query, md_packet *response, uint64_t deadline, char *err) {
    if (md_now() >= deadline) return fail(err, "query execution deadline exceeded");
    upstream_group *group = &e->upstreams[cn ? 0 : 1];
    int rc = md_forward(group->items, group->count, group->concurrent, query, response, err);
    if (!rc) rc = finalize(e, cn, response, deadline, err);
    if (response->len) md_cache_put(e->cache, query, response, md_now());
    return rc;
}
static void *refresh_thread(void *opaque) {
    refresh_job *job = opaque;
    md_packet *response = calloc(1, sizeof(*response)); char err[MD_ERROR_SIZE] = {0};
    if (response) { (void)resolve(job->engine, job->cn, &job->query, response, md_now() + 5, err); free(response); }
    md_cache_refresh_end(job->engine->cache, &job->query);
    pthread_mutex_lock(&job->engine->lock); job->done = true; pthread_mutex_unlock(&job->engine->lock);
    return NULL;
}
static void refresh_start(md_engine *e, bool cn, const md_packet *query) {
    pthread_mutex_lock(&e->lock);
    refresh_job **link = &e->jobs; size_t active = 0;
    while (*link) {
        refresh_job *job = *link;
        if (job->done) { *link = job->next; pthread_join(job->thread, NULL); free(job); }
        else { active++; link = &job->next; }
    }
    if (e->stopping || active >= 64 || !md_cache_refresh_begin(e->cache, query)) {
        pthread_mutex_unlock(&e->lock); return;
    }
    refresh_job *job = calloc(1, sizeof(*job));
    if (!job) { md_cache_refresh_end(e->cache, query); pthread_mutex_unlock(&e->lock); return; }
    job->engine = e; job->query = *query; job->cn = cn; job->next = e->jobs;
    if (pthread_create(&job->thread, NULL, refresh_thread, job)) { md_cache_refresh_end(e->cache, query); free(job); }
    else e->jobs = job;
    pthread_mutex_unlock(&e->lock);
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
    if (rc) { md_engine_free(e); return NULL; }
    return e;
}
size_t md_engine_listener_count(const md_engine *e) { return e ? e->listener_count : 0; }
const md_listener *md_engine_listener(const md_engine *e, size_t i) { return e && i < e->listener_count ? &e->listeners[i] : NULL; }
/* Cached replies always use the worker path: an event-loop shortcut must never
 * bypass nft, lazy refresh, or errors. The server retains its existing API. */
bool md_engine_cached_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r) {
    (void)e; (void)entry; (void)q;
    if (r) r->len = 0;
    return false;
}
int md_engine_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r, char *err) {
    char scratch_error[MD_ERROR_SIZE] = {0};
    if (!err) err = scratch_error;
    if (!r) return fail(err, "response is required");
    r->len = 0;
    if (!e || !q || entry) return fail(err, "invalid fixed splitter entry/query");
    if (e->check) return fail(err, "checked configuration cannot execute queries");
    uint64_t deadline = md_now() + 5;
    md_question question;
    if (md_dns_question(q, &question, err)) return -1;
    bool cn = md_domain_match(e->cn, question.name);
    int hit = md_cache_get(e->cache, q, r, md_now());
    if (hit == 2) refresh_start(e, cn, q);
    if (hit) return finalize(e, cn, r, deadline, err);
    int rc = resolve(e, cn, q, r, deadline, err);
    if (!rc && !r->len) return fail(err, "upstream completed without a response");
    return rc;
}
/* Stop foreground queries first. Joining refreshers before freeing immutable
 * routing resources/cache prevents use-after-free during shutdown. */
void md_engine_free(md_engine *e) {
    if (!e) return;
    pthread_mutex_lock(&e->lock); e->stopping = true; refresh_job *jobs = e->jobs; e->jobs = NULL; pthread_mutex_unlock(&e->lock);
    while (jobs) { refresh_job *next = jobs->next; pthread_join(jobs->thread, NULL); free(jobs); jobs = next; }
    md_domain_free(e->cn); md_cache_free(e->cache); md_nft_free(e->nft);
    free(e->upstreams[0].items); free(e->upstreams[1].items); free(e->listeners);
    pthread_mutex_destroy(&e->lock); free(e);
}
