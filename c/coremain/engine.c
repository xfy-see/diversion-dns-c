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
    CN_CONCURRENT, FOREIGN_CONCURRENT, TCP_IDLE, NFT4, NFT6, NFT_FAST,
    QUEUE_TIMEOUT, TCP_READ, TCP_WRITE, TCP_MAX, TCP_MAX_IP,
    UDP_SPORT_REUSE, UDP_SPORT_REUSE_MAX_USES, UDP_SPORT_REUSE_TTL_MS, UDP_SPORT_REUSE_POOL,
    KEY_COUNT
} config_key;
static const char *const key_names[KEY_COUNT] = {
    "listen_udp", "listen_tcp", "cn_domain_file", "cn_upstream", "foreign_upstream",
    "cache_size", "cache_lazy_ttl", "cn_mark", "foreign_mark", "cn_interface", "foreign_interface",
    "cn_concurrent", "foreign_concurrent", "tcp_idle_timeout", "nftset_ipv4", "nftset_ipv6", "nftset_fast",
    "queue_timeout_ms", "tcp_read_timeout", "tcp_write_timeout", "tcp_max_connections", "tcp_max_connections_per_ip",
    "udp_sport_reuse", "udp_sport_reuse_max_uses", "udp_sport_reuse_ttl_ms", "udp_sport_reuse_pool"
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
    md_server_limits limits;
    bool check, stopping;
    pthread_mutex_t lock;
    refresh_job *jobs;
};
struct refresh_job {
    pthread_t thread;
    md_engine *engine;
    md_packet query;
    md_dns_query qv; /* 前台请求解析结果的副本，刷新线程不再解析请求 */
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
    if (capacity && !e->check && !(e->cache = md_cache_new(capacity, lazy)))
        return config_error(err, path, key_line(c, CACHE_SIZE), "cannot allocate cache");
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
static int resolve(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv, md_packet *response, uint64_t deadline, char *err) {
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
    if (response->len) md_cache_put_q(e->cache, query, qv, response, view, md_now());
    return rc;
}
static void *refresh_thread(void *opaque) {
    refresh_job *job = opaque;
    md_packet *response = calloc(1, sizeof(*response)); char err[MD_ERROR_SIZE] = {0};
    md_trace tr; memset(&tr, 0, sizeof(tr));
    if (md_trace_enabled) { tr.flags = MD_TF_REFRESH_JOB; tr.t[MD_T_ENGINE0] = md_now_ns(); md_trace_cur = &tr; }
    int rc = -1;
    if (response) { rc = resolve(job->engine, job->cn, &job->query, &job->qv, response, md_now() + 5, err); free(response); }
    if (md_trace_enabled) {
        md_trace_cur = NULL; tr.t[MD_T_ENGINE1] = md_now_ns();
        if (rc) tr.flags |= MD_TF_ERROR;
        md_trace_emit(&tr, &job->query);
    }
    md_cache_refresh_end_q(job->engine->cache, &job->query, &job->qv);
    pthread_mutex_lock(&job->engine->lock); job->done = true; pthread_mutex_unlock(&job->engine->lock);
    return NULL;
}
static void refresh_start(md_engine *e, bool cn, const md_packet *query, const md_dns_query *qv) {
    pthread_mutex_lock(&e->lock);
    refresh_job **link = &e->jobs; size_t active = 0;
    while (*link) {
        refresh_job *job = *link;
        if (job->done) { *link = job->next; pthread_join(job->thread, NULL); free(job); }
        else { active++; link = &job->next; }
    }
    if (e->stopping || active >= 64 || !md_cache_refresh_begin_q(e->cache, query, qv)) {
        pthread_mutex_unlock(&e->lock); return;
    }
    refresh_job *job = calloc(1, sizeof(*job));
    if (!job) { md_cache_refresh_end_q(e->cache, query, qv); pthread_mutex_unlock(&e->lock); return; }
    job->engine = e; job->query = *query; job->qv = *qv; job->cn = cn; job->next = e->jobs;
    if (md_thread_create(&job->thread, refresh_thread, job)) { md_cache_refresh_end_q(e->cache, query, qv); free(job); }
    else { e->jobs = job; md_trace_flag(MD_TF_REFRESH_START); }
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
    int hit = md_cache_get_q(e->cache, q, qv, r, view, md_now());
    if (hit == 1 && !cn && !finalize(e, false, r, view, md_now() + 5, err)) { md_trace_flag(MD_TF_HIT_FRESH); return MD_LANE_REPLY; }
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
    int hit = md_cache_get_q(e->cache, q, qv, r, view, md_now());
    if (hit == 2) { md_trace_flag(MD_TF_HIT_STALE); refresh_start(e, cn, q, qv); }
    else if (hit) md_trace_flag(MD_TF_HIT_FRESH);
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
    pthread_mutex_lock(&e->lock); e->stopping = true; refresh_job *jobs = e->jobs; e->jobs = NULL; pthread_mutex_unlock(&e->lock);
    while (jobs) { refresh_job *next = jobs->next; pthread_join(jobs->thread, NULL); free(jobs); jobs = next; }
    md_trace_close();
    md_domain_free(e->cn); md_cache_free(e->cache); md_nft_free(e->nft);
    free(e->upstreams[0].items); free(e->upstreams[1].items); free(e->listeners);
    pthread_mutex_destroy(&e->lock); free(e);
}
