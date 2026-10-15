/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 上游转发采用非阻塞 socket 和 poll 驱动状态机。连接池只在显式启用的
 * worker 线程内存在；普通库调用使用新连接，不依赖服务端线程生命周期。 */
#define _GNU_SOURCE
#ifdef __APPLE__
#define _DARWIN_C_SOURCE /* arc4random_buf under -std=c11/_POSIX_C_SOURCE */
#endif
#include "mosdns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/uio.h>
#include <unistd.h>
#ifdef __linux__
#include <sys/random.h>
#endif

static int fail(char *err, const char *s) {
    if (err) snprintf(err, MD_ERROR_SIZE, "%s", s);
    return -1;
}
static int syserr(char *err, const char *s) {
    if (err) snprintf(err, MD_ERROR_SIZE, "%s: %s", s, strerror(errno));
    return -1;
}
static int port_number(const char *s, unsigned *port) {
    if (!s || !*s) return -1;
    unsigned n = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return -1;
        n = n * 10 + (unsigned)(*s - '0');
        if (n > 65535) return -1;
    }
    *port = n;
    return 0;
}
/* 只解析数字 IP，不做 DNS 引导查询；带端口的 IPv6 必须使用方括号。
 * 无端口的 IPv6 可直接写地址，作用域支持接口名或数值。 */
int md_parse_address(const char *s, unsigned default_port, struct sockaddr_storage *a,
                     socklen_t *len, char *err) {
    if (!s || !*s || strlen(s) >= 256 || default_port > 65535 || !a || !len)
        return fail(err, "invalid numeric socket address");
    char host[256];
    unsigned port = default_port;
    bool ipv6 = false;
    if (*s == '[') {
        const char *end = strchr(s, ']');
        if (!end || end == s + 1 || (end[1] && (end[1] != ':' || port_number(end + 2, &port))))
            return fail(err, "invalid bracketed IPv6 address");
        size_t n = (size_t)(end - s - 1);
        memcpy(host, s + 1, n); host[n] = '\0'; ipv6 = true;
    } else {
        const char *colon = strchr(s, ':');
        if (colon && !strchr(colon + 1, ':')) {
            size_t n = (size_t)(colon - s);
            memcpy(host, s, n); host[n] = '\0';
            if (port_number(colon + 1, &port)) return fail(err, "invalid socket port");
        } else {
            strcpy(host, s); ipv6 = colon != NULL;
        }
    }
    memset(a, 0, sizeof(*a));
    if (ipv6) {
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)a;
        char *scope = strchr(host, '%');
        if (scope) {
            *scope++ = '\0';
            if (!*scope) return fail(err, "empty IPv6 scope");
            unsigned number;
            if (!port_number(scope, &number)) v6->sin6_scope_id = number;
            else if (!(v6->sin6_scope_id = if_nametoindex(scope))) return fail(err, "unknown IPv6 scope interface");
        }
        if (inet_pton(AF_INET6, host, &v6->sin6_addr) != 1)
            return fail(err, "upstream/listener requires numeric IPv6 address");
        v6->sin6_family = AF_INET6; v6->sin6_port = htons((uint16_t)port);
        *len = sizeof(*v6);
    } else {
        struct sockaddr_in *v4 = (struct sockaddr_in *)a;
        if (!*host) v4->sin_addr.s_addr = htonl(INADDR_ANY);
        else if (inet_pton(AF_INET, host, &v4->sin_addr) != 1)
            return fail(err, "upstream/listener requires numeric IPv4 address");
        v4->sin_family = AF_INET; v4->sin_port = htons((uint16_t)port);
        *len = sizeof(*v4);
    }
    return 0;
}
/* dial_addr 只覆盖实际拨号目标，传输协议仍由 addr 决定。 */
int md_upstream_init(md_upstream *u, const char *addr, const char *dial_addr,
                     uint32_t mark, const char *device, char *err) {
    if (!u || !addr || !*addr) return fail(err, "upstream address is required");
    memset(u, 0, sizeof(*u));
    const char *numeric = addr;
    if (!strncmp(addr, "udp://", 6)) numeric += 6;
    else if (!strncmp(addr, "tcp://", 6)) { u->tcp = true; numeric += 6; }
    else if (strstr(addr, "://")) return fail(err, "C minimal upstream supports udp:// and tcp:// only");
    /* A numeric dial override replaces the address, as in the Go minimal
     * profile. The display address may then be a hostname; no lookup occurs. */
    if (!*numeric || strpbrk(numeric, "/?#@ \t\r\n")) return fail(err, "invalid upstream address");
    if ((*numeric == ':' && !strchr(numeric + 1, ':')) ||
        (dial_addr && *dial_addr == ':' && !strchr(dial_addr + 1, ':')))
        return fail(err, "upstream address requires a nonempty host");
    if (md_parse_address(dial_addr && *dial_addr ? dial_addr : numeric, 53,
                         &u->address, &u->address_len, err)) return -1;
    if ((u->address.ss_family == AF_INET && !((struct sockaddr_in *)&u->address)->sin_port) ||
        (u->address.ss_family == AF_INET6 && !((struct sockaddr_in6 *)&u->address)->sin6_port))
        return fail(err, "upstream port must be nonzero");
    if (device && strlen(device) >= sizeof(u->bind_device)) return fail(err, "bind_to_device is too long");
    u->so_mark = mark;
    if (device) strcpy(u->bind_device, device);
    snprintf(u->tag, sizeof(u->tag), "%s", addr);
    return 0;
}

/* UDP 等待一个数据报；TCP 分别累计两字节长度和消息体，短读/短写均可继续。 */
typedef enum { CONNECTING, SENDING, UDP_READING, TCP_LENGTH, TCP_BODY, DEAD } phase;
#define WORKER_TCP_CAPACITY 8
#define WORKER_TCP_IDLE_MS 30000
#define WORKER_UDP_SPARES 8
#define WORKER_UDP_DEAD 16
/* 空闲 socket 归池所有，借出后由 exchange 持有 fd。每条连接记录已用 ID，
 * 复用同一 ID 前退休连接，避免旧响应被当成新查询的结果。 */
typedef struct {
    int fd;
    bool busy, tcp;
    md_upstream key;
    const md_upstream *owner; /* Identity only; never dereferenced. */
    uint64_t last;
    /* Retire a connection before an ID repeats, including wraparound. */
    uint8_t ids[65536 / 8];
} worker_connection;
typedef struct {
    int fd;
    phase state;
    bool tcp;
    const md_upstream *upstream;
    uint8_t prefix[2];
    size_t done;
    uint64_t udp_retry;
    worker_connection *cached;
    uint16_t query_id;
    bool reused, dirty;
    /* UDP park/reuse bookkeeping (ignored for TCP). udp_uses is completed queries
     * already done on this fd before the current exchange; udp_born is open time. */
    unsigned udp_uses;
    uint64_t udp_born;
    md_packet packet;
} exchange;
typedef struct {
    worker_connection slots[WORKER_TCP_CAPACITY];
    /* One synchronous forward at a time per worker. Reentrant/library calls
     * keep an independent allocation so they cannot overwrite live replies. */
    exchange exchanges[3];
    md_packet query; /* The upstream copy of the query (random ID, M4). */
    md_dns_view view; /* 接收时唯一一次整包解析的结果，供匹配/RCODE/调用方复用。 */
    bool exchanges_in_use;
    /* M4 default: one fresh, never-used UDP socket per upstream (spare_uses==0).
     * Opt-in udp_sport_reuse may park a quiet used socket back with spare_uses>0
     * until max_uses/ttl, still one in-flight owner at a time. Close of dead fds
     * and refill of virgin spares run in md_forward_worker_idle(). */
    int spare_fd[WORKER_UDP_SPARES];
    uint64_t spare_born[WORKER_UDP_SPARES];
    unsigned spare_uses[WORKER_UDP_SPARES];
    md_upstream spare_key[WORKER_UDP_SPARES];
    bool spare_wanted[WORKER_UDP_SPARES];
    int dead_fd[WORKER_UDP_DEAD];
    unsigned dead_count;
    bool maintenance; /* Set only when a spare was taken or a UDP fd retired. */
} worker_connections;
/* 池和可复用报文缓冲都属于当前线程，不需要跨 worker 加锁。 */
static _Thread_local worker_connections *worker_tcp;

/* 超时和闲置回收使用单调时钟，系统时间校准不会延长或缩短查询期限。 */
static uint64_t milliseconds(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
/* M4: every forwarded query gets a fresh unpredictable 16-bit DNS ID instead
 * of the client's. Bytes come from the kernel CSPRNG (getrandom/arc4random) in
 * small per-thread batches; if that is unavailable (very early boot, seccomp),
 * fall back to a splitmix64 stream seeded from the monotonic and realtime
 * clocks, the thread's stack address and a global counter. */
static _Thread_local uint16_t random_pool[32];
static _Thread_local unsigned random_left;
static _Thread_local uint64_t random_state;
static atomic_uint_fast64_t random_counter;
/* Process-wide opt-in UDP source-port reuse. Default off preserves M4. Workers
 * read a snapshot; engine load / tests call set before enabling workers. */
static md_udp_sport_reuse g_udp_reuse = { .enabled = 0, .max_uses = 16, .ttl_ms = 2000, .pool_size = 2 };
void md_forward_set_udp_sport_reuse(const md_udp_sport_reuse *cfg) {
    md_udp_sport_reuse next = { .enabled = 0, .max_uses = 16, .ttl_ms = 2000, .pool_size = 2 };
    if (cfg) {
        next.enabled = cfg->enabled ? 1u : 0u;
        if (cfg->max_uses) next.max_uses = cfg->max_uses;
        if (cfg->ttl_ms) next.ttl_ms = cfg->ttl_ms;
        if (cfg->pool_size) next.pool_size = cfg->pool_size;
        if (next.max_uses < 1) next.max_uses = 1;
        if (next.max_uses > 256) next.max_uses = 256;
        if (next.ttl_ms < 100) next.ttl_ms = 100;
        if (next.ttl_ms > 60000) next.ttl_ms = 60000;
        if (next.pool_size < 1) next.pool_size = 1;
        if (next.pool_size > 4) next.pool_size = 4;
    }
    g_udp_reuse = next;
}
void md_forward_get_udp_sport_reuse(md_udp_sport_reuse *cfg) {
    if (cfg) *cfg = g_udp_reuse;
}
static md_udp_sport_reuse reuse_snapshot(void) { return g_udp_reuse; }
static bool random_fill(void *buffer, size_t size) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    arc4random_buf(buffer, size); return true;
#elif defined(__linux__)
    uint8_t *p = buffer;
    while (size) {
        ssize_t n = getrandom(p, size, GRND_NONBLOCK);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n; size -= (size_t)n;
    }
    return true;
#else
    (void)buffer; (void)size; return false;
#endif
}
static uint16_t random_id(void) {
    if (!random_left) {
        if (random_fill(random_pool, sizeof(random_pool))) random_left = sizeof(random_pool) / sizeof(random_pool[0]);
        else {
            struct timespec a = {0, 0}, b = {0, 0};
            clock_gettime(CLOCK_MONOTONIC, &a); clock_gettime(CLOCK_REALTIME, &b);
            random_state ^= (uint64_t)a.tv_nsec ^ ((uint64_t)a.tv_sec << 32) ^ (uint64_t)b.tv_nsec * 0x9e3779b97f4a7c15u ^
                (uint64_t)(uintptr_t)&a ^ atomic_fetch_add_explicit(&random_counter, 0x632be59bd9b4e019u, memory_order_relaxed);
            uint64_t z = (random_state += 0x9e3779b97f4a7c15u);
            z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9u; z = (z ^ (z >> 27)) * 0x94d049bb133111ebu;
            return (uint16_t)((z ^ (z >> 31)) >> 16);
        }
    }
    return random_pool[--random_left];
}
static void retire(worker_connection *c) {
    if (c->fd >= 0) close(c->fd);
    c->fd = -1; c->busy = false;
}
void md_forward_worker_cleanup(void) {
    if (!worker_tcp) return;
    for (unsigned i = 0; i < WORKER_TCP_CAPACITY; i++) retire(&worker_tcp->slots[i]);
    for (unsigned i = 0; i < WORKER_UDP_SPARES; i++) if (worker_tcp->spare_fd[i] >= 0) close(worker_tcp->spare_fd[i]);
    for (unsigned i = 0; i < worker_tcp->dead_count; i++) close(worker_tcp->dead_fd[i]);
    free(worker_tcp); worker_tcp = NULL;
}
/* 分配失败时保持 NULL，后续转发自动退回临时 exchange 和新 socket。 */
void md_forward_worker_enable(void) {
    md_forward_worker_cleanup();
    worker_tcp = calloc(1, sizeof(*worker_tcp));
    if (worker_tcp) {
        for (unsigned i = 0; i < WORKER_TCP_CAPACITY; i++) worker_tcp->slots[i].fd = -1;
        for (unsigned i = 0; i < WORKER_UDP_SPARES; i++) {
            worker_tcp->spare_fd[i] = -1; worker_tcp->spare_uses[i] = 0;
        }
    }
}
/* 池键包含目标、配置协议、mark 和设备，避免复用改变了路由约束的连接。 */
static bool same_endpoint(const md_upstream *a, const md_upstream *b) {
    return a->tcp == b->tcp && a->address_len == b->address_len &&
        a->address_len <= sizeof(a->address) &&
        !memcmp(&a->address, &b->address, a->address_len) &&
        a->so_mark == b->so_mark && !strcmp(a->bind_device, b->bind_device);
}
/* owner 只比较对象身份：同一配置对象改了拨号参数时淘汰旧连接，
 * 不通过可能已失效的 owner 指针读取配置。 */
static void prepare_worker(const md_upstream *us, size_t count) {
    if (!worker_tcp) return;
    uint64_t now = milliseconds();
    for (unsigned i = 0; i < WORKER_TCP_CAPACITY; i++) {
        worker_connection *c = &worker_tcp->slots[i];
        if (c->busy || c->fd < 0) continue;
        bool retargeted = false;
        for (size_t j = 0; j < count; j++)
            if (c->owner == &us[j] && !same_endpoint(&c->key, &us[j])) { retargeted = true; break; }
        if (retargeted || now - c->last >= WORKER_TCP_IDLE_MS) retire(c);
    }
}
/* 只有无待收字节且未关闭的 socket 才可复用；残留帧或旧数据报都会淘汰。 */
static bool quiet_socket(int fd) {
    uint8_t byte;
    ssize_t n = recv(fd, &byte, 1, MSG_PEEK);
    return n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
}
/* 优先借出安全的同目标连接，否则使用空槽或最久未用的空闲槽；
 * busy 槽不会被重入调用覆盖，池满时调用方可直接建立非池化连接。 */
static worker_connection *take_connection(const md_upstream *u, bool tcp, uint16_t id, bool allow_reuse) {
    if (!worker_tcp) return NULL;
    worker_connection *available = NULL;
    for (unsigned i = 0; i < WORKER_TCP_CAPACITY; i++) {
        worker_connection *c = &worker_tcp->slots[i];
        if (c->busy) continue;
        if (allow_reuse && c->fd >= 0 && c->tcp == tcp && same_endpoint(&c->key, u)) {
            if (!(c->ids[id / 8] & (1u << (id % 8))) && quiet_socket(c->fd)) {
                c->owner = u; c->busy = true; return c;
            }
            retire(c);
        }
        if (!available || c->fd < 0 || (available->fd >= 0 && c->last < available->last)) available = c;
    }
    if (!available) return NULL;
    retire(available);
    available->key = *u; available->owner = u; available->tcp = tcp; available->busy = true;
    memset(available->ids, 0, sizeof(available->ids));
    return available;
}
/* Count parked sockets for one upstream (fd still held in a spare slot). */
static unsigned parked_for(const md_upstream *u) {
    unsigned n = 0;
    for (unsigned i = 0; i < WORKER_UDP_SPARES; i++)
        if (worker_tcp->spare_wanted[i] && worker_tcp->spare_fd[i] >= 0 &&
            same_endpoint(&worker_tcp->spare_key[i], u)) n++;
    return n;
}
/* Opt-in: return a quiet UDP socket to the spare list when under max-uses, age,
 * and per-upstream pool_size. Default path never parks used sockets. */
static bool park_udp(exchange *x) {
    md_udp_sport_reuse cfg = reuse_snapshot();
    if (!cfg.enabled || !worker_tcp || x->fd < 0 || x->tcp || x->dirty || !x->upstream) return false;
    unsigned next = x->udp_uses + 1;
    uint64_t now = milliseconds();
    if (next > cfg.max_uses || now - x->udp_born >= cfg.ttl_ms || !quiet_socket(x->fd)) return false;
    if (parked_for(x->upstream) >= cfg.pool_size) return false;
    unsigned slot = WORKER_UDP_SPARES;
    for (unsigned i = 0; i < WORKER_UDP_SPARES; i++) {
        if (worker_tcp->spare_wanted[i] && worker_tcp->spare_fd[i] < 0 &&
            same_endpoint(&worker_tcp->spare_key[i], x->upstream)) { slot = i; break; }
        if (!worker_tcp->spare_wanted[i] && slot == WORKER_UDP_SPARES) slot = i;
    }
    if (slot == WORKER_UDP_SPARES) return false;
    worker_tcp->spare_fd[slot] = x->fd;
    worker_tcp->spare_born[slot] = x->udp_born;
    worker_tcp->spare_uses[slot] = next;
    worker_tcp->spare_key[slot] = *x->upstream;
    worker_tcp->spare_wanted[slot] = true;
    worker_tcp->maintenance = true;
    x->fd = -1;
    return true;
}
/* 失败和未胜出的 exchange 都关闭自己持有的 fd，并释放对应池槽。 */
static void stop(exchange *x) {
    /* Default M4: used UDP sockets are never reused; close is deferred to idle.
     * With udp_sport_reuse, a quiet socket may park back under uses/age/pool caps. */
    if (x->fd >= 0 && !x->tcp && !x->cached && worker_tcp && park_udp(x))
        { /* parked */ }
    else if (x->fd >= 0 && !x->tcp && !x->cached && worker_tcp && worker_tcp->dead_count < WORKER_UDP_DEAD)
        worker_tcp->dead_fd[worker_tcp->dead_count++] = x->fd, worker_tcp->maintenance = true;
    else if (x->fd >= 0) close(x->fd);
    x->fd = -1; x->state = DEAD; x->udp_retry = 0;
    if (x->cached) { retire(x->cached); x->cached = NULL; }
    x->reused = x->dirty = false; x->udp_uses = 0; x->udp_born = 0;
}
/* 在 connect 前应用路由 mark/绑定设备；不支持的平台直接报错，
 * 避免配置要求分流时悄悄使用默认路由。 */
static int socket_options(int fd, const md_upstream *u, char *err) {
#ifdef __linux__
    if (u->so_mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &u->so_mark, sizeof(u->so_mark)))
        return syserr(err, "set SO_MARK");
    if (u->bind_device[0] && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE,
            u->bind_device, (socklen_t)(strlen(u->bind_device) + 1)))
        return syserr(err, "set SO_BINDTODEVICE");
#else
    if (u->so_mark || u->bind_device[0])
        return fail(err, "SO_MARK/bind_to_device require Linux; refusing an unmarked/unbound socket");
#endif
#ifdef SO_NOSIGPIPE
    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one))) return syserr(err, "set SO_NOSIGPIPE");
#endif
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    (void)0; /* upstream_socket() already created it nonblocking + close-on-exec. */
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) < 0)
        return syserr(err, "set socket flags");
#endif
    return 0;
}
/* One syscall instead of socket + 3 fcntl per fresh upstream socket (M4 opens
 * one per UDP query). Flags are identical: O_NONBLOCK and FD_CLOEXEC. */
static int upstream_socket(int family, int type) {
#if defined(SOCK_NONBLOCK) && defined(SOCK_CLOEXEC)
    return socket(family, type | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
#else
    return socket(family, type, 0);
#endif
}
/* Hand out a parked or pre-opened UDP socket for this upstream. Default M4 only
 * accepts virgin (uses==0) spares; opt-in reuse also accepts quiet sockets under
 * max_uses and ttl. A stale, dirty, or over-limit socket is closed. Asking idle
 * to refill keeps the next cold query off the hot path when possible. */
static int take_spare(const md_upstream *u, unsigned *out_uses, uint64_t *out_born) {
    if (!worker_tcp) return -1;
    md_udp_sport_reuse cfg = reuse_snapshot();
    uint64_t now = milliseconds();
    unsigned age_limit = cfg.enabled ? cfg.ttl_ms : WORKER_TCP_IDLE_MS;
    unsigned free_slot = WORKER_UDP_SPARES;
    for (unsigned i = 0; i < WORKER_UDP_SPARES; i++) {
        if (!worker_tcp->spare_wanted[i]) { if (free_slot == WORKER_UDP_SPARES) free_slot = i; continue; }
        if (!same_endpoint(&worker_tcp->spare_key[i], u)) continue;
        int fd = worker_tcp->spare_fd[i];
        unsigned uses = worker_tcp->spare_uses[i];
        uint64_t born = worker_tcp->spare_born[i];
        worker_tcp->spare_fd[i] = -1; worker_tcp->spare_uses[i] = 0; worker_tcp->maintenance = true;
        if (fd < 0) return -1;
        bool age_ok = now - born < age_limit;
        bool uses_ok = cfg.enabled ? uses < cfg.max_uses : uses == 0;
        if (age_ok && uses_ok && quiet_socket(fd)) {
            if (out_uses) *out_uses = uses;
            if (out_born) *out_born = born;
            return fd;
        }
        close(fd); return -1;
    }
    if (free_slot < WORKER_UDP_SPARES) {
        worker_tcp->spare_key[free_slot] = *u; worker_tcp->spare_wanted[free_slot] = true;
        worker_tcp->spare_uses[free_slot] = 0; worker_tcp->maintenance = true;
    }
    return -1;
}
/* Cache hits and other replies that did not touch a UDP upstream return
 * here after one flag test: no clock read, no syscall, no slot scan. */
void md_forward_worker_idle(void) {
    if (!worker_tcp || !worker_tcp->maintenance) return;
    worker_tcp->maintenance = false;
    md_udp_sport_reuse cfg = reuse_snapshot();
    uint64_t now = milliseconds();
    unsigned age_limit = cfg.enabled ? cfg.ttl_ms : WORKER_TCP_IDLE_MS;
    for (unsigned i = 0; i < worker_tcp->dead_count; i++) close(worker_tcp->dead_fd[i]);
    worker_tcp->dead_count = 0;
    for (unsigned i = 0; i < WORKER_UDP_SPARES; i++) {
        if (!worker_tcp->spare_wanted[i]) continue;
        if (worker_tcp->spare_fd[i] >= 0) {
            /* Aged or over-limit parked sockets leave the pool. */
            bool over_age = now - worker_tcp->spare_born[i] >= age_limit;
            bool over_uses = cfg.enabled && worker_tcp->spare_uses[i] >= cfg.max_uses;
            if (over_age || over_uses || (!cfg.enabled && worker_tcp->spare_uses[i] > 0)) {
                close(worker_tcp->spare_fd[i]);
                worker_tcp->spare_fd[i] = -1; worker_tcp->spare_uses[i] = 0;
                worker_tcp->spare_wanted[i] = false;
            }
            continue;
        }
        /* Refill empty wanted slots with a virgin prewarm (uses==0). Cap how many
         * sockets one upstream keeps when reuse is on (pool_size). */
        if (cfg.enabled && parked_for(&worker_tcp->spare_key[i]) >= cfg.pool_size) {
            worker_tcp->spare_wanted[i] = false; continue;
        }
        const md_upstream *u = &worker_tcp->spare_key[i];
        int fd = upstream_socket(u->address.ss_family, SOCK_DGRAM);
        if (fd < 0) continue;
        if (socket_options(fd, u, NULL) || connect(fd, (const struct sockaddr *)&u->address, u->address_len)) {
            close(fd); continue;
        }
        worker_tcp->spare_fd[i] = fd; worker_tcp->spare_born[i] = now; worker_tcp->spare_uses[i] = 0;
    }
}
/* 借用时把 fd 从池槽移到 exchange；成功后 keep_response 才将所有权交还。 */
/* M4 default: only TCP connections are pooled; every UDP exchange uses a fresh
 * connected socket (kernel-random ephemeral port) so an off-path spoofer must
 * guess ~31 bits with the random ID. Opt-in udp_sport_reuse may hand out a quiet
 * parked UDP socket under max_uses/ttl instead of opening a new port. */
static int begin_connection(exchange *x, const md_upstream *u, bool tcp, bool allow_reuse, char *err) {
    stop(x); x->tcp = tcp; x->upstream = u; x->done = 0; x->udp_uses = 0; x->udp_born = 0;
    if (tcp && (x->cached = take_connection(u, tcp, x->query_id, allow_reuse))) {
        x->cached->ids[x->query_id / 8] |= (uint8_t)(1u << (x->query_id % 8));
        if (x->cached->fd >= 0) {
            x->fd = x->cached->fd; x->cached->fd = -1;
            x->state = SENDING; x->reused = true; return 0;
        }
    }
    if (!tcp) {
        unsigned uses = 0; uint64_t born = 0;
        if ((x->fd = take_spare(u, &uses, &born)) >= 0) {
            x->udp_uses = uses; x->udp_born = born; x->state = SENDING; return 0;
        }
    }
    x->fd = upstream_socket(u->address.ss_family, tcp ? SOCK_STREAM : SOCK_DGRAM);
    if (x->fd < 0) { syserr(err, "create upstream socket"); stop(x); return -1; }
    if (socket_options(x->fd, u, err)) { stop(x); return -1; }
    if (!connect(x->fd, (const struct sockaddr *)&u->address, u->address_len)) x->state = SENDING;
    else if (errno == EINPROGRESS || errno == EWOULDBLOCK) x->state = CONNECTING;
    else { syserr(err, "connect upstream"); stop(x); return -1; }
    if (!tcp) { x->udp_uses = 0; x->udp_born = milliseconds(); }
    return 0;
}
static int begin(exchange *x, const md_upstream *u, bool tcp, char *err) {
    if (md_trace_cur) { md_trace_cur->up_attempts++; if (tcp) md_trace_cur->flags |= MD_TF_UP_TCP; }
    return begin_connection(x, u, tcp, true, err);
}
/* 仅在恰好收完匹配响应、无污染/挂断事件且没有剩余数据时保留连接。
 * UDP 的额外数据报和 TCP 的额外帧都会阻止复用。 */
static void keep_response(exchange *x, short events) {
    if (!x->cached || x->dirty ||
        x->state != (x->tcp ? TCP_LENGTH : UDP_READING) || x->done ||
        (events & (POLLERR | POLLNVAL | POLLHUP)) || !quiet_socket(x->fd)) return;
    x->cached->fd = x->fd; x->cached->last = milliseconds(); x->cached->busy = false;
    x->fd = -1; x->state = DEAD; x->cached = NULL;
}
static bool again(void) { return errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK; }
static int send_flags(void) {
#ifdef MSG_NOSIGNAL
    return MSG_NOSIGNAL;
#else
    return 0;
#endif
}
/* 整包校验与身份匹配一次完成；view 随后直接给出 extended RCODE 并交给调用方。 */
static bool response_matches(const md_packet *q, const md_question *qq, const md_packet *r, md_dns_view *view) {
    return !md_dns_view_parse(r, view, NULL) && md_dns_view_matches(q, qq, r, view);
}
static int resend_udp(exchange *x, const md_packet *q, char *err) {
    /* Retain the connected socket, ID, mark, and device for every retry. */
    ssize_t n = send(x->fd, q->data, q->len, send_flags());
    if (n < 0) {
        if (again()) return 0;
        syserr(err, "resend upstream UDP query"); stop(x); return -1;
    }
    if ((size_t)n != q->len) { fail(err, "short upstream UDP resend"); stop(x); return -1; }
    x->udp_retry = milliseconds() + 1000;
    if (md_trace_cur) md_trace_cur->up_resends++;
    return 0;
}
/* 1 is a matching complete response; 0 means pending; -1 means failed. */
/* 复用连接若在尚未发送任何字节时失效，可重建一次新连接；
 * 已部分发送的 TCP 查询不走这条重试路径。dirty 标记收到过异常内容，
 * 此后仍可等待有效响应，但完成后不能把连接放回池中。 */
/* qq 是 q 已校验的问题段；view 为 scratch，返回 1 时描述 x->packet。 */
static int advance(exchange *x, short events, const md_packet *q, const md_question *qq,
                   md_dns_view *view, char *err) {
    if (x->reused && x->state == SENDING && !x->done &&
        !(events & POLLOUT) && (events & (POLLERR | POLLNVAL | POLLHUP)))
        return begin_connection(x, x->upstream, x->tcp, false, err);
    if (x->state == CONNECTING && (events & (POLLOUT | POLLIN | POLLERR | POLLHUP))) {
        int e = 0; socklen_t n = sizeof(e);
        if (getsockopt(x->fd, SOL_SOCKET, SO_ERROR, &e, &n) || e) {
            if (e) errno = e;
            syserr(err, "connect upstream"); stop(x); return -1;
        }
        x->state = SENDING;
    }
    if (x->state == SENDING && (events & POLLOUT)) {
        ssize_t n;
        if (x->tcp) {
            struct iovec iov[2]; size_t count = 0, offset = 0;
            if (x->done < 2) {
                md_write16(x->prefix, (uint16_t)q->len);
                iov[count++] = (struct iovec){ .iov_base = x->prefix + x->done,
                                              .iov_len = 2 - x->done };
            } else offset = x->done - 2;
            iov[count++] = (struct iovec){ .iov_base = (void *)(q->data + offset),
                                          .iov_len = q->len - offset };
            struct msghdr msg = { .msg_iov = iov, .msg_iovlen = count };
            n = sendmsg(x->fd, &msg, send_flags());
        } else n = send(x->fd, q->data, q->len, send_flags());
        if (n < 0) {
            if (again()) return 0;
            if (x->reused && !x->done) return begin_connection(x, x->upstream, x->tcp, false, err);
            syserr(err, "send upstream query"); stop(x); return -1;
        }
        if (!n && x->reused && !x->done) return begin_connection(x, x->upstream, x->tcp, false, err);
        if (!n || (!x->tcp && (size_t)n != q->len)) { fail(err, "short upstream send"); stop(x); return -1; }
        x->done += (size_t)n;
        if ((!x->tcp && x->done == q->len) || (x->tcp && x->done == q->len + 2)) {
            x->done = 0; x->state = x->tcp ? TCP_LENGTH : UDP_READING;
            if (!x->tcp) x->udp_retry = milliseconds() + 1000;
        }
    }
    if (x->state == UDP_READING && (events & POLLIN)) {
        struct iovec iov = { .iov_base = x->packet.data, .iov_len = MD_MAX_PACKET };
        struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
        ssize_t n = recvmsg(x->fd, &msg, 0);
        if (n < 0) { if (again()) return 0; syserr(err, "receive upstream UDP"); stop(x); return -1; }
        if (msg.msg_flags & MSG_TRUNC) { x->dirty = true; return 0; }
        x->packet.len = (size_t)n;
        if (!response_matches(q, qq, &x->packet, view)) { x->dirty = true; return 0; }
        /* 只有匹配当前问题的 TC 响应触发 TCP 回退，沿用目标和 socket 路由约束。 */
        if (md_read16(x->packet.data + 2) & 0x0200u) {
            const md_upstream *u = x->upstream;
            md_trace_flag(MD_TF_UP_TC_FALLBACK | MD_TF_UP_TCP);
            if (begin(x, u, true, err)) return -1;
            return 0;
        }
        return 1;
    }
    if ((x->state == TCP_LENGTH || x->state == TCP_BODY) && (events & POLLIN)) {
        bool prefix = x->state == TCP_LENGTH;
        uint8_t *data = prefix ? x->prefix : x->packet.data;
        size_t wanted = prefix ? 2 : x->packet.len;
        ssize_t n = recv(x->fd, data + x->done, wanted - x->done, 0);
        if (n < 0) { if (again()) return 0; syserr(err, "receive upstream TCP"); stop(x); return -1; }
        /* A pooled connection the upstream closed while idle can still accept
         * our send; EOF before any response byte then gets one fresh connection.
         * Random upstream IDs (M4) make such reuse common, so this is required. */
        if (!n && x->reused && prefix && !x->done) return begin_connection(x, x->upstream, x->tcp, false, err);
        if (!n) { fail(err, "upstream TCP closed before a response"); stop(x); return -1; }
        x->done += (size_t)n;
        if (x->done == wanted) {
            x->done = 0;
            if (prefix) {
                x->packet.len = md_read16(x->prefix);
                x->state = x->packet.len ? TCP_BODY : TCP_LENGTH;
                if (!x->packet.len) x->dirty = true;
            } else {
                x->state = TCP_LENGTH;
                if (response_matches(q, qq, &x->packet, view)) return 1;
                x->dirty = true;
            }
        }
    }
    if (events & (POLLERR | POLLNVAL | POLLHUP)) {
        /* POLLHUP may accompany a readable final frame. Read it on subsequent
         * polls before treating an EOF as failure, including partial framing. */
        if ((events & POLLIN) && (x->state == TCP_LENGTH || x->state == TCP_BODY)) return 0;
        fail(err, "upstream socket failed"); stop(x); return -1;
    }
    return 0;
}
/* 每次最多竞争三个轮转选出的上游，共享五秒总期限；UDP 每秒重发。
 * 首个 NOERROR/NXDOMAIN 胜出；其他 RCODE 暂存，等待竞争者成功或全部结束。 */
int md_forward(const md_upstream *us, size_t count, unsigned concurrent,
               const md_packet *q, md_packet *r, char *err) {
    return md_forward_view(us, count, concurrent, q, r, NULL, err);
}
int md_forward_view(const md_upstream *us, size_t count, unsigned concurrent,
                    const md_packet *q, md_packet *r, md_dns_view *rv, char *err) {
    return md_forward_q(us, count, concurrent, q, NULL, r, rv, err);
}
int md_forward_q(const md_upstream *us, size_t count, unsigned concurrent,
                 const md_packet *q, const md_dns_query *qv, md_packet *r, md_dns_view *rv, char *err) {
    md_dns_query local;
    if (rv) { rv->valid = false; rv->count = 0; }
    /* 复用调用方的一次请求解析；兼容入口（qv 无效）才在此解析。 */
    if (!md_dns_query_ok(q, qv)) qv = q && !md_dns_query_parse(q, &local, err) ? &local : NULL;
    if (!us || !count || !q || !r || !qv || (qv->q.flags & 0x8000u))
        return fail(err, "invalid forward query or empty upstream list");
    const md_question parsed = qv->q;
    if (!concurrent) concurrent = 1;
    if (concurrent > 3) concurrent = 3;
    if (concurrent > count) concurrent = (unsigned)count;
    /* 同步 worker 调用复用大报文缓冲；重入调用独立分配，避免覆盖尚在读取的响应。 */
    bool scoped = worker_tcp && !worker_tcp->exchanges_in_use;
    exchange *xs = scoped ? worker_tcp->exchanges : malloc(concurrent * sizeof(*xs));
    md_packet *uq = scoped ? &worker_tcp->query : malloc(sizeof(*uq));
    md_dns_view *view = scoped ? &worker_tcp->view : malloc(sizeof(*view));
    if (!xs || !uq || !view) {
        if (!scoped) { free(xs); free(uq); free(view); }
        return fail(err, "out of memory for upstream exchanges");
    }
    if (scoped) worker_tcp->exchanges_in_use = true;
    /* M4: upstreams see a random ID, never the client's. Responses must match
     * that ID and the question (case-insensitive name, type, class) on the
     * connected socket of that upstream; the client ID is restored below. */
    uint16_t client_id = md_read16(q->data), upstream_id = random_id();
    memcpy(uq->data, q->data, q->len); uq->len = q->len;
    md_write16(uq->data, upstream_id);
    for (unsigned i = 0; i < concurrent; i++) {
        memset(&xs[i], 0, offsetof(exchange, packet));
        xs[i].packet.len = 0; xs[i].fd = -1; xs[i].state = DEAD;
    }
    static atomic_size_t rotation = 0;
    size_t first = atomic_fetch_add_explicit(&rotation, 1, memory_order_relaxed) % count;
    uint64_t deadline = milliseconds() + 5000;
    prepare_worker(us, count);
    char last_error[MD_ERROR_SIZE] = "all upstreams failed";
    for (unsigned i = 0; i < concurrent; i++) {
        xs[i].query_id = upstream_id;
        begin(&xs[i], &us[(first + i) % count], us[(first + i) % count].tcp, last_error);
        /* A connected nonblocking socket can try sending immediately. A TCP
         * connect still waits for poll/SO_ERROR; EAGAIN keeps SENDING pending. */
        if (xs[i].state == SENDING) advance(&xs[i], POLLOUT, uq, &parsed, view, last_error);
    }
    bool have_error_response = false;
    int result = -1;
    while (milliseconds() < deadline) {
        struct pollfd fds[3];
        unsigned live = 0;
        uint64_t now = milliseconds(), wake = deadline;
        if (now >= deadline) break;
        for (unsigned i = 0; i < concurrent; i++) {
            fds[i].fd = xs[i].fd;
            fds[i].events = xs[i].state == CONNECTING || xs[i].state == SENDING ? POLLOUT : POLLIN;
            fds[i].revents = 0;
            if (xs[i].state != DEAD) live++;
            if (xs[i].state == UDP_READING) {
                if (xs[i].udp_retry <= now) fds[i].events |= POLLOUT;
                else if (xs[i].udp_retry < wake) wake = xs[i].udp_retry;
            }
        }
        if (!live) break;
        int n = poll(fds, concurrent, (int)(wake - now));
        if (n < 0) { if (errno == EINTR) continue; syserr(last_error, "poll upstreams"); break; }
        if (!n) continue; /* A one-second resend timer does not end the exchange. */
        for (unsigned i = 0; i < concurrent; i++) {
            if (!fds[i].revents || xs[i].state == DEAD) continue;
            int status = advance(&xs[i], fds[i].revents, uq, &parsed, view, last_error);
            if (status == 1) {
                unsigned rcode = md_dns_view_rcode(&xs[i].packet, view);
                memcpy(r->data, xs[i].packet.data, xs[i].packet.len); r->len = xs[i].packet.len;
                /* 只复制已用的 RR 描述符；错误响应暂存期间 scratch 会被后续包覆盖。 */
                if (rv) md_dns_view_copy(rv, view);
                md_write16(r->data, client_id);
                if (rcode == 0 || rcode == 3) {
                    keep_response(&xs[i], fds[i].revents); result = 0; goto finished;
                }
                have_error_response = true; stop(&xs[i]);
            }
            /* Check readable replies first, then service a due retry. Invalid
             * replies cannot suppress retries; TCP fallback has no UDP timer.
             * POLLOUT avoids a busy loop when the UDP send buffer is full. */
            uint64_t retry_now = milliseconds();
            if (!status && xs[i].state == UDP_READING && (fds[i].revents & POLLOUT) &&
                retry_now >= xs[i].udp_retry && retry_now < deadline)
                resend_udp(&xs[i], uq, last_error);
        }
    }
    if (have_error_response) result = 0;
    else if (err) {
        if (milliseconds() >= deadline) snprintf(last_error, sizeof(last_error), "upstream query timed out after 5 seconds");
        snprintf(err, MD_ERROR_SIZE, "%s", last_error);
    }
finished:
    /* 胜出且符合条件的连接已交回池；这里关闭所有其他仍在竞争的连接。 */
    for (unsigned i = 0; i < concurrent; i++) stop(&xs[i]);
    if (scoped) worker_tcp->exchanges_in_use = false;
    else { free(xs); free(uq); free(view); }
    return result;
}
