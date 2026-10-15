/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 用原始报文和 loopback 上游覆盖 DNS 校验、TCP 分帧、TC 回退与重传资源释放。 */
#include "mosdns.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

static void make_query(md_packet *q) {
    memset(q, 0, sizeof(*q));
    md_write16(q->data, 0x1234); md_write16(q->data + 2, 0x0100); md_write16(q->data + 4, 1);
    const uint8_t question[] = {7,'E','x','a','m','p','l','e',3,'c','o','m',0,0,1,0,1};
    memcpy(q->data + 12, question, sizeof(question)); q->len = 12 + sizeof(question);
}
static void add_a(md_packet *p, unsigned section) {
    uint8_t rr[] = {0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,1};
    memcpy(p->data + p->len, rr, sizeof(rr)); p->len += sizeof(rr);
    size_t at = 6 + section * 2;
    md_write16(p->data + at, (uint16_t)(md_read16(p->data + at) + 1));
}
static void add_opt(md_packet *p, unsigned size) {
    uint8_t rr[] = {0,0,41,0,0,0,0,0x80,0,0,0};
    md_write16(rr + 3, (uint16_t)size);
    memcpy(p->data + p->len, rr, sizeof(rr)); p->len += sizeof(rr);
    md_write16(p->data + 10, (uint16_t)(md_read16(p->data + 10) + 1));
}
static int count_rr(const md_packet *p, const md_rr *rr, void *v) {
    (void)p; assert(rr->type == 1 && rr->section == 0 && rr->ttl == 60);
    (*(unsigned *)v)++; return 0;
}
/* 在同一报文上逐项破坏字段，验证 ID/名称/结构校验不会仅依赖报头。 */
static void dns_tests(void) {
    md_packet q, r, copy;
    md_question parsed; char err[MD_ERROR_SIZE];
    make_query(&q);
    assert(!md_dns_question(&q, &parsed, err));
    assert(!strcmp(parsed.name, "example.com") && parsed.type == 1 && parsed.class_ == 1 && parsed.udp_size == 512);
    assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
    assert(md_dns_response_matches(&q, &r));
    unsigned seen = 0;
    assert(!md_dns_records(&r, count_rr, &seen, err) && seen == 1);
    md_write16(r.data, 0x1235); assert(!md_dns_response_matches(&q, &r)); md_write16(r.data, 0x1234);
    r.data[20] = 'o'; assert(!md_dns_response_matches(&q, &r)); r.data[20] = 3;
    assert(!md_dns_error(&q, &r, 2));
    assert((md_read16(r.data + 2) & 15) == 2 && r.len == q.len && !md_read16(r.data + 6));
    assert(md_dns_error(&q, &r, 16));

    /* Header, question, pointer bounds/cycles, and expansion bounds. */
    copy = q; copy.len = 11; assert(md_dns_question(&copy, &parsed, err));
    copy = q; md_write16(copy.data + 4, 2); assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.data[12] = 0xc0; copy.data[13] = 12; assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.data[12] = 0xc0; copy.data[13] = 0xff; assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.data[12] = 64; assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.data[13] = 0; assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.len = 12;
    for (unsigned i = 0; i < 4; i++) { copy.data[copy.len++] = 63; memset(copy.data + copy.len, 'a', 63); copy.len += 63; }
    copy.data[copy.len++] = 0; memset(copy.data + copy.len, 0, 4); copy.len += 4;
    assert(md_dns_question(&copy, &parsed, err));

    assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
    copy = r; copy.data[copy.len - 5] = 5; assert(md_dns_records(&copy, NULL, NULL, err));
    copy = r; copy.data[copy.len - 6] = 0xff; assert(md_dns_records(&copy, NULL, NULL, err));
    copy = r; copy.data[copy.len++] = 0; assert(md_dns_records(&copy, NULL, NULL, err));
    copy = r; add_a(&copy, 0); copy.len--;
    seen = 0; assert(md_dns_records(&copy, count_rr, &seen, err) && seen == 0);
    copy = q; size_t start = copy.len;
    const uint8_t cyclic[] = {1,'a',0xc0,0,0,1,0,1,0,0,0,60,0,4,192,0,2,1};
    memcpy(copy.data + start, cyclic, sizeof(cyclic)); copy.data[start + 3] = (uint8_t)start;
    copy.len += sizeof(cyclic); md_write16(copy.data + 6, 1);
    assert(md_dns_records(&copy, NULL, NULL, err));

    add_opt(&q, 1232);
    assert(!md_dns_question(&q, &parsed, err) && parsed.udp_size == 1232 && parsed.do_bit);
    size_t original = r.len; add_opt(&r, 1232);
    assert(!md_dns_strip_opt(&r) && r.len == original && !md_read16(r.data + 10));
    add_opt(&r, 1232); add_a(&r, 2); copy = r;
    assert(md_dns_strip_opt(&r) && r.len == copy.len && !memcmp(r.data, copy.data, r.len));
    copy = q; add_opt(&copy, 1232); assert(md_dns_question(&copy, &parsed, err));
    copy = q; copy.data[copy.len++] = 0; md_write16(copy.data + copy.len - 3, 1);
    assert(md_dns_question(&copy, &parsed, err));

    make_query(&q); assert(!md_dns_error(&q, &r, 0));
    for (unsigned i = 0; i < 4; i++) {
        uint8_t txt[] = {0xc0,12,0,16,0,1,0,0,0,60,0,201,200};
        memcpy(r.data + r.len, txt, sizeof(txt)); r.len += sizeof(txt);
        memset(r.data + r.len, 'x', 200); r.len += 200;
    }
    md_write16(r.data + 6, 4); assert(!md_dns_records(&r, NULL, NULL, err));
    copy = r; add_opt(&q, 1232); md_dns_limit_udp(&q, &copy); assert(copy.len == r.len);
    assert(!md_dns_strip_opt(&q)); md_dns_limit_udp(&q, &r);
    assert(r.len == q.len && (md_read16(r.data + 2) & 0x0200) && !md_read16(r.data + 6));
}

static void address_tests(void) {
    struct sockaddr_storage addr; socklen_t len; char err[MD_ERROR_SIZE]; md_upstream u;
    assert(!md_parse_address("127.0.0.1", 5353, &addr, &len, err));
    assert(addr.ss_family == AF_INET && ntohs(((struct sockaddr_in *)&addr)->sin_port) == 5353);
    assert(!md_parse_address("[::1]:1053", 53, &addr, &len, err));
    assert(addr.ss_family == AF_INET6 && ntohs(((struct sockaddr_in6 *)&addr)->sin6_port) == 1053);
    assert(!md_parse_address("::1", 53, &addr, &len, err));
    assert(!md_parse_address(":0", 53, &addr, &len, err));
    assert(md_parse_address("dns.example", 53, &addr, &len, err));
    assert(md_parse_address("127.0.0.1:65536", 53, &addr, &len, err));
    assert(md_parse_address("[::1]:-1", 53, &addr, &len, err));
    assert(md_parse_address("[::1]garbage", 53, &addr, &len, err));
    assert(!md_upstream_init(&u, "udp://127.0.0.1", NULL, 0, NULL, err) && !u.tcp);
    assert(!md_upstream_init(&u, "tcp://[::1]:53", NULL, 0, NULL, err) && u.tcp);
    assert(!md_upstream_init(&u, "tcp://dns.example", "127.0.0.1:5353", 0, NULL, err));
    assert(md_upstream_init(&u, "https://127.0.0.1/dns-query", NULL, 0, NULL, err));
    assert(md_upstream_init(&u, "udp://127.0.0.1/path", NULL, 0, NULL, err));
    assert(md_upstream_init(&u, "127.0.0.1:0", NULL, 0, NULL, err));
    assert(md_upstream_init(&u, ":53", NULL, 0, NULL, err));
    assert(md_upstream_init(&u, "udp://:53", "127.0.0.1", 0, NULL, err));
    assert(md_upstream_init(&u, "127.0.0.1", ":53", 0, NULL, err));
#ifndef __linux__
    assert(!md_upstream_init(&u, "127.0.0.1", NULL, 1, NULL, err));
    md_packet q, r; make_query(&q);
    assert(md_forward(&u, 1, 1, &q, &r, err) && strstr(err, "require Linux"));
#endif
}

typedef struct { int udp, tcp; unsigned mode, delay_ms; uint16_t seen_id; } fixture;
static bool exact_read(int fd, uint8_t *p, size_t len) {
    while (len) { ssize_t n = recv(fd, p, len, 0); if (n <= 0) return false; p += n; len -= (size_t)n; }
    return true;
}
static void write_frame(int fd, const md_packet *p, bool partial) {
    uint8_t frame[MD_MAX_PACKET + 2]; md_write16(frame, (uint16_t)p->len); memcpy(frame + 2, p->data, p->len);
    for (size_t at = 0; at < p->len + 2;) {
        size_t wanted = partial ? 1 : p->len + 2 - at;
        ssize_t n = send(fd, frame + at, wanted, 0); assert(n > 0); at += (size_t)n;
        if (partial) { struct timespec t = {0, 1000000}; nanosleep(&t, NULL); }
    }
}
static void *serve_fixture(void *arg) {
    fixture *f = arg; md_packet q, r;
    if (f->udp >= 0) {
        struct sockaddr_storage peer; socklen_t len = sizeof(peer);
        ssize_t n = recvfrom(f->udp, q.data, sizeof(q.data), 0, (struct sockaddr *)&peer, &len); assert(n > 0);
        q.len = (size_t)n; assert(!md_dns_error(&q, &r, 0)); f->seen_id = md_read16(q.data);
        if (f->delay_ms) {
            struct timespec pause = {f->delay_ms / 1000, (long)(f->delay_ms % 1000) * 1000000};
            nanosleep(&pause, NULL);
        }
        if (f->mode == 3) md_write16(r.data + 2, (uint16_t)(md_read16(r.data + 2) | 0x0200));
        else if (f->mode == 4) {
            add_opt(&r, 1232); r.data[r.len - 6] = 1; /* BADVERS = extended RCODE 1, low RCODE 0. */
        }
        else {
            add_a(&r, 0); md_write16(r.data, 0x4321);
            assert(sendto(f->udp, r.data, r.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)r.len);
            md_write16(r.data, md_read16(q.data));
            /* M4: the right ID with a different question (QTYPE AAAA) is ignored too. */
            md_packet bad = r; md_question question;
            assert(!md_dns_question(&bad, &question, NULL)); md_write16(bad.data + question.end - 4, 28);
            assert(sendto(f->udp, bad.data, bad.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)bad.len);
        }
        assert(sendto(f->udp, r.data, r.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)r.len);
    }
    if (f->tcp >= 0) {
        struct pollfd pfd = { .fd = f->tcp, .events = POLLIN }; assert(poll(&pfd, 1, 2000) == 1);
        int fd = accept(f->tcp, NULL, NULL); assert(fd >= 0);
        struct timeval timeout = {2, 0}; assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        uint8_t prefix[2]; assert(exact_read(fd, prefix, 2)); q.len = md_read16(prefix); assert(exact_read(fd, q.data, q.len));
        f->seen_id = md_read16(q.data);
        assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
        if (f->mode == 2) { md_write16(r.data, 0x4321); write_frame(fd, &r, true); md_write16(r.data, md_read16(q.data)); }
        write_frame(fd, &r, true); close(fd);
    }
    return NULL;
}
static int try_bound_socket(int type, uint16_t *port) {
    int fd = socket(AF_INET, type, 0); assert(fd >= 0);
    /* UDP upstream fixtures must own distinct endpoints. SO_REUSEADDR permits
     * two live UDP listeners to share an address/port on Linux, so competing
     * upstreams can be delivered to one fixture and look like a source-port
     * change. Only TCP needs address reuse for its TIME_WAIT lifecycle. */
    if (type == SOCK_STREAM) {
        int one = 1; assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    }
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(*port) };
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    int bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
    if (bound) { int saved = errno; close(fd); errno = saved; return -1; }
    socklen_t len = sizeof(address); assert(!getsockname(fd, (struct sockaddr *)&address, &len)); *port = ntohs(address.sin_port);
    struct timeval timeout = {2, 0}; assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    if (type == SOCK_STREAM) assert(!listen(fd, 2));
    return fd;
}
static int bound_socket(int type, uint16_t *port) {
    int fd = try_bound_socket(type, port);
    if (fd < 0) {
        fprintf(stderr, "fixture bind type=%d requested_port=%u: ", type, (unsigned)*port);
        perror("bind");
    }
    assert(fd >= 0); return fd;
}
/* Choosing a free TCP port does not reserve its UDP counterpart. Keep both
 * sockets open together; on a setup-only collision close our TCP reservation
 * and try a fresh ephemeral pair. No query assertion or timeout is retried. */
static void bound_pair(int *tcp, int *udp, uint16_t *port) {
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        *tcp = try_bound_socket(SOCK_STREAM, port);
        if (*tcp < 0) { assert(errno == EADDRINUSE); *port = 0; continue; }
        *udp = try_bound_socket(SOCK_DGRAM, port);
        if (*udp >= 0) return;
        int saved = errno; close(*tcp); *tcp = -1;
        assert(saved == EADDRINUSE); *port = 0;
    }
    assert(!"could not reserve fixture TCP/UDP pair");
}
/* A second reusable UDP listener must not be able to steal this endpoint.
 * This fails with the former SO_REUSEADDR-on-both fixture on Linux. */
static void fixture_exclusive_test(void) {
    uint16_t port = 0;
    int owner = bound_socket(SOCK_DGRAM, &port);
    int other = socket(AF_INET, SOCK_DGRAM, 0); assert(other >= 0);
    int one = 1; assert(!setsockopt(other, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(port) };
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    assert(bind(other, (struct sockaddr *)&address, sizeof(address)) == -1 && errno == EADDRINUSE);
    close(other);
    /* Force the former cross-protocol setup race: UDP is already owned but
     * the requested TCP port may be free. The pair must select another port. */
    uint16_t pair_port = port; int tcp = -1, udp = -1;
    bound_pair(&tcp, &udp, &pair_port);
    assert(pair_port != port && tcp >= 0 && udp >= 0);
    close(tcp); close(udp); close(owner);
}
/* 可控 UDP/TCP 响应验证回退和多上游竞争；错误响应不能抢先压过有效答案。 */
static void upstream_tests(void) {
    unsigned client_ids_seen = 0;
    for (unsigned mode = 1; mode <= 3; mode++) {
        uint16_t port = 0;
        fixture f = { .udp = -1, .tcp = -1, .mode = mode };
        if (mode == 3) bound_pair(&f.tcp, &f.udp, &port);
        else if (mode == 2) f.tcp = bound_socket(SOCK_STREAM, &port);
        else f.udp = bound_socket(SOCK_DGRAM, &port);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_fixture, &f));
        char address[64], err[MD_ERROR_SIZE];
        snprintf(address, sizeof(address), "%s://127.0.0.1:%u", mode == 2 ? "tcp" : "udp", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_packet q, r; make_query(&q);
        assert(!md_forward(&u, 1, 1, &q, &r, err));
        assert(md_dns_response_matches(&q, &r) && md_read16(r.data + 6) == 1 && !(md_read16(r.data + 2) & 0x0200));
        assert(!pthread_join(thread, NULL));
        /* M4: the upstream sees a random ID; the client gets its own ID back. */
        assert(md_read16(r.data) == 0x1234); client_ids_seen += f.seen_id == 0x1234;
        if (f.udp >= 0) close(f.udp);
        if (f.tcp >= 0) close(f.tcp);
    }
    assert(client_ids_seen <= 1); /* 3 random IDs: all-but-impossible to repeat 0x1234 twice. */
    /* The first response may be an EDNS error whose low RCODE looks like
     * NOERROR. Wait for the usable answer, and close the other exchange. */
    uint16_t ports[2] = {0, 0};
    fixture fixtures[2] = {{ .tcp = -1, .mode = 4 }, { .tcp = -1, .mode = 1, .delay_ms = 80 }};
    pthread_t threads[2]; md_upstream upstreams[2]; char err[MD_ERROR_SIZE];
    for (unsigned i = 0; i < 2; i++) {
        fixtures[i].udp = bound_socket(SOCK_DGRAM, &ports[i]);
        char address[64]; snprintf(address, sizeof(address), "127.0.0.1:%u", ports[i]);
        assert(!md_upstream_init(&upstreams[i], address, NULL, 0, NULL, err));
        assert(!pthread_create(&threads[i], NULL, serve_fixture, &fixtures[i]));
    }
    md_packet q, r; make_query(&q);
    assert(!md_forward(upstreams, 2, 100, &q, &r, err));
    assert(md_read16(r.data + 6) == 1 && !md_read16(r.data + 10));
    for (unsigned i = 0; i < 2; i++) { assert(!pthread_join(threads[i], NULL)); close(fixtures[i].udp); }
}

typedef enum { DROP_QUERY, DROP_RESPONSE, INVALID_REPLY, BLACKHOLE, DELAY_TCP, LATE_TCP, RACE_RETRY } retry_mode;
typedef struct {
    int udp, tcp;
    retry_mode mode;
    atomic_bool stop;
    unsigned queries;
    uint16_t source_port;
    uint64_t received[8];
} retry_fixture;
static uint64_t monotonic_ms(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static unsigned open_fds(void) {
    unsigned count = 0;
    for (int i = 0; i < 512; i++) if (fcntl(i, F_GETFD) >= 0) count++;
    return count;
}
static void send_reply(int fd, const md_packet *r, const struct sockaddr_in *peer) {
    assert(sendto(fd, r->data, r->len, 0, (const struct sockaddr *)peer, sizeof(*peer)) == (ssize_t)r->len);
}
static void *serve_retry(void *arg) {
    retry_fixture *f = arg;
    md_packet q, first, r;
    bool sent = false;
    while (!atomic_load(&f->stop)) {
        struct pollfd pf = { .fd = f->udp, .events = POLLIN };
        int ready = poll(&pf, 1, 100);
        assert(ready >= 0);
        if (!ready) continue;
        struct sockaddr_in peer; socklen_t len = sizeof(peer);
        ssize_t n = recvfrom(f->udp, q.data, sizeof(q.data), 0, (struct sockaddr *)&peer, &len);
        assert(n > 0); q.len = (size_t)n;
        assert(f->queries < 8);
        f->received[f->queries++] = monotonic_ms();
        if (f->queries == 1) { first = q; f->source_port = peer.sin_port; }
        else {
            if (peer.sin_port != f->source_port) {
                struct sockaddr_in local; socklen_t local_len = sizeof(local);
                assert(!getsockname(f->udp, (struct sockaddr *)&local, &local_len));
                fprintf(stderr, "retry fixture mode=%u local=%u queries=%u first_peer=%u peer=%u first_id=%u id=%u\n",
                        (unsigned)f->mode, ntohs(local.sin_port), f->queries,
                        ntohs(f->source_port), ntohs(peer.sin_port), md_read16(first.data), md_read16(q.data));
            }
            assert(peer.sin_port == f->source_port);
            assert(q.len == first.len && !memcmp(q.data, first.data, q.len));
        }
        assert(!sent);
        if (f->mode == BLACKHOLE || (f->mode == DROP_QUERY && f->queries == 1)) continue;
        if (f->mode == LATE_TCP && f->queries < 4) continue;
        assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
        if (f->queries == 1 && f->mode == DROP_RESPONSE) continue;
        if (f->queries == 1 && f->mode == INVALID_REPLY) {
            md_write16(r.data, (uint16_t)(md_read16(q.data) + 1)); send_reply(f->udp, &r, &peer);
            md_write16(r.data, md_read16(q.data)); r.len--; send_reply(f->udp, &r, &peer);
            continue;
        }
        if (f->queries == 1 && f->mode == RACE_RETRY) continue;
        if (f->mode == DELAY_TCP || f->mode == LATE_TCP) {
            assert(f->queries == (f->mode == DELAY_TCP ? 1u : 4u));
            assert(!md_dns_error(&q, &r, 0));
            md_write16(r.data + 2, (uint16_t)(md_read16(r.data + 2) | 0x0200)); send_reply(f->udp, &r, &peer);
            struct pollfd accept_ready = { .fd = f->tcp, .events = POLLIN };
            assert(poll(&accept_ready, 1, 2500) == 1);
            int fd = accept(f->tcp, NULL, NULL); assert(fd >= 0);
            struct timeval timeout = {2, 0}; assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
            uint8_t prefix[2]; assert(exact_read(fd, prefix, 2)); q.len = md_read16(prefix);
            assert(exact_read(fd, q.data, q.len));
            assert(q.len == first.len && !memcmp(q.data, first.data, q.len));
            if (f->mode == LATE_TCP) {
                while (!atomic_load(&f->stop)) {
                    struct timespec pause = {0, 50000000}; assert(!nanosleep(&pause, NULL));
                }
                close(fd); return NULL;
            }
            struct timespec delay = {1, 400000000}; assert(!nanosleep(&delay, NULL));
            assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0); write_frame(fd, &r, false); close(fd);
        } else send_reply(f->udp, &r, &peer);
        sent = true;
    }
    return NULL;
}
/* 丢请求、丢响应、损坏回复及超时分别验证重传时序与 fd 清理；不是吞吐基准。 */
static void retry_tests(void) {
    for (retry_mode mode = DROP_QUERY; mode <= LATE_TCP; mode++) {
        fprintf(stderr, "retry fixture start mode=%u\n", (unsigned)mode);
        unsigned before = open_fds();
        uint16_t port = 0;
        retry_fixture fixture = { .tcp = -1, .mode = mode };
        atomic_init(&fixture.stop, false);
        if (mode == DELAY_TCP || mode == LATE_TCP) bound_pair(&fixture.tcp, &fixture.udp, &port);
        else fixture.udp = bound_socket(SOCK_DGRAM, &port);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_retry, &fixture));
        char address[64], err[MD_ERROR_SIZE]; snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_packet q, r; make_query(&q);
        uint64_t start = monotonic_ms();
        int result = md_forward(&u, 1, 1, &q, &r, err);
        uint64_t elapsed = monotonic_ms() - start;
        if (mode == BLACKHOLE || mode == LATE_TCP) {
            assert(result < 0 && strstr(err, "5 seconds"));
            assert(elapsed >= 4900 && elapsed < 6500);
        } else {
            assert(!result && md_dns_response_matches(&q, &r) && md_read16(r.data + 6) == 1);
            assert(elapsed >= 900 && elapsed < 3500);
        }
        /* Drain immediate duplicates; the fd count separately verifies closure. */
        struct timespec settle = {0, 150000000}; assert(!nanosleep(&settle, NULL));
        atomic_store(&fixture.stop, true); assert(!pthread_join(thread, NULL));
        if (mode == BLACKHOLE) assert(fixture.queries >= 2 && fixture.queries <= 5);
        else if (mode == DELAY_TCP) assert(fixture.queries == 1);
        else if (mode == LATE_TCP) assert(fixture.queries == 4);
        else assert(fixture.queries == 2);
        close(fixture.udp); if (fixture.tcp >= 0) close(fixture.tcp);
        assert(open_fds() == before);
    }
    /* Four configured upstreams still produce at most three exchanges; a
     * usable response after one retry closes every loser and its retry timer. */
    unsigned before = open_fds();
    retry_fixture fixtures[4]; pthread_t threads[4]; md_upstream us[4];
    for (unsigned i = 0; i < 4; i++) {
        uint16_t port = 0;
        fixtures[i] = (retry_fixture){ .tcp = -1, .mode = RACE_RETRY };
        atomic_init(&fixtures[i].stop, false);
        fprintf(stderr, "race retry fixture index=%u requested_port=%u\n", i, (unsigned)port);
        fixtures[i].udp = bound_socket(SOCK_DGRAM, &port);
        char address[64], err[MD_ERROR_SIZE]; snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        assert(!md_upstream_init(&us[i], address, NULL, 0, NULL, err));
        assert(!pthread_create(&threads[i], NULL, serve_retry, &fixtures[i]));
    }
    md_packet q, r; char err[MD_ERROR_SIZE]; make_query(&q);
    assert(!md_forward(us, 4, 100, &q, &r, err) && md_dns_response_matches(&q, &r));
    struct timespec settle = {0, 150000000}; assert(!nanosleep(&settle, NULL));
    unsigned active = 0;
    for (unsigned i = 0; i < 4; i++) {
        atomic_store(&fixtures[i].stop, true); assert(!pthread_join(threads[i], NULL));
        if (fixtures[i].queries) { active++; assert(fixtures[i].queries <= 2); }
        close(fixtures[i].udp);
    }
    assert(active == 3 && open_fds() == before);
}
/* Opt-in UDP source-port reuse: default keeps unique ports; enabled reuses then rotates. */
typedef struct {
    int udp;
    atomic_bool stop;
    unsigned count;
    uint16_t ports[32];
} port_fixture;
static void *serve_ports(void *arg) {
    port_fixture *f = arg;
    while (!atomic_load(&f->stop)) {
        struct pollfd pf = { .fd = f->udp, .events = POLLIN };
        int ready = poll(&pf, 1, 50);
        assert(ready >= 0);
        if (!ready) continue;
        md_packet q, r; struct sockaddr_in peer; socklen_t len = sizeof(peer);
        ssize_t n = recvfrom(f->udp, q.data, sizeof(q.data), 0, (struct sockaddr *)&peer, &len);
        assert(n > 0); q.len = (size_t)n;
        assert(f->count < 32);
        f->ports[f->count++] = ntohs(peer.sin_port);
        assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
        assert(sendto(f->udp, r.data, r.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)r.len);
    }
    return NULL;
}
static unsigned distinct_ports(const uint16_t *ports, unsigned n) {
    unsigned d = 0;
    for (unsigned i = 0; i < n; i++) {
        unsigned j; for (j = 0; j < i; j++) if (ports[j] == ports[i]) break;
        if (j == i) d++;
    }
    return d;
}
static void udp_reuse_tests(void) {
    md_udp_sport_reuse off = {0, 16, 2000, 2};
    md_forward_set_udp_sport_reuse(&off);
    /* (a) Default: worker + idle still uses a unique source port per query. */
    {
        uint16_t port = 0; port_fixture f = { .udp = bound_socket(SOCK_DGRAM, &port) };
        atomic_init(&f.stop, false);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_ports, &f));
        char address[64], err[MD_ERROR_SIZE];
        snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_forward_worker_enable();
        for (unsigned i = 0; i < 10; i++) {
            md_packet q, r; make_query(&q); md_write16(q.data, (uint16_t)(0x1000 + i));
            assert(!md_forward(&u, 1, 1, &q, &r, err));
            md_forward_worker_idle();
        }
        struct timespec settle = {0, 100000000}; assert(!nanosleep(&settle, NULL));
        atomic_store(&f.stop, true); assert(!pthread_join(thread, NULL));
        assert(f.count == 10 && distinct_ports(f.ports, f.count) == 10);
        md_forward_worker_cleanup(); close(f.udp);
    }
    /* (b) Enabled: reuse within max_uses, then rotate to a new port. */
    {
        md_udp_sport_reuse on = {1, 4, 5000, 1};
        md_forward_set_udp_sport_reuse(&on);
        uint16_t port = 0; port_fixture f = { .udp = bound_socket(SOCK_DGRAM, &port) };
        atomic_init(&f.stop, false);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_ports, &f));
        char address[64], err[MD_ERROR_SIZE];
        snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_forward_worker_enable();
        for (unsigned i = 0; i < 8; i++) {
            md_packet q, r; make_query(&q); md_write16(q.data, (uint16_t)(0x2000 + i));
            assert(!md_forward(&u, 1, 1, &q, &r, err));
            md_forward_worker_idle();
        }
        struct timespec settle = {0, 100000000}; assert(!nanosleep(&settle, NULL));
        atomic_store(&f.stop, true); assert(!pthread_join(thread, NULL));
        assert(f.count == 8);
        unsigned distinct = distinct_ports(f.ports, f.count);
        /* 8 queries / max_uses 4 => about 2 ports; allow a little slack for prewarm. */
        assert(distinct >= 2 && distinct <= 3);
        assert(f.ports[0] == f.ports[1] && f.ports[0] == f.ports[2] && f.ports[0] == f.ports[3]);
        assert(f.ports[4] != f.ports[0]);
        assert(f.ports[4] == f.ports[5] && f.ports[4] == f.ports[6] && f.ports[4] == f.ports[7]);
        md_forward_worker_cleanup(); close(f.udp);
    }
    /* (c) Age expiry forces a new port even when uses remain. */
    {
        md_udp_sport_reuse on = {1, 100, 200, 1};
        md_forward_set_udp_sport_reuse(&on);
        uint16_t port = 0; port_fixture f = { .udp = bound_socket(SOCK_DGRAM, &port) };
        atomic_init(&f.stop, false);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_ports, &f));
        char address[64], err[MD_ERROR_SIZE];
        snprintf(address, sizeof(address), "127.0.0.1:%u", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_forward_worker_enable();
        md_packet q, r; make_query(&q);
        assert(!md_forward(&u, 1, 1, &q, &r, err)); md_forward_worker_idle();
        assert(!md_forward(&u, 1, 1, &q, &r, err)); md_forward_worker_idle();
        struct timespec wait = {0, 350000000}; assert(!nanosleep(&wait, NULL));
        /* Force age sweep: maintenance may be false after idle, so take a dead path
         * by setting maintenance via a no-op park miss — call idle after marking. */
        md_forward_worker_idle();
        assert(!md_forward(&u, 1, 1, &q, &r, err)); md_forward_worker_idle();
        struct timespec settle = {0, 100000000}; assert(!nanosleep(&settle, NULL));
        atomic_store(&f.stop, true); assert(!pthread_join(thread, NULL));
        assert(f.count == 3);
        assert(f.ports[0] == f.ports[1]);
        assert(f.ports[2] != f.ports[0]);
        md_forward_worker_cleanup(); close(f.udp);
    }
    md_forward_set_udp_sport_reuse(&off);
}
/* ---- md_dns_view：与旧的逐次解析接口做差分，保证"一次解析"不放宽校验 ---- */
static bool same_rr(const md_rr *a, const md_rr *b) {
    return a->ttl_offset == b->ttl_offset && a->data_offset == b->data_offset && a->type == b->type &&
        a->class_ == b->class_ && a->data_len == b->data_len && a->ttl == b->ttl && a->section == b->section;
}
typedef struct { unsigned n; md_rr rr[64]; } rr_list;
static int list_rr(const md_packet *p, const md_rr *rr, void *v) {
    (void)p; rr_list *l = v; if (l->n < 64) l->rr[l->n] = *rr; l->n++; return 0;
}
static uint64_t view_rng = 0x9e3779b97f4a7c15u;
static uint32_t view_rand(void) {
    view_rng ^= view_rng << 13; view_rng ^= view_rng >> 7; view_rng ^= view_rng << 17;
    return (uint32_t)view_rng;
}
static void view_add_rr(md_packet *p, unsigned section, const uint8_t *owner, size_t owner_len,
                        uint16_t type, uint32_t ttl, const uint8_t *data, size_t len) {
    memcpy(p->data + p->len, owner, owner_len); p->len += owner_len;
    md_write16(p->data + p->len, type); md_write16(p->data + p->len + 2, 1);
    md_write32(p->data + p->len + 4, ttl); md_write16(p->data + p->len + 8, (uint16_t)len);
    p->len += 10; if (len) memcpy(p->data + p->len, data, len); p->len += len;
    size_t at = 6 + section * 2; md_write16(p->data + at, (uint16_t)(md_read16(p->data + at) + 1));
}
/* 对同一报文比较：校验结论、问题段、RR 序列、TTL 规范化、extended RCODE、匹配。 */
static void view_compare(const md_packet *q, const md_packet *m, md_dns_view *v) {
    md_question lq; char err[MD_ERROR_SIZE];
    bool legacy = !md_dns_question(m, &lq, err) && !md_dns_records(m, NULL, NULL, err);
    bool viewed = !md_dns_view_parse(m, v, err);
    assert(legacy == viewed);
    assert(md_dns_response_matches(q, m) == (viewed && md_dns_question(q, &lq, NULL) == 0 &&
           md_dns_view_matches(q, &lq, m, v)));
    if (!viewed) { assert(!v->valid && md_dns_view_each(m, v, NULL, NULL, err)); return; }
    assert(!md_dns_question(m, &lq, err));
    assert(!strcmp(lq.name, v->q.name) && lq.type == v->q.type && lq.class_ == v->q.class_ &&
           lq.flags == v->q.flags && lq.end == v->q.end && lq.udp_size == v->q.udp_size && lq.do_bit == v->q.do_bit);
    rr_list a = {0}, b = {0};
    assert(!md_dns_records(m, list_rr, &a, err) && !md_dns_view_each(m, v, list_rr, &b, err));
    assert(a.n == b.n && a.n == v->count);
    unsigned rcode = md_read16(m->data + 2) & 15, addresses = 0; bool signed_ = false;
    for (unsigned i = 0; i < a.n && i < 64; i++) {
        assert(same_rr(&a.rr[i], &b.rr[i]));
        if (a.rr[i].type == 41) rcode |= (a.rr[i].ttl >> 24) << 4;
        if (!a.rr[i].section && a.rr[i].class_ == 1 && (a.rr[i].type == 1 || a.rr[i].type == 28)) addresses++;
        if (a.rr[i].type == 250 || (a.rr[i].type == 24 && a.rr[i].section == 2)) signed_ = true;
    }
    if (a.n <= 64) { assert(addresses == v->addresses && signed_ == v->signed_); }
    assert(rcode == md_dns_view_rcode(m, v));
    md_packet *x = malloc(sizeof(*x)), *y = malloc(sizeof(*y)); assert(x && y);
    *x = *m; *y = *m;
    int rx = md_dns_normalize_ttl(x, err), ry = md_dns_normalize_ttl_view(y, v, err);
    /* Both fail or both succeed; on success the bytes are identical and the
     * view re-validated the rewritten packet. Failure contents may differ
     * (legacy stops mid-rewrite), but neither is then used. */
    assert(rx == ry);
    if (!ry) assert(x->len == y->len && !memcmp(x->data, y->data, x->len) && v->valid && v->len == y->len);
    else assert(!v->valid || (y->len == m->len && !memcmp(y->data, m->data, m->len)));
    free(x); free(y);
}
/* Regression: a compression pointer must target an earlier name start. A
 * pointer into an RR's TYPE/CLASS/TTL/RDLENGTH, opaque RDATA, the question's
 * QTYPE/QCLASS or the middle of a label makes the whole response invalid on
 * every parse path (legacy, view, TTL normalisation), so nothing is learned.
 * Previously TTL=0xC00C0000 made the TTL bytes a "pointer" and after TTL
 * normalisation to 0 the referring owner silently became the root name. */
static void ptr_target_tests(const md_packet *q, md_packet *m, md_dns_view *v) {
    char err[MD_ERROR_SIZE]; md_question parsed;
    const uint8_t ptr[] = {0xc0, 12}, a4[] = {192,0,2,1};
    /* RR1 owner (2) + TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) RDATA(4). */
    struct { const char *what; size_t delta; } bad[] = {
        {"TYPE", 2}, {"CLASS", 4}, {"TTL", 6}, {"TTL+2", 8}, {"RDLENGTH", 10}, {"RDATA", 12},
    };
    for (unsigned i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        for (unsigned ttlptr = 0; ttlptr < 2; ttlptr++) {
            assert(!md_dns_error(q, m, 0)); md_write16(m->data + 2, 0x8180);
            size_t base = m->len;
            /* With TTL=0xC00C0000 the TTL bytes look like a valid pointer to qname. */
            view_add_rr(m, 0, ptr, 2, 1, ttlptr ? 0xC00C0000u : 300, a4, 4);
            view_add_rr(m, 0, ptr, 2, 1, 300, a4, 4);
            uint8_t o[2] = {(uint8_t)(0xc0 | ((base + bad[i].delta) >> 8)), (uint8_t)(base + bad[i].delta)};
            view_add_rr(m, 0, o, 2, 1, 300, a4, 4);
            md_packet copy = *m;
            assert(md_dns_view_parse(m, v, err) && !v->valid && v->count == 0);
            assert(md_dns_question(m, &parsed, err));
            assert(md_dns_records(m, NULL, NULL, err));
            assert(md_dns_normalize_ttl(m, err) && !memcmp(m->data, copy.data, m->len));
            assert(!md_dns_response_matches(q, m));
            view_compare(q, m, v);
        }
    }
    /* Pointer into an rdata name start (CNAME target) is fine; into the
     * middle of a label or into the question's QTYPE is not. */
    assert(!md_dns_error(q, m, 0)); md_write16(m->data + 2, 0x8180);
    size_t cname_at = m->len + 12; const uint8_t cname[] = {3,'w','w','w',0xc0,12};
    view_add_rr(m, 0, ptr, 2, 5, 300, cname, sizeof(cname));
    md_packet good = *m;
    uint8_t o[2] = {(uint8_t)(0xc0 | (cname_at >> 8)), (uint8_t)cname_at};
    view_add_rr(m, 0, o, 2, 1, 300, a4, 4);
    assert(!md_dns_view_parse(m, v, err) && v->count == 2); view_compare(q, m, v);
    *m = good; o[1] = (uint8_t)(cname_at + 1); view_add_rr(m, 0, o, 2, 1, 300, a4, 4);
    assert(md_dns_view_parse(m, v, err)); view_compare(q, m, v);
    size_t qtype = q->len - 4;
    *m = good; o[0] = (uint8_t)(0xc0 | (qtype >> 8)); o[1] = (uint8_t)qtype; view_add_rr(m, 0, o, 2, 1, 300, a4, 4);
    assert(md_dns_view_parse(m, v, err)); view_compare(q, m, v);
    /* RFC 1035 single-name types (NS MD MF CNAME MB MG MR PTR): a later owner
     * may point at the RDATA name; the middle of its label is still rejected.
     * SRV/DNAME names (RFC 2782/6672) and RP (17, opaque per RFC 3597) are
     * never compression targets. */
    const uint16_t one_name[] = {2, 3, 4, 5, 7, 8, 9, 12, 39, 33, 17};
    for (unsigned i = 0; i < sizeof(one_name) / sizeof(one_name[0]); i++) {
        uint16_t t = one_name[i]; size_t pre = t == 33 ? 6 : 0;
        uint8_t rd[16] = {0}; size_t rl = pre;
        const uint8_t nm[] = {2,'m','b',0xc0,12}; memcpy(rd + rl, nm, sizeof(nm)); rl += sizeof(nm);
        bool target = t != 39 && t != 33 && t != 17;
        assert(!md_dns_error(q, m, 0)); md_write16(m->data + 2, 0x8180);
        size_t nat = m->len + 12 + pre;
        view_add_rr(m, 0, ptr, 2, t, 300, rd, rl);
        md_packet base = *m;
        assert(!md_dns_view_parse(m, v, err)); view_compare(q, m, v);
        uint8_t po[2] = {(uint8_t)(0xc0 | (nat >> 8)), (uint8_t)nat};
        view_add_rr(m, 0, po, 2, 1, 300, a4, 4);
        assert(target ? !md_dns_view_parse(m, v, err) && v->count == 2 : md_dns_view_parse(m, v, err) != 0);
        view_compare(q, m, v);
        if (target) { char n2[MD_ERROR_SIZE]; assert(!md_dns_records(m, NULL, NULL, n2)); }
        *m = base; po[1] = (uint8_t)(nat + 1); view_add_rr(m, 0, po, 2, 1, 300, a4, 4);
        assert(md_dns_view_parse(m, v, err)); view_compare(q, m, v);
    }
    /* MINFO (14): both RMAILBX and EMAILBX are targets; label bodies are not. */
    {
        const uint8_t mi[] = {1,'r',0xc0,12, 1,'e',0xc0,12};
        assert(!md_dns_error(q, m, 0)); md_write16(m->data + 2, 0x8180);
        size_t r0 = m->len + 12, e0 = r0 + 4;
        view_add_rr(m, 0, ptr, 2, 14, 300, mi, sizeof(mi));
        md_packet base = *m;
        size_t offs[] = {r0, e0, r0 + 1, e0 + 1};
        for (unsigned k = 0; k < 4; k++) {
            *m = base; uint8_t po[2] = {(uint8_t)(0xc0 | (offs[k] >> 8)), (uint8_t)offs[k]};
            view_add_rr(m, 0, po, 2, 1, 300, a4, 4);
            int rc = md_dns_view_parse(m, v, err);
            assert(k < 2 ? rc == 0 && v->count == 2 : rc != 0); view_compare(q, m, v);
        }
        /* Truncated MINFO (one name only) is malformed. */
        *m = base; m->len = 0; assert(!md_dns_error(q, m, 0)); md_write16(m->data + 2, 0x8180);
        view_add_rr(m, 0, ptr, 2, 14, 300, mi, 4);
        assert(md_dns_view_parse(m, v, err)); view_compare(q, m, v);
    }
    /* Qname pointing at its own first label (target not before the name). */
    md_packet self = *q; self.data[12] = 0xc0; self.data[13] = 12;
    assert(md_dns_question(&self, &parsed, err));
}
/* Request parse-once: md_dns_query_parse must accept/reject exactly like
 * md_dns_question (same error text and md_question), its cache EDNS flag must
 * equal the old make_key md_dns_records inspection, and the *_q helpers must
 * produce byte-identical results to their packet-only counterparts. */
typedef struct { unsigned opts; bool unsafe; } old_opts;
static int old_inspect(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p; old_opts *v = arg;
    if (rr->type != 41 || rr->section != 2 || ++v->opts > 1 || rr->data_len || (rr->ttl & 0xffff0000u)) v->unsafe = true;
    return 0;
}
static void query_compare(const md_packet *q) {
    char e1[MD_ERROR_SIZE] = "", e2[MD_ERROR_SIZE] = "";
    md_question a; md_dns_query v;
    int r1 = md_dns_question(q, &a, e1), r2 = md_dns_query_parse(q, &v, e2);
    assert(!r1 == !r2 && !strcmp(e1, e2));
    assert(md_dns_query_ok(q, &v) == !r2);
    if (!r1) {
        assert(!memcmp(&a, &v.q, sizeof(a)) && v.route == -1);
        old_opts o = {0}; assert(!md_dns_records(q, old_inspect, &o, NULL));
        assert(v.cache_edns_ok == !o.unsafe);
    }
    static md_packet r1p, r2p;
    for (unsigned rc = 0; rc < 3; rc++) {
        r1p.len = r2p.len = 0;
        assert(md_dns_error(q, &r1p, rc) == md_dns_error_q(q, &v, &r2p, rc));
        assert(r1p.len == r2p.len && !memcmp(r1p.data, r2p.data, r1p.len));
    }
    /* Oversized response against the request's UDP limit. */
    for (size_t big = 400; big <= 1400; big += 500) {
        memcpy(r1p.data, q->data, q->len); r1p.len = q->len; md_write16(r1p.data + 2, 0x8180);
        if (r1p.len < big) { memset(r1p.data + r1p.len, 0, big - r1p.len); r1p.len = big; }
        memcpy(r2p.data, r1p.data, r1p.len); r2p.len = r1p.len;
        md_dns_limit_udp(q, &r1p); md_dns_limit_udp_q(q, &v, &r2p);
        assert(r1p.len == r2p.len && !memcmp(r1p.data, r2p.data, r1p.len));
    }
    /* A stale view (length changed) is never trusted. */
    if (!r2 && q->len > 12) { static md_packet t; memcpy(t.data, q->data, q->len); t.len = q->len - 1; assert(!md_dns_query_ok(&t, &v)); }
}
static void query_parse_tests(void) {
    md_packet *seeds = calloc(8, sizeof(*seeds)), *m = malloc(sizeof(*m));
    const uint8_t qn[] = {3,'w','w','w',7,'e','x','a','m','p','l','e',2,'c','n',0,0,1,0,1};
    unsigned n = 0;
    for (unsigned k = 0; k < 6; k++) {
        md_packet *p = &seeds[n++];
        md_write16(p->data, 0x1234); md_write16(p->data + 2, 0x0100); md_write16(p->data + 4, 1);
        memcpy(p->data + 12, qn, sizeof(qn)); p->len = 12 + sizeof(qn);
        if (k == 1 || k == 2 || k == 3 || k == 5) { /* OPT: plain, ECS option, DO bit, non-zero version */
            uint8_t opt[11] = {0, 0,41, 0x04,0xd0, 0,0,0,0, 0,0};
            if (k == 3) opt[7] = 0x80;
            if (k == 5) opt[6] = 1;
            memcpy(p->data + p->len, opt, 11); p->len += 11; md_write16(p->data + 10, 1);
            if (k == 2) { const uint8_t ecs[] = {0,8,0,7,0,1,24,0,192,0,2}; md_write16(p->data + p->len - 2, sizeof(ecs));
                memcpy(p->data + p->len, ecs, sizeof(ecs)); p->len += sizeof(ecs); }
        }
        if (k == 4) { /* two OPTs (invalid) */
            uint8_t opt[11] = {0, 0,41, 0x04,0xd0, 0,0,0,0, 0,0};
            memcpy(p->data + p->len, opt, 11); p->len += 11; memcpy(p->data + p->len, opt, 11); p->len += 11;
            md_write16(p->data + 10, 2);
        }
    }
    /* Compressed question name (valid but not cacheable) and a QR=1 packet. */
    seeds[n] = seeds[0]; seeds[n].data[12] = 0xc0; seeds[n].data[13] = 12; n++;
    seeds[n] = seeds[1]; md_write16(seeds[n].data + 2, 0x8180); n++;
    for (unsigned i = 0; i < n; i++) query_compare(&seeds[i]);
    md_dns_query v; char err[MD_ERROR_SIZE];
    assert(!md_dns_query_parse(&seeds[0], &v, err) && v.cache_edns_ok);
    assert(!md_dns_query_parse(&seeds[2], &v, err) && !v.cache_edns_ok);
    assert(md_dns_query_parse(&seeds[4], &v, err) && !v.valid);
    /* Cache: *_q entry points with the request parse behave like the legacy
     * ones (cacheable plain/OPT/DO queries hit; ECS, bad version, two OPTs,
     * compressed QNAME and QR=1 never hit), across both entry styles. */
    for (unsigned i = 0; i < n; i++) {
        md_cache *c1 = md_cache_new(16, 0), *c2 = md_cache_new(16, 0);
        md_packet *r = malloc(sizeof(*r)), *o1 = malloc(sizeof(*o1)), *o2 = malloc(sizeof(*o2));
        md_dns_view *rv = malloc(sizeof(*rv));
        md_dns_query qv; bool ok = !md_dns_query_parse(&seeds[i], &qv, NULL);
        *r = seeds[i]; md_write16(r->data + 2, (uint16_t)(md_read16(r->data + 2) | 0x8080));
        r->len = 12 + sizeof(qn); md_write16(r->data + 10, 0); md_write16(r->data + 6, 1);
        const uint8_t a4[] = {0xc0,12,0,1,0,1,0,0,0,60,0,4,192,0,2,1};
        memcpy(r->data + r->len, a4, sizeof(a4)); r->len += sizeof(a4);
        if (i == n - 2) { r->data[12] = 0xc0; r->data[13] = 12; r->len = seeds[i].len; } /* compressed */
        if (!md_dns_view_parse(r, rv, NULL)) {
            md_cache_put_view(c1, &seeds[i], r, rv, 100);
            md_cache_put_q(c2, &seeds[i], ok ? &qv : NULL, r, rv, 100);
        }
        int h1 = md_cache_get(c1, &seeds[i], o1, 101);
        int h2 = md_cache_get_q(c2, &seeds[i], ok ? &qv : NULL, o2, rv, 101);
        assert(h1 == h2 && (!h1 || (o1->len == o2->len && !memcmp(o1->data, o2->data, o1->len))));
        assert(h1 == (i == 0 || i == 1 || i == 3));
        int h3 = md_cache_get(c2, &seeds[i], o1, 101);
        assert(h3 == h1);
        assert(md_cache_refresh_begin_q(c1, &seeds[i], ok ? &qv : NULL) == md_cache_refresh_begin(c2, &seeds[i]));
        md_cache_refresh_end(c1, &seeds[i]); md_cache_refresh_end_q(c2, &seeds[i], ok ? &qv : NULL);
        if (h1) assert(md_cache_refresh_begin(c1, &seeds[i]) && md_cache_refresh_begin_q(c2, &seeds[i], &qv));
        md_cache_free(c1); md_cache_free(c2); free(r); free(o1); free(o2); free(rv);
    }
    /* Copy only the used bytes: whole-md_packet copies dominate on musl/qemu. */
    for (unsigned i = 0; i < 100000; i++) {
        const md_packet *sd = &seeds[view_rand() % n];
        memcpy(m->data, sd->data, sd->len + 8); m->len = sd->len;
        unsigned flips = 1 + view_rand() % 3;
        for (unsigned f = 0; f < flips; f++) {
            unsigned kind = view_rand() % 6;
            if (kind < 4 && m->len) m->data[view_rand() % m->len] = (uint8_t)view_rand();
            else if (kind == 4 && m->len > 12) m->len -= 1 + view_rand() % 4;
            else md_write16(m->data + 4 + 2 * (view_rand() % 4), (uint16_t)(view_rand() % 3));
        }
        query_compare(m);
    }
    free(seeds); free(m);
}
static void view_tests(void) {
    md_dns_view *v = malloc(sizeof(*v)); assert(v);
    md_packet q, r, *m = malloc(sizeof(*m)); char err[MD_ERROR_SIZE]; assert(m);
    make_query(&q);
    const uint8_t ptr[] = {0xc0, 12}, root[] = {0}, a4[] = {192,0,2,1};
    const uint8_t a6[16] = {0x20,0x01,0x0d,0xb8,[15]=9};
    /* Seeds: A/AAAA/CNAME with compression, authority SOA, OPT, TXT, TSIG. */
    md_packet seeds[6]; unsigned nseeds = 0;
    assert(!md_dns_error(&q, &r, 0)); md_write16(r.data + 2, 0x8180);
    view_add_rr(&r, 0, ptr, 2, 1, 60, a4, 4); seeds[nseeds++] = r;
    const uint8_t cname[] = {3,'w','w','w',0xc0,12};
    view_add_rr(&r, 0, ptr, 2, 5, 0x80000000u, cname, sizeof(cname));
    view_add_rr(&r, 0, ptr, 2, 28, 100000, a6, 16); seeds[nseeds++] = r;
    uint8_t soa[2 + 2 + 20] = {0xc0,12,0xc0,12}; md_write32(soa + 4 + 16, 30);
    view_add_rr(&r, 1, ptr, 2, 6, 300, soa, sizeof(soa));
    uint8_t opt[4] = {0, 8, 0, 0};
    view_add_rr(&r, 2, root, 1, 41, 0x01008000u, opt, 4); md_write16(r.data + r.len - 4 - 10 + 2, 1232);
    seeds[nseeds++] = r;
    const uint8_t txt[] = {3,'a','b','c',0};
    assert(!md_dns_error(&q, &r, 3)); view_add_rr(&r, 0, ptr, 2, 16, 10, txt, sizeof(txt)); seeds[nseeds++] = r;
    assert(!md_dns_error(&q, &r, 0)); view_add_rr(&r, 0, ptr, 2, 1, 99999, a4, 4);
    view_add_rr(&r, 2, ptr, 2, 250, 0, a4, 4); seeds[nseeds++] = r;
    for (unsigned s = 0; s < nseeds; s++) view_compare(&q, &seeds[s], v);
    /* TSIG: TTL policy change is refused on both paths, packet unchanged. */
    *m = seeds[4]; assert(!md_dns_view_parse(m, v, err) && v->signed_);
    assert(md_dns_normalize_ttl_view(m, v, err) && !memcmp(m->data, seeds[4].data, m->len));
    /* Random mutation differential (byte flips, truncation, extension, counts). */
    for (unsigned i = 0; i < 300000; i++) {
        *m = seeds[view_rand() % nseeds];
        unsigned flips = 1 + view_rand() % 4;
        for (unsigned f = 0; f < flips; f++) {
            unsigned kind = view_rand() % 8;
            if (kind < 5 && m->len) m->data[view_rand() % m->len] = (uint8_t)view_rand();
            else if (kind == 5 && m->len > 12) m->len -= 1 + view_rand() % 4;
            else if (kind == 6) { for (unsigned k = view_rand() % 6; k; k--) m->data[m->len++] = (uint8_t)view_rand(); }
            else md_write16(m->data + 6 + 2 * (view_rand() % 3), (uint16_t)(view_rand() % 5));
        }
        view_compare(&q, m, v);
    }
    /* Pointer chains: backward pointer-only chain of 255 hops is accepted,
     * 256 hops rejected. Every hop must land on an earlier name start, so the
     * chain is built from owner names: RR k's owner points at RR k-1's owner. */
    for (unsigned hops = 254; hops <= 256; hops++) {
        assert(!md_dns_error(&q, m, 0)); md_write16(m->data + 2, 0x8180);
        size_t prev = 12;
        for (unsigned h = 1; h < hops; h++) {
            size_t here = m->len;
            uint8_t o[2] = {(uint8_t)(0xc0 | (prev >> 8)), (uint8_t)prev};
            view_add_rr(m, 0, o, 2, 99, 1, NULL, 0); prev = here;
        }
        uint8_t owner[2] = {(uint8_t)(0xc0 | (prev >> 8)), (uint8_t)prev};
        view_add_rr(m, 0, owner, 2, 1, 1, a4, 4);
        int rc = md_dns_view_parse(m, v, err);
        assert(hops <= 255 ? rc == 0 : rc != 0);
        view_compare(&q, m, v);
    }
    ptr_target_tests(&q, m, v);
    /* Stale views (length changed) are refused by every view consumer. */
    *m = seeds[2]; assert(!md_dns_view_parse(m, v, err)); m->len--;
    assert(md_dns_view_each(m, v, NULL, NULL, err) && md_dns_normalize_ttl_view(m, v, err));
    assert(!md_dns_view_matches(&q, &(md_question){0}, m, v));
    /* Large answers up to the theoretical maximum RR count of a 64 KiB packet. */
    unsigned sizes[] = {256, 1000, 4000};
    for (unsigned s = 0; s < 3; s++) {
        assert(!md_dns_error(&q, m, 0)); md_write16(m->data + 2, 0x8180);
        for (unsigned i = 0; i < sizes[s]; i++) view_add_rr(m, 0, ptr, 2, 1, 60, a4, 4);
        assert(!md_dns_view_parse(m, v, err) && v->count == sizes[s] && v->addresses == sizes[s]);
        assert(md_dns_response_matches(&q, m));
    }
    memset(m, 0, sizeof(*m)); md_write16(m->data + 2, 0x8180); md_write16(m->data + 4, 1);
    m->len = 12; m->data[m->len++] = 0; md_write16(m->data + m->len, 1); md_write16(m->data + m->len + 2, 1); m->len += 4;
    unsigned most = 0;
    while (m->len + 11 <= MD_MAX_PACKET) { view_add_rr(m, 1, root, 1, 99, 1, NULL, 0); most++; }
    assert(most == 5956 && most <= MD_DNS_VIEW_MAX_RR);
    assert(!md_dns_view_parse(m, v, err) && v->count == most);
    free(m); free(v);
}

int main(void) {
    fixture_exclusive_test(); dns_tests(); view_tests(); query_parse_tests(); address_tests(); upstream_tests(); retry_tests(); udp_reuse_tests();
    puts("dns/upstream tests passed"); return 0;
}

