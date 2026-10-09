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

typedef struct { int udp, tcp; unsigned mode, delay_ms; } fixture;
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
        q.len = (size_t)n; assert(!md_dns_error(&q, &r, 0));
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
        }
        assert(sendto(f->udp, r.data, r.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)r.len);
    }
    if (f->tcp >= 0) {
        struct pollfd pfd = { .fd = f->tcp, .events = POLLIN }; assert(poll(&pfd, 1, 2000) == 1);
        int fd = accept(f->tcp, NULL, NULL); assert(fd >= 0);
        struct timeval timeout = {2, 0}; assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
        uint8_t prefix[2]; assert(exact_read(fd, prefix, 2)); q.len = md_read16(prefix); assert(exact_read(fd, q.data, q.len));
        assert(!md_dns_error(&q, &r, 0)); add_a(&r, 0);
        if (f->mode == 2) { md_write16(r.data, 0x4321); write_frame(fd, &r, true); md_write16(r.data, md_read16(q.data)); }
        write_frame(fd, &r, true); close(fd);
    }
    return NULL;
}
static int bound_socket(int type, uint16_t *port) {
    int fd = socket(AF_INET, type, 0); assert(fd >= 0);
    int one = 1; assert(!setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
    struct sockaddr_in address = { .sin_family = AF_INET, .sin_port = htons(*port) };
    assert(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);
    int bound = bind(fd, (struct sockaddr *)&address, sizeof(address));
    if (bound) perror("fixture bind");
    assert(!bound);
    socklen_t len = sizeof(address); assert(!getsockname(fd, (struct sockaddr *)&address, &len)); *port = ntohs(address.sin_port);
    struct timeval timeout = {2, 0}; assert(!setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)));
    if (type == SOCK_STREAM) assert(!listen(fd, 2));
    return fd;
}
/* 可控 UDP/TCP 响应验证回退和多上游竞争；错误响应不能抢先压过有效答案。 */
static void upstream_tests(void) {
    for (unsigned mode = 1; mode <= 3; mode++) {
        uint16_t port = 0;
        fixture f = { .udp = -1, .tcp = -1, .mode = mode };
        if (mode != 1) f.tcp = bound_socket(SOCK_STREAM, &port);
        if (mode != 2) f.udp = bound_socket(SOCK_DGRAM, &port);
        pthread_t thread; assert(!pthread_create(&thread, NULL, serve_fixture, &f));
        char address[64], err[MD_ERROR_SIZE];
        snprintf(address, sizeof(address), "%s://127.0.0.1:%u", mode == 2 ? "tcp" : "udp", port);
        md_upstream u; assert(!md_upstream_init(&u, address, NULL, 0, NULL, err));
        md_packet q, r; make_query(&q);
        assert(!md_forward(&u, 1, 1, &q, &r, err));
        assert(md_dns_response_matches(&q, &r) && md_read16(r.data + 6) == 1 && !(md_read16(r.data + 2) & 0x0200));
        assert(!pthread_join(thread, NULL));
        if (f.udp >= 0) close(f.udp);
        if (f.tcp >= 0) close(f.tcp);
    }
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
        unsigned before = open_fds();
        uint16_t port = 0;
        retry_fixture fixture = { .tcp = -1, .mode = mode };
        atomic_init(&fixture.stop, false);
        if (mode == DELAY_TCP || mode == LATE_TCP) fixture.tcp = bound_socket(SOCK_STREAM, &port);
        fixture.udp = bound_socket(SOCK_DGRAM, &port);
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
int main(void) {
    dns_tests(); address_tests(); upstream_tests(); retry_tests();
    puts("dns/upstream tests passed"); return 0;
}
