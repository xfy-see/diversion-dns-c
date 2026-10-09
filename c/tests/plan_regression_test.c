/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Layer 1 of docs/testing-plan-131.md. Native and target-device runnable. */
#include "mosdns.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void query(md_packet *p, uint16_t type, uint16_t class_, uint16_t flags) {
    const uint8_t qname[] = {7,'m','i','s','s','i','n','g',4,'z','o','n','e',4,'t','e','s','t',0};
    memset(p, 0, sizeof(*p));
    md_write16(p->data, 0x1234); md_write16(p->data + 2, flags); md_write16(p->data + 4, 1);
    memcpy(p->data + 12, qname, sizeof(qname)); p->len = 12 + sizeof(qname);
    md_write16(p->data + p->len, type); md_write16(p->data + p->len + 2, class_); p->len += 4;
}
static void add_a(md_packet *r, uint16_t class_, uint32_t ttl) {
    uint8_t rr[] = {0xc0,12,0,1,0,1,0,0,0,0,0,4,192,0,2,9};
    md_write16(rr + 4, class_); md_write32(rr + 6, ttl);
    memcpy(r->data + r->len, rr, sizeof(rr)); r->len += sizeof(rr);
    md_write16(r->data + 6, (uint16_t)(md_read16(r->data + 6) + 1));
}
static void add_soa(md_packet *r, uint32_t ttl) {
    /* Owner zone.test, and compressed MNAME/RNAME. 20 is its question offset. */
    uint8_t rr[] = {0xc0,20,0,6,0,1,0,0,0,0,0,24,0xc0,20,0xc0,20,
                   0,0,0,7,0,0,0,30,0,0,0,10,0,0,0,90,0,0,0,15};
    md_write32(rr + 6, ttl);
    memcpy(r->data + r->len, rr, sizeof(rr)); r->len += sizeof(rr);
    md_write16(r->data + 8, 1);
}
typedef struct { unsigned count; uint16_t class_; uint32_t ttl; bool soa; } record_check;
static int check_record(const md_packet *p, const md_rr *rr, void *opaque) {
    record_check *v = opaque;
    assert(rr->class_ == v->class_ && rr->ttl == v->ttl);
    assert(rr->type == (v->soa ? 6 : 1) && rr->section == (v->soa ? 1u : 0u));
    assert(p->data[rr->ttl_offset - 6] == 0xc0);
    assert(p->data[rr->ttl_offset - 5] == (v->soa ? 20 : 12));
    if (v->soa) {
        assert(rr->data_len == 24 && !memcmp(p->data + rr->data_offset, "\xc0\x14\xc0\x14", 4));
        const uint32_t expected[] = {7,30,10,90,15};
        for (unsigned i = 0; i < 5; ++i) assert(md_read32(p->data + rr->data_offset + 4 + i * 4) == expected[i]);
    } else {
        assert(rr->data_len == 4 && !memcmp(p->data + rr->data_offset, "\xc0\0\2\11", 4));
    }
    ++v->count; return 0;
}
static void records(md_packet *r, bool soa, uint16_t class_, uint32_t ttl) {
    record_check v = {0, class_, ttl, soa}; char err[MD_ERROR_SIZE];
    assert(!md_dns_records(r, check_record, &v, err) && v.count == 1);
}
static void flags_question_owner_class(void) {
    md_packet q, r, altered; char err[MD_ERROR_SIZE]; md_question parsed;
    query(&q, 1, 3, 0x0730); /* RD, CD, AD, AA and TC: reject must retain only RD/CD. */
    assert(!md_dns_error(&q, &r, 3));
    assert(md_read16(r.data) == 0x1234 && md_read16(r.data + 2) == 0x8193);
    assert(r.len == q.len && !memcmp(r.data + 12, q.data + 12, q.len - 12));
    assert(md_dns_response_matches(&q, &r));
    altered = r; md_write16(altered.data + 2, 0x0193); assert(!md_dns_response_matches(&q, &altered));
    altered = r; md_write16(altered.data + altered.len - 2, 1); assert(!md_dns_response_matches(&q, &altered));
    altered = r; md_write16(altered.data + altered.len - 4, 28); assert(!md_dns_response_matches(&q, &altered));
    altered = q; md_write16(altered.data + 2, 0x8130); assert(!md_dns_response_matches(&altered, &r));
    add_a(&r, 3, 120); records(&r, false, 3, 120);
    assert(!md_dns_question(&r, &parsed, err) && parsed.class_ == 3 && parsed.type == 1);
    puts("plan: DNS ID/question/flags/owner/class passed");
}
static void negative_soa_and_copy(void) {
    md_packet q, r, original, hit; char err[MD_ERROR_SIZE];
    query(&q, 1, 1, 0x0110); assert(!md_dns_error(&q, &r, 3));
    md_write16(r.data + 2, 0x85b3); add_soa(&r, 120); original = r;
    records(&r, true, 1, 120);
    md_cache *c = md_cache_new(8, 1000); assert(c); md_cache_put(c, &q, &r, 100);
    memset(r.data, 0xff, r.len); /* Ownership: insertion must copy the caller's response. */
    md_write16(q.data, 0xabcd);
    assert(md_cache_get(c, &q, &hit, 100) == 1);
    assert(md_read16(hit.data) == 0xabcd && md_read16(hit.data + 2) == 0x85b3);
    assert(hit.len == original.len && !memcmp(hit.data + 2, original.data + 2, original.len - 2));
    records(&hit, true, 1, 120);
    assert(md_cache_get(c, &q, &hit, 109) == 1); records(&hit, true, 1, 111);
    memset(hit.data, 0xee, hit.len); /* Retrieval must also return an independent copy. */
    assert(md_cache_get(c, &q, &hit, 110) == 1); records(&hit, true, 1, 110);
    assert(md_cache_get(c, &q, &hit, 129) == 1); records(&hit, true, 1, 91);
    /* C/Go minimal compatibility: NXDOMAIN lifetime is fixed at 30 s, no lazy retention. */
    assert(!md_cache_get(c, &q, &hit, 130)); md_cache_free(c);
    r = original; md_write16(r.data + q.len + 10, 23);
    assert(md_dns_records(&r, NULL, NULL, err));
    r = original; r.data[q.len + 13] = (uint8_t)(q.len + 12);
    assert(md_dns_records(&r, NULL, NULL, err));
    puts("plan: NXDOMAIN/SOA preservation and response copies passed");
}
static void positive_copy_and_lazy_lifecycle(void) {
    md_packet q, r, original, hit, other;
    query(&q, 1, 1, 0x0100); assert(!md_dns_error(&q, &r, 0)); add_a(&r, 1, 10); original = r;
    md_cache *c = md_cache_new(1, 30); assert(c); md_cache_put(c, &q, &r, 100);
    r.data[r.len - 1] = 99;
    assert(md_cache_get(c, &q, &hit, 100) == 1);
    assert(!memcmp(hit.data, original.data, original.len));
    hit.data[hit.len - 1] = 77;
    assert(md_cache_get(c, &q, &hit, 109) == 1); records(&hit, false, 1, 1);
    assert(md_cache_get(c, &q, &hit, 110) == 2); records(&hit, false, 1, 5);
    assert(md_cache_refresh_begin(c, &q)); assert(!md_cache_refresh_begin(c, &q));
    other = q; other.data[13] = 'n';
    assert(!md_cache_refresh_begin(c, &other)); /* Refresh markers are capacity bounded. */
    md_cache_refresh_end(c, &q); assert(md_cache_refresh_begin(c, &other));
    md_cache_refresh_end(c, &other); assert(md_cache_refresh_begin(c, &q));
    assert(md_cache_get(c, &q, &hit, 129) == 2); records(&hit, false, 1, 5);
    assert(!md_cache_get(c, &q, &hit, 130));
    md_cache_free(c); /* Pending marker destruction is exercised under ASan. */
    puts("plan: positive response copies and lazy lifecycle passed");
}
static int socket_bound(int type, uint16_t *port) {
    int fd = socket(AF_INET, type, 0); assert(fd >= 0);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(*port)};
    assert(inet_pton(AF_INET, "127.0.0.1", &a.sin_addr) == 1);
    assert(!bind(fd, (struct sockaddr *)&a, sizeof(a)));
    socklen_t len = sizeof(a); assert(!getsockname(fd, (struct sockaddr *)&a, &len)); *port = ntohs(a.sin_port);
    if (type == SOCK_STREAM) assert(!listen(fd, 4));
    return fd;
}
static unsigned open_fds(void) {
    long limit = sysconf(_SC_OPEN_MAX); assert(limit > 0);
    unsigned n = 0;
    for (int fd = 0; fd < limit && fd < 4096; ++fd) if (fcntl(fd, F_GETFD) >= 0) ++n;
    return n;
}
static double seconds(void) {
    struct timespec t; assert(!clock_gettime(CLOCK_MONOTONIC, &t));
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}
static void timeout_closes_exchange(void) {
    uint16_t port = 0; int blackhole = socket_bound(SOCK_DGRAM, &port);
    md_upstream u; char addr[64], err[MD_ERROR_SIZE]; md_packet q, r, original;
    snprintf(addr, sizeof(addr), "127.0.0.1:%u", port); assert(!md_upstream_init(&u, addr, NULL, 0, NULL, err));
    query(&q, 1, 1, 0x0100); original = q; memset(&r, 0, sizeof(r));
    unsigned before = open_fds(); double start = seconds();
    assert(md_forward(&u, 1, 1, &q, &r, err));
    double elapsed = seconds() - start;
    assert(elapsed >= 4.5 && elapsed < 7.5 && strstr(err, "timed out"));
    assert(!memcmp(q.data, original.data, original.len) && !r.len && open_fds() == before);
    close(blackhole); puts("plan: 5 second exchange timeout and socket release passed");
}
typedef struct {
    int tcp, udp; pthread_mutex_t lock; pthread_cond_t ready; bool received, eof;
} race_fixture;
static void exact_read(int fd, void *data, size_t len) {
    uint8_t *p = data;
    while (len) { ssize_t n = recv(fd, p, len, 0); assert(n > 0); p += n; len -= (size_t)n; }
}
static void *losing_tcp(void *opaque) {
    race_fixture *f = opaque; struct pollfd p = {f->tcp, POLLIN, 0}; assert(poll(&p, 1, 2000) == 1);
    int fd = accept(f->tcp, NULL, NULL); assert(fd >= 0); uint8_t prefix[2]; md_packet q;
    exact_read(fd, prefix, 2); q.len = md_read16(prefix); exact_read(fd, q.data, q.len);
    pthread_mutex_lock(&f->lock); f->received = true; pthread_cond_signal(&f->ready); pthread_mutex_unlock(&f->lock);
    p = (struct pollfd){fd, POLLIN, 0}; assert(poll(&p, 1, 2000) == 1);
    uint8_t b; f->eof = recv(fd, &b, 1, 0) == 0; close(fd); return NULL;
}
static void *winning_udp(void *opaque) {
    race_fixture *f = opaque; md_packet q, r; struct sockaddr_in peer; socklen_t len = sizeof(peer);
    struct pollfd p = {f->udp, POLLIN, 0}; assert(poll(&p, 1, 2000) == 1);
    ssize_t n = recvfrom(f->udp, q.data, sizeof(q.data), 0, (struct sockaddr *)&peer, &len); assert(n > 0); q.len = (size_t)n;
    pthread_mutex_lock(&f->lock);
    while (!f->received) pthread_cond_wait(&f->ready, &f->lock);
    pthread_mutex_unlock(&f->lock);
    assert(!md_dns_error(&q, &r, 0)); add_a(&r, 1, 60);
    assert(sendto(f->udp, r.data, r.len, 0, (struct sockaddr *)&peer, len) == (ssize_t)r.len); return NULL;
}
static void winner_closes_losing_socket(void) {
    uint16_t tcp_port = 0, udp_port = 0; race_fixture f = {0};
    f.tcp = socket_bound(SOCK_STREAM, &tcp_port); f.udp = socket_bound(SOCK_DGRAM, &udp_port);
    assert(!pthread_mutex_init(&f.lock, NULL) && !pthread_cond_init(&f.ready, NULL));
    pthread_t t[2]; assert(!pthread_create(&t[0], NULL, losing_tcp, &f)); assert(!pthread_create(&t[1], NULL, winning_udp, &f));
    md_upstream us[2]; char addr[64], err[MD_ERROR_SIZE]; md_packet q, r;
    snprintf(addr, sizeof(addr), "tcp://127.0.0.1:%u", tcp_port); assert(!md_upstream_init(&us[0], addr, NULL, 0, NULL, err));
    snprintf(addr, sizeof(addr), "127.0.0.1:%u", udp_port); assert(!md_upstream_init(&us[1], addr, NULL, 0, NULL, err));
    query(&q, 1, 1, 0x0100); assert(!md_forward(us, 2, 2, &q, &r, err)); records(&r, false, 1, 60);
    assert(!pthread_join(t[0], NULL) && !pthread_join(t[1], NULL) && f.eof);
    close(f.tcp); close(f.udp); pthread_cond_destroy(&f.ready); pthread_mutex_destroy(&f.lock);
    puts("plan: winning exchange closes the pending TCP exchange passed");
}
int main(void) {
    flags_question_owner_class(); negative_soa_and_copy(); positive_copy_and_lazy_lifecycle();
    timeout_closes_exchange(); winner_closes_losing_socket();
    puts("plan: 5 regression groups passed"); return 0;
}
