/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#define MAX_CONNECTIONS 128
#define MAX_JOBS 64
#define MAX_IDLE_JOBS 8
#define UDP_RECEIVE_BUFFER_BYTES (256 * 1024)
typedef struct job {
    struct job *next;
    int socket, slot;
    uint64_t generation;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    size_t entry;
    md_packet query, response;
} job;
typedef struct {
    md_engine *engine;
    pthread_mutex_t lock;
    pthread_cond_t ready;
    job *head, *tail, *done_head, *done_tail;
    /* Only the event-loop thread owns idle jobs. Workers never recycle them. */
    job *idle;
    size_t idle_count;
    size_t outstanding;
    bool stopping;
    int wake[2];
} pool;
typedef struct {
    int fd;
    uint64_t generation, last;
    unsigned idle;
    size_t entry, header_len, body_len, expected, sent;
    uint8_t header[2], *body;
    bool busy;
    job *output;
} connection;
static volatile sig_atomic_t stop_requested;
static void stop_signal(int sig) { (void)sig; stop_requested = 1; }
static int nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
           fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ? -1 : 0;
}
static job *acquire_job(pool *p) {
    job *j = p->idle;
    if (j) { p->idle = j->next; p->idle_count--; }
    else j = malloc(sizeof(*j));
    if (j) {
        /* Packet bytes are initialized by recv/engine and read only to len.
         * Avoid clearing both 64 KiB packet capacities for every request. */
        memset(j, 0, offsetof(job, query));
        j->query.len = j->response.len = 0;
    }
    return j;
}
static void recycle_job(pool *p, job *j) {
    if (p->idle_count < MAX_IDLE_JOBS) {
        j->next = p->idle; p->idle = j; p->idle_count++;
    } else free(j);
}
static void release_job(pool *p, job *j) {
    pthread_mutex_lock(&p->lock);
    p->outstanding--;
    pthread_mutex_unlock(&p->lock);
    recycle_job(p, j);
}
static bool enqueue(pool *p, job *j) {
    pthread_mutex_lock(&p->lock);
    if (p->stopping || p->outstanding >= MAX_JOBS) {
        pthread_mutex_unlock(&p->lock); return false;
    }
    j->next = NULL;
    if (p->tail) p->tail->next = j; else p->head = j;
    p->tail = j; p->outstanding++;
    pthread_cond_signal(&p->ready);
    pthread_mutex_unlock(&p->lock);
    return true;
}
static bool retain_output(pool *p) {
    pthread_mutex_lock(&p->lock);
    bool ok = !p->stopping && p->outstanding < MAX_JOBS;
    if (ok) p->outstanding++;
    pthread_mutex_unlock(&p->lock);
    return ok;
}
static void *work(void *arg) {
    pool *p = arg;
    md_forward_worker_enable();
    for (;;) {
        pthread_mutex_lock(&p->lock);
        while (!p->head && !p->stopping) pthread_cond_wait(&p->ready, &p->lock);
        if (p->stopping) { pthread_mutex_unlock(&p->lock); break; }
        job *j = p->head;
        p->head = j->next;
        if (!p->head) p->tail = NULL;
        pthread_mutex_unlock(&p->lock);
        char err[MD_ERROR_SIZE] = {0};
        if (md_engine_query(p->engine, j->entry, &j->query, &j->response, err)) {
            fprintf(stderr, "query failed: %s\n", err);
            if (md_dns_error(&j->query, &j->response, 2)) j->response.len = 0;
        }
        if (j->slot < 0) {
            md_dns_limit_udp(&j->query, &j->response);
            /* The listener stays open until all workers join. Datagram sends
             * are atomic; reply here rather than waiting for a second wakeup
             * and scheduling the event loop. It still owns job recycling. */
            if (j->response.len) {
                ssize_t ignored = sendto(j->socket, j->response.data, j->response.len, 0,
                                        (struct sockaddr *)&j->peer, j->peer_len);
                (void)ignored;
            }
        }
        pthread_mutex_lock(&p->lock);
        j->next = NULL;
        if (p->done_tail) p->done_tail->next = j; else p->done_head = j;
        p->done_tail = j;
        pthread_mutex_unlock(&p->lock);
        uint8_t byte = 1;
        ssize_t ignored = write(p->wake[1], &byte, 1); (void)ignored;
    }
    md_forward_worker_cleanup();
    return NULL;
}
static void close_connection(pool *p, connection *c) {
    if (c->fd >= 0) close(c->fd);
    free(c->body);
    if (c->output) release_job(p, c->output);
    uint64_t generation = c->generation + 1;
    memset(c, 0, sizeof(*c));
    c->fd = -1; c->generation = generation;
}
static void completions(pool *p, connection *cs) {
    uint8_t bytes[128];
    while (read(p->wake[0], bytes, sizeof(bytes)) > 0) {}
    pthread_mutex_lock(&p->lock);
    job *j = p->done_head;
    p->done_head = p->done_tail = NULL;
    pthread_mutex_unlock(&p->lock);
    while (j) {
        job *next = j->next;
        if (j->slot < 0) {
            release_job(p, j);
        } else {
            connection *c = &cs[j->slot];
            if (c->fd < 0 || c->generation != j->generation || !j->response.len) {
                if (c->fd >= 0 && c->generation == j->generation) close_connection(p, c);
                release_job(p, j);
            } else {
                c->output = j; c->sent = 0;
                c->last = md_now();
                md_write16(c->header, (uint16_t)j->response.len);
            }
        }
        j = next;
    }
}
static void tcp_read(pool *p, connection *c, int slot) {
    while (!c->busy) {
        uint8_t *dest = c->header_len < 2 ? c->header + c->header_len : c->body + c->body_len;
        size_t need = c->header_len < 2 ? 2 - c->header_len : c->expected - c->body_len;
        ssize_t n = recv(c->fd, dest, need, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) { close_connection(p, c); return; }
        c->last = md_now();
        if (c->header_len < 2) {
            c->header_len += (size_t)n;
            if (c->header_len == 2) {
                c->expected = md_read16(c->header);
                if (c->expected < 12 || !(c->body = malloc(c->expected))) {
                    close_connection(p, c); return;
                }
            }
        } else {
            c->body_len += (size_t)n;
            if (c->body_len == c->expected) {
                job *j = acquire_job(p);
                if (!j) { close_connection(p, c); return; }
                memcpy(j->query.data, c->body, c->expected);
                j->query.len = c->expected;
                j->entry = c->entry; j->slot = slot; j->generation = c->generation;
                md_question q; char err[MD_ERROR_SIZE];
                if (md_dns_question(&j->query, &q, err) || (q.flags & 0x8000)) {
                    recycle_job(p, j); close_connection(p, c); return;
                }
                if (md_engine_cached_query(p->engine, j->entry, &j->query, &j->response)) {
                    if (!retain_output(p)) { recycle_job(p, j); close_connection(p, c); return; }
                    c->output = j; c->sent = 0;
                    md_write16(c->header, (uint16_t)j->response.len);
                } else if (!enqueue(p, j)) {
                    recycle_job(p, j); close_connection(p, c); return;
                }
                free(c->body); c->body = NULL; c->busy = true;
            }
        }
    }
}
static void tcp_write(pool *p, connection *c) {
    job *j = c->output;
    while (c->sent < j->response.len + 2) {
        struct iovec iov[2]; size_t count = 0, offset = 0;
        if (c->sent < 2) {
            iov[count++] = (struct iovec){ .iov_base = c->header + c->sent,
                                          .iov_len = 2 - c->sent };
        } else offset = c->sent - 2;
        iov[count++] = (struct iovec){ .iov_base = j->response.data + offset,
                                      .iov_len = j->response.len - offset };
        struct msghdr msg = { .msg_iov = iov, .msg_iovlen = count };
        ssize_t n = sendmsg(c->fd, &msg, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) { close_connection(p, c); return; }
        c->sent += (size_t)n; c->last = md_now();
    }
    release_job(p, j); c->output = NULL; c->busy = false;
    c->header_len = c->body_len = c->expected = c->sent = 0;
}
static void udp_read(pool *p, int fd, size_t entry) {
    /* Bound each drain so a hot UDP listener cannot starve TCP/completions. */
    for (unsigned i = 0; i < 16; i++) {
        job *j = acquire_job(p);
        if (!j) return;
        j->peer_len = sizeof(j->peer);
        ssize_t n = recvfrom(fd, j->query.data, MD_MAX_PACKET, 0,
                             (struct sockaddr *)&j->peer, &j->peer_len);
        if (n < 0) { recycle_job(p, j); return; }
        j->query.len = (size_t)n; j->socket = fd; j->entry = entry; j->slot = -1;
        md_question q; char err[MD_ERROR_SIZE];
        if (md_dns_question(&j->query, &q, err) || (q.flags & 0x8000)) { recycle_job(p, j); continue; }
        if (md_engine_cached_query(p->engine, entry, &j->query, &j->response)) {
            md_dns_limit_udp(&j->query, &j->response);
            ssize_t ignored = sendto(fd, j->response.data, j->response.len, 0,
                                    (struct sockaddr *)&j->peer, j->peer_len);
            (void)ignored;
            recycle_job(p, j); continue;
        }
        if (!enqueue(p, j)) {
            if (!md_dns_error(&j->query, &j->response, 2)) {
                ssize_t ignored = sendto(fd, j->response.data, j->response.len, 0,
                                        (struct sockaddr *)&j->peer, j->peer_len);
                (void)ignored;
            }
            recycle_job(p, j);
        }
    }
}
int md_server_run(md_engine *e, unsigned workers, char *err) {
    size_t count = md_engine_listener_count(e);
    if (!count || count > 64 || workers < 1 || workers > 64) {
        snprintf(err, MD_ERROR_SIZE, "requires 1..64 listeners and 1..64 workers"); return -1;
    }
    int result = -1, *fds = calloc(count, sizeof(*fds));
    connection *cs = calloc(MAX_CONNECTIONS, sizeof(*cs));
    pthread_t *threads = calloc(workers, sizeof(*threads));
    pool p = {.engine = e, .wake = {-1, -1}};
    int udp_rcvbuf[64] = {0};
    unsigned started = 0;
    if (!fds || !cs || !threads) {
        snprintf(err, MD_ERROR_SIZE, "out of memory"); free(fds); free(cs); free(threads); return -1;
    }
    for (size_t i = 0; i < count; i++) fds[i] = -1;
    for (size_t i = 0; i < MAX_CONNECTIONS; i++) cs[i].fd = -1;
    pthread_mutex_init(&p.lock, NULL); pthread_cond_init(&p.ready, NULL);
    if (pipe(p.wake) || nonblock(p.wake[0]) || nonblock(p.wake[1])) {
        snprintf(err, MD_ERROR_SIZE, "completion pipe: %s", strerror(errno)); goto cleanup;
    }
    for (size_t i = 0; i < count; i++) {
        const md_listener *l = md_engine_listener(e, i);
        struct sockaddr_storage a; socklen_t alen;
        if (md_parse_address(l->listen, 53, &a, &alen, err)) goto cleanup;
        int fd = socket(a.ss_family, l->tcp ? SOCK_STREAM : SOCK_DGRAM, 0);
        if (fd < 0) { snprintf(err, MD_ERROR_SIZE, "socket: %s", strerror(errno)); goto cleanup; }
        fds[i] = fd;
        if (!l->tcp) {
            int requested = UDP_RECEIVE_BUFFER_BYTES;
            socklen_t size = sizeof(udp_rcvbuf[i]);
            if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &requested, sizeof(requested)) ||
                getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &udp_rcvbuf[i], &size)) {
                snprintf(err, MD_ERROR_SIZE, "udp receive buffer %s: %s", l->listen, strerror(errno));
                goto cleanup;
            }
            if (size != sizeof(udp_rcvbuf[i]) || udp_rcvbuf[i] <= 0) {
                snprintf(err, MD_ERROR_SIZE, "udp receive buffer %s: invalid reported value", l->listen);
                goto cleanup;
            }
        }
        int one = 1;
        if (l->tcp) setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (a.ss_family == AF_INET6) setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
        if (nonblock(fd) || bind(fd, (struct sockaddr *)&a, alen) || (l->tcp && listen(fd, 128))) {
            snprintf(err, MD_ERROR_SIZE, "listen %s: %s", l->listen, strerror(errno)); goto cleanup;
        }
    }
    for (; started < workers; started++) {
        int rc = pthread_create(&threads[started], NULL, work, &p);
        if (rc) { snprintf(err, MD_ERROR_SIZE, "worker: %s", strerror(rc)); goto cleanup; }
    }
    struct sigaction handler, old_int, old_term;
    memset(&handler, 0, sizeof(handler)); handler.sa_handler = stop_signal;
    sigemptyset(&handler.sa_mask); stop_requested = 0;
    sigaction(SIGINT, &handler, &old_int); sigaction(SIGTERM, &handler, &old_term);
    for (size_t i = 0; i < count; i++) {
        const md_listener *l = md_engine_listener(e, i);
        fprintf(stderr, "%s listening on %s\n", l->tcp ? "tcp" : "udp", l->listen);
        if (!l->tcp) {
#ifdef __linux__
            /* Linux reports twice the requested buffer, including bookkeeping. */
            const char *clamped = udp_rcvbuf[i] < UDP_RECEIVE_BUFFER_BYTES * 2 ? "yes" : "no";
#else
            const char *clamped = "unknown";
#endif
            fprintf(stderr, "udp receive buffer on %s: requested_bytes=%d reported_bytes=%d linux_clamped=%s\n",
                    l->listen, UDP_RECEIVE_BUFFER_BYTES, udp_rcvbuf[i], clamped);
        }
    }
    while (!stop_requested) {
        struct pollfd pf[65 + MAX_CONNECTIONS];
        int slots[65 + MAX_CONNECTIONS];
        uint64_t generations[65 + MAX_CONNECTIONS];
        size_t n = 0;
        pf[n] = (struct pollfd){p.wake[0], POLLIN, 0}; slots[n++] = -2;
        for (size_t i = 0; i < count; i++) { pf[n] = (struct pollfd){fds[i], POLLIN, 0}; slots[n++] = -1; }
        uint64_t now = md_now();
        for (int i = 0; i < MAX_CONNECTIONS; i++) {
            connection *c = &cs[i];
            if (c->fd < 0) continue;
            if (c->busy && !c->output) continue;
            if (now - c->last >= c->idle) { close_connection(&p, c); continue; }
            pf[n] = (struct pollfd){c->fd, c->output ? POLLOUT : POLLIN, 0};
            generations[n] = c->generation; slots[n++] = i;
        }
        int rc = poll(pf, (nfds_t)n, 250);
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) { snprintf(err, MD_ERROR_SIZE, "poll: %s", strerror(errno)); break; }
        if (pf[0].revents) completions(&p, cs);
        for (size_t i = 1; i <= count; i++) {
            if (!pf[i].revents) continue;
            const md_listener *l = md_engine_listener(e, i - 1);
            if (!l->tcp) { udp_read(&p, fds[i - 1], l->entry); continue; }
            for (unsigned k = 0; k < 16; k++) {
                int fd = accept(fds[i - 1], NULL, NULL);
                if (fd < 0) break;
                int slot = 0;
                while (slot < MAX_CONNECTIONS && cs[slot].fd >= 0) slot++;
                if (slot == MAX_CONNECTIONS || nonblock(fd)) { close(fd); continue; }
                cs[slot].fd = fd; cs[slot].last = md_now();
                cs[slot].entry = l->entry; cs[slot].idle = l->idle_timeout ? l->idle_timeout : 10;
            }
        }
        for (size_t i = count + 1; i < n; i++) {
            connection *c = &cs[slots[i]];
            /* Completions/listener processing may have reused the slot. */
            if (!pf[i].revents || c->fd != pf[i].fd || c->generation != generations[i]) continue;
            if (pf[i].revents & (POLLERR | POLLNVAL)) { close_connection(&p, c); continue; }
            if ((pf[i].revents & POLLOUT) && c->output) tcp_write(&p, c);
            else if ((pf[i].revents & POLLIN) && !c->busy) tcp_read(&p, c, slots[i]);
            else if ((pf[i].revents & POLLHUP) && !c->busy) close_connection(&p, c);
        }
    }
    if (stop_requested) result = 0;
    sigaction(SIGINT, &old_int, NULL); sigaction(SIGTERM, &old_term, NULL);
cleanup:
    pthread_mutex_lock(&p.lock); p.stopping = true;
    pthread_cond_broadcast(&p.ready); pthread_mutex_unlock(&p.lock);
    for (unsigned i = 0; i < started; i++) pthread_join(threads[i], NULL);
    for (int i = 0; i < MAX_CONNECTIONS; i++) close_connection(&p, &cs[i]);
    job *j = p.head;
    while (j) { job *next = j->next; free(j); j = next; }
    j = p.done_head;
    while (j) { job *next = j->next; free(j); j = next; }
    j = p.idle;
    while (j) { job *next = j->next; free(j); j = next; }
    for (size_t i = 0; i < count; i++) if (fds[i] >= 0) close(fds[i]);
    if (p.wake[0] >= 0) close(p.wake[0]);
    if (p.wake[1] >= 0) close(p.wake[1]);
    pthread_cond_destroy(&p.ready); pthread_mutex_destroy(&p.lock);
    free(threads); free(cs); free(fds);
    return result;
}
