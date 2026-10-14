/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 一个 poll 事件循环管理监听器和 TCP 帧，worker 执行可能阻塞的查询图。
 * job 经待执行/完成队列转移所有权，最终统一由事件循环回收。
 * 待执行队列按 lane（缓存命中/CN 上游/国外上游）拆分，每条 lane 有自己的
 * worker 和 MAX_JOBS 配额：一个上游组全部超时也不会拖住另一组或缓存命中。
 * 同一 lane 内，排队超过 queue_timeout_ms 的任务直接回 SERVFAIL，不再访问上游；
 * 与正在执行的上游查询除 ID 外完全相同的查询挂在它后面共享结果，不另占 worker。
 * TCP 待写回复不计入 lane 配额（每连接至多一个，由连接上限和写期限约束）。 */
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
#ifdef __linux__
#include <limits.h>
#include <sys/resource.h>
#endif

#define MAX_JOBS 64
#define MAX_IDLE_JOBS 8
#define UDP_RECEIVE_BUFFER_BYTES (256 * 1024)
/* slot < 0 表示 UDP；TCP 同时保存 slot 和 generation，防连接关闭后槽位复用。 */
/* lane 为 MD_LANE_REPLY 表示不再占用任何 lane 配额（事件循环回复或已交给 TCP 连接）。
 * queued 为入队时刻（毫秒）；followers 是等待共享本 job 上游结果的相同查询。 */
typedef struct job {
    struct job *next, *running_next, *followers;
    int socket, slot;
    unsigned lane;
    uint64_t generation, queued;
    struct sockaddr_storage peer;
    socklen_t peer_len;
    size_t entry;
    md_dns_query qv; /* 收包时唯一一次请求解析；acquire_job 清零（valid=false） */
    md_trace tr;     /* 诊断计时（DIVERSION_TRACE），acquire_job 清零 */
    md_packet query, response;
} job;
/* 每条 lane 的待执行队列、正在访问上游的 job 链表与 outstanding；后者包含排队、
 * 执行、跟随者以及尚未交给连接的完成项。TCP 待写回复在完成时即释放配额，
 * 慢读 TCP 客户端因而不能占满某条 lane（尤其是 UDP CN 缓存命中所在的缓存 lane）。 */
typedef struct {
    pthread_cond_t ready;
    job *head, *tail, *running;
    size_t outstanding;
} lane;
/* lock 保护各 lane 队列、完成队列和 outstanding。wake 管道只是通知，
 * 完成队列才是结果来源。 */
typedef struct {
    md_engine *engine;
    pthread_mutex_t lock;
    lane lanes[MD_LANE_COUNT];
    job *done_head, *done_tail;
    /* Only the event-loop thread owns idle jobs. Workers never recycle them. */
    job *idle;
    size_t idle_count;
    uint64_t queue_timeout;
    bool stopping;
    int wake[2];
} pool;
typedef struct { pool *p; unsigned lane; } worker;
/* TCP 每条连接至多有一个处理中的查询，读完消息体后 busy 置位，
 * 完整回复写出后才继续读取下一帧；header/sent 保存非阻塞 I/O 的进度。
 * 时间均为单调毫秒：last 为最近一次读写进展，frame_start 为当前帧首字节到达，
 * write_start 为当前回复开始写出；source 是对端地址（IPv4 映射为 ::ffff:a.b.c.d）。 */
typedef struct {
    int fd;
    uint64_t generation, last, idle, frame_start, write_start;
    size_t entry, header_len, body_len, expected, sent;
    uint8_t header[2], *body, source[16];
    bool busy;
    job *output;
} connection;
/* 事件循环使用的 TCP 期限与连接上限（毫秒/个）。 */
typedef struct {
    uint64_t read_timeout, write_timeout;
    unsigned max_connections, max_per_ip;
} tcp_limits;
/* 信号处理器只置位，释放队列/socket 和等待线程均在正常执行路径完成。 */
static volatile sig_atomic_t stop_requested;
static void stop_signal(int sig) { (void)sig; stop_requested = 1; }
static int nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    return flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 ||
           fcntl(fd, F_SETFD, FD_CLOEXEC) < 0 ? -1 : 0;
}
/* Linux expands a shared fd table with synchronize_rcu(). Even an empty
 * nonblocking accept can trigger that before returning EAGAIN, stalling the
 * event loop at the first capacity boundary (32 descriptors on MIPS).
 * Grow once while single-threaded. F_DUPFD_CLOEXEC reserves a table slot, not
 * a connection; closing the duplicate immediately retains the table capacity.
 * Budget for configured clients/listeners, worker socket pools and concurrent
 * refreshes. This is headroom, not a new fd limit or a promise for arbitrary
 * inherited descriptors. Respect RLIMIT_NOFILE and retain old behaviour if
 * this optional optimization cannot be applied. */
static void preallocate_fdtable(int fd, size_t listeners, unsigned clients, unsigned workers) {
#ifdef __linux__
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE, &limit)) {
        fprintf(stderr, "fd table preallocation: getrlimit: %s\n", strerror(errno));
        return;
    }
    if (!limit.rlim_cur) return;
    /* Worker pools: 8 TCP + 8 UDP spare + 16 retired + active/netlink margin.
     * 320 also covers up to 64 refresh jobs (up to 3 upstream sockets each)
     * and baseline/temporary descriptors. No sockets are kept open here. */
    uint64_t wanted = (uint64_t)clients + listeners + 40ull * workers + 320;
    if (limit.rlim_cur != RLIM_INFINITY && wanted >= limit.rlim_cur)
        wanted = limit.rlim_cur - 1;
    if (wanted > INT_MAX) wanted = INT_MAX;
    int reserved = fcntl(fd, F_DUPFD_CLOEXEC, (int)wanted);
    if (reserved < 0) {
        fprintf(stderr, "fd table preallocation: fcntl: %s (continuing)\n", strerror(errno));
        return;
    }
    close(reserved);
    fprintf(stderr, "fd table preallocated through descriptor %d\n", reserved);
#else
    (void)fd; (void)listeners; (void)clients; (void)workers;
#endif
}
/* 只缓存少量空闲大报文对象，平衡每次 malloc 的成本和空闲内存占用。 */
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
/* 只能由事件循环调用：释放仍持有的 lane 配额。 */
static void release_quota(pool *p, job *j) {
    if (j->lane >= MD_LANE_COUNT) return;
    pthread_mutex_lock(&p->lock);
    p->lanes[j->lane].outstanding--;
    pthread_mutex_unlock(&p->lock);
    j->lane = MD_LANE_REPLY;
}
/* 只能由事件循环调用：先释放 outstanding 配额，再放回线程私有空闲链表。 */
static void release_job(pool *p, job *j) {
    release_quota(p, j);
    recycle_job(p, j);
}
/* 除 DNS ID 外字节完全相同的查询（问题大小写、标志、EDNS 全同）得到的上游回答
 * 对双方都有效，只需改写 ID；不同写法的查询不合并，避免返回不匹配的报文。 */
static bool same_query(const job *a, const job *b) {
    return a->entry == b->entry && a->query.len == b->query.len &&
           !memcmp(a->query.data + 2, b->query.data + 2, a->query.len - 2);
}
/* 持锁调用：在上游 lane 中查找正在执行的相同查询，找到则把 j 挂为其跟随者。 */
static bool follow_running(lane *l, job *j) {
    if (j->lane == MD_LANE_CACHED) return false;
    for (job *r = l->running; r; r = r->running_next) {
        if (!same_query(r, j)) continue;
        j->next = r->followers; r->followers = j;
        return true;
    }
    return false;
}
/* 成功入队（或挂到相同的在途查询）后 job 交给 worker；失败时调用方仍负责发送错误或释放 job。
 * 跟随者同样计入 outstanding，因此合并不会放宽每条 lane 的内存上限。 */
static bool enqueue(pool *p, job *j) {
    lane *l = &p->lanes[j->lane];
    j->queued = md_now_ms();
    if (md_trace_enabled) j->tr.t[MD_T_ENQUEUE] = md_now_ns();
    pthread_mutex_lock(&p->lock);
    if (p->stopping || l->outstanding >= MAX_JOBS) {
        pthread_mutex_unlock(&p->lock); return false;
    }
    l->outstanding++;
    if (!follow_running(l, j)) {
        j->next = NULL;
        if (l->tail) l->tail->next = j; else l->head = j;
        l->tail = j;
        pthread_cond_signal(&l->ready);
    }
    pthread_mutex_unlock(&p->lock);
    return true;
}
/* The listener stays open until all workers join. Datagram sends are atomic;
 * reply here rather than waiting for a second wakeup and scheduling the event
 * loop. It still owns job recycling. */
static void trace_done(job *j) {
    if (!md_trace_enabled) return;
    j->tr.t[MD_T_REPLY] = md_now_ns(); j->tr.lane = j->lane;
    md_trace_emit(&j->tr, &j->query);
}
static void reply_udp(job *j) {
    if (j->slot >= 0) return;
    md_dns_limit_udp_q(&j->query, &j->qv, &j->response);
    if (j->response.len) {
        ssize_t ignored = sendto(j->socket, j->response.data, j->response.len, 0,
                                (struct sockaddr *)&j->peer, j->peer_len);
        (void)ignored;
    }
    trace_done(j);
}
/* 每个 worker 建立自己的上游连接池，退出时释放；执行期间独占取出的 job。
 * UDP 可直接发回完整数据报，TCP 写操作必须交还事件循环保持帧进度一致。
 * 排队已超过 queue_timeout 的 job 客户端多半已放弃：直接回 SERVFAIL（与 lane 满时
 * 相同），不访问上游，worker 立即处理下一个，避免一批注定超时的任务串行拖住整条 lane。 */
static void *work(void *arg) {
    pool *p = ((worker *)arg)->p;
    lane *l = &p->lanes[((worker *)arg)->lane];
    md_forward_worker_enable();
    for (;;) {
        pthread_mutex_lock(&p->lock);
        while (!l->head && !p->stopping) pthread_cond_wait(&l->ready, &p->lock);
        if (p->stopping) { pthread_mutex_unlock(&p->lock); break; }
        job *j = l->head;
        l->head = j->next;
        if (!l->head) l->tail = NULL;
        uint64_t waited = md_now_ms() - j->queued;
        bool stale = p->queue_timeout && waited >= p->queue_timeout, running = false;
        if (!stale && follow_running(l, j)) { pthread_mutex_unlock(&p->lock); continue; }
        if (!stale && j->lane != MD_LANE_CACHED) {
            j->running_next = l->running; l->running = j; running = true;
        }
        pthread_mutex_unlock(&p->lock);
        char err[MD_ERROR_SIZE] = {0};
        if (md_trace_enabled) {
            j->tr.t[MD_T_PICKUP] = md_now_ns();
            if (stale) j->tr.flags |= MD_TF_STALE_DROP;
            md_trace_cur = &j->tr;
        }
        if (stale) {
            fprintf(stderr, "query dropped: queued %llu ms (queue_timeout_ms=%llu)\n",
                    (unsigned long long)waited, (unsigned long long)p->queue_timeout);
            if (md_dns_error_q(&j->query, &j->qv, &j->response, 2)) j->response.len = 0;
        } else if (md_engine_query_q(p->engine, j->entry, &j->query, &j->qv, &j->response, err)) {
            fprintf(stderr, "query failed: %s\n", err);
            md_trace_flag(MD_TF_ERROR);
            if (md_dns_error_q(&j->query, &j->qv, &j->response, 2)) j->response.len = 0;
        }
        md_trace_cur = NULL;
        job *followers = NULL;
        if (running) {
            pthread_mutex_lock(&p->lock);
            for (job **link = &l->running; *link; link = &(*link)->running_next)
                if (*link == j) { *link = j->running_next; break; }
            followers = j->followers; j->followers = NULL;
            pthread_mutex_unlock(&p->lock);
        }
        /* 跟随者的查询与 j 除 ID 外相同，复制完整（未截断的）回复后只改写 ID。 */
        job *last = j;
        for (job *f = followers; f; f = f->next) {
            if (md_trace_enabled) {
                memcpy(f->tr.t + MD_T_PICKUP, j->tr.t + MD_T_PICKUP, (MD_T_REPLY - MD_T_PICKUP) * sizeof(f->tr.t[0]));
                f->tr.flags |= MD_TF_FOLLOWER | (j->tr.flags & ~(uint32_t)MD_TF_LOOP_REPLY);
            }
            f->response.len = j->response.len;
            if (j->response.len) {
                memcpy(f->response.data, j->response.data, j->response.len);
                memcpy(f->response.data, f->query.data, 2);
            }
            reply_udp(f);
            last = f;
        }
        reply_udp(j);
        pthread_mutex_lock(&p->lock);
        j->next = followers; last->next = NULL;
        if (p->done_tail) p->done_tail->next = j; else p->done_head = j;
        p->done_tail = last;
        pthread_mutex_unlock(&p->lock);
        uint8_t byte = 1;
        ssize_t ignored = write(p->wake[1], &byte, 1); (void)ignored;
        md_forward_worker_idle();
    }
    md_forward_worker_cleanup();
    return NULL;
}
/* generation 在每次关闭时递增；已经提交给 worker 的 job 仍会完成，
 * 完成项据此丢弃旧连接的结果，不会发给占用同一槽位的新客户端。 */
static void close_connection(pool *p, connection *c) {
    if (c->fd >= 0) close(c->fd);
    free(c->body);
    if (c->output) release_job(p, c->output);
    uint64_t generation = c->generation + 1;
    memset(c, 0, sizeof(*c));
    c->fd = -1; c->generation = generation;
}
/* 清空通知后一次取走当前完成链表；管道写满也不会丢结果，因为队列受锁保护。
 * 交给 TCP 连接的回复立即释放 lane 配额：之后只受连接上限和写期限约束。 */
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
                release_quota(p, j);
                c->output = j; c->sent = 0;
                c->last = c->write_start = md_now_ms();
                md_write16(c->header, (uint16_t)j->response.len);
            }
        }
        j = next;
    }
}
/* 严格按长度前缀收包，拒绝短于 DNS 头的帧；完整结构校验通过后才能执行。
 * 帧首字节到达时记录 frame_start，事件循环据此执行整帧读期限。 */
static void tcp_read(pool *p, connection *c, int slot) {
    while (!c->busy) {
        uint8_t *dest = c->header_len < 2 ? c->header + c->header_len : c->body + c->body_len;
        size_t need = c->header_len < 2 ? 2 - c->header_len : c->expected - c->body_len;
        ssize_t n = recv(c->fd, dest, need, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (n <= 0) { close_connection(p, c); return; }
        c->last = md_now_ms();
        if (!c->header_len) c->frame_start = c->last;
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
                if (md_trace_enabled) j->tr.t[MD_T_RECV] = md_now_ns();
                j->entry = c->entry; j->slot = slot; j->generation = c->generation;
                char err[MD_ERROR_SIZE];
                if (md_dns_query_parse(&j->query, &j->qv, err) || (j->qv.q.flags & 0x8000)) {
                    recycle_job(p, j); close_connection(p, c); return;
                }
                /* 快路径只处理引擎确认可直接返回的鲜缓存，其他查询按 lane 执行完整查询图。 */
                if (md_trace_enabled) md_trace_cur = &j->tr;
                j->lane = md_engine_dispatch_q(p->engine, j->entry, &j->query, &j->qv, &j->response);
                md_trace_cur = NULL;
                if (md_trace_enabled) j->tr.t[MD_T_DISPATCHED] = md_now_ns();
                if (j->lane == MD_LANE_REPLY) {
                    j->tr.flags |= MD_TF_LOOP_REPLY;
                    /* 不占任何 lane 配额：每连接至多一个待写回复，受连接上限与写期限约束。 */
                    c->output = j; c->sent = 0; c->write_start = md_now_ms();
                    md_write16(c->header, (uint16_t)j->response.len);
                } else if (!enqueue(p, j)) {
                    recycle_job(p, j); close_connection(p, c); return;
                }
                free(c->body); c->body = NULL; c->busy = true;
            }
        }
    }
}
/* sendmsg 拼接长度和消息体，sent 跨事件保存进度，避免为 TCP 前缀复制整个回复。 */
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
        c->sent += (size_t)n; c->last = md_now_ms();
    }
    if (md_trace_enabled) { j->tr.flags |= MD_TF_TCP; trace_done(j); }
    release_job(p, j); c->output = NULL; c->busy = false;
    c->header_len = c->body_len = c->expected = c->sent = 0;
}
/* 以 16 字节地址区分来源；IPv4 按 ::ffff:a.b.c.d 映射，与 IPv6 不会混淆。 */
static void source_key(const struct sockaddr_storage *a, uint8_t key[16]) {
    memset(key, 0, 16);
    if (a->ss_family == AF_INET) {
        key[10] = key[11] = 0xff;
        memcpy(key + 12, &((const struct sockaddr_in *)a)->sin_addr, 4);
    } else if (a->ss_family == AF_INET6) {
        memcpy(key, &((const struct sockaddr_in6 *)a)->sin6_addr, 16);
    }
}
/* 淘汰优先级：没有处理中查询的连接最先（只占槽位，不丢已收完整查询），其次是回复
 * 写不出去的连接（客户端不读）；正在等待 worker 的连接不淘汰。同级取最久无进展者。 */
static bool evict_before(const connection *a, const connection *b) {
    if (!b) return true;
    if (!a->busy != !b->busy) return !a->busy;
    return a->last < b->last;
}
/* 为新连接选择槽位。同一来源达到每 IP 上限时淘汰该来源中最该淘汰的连接；
 * 总数达到上限时在全部连接中淘汰。没有可淘汰者时返回 -1 拒绝新连接。 */
static int admit(pool *p, connection *cs, const tcp_limits *t, const uint8_t key[16]) {
    int free_slot = -1, oldest = -1, oldest_same = -1;
    unsigned same = 0;
    for (int i = 0; i < (int)t->max_connections; i++) {
        connection *c = &cs[i];
        if (c->fd < 0) { if (free_slot < 0) free_slot = i; continue; }
        bool mine = !memcmp(c->source, key, 16);
        same += mine;
        if (c->busy && !c->output) continue;
        if (evict_before(c, oldest < 0 ? NULL : &cs[oldest])) oldest = i;
        if (mine && evict_before(c, oldest_same < 0 ? NULL : &cs[oldest_same])) oldest_same = i;
    }
    int victim;
    if (same >= t->max_per_ip) victim = oldest_same;
    else if (free_slot < 0) victim = oldest;
    else return free_slot;
    if (victim >= 0) close_connection(p, &cs[victim]);
    return victim;
}
/* 期限检查：busy 且尚无回复的连接由 worker 持有，不受期限影响（与原空闲超时一致）。 */
static bool expired(const connection *c, const tcp_limits *t, uint64_t now) {
    if (now - c->last >= c->idle) return true;
    if (c->output) return now - c->write_start >= t->write_timeout;
    return c->header_len && now - c->frame_start >= t->read_timeout;
}
/* UDP 鲜缓存可在事件循环当场回复；队列满时返回 SERVFAIL，并回收未入队对象。 */
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
        if (md_trace_enabled) j->tr.t[MD_T_RECV] = md_now_ns();
        char err[MD_ERROR_SIZE];
        if (md_dns_query_parse(&j->query, &j->qv, err) || (j->qv.q.flags & 0x8000)) { recycle_job(p, j); continue; }
        if (md_trace_enabled) md_trace_cur = &j->tr;
        j->lane = md_engine_dispatch_q(p->engine, entry, &j->query, &j->qv, &j->response);
        md_trace_cur = NULL;
        if (md_trace_enabled) j->tr.t[MD_T_DISPATCHED] = md_now_ns();
        if (j->lane == MD_LANE_REPLY) {
            j->tr.flags |= MD_TF_LOOP_REPLY;
            reply_udp(j);
            recycle_job(p, j); continue;
        }
        if (!enqueue(p, j)) {
            if (!md_dns_error_q(&j->query, &j->qv, &j->response, 2)) {
                ssize_t ignored = sendto(fd, j->response.data, j->response.len, 0,
                                        (struct sockaddr *)&j->peer, j->peer_len);
                (void)ignored;
            }
            recycle_job(p, j);
        }
    }
}
/* 启动时记录实际 UDP 接收缓冲值；操作系统可能夹紧请求值，日志保留这个差异。 */
int md_server_run(md_engine *e, unsigned workers, char *err) {
    size_t count = md_engine_listener_count(e);
    if (!count || count > 64 || workers < 1 || workers > 64) {
        snprintf(err, MD_ERROR_SIZE, "requires 1..64 listeners and 1..64 workers"); return -1;
    }
    md_trace_init();
    static const md_server_limits fallback = {2000, 5, 10, 128, 32};
    const md_server_limits *limits = md_engine_server_limits(e);
    if (!limits) limits = &fallback;
    const tcp_limits tl = {limits->tcp_read_timeout * 1000ull, limits->tcp_write_timeout * 1000ull,
                           limits->tcp_max_connections ? limits->tcp_max_connections : 1,
                           limits->tcp_max_connections_per_ip ? limits->tcp_max_connections_per_ip : 1};
    const unsigned max_connections = tl.max_connections, max_polled = 65 + max_connections;
    unsigned total = workers * MD_LANE_COUNT;
    int result = -1, *fds = calloc(count, sizeof(*fds));
    connection *cs = calloc(max_connections, sizeof(*cs));
    pthread_t *threads = calloc(total, sizeof(*threads));
    worker *roles = calloc(total, sizeof(*roles));
    struct pollfd *pf = calloc(max_polled, sizeof(*pf));
    int *slots = calloc(max_polled, sizeof(*slots));
    uint64_t *generations = calloc(max_polled, sizeof(*generations));
    pool p = {.engine = e, .wake = {-1, -1}, .queue_timeout = limits->queue_timeout_ms};
    int udp_rcvbuf[64] = {0};
    unsigned started = 0;
    if (!fds || !cs || !threads || !roles || !pf || !slots || !generations) {
        snprintf(err, MD_ERROR_SIZE, "out of memory"); free(fds); free(cs); free(threads); free(roles);
        free(pf); free(slots); free(generations); return -1;
    }
    for (size_t i = 0; i < count; i++) fds[i] = -1;
    for (size_t i = 0; i < max_connections; i++) cs[i].fd = -1;
    pthread_mutex_init(&p.lock, NULL);
    for (unsigned i = 0; i < MD_LANE_COUNT; i++) pthread_cond_init(&p.lanes[i].ready, NULL);
    if (pipe(p.wake) || nonblock(p.wake[0]) || nonblock(p.wake[1])) {
        snprintf(err, MD_ERROR_SIZE, "completion pipe: %s", strerror(errno)); goto cleanup;
    }
    preallocate_fdtable(p.wake[0], count, max_connections, total);
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
    for (; started < total; started++) {
        roles[started] = (worker){&p, started % MD_LANE_COUNT};
        int rc = md_thread_create(&threads[started], work, &roles[started]);
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
        size_t n = 0;
        pf[n] = (struct pollfd){p.wake[0], POLLIN, 0}; slots[n++] = -2;
        for (size_t i = 0; i < count; i++) { pf[n] = (struct pollfd){fds[i], POLLIN, 0}; slots[n++] = -1; }
        uint64_t now = md_now_ms();
        /* worker 尚未完成的 TCP 连接暂不参与读写轮询；完成通知会重新挂上写事件。 */
        for (int i = 0; i < (int)max_connections; i++) {
            connection *c = &cs[i];
            if (c->fd < 0) continue;
            if (c->busy && !c->output) continue;
            if (expired(c, &tl, now)) { close_connection(&p, c); continue; }
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
                struct sockaddr_storage peer; socklen_t peer_len = sizeof(peer);
                memset(&peer, 0, sizeof(peer));
                int fd = accept(fds[i - 1], (struct sockaddr *)&peer, &peer_len);
                if (fd < 0) break;
                uint8_t key[16]; source_key(&peer, key);
                int slot = admit(&p, cs, &tl, key);
                if (slot < 0 || nonblock(fd)) { close(fd); continue; }
                cs[slot].fd = fd; cs[slot].last = md_now_ms();
                memcpy(cs[slot].source, key, sizeof(key));
                cs[slot].entry = l->entry;
                cs[slot].idle = (l->idle_timeout ? l->idle_timeout : 10) * 1000ull;
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
    /* 先禁止新任务并等待所有 worker，再释放 job 和监听器；保证 worker 发 UDP 时
     * socket 仍有效，且不会访问已释放的队列或引擎引用。 */
    pthread_mutex_lock(&p.lock); p.stopping = true;
    for (unsigned i = 0; i < MD_LANE_COUNT; i++) pthread_cond_broadcast(&p.lanes[i].ready);
    pthread_mutex_unlock(&p.lock);
    for (unsigned i = 0; i < started; i++) pthread_join(threads[i], NULL);
    for (int i = 0; i < (int)max_connections; i++) close_connection(&p, &cs[i]);
    job *j;
    for (unsigned i = 0; i < MD_LANE_COUNT; i++) {
        j = p.lanes[i].head;
        while (j) { job *next = j->next; free(j); j = next; }
    }
    j = p.done_head;
    while (j) { job *next = j->next; free(j); j = next; }
    j = p.idle;
    while (j) { job *next = j->next; free(j); j = next; }
    for (size_t i = 0; i < count; i++) if (fds[i] >= 0) close(fds[i]);
    if (p.wake[0] >= 0) close(p.wake[0]);
    if (p.wake[1] >= 0) close(p.wake[1]);
    for (unsigned i = 0; i < MD_LANE_COUNT; i++) pthread_cond_destroy(&p.lanes[i].ready);
    pthread_mutex_destroy(&p.lock);
    free(roles); free(threads); free(cs); free(fds);
    free(pf); free(slots); free(generations);
    return result;
}
