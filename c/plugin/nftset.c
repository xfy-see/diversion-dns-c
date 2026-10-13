/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 将 DNS 答案中的 A/AAAA 写入预先存在的 nft set。普通 set 使用有界
 * netlink 批次，interval set 使用 nft CLI 的前缀语法；不创建表或集合。
 * 执行仅支持 Linux，非 Linux 保留配置解析及可移植报文测试能力。 */
#define _POSIX_C_SOURCE 200809L
#include "mosdns.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __linux__
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <stdatomic.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "nft_netlink.h"
#include <time.h>
#include <unistd.h>
extern char **environ;
#endif

/* IPv4/IPv6 各保存一个目标；mask 只用于 interval set 的前缀聚合，
 * 普通 set 始终写入完整地址。 */
typedef struct {
    char family[5], table[128], set[128];
    unsigned mask, bytes;
    bool enabled;
} nft_target;
#ifdef __linux__
typedef struct nft_fast_state nft_fast_state;
typedef struct nft_fast_waiter nft_fast_waiter;
typedef struct nft_waiter { struct nft_waiter *next; } nft_waiter;
#endif
struct md_nft {
    nft_target v4, v6;
    bool fast_enabled;
#ifdef __linux__
    /* This mutex protects only the FIFO and active token, not nft I/O. */
    pthread_mutex_t lock;
    pthread_cond_t ready;
    nft_waiter *head, *tail;
    bool active;
    nft_fast_state *fast;
    nft_fast_waiter *fast_head, *fast_tail;
#endif
};
/* 表名、集合名只接受有限 ASCII 标识符，随后可直接作为 nft 的 token。
 * 这些限制也与可移植 netlink 编码器的标识符检查保持一致。 */
static bool valid_name(const char *s) {
    size_t n = strlen(s);
    if (!n || n >= 128) return false;
    unsigned char first = (unsigned char)s[0];
    if (!((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z') || first == '_')) return false;
    for (size_t i = 0; i < n; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return false;
    }
    return true;
}
/* 每段配置是 family,table,set,address_type,mask，最多两段。
 * 同一种地址类型的后段覆盖前段；解析失败不向调用方交付半成品对象。 */
md_nft *md_nft_new(const char *args, char *err) {
    md_nft *n = calloc(1, sizeof(*n));
    if (!n) { snprintf(err, MD_ERROR_SIZE, "out of memory creating nftset"); return NULL; }
    char *copy = strdup(args ? args : "");
    if (!copy) { free(n); snprintf(err, MD_ERROR_SIZE, "out of memory creating nftset"); return NULL; }
    char *save = NULL, *field = strtok_r(copy, " \t\r\n", &save); unsigned count = 0;
    while (field) {
        if (++count > 2) { snprintf(err, MD_ERROR_SIZE, "nftset expects at most two set specifications"); goto fail; }
        char *parts[5], *p = field;
        for (unsigned i = 0; i < 5; ++i) {
            parts[i] = p; char *comma = strchr(p, ',');
            if ((i < 4 && !comma) || (i == 4 && comma)) { snprintf(err, MD_ERROR_SIZE, "nftset expects family,table,set,address_type,mask"); goto fail; }
            if (comma) { *comma = '\0'; p = comma + 1; }
        }
        bool v4 = !strcmp(parts[3], "ipv4_addr"), v6 = !strcmp(parts[3], "ipv6_addr");
        if (!v4 && !v6) { snprintf(err, MD_ERROR_SIZE, "invalid nftset address type: %.100s", parts[3]); goto fail; }
        if (strcmp(parts[0], "inet") && strcmp(parts[0], "ip") && strcmp(parts[0], "ip6")) {
            snprintf(err, MD_ERROR_SIZE, "unsupported nftset family: %.100s", parts[0]); goto fail;
        }
        if (!valid_name(parts[1]) || !valid_name(parts[2])) { snprintf(err, MD_ERROR_SIZE, "nftset table/set names must start with an ASCII letter or underscore, then use ASCII letters, digits, underscore or hyphen (1-127 bytes)"); goto fail; }
        char *end = NULL; errno = 0; unsigned long mask = strtoul(parts[4], &end, 10);
        if (!parts[4][0] || parts[4][0] == '-' || errno || *end || mask > (v4 ? 32 : 128)) {
            snprintf(err, MD_ERROR_SIZE, "invalid nftset prefix mask: %.100s", parts[4]); goto fail;
        }
        /* Keep original unsigned-default behavior: zero means /24 or /48. */
        if (!mask) mask = v4 ? 24 : 48;
        nft_target *t = v4 ? &n->v4 : &n->v6;
        strcpy(t->family, parts[0]); strcpy(t->table, parts[1]); strcpy(t->set, parts[2]);
        t->mask = (unsigned)mask; t->bytes = v4 ? 4 : 16; t->enabled = true;
        field = strtok_r(NULL, " \t\r\n", &save);
    }
    free(copy);
#ifdef __linux__
    int initialized = pthread_mutex_init(&n->lock, NULL);
    if (initialized) { snprintf(err, MD_ERROR_SIZE, "initialize nftset mutex: %s", strerror(initialized)); free(n); return NULL; }
    /* 条件变量和整笔请求的截止时间都使用 CLOCK_MONOTONIC，
     * 排队耗时也计入 5 秒预算。 */
    pthread_condattr_t attr;
    initialized = pthread_condattr_init(&attr);
    bool attr_created = !initialized, cond_created = false;
    if (!initialized) initialized = pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
    if (!initialized) { initialized = pthread_cond_init(&n->ready, &attr); cond_created = !initialized; }
    if (attr_created) {
        int destroyed = pthread_condattr_destroy(&attr);
        if (!initialized) initialized = destroyed;
    }
    if (initialized) {
        if (cond_created) pthread_cond_destroy(&n->ready);
        pthread_mutex_destroy(&n->lock); free(n);
        snprintf(err, MD_ERROR_SIZE, "initialize nftset condition: %s", strerror(initialized)); return NULL;
    }
#endif
    return n;
fail:
    free(copy); free(n); return NULL;
}

#ifdef __linux__
/* Use the installed nft program directly, without a shell. All configuration
 * identifiers and generated addresses are validated before nft parses them. */
static const char *nft_binary(void) {
    const char *paths[] = {"/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"};
    for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i)
        if (!access(paths[i], X_OK)) return paths[i];
    return NULL;
}
static uint64_t milliseconds(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
/* Callers join all users before md_nft_free and never cancel a queued worker.
 * The stack waiter is unlinked under lock on every return. A new request may
 * claim the active token only as head, so a hot worker cannot bypass waiters. */
/* FIFO 中的等待节点在调用线程栈上，退出前必须持锁摘除。
 * active 是整笔 nft 操作的串行令牌：锁只保护队列，不在 I/O 期间持有；
 * 同一实例一次只允许一个请求操作目标，超时请求不会留在队列中。 */
static int nft_worker_enter(md_nft *n, uint64_t until, char *err) {
    int waiting = pthread_mutex_lock(&n->lock);
    if (waiting) { snprintf(err, MD_ERROR_SIZE, "lock nftset: %s", strerror(waiting)); return -1; }
    nft_waiter waiter = {NULL};
    if (n->tail) n->tail->next = &waiter;
    else n->head = &waiter;
    n->tail = &waiter;
    struct timespec deadline = {(time_t)(until / 1000), (long)(until % 1000) * 1000000};
    while (n->active || n->head != &waiter) {
        if (milliseconds() >= until) { waiting = ETIMEDOUT; break; }
        waiting = pthread_cond_timedwait(&n->ready, &n->lock, &deadline);
        if (waiting) break;
    }
    if (!waiting && milliseconds() >= until) waiting = ETIMEDOUT;
    if (!waiting) n->active = true;
    nft_waiter **link = &n->head, *previous = NULL;
    while (*link != &waiter) { previous = *link; link = &(*link)->next; }
    *link = waiter.next;
    if (n->tail == &waiter) n->tail = previous;
    if (!n->active && n->head) pthread_cond_broadcast(&n->ready);
    pthread_mutex_unlock(&n->lock);
    if (waiting == ETIMEDOUT) snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline waiting for a worker");
    else if (waiting) snprintf(err, MD_ERROR_SIZE, "wait for nftset worker: %s", strerror(waiting));
    return waiting ? -1 : 0;
}
/* 释放串行令牌并唤醒等待者；是否成为下一位由 FIFO 头部决定。 */
static int nft_worker_leave(md_nft *n, char *err) {
    int released = pthread_mutex_lock(&n->lock);
    if (released) { snprintf(err, MD_ERROR_SIZE, "release nftset worker: %s", strerror(released)); return -1; }
    n->active = false;
    released = pthread_cond_broadcast(&n->ready);
    int unlocked = pthread_mutex_unlock(&n->lock);
    if (!released) released = unlocked;
    if (released) snprintf(err, MD_ERROR_SIZE, "release nftset worker: %s", strerror(released));
    return released ? -1 : 0;
}
/* posix_spawn 直接执行程序，不经 shell；stderr 与 stdout 合并收集。
 * 输入从已生成的文件描述符读取，输出有固定上限；必须同时等到子进程
 * 已回收和输出 EOF。超时或读输出失败时终止并回收尚未退出的子进程。 */
static int run_nft(const char *binary, char *const argv[], int input,
                   char *output, size_t output_size, uint64_t until, char *err) {
    if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline"); return -1; }
    int pipes[2];
    if (pipe(pipes)) { snprintf(err, MD_ERROR_SIZE, "nft output pipe: %s", strerror(errno)); return -1; }
    fcntl(pipes[0], F_SETFD, FD_CLOEXEC); fcntl(pipes[1], F_SETFD, FD_CLOEXEC);
    posix_spawn_file_actions_t actions;
    int action_error = posix_spawn_file_actions_init(&actions);
    bool initialized = !action_error;
    if (!action_error) action_error = posix_spawn_file_actions_adddup2(&actions, pipes[1], STDOUT_FILENO);
    if (!action_error) action_error = posix_spawn_file_actions_adddup2(&actions, pipes[1], STDERR_FILENO);
    if (!action_error) action_error = posix_spawn_file_actions_addclose(&actions, pipes[0]);
    if (!action_error) action_error = posix_spawn_file_actions_addclose(&actions, pipes[1]);
    if (!action_error) action_error = input >= 0 ?
        posix_spawn_file_actions_adddup2(&actions, input, STDIN_FILENO) :
        posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    pid_t pid = -1;
    int spawn_error = action_error ? action_error : posix_spawn(&pid, binary, &actions, NULL, argv, environ);
    if (initialized) posix_spawn_file_actions_destroy(&actions);
    close(pipes[1]);
    if (spawn_error) { close(pipes[0]); snprintf(err, MD_ERROR_SIZE, "execute nft: %s", strerror(spawn_error)); return -1; }
    int flags = fcntl(pipes[0], F_GETFL, 0); fcntl(pipes[0], F_SETFL, flags | O_NONBLOCK);
    /* A pidfd tracks this exact child without consuming its wait status. It is
     * optional: older kernels or policy restrictions retain bounded polling. */
    int pidfd = -1;
#ifdef SYS_pidfd_open
    long process_fd = syscall(SYS_pidfd_open, pid, 0u);
    if (process_fd >= 0) {
        pidfd = (int)process_fd;
        if (fcntl(pidfd, F_SETFD, FD_CLOEXEC)) { close(pidfd); pidfd = -1; }
    }
#endif
    size_t used = 0; int status = 0; bool exited = false, eof = false, failed = false;
    while (!exited || !eof) {
        char chunk[4096]; ssize_t bytes;
        while ((bytes = read(pipes[0], chunk, sizeof(chunk))) > 0) {
            if ((size_t)bytes >= output_size - used) {
                snprintf(err, MD_ERROR_SIZE, "nft output exceeds %zu bytes", output_size - 1); failed = true; break;
            }
            memcpy(output + used, chunk, (size_t)bytes); used += (size_t)bytes;
        }
        if (failed) break;
        if (!bytes) eof = true;
        else if (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
            snprintf(err, MD_ERROR_SIZE, "read nft output: %s", strerror(errno)); failed = true; break;
        }
        if (!exited) {
            pid_t result = waitpid(pid, &status, WNOHANG);
            if (result == pid) exited = true;
            else if (result < 0 && errno != EINTR) { snprintf(err, MD_ERROR_SIZE, "wait for nft: %s", strerror(errno)); failed = true; break; }
        }
        if (exited && eof) break;
        if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline"); failed = true; break; }
        uint64_t now = milliseconds();
        if (now >= until) continue;
        int remaining = (int)(until - now); /* This transaction starts at 5 s. */
        if (eof && pidfd >= 0) {
            struct pollfd process = {pidfd, POLLIN, 0};
            int ready = poll(&process, 1, remaining);
            if ((ready < 0 && errno != EINTR) ||
                (ready > 0 && (process.revents & (POLLERR | POLLNVAL)))) {
                close(pidfd); pidfd = -1;
            }
        } else if (eof) {
            struct timespec delay = {0, (long)(remaining < 50 ? remaining : 50) * 1000000};
            nanosleep(&delay, NULL);
        } else {
            struct pollfd fd = {pipes[0], POLLIN, 0};
            poll(&fd, 1, remaining < 50 ? remaining : 50);
        }
    }
    output[used] = '\0'; close(pipes[0]);
    if (pidfd >= 0) close(pidfd);
    if (failed) {
        if (!exited) { kill(pid, SIGKILL); while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {} }
        return -1;
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status)) {
        while (used && (output[used - 1] == '\n' || output[used - 1] == '\r')) output[--used] = '\0';
        snprintf(err, MD_ERROR_SIZE, "nft command failed: %.450s", used ? output : "no diagnostics"); return -1;
    }
    return 0;
}
/* 64 KiB 输出缓冲放在堆上：musl 默认线程栈只有 128 KiB。 */
#define NFT_OUTPUT_SIZE 65536u
/* 数据路径的告警（跳过的元素等）按类别限速：每类最多每 10 秒一行，
 * 并附上期间被抑制的条数，避免攻击者或异常回答刷屏日志。 */
enum { NFT_WARN_OVERLAP, NFT_WARN_ANSWER_CAP, NFT_WARN_KINDS };
static void nft_warn(unsigned kind, const char *format, ...) __attribute__((format(printf, 2, 3)));
static void nft_warn(unsigned kind, const char *format, ...) {
    static atomic_uint_fast64_t last[NFT_WARN_KINDS], suppressed[NFT_WARN_KINDS];
    uint64_t now = milliseconds() + 10001, previous = atomic_load_explicit(&last[kind], memory_order_relaxed);
    if ((previous && now - previous < 10000) ||
        !atomic_compare_exchange_strong_explicit(&last[kind], &previous, now, memory_order_relaxed, memory_order_relaxed)) {
        atomic_fetch_add_explicit(&suppressed[kind], 1, memory_order_relaxed); return;
    }
    char text[MD_ERROR_SIZE]; va_list args; va_start(args, format);
    vsnprintf(text, sizeof(text), format, args); va_end(args);
    uint64_t skipped = atomic_exchange_explicit(&suppressed[kind], 0, memory_order_relaxed);
    if (skipped) fprintf(stderr, "nftset warning: %s (%llu similar warnings suppressed)\n", text, (unsigned long long)skipped);
    else fprintf(stderr, "nftset warning: %s\n", text);
}
/* Wire helper constants are portable for memory tests; bind them to Linux UAPI. */
_Static_assert(sizeof(struct nlmsghdr) == 16 && sizeof(struct nfgenmsg) == 4 && sizeof(struct nlattr) == 4, "netlink ABI layout");
_Static_assert(NFNL_SUBSYS_NFTABLES == 10 && NETLINK_NETFILTER == 12 && NFNETLINK_V0 == 0, "netfilter ABI");
_Static_assert(NFT_MSG_NEWSETELEM == 12 && NFT_MSG_GETGEN == 16 && NFT_MSG_NEWGEN == 15, "nft message ABI");
_Static_assert(NFNL_MSG_BATCH_BEGIN == 16 && NFNL_MSG_BATCH_END == 17 && NFNL_BATCH_GENID == 1, "batch ABI");
_Static_assert(NLM_F_REQUEST == 1 && NLM_F_ACK == 4 && NLM_F_CREATE == 0x400 && NLA_F_NESTED == 0x8000, "netlink flag ABI");
_Static_assert(NFTA_SET_ELEM_LIST_TABLE == 1 && NFTA_SET_ELEM_LIST_SET == 2 && NFTA_SET_ELEM_LIST_ELEMENTS == 3 && NFTA_LIST_ELEM == 1 && NFTA_SET_ELEM_KEY == 1 && NFTA_DATA_VALUE == 1 && NFTA_GEN_ID == 1, "nft attribute ABI");
_Static_assert(AF_NETLINK == 16 && NFPROTO_INET == 1 && NFPROTO_IPV4 == 2 && NFPROTO_IPV6 == 10, "netlink family ABI");
typedef struct { const nft_target *target; uint8_t (*keys)[16]; size_t count; uint64_t until; } nft_keys;
/* 只收集 answer section 的 IN A/AAAA，去重后最多保存 4095 个地址。
 * 扫描及去重过程中检查整笔请求的截止时间，避免大响应耗尽预算。 */
static int collect_plain_key(const md_packet *p, const md_rr *rr, void *arg) {
    nft_keys *v = arg;
    if (rr->section || rr->class_ != 1 || rr->type != (v->target->bytes == 4 ? 1 : 28)) return 0;
    if (rr->data_len != v->target->bytes || milliseconds() >= v->until) return -1;
    const uint8_t *key = p->data + rr->data_offset;
    for (size_t i = 0; i < v->count; ++i) {
        if (!(i % 64) && milliseconds() >= v->until) return -1;
        if (!memcmp(v->keys[i], key, rr->data_len)) return 0;
    }
    if (v->count == MD_NL_MAX_KEYS) return -1;
    memcpy(v->keys[v->count++], key, rr->data_len); return 0;
}
/* 下列发送、接收和 ACK 处理共享同一个截止点，重试 EINTR/EAGAIN
 * 不会重新获得一份超时预算。 */
static int nft_nl_wait(int fd, short events, uint64_t until, char *err) {
    while (milliseconds() < until) {
        uint64_t now = milliseconds(); if (now >= until) break;
        struct pollfd p = {fd, events, 0}; int rc = poll(&p, 1, (int)(until - now));
        if (rc < 0 && errno == EINTR) continue;
        if (rc < 0) { snprintf(err, MD_ERROR_SIZE, "poll nft netlink: %s", strerror(errno)); return -1; }
        if (!rc || milliseconds() >= until) break;
        if (p.revents & (POLLERR | POLLHUP | POLLNVAL)) { snprintf(err, MD_ERROR_SIZE, "nft netlink socket error"); return -1; }
        if (p.revents & events) return 0;
    }
    snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline in netlink"); return -1;
}
static int nft_nl_send(int fd, const uint8_t *wire, size_t length, uint64_t until, char *err) {
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    for (;;) {
        if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline before netlink send"); return -1; }
        ssize_t sent = sendto(fd, wire, length, 0, (struct sockaddr *)&kernel, sizeof(kernel));
        if (sent == (ssize_t)length) return 0;
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) { if (nft_nl_wait(fd, POLLOUT, until, err)) return -1; continue; }
        if (sent >= 0) snprintf(err, MD_ERROR_SIZE, "short nft netlink datagram send; mutation state unknown");
        else snprintf(err, MD_ERROR_SIZE, "send nft netlink: %s", strerror(errno));
        return -1;
    }
}
/* 只接收内核的单播消息；截断、控制数据截断及意外发送方均拒绝。
 * 编码器负责结构及请求关联检查，本层先确认 recvmsg 的来源和完整性。 */
static int nft_nl_receive(int fd, uint8_t *wire, size_t capacity, size_t *length, uint64_t until, char *err) {
    for (;;) {
        if (nft_nl_wait(fd, POLLIN, until, err)) return -1;
        struct sockaddr_nl sender = {0}; struct iovec iov = {wire, capacity};
        struct msghdr message = {.msg_name = &sender, .msg_namelen = sizeof(sender), .msg_iov = &iov, .msg_iovlen = 1};
        ssize_t received = recvmsg(fd, &message, 0);
        if (received < 0 && (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (received < 0) { snprintf(err, MD_ERROR_SIZE, "receive nft netlink: %s", strerror(errno)); return -1; }
        if (!received || (message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) || message.msg_namelen != sizeof(sender) || sender.nl_family != AF_NETLINK || sender.nl_pid || sender.nl_groups) {
            snprintf(err, MD_ERROR_SIZE, "invalid/truncated nft netlink kernel sender"); return -1;
        }
        if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline receiving netlink"); return -1; }
        *length = (size_t)received; return 0;
    }
}
/* GETGEN 返回完整的 32 位 ruleset generation，作为后续批次的
 * 乐观并发条件；不能用 nfgenmsg.res_id 的 16 位摘要替代。 */
static int nft_nl_generation(int fd, uint32_t port, uint32_t seq, uint8_t *receive, uint64_t until, uint32_t *generation, char *err) {
    uint8_t request[20]; md_nl_requests requests; size_t length; int kernel_errno = 0;
    if (!seq) { snprintf(err, MD_ERROR_SIZE, "nft sequence exhausted"); return -1; }
    if (md_nft_nl_getgen_encode(request, sizeof(request), &requests, port, seq) || nft_nl_send(fd, request, requests.length, until, err) || nft_nl_receive(fd, receive, MD_NL_BUFFER_SIZE, &length, until, err)) return -1;
    if (md_nft_nl_gen_consume(&requests, receive, length, generation, &kernel_errno)) { snprintf(err, MD_ERROR_SIZE, "invalid nft generation reply"); return -1; }
    if (kernel_errno) { snprintf(err, MD_ERROR_SIZE, "nft generation query: %s", strerror(kernel_errno)); return -1; }
    if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline validating generation"); return -1; }
    return 0;
}
/* 每次写入都新开私有 netlink socket，序列号只需在该 socket 内唯一。
 * 进程级计数按 16 个序列号一组分配，在 32 位范围内回绕并跳过 0，长期运行
 * 不会耗尽；每组覆盖 GETGEN、GETSET、GETGEN 及最多 10 条批次请求。 */
#define NFT_SEQ_BLOCKS ((UINT32_MAX - 16u) / 16u)
static atomic_uint_fast64_t nft_sequence = ATOMIC_VAR_INIT(0);
static uint32_t nft_sequence_ticket(void) {
    uint64_t block = atomic_fetch_add_explicit(&nft_sequence, 1, memory_order_relaxed);
    return (uint32_t)(block % NFT_SEQ_BLOCKS) * 16u + 1u;
}
/* 其他 nft 写者（dnsmasq、fw4、另一实例）提交会让 generation 检查失败；
 * 重试前短暂退避 1-4 ms 并加抖动，避免与对方同步碰撞，且不超过截止时间。 */
#define NFT_RETRY 1
#define NFT_PLAIN_ATTEMPTS 3u
static void nft_retry_backoff(unsigned attempt, uint64_t until) {
    static atomic_uint jitter = ATOMIC_VAR_INIT(0);
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    unsigned x = (unsigned)now.tv_nsec ^ atomic_fetch_add_explicit(&jitter, 0x9e3779b9u, memory_order_relaxed);
    x ^= x >> 15; x *= 0x2c1b3c6du; x ^= x >> 12;
    uint64_t delay = (1u << (attempt < 2 ? attempt : 2)) + x % 3u;
    if (milliseconds() + delay >= until) return;
    struct timespec pause = {0, (long)delay * 1000000L};
    nanosleep(&pause, NULL);
}
/* 用 netlink GETSET 读取集合元数据（类型、键长、flags），不再 fork
 * `nft list set`：GETSET 回复本身带 NFTA_SET_FLAGS，可以直接判断 interval。
 * 只接受键类型/长度匹配、非 map/object/concat 的地址集合；interval 由
 * *interval 报告，调用方改走 nft -f。automerge 可为 NULL。 */
#define NFT_INTERVAL 2
static int nft_nl_metadata(int fd, uint32_t port, uint32_t seq, const nft_target *t,
                           uint8_t *receive, uint64_t until, bool *interval, bool *automerge, char *err) {
    uint8_t request[320]; md_nl_requests requests; size_t length; int kernel_errno = 0; uint32_t flags = 0;
    uint8_t family = !strcmp(t->family, "inet") ? 1 : !strcmp(t->family, "ip") ? 2 : 10;
    if (md_nft_nl_getset_encode(request, sizeof(request), &requests, port, seq, family, t->table, t->set)) {
        snprintf(err, MD_ERROR_SIZE, "encode nft set metadata query"); return -1;
    }
    if (nft_nl_send(fd, request, requests.length, until, err) || nft_nl_receive(fd, receive, MD_NL_BUFFER_SIZE, &length, until, err)) return -1;
    if (md_nft_nl_set_inspect(&requests, receive, length, family, t->table, t->set, t->bytes, &kernel_errno, 2, &flags, automerge)) {
        snprintf(err, MD_ERROR_SIZE, "nftset %s/%s/%s is not a supported %s set (changed during metadata check?)", t->family, t->table, t->set, t->bytes == 4 ? "ipv4_addr" : "ipv6_addr"); return -1;
    }
    if (kernel_errno) { snprintf(err, MD_ERROR_SIZE, "nft set metadata: %s", strerror(kernel_errno)); return -1; }
    *interval = (flags & 4u) != 0;
    return 0;
}
/* 使用独立 netlink socket 和序列号范围，避免混入其他事务的 ACK。
 * 先查询 generation，再读集合元数据并复查 generation；批次携带该值，
 * 让内核拒绝元数据检查后发生的规则变更。发送后的失败不转用 CLI，
 * 因为写入结果可能已经生效，重放会掩盖不确定的状态。只有确定未提交的
 * 冲突（generation 变化、批次 ERESTART）返回 NFT_RETRY，由调用方新开 socket 重试。 */
static int add_plain_attempt(const nft_target *t, const nft_keys *values, uint8_t *wire, uint8_t *receive, uint64_t until, char *err) {
    int fd = -1, rc = -1;
    uint32_t ticket = nft_sequence_ticket();
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (fd < 0) { snprintf(err, MD_ERROR_SIZE, "open nft netlink: %s", strerror(errno)); goto done; }
    struct sockaddr_nl local = {.nl_family = AF_NETLINK}; socklen_t size = sizeof(local);
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) || getsockname(fd, (struct sockaddr *)&local, &size) || size != sizeof(local) || local.nl_family != AF_NETLINK || !local.nl_pid || local.nl_groups) {
        snprintf(err, MD_ERROR_SIZE, "bind private nft netlink port: %s", strerror(errno)); goto done;
    }
    uint32_t before, after; bool interval = false;
    if (nft_nl_generation(fd, local.nl_pid, ticket, receive, until, &before, err) ||
        nft_nl_metadata(fd, local.nl_pid, ticket + 1, t, receive, until, &interval, NULL, err)) goto done;
    /* interval set：前缀/区间语义交给 nft -f，不再额外 fork `nft list set`。 */
    if (interval) { snprintf(err, MD_ERROR_SIZE, "nftset %s/%s/%s is an interval set", t->family, t->table, t->set); rc = NFT_INTERVAL; goto done; }
    if (nft_nl_generation(fd, local.nl_pid, ticket + 2, receive, until, &after, err)) goto done;
    if (before != after) { snprintf(err, MD_ERROR_SIZE, "nft ruleset generation changed during metadata check"); rc = NFT_RETRY; goto done; }
    md_nl_requests requests; uint8_t family = !strcmp(t->family, "inet") ? 1 : !strcmp(t->family, "ip") ? 2 : 10;
    if (md_nft_nl_batch_encode(wire, MD_NL_BUFFER_SIZE, &requests, local.nl_pid, ticket + 3, family, t->table, t->set, (const uint8_t (*)[16])values->keys, values->count, t->bytes, after)) { snprintf(err, MD_ERROR_SIZE, "encode bounded nft add batch"); goto done; }
    if (nft_nl_send(fd, wire, requests.length, until, err)) goto done;
    /* 一个 recvmsg 可以包含多个 ACK；必须检查整包中的边界错误，
     * 收齐所有要求 ACK 的添加请求后，才报告本批次成功。 */
    do {
        size_t length; int kernel_errno = 0;
        if (nft_nl_receive(fd, receive, MD_NL_BUFFER_SIZE, &length, until, err)) goto done;
        if (md_nft_nl_ack_consume(&requests, receive, length, &kernel_errno)) { snprintf(err, MD_ERROR_SIZE, "invalid nft add ACK cohort; mutation state unknown"); goto done; }
        if (kernel_errno) {
            snprintf(err, MD_ERROR_SIZE, "nft add transaction: %s", strerror(kernel_errno));
            /* GENID 拒绝不提交任何修改（MIPS 与 asm-generic 的 errno 值不同）。 */
            if (kernel_errno == ERESTART) rc = NFT_RETRY;
            goto done;
        }
    } while (!md_nft_nl_ack_complete(&requests));
    if (milliseconds() >= until) { snprintf(err, MD_ERROR_SIZE, "nftset query exceeded its 5 second deadline validating add ACKs"); goto done; }
    rc = 0;
done:
    if (fd >= 0) close(fd);
    return rc;
}
/* 返回 0 成功、-1 失败；NFT_INTERVAL 表示目标是 interval set，尚未写入任何内容。 */
static int add_plain_target(const nft_target *t, const md_packet *r, uint64_t until, char *err) {
    /* No fallback after send. Interval targets return before any batch is sent. */
    int rc = -1; uint8_t (*keys)[16] = calloc(MD_NL_MAX_KEYS, sizeof(*keys));
    uint8_t *wire = malloc(MD_NL_BUFFER_SIZE), *receive = malloc(MD_NL_BUFFER_SIZE);
    if (!keys || !wire || !receive) { snprintf(err, MD_ERROR_SIZE, "allocate bounded nft netlink transaction"); goto done; }
    nft_keys values = {t, keys, 0, until};
    if (md_dns_records(r, collect_plain_key, &values, err)) goto done;
    if (!values.count) { snprintf(err, MD_ERROR_SIZE, "nft plain address collection failed"); goto done; }
    for (unsigned attempt = 0; ; attempt++) {
        rc = add_plain_attempt(t, &values, wire, receive, until, err);
        if (rc != NFT_RETRY) break;
        if (attempt + 1 >= NFT_PLAIN_ATTEMPTS || milliseconds() >= until) { rc = -1; break; }
        nft_retry_backoff(attempt, until);
    }
done:
    free(keys); free(wire); free(receive); return rc == NFT_INTERVAL ? NFT_INTERVAL : rc ? -1 : 0;
}
/* interval 元素按 mask 清零主机位后去重，保存为文本前缀。 */
#define NFT_ELEMENT_TEXT (INET6_ADDRSTRLEN + 4)
typedef struct { const nft_target *target; char (*text)[NFT_ELEMENT_TEXT]; size_t count; } nft_prefixes;
static int collect_prefix(const md_packet *p, const md_rr *rr, void *arg) {
    nft_prefixes *v = arg;
    if (rr->section || rr->class_ != 1 || rr->type != (v->target->bytes == 4 ? 1 : 28)) return 0;
    if (rr->data_len != v->target->bytes) return -1;
    uint8_t bytes[16]; memcpy(bytes, p->data + rr->data_offset, rr->data_len);
    unsigned bits = v->target->mask;
    for (unsigned i = 0; i < v->target->bytes; ++i) {
        if (bits >= 8) bits -= 8;
        else { bytes[i] &= bits ? (uint8_t)(0xffu << (8 - bits)) : 0; bits = 0; }
    }
    char address[INET6_ADDRSTRLEN], text[NFT_ELEMENT_TEXT];
    if (!inet_ntop(v->target->bytes == 4 ? AF_INET : AF_INET6, bytes, address, sizeof(address))) return -1;
    snprintf(text, sizeof(text), "%s/%u", address, v->target->mask);
    for (size_t i = 0; i < v->count; ++i) if (!strcmp(v->text[i], text)) return 0;
    if (v->count == MD_NL_MAX_KEYS) return -1;
    memcpy(v->text[v->count++], text, sizeof(text)); return 0;
}
static int count_address(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p; const nft_target *t = ((const nft_prefixes *)arg)->target;
    if (!rr->section && rr->class_ == 1 && rr->type == (t->bytes == 4 ? 1 : 28)) ++((nft_prefixes *)arg)->count;
    return 0;
}
/* nft 对 interval 冲突的诊断形如 "/dev/stdin:1:25-34: Error: interval overlaps
 * with an existing one"（旧内核为 "File exists"）。按列号找到冲突元素的下标；
 * 无法定位时返回 -1。column[i] 是第 i 个元素在第 1 行的起始列（从 1 开始）。 */
static long overlap_element(const char *output, const size_t *column, size_t count) {
    if (!strstr(output, "interval overlaps") && !strstr(output, "File exists")) return -1;
    for (const char *p = strstr(output, ":1:"); p; p = strstr(p + 1, ":1:")) {
        unsigned first = 0, last = 0;
        if (sscanf(p, ":1:%u-%u:", &first, &last) != 2 || first > last) continue;
        for (size_t i = 0; i < count; ++i)
            if (column[i] == first) return (long)i;
    }
    return count == 1 ? 0 : -1;
}
/* 没有 auto-merge 的 interval set 里已有重叠前缀时，nft 拒绝整个批次。
 * 逐个剔除 nft 报告的冲突元素后重试（每次 1 次 exec，最多 NFT_OVERLAP_SKIPS 个），
 * 其余元素照常写入，DNS 回答正常返回；被跳过的前缀已与集合中现有区间重叠。 */
#define NFT_OVERLAP_SKIPS 16u
static int add_interval_target(const char *binary, const nft_target *t, const md_packet *r, uint64_t until, char *err) {
    if (!binary) binary = nft_binary();
    if (!binary) { snprintf(err, MD_ERROR_SIZE, "nftset requires nft in /usr/sbin, /sbin, /usr/bin or /bin"); return -1; }
    int rc = -1; FILE *file = NULL;
    nft_prefixes v = {t, calloc(MD_NL_MAX_KEYS, NFT_ELEMENT_TEXT), 0};
    size_t *column = calloc(MD_NL_MAX_KEYS, sizeof(*column));
    char *output = malloc(NFT_OUTPUT_SIZE), *argv[] = {(char *)binary, "-f", "-", NULL};
    if (!v.text || !column || !output) { snprintf(err, MD_ERROR_SIZE, "allocate nft interval input"); goto done; }
    if (md_dns_records(r, collect_prefix, &v, err)) goto done;
    for (unsigned skipped = 0; v.count; ) {
        file = tmpfile();
        if (!file) { snprintf(err, MD_ERROR_SIZE, "create nft input: %s", strerror(errno)); goto done; }
        fcntl(fileno(file), F_SETFD, FD_CLOEXEC);
        int at = fprintf(file, "add element %s %s %s { ", t->family, t->table, t->set);
        for (size_t i = 0; at > 0 && i < v.count; ++i) {
            column[i] = (size_t)at + 1;
            int n = fprintf(file, "%s%s", v.text[i], i + 1 < v.count ? ", " : "");
            at = n < 0 ? -1 : at + n;
        }
        fputs(" }\n", file);
        if (at < 0 || fflush(file) || ferror(file)) { snprintf(err, MD_ERROR_SIZE, "write nft input: %s", strerror(errno)); goto done; }
        rewind(file);
        rc = run_nft(binary, argv, fileno(file), output, NFT_OUTPUT_SIZE, until, err);
        fclose(file); file = NULL;
        if (!rc) break;
        long bad = overlap_element(output, column, v.count);
        if (bad < 0 || skipped >= NFT_OVERLAP_SKIPS || milliseconds() >= until) goto done;
        nft_warn(NFT_WARN_OVERLAP, "skip %s for %s/%s/%s: overlaps an existing interval (add flags interval + auto-merge to this set)",
                 v.text[bad], t->family, t->table, t->set);
        memmove(v.text[bad], v.text[bad + 1], (v.count - (size_t)bad - 1) * NFT_ELEMENT_TEXT);
        --v.count; ++skipped; rc = 0;
    }
done:
    if (file) fclose(file);
    free(v.text); free(column); free(output); return rc;
}
/* 先确认响应中有目标地址，再访问 nft 元数据。元数据只走 netlink GETSET：
 * 普通 set 直接用 netlink 批次写入（0 次 exec），interval set 用一次 nft -f -。 */
static int add_target(const char *binary, const nft_target *t, const md_packet *r, uint64_t until, char *err) {
    if (!t->enabled) return 0;
    /* Collect before reading metadata: no A/AAAA answers means no nft access. */
    nft_prefixes count = {t, NULL, 0};
    if (md_dns_records(r, count_address, &count, err)) return -1;
    if (!count.count) return 0;
    int rc = add_plain_target(t, r, until, err);
    return rc == NFT_INTERVAL ? add_interval_target(binary, t, r, until, err) : rc;
}
#endif

#ifdef __linux__
#include "nft_fast.h"
#endif
int md_nft_enable_fast(md_nft *n, char *err) {
    if (!n || (!n->v4.enabled && !n->v6.enabled) ||
        (n->v4.enabled && n->v4.mask != 32) || (n->v6.enabled && n->v6.mask != 128)) {
        snprintf(err, MD_ERROR_SIZE, "fast nftset requires full-address /32 and /128 targets"); return -1;
    }
#ifdef __linux__
    /* Conservative deployment baseline; older/backported kernels must use the
     * compatible path until their timeout-update semantics are validated. */
    struct utsname system;
    unsigned major = 0, minor = 0;
    if (uname(&system) || sscanf(system.release, "%u.%u", &major, &minor) != 2 ||
        major < 6 || (major == 6 && minor < 12)) {
        snprintf(err, MD_ERROR_SIZE, "fast nftset requires Linux 6.12 or newer; use nftset_fast=0");
        return -1;
    }
#endif
    n->fast_enabled = true; return 0;
}

#ifdef __linux__
/* 只读检查：interval 目标缺少 auto-merge 时，已有重叠前缀会让写入被拒绝
 * （运行时会跳过冲突元素，见 add_interval_target）。读不到（集合尚未创建、
 * 无权限、非 Linux）时保持沉默，不影响启动或 check 的结果。 */
static void nft_audit_target(const nft_target *t, uint8_t *receive) {
    if (!t->enabled) return;
    char err[MD_ERROR_SIZE];
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (fd < 0) return;
    struct sockaddr_nl local = {.nl_family = AF_NETLINK}; socklen_t size = sizeof(local);
    bool interval = false, automerge = false;
    if (!bind(fd, (struct sockaddr *)&local, sizeof(local)) && !getsockname(fd, (struct sockaddr *)&local, &size) &&
        size == sizeof(local) && local.nl_pid &&
        !nft_nl_metadata(fd, local.nl_pid, nft_sequence_ticket(), t, receive, milliseconds() + 1000, &interval, &automerge, err) &&
        interval && !automerge)
        fprintf(stderr, "nftset warning: %s %s %s is an interval set without auto-merge; answers whose prefixes overlap "
                "existing elements will have those prefixes skipped. Recreate it with \"flags interval; auto-merge;\"\n",
                t->family, t->table, t->set);
    close(fd);
}
#endif
void md_nft_audit(const md_nft *n) {
#ifdef __linux__
    if (!n || n->fast_enabled) return;
    uint8_t *receive = malloc(MD_NL_BUFFER_SIZE);
    if (!receive) return;
    nft_audit_target(&n->v4, receive); nft_audit_target(&n->v6, receive);
    free(receive);
#else
    (void)n;
#endif
}
/* IPv4 后 IPv6 共用排队与 I/O 的 5 秒预算；第一个失败立即返回。
 * 两种地址目标之间没有统一事务，IPv6 失败不会回滚已完成的 IPv4 写入。
 * 无论哪条路径出错，取得的串行令牌都由 leave 释放。 */
int md_nft_apply(md_nft *n, const md_packet *r, char *err) {
    if (!n || !r) { snprintf(err, MD_ERROR_SIZE, "invalid nftset input"); return -1; }
#ifndef __linux__
    snprintf(err, MD_ERROR_SIZE, "nftset execution is supported only on Linux"); return -1;
#else
    if (n->fast_enabled) return nft_fast_apply(n, r, err);
    uint64_t until = milliseconds() + 5000;
    if (nft_worker_enter(n, until, err)) return -1;
    /* nft 程序只在 interval set 需要时才查找（NULL 表示按固定路径查找）。 */
    int rc = add_target(NULL, &n->v4, r, until, err);
    if (!rc) rc = add_target(NULL, &n->v6, r, until, err);
    char release_error[MD_ERROR_SIZE] = {0};
    if (nft_worker_leave(n, release_error) && !rc) { snprintf(err, MD_ERROR_SIZE, "%s", release_error); rc = -1; }
    return rc;
#endif
}
/* 销毁前调用方须停止并等待所有使用者，包含排队线程；此处不取消任务。 */
void md_nft_free(md_nft *n) {
    if (!n) return;
#ifdef __linux__
    nft_fast_free(n->fast);
    pthread_cond_destroy(&n->ready); pthread_mutex_destroy(&n->lock);
#endif
    free(n);
}
