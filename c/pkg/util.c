/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
/* 缓存 TTL 和执行期限使用单调时钟的整秒值，避免系统校时改变存活时间。
 * 读取失败保留现有约定返回 0；调用方不会把它当成 Unix 时间戳。 */
uint64_t md_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec;
}
uint64_t md_now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}
uint64_t md_now_ns(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec * 1000000000u + (uint64_t)ts.tv_nsec;
}
/* 诊断计时输出：一个带 1 MiB 缓冲的 FILE，stdio 自带的锁串行化各线程写入。 */
bool md_trace_enabled;
_Thread_local md_trace *md_trace_cur;
static FILE *trace_file;
void md_trace_init(void) {
    const char *path = getenv("DIVERSION_TRACE");
    if (trace_file || !path || !*path) return;
    trace_file = fopen(path, "w");
    if (!trace_file) { fprintf(stderr, "DIVERSION_TRACE: cannot open %s\n", path); return; }
    setvbuf(trace_file, NULL, _IOFBF, 1u << 20);
    fputs("#diversion-trace v1 kind lane flags id qtype qname resends attempts recv dispatched enqueue pickup engine0 up_send up_recv nft0 nft_io nft1 engine1 reply\n", trace_file);
    md_trace_enabled = true;
}
void md_trace_emit(const md_trace *t, const md_packet *q) {
    if (!trace_file || !t) return;
    char name[256] = "-"; unsigned id = 0, qtype = 0;
    if (q && q->len >= 12) {
        id = md_read16(q->data);
        md_question parsed;
        if (q->len <= MD_MAX_PACKET && !md_dns_question(q, &parsed, NULL)) {
            snprintf(name, sizeof(name), "%s", parsed.name); qtype = parsed.type;
        }
    }
    flockfile(trace_file);
    fprintf(trace_file, "%c\t%u\t%u\t%u\t%u\t%s\t%u\t%u", (t->flags & MD_TF_REFRESH_JOB) ? 'R' : 'Q',
            t->lane, (unsigned)t->flags, id, qtype, name, (unsigned)t->up_resends, (unsigned)t->up_attempts);
    for (unsigned i = 0; i < MD_T_COUNT; i++) fprintf(trace_file, "\t%llu", (unsigned long long)t->t[i]);
    fputc('\n', trace_file);
    funlockfile(trace_file);
}
void md_trace_close(void) {
    if (trace_file) { fclose(trace_file); trace_file = NULL; }
    md_trace_enabled = false;
}
/* worker 与 lazy refresh 线程会执行 nft、缓存和上游代码；不依赖链接参数，
 * 显式保证线程栈不小于 MD_THREAD_STACK，平台默认更大时保持不变。 */
int md_thread_create(pthread_t *thread, void *(*fn)(void *), void *arg) {
    pthread_attr_t attr; size_t size = 0;
    int rc = pthread_attr_init(&attr);
    if (rc) return rc;
    if (pthread_attr_getstacksize(&attr, &size) || size < MD_THREAD_STACK)
        rc = pthread_attr_setstacksize(&attr, MD_THREAD_STACK);
    if (!rc) rc = pthread_create(thread, &attr, fn, arg);
    pthread_attr_destroy(&attr);
    return rc;
}
