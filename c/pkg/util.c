/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <pthread.h>
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
