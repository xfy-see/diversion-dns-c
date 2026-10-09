/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <time.h>
/* 缓存 TTL 和执行期限使用单调时钟的整秒值，避免系统校时改变存活时间。
 * 读取失败保留现有约定返回 0；调用方不会把它当成 Unix 时间戳。 */
uint64_t md_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec;
}
