/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <time.h>
uint64_t md_now(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) return 0;
    return (uint64_t)ts.tv_sec;
}
