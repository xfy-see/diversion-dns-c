/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MD_REQUEST_METRICS_H
#define MD_REQUEST_METRICS_H
#include "mosdns.h"
typedef struct md_request_metrics md_request_metrics;
/* Disabled unless DIVERSION_METRICS_FILE is an absolute path. Never logs names. */
md_request_metrics *md_request_metrics_new(md_engine *engine);
uint64_t md_request_metrics_begin(md_request_metrics *m, bool tcp);
void md_request_metrics_end(md_request_metrics *m, uint64_t start,
                            const md_packet *response, bool sent, bool rejected);
/* Event-loop only; at most once per five seconds unless final=true. */
void md_request_metrics_write(md_request_metrics *m, bool final);
void md_request_metrics_free(md_request_metrics *m);
#endif
