/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MD_STATS_H
#define MD_STATS_H
/* Optional bounded runtime telemetry. No client IPs or packet logs. */
typedef struct md_stats md_stats;
enum { MD_SE_NONE, MD_SE_QUEUE_FULL, MD_SE_QUEUE_TIMEOUT, MD_SE_UPSTREAM,
       MD_SE_UPSTREAM_TIMEOUT, MD_SE_NFT, MD_SE_DEADLINE, MD_SE_RESPONSE,
       MD_SE_MEMORY, MD_SE_SEND, MD_SE_DISCONNECTED, MD_SE_SHUTDOWN, MD_SE_COUNT };
enum { MD_SV_INVALID_UDP, MD_SV_INVALID_TCP, MD_SV_TCP_READ_TIMEOUT,
       MD_SV_TCP_WRITE_TIMEOUT, MD_SV_TCP_LIMIT, MD_SV_TCP_EVICT,
       MD_SV_MEMORY, MD_SV_COUNT };
md_stats *md_stats_new(const char *path, unsigned interval, md_cache *cache, char *err);
int md_stats_start(md_stats *s, char *err);
void md_stats_free(md_stats *s);
uint64_t md_stats_begin(md_stats *s);
void md_stats_event(md_stats *s, unsigned event);
void md_stats_done(md_stats *s, const md_dns_query *qv, bool tcp, uint64_t start,
                   uint64_t queue_us, uint64_t service_us, bool delivered,
                   bool truncated, unsigned error);
md_stats *md_engine_stats(md_engine *e);
/* Read-only bounded snapshot display; does not load configuration or start DNS. */
int md_stats_show(const char *path);
#endif
