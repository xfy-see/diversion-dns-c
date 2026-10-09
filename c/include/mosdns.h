/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef MOSDNS_C_H
#define MOSDNS_C_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#define MD_MAX_PACKET 65535
#define MD_ERROR_SIZE 512
typedef struct { uint8_t data[MD_MAX_PACKET]; size_t len; } md_packet;
typedef struct {
    char name[256]; uint16_t type, class_, flags, udp_size;
    size_t end; bool do_bit;
} md_question;
typedef struct {
    size_t ttl_offset, data_offset; uint16_t type, class_, data_len;
    uint32_t ttl; unsigned section;
} md_rr;
typedef int (*md_rr_fn)(const md_packet *, const md_rr *, void *);
uint16_t md_read16(const uint8_t *p);
uint32_t md_read32(const uint8_t *p);
void md_write16(uint8_t *p, uint16_t n);
void md_write32(uint8_t *p, uint32_t n);
int md_dns_question(const md_packet *p, md_question *q, char *err);
int md_dns_records(const md_packet *p, md_rr_fn fn, void *arg, char *err);
bool md_dns_response_matches(const md_packet *q, const md_packet *r);
int md_dns_error(const md_packet *q, md_packet *r, unsigned rcode);
int md_dns_strip_opt(md_packet *p);
void md_dns_limit_udp(const md_packet *q, md_packet *r);

typedef struct md_domain md_domain;
md_domain *md_domain_new(void);
int md_domain_add(md_domain *d, const char *rule, char *err);
int md_domain_load(md_domain *d, const char *path, char *err);
bool md_domain_match(const md_domain *d, const char *name);
void md_domain_free(md_domain *d);

typedef struct md_cache md_cache;
md_cache *md_cache_new(size_t capacity, uint32_t lazy_ttl);
/* 0 miss, 1 fresh, 2 stale. now is monotonic seconds. */
int md_cache_get(md_cache *c, const md_packet *q, md_packet *r, uint64_t now);
void md_cache_put(md_cache *c, const md_packet *q, const md_packet *r, uint64_t now);
bool md_cache_refresh_begin(md_cache *c, const md_packet *q);
void md_cache_refresh_end(md_cache *c, const md_packet *q);
void md_cache_free(md_cache *c);

typedef struct {
    struct sockaddr_storage address; socklen_t address_len;
    bool tcp; uint32_t so_mark; char bind_device[64]; char tag[128];
} md_upstream;
int md_parse_address(const char *s, unsigned default_port, struct sockaddr_storage *a,
                     socklen_t *len, char *err);
int md_upstream_init(md_upstream *u, const char *addr, const char *dial_addr,
                     uint32_t mark, const char *device, char *err);
int md_forward(const md_upstream *us, size_t count, unsigned concurrent,
               const md_packet *q, md_packet *r, char *err);
/* Server workers opt in once and clean up after their final synchronous query.
 * Unscoped/library calls keep fresh sockets. Allocation failure also stays fresh. */
void md_forward_worker_enable(void);
void md_forward_worker_cleanup(void);

typedef struct md_nft md_nft;
md_nft *md_nft_new(const char *args, char *err);
int md_nft_apply(md_nft *n, const md_packet *r, char *err);
void md_nft_free(md_nft *n);

typedef struct md_engine md_engine;
typedef struct { char listen[256]; bool tcp; size_t entry; unsigned idle_timeout; } md_listener;
/* check=false loads domain files; check=true validates config without side effects. */
md_engine *md_engine_load(const char *path, bool check, char *err);
size_t md_engine_listener_count(const md_engine *e);
const md_listener *md_engine_listener(const md_engine *e, size_t i);
int md_engine_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r, char *err);
/* A fresh cache hit may finish synchronously only for the exact leading
 * unconditional cache -> has_resp/accept pair. Never runs downstream effects
 * or lazy refresh. A miss/ineligible/stale query leaves r->len=0. */
bool md_engine_cached_query(md_engine *e, size_t entry, const md_packet *q, md_packet *r);
void md_engine_free(md_engine *e);
uint64_t md_now(void);
int md_server_run(md_engine *e, unsigned workers, char *err);
#endif
