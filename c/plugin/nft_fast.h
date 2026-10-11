/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The FIFO leader owns the socket and caches without holding the queue mutex.
 * Generation changes invalidate readback, never imply that a mapping survived.
 * A bounded retry re-reads all targets; successful DNS requires complete ACKs.
 */
#define NFT_FAST_SLOTS 2048u
#define NFT_FAST_KEYS 1024u
#define NFT_FAST_ANSWER_KEYS 256u
#define NFT_FAST_WIRE 65536u
#define NFT_FAST_COHORT 32u
#define NFT_FAST_ATTEMPTS 3u
#define NFT_FAST_RETRY 1
#define NFT_FAST_SEQ_RESERVE ((2u * NFT_FAST_KEYS + 64u) * 16u)
struct nft_fast_waiter {
    struct nft_fast_waiter *next;
    const md_packet *packet;
    uint64_t until;
    unsigned addresses;
    bool working, done;
    int rc;
    char error[MD_ERROR_SIZE];
};
typedef struct { uint8_t key[16]; uint64_t expires; unsigned bytes; } nft_fast_entry;
struct nft_fast_state {
    int fd;
    uint32_t port, seq, generation;
    size_t chunk_keys;
    bool metadata[2];
    nft_fast_entry entries[2][NFT_FAST_SLOTS];
    uint8_t keys[NFT_FAST_KEYS][16];
    uint64_t timeouts[NFT_FAST_KEYS];
    uint8_t wire[NFT_FAST_WIRE], receive[MD_NL_BUFFER_SIZE];
};
static void nft_fast_invalidate(nft_fast_state *s) {
    memset(s->entries, 0, sizeof(s->entries));
    s->metadata[0] = s->metadata[1] = false;
    s->generation = 0;
}
static void nft_fast_reset(nft_fast_state *s) {
    if (!s) return;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
    nft_fast_invalidate(s);
}
static void nft_fast_free(nft_fast_state *s) {
    nft_fast_reset(s);
    free(s);
}
static uint32_t nft_fast_seq(nft_fast_state *s) {
    if (s->seq > UINT32_MAX - 32u) return 0;
    uint32_t seq = s->seq;
    s->seq += 16;
    return seq;
}
static int nft_fast_open(md_nft *n, char *err) {
    if (!n->fast) {
        n->fast = calloc(1, sizeof(*n->fast));
        if (!n->fast) { snprintf(err, MD_ERROR_SIZE, "allocate bounded fast nft state"); return -1; }
        n->fast->fd = -1;
    }
    nft_fast_state *s = n->fast;
    if (s->fd >= 0 && s->seq <= UINT32_MAX - NFT_FAST_SEQ_RESERVE) return 0;
    nft_fast_reset(s);
    s->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_NETFILTER);
    if (s->fd < 0) { snprintf(err, MD_ERROR_SIZE, "open fast nft socket: %s", strerror(errno)); return -1; }
    struct sockaddr_nl local = {.nl_family = AF_NETLINK};
    socklen_t size = sizeof(local);
    int sndbuf = 0;
    socklen_t sndsize = sizeof(sndbuf);
    if (bind(s->fd, (struct sockaddr *)&local, sizeof(local)) ||
        getsockname(s->fd, (struct sockaddr *)&local, &size) ||
        size != sizeof(local) || local.nl_family != AF_NETLINK || !local.nl_pid || local.nl_groups ||
        getsockopt(s->fd, SOL_SOCKET, SO_SNDBUF, &sndbuf, &sndsize) ||
        sndsize != sizeof(sndbuf) || sndbuf < 1152) {
        snprintf(err, MD_ERROR_SIZE, "invalid fast nft socket/address/send buffer");
        nft_fast_reset(s);
        return -1;
    }
    /* netlink_sendmsg requires len <= sk_sndbuf - 32. Reserve 1024 for
     * names/headers and 64 per key (IPv6 with both time attributes: <=52).
     * Each transaction stays below both the real socket limit and our buffer.
     */
    size_t budget = (size_t)sndbuf - 32;
    if (budget > sizeof(s->wire)) budget = sizeof(s->wire);
    s->chunk_keys = (budget - 1024) / 64;
    if (s->chunk_keys > MD_NL_CHUNK_KEYS) s->chunk_keys = MD_NL_CHUNK_KEYS;
    s->port = local.nl_pid;
    s->seq = 1;
    return 0;
}
static unsigned nft_fast_slot(const uint8_t *key, unsigned bytes) {
    uint32_t h = 2166136261u;
    for (unsigned i = 0; i < bytes; i++) h = (h ^ key[i]) * 16777619u;
    return h & (NFT_FAST_SLOTS - 1u);
}
static nft_fast_entry *nft_fast_entry_for(nft_fast_state *s, unsigned family,
                                         const uint8_t *key, unsigned bytes) {
    return &s->entries[family][nft_fast_slot(key, bytes)];
}
static void nft_fast_remember(nft_fast_state *s, unsigned family, const uint8_t *key,
                              unsigned bytes, uint64_t expires) {
    nft_fast_entry *e = nft_fast_entry_for(s, family, key, bytes);
    memcpy(e->key, key, 16);
    e->bytes = bytes;
    e->expires = expires;
}
static uint8_t nft_fast_family(const nft_target *t) {
    return !strcmp(t->family, "inet") ? 1 : !strcmp(t->family, "ip") ? 2 : 10;
}
static int nft_fast_generation(nft_fast_state *s, uint64_t until, char *err) {
    uint32_t after;
    if (nft_nl_generation(s->fd, s->port, nft_fast_seq(s), s->receive, until, &after, err)) return -1;
    if (after == s->generation) return 0;
    snprintf(err, MD_ERROR_SIZE, "nft generation changed; revalidate all mappings");
    return NFT_FAST_RETRY;
}
static int nft_fast_metadata(nft_fast_state *s, const nft_target *t, uint64_t until, char *err) {
    uint8_t request[320];
    md_nl_requests requests;
    size_t length;
    int e = 0;
    if (md_nft_nl_getset_encode(request, sizeof(request), &requests, s->port,
                              nft_fast_seq(s), nft_fast_family(t), t->table, t->set)) {
        snprintf(err, MD_ERROR_SIZE, "encode fast nft metadata/sequence");
        return -1;
    }
    if (nft_nl_send(s->fd, request, requests.length, until, err) ||
        nft_nl_receive(s->fd, s->receive, sizeof(s->receive), &length, until, err)) return -1;
    if (md_nft_nl_set_consume(&requests, s->receive, length, nft_fast_family(t),
                            t->table, t->set, t->bytes, &e)) {
        snprintf(err, MD_ERROR_SIZE, "fast nft target must be a plain timeout IPv%u set", t->bytes == 4 ? 4u : 6u);
        return -1;
    }
    if (e) { snprintf(err, MD_ERROR_SIZE, "fast nft metadata: %s", strerror(e)); return -1; }
    return 0;
}
/* Accept Linux's unflagged nesting, but validate all lengths, identity and key.
 * KEY without EXPIRATION means permanent; never convert or shorten that entry.
 * ENOENT is an ordinary miss. UINT64_MAX is only a sentinel, never added to.
 */
static int nft_fast_existing(nft_fast_state *s, const nft_target *t, const uint8_t key[16],
                             uint64_t until, uint64_t *remaining, char *err) {
    uint8_t request[384];
    md_nl_requests req = {0};
    req.wire = request;
    req.port = s->port;
    md_nl_writer w = {request, sizeof(request), 0};
    size_t at, es, elem, k, length;
    int e = 0;
    *remaining = 0;
    if (md_nl_message_start(&w, &req, 0xA0D, 1, nft_fast_seq(s), nft_fast_family(t), 0, &at) ||
        md_nl_attr(&w, 1, t->table, strlen(t->table) + 1) || md_nl_attr(&w, 2, t->set, strlen(t->set) + 1) ||
        md_nl_nested_start(&w, 3, &es) || md_nl_nested_start(&w, 1, &elem) ||
        md_nl_nested_start(&w, 1, &k) || md_nl_attr(&w, 1, key, t->bytes) ||
        md_nl_nested_end(&w, k) || md_nl_nested_end(&w, elem) || md_nl_nested_end(&w, es)) {
        snprintf(err, MD_ERROR_SIZE, "encode fast nft element/sequence");
        return -1;
    }
    md_nl_message_end(&w, at);
    req.length = w.length;
    if (nft_nl_send(s->fd, request, w.length, until, err) ||
        nft_nl_receive(s->fd, s->receive, sizeof(s->receive), &length, until, err)) return -1;
    uint8_t *p = s->receive;
    if (length < 20 || md_nl_u32(p) != length || md_nl_u32(p+8) != md_nl_u32(request+8) ||
        md_nl_u32(p+12) != s->port) goto invalid;
    if (md_nl_u16(p+4) == 2) {
        if (md_nl_ack_one(&req, p, length, &e)) goto invalid;
        if (e == ENOENT) return 0;
        snprintf(err, MD_ERROR_SIZE, "fast nft element read: %s", strerror(e ? e : EPROTO));
        return -1;
    }
    if (md_nl_u16(p+4) != 0xA0C || md_nl_u16(p+6) || p[16] != nft_fast_family(t) || p[17]) goto invalid;
    p += 20;
    length -= 20;
    unsigned seen = 0;
    bool found = false;
    while (length) {
        if (length < 4) goto invalid;
        size_t a = md_nl_u16(p);
        unsigned type = md_nl_u16(p+2);
        if (a < 4 || md_nl_align(a) > length) goto invalid;
        if (type == 1 || type == 2) {
            const char *v = type == 1 ? t->table : t->set;
            if ((seen & (1u << type)) || a != strlen(v) + 5 || memcmp(p+4, v, a-4)) goto invalid;
            seen |= 1u << type;
        } else if ((type & ~0x8000u) == 3) {
            if (seen & 8) goto invalid;
            seen |= 8;
            const uint8_t *el = p+4;
            size_t eln = a-4;
            if (eln < 4 || md_nl_u16(el) != eln || (md_nl_u16(el+2) & ~0x8000u) != 1) goto invalid;
            el += 4;
            eln -= 4;
            unsigned fields = 0;
            while (eln) {
                if (eln < 4) goto invalid;
                size_t z = md_nl_u16(el);
                unsigned ty = md_nl_u16(el+2);
                if (z < 4 || md_nl_align(z) > eln) goto invalid;
                if ((ty & ~0x8000u) == 1) {
                    if ((fields & 1) || z != 8+t->bytes || md_nl_u16(el+4) != 4+t->bytes ||
                        md_nl_u16(el+6) != 1 || memcmp(el+8, key, t->bytes)) goto invalid;
                    fields |= 1;
                } else if (ty == 5) {
                    if ((fields & 2) || z != 12) goto invalid;
                    fields |= 2;
                    *remaining = ((uint64_t)md_nl_read_be32(el+4) << 32) | md_nl_read_be32(el+8);
                }
                el += md_nl_align(z);
                eln -= md_nl_align(z);
            }
            if (fields == 1) *remaining = UINT64_MAX;
            else if (fields != 3) goto invalid;
            found = true;
        }
        p += md_nl_align(a);
        length -= md_nl_align(a);
    }
    if (seen != 14 || !found) goto invalid;
    return 0;
invalid:
    snprintf(err, MD_ERROR_SIZE, "invalid fast nft element metadata");
    return -1;
}
typedef struct { nft_fast_state *s; const nft_target *t; size_t count; uint64_t until; } nft_fast_keys;
static int nft_fast_collect(const md_packet *p, const md_rr *rr, void *arg) {
    nft_fast_keys *v = arg;
    if (rr->section || rr->class_ != 1 || rr->type != (v->t->bytes == 4 ? 1 : 28)) return 0;
    if (rr->data_len != v->t->bytes || milliseconds() >= v->until) return -1;
    const uint8_t *key = p->data + rr->data_offset;
    uint64_t ttl = (uint64_t)md_dns_ttl(rr->ttl) * 1000 + 15000;
    for (size_t i = 0; i < v->count; i++) {
        if (!memcmp(v->s->keys[i], key, v->t->bytes)) {
            if (v->s->timeouts[i] < ttl) v->s->timeouts[i] = ttl;
            return 0;
        }
    }
    if (v->count == NFT_FAST_KEYS) return -1;
    memset(v->s->keys[v->count], 0, 16);
    memcpy(v->s->keys[v->count], key, v->t->bytes);
    v->s->timeouts[v->count++] = ttl;
    return 0;
}
static int nft_fast_commit(nft_fast_state *s, const nft_target *t, unsigned family,
                           size_t offset, size_t count, uint64_t until, char *err) {
    md_nl_requests requests;
    if (md_nft_nl_batch_timed_encode(s->wire, sizeof(s->wire), &requests, s->port,
        nft_fast_seq(s), nft_fast_family(t), t->table, t->set,
        (const uint8_t (*)[16])(s->keys + offset), count, t->bytes, s->generation, s->timeouts + offset)) {
        snprintf(err, MD_ERROR_SIZE, "encode fast nft batch/sequence");
        return -1;
    }
    uint64_t sent_at = milliseconds();
    if (nft_nl_send(s->fd, s->wire, requests.length, until, err)) return -1;
    do {
        size_t length;
        int e = 0;
        if (nft_nl_receive(s->fd, s->receive, sizeof(s->receive), &length, until, err)) return -1;
        if (md_nft_nl_ack_consume(&requests, s->receive, length, &e)) {
            snprintf(err, MD_ERROR_SIZE, "invalid fast nft ACK; mutation state unknown");
            return -1;
        }
        if (e) {
            snprintf(err, MD_ERROR_SIZE, "fast nft update: %s", strerror(e));
            /* GENID rejection commits no mutation; use the target errno
             * value (MIPS and asm-generic differ).
             * Reopen before retry to discard all remaining transaction ACKs.
             */
            return e == ERESTART ? NFT_FAST_RETRY : -1;
        }
    } while (!md_nft_nl_ack_complete(&requests));
    uint32_t after;
    if (nft_nl_generation(s->fd, s->port, nft_fast_seq(s), s->receive, until, &after, err)) return -1;
    if (after != s->generation + 1u) {
        snprintf(err, MD_ERROR_SIZE, "nft generation changed around commit; revalidate all mappings");
        return NFT_FAST_RETRY;
    }
    s->generation = after;
    for (size_t i = offset; i < offset + count; i++)
        nft_fast_remember(s, family, s->keys[i], t->bytes, sent_at + s->timeouts[i]);
    return 0;
}
static int nft_fast_target(nft_fast_state *s, const nft_target *t, unsigned family,
                           nft_fast_waiter **cohort, size_t count, uint64_t until, char *err) {
    if (!t->enabled) return 0;
    nft_fast_keys v = {s, t, 0, until};
    for (size_t i = 0; i < count; i++)
        if (md_dns_records(cohort[i]->packet, nft_fast_collect, &v, err)) return -1;
    if (!v.count) return 0;
    if (!s->metadata[family]) {
        if (nft_fast_metadata(s, t, until, err)) return -1;
        int rc = nft_fast_generation(s, until, err);
        if (rc) return rc;
        s->metadata[family] = true;
    }
    size_t pending = 0;
    for (size_t i = 0; i < v.count; i++) {
        uint64_t now = milliseconds();
        if (now >= until) { snprintf(err, MD_ERROR_SIZE, "fast nft readback deadline"); return -1; }
        nft_fast_entry *entry = nft_fast_entry_for(s, family, s->keys[i], t->bytes);
        uint64_t needed = until + s->timeouts[i] - 14000;
        bool known = entry->bytes == t->bytes && !memcmp(entry->key, s->keys[i], t->bytes);
        if (known && entry->expires >= needed) continue;
        uint64_t existing = 0;
        if (nft_fast_existing(s, t, s->keys[i], until, &existing, err)) return -1;
        /* now precedes readback, so the cached deadline is conservative. */
        uint64_t expires = existing > UINT64_MAX - now ? UINT64_MAX : now + existing;
        if (existing == UINT64_MAX || expires >= needed) {
            nft_fast_remember(s, family, s->keys[i], t->bytes, expires);
            continue;
        }
        if (existing > s->timeouts[i]) s->timeouts[i] = existing + 1000;
        if (pending != i) {
            memcpy(s->keys[pending], s->keys[i], 16);
            s->timeouts[pending] = s->timeouts[i];
        }
        pending++;
    }
    /* Even an all-readback/all-cache hit validates the generation before
     * success. External flush can occur without any writes from this cohort.
     */
    int rc = nft_fast_generation(s, until, err);
    if (rc) return rc;
    for (size_t offset = 0; offset < pending; ) {
        size_t n = pending - offset;
        if (n > s->chunk_keys) n = s->chunk_keys;
        rc = nft_fast_commit(s, t, family, offset, n, until, err);
        if (rc) return rc;
        offset += n;
    }
    return 0;
}
static int nft_fast_cohort(md_nft *n, nft_fast_waiter **cohort, size_t count,
                           uint64_t until, char *err) {
    for (unsigned attempt = 0; attempt < NFT_FAST_ATTEMPTS; attempt++) {
        if (milliseconds() >= until) break;
        if (nft_fast_open(n, err)) return -1;
        nft_fast_state *s = n->fast;
        uint32_t gen;
        int rc = nft_nl_generation(s->fd, s->port, nft_fast_seq(s), s->receive, until, &gen, err);
        if (!rc) {
            if (gen != s->generation) nft_fast_invalidate(s);
            s->generation = gen;
            rc = nft_fast_target(s, &n->v4, 0, cohort, count, until, err);
            if (!rc) rc = nft_fast_target(s, &n->v6, 1, cohort, count, until, err);
        }
        if (!rc && milliseconds() < until) return 0;
        nft_fast_reset(s);
        if (!rc) snprintf(err, MD_ERROR_SIZE, "fast nft deadline exceeded after verification");
        if (rc != NFT_FAST_RETRY) return -1;
        /* Concurrent writers: jittered backoff instead of an immediate retry. */
        if (attempt + 1 < NFT_FAST_ATTEMPTS) nft_retry_backoff(attempt, until);
    }
    snprintf(err, MD_ERROR_SIZE, "fast nft retry budget/deadline exhausted");
    return -1;
}
static void nft_fast_process(md_nft *n, nft_fast_waiter **cohort, size_t count, uint64_t until) {
    char message[MD_ERROR_SIZE] = {0};
    /* Reserve time for member isolation after a shared batch failure. */
    uint64_t shared_until = until;
    if (count > 1 && shared_until > milliseconds() + 1000) shared_until = milliseconds() + 1000;
    int rc = nft_fast_cohort(n, cohort, count, shared_until, message);
    for (size_t i = 0; i < count; i++) {
        int member_rc = rc;
        char member_error[MD_ERROR_SIZE] = {0};
        if (rc && count > 1) {
            uint64_t now = milliseconds();
            uint64_t left = cohort[i]->until > now ? cohort[i]->until - now : 0;
            uint64_t member_until = now + left / (count - i);
            member_rc = nft_fast_cohort(n, &cohort[i], 1, member_until, member_error);
        }
        cohort[i]->rc = member_rc;
        snprintf(cohort[i]->error, MD_ERROR_SIZE, "%s", rc && count > 1 ? member_error : message);
    }
}
static int nft_fast_count(const md_packet *p, const md_rr *rr, void *arg) {
    (void)p;
    unsigned *count = arg;
    if (!rr->section && rr->class_ == 1 && (rr->type == 1 || rr->type == 28)) ++*count;
    return 0;
}
static int nft_fast_apply(md_nft *n, const md_packet *r, char *err) {
    nft_fast_waiter self = {.packet = r, .until = milliseconds() + 5000};
    if (md_dns_records(r, nft_fast_count, &self.addresses, err)) return -1;
    /* No A/AAAA (NXDOMAIN, TXT, CNAME-only): nothing to learn, no netlink round trip. */
    if (!self.addresses) return 0;
    if (self.addresses > NFT_FAST_ANSWER_KEYS) {
        snprintf(err, MD_ERROR_SIZE, "fast nft answer exceeds 256 address records");
        return -1;
    }
    int lock_rc = pthread_mutex_lock(&n->lock);
    if (lock_rc) { snprintf(err, MD_ERROR_SIZE, "fast nft mutex: %s", strerror(lock_rc)); return -1; }
    if (n->fast_tail) n->fast_tail->next = &self;
    else n->fast_head = &self;
    n->fast_tail = &self;
    while (!self.done) {
        if (!n->active && n->fast_head == &self) {
            nft_fast_waiter *cohort[NFT_FAST_COHORT];
            size_t count = 0;
            unsigned addresses = 0;
            uint64_t until = self.until;
            while (n->fast_head && count < NFT_FAST_COHORT &&
                   addresses + n->fast_head->addresses <= NFT_FAST_KEYS) {
                nft_fast_waiter *p = n->fast_head;
                n->fast_head = p->next;
                p->working = true;
                cohort[count++] = p;
                addresses += p->addresses;
                if (p->until < until) until = p->until;
            }
            if (!n->fast_head) n->fast_tail = NULL;
            n->active = true;
            pthread_mutex_unlock(&n->lock);
            nft_fast_process(n, cohort, count, until);
            pthread_mutex_lock(&n->lock);
            for (size_t i = 0; i < count; i++) cohort[i]->done = true;
            n->active = false;
            pthread_cond_broadcast(&n->ready);
        } else {
            if (self.working) { pthread_cond_wait(&n->ready, &n->lock); continue; }
            struct timespec deadline = {(time_t)(self.until / 1000), (long)(self.until % 1000) * 1000000};
            int rc = pthread_cond_timedwait(&n->ready, &n->lock, &deadline);
            if (rc && !self.working && !self.done) {
                nft_fast_waiter **p = &n->fast_head, *previous = NULL;
                while (*p != &self) { previous = *p; p = &(*p)->next; }
                *p = self.next;
                if (n->fast_tail == &self) n->fast_tail = previous;
                self.rc = -1;
                snprintf(self.error, MD_ERROR_SIZE, "fast nft queue timeout/error: %s", strerror(rc));
                self.done = true;
                pthread_cond_broadcast(&n->ready);
            }
        }
    }
    pthread_mutex_unlock(&n->lock);
    if (self.rc) snprintf(err, MD_ERROR_SIZE, "%s", self.error);
    return self.rc;
}
