/* SPDX-License-Identifier: GPL-3.0-or-later */
/* The FIFO leader owns the socket and caches without holding the queue mutex.
 * Generation changes invalidate readback, never imply that a mapping survived:
 * after a concurrent commit every key is read back again (present with enough
 * lifetime = success). A bounded retry re-reads all targets and writes only the
 * keys still missing; successful DNS requires complete ACKs.
 */
#define NFT_FAST_SLOTS 2048u
#define NFT_FAST_KEYS 1024u
#define NFT_FAST_ANSWER_KEYS 256u
#define NFT_FAST_WIRE 65536u
#define NFT_FAST_COHORT 32u
#define NFT_FAST_ATTEMPTS 5u
#define NFT_FAST_RETRY 1
#define NFT_FAST_SEQ_RESERVE ((2u * NFT_FAST_KEYS + 64u) * 16u)
struct nft_fast_waiter {
    struct nft_fast_waiter *next;
    const md_packet *packet;
    const md_dns_view *view; /* packet 的整包校验结果；cohort 写者只遍历描述符 */
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
    uint8_t keys[NFT_FAST_KEYS][16], keys6[NFT_FAST_KEYS][16];
    uint64_t timeouts[NFT_FAST_KEYS], timeouts6[NFT_FAST_KEYS];
    /* recent_stale: cached mappings were dropped (generation adopted/reset), so the
     * hit-skip records in md_nft must be cleared before new ones are noted.
     * verify_ms: cohort start, before its generation read (conservative). */
    bool recent_stale;
    uint64_t verify_ms;
    /* Pipelined readback scratch (per family) and the generation read by the
     * GETGEN that rode on the last readback datagram (tail_gen_valid). */
    uint64_t rb_existing[2][NFT_FAST_KEYS], rb_now[2][NFT_FAST_KEYS];
    bool rb_need[2][NFT_FAST_KEYS], tail_gen_valid;
    uint32_t tail_gen;
    uint8_t wire[NFT_FAST_WIRE], receive[MD_NL_BUFFER_SIZE];
};
static void nft_fast_invalidate(nft_fast_state *s) {
    s->recent_stale = true;
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
static int nft_fast_generation(nft_fast_state *s, uint64_t until, uint32_t *seen, char *err) {
    uint32_t after;
    if (nft_nl_generation(s->fd, s->port, nft_fast_seq(s), s->receive, until, &after, err)) return -1;
    if (seen) *seen = after;
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
/* Encode one REQUEST-only GETSETELEM for `key` at out[0..). req describes only
 * this message (wire = out), so ACK/echo checks stay per request. */
static int nft_fast_elem_encode(nft_fast_state *s, const nft_target *t, const uint8_t key[16],
                                uint8_t *out, size_t cap, md_nl_requests *req, size_t *length) {
    memset(req, 0, sizeof(*req));
    req->wire = out;
    req->port = s->port;
    md_nl_writer w = {out, cap, 0};
    size_t at, es, elem, k;
    uint32_t seq = nft_fast_seq(s);
    if (md_nl_message_start(&w, req, 0xA0D, 1, seq, nft_fast_family(t), 0, &at) ||
        md_nl_attr(&w, 1, t->table, strlen(t->table) + 1) || md_nl_attr(&w, 2, t->set, strlen(t->set) + 1) ||
        md_nl_nested_start(&w, 3, &es) || md_nl_nested_start(&w, 1, &elem) ||
        md_nl_nested_start(&w, 1, &k) || md_nl_attr(&w, 1, key, t->bytes) ||
        md_nl_nested_end(&w, k) || md_nl_nested_end(&w, elem) || md_nl_nested_end(&w, es)) return -1;
    md_nl_message_end(&w, at);
    req->length = *length = w.length;
    return 0;
}
/* Parse exactly one reply message p[0..length) to the request in req. */
static int nft_fast_elem_reply(nft_fast_state *s, const nft_target *t, const uint8_t key[16],
                               md_nl_requests *req, const uint8_t *p, size_t length,
                               uint64_t *remaining, char *err) {
    int e = 0;
    *remaining = 0;
    if (length < 20 || md_nl_u32(p) != length || md_nl_u32(p+8) != md_nl_u32(req->wire+8) ||
        md_nl_u32(p+12) != s->port) goto invalid;
    if (md_nl_u16(p+4) == 2) {
        if (md_nl_ack_one(req, p, length, &e)) goto invalid;
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
/* Pipelined readback: one sendto carries up to NFT_FAST_PIPE REQUEST-only
 * GETSETELEMs, optionally followed by one GETGEN. The kernel processes the
 * messages of one datagram in order, so the result equals the previous
 * one-round-trip-per-key sequence (and the trailing GETGEN equals the
 * generation check that used to follow the last readback), with fewer
 * syscalls and wakeups. Replies may arrive in one or several datagrams;
 * every reply is matched by sequence number and checked like before.
 * The chunk bound keeps all replies far below the socket receive buffer. */
#define NFT_FAST_PIPE 8u
static int nft_fast_existing_many(nft_fast_state *s, const nft_target *t, uint8_t (*keys)[16],
                                  const size_t *index, size_t n, bool with_gen, uint64_t until,
                                  uint64_t *remaining, uint32_t *generation, char *err) {
    md_nl_requests req[NFT_FAST_PIPE + 1];
    bool seen[NFT_FAST_PIPE + 1] = {0};
    size_t used = 0, total = n + (with_gen ? 1u : 0u), got = 0;
    if (with_gen && !generation) { snprintf(err, MD_ERROR_SIZE, "fast nft readback pipeline generation"); return -1; }
    if (!n || n > NFT_FAST_PIPE) { snprintf(err, MD_ERROR_SIZE, "fast nft readback pipeline size"); return -1; }
    for (size_t i = 0; i < n; i++) {
        size_t length;
        if (nft_fast_elem_encode(s, t, keys[index[i]], s->wire + used, sizeof(s->wire) - used, &req[i], &length)) {
            snprintf(err, MD_ERROR_SIZE, "encode fast nft element/sequence");
            return -1;
        }
        used += md_nl_align(length);
    }
    if (with_gen) {
        uint32_t seq = nft_fast_seq(s);
        if (!seq || md_nft_nl_getgen_encode(s->wire + used, sizeof(s->wire) - used, &req[n], s->port, seq)) {
            snprintf(err, MD_ERROR_SIZE, "nft sequence exhausted");
            return -1;
        }
        used += req[n].length;
    }
    if (nft_nl_send(s->fd, s->wire, used, until, err)) return -1;
    while (got < total) {
        size_t length;
        if (nft_nl_receive(s->fd, s->receive, sizeof(s->receive), &length, until, err)) return -1;
        const uint8_t *p = s->receive;
        while (length) {
            if (length < 20) goto invalid;
            size_t len = md_nl_u32(p);
            if (len < 20 || len > length) goto invalid;
            size_t step = md_nl_align(len) <= length ? md_nl_align(len) : len;
            uint32_t seq = md_nl_u32(p+8);
            size_t j = 0;
            for (; j < total; j++) if (md_nl_u32(req[j].wire + 8) == seq) break;
            if (j == total || seen[j]) goto invalid;
            if (j < n) {
                if (nft_fast_elem_reply(s, t, keys[index[j]], &req[j], p, len, &remaining[j], err)) return -1;
            } else {
                int e = 0;
                if (md_nft_nl_gen_consume(&req[j], p, step, generation, &e)) {
                    snprintf(err, MD_ERROR_SIZE, "invalid nft generation reply");
                    return -1;
                }
                if (e) { snprintf(err, MD_ERROR_SIZE, "nft generation query: %s", strerror(e)); return -1; }
            }
            seen[j] = true;
            got++;
            p += step;
            length -= step;
        }
    }
    return 0;
invalid:
    snprintf(err, MD_ERROR_SIZE, "invalid fast nft pipelined reply");
    return -1;
}
/* seen/limit count Answer IN A+AAAA in wire order, so an oversized answer
 * learns exactly its first `limit` addresses (the same records as md_dns_view.addresses). */
typedef struct { uint8_t (*keys)[16]; uint64_t *timeouts; const nft_target *t; size_t count; uint64_t until; unsigned seen, limit; } nft_fast_keys;
static int nft_fast_collect(const md_packet *p, const md_rr *rr, void *arg) {
    nft_fast_keys *v = arg;
    if (rr->section || rr->class_ != 1 || (rr->type != 1 && rr->type != 28) || ++v->seen > v->limit) return 0;
    if (rr->type != (v->t->bytes == 4 ? 1 : 28)) return 0;
    if (rr->data_len != v->t->bytes || milliseconds() >= v->until) return -1;
    const uint8_t *key = p->data + rr->data_offset;
    uint64_t ttl = (uint64_t)md_dns_ttl(rr->ttl) * 1000 + 15000;
    for (size_t i = 0; i < v->count; i++) {
        if (!memcmp(v->keys[i], key, v->t->bytes)) {
            if (v->timeouts[i] < ttl) v->timeouts[i] = ttl;
            return 0;
        }
    }
    if (v->count == NFT_FAST_KEYS) return -1;
    memset(v->keys[v->count], 0, 16);
    memcpy(v->keys[v->count], key, v->t->bytes);
    v->timeouts[v->count++] = ttl;
    return 0;
}
/* Adopt a generation committed by another writer: drop every cached mapping
 * (that commit may have removed them) and re-check this target's metadata. */
/* One target family's keys for this cohort; keys[0..pending) need a write. */
typedef struct { const nft_target *t; unsigned family; uint8_t (*keys)[16]; uint64_t *timeouts; size_t count, pending; } nft_fast_group;
static int nft_fast_revalidate(nft_fast_state *s, const nft_fast_group *g, size_t ng,
                               uint32_t generation, uint64_t until, char *err) {
    s->recent_stale = true;
    memset(s->entries, 0, sizeof(s->entries));
    s->metadata[0] = s->metadata[1] = false;
    s->generation = generation;
    for (size_t i = 0; i < ng; i++) {
        if (nft_fast_metadata(s, g[i].t, until, err)) return -1;
        s->metadata[g[i].family] = true;
    }
    return 0;
}
/* Readback confirmation after an ambiguous concurrent commit. Each key must be
 * present (or permanent) with remaining lifetime >= requested - 14 s, the same
 * margin nft_fast_target uses to skip writes. Confirmed keys are cached under
 * the new generation; if any key is missing the cohort retries, and the retry's
 * per-key readback writes only the keys that are still missing or short. */
static int nft_fast_confirm(nft_fast_state *s, const nft_fast_group *g, uint64_t until, char *err) {
    size_t missing = 0, count = g->count, at = 0;
    while (at < count) {
        size_t index[NFT_FAST_PIPE], n = 0;
        uint64_t now = milliseconds();
        if (now >= until) { snprintf(err, MD_ERROR_SIZE, "fast nft readback deadline"); return -1; }
        while (at < count && n < NFT_FAST_PIPE) index[n++] = at++;
        uint64_t existing[NFT_FAST_PIPE];
        if (nft_fast_existing_many(s, g->t, g->keys, index, n, false, until, existing, NULL, err)) return -1;
        for (size_t k = 0; k < n; k++) {
            uint64_t rem = existing[k];
            uint64_t expires = rem > UINT64_MAX - now ? UINT64_MAX : now + rem;
            if (rem == UINT64_MAX || (rem && expires >= until + g->timeouts[index[k]] - 14000)) {
                nft_fast_remember(s, g->family, g->keys[index[k]], g->t->bytes, expires);
                continue;
            }
            missing++;
        }
    }
    if (!missing) return 0;
    snprintf(err, MD_ERROR_SIZE, "nft generation changed around commit; %zu of %zu keys not confirmed", missing, count);
    return NFT_FAST_RETRY;
}
/* Commit g[i].keys[offset[i] .. offset[i]+count[i]) for every listed group in ONE
 * GENID-guarded transaction (Stage 4: a cohort's IPv4 and IPv6 keys share the
 * begin/end, ACK round trip and generation re-read). `all` lists every group of
 * the cohort, so an adopted generation re-checks all their metadata. */
static int nft_fast_commit(nft_fast_state *s, const nft_fast_group *g, size_t ng, const size_t *offset,
                           const size_t *count, const nft_fast_group *all, size_t nall,
                           uint64_t until, bool *moved, char *err) {
    md_nl_requests requests;
    md_nl_set_keys sets[2];
    size_t used = 0;
    for (size_t i = 0; i < ng; i++) {
        if (!count[i]) continue;
        sets[used++] = (md_nl_set_keys){nft_fast_family(g[i].t), g[i].t->table, g[i].t->set,
                                        (const uint8_t (*)[16])(g[i].keys + offset[i]), count[i], g[i].t->bytes,
                                        g[i].timeouts + offset[i]};
    }
    if (!used || md_nft_nl_batch_multi_encode(s->wire, sizeof(s->wire), &requests, s->port,
                                              nft_fast_seq(s), s->generation, sets, used)) {
        snprintf(err, MD_ERROR_SIZE, "encode fast nft batch/sequence");
        return -1;
    }
    uint64_t sent_at = milliseconds();
    if (nft_nl_send(s->fd, s->wire, requests.length, until, err)) return -1;
    atomic_fetch_add(&nft_stat_transactions, 1);
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
        /* Every ACK succeeded, so this GENID-guarded batch committed; another
         * writer committed too. Instead of failing (and retrying) the cohort,
         * adopt the new generation; the caller then reads every key back
         * (present with at least the requested lifetime counts as success). */
        *moved = true;
        return nft_fast_revalidate(s, all, nall, after, until, err);
    }
    s->generation = after;
    for (size_t j = 0; j < ng; j++)
        for (size_t i = offset[j]; i < offset[j] + count[j]; i++)
            nft_fast_remember(s, g[j].family, g[j].keys[i], g[j].t->bytes, sent_at + g[j].timeouts[i]);
    return 0;
}
/* Collect and metadata for one family, then mark the keys that need a kernel
 * readback (not cached with enough lifetime); no mutation, no readback yet. */
static int nft_fast_prepare(nft_fast_state *s, nft_fast_group *g, nft_fast_waiter **cohort, size_t count,
                            uint64_t until, char *err) {
    const nft_target *t = g->t;
    unsigned family = g->family;
    g->count = g->pending = 0;
    if (!t->enabled) return 0;
    nft_fast_keys v = {g->keys, g->timeouts, t, 0, until, 0, 0};
    for (size_t i = 0; i < count; i++) {
        v.seen = 0; v.limit = NFT_FAST_ANSWER_KEYS;
        if (md_dns_view_each(cohort[i]->packet, cohort[i]->view, nft_fast_collect, &v, err)) return -1;
    }
    g->count = v.count;
    if (!v.count) return 0;
    /* Metadata must be read inside one stable generation. If another writer
     * commits meanwhile, adopt its generation and read the metadata again
     * (bounded) instead of failing the whole attempt (N3). */
    for (unsigned tries = 0; !s->metadata[family]; tries++) {
        uint32_t seen = 0;
        s->tail_gen_valid = false;
        if (nft_fast_metadata(s, t, until, err)) return -1;
        int rc = nft_fast_generation(s, until, &seen, err);
        if (rc && (rc != NFT_FAST_RETRY || tries + 1 >= NFT_FAST_ATTEMPTS)) return rc;
        if (rc) { nft_fast_invalidate(s); s->generation = seen; continue; }
        s->metadata[family] = true;
    }
    for (size_t i = 0; i < v.count; i++) {
        nft_fast_entry *entry = nft_fast_entry_for(s, family, g->keys[i], t->bytes);
        uint64_t needed = until + g->timeouts[i] - 14000;
        bool known = entry->bytes == t->bytes && !memcmp(entry->key, g->keys[i], t->bytes);
        s->rb_need[family][i] = !(known && entry->expires >= needed);
    }
    return 0;
}
/* Read back every marked key of every group, NFT_FAST_PIPE per datagram. The
 * very last datagram also carries the GETGEN that nft_fast_finish needs, so a
 * cold single-key cohort costs one round trip for readback + generation
 * instead of two. Messages run in order in the kernel: the generation is read
 * after every readback exactly as before. */
static int nft_fast_readback(nft_fast_state *s, nft_fast_group *g, size_t ng, uint64_t until, char *err) {
    size_t last = ng;
    for (size_t j = 0; j < ng; j++)
        for (size_t i = 0; i < g[j].count; i++) if (s->rb_need[g[j].family][i]) { last = j; break; }
    s->tail_gen_valid = false;
    if (last == ng) return 0;
    for (size_t j = 0; j <= last; j++) {
        unsigned family = g[j].family;
        size_t index[NFT_FAST_PIPE], n = 0, remaining_marked = 0;
        for (size_t i = 0; i < g[j].count; i++) remaining_marked += s->rb_need[family][i];
        for (size_t i = 0; i < g[j].count; i++) {
            if (!s->rb_need[family][i]) continue;
            index[n++] = i;
            remaining_marked--;
            if (n < NFT_FAST_PIPE && remaining_marked) continue;
            uint64_t now = milliseconds();
            if (now >= until) { snprintf(err, MD_ERROR_SIZE, "fast nft readback deadline"); return -1; }
            bool tail = j == last && !remaining_marked;
            uint64_t existing[NFT_FAST_PIPE];
            uint32_t gen = 0;
            if (nft_fast_existing_many(s, g[j].t, g[j].keys, index, n, tail, until, existing, &gen, err)) return -1;
            for (size_t k = 0; k < n; k++) {
                s->rb_existing[family][index[k]] = existing[k];
                s->rb_now[family][index[k]] = now; /* precedes readback: conservative */
            }
            if (tail) { s->tail_gen = gen; s->tail_gen_valid = true; }
            n = 0;
        }
    }
    return 0;
}
/* Apply readback results exactly as the per-key loop did: cache keys that are
 * present with enough lifetime (or permanent), never shorten a longer one, and
 * move the keys that need a write to keys[0..pending). */
static void nft_fast_settle(nft_fast_state *s, nft_fast_group *g, uint64_t until) {
    const nft_target *t = g->t;
    unsigned family = g->family;
    size_t pending = 0;
    for (size_t i = 0; i < g->count; i++) {
        if (!s->rb_need[family][i]) continue;
        uint64_t needed = until + g->timeouts[i] - 14000;
        uint64_t existing = s->rb_existing[family][i], now = s->rb_now[family][i];
        uint64_t expires = existing > UINT64_MAX - now ? UINT64_MAX : now + existing;
        if (existing == UINT64_MAX || expires >= needed) {
            nft_fast_remember(s, family, g->keys[i], t->bytes, expires);
            continue;
        }
        if (existing > g->timeouts[i]) g->timeouts[i] = existing + 1000;
        /* Swap, not overwrite: keys[0..count) stay complete so every key can
         * be confirmed again if another writer commits. */
        if (pending != i) {
            uint8_t key[16]; uint64_t timeout = g->timeouts[pending];
            bool need = s->rb_need[family][pending];
            uint64_t ex = s->rb_existing[family][pending], at = s->rb_now[family][pending];
            memcpy(key, g->keys[pending], 16);
            memcpy(g->keys[pending], g->keys[i], 16);
            g->timeouts[pending] = g->timeouts[i];
            s->rb_need[family][pending] = true;
            memcpy(g->keys[i], key, 16);
            g->timeouts[i] = timeout;
            s->rb_need[family][i] = need; s->rb_existing[family][i] = ex; s->rb_now[family][i] = at;
        }
        pending++;
    }
    g->pending = pending;
}
/* Even an all-readback/all-cache hit validates the generation before
 * success. External flush can occur without any writes from this cohort.
 * If another writer committed meanwhile, do not discard the whole attempt:
 * adopt its generation (metadata re-checked), commit the pending keys under
 * it, then read every key back once more (N3). Two families with pending keys
 * that fit one transaction share it (Stage 4); otherwise each family commits
 * in SO_SNDBUF-sized chunks exactly as before. */
static int nft_fast_finish(nft_fast_state *s, nft_fast_group *g, size_t ng, uint64_t until, char *err) {
    bool moved = false;
    uint32_t seen = 0;
    int rc;
    if (s->tail_gen_valid) {
        /* The GETGEN that followed the last readback in the same datagram. */
        s->tail_gen_valid = false;
        seen = s->tail_gen;
        rc = 0;
        if (seen != s->generation) {
            snprintf(err, MD_ERROR_SIZE, "nft generation changed; revalidate all mappings");
            rc = NFT_FAST_RETRY;
        }
    } else rc = nft_fast_generation(s, until, &seen, err);
    if (rc == NFT_FAST_RETRY) {
        moved = true;
        if (nft_fast_revalidate(s, g, ng, seen, until, err)) return -1;
    } else if (rc) return rc;
    if (ng == 2 && g[0].pending && g[1].pending && g[0].pending + g[1].pending <= s->chunk_keys) {
        size_t offset[2] = {0, 0}, count[2] = {g[0].pending, g[1].pending};
        rc = nft_fast_commit(s, g, 2, offset, count, g, ng, until, &moved, err);
        if (rc) return rc;
    } else {
        for (size_t j = 0; j < ng; j++)
            for (size_t offset = 0; offset < g[j].pending; ) {
                size_t n = g[j].pending - offset;
                if (n > s->chunk_keys) n = s->chunk_keys;
                rc = nft_fast_commit(s, &g[j], 1, &offset, &n, g, ng, until, &moved, err);
                if (rc) return rc;
                offset += n;
            }
    }
    if (moved)
        for (size_t j = 0; j < ng; j++)
            if ((rc = nft_fast_confirm(s, &g[j], until, err))) return rc;
    return 0;
}
/* Record every key this cohort verified (cached expiry known) for the hit-skip
 * window. Stale records are cleared first when mappings were dropped. */
static void nft_fast_note_recent(md_nft *n, nft_fast_state *s, const nft_fast_group *g, size_t ng) {
    if (s->recent_stale) { nft_recent_clear(n); s->recent_stale = false; }
    if (!n->hit_window_ms) return;
    pthread_mutex_lock(&n->recent_lock);
    for (size_t j = 0; j < ng; j++)
        for (size_t i = 0; i < g[j].count; i++) {
            const nft_fast_entry *e = nft_fast_entry_for(s, g[j].family, g[j].keys[i], g[j].t->bytes);
            if (e->bytes == g[j].t->bytes && !memcmp(e->key, g[j].keys[i], g[j].t->bytes))
                nft_recent_put(n, g[j].family, g[j].keys[i], g[j].t->bytes, s->verify_ms, e->expires);
        }
    pthread_mutex_unlock(&n->recent_lock);
}
/* Both families: prepare IPv4 then IPv6 (no mutation), then one finish. A
 * cohort whose answers carry only one family behaves exactly as before. */
static int nft_fast_targets(md_nft *n, nft_fast_state *s, nft_fast_waiter **cohort, size_t count,
                            uint64_t until, char *err) {
    nft_fast_group g[2] = {{&n->v4, 0, s->keys, s->timeouts, 0, 0}, {&n->v6, 1, s->keys6, s->timeouts6, 0, 0}};
    s->tail_gen_valid = false;
    int rc = nft_fast_prepare(s, &g[0], cohort, count, until, err);
    if (!rc) rc = nft_fast_prepare(s, &g[1], cohort, count, until, err);
    if (rc) return rc;
    nft_fast_group active[2];
    size_t ng = 0;
    for (size_t j = 0; j < 2; j++) if (g[j].count) active[ng++] = g[j];
    if (ng && (rc = nft_fast_readback(s, active, ng, until, err))) return rc;
    for (size_t j = 0; j < ng; j++) nft_fast_settle(s, &active[j], until);
    if (!ng) { nft_fast_note_recent(n, s, active, 0); return 0; }
    rc = nft_fast_finish(s, active, ng, until, err);
    if (!rc) nft_fast_note_recent(n, s, active, ng);
    return rc;
}
static int nft_fast_cohort(md_nft *n, nft_fast_waiter **cohort, size_t count,
                           uint64_t until, char *err) {
    for (unsigned attempt = 0; attempt < NFT_FAST_ATTEMPTS; attempt++) {
        if (milliseconds() >= until) break;
        if (nft_fast_open(n, err)) return -1;
        nft_fast_state *s = n->fast;
        uint32_t gen;
        s->verify_ms = milliseconds();
        int rc = nft_nl_generation(s->fd, s->port, nft_fast_seq(s), s->receive, until, &gen, err);
        if (!rc) {
            if (gen != s->generation) nft_fast_invalidate(s);
            s->generation = gen;
            rc = nft_fast_targets(n, s, cohort, count, until, err);
        }
        if (!rc && milliseconds() < until) return 0;
        /* Any failure leaves kernel state uncertain: drop every hit-skip record. */
        nft_recent_clear(n);
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
static int nft_fast_apply(md_nft *n, const md_packet *r, const md_dns_view *view, char *err) {
    nft_fast_waiter self = {.packet = r, .view = view, .until = milliseconds() + 5000};
    /* view->addresses 统计 Answer 中 IN A/AAAA，与 nft_fast_collect 的 seen 口径一致。 */
    self.addresses = view->addresses;
    /* No A/AAAA (NXDOMAIN, TXT, CNAME-only): nothing to learn, no netlink round trip. */
    if (!self.addresses) return 0;
    /* N2: learn the first 256 addresses and answer normally; SERVFAIL for a
     * large CDN/round-robin answer would hide every address from the client. */
    if (self.addresses > NFT_FAST_ANSWER_KEYS) {
        nft_warn(NFT_WARN_ANSWER_CAP, "fast nft answer has %u A/AAAA records; only the first %u are added to the set",
                 self.addresses, NFT_FAST_ANSWER_KEYS);
        self.addresses = NFT_FAST_ANSWER_KEYS;
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
            if (md_trace_cur) { md_trace_cur->t[MD_T_NFT_IO] = md_now_ns(); md_trace_cur->flags |= MD_TF_NFT_LEADER; }
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
