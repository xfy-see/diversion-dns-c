/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Included by engine.c. Fixed administrator-owned list, read once at load.
 * Deliberately separate from the runtime-owned restart warm snapshot. */
static int keep_load(md_engine *e, const char *path, char *err) {
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return fail(err, "cache keep: cannot open list: %s", strerror(errno));
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 || st.st_size > KEEP_FILE_MAX) {
        close(fd); return fail(err, "cache keep: expected regular file <= 64 KiB");
    }
    char *buf = malloc(KEEP_FILE_MAX + 1);
    md_packet *q = malloc(sizeof(*q));
    e->keep = calloc(KEEP_MAX, sizeof(*e->keep));
    if (!buf || !q || !e->keep) { close(fd); free(buf); free(q); return fail(err, "out of memory"); }
    size_t bytes = 0; int rc = 0;
    while (bytes < KEEP_FILE_MAX + 1) {
        ssize_t n = read(fd, buf + bytes, KEEP_FILE_MAX + 1 - bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { rc = fail(err, "cache keep: list read failed"); break; }
        if (!n) break;
        bytes += (size_t)n;
    }
    close(fd);
    if (!rc && (bytes > KEEP_FILE_MAX || memchr(buf, 0, bytes))) rc = fail(err, "cache keep: oversized list or NUL byte");
    size_t pos = 0, rows = 0, skipped = 0;
    while (!rc && pos < bytes) {
        size_t start = pos;
        while (pos < bytes && buf[pos] != '\n') pos++;
        size_t length = pos - start; pos++; rows++;
        if (length > 1024 || rows > 1024) { rc = fail(err, "cache keep: row/file limit exceeded"); break; }
        buf[start + length] = 0;
        char *line = trim(buf + start);
        if (!*line || *line == '#') continue;
        unsigned flags, type; char name[256], extra;
        if (sscanf(line, "%u %u %255s %c", &flags, &type, name, &extra) != 3 ||
            flags > 7 || (type != 1 && type != 28) || strlen(name) > 253 ||
            !strchr(name, '.') || strpbrk(name, "*:/")) {
            rc = fail(err, "cache keep: invalid flags/type/name at row %zu", rows); break;
        }
        uint8_t address[16];
        if (inet_pton(AF_INET, name, address) == 1 || inet_pton(AF_INET6, name, address) == 1) {
            rc = fail(err, "cache keep: IP literal at row %zu", rows); break;
        }
        for (char *p = name; *p; p++) if (*p >= 'A' && *p <= 'Z') *p = (char)(*p + ('a' - 'A'));
        char normalized[280]; snprintf(normalized, sizeof(normalized), "%u %u %s", flags, type, name);
        md_dns_query qv;
        if (warm_query(normalized, q) || md_dns_query_parse(q, &qv, NULL)) {
            rc = fail(err, "cache keep: invalid DNS name at row %zu", rows); break;
        }
        /* Never override classification or send a CN name to foreign DNS. */
        if (md_domain_match(e->cn, qv.q.name)) { skipped++; continue; }
        bool duplicate = false;
        for (size_t i = 0; i < e->keep_count; i++)
            if (!strcmp(normalized, e->keep[i].line)) { duplicate = true; break; }
        if (duplicate) continue;
        if (e->keep_count == KEEP_MAX) { rc = fail(err, "cache keep: exceeds 256 unique query keys"); break; }
        keep_entry *entry = &e->keep[e->keep_count++];
        snprintf(entry->line, sizeof(entry->line), "%s", normalized);
        /* Stable per-key offset plus process-start noise, no per-hit RNG. */
        uint64_t h = md_now_ns();
        for (const char *p = normalized; *p; p++) h = h * 33 + (unsigned char)*p;
        entry->jitter = 75 + (unsigned)(h % 51);
    }
    if (!rc) fprintf(stderr, "cache keep: loaded %zu query keys, skipped %zu CN rows\n", e->keep_count, skipped);
    free(buf); free(q); return rc;
}

/* Positive answers refresh before expiry; negative entries wait until expiry.
 * A five-second minimum per key bounds tiny TTLs. Such TTLs may expire before
 * the next refresh; this feature never extends freshness or pins cache data. */
static uint64_t keep_due(md_engine *e, keep_entry *entry, const md_cache_lifetime *life) {
    uint64_t ttl = life->expires - life->stored, advance = 0;
    if (life->positive && ttl > 1) {
        advance = ttl * e->keep_percent * entry->jitter / 10000;
        if (!advance) advance = 1;
        if (advance >= ttl) advance = ttl - 1;
    }
    uint64_t due = life->expires - advance;
    uint64_t minimum = life->stored + (life->positive ? 5 : 30);
    return due > minimum ? due : minimum;
}
static void keep_tick(md_engine *e, md_packet *q, md_packet *r) {
    uint64_t now_ns = md_now_ns();
    if (now_ns < e->keep_next_ns) return;
    for (size_t n = 0; n < e->keep_count; n++) {
        size_t i = (e->keep_cursor + n) % e->keep_count;
        keep_entry *entry = &e->keep[i];
        if (now_ns < entry->next_ns) continue;
        md_dns_query qv; char err[MD_ERROR_SIZE] = {0};
        if (warm_query(entry->line, q) || md_dns_query_parse(q, &qv, err)) continue; /* load-validated */
        md_cache_lifetime life;
        uint64_t now = md_now();
        if (!entry->failures && md_cache_peek(e->cache, q, &qv, &life)) {
            uint64_t due = keep_due(e, entry, &life);
            if (due > now) { entry->next_ns = due * UINT64_C(1000000000); continue; }
        }
        /* Same marker/backoff as stale and demand prefetch. Foreground cache
         * misses retain their existing behavior (no foreground queue added). */
        if (!md_cache_refresh_begin_at(e->cache, q, &qv, now)) {
            entry->next_ns = now_ns + UINT64_C(1000000000);
            md_cache_count(e->cache, MD_CACHE_FOREIGN, MD_CS_KEEP_DEFER); continue;
        }
        e->keep_cursor = (i + 1) % e->keep_count;
        md_cache_count(e->cache, MD_CACHE_FOREIGN, MD_CS_KEEP_QUERY);
        r->len = 0;
        int rc = resolve_ex(e, false, q, &qv, r, now + 5, true, err);
        md_dns_view *view = md_dns_view_scratch();
        bool accepted = r->len >= 12 && view && view->valid && view->len == r->len &&
            !view->signed_ && !(md_read16(r->data + 2) & 0x0200) &&
            (md_dns_view_rcode(r, view) == 0 || md_dns_view_rcode(r, view) == 3) &&
            md_dns_view_matches(q, &qv.q, r, view);
        bool ok = !rc && accepted;
        now = md_now(); now_ns = md_now_ns();
        md_cache_refresh_finish(e->cache, q, &qv, now, accepted);
        md_cache_count(e->cache, MD_CACHE_FOREIGN, ok ? MD_CS_KEEP_OK : MD_CS_KEEP_FAIL);
        if (ok) {
            entry->failures = 0;
            /* TTL=0/uncacheable/empty negative: retry at most every 30 s. */
            uint64_t due = now + 30;
            if (md_cache_peek(e->cache, q, &qv, &life)) due = keep_due(e, entry, &life);
            entry->next_ns = (due > now ? due : now + 5) * UINT64_C(1000000000);
        } else {
            if (entry->failures < 5) entry->failures++;
            unsigned delay = 5u << (entry->failures - 1);
            if (delay > 60) delay = 60;
            entry->next_ns = now_ns + (uint64_t)delay * UINT64_C(1000000000);
        }
        /* Pace after completion, so no catch-up burst after a slow timeout. */
        e->keep_next_ns = now_ns + UINT64_C(1000000000) / e->keep_qps;
        break;
    }
}
