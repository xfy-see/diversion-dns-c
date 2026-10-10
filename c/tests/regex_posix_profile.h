/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Test-only POSIX-lite contract, included by cache_domain_test.c. PCRE2 keeps
 * its original profile tests; every narrowing here is deliberate and named. */
static void posix_reject_rule(const char *rule) {
    char err[MD_ERROR_SIZE], path[] = "/tmp/mosdns-c-posix-XXXXXX";
    md_domain *d = md_domain_new(); assert(d);
    assert(md_domain_add(d, rule, err));
    assert(strstr(err, "invalid POSIX-lite regexp at "));
    int fd = mkstemp(path); assert(fd >= 0);
    FILE *f = fdopen(fd, "w"); assert(f);
    assert(fprintf(f, "# profile rejection\nfull:before.test\n\n%s\nfull:after.test\n", rule) > 0);
    assert(!fclose(f));
    assert(md_domain_load(d, path, err));
    assert(strstr(err, path) && strstr(err, "line 4:") && strstr(err, "invalid POSIX-lite regexp at "));
    assert(md_domain_match(d, "before.test"));
    assert(!md_domain_match(d, "after.test")); /* No skipping rejected lines. */
    assert(!unlink(path)); md_domain_free(d);
}

static void regex_profile_tests(void) {
    const char *unsupported[] = {
        /* The PCRE2 feature profile still rejects Unicode directives. */
        "regexp:(*UTF)^example\\.test$", "regexp:(*UCP)^example\\.test$",
        "regexp:^\\p{L}+\\.test$", "regexp:^\\P{L}+\\.test$", "regexp:^\\X\\.test$",
        /* No extended groups, backreferences, assertions, quoting or escapes. */
        "regexp:(?:a)", "regexp:(?=a)a", "regexp:(?!a)b", "regexp:(?<=a)b",
        "regexp:(?<!a)b", "regexp:(?i)a", "regexp:(?<word>a)", "regexp:(?>a)",
        "regexp:(a)\\1", "regexp:\\141", "regexp:\\0", "regexp:\\x61",
        "regexp:\\Qliteral[a]\\E", "regexp:\\bword\\b", "regexp:\\Bword",
        "regexp:\\D", "regexp:\\W", "regexp:\\s", "regexp:\\a", "regexp:\\-", "regexp:a\\",
        /* Greedy quantifiers only, with finite bounded-repeat upper limits. */
        "regexp:a+?", "regexp:a*?", "regexp:a??", "regexp:a{1,2}?",
        "regexp:a++", "regexp:a*+", "regexp:a?+", "regexp:a{1,2}+", "regexp:a**",
        "regexp:a{1,}", "regexp:a{,2}", "regexp:a{2,1}", "regexp:a{65}",
        "regexp:a{0,65}", "regexp:a{99999999999999999999999999}", "regexp:a{1",
        "regexp:*a", "regexp:+a", "regexp:?a", "regexp:{2}a",
        /* musl has known zero-upper-bound repeat drift; reject even nested
         * zero repetitions while retaining {0,n} for positive n. */
        "regexp:^a{0}$", "regexp:^a{0,0}b$", "regexp:^((a){0}){2}$",
        "regexp:^[a-c]*.{0,2}[ab]{0,2}$|\\[{0}",
        /* No empty alternatives/groups, misplaced anchors or anchor repeats. */
        "regexp:", "regexp:()", "regexp:(a|)", "regexp:(|a)", "regexp:a||b",
        "regexp:|a", "regexp:a|", "regexp:(a", "regexp:a)", "regexp:a^b",
        "regexp:a$b", "regexp:^*a", "regexp:a$?",
        /* Quantified anchor-bearing groups have libc-dependent semantics.
         * Reject every quantifier, including recursively nested anchors. */
        "regexp:^(a$){2}$", "regexp:(^a){2}", "regexp:^(a$){1}$",
        "regexp:(^a)?", "regexp:(^a)*", "regexp:(^a)+", "regexp:(^a){0}",
        "regexp:(a$){0,2}", "regexp:((^a)){2}", "regexp:^((a$)){2}$",
        "regexp:((^a)|b)+", "regexp:(a|(^b))*", "regexp:(((a$)|b))?",
        /* Brackets use only portable ASCII literal sets and simple ranges. */
        "regexp:[\\d]", "regexp:[\\w]", "regexp:[\\.]", "regexp:[[:alpha:]]",
        "regexp:[[.a.]]", "regexp:[[=a=]]", "regexp:[[]", "regexp:[]a]",
        "regexp:[a^]", "regexp:[A-z]", "regexp:[z-a]", "regexp:[0-a]",
        "regexp:[]", "regexp:[^]", "regexp:[", "regexp:[abc",
        "regexp:\xc3\xa9", "regexp:a\x7f",
        /* Expanded cost exceeds 2048 despite a short source expression. */
        "regexp:^(a{64}){16}$", "regexp:^(a{64}){15}a{47}a$"
    };
    for (size_t i = 0; i < sizeof(unsupported) / sizeof(unsupported[0]); ++i)
        posix_reject_rule(unsupported[i]);

    const struct { const char *rule, *yes, *no; } accepted[] = {
        {"regexp:^asset-\\d+\\.\\w+$", "ASSET-123.A_B.", "asset-a.test"},
        {"regexp:^(ab|c)+d?e*\\.test$", "ABCABDEEE.TEST.", "abdq.test"},
        {"regexp:^a{2}b{1,3}c?\\.test$", "aabbbc.test", "ab.test"},
        {"regexp:^[a-c0-2_-]+\\.test$", "CAB_02-.TEST.", "d.test"},
        {"regexp:^[-ab]+\\.test$", "-ba-.test", "c.test"},
        {"regexp:^[^a-c]+\\.test$", "xyz-9.test", "a.test"},
        {"regexp:^a\\.\\+\\?\\(\\)\\[\\]\\{\\}\\|\\^\\$\\\\z$", "a.+?()[]{}|^$\\z", "a.z"},
        {"regexp:needle", "before.needle.after", "needl.after"},
        {"regexp:^a$|^b$", "B.", "ab"},
        {"regexp:^a{0,64}$", "a", "b"},
        {"regexp:^((a))$", "A.", "b"},
        {"regexp:(^a)|(^b$)", "A.", "ba"},
        {"regexp:((^a))b$", "AB.", "bab"},
        {"regexp:^a((b$))", "AB.", "abc"},
        {"regexp:^(\\^a){2}$", "^a^a", "aa"},
        {"regexp:^(a\\$){2}$", "a$a$", "aa"},
        {"regexp:^([a$]){2}$", "a$", "ab"}
    };
    char err[MD_ERROR_SIZE];
    const char *global = setlocale(LC_ALL, NULL); assert(global);
    char *global_before = strdup(global); assert(global_before);
    locale_t locale = newlocale(LC_ALL_MASK, "C", (locale_t)0); assert(locale);
    locale_t previous = uselocale(locale); assert(previous);
    for (size_t i = 0; i < sizeof(accepted) / sizeof(accepted[0]); ++i) {
        md_domain *d = md_domain_new(); assert(d);
        assert(!md_domain_add(d, accepted[i].rule, err));
        assert(uselocale((locale_t)0) == locale);
        assert(md_domain_match(d, accepted[i].yes));
        assert(!md_domain_match(d, accepted[i].no));
        assert(uselocale((locale_t)0) == locale);
        md_domain_free(d);
    }
    assert(uselocale(previous) == locale); freelocale(locale);
    assert(!strcmp(global_before, setlocale(LC_ALL, NULL))); free(global_before);

    /* Exact source, nesting, repetition and distinct-rule count boundaries. */
    char rule[7 + 514]; memcpy(rule, "regexp:", 7);
    memset(rule + 7, 'a', 512); rule[7 + 512] = '\0';
    md_domain *d = md_domain_new(); assert(d);
    assert(!md_domain_add(d, rule, err)); md_domain_free(d);
    rule[7 + 512] = 'a'; rule[7 + 513] = '\0'; posix_reject_rule(rule);
    for (unsigned depth = 16; depth <= 17; ++depth) {
        char nested[64]; size_t n = 0; memcpy(nested, "regexp:", 7); n = 7;
        for (unsigned i = 0; i < depth; ++i) nested[n++] = '(';
        nested[n++] = 'a';
        for (unsigned i = 0; i < depth; ++i) nested[n++] = ')';
        nested[n] = '\0';
        if (depth == 17) posix_reject_rule(nested);
        else { d = md_domain_new(); assert(d); assert(!md_domain_add(d, nested, err));
               assert(md_domain_match(d, "a")); md_domain_free(d); }
    }
    d = md_domain_new(); assert(d);
    assert(!md_domain_add(d, "regexp:^(a{64}){15}$", err));
    /* ((1+1)*64+1+1)*15+1 + (1+1)*47+1 + two anchors = 2048. */
    assert(!md_domain_add(d, "regexp:^(a{64}){15}a{47}$", err)); md_domain_free(d);
    d = md_domain_new(); assert(d);
    for (unsigned i = 0; i < 128; ++i) {
        snprintf(rule, sizeof(rule), "regexp:^rule-%u$", i);
        assert(!md_domain_add(d, rule, err));
    }
    assert(!md_domain_add(d, "regexp:^rule-127$", err)); /* Duplicates cost no slot. */
    assert(md_domain_add(d, "regexp:^overflow$", err));
    assert(strstr(err, "invalid POSIX-lite regexp at "));
    assert(md_domain_match(d, "rule-0") && md_domain_match(d, "rule-127"));
    assert(!md_domain_match(d, "overflow"));
    char count_path[] = "/tmp/mosdns-c-count-XXXXXX";
    int count_fd = mkstemp(count_path); assert(count_fd >= 0);
    FILE *count_file = fdopen(count_fd, "w"); assert(count_file);
    assert(fputs("# count limit\nfull:before.test\n\nregexp:^overflow$\nfull:after.test\n", count_file) >= 0);
    assert(!fclose(count_file)); assert(md_domain_load(d, count_path, err));
    assert(strstr(err, count_path) && strstr(err, "line 4:") && strstr(err, "invalid POSIX-lite regexp at "));
    assert(md_domain_match(d, "before.test") && !md_domain_match(d, "after.test"));
    assert(!unlink(count_path)); md_domain_free(d);

    /* A regex sees printable ASCII only and <=253 bytes after ONE tail dot. */
    d = md_domain_new(); assert(d); assert(!md_domain_add(d, "regexp:^.*$", err));
    assert(md_domain_match(d, "")); assert(md_domain_match(d, "ASCII space ~"));
    assert(!md_domain_match(d, "\xc3\xa9.bytes"));
    assert(!md_domain_match(d, "asset-\xd9\xa1.test"));
    assert(!md_domain_match(d, "tab\t.test")); assert(!md_domain_match(d, "del\x7f.test"));
    assert(!md_domain_match(d, "ctrl\x01.test"));
    char name[303]; memset(name, 'a', 253); name[253] = '\0';
    assert(md_domain_match(d, name)); name[253] = '.'; name[254] = '\0';
    assert(md_domain_match(d, name)); name[254] = '.'; name[255] = '\0';
    assert(!md_domain_match(d, name)); name[253] = 'a'; name[254] = '\0';
    assert(!md_domain_match(d, name)); md_domain_free(d);

    /* Regex input limits must not leak into full, keyword or suffix matching. */
    d = md_domain_new(); assert(d); assert(!md_domain_add(d, "regexp:^nomatch$", err));
    assert(!md_domain_add(d, "full:\xc3\xa9.bytes", err));
    assert(md_domain_match(d, "\xc3\xa9.bytes"));
    assert(!md_domain_add(d, "keyword:marker", err)); assert(md_domain_match(d, "\x80marker"));
    assert(!md_domain_add(d, "domain:suffix", err)); assert(md_domain_match(d, "\xff.suffix"));
    memset(name, 'a', 300); name[300] = '\0';
    char long_rule[306]; assert(snprintf(long_rule, sizeof(long_rule), "full:%s", name) == 305);
    assert(!md_domain_add(d, long_rule, err)); assert(md_domain_match(d, name));
    md_domain_free(d);
    printf("POSIX-lite profile: %zu explicit syntax/complexity rejections; grammar, limits, ASCII and locale checks passed\n",
           sizeof(unsupported) / sizeof(unsupported[0]));
}
