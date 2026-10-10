/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Exercise shared immutable compiled objects with independent per-call state. */
typedef struct {
    const md_domain *domain;
    locale_t locale;
    unsigned index;
} regex_thread_test;

static void *regex_match_thread(void *arg) {
    regex_thread_test *v = arg;
    locale_t previous = uselocale(v->locale); assert(previous);
    const struct { const char *name; bool matches; } cases[] = {
        {"R1.SN-2X3ABCDE.GOOGLEVIDEO.COM.", true},
        {"rr123---sn-ni5a0b1c.googlevideo.com", true},
        {"r1--sn-2x3abcde.googlevideo.com", false},
        {"r1---sn-xxxabcde.googlevideo.com", false},
        {"r1.sn-2x3abcde.googlevideo.com.evil", false},
        {"CDN2-EPICGAMES-9.FILE.MYQCLOUD.COM.", true},
        {"cdn1-epicgames-.file.myqcloud.com", false},
        {"A.B.ZH.OKAAPPS.COM.", true}, {"prefixzh.okaapps.com", false},
        {"XYZZZ.TEST.", true}, {"xz.test", false},
        {"www.static.test", true}, {"badstatic.test", false},
        {"exact.test", true}, {"sub.exact.test", false},
        {"contains-needle.test", true}, {"unmatched.invalid", false},
        {"\xc3\xa9.invalid", false}
    };
    for (unsigned round = 0; round < 300; ++round) {
        for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
            size_t at = (i + v->index + round) % (sizeof(cases) / sizeof(cases[0]));
            char name[256]; assert(strlen(cases[at].name) < sizeof(name));
            strcpy(name, cases[at].name);
            assert(md_domain_match(v->domain, name) == cases[at].matches);
            assert(!strcmp(name, cases[at].name));
            assert(uselocale((locale_t)0) == v->locale);
        }
    }
    assert(uselocale(previous) == v->locale); return NULL;
}

static void regex_concurrency_tests(void) {
    char err[MD_ERROR_SIZE]; md_domain *d = md_domain_new(); assert(d);
    const char *rules[] = {
        "regexp:^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.googlevideo\\.com$",
        "regexp:^cdn\\d-epicgames-\\d+\\.file\\.myqcloud\\.com$",
        "regexp:^(.+\\.)*zh\\.okaapps\\.com$", "regexp:^(x|y)+z{2,3}\\.test$",
        "domain:static.test", "full:exact.test", "keyword:needle"
    };
    const char *global = setlocale(LC_ALL, NULL); assert(global);
    char *global_before = strdup(global); assert(global_before);
    for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); ++i)
        assert(!md_domain_add(d, rules[i], err));
    /* No mutation after publishing d; only free it after every reader joins. */
    pthread_t threads[8]; regex_thread_test args[8]; unsigned utf8 = 0;
    for (unsigned i = 0; i < 8; ++i) {
        locale_t locale = (locale_t)0;
        if (i & 1) {
            locale = newlocale(LC_ALL_MASK, "C.UTF-8", (locale_t)0);
            if (!locale) locale = newlocale(LC_ALL_MASK, "en_US.UTF-8", (locale_t)0);
            utf8 += locale != (locale_t)0;
        }
        if (!locale) locale = newlocale(LC_ALL_MASK, "C", (locale_t)0);
        assert(locale); args[i] = (regex_thread_test){d, locale, i};
        assert(!pthread_create(&threads[i], NULL, regex_match_thread, &args[i]));
    }
    for (unsigned i = 0; i < 8; ++i) {
        assert(!pthread_join(threads[i], NULL)); freelocale(args[i].locale);
    }
    assert(!strcmp(global_before, setlocale(LC_ALL, NULL))); free(global_before);
    md_domain_free(d);
    printf("shared frozen domain regex: 8 threads / 43200 matches passed (%u UTF-8 thread locales available)\n", utf8);
}
