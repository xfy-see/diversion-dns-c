/* SPDX-License-Identifier: GPL-3.0-or-later */
/* PCRE2-only evidence for intentional operational, not grammar, differences.
 * The public bool API cannot distinguish exhausted execution budgets from an
 * ordinary no-match. Verify the underlying error directly at identical limits. */
static void regex_budget_tests(void) {
    const char *patterns[] = {"^(a|aa)+a{64}$", "^(a+)+a{64}$"};
    char subject[66]; memset(subject, 'a', 65); subject[65] = '\0';
    for (size_t i = 0; i < sizeof(patterns) / sizeof(patterns[0]); ++i) {
        int error; PCRE2_SIZE offset;
        pcre2_code *code = pcre2_compile((PCRE2_SPTR)patterns[i], PCRE2_ZERO_TERMINATED,
                                         0, &error, &offset, NULL);
        assert(code);
        pcre2_match_data *data = pcre2_match_data_create(1, NULL); assert(data);
        pcre2_match_context *context = pcre2_match_context_create(NULL); assert(context);
        assert(!pcre2_set_match_limit(context, 100000));
        assert(!pcre2_set_depth_limit(context, 1000));
        int rc = pcre2_match(code, (PCRE2_SPTR)subject, 65, 0, 0, data, context);
        assert(rc == PCRE2_ERROR_MATCHLIMIT);
        char rule[128], err[MD_ERROR_SIZE];
        assert(snprintf(rule, sizeof(rule), "regexp:%s", patterns[i]) > 0);
        md_domain *d = md_domain_new(); assert(d);
        assert(!md_domain_add(d, rule, err));
        assert(!md_domain_match(d, subject)); /* Existing bool API maps the error to false. */
        md_domain_free(d);
        pcre2_match_context_free(context); pcre2_match_data_free(data); pcre2_code_free(code);
    }
    printf("PCRE2 operational budget: 2 direct MATCHLIMIT(%d) errors verified; bool API returns false\n",
           PCRE2_ERROR_MATCHLIMIT);
}
