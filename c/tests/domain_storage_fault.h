/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Compile a private copy with allocator injection: no production hook or flag. */
static int storage_budget = -1;
static unsigned storage_allocations;
static bool storage_allow(void) {
    if (!storage_budget) return false;
    if (storage_budget > 0) --storage_budget;
    ++storage_allocations; return true;
}
static void *storage_malloc(size_t n) { return storage_allow() ? malloc(n) : NULL; }
static void *storage_calloc(size_t n, size_t s) { return storage_allow() ? calloc(n, s) : NULL; }
typedef struct storage_domain storage_domain;
#define md_domain storage_domain
#define md_domain_new storage_new
#define md_domain_add storage_add
#define md_domain_load storage_load
#define md_domain_match storage_match
#define md_domain_free storage_free
#define malloc storage_malloc
#define calloc storage_calloc
#include "../pkg/domain.c"
#undef calloc
#undef malloc
#undef md_domain_free
#undef md_domain_match
#undef md_domain_load
#undef md_domain_add
#undef md_domain_new
#undef md_domain
static void domain_storage_fault_tests(void) {
    char err[MD_ERROR_SIZE], rule[96], name[96];
    unsigned failures = 0;
    for (int budget = 0; budget < 32; ++budget) {
        storage_budget = budget;
        storage_domain *d = storage_new();
        if (!d) { ++failures; continue; }
        unsigned i;
        for (i = 0; i < 2000; ++i) {
            snprintf(rule, sizeof(rule), "domain:f%u.failure.test", i);
            if (storage_add(d, rule, err)) { ++failures; break; }
        }
        /* Every successfully added rule survives a failed resize/block allocation. */
        for (unsigned j = 0; j < i; ++j) {
            snprintf(name, sizeof(name), "child.f%u.failure.test", j);
            assert(storage_match(d, name));
        }
        storage_budget = -1;
        assert(!storage_add(d, "domain:recovered.test", err));
        assert(storage_match(d, "recovered.test"));
        assert(!entry_alloc(d, SIZE_MAX));
        storage_free(d);
    }
    assert(failures > 10);
    storage_budget = -1; storage_allocations = 0;
    storage_domain *d = storage_new(); assert(d);
    assert(!storage_add(d, "domain:duplicate.test", err));
    unsigned before = storage_allocations;
    for (unsigned i = 0; i < 1000; ++i) assert(!storage_add(d, "domain:duplicate.test", err));
    assert(storage_allocations == before);
    storage_free(d);
}
