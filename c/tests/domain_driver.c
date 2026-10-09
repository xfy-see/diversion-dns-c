/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "mosdns.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Small test-only bridge for the existing Go/Rust JSON fixture. */
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    md_domain *d = md_domain_new();
    if (!d) return 2;
    char err[MD_ERROR_SIZE];
    if (md_domain_load(d, argv[1], err)) printf("error:%s\n", err);
    else puts("ok");
    char *line = NULL; size_t cap = 0; ssize_t n;
    while ((n = getline(&line, &cap, stdin)) >= 0) {
        while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = '\0';
        puts(md_domain_match(d, line) ? "1" : "0");
    }
    free(line); md_domain_free(d); return 0;
}
