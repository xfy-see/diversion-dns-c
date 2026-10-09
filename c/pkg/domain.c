/* SPDX-License-Identifier: GPL-3.0-or-later */
/* 域名规则在加载时建立索引，查询时只读；调用方应在发布规则集前完成加载。
 * full 和 domain 使用哈希表，keyword 和 regexp 使用链表；domain 查询按
 * 标签边界枚举后缀，不需要逐条扫描大型域名列表。 */
#define _POSIX_C_SOURCE 200809L
#define PCRE2_CODE_UNIT_WIDTH 8
#include "mosdns.h"
#include <pcre2.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct domain_entry {
    struct domain_entry *next;
    uint64_t hash;
    char text[];
} domain_entry;
typedef struct { domain_entry **buckets; size_t count, size; } domain_table;
typedef struct domain_regex {
    struct domain_regex *next;
    pcre2_code *code;
    char text[];
} domain_regex;
struct md_domain {
    domain_table full, suffix;
    domain_entry *keywords;
    domain_regex *regexes;
    bool root;
};

static uint64_t hash_text(const char *s) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (; *s; ++s) h = (h ^ (unsigned char)*s) * UINT64_C(1099511628211);
    return h;
}
static bool table_has(const domain_table *t, const char *s) {
    if (!t->size) return false;
    uint64_t h = hash_text(s);
    for (const domain_entry *e = t->buckets[h & (t->size - 1)]; e; e = e->next)
        if (e->hash == h && !strcmp(e->text, s)) return true;
    return false;
}
/* 桶数始终为 2 的幂，因此 hash & (size - 1) 可以直接定位桶。
 * 扩容只重连已有节点；字符串及其所有权仍属于规则表。 */
static int table_grow(domain_table *t) {
    size_t size = t->size ? t->size * 2 : 64;
    if (size < t->size || size > SIZE_MAX / sizeof(*t->buckets)) return -1;
    domain_entry **b = calloc(size, sizeof(*b));
    if (!b) return -1;
    for (size_t i = 0; i < t->size; ++i) {
        domain_entry *e = t->buckets[i];
        while (e) {
            domain_entry *next = e->next;
            size_t n = e->hash & (size - 1);
            e->next = b[n]; b[n] = e; e = next;
        }
    }
    free(t->buckets); t->buckets = b; t->size = size;
    return 0;
}
/* 相同规则只保存一次；负载达到 3/4 时先扩容，避免长冲突链。 */
static int table_add(domain_table *t, const char *s) {
    if (table_has(t, s)) return 0;
    if ((!t->size || t->count >= t->size * 3 / 4) && table_grow(t)) return -1;
    domain_entry *e = malloc(sizeof(*e) + strlen(s) + 1);
    if (!e) return -1;
    e->hash = hash_text(s); strcpy(e->text, s);
    size_t i = e->hash & (t->size - 1);
    e->next = t->buckets[i]; t->buckets[i] = e; ++t->count;
    return 0;
}
static void table_free(domain_table *t) {
    for (size_t i = 0; i < t->size; ++i) {
        domain_entry *e = t->buckets[i];
        while (e) { domain_entry *next = e->next; free(e); e = next; }
    }
    free(t->buckets);
}
/* Go's full/keyword normalization removes one final dot. Its domain scanner
 * removes a second dot. ASCII folding preserves bytes outside A-Z. */
/* 只折叠 ASCII 大写字母；非 ASCII 字节原样保留，避免引入 Unicode
 * 归一化。不同规则类型移除尾点的次数用于兼容原有 Go 扫描语义。 */
static void normalize(char *s, unsigned dots) {
    size_t n = strlen(s);
    while (dots-- && n && s[n - 1] == '.') s[--n] = '\0';
    for (size_t i = 0; i < n; ++i)
        if (s[i] >= 'A' && s[i] <= 'Z') s[i] += 'a' - 'A';
}
static bool ascii_space(unsigned char c) {
    return c == ' ' || (c >= '\t' && c <= '\r');
}

md_domain *md_domain_new(void) { return calloc(1, sizeof(md_domain)); }

/* 无类型前缀的规则按 domain 后缀处理。非正则规则复制后归一化，
 * 正则表达式保留原始文本，编译失败时把 PCRE2 的偏移和原因返回给配置层。 */
int md_domain_add(md_domain *d, const char *rule, char *err) {
    if (!d || !rule) { snprintf(err, MD_ERROR_SIZE, "invalid domain rule"); return -1; }
    const char *pattern = strchr(rule, ':');
    size_t type_len = pattern ? (size_t)(pattern - rule) : 0;
    pattern = pattern ? pattern + 1 : rule;
    enum { SUFFIX, FULL, KEYWORD, REGEX } type = SUFFIX;
    if (type_len) {
        if (type_len == 6 && !memcmp(rule, "domain", 6)) type = SUFFIX;
        else if (type_len == 4 && !memcmp(rule, "full", 4)) type = FULL;
        else if (type_len == 7 && !memcmp(rule, "keyword", 7)) type = KEYWORD;
        else if (type_len == 6 && !memcmp(rule, "regexp", 6)) type = REGEX;
        else { snprintf(err, MD_ERROR_SIZE, "unsupported domain matcher: %.*s", (int)type_len, rule); return -1; }
    }
    if (type == REGEX) {
        for (domain_regex *r = d->regexes; r; r = r->next)
            if (!strcmp(r->text, pattern)) return 0;
        /* 使用 PCRE2 的 8 位字节接口，不启用 UTF/UCP；当前构建也关闭
         * Unicode 支持。普通域名仍可使用分组、回溯引用、前后查找等语法。 */
        int code; PCRE2_SIZE offset;
        pcre2_code *compiled = pcre2_compile((PCRE2_SPTR)pattern, PCRE2_ZERO_TERMINATED,
                                            0, &code, &offset, NULL);
        if (!compiled) {
            PCRE2_UCHAR msg[160];
            pcre2_get_error_message(code, msg, sizeof(msg));
            snprintf(err, MD_ERROR_SIZE, "invalid PCRE2 regexp at %zu: %s", (size_t)offset, (char *)msg);
            return -1;
        }
        domain_regex *r = malloc(sizeof(*r) + strlen(pattern) + 1);
        if (!r) { pcre2_code_free(compiled); goto oom; }
        r->code = compiled; strcpy(r->text, pattern); r->next = d->regexes; d->regexes = r;
        return 0;
    }
    char *s = strdup(pattern);
    if (!s) goto oom;
    normalize(s, type == SUFFIX ? 2 : 1);
    int rc = 0;
    if (type == SUFFIX) {
        /* ReverseDomainScanner ignores an empty leading label. */
        if (!s[0]) d->root = true;
        else {
            if (s[0] == '.') memmove(s, s + 1, strlen(s));
            rc = table_add(&d->suffix, s);
        }
    } else if (type == FULL) rc = table_add(&d->full, s);
    else {
        for (domain_entry *e = d->keywords; e; e = e->next)
            if (!strcmp(e->text, s)) { free(s); return 0; }
        domain_entry *e = malloc(sizeof(*e) + strlen(s) + 1);
        if (!e) rc = -1;
        else { strcpy(e->text, s); e->next = d->keywords; d->keywords = e; }
    }
    free(s);
    if (!rc) return 0;
oom:
    snprintf(err, MD_ERROR_SIZE, "out of memory loading domain rules"); return -1;
}

/* 文件按行读取，# 后视为注释；空白行跳过，规则内部不允许 ASCII 空白。
 * 失败保留已加入的规则，调用方负责销毁未成功加载的整个规则集。 */
int md_domain_load(md_domain *d, const char *path, char *err) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, MD_ERROR_SIZE, "open domain file %s: %s", path, strerror(errno)); return -1; }
    char *line = NULL; size_t cap = 0, number = 0; ssize_t len; int rc = 0;
    while ((len = getline(&line, &cap, f)) >= 0) {
        ++number;
        if (len > 65535) { snprintf(err, MD_ERROR_SIZE, "%s line %zu: rule exceeds 65535 bytes", path, number); rc = -1; break; }
        char *comment = strchr(line, '#'); if (comment) *comment = '\0';
        char *start = line; while (ascii_space((unsigned char)*start)) ++start;
        size_t n = strlen(start); while (n && ascii_space((unsigned char)start[n - 1])) start[--n] = '\0';
        if (!n) continue;
        bool spaces = false;
        for (size_t i = 0; i < n; ++i) spaces |= ascii_space((unsigned char)start[i]);
        char detail[MD_ERROR_SIZE] = {0};
        if (spaces || md_domain_add(d, start, detail)) {
            snprintf(err, MD_ERROR_SIZE, "%s line %zu: %.300s", path, number,
                     spaces ? "rule string has more than one section" : detail);
            rc = -1; break;
        }
    }
    if (!rc && ferror(f)) { snprintf(err, MD_ERROR_SIZE, "read domain file %s: %s", path, strerror(errno)); rc = -1; }
    free(line); fclose(f); return rc;
}

/* 常见 DNS 名称使用栈上副本；每次匹配的 PCRE2 上下文独立分配，
 * 因此已冻结的规则集可供多个工作线程读取。名称副本分配失败时未命中，
 * 正则执行失败时继续尝试其他规则；共享规则和调用方名称均不被修改。 */
bool md_domain_match(const md_domain *d, const char *name) {
    if (!d || !name) return false;
    char local[256], *s = local; size_t n = strlen(name);
    if (n >= sizeof(local)) { s = malloc(n + 1); if (!s) return false; }
    memcpy(s, name, n + 1); normalize(s, 1);
    bool result = table_has(&d->full, s);
    if (!result) {
        for (domain_entry *k = d->keywords; k; k = k->next)
            if (strstr(s, k->text)) { result = true; break; }
    }
    if (!result && d->regexes) {
        pcre2_match_data *data = pcre2_match_data_create(1, NULL);
        pcre2_match_context *ctx = pcre2_match_context_create(NULL);
        if (data && ctx) {
            /* Bound backtracking for user-provided PCRE2 expressions. */
            pcre2_set_match_limit(ctx, 100000);
            pcre2_set_depth_limit(ctx, 1000);
            /* 本模块只需要是否命中；返回 0 也代表匹配成功，只是捕获
             * 槽位不足，不能把它误判成未命中。 */
            for (domain_regex *r = d->regexes; r; r = r->next)
                if (pcre2_match(r->code, (PCRE2_SPTR)s, strlen(s), 0, 0, data, ctx) >= 0) { result = true; break; }
        }
        pcre2_match_data_free(data); pcre2_match_context_free(ctx);
    }
    if (!result) {
        normalize(s, 1);
        result = d->root;
        /* 从最右标签向左扩展；每个查表字符串都始于标签边界，
         * domain:example.com 会命中子域名，但不会命中 badexample.com。 */
        size_t end = strlen(s);
        while (!result && end) {
            size_t start = end;
            while (start && s[start - 1] != '.') --start;
            result = table_has(&d->suffix, s + start);
            if (!start) break;
            end = start - 1;
        }
    }
    if (s != local) free(s);
    return result;
}
/* 同时释放索引节点、规则字符串和 PCRE2 编译对象；销毁前须停止查询。 */
void md_domain_free(md_domain *d) {
    if (!d) return;
    table_free(&d->full); table_free(&d->suffix);
    domain_entry *k = d->keywords;
    while (k) { domain_entry *next = k->next; free(k); k = next; }
    domain_regex *r = d->regexes;
    while (r) { domain_regex *next = r->next; pcre2_code_free(r->code); free(r); r = next; }
    free(d);
}
