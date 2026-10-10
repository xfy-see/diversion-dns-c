/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Private validator/normalizer for the experimental POSIX-lite backend.
 * Never pass unchecked PCRE syntax to regcomp: undefined ERE escapes can be
 * silently reinterpreted by libc. See REGEX-POSIX-LITE.md for the grammar. */
#define LITE_PATTERN_MAX 512u
#define LITE_OUTPUT_MAX (LITE_PATTERN_MAX * 16u)
#define LITE_DEPTH_MAX 16u
#define LITE_REPEAT_MAX 64u
#define LITE_COST_MAX 2048u
#define LITE_RULE_MAX 128u
#define LITE_SUBJECT_MAX 253u

typedef struct {
    const char *input;
    size_t pos, used;
    char output[LITE_OUTPUT_MAX + 1];
    char *err;
} lite_parser;

static int lite_error(lite_parser *p, const char *reason) {
    snprintf(p->err, MD_ERROR_SIZE, "invalid POSIX-lite regexp at %zu: %s", p->pos, reason);
    return -1;
}
static int lite_emit(lite_parser *p, const char *s, size_t n) {
    if (n > LITE_OUTPUT_MAX - p->used) return lite_error(p, "normalized pattern too large");
    memcpy(p->output + p->used, s, n); p->used += n;
    p->output[p->used] = '\0'; return 0;
}
static int lite_char(lite_parser *p, char c) { return lite_emit(p, &c, 1); }
static int lite_literal(lite_parser *p, char c) {
    /* Brackets avoid undefined ERE escapes such as \}. Backslash and caret
     * have defined escaped ERE forms; ] has a special first-member form. */
    if (c == '\\') return lite_emit(p, "\\\\", 2);
    if (c == '^') return lite_emit(p, "\\^", 2);
    if (c == ']') return lite_emit(p, "[]]", 3);
    char b[] = {'[', c, ']'}; return lite_emit(p, b, sizeof(b));
}
static bool lite_digit(char c) { return c >= '0' && c <= '9'; }
static int lite_category(char c) {
    if (lite_digit(c)) return 1;
    if (c >= 'a' && c <= 'z') return 2;
    if (c >= 'A' && c <= 'Z') return 3;
    return 0;
}
static bool lite_member(char c) {
    return c >= '!' && c <= '~' && c != '[' && c != ']' && c != '\\' && c != '^' && c != '-';
}
static int lite_class(lite_parser *p) {
    if (lite_char(p, p->input[p->pos++])) return -1; /* [ */
    if (p->input[p->pos] == '^' && lite_char(p, p->input[p->pos++])) return -1;
    unsigned members = 0;
    while (p->input[p->pos] && p->input[p->pos] != ']') {
        char c = p->input[p->pos];
        if (c == '-' && (!members || p->input[p->pos + 1] == ']')) {
            if (lite_char(p, c)) return -1;
            ++p->pos; ++members; continue;
        }
        if (!lite_member(c)) return lite_error(p, "unsupported or ambiguous bracket member");
        if (p->input[p->pos + 1] == '-' && p->input[p->pos + 2] && p->input[p->pos + 2] != ']') {
            char end = p->input[p->pos + 2];
            if (!lite_category(c) || lite_category(c) != lite_category(end) || c > end)
                return lite_error(p, "ranges must be ordered within A-Z, a-z, or 0-9");
            if (lite_emit(p, p->input + p->pos, 3)) return -1;
            p->pos += 3;
        } else {
            if (lite_char(p, c)) return -1;
            ++p->pos;
        }
        ++members;
    }
    if (!members || p->input[p->pos] != ']') return lite_error(p, "empty or unclosed bracket expression");
    return lite_char(p, p->input[p->pos++]);
}
static int lite_expression(lite_parser *p, unsigned depth, unsigned *cost, bool *has_anchor);
static int lite_number(lite_parser *p, unsigned *n) {
    if (!lite_digit(p->input[p->pos])) return lite_error(p, "expected repetition count");
    *n = 0;
    do {
        *n = *n * 10u + (unsigned)(p->input[p->pos++] - '0');
        if (*n > LITE_REPEAT_MAX) return lite_error(p, "repetition exceeds 64");
    } while (lite_digit(p->input[p->pos]));
    return 0;
}
static int lite_piece(lite_parser *p, unsigned depth, unsigned *cost, bool first, bool *has_anchor) {
    char c = p->input[p->pos];
    *has_anchor = false;
    *cost = 1;
    if (c == '(') {
        if (depth >= LITE_DEPTH_MAX) return lite_error(p, "group nesting exceeds 16");
        if (lite_char(p, p->input[p->pos++]) || lite_expression(p, depth + 1, cost, has_anchor)) return -1;
        if (p->input[p->pos] != ')') return lite_error(p, "unclosed group");
        if (lite_char(p, p->input[p->pos++])) return -1;
    } else if (c == '[') {
        if (lite_class(p)) return -1;
    } else if (c == '\\') {
        ++p->pos; c = p->input[p->pos];
        if (c == 'd') { if (lite_emit(p, "[0-9]", 5)) return -1; }
        else if (c == 'w') { if (lite_emit(p, "[A-Za-z0-9_]", 12)) return -1; }
        else if (c && strchr("\\.^$|?*+(){}[]", c)) { if (lite_literal(p, c)) return -1; }
        else return lite_error(p, "unsupported escape (only d, w, or escaped ERE metacharacters)");
        ++p->pos;
    } else if (c == '^' || c == '$') {
        if (c == '^' && !first) return lite_error(p, "^ must begin an alternative");
        char next = p->input[p->pos + 1];
        if (c == '$' && next && next != '|' && next != ')') return lite_error(p, "$ must end an alternative");
        *has_anchor = true;
        if (lite_char(p, p->input[p->pos++])) return -1;
    } else {
        if (c < '!' || c > '~' || strchr("?*+{}]", c)) return lite_error(p, "unsupported or misplaced token");
        if (lite_char(p, p->input[p->pos++])) return -1;
    }
    c = p->input[p->pos];
    if (c && strchr("?*+{", c)) {
        if (*has_anchor) return lite_error(p, "anchors or groups containing anchors cannot be repeated");
        if (c == '{') {
            size_t start = p->pos++; unsigned min, max;
            if (lite_number(p, &min)) return -1;
            max = min;
            if (p->input[p->pos] == ',') { ++p->pos; if (lite_number(p, &max)) return -1; }
            if (p->input[p->pos] != '}' || max < min) return lite_error(p, "expected {m} or {m,n}, m <= n <= 64");
            if (!max) return lite_error(p, "zero-upper-bound repetition is unsupported");
            ++p->pos;
            if (lite_emit(p, p->input + start, p->pos - start)) return -1;
            *cost = (*cost + 1u) * max + 1u;
        } else {
            if (lite_char(p, p->input[p->pos++])) return -1;
            ++*cost;
        }
        if (p->input[p->pos] && strchr("?*+{", p->input[p->pos])) return lite_error(p, "stacked, lazy, or possessive repetition is unsupported");
    }
    if (*cost > LITE_COST_MAX) return lite_error(p, "expanded complexity exceeds 2048");
    return 0;
}
static int lite_expression(lite_parser *p, unsigned depth, unsigned *cost, bool *has_anchor) {
    *cost = 0; *has_anchor = false;
    for (;;) {
        unsigned count = 0;
        while (p->input[p->pos] && p->input[p->pos] != ')' && p->input[p->pos] != '|') {
            unsigned piece; bool piece_anchor;
            if (lite_piece(p, depth, &piece, !count, &piece_anchor)) return -1;
            *has_anchor |= piece_anchor;
            *cost += piece; ++count;
            if (*cost > LITE_COST_MAX) return lite_error(p, "expanded complexity exceeds 2048");
        }
        if (!count) return lite_error(p, "empty patterns, groups, or alternatives are unsupported");
        if (p->input[p->pos] != '|') return 0;
        if (lite_char(p, p->input[p->pos++])) return -1;
        if (++*cost > LITE_COST_MAX) return lite_error(p, "expanded complexity exceeds 2048");
    }
}
static int lite_normalize(lite_parser *p, const char *pattern, char *err) {
    p->input = pattern; p->pos = p->used = 0; p->err = err;
    if (strnlen(pattern, LITE_PATTERN_MAX + 1) > LITE_PATTERN_MAX)
        return lite_error(p, "pattern exceeds 512 bytes");
    unsigned cost; bool has_anchor;
    if (lite_expression(p, 0, &cost, &has_anchor)) return -1;
    if (p->input[p->pos]) return lite_error(p, "unexpected closing group");
    return 0;
}
static bool lite_subject(const char *s) {
    size_t n = 0;
    for (; s[n]; ++n)
        if (n >= LITE_SUBJECT_MAX || (unsigned char)s[n] < 32 || (unsigned char)s[n] > 126) return false;
    return true;
}
