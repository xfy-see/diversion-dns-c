#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Compare PCRE2 and POSIX-lite drivers on a deterministic, bounded corpus.

Example: python3 c/tests/regex_differential.py --pcre2 /path/to/pcre2/domain_driver \
    --posix-lite /path/to/posix/domain_driver --output result.json
This is correctness evidence, not a performance benchmark.
"""
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import random
import subprocess
import tempfile


def run(driver, rule, subjects):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as source:
        source.write("# differential corpus\n" + rule + "\n")
        source.flush()
        result = subprocess.run([str(driver), source.name],
                                input="".join(subject + "\n" for subject in subjects),
                                text=True, capture_output=True, check=True, timeout=30)
    lines = result.stdout.splitlines()
    assert len(lines) == len(subjects) + 1, (driver, rule, result)
    if lines[0].startswith("error:"):
        assert source.name in lines[0] and "line 2:" in lines[0], (rule, lines[0])
    assert all(item in ("0", "1") for item in lines[1:]), (rule, lines)
    return lines[0], lines[1:]


# The exact eight production rules and all 72 original CN-list assertions are
# reused from the C test, with no second hand-maintained copy of their strings.
def production_cases():
    import re
    source = Path(__file__).with_name("cache_domain_test.c").read_text()
    start = source.index("static void direct_list_regex_tests(void)")
    stop = source.index("assert(sizeof(cases)", start)
    section = source[start:stop]
    # These source literals contain only JSON-compatible C string escapes.
    literals = [json.loads(item) for item in re.findall(r'"(?:\\.|[^"\\])*"', section)]
    assert len(literals) == 8 * 9, len(literals)
    result = []
    for i in range(0, len(literals), 9):
        rule, *names = literals[i:i + 9]
        assert rule.startswith("regexp:")
        result.append((rule, [(name, "1") for name in names[:4]] +
                            [(name, "0") for name in names[4:]] +
                            [(names[0] + ".evil", "0")]))
    return result


def portable_corpus():
    """Fixed seed, known-valid grammar, normalized printable ASCII subjects."""
    rng = random.Random(20261010)
    subjects = ["", ".", "A.", "AB12._-", "a" * 64, "b" * 64,
                "a" * 253, "a" * 253 + ".", "before.needle.after", "~", r"a.+?()[]{}|^$\z", "^a^a", "a$a$", "a$"]
    subjects += ["".join(chars) for length in range(1, 4)
                 for chars in itertools.product("ab12.-_", repeat=length)]
    subjects += ["".join(rng.choice("ab12.-_") for _ in range(rng.randrange(1, 40)))
                 for _ in range(150)]
    atoms = ["a", "b", "1", "2", ".", r"\.", r"\d", r"\w", "[ab]", "[0-2]",
             "[^ab]", "[-ab]", "[ab-]", "[a-c0-2_]", "(a|b)", "(ab|1)", "[A-Z]"]
    metacharacters = "\\.^$|?*+(){}[]"
    subjects += [text for c in metacharacters for text in (c, c * 2, c * 3, "a" + c + "b")]
    repetitions = ["", "?", "*", "+", "{0,2}", "{1}", "{2,4}"]
    patterns = ["^.*$", "^a{64}$", "^a{0,64}$", "^a$|^b$", "needle",
                "^(a|ab)+$", "^(a?b?)*$", r"^\d+\.\w+$", r"^..\.bytes$",
                r"^a\.\+\?\(\)\[\]\{\}\|\^\$\\z$", "^(a{64}){15}$"]
    # Unquantified anchor-bearing groups stay supported; escaped anchors and
    # literal $ class members are safe to quantify and must not be overrejected.
    patterns += ["(^a)|(^b$)", "((^a))b$", "^a((b$))", r"^(\^a){2}$",
                 r"^(a\$){2}$", "^([a$]){2}$"]
    patterns += ["^\\" + c + "+$" for c in metacharacters]
    for _ in range(100):
        parts = [rng.choice(atoms) + rng.choice(repetitions)
                 for _ in range(rng.randrange(1, 5))]
        pattern = "".join(parts)
        if rng.randrange(2):
            pattern = "^" + pattern
        if rng.randrange(2):
            pattern += "$"
        patterns.append(pattern)
    return [("regexp:" + pattern, subjects) for pattern in patterns]


def intentional_differences():
    # Each PCRE2 feature is required to compile and match its positive case;
    # POSIX-lite must reject the rule with a useful error rather than reinterpret it.
    return [
        (r"regexp:^(?:a)\.test$", "a.test", "noncapturing group"),
        (r"regexp:^(?=a)a\.test$", "a.test", "lookahead"),
        (r"regexp:^a(?<=a)\.test$", "a.test", "lookbehind"),
        (r"regexp:^(a)\1\.test$", "aa.test", "backreference"),
        (r"regexp:^a+?\.test$", "aaa.test", "lazy quantifier"),
        (r"regexp:^a++\.test$", "aaa.test", "possessive quantifier"),
        (r"regexp:^\Qliteral[a].quoted\E$", "literal[a].quoted", "quoted literal"),
        (r"regexp:^\141\.octal$", "a.octal", "octal escape"),
        (r"regexp:^[\d]+\.class$", "123.class", "escape inside class"),
        (r"regexp:\bexample\b", "example.com", "word boundary"),
        (r"regexp:^[[:alpha:]]+\.test$", "abc.test", "POSIX named class"),
        (r"regexp:^a{65}$", "a" * 65, "bounded repeat limit"),
        (r"regexp:^a{1,}$", "aaa", "open-ended brace repeat"),
        (r"regexp:^a{0}$", "", "exact-zero repeat"),
        (r"regexp:^a{0,0}b$", "b", "zero-upper-bound range repeat"),
        (r"regexp:^((a){0}){2}$", "", "nested exact-zero repeat"),
        (r"regexp:^[a-c]*.{0,2}[ab]{0,2}$|\[{0}", "outside", "reported musl zero-upper-bound regression"),
        (r"regexp:^()a$", "a", "empty group"),
        (r"regexp:^(a|)$", "a", "empty alternative"),
        (r"regexp:^(a$){1}$", "a", "quantified end-anchor group"),
        (r"regexp:(^a)?", "a", "optional start-anchor group"),
        (r"regexp:(^a)*", "", "starred start-anchor group"),
        (r"regexp:(^a)+", "a", "plus start-anchor group"),
        (r"regexp:((^a)){1}", "a", "quantified recursively nested start anchor"),
        (r"regexp:((a$)){1}", "a", "quantified recursively nested end anchor"),
        (r"regexp:(b|(^a)){1}", "a", "quantified alternative containing anchor"),
        ("regexp:" + "a" * 513, "a" * 513, "pattern byte limit"),
        ("regexp:" + "(" * 17 + "a" + ")" * 17, "a", "group depth limit"),
    ]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pcre2", type=Path, required=True)
    parser.add_argument("--posix-lite", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    pcre2, posix = args.pcre2.resolve(), args.posix_lite.resolve()
    corpus = portable_corpus()
    production = production_cases()
    production_checks = 0
    for rule, cases in production:
        subjects = [subject for subject, _ in cases]
        expected = [expected for _, expected in cases]
        for driver in (pcre2, posix):
            state, results = run(driver, rule, subjects)
            assert state == "ok", (driver, rule, state)
            assert results == expected, (driver, rule, subjects, expected, results)
        production_checks += len(cases)
    assert production_checks == 72
    print("production CN corpus: 8 unchanged rules / 72 assertions passed in both backends", flush=True)

    compared = 0
    for rule, subjects in corpus:
        a_state, a_results = run(pcre2, rule, subjects)
        b_state, b_results = run(posix, rule, subjects)
        assert a_state == b_state == "ok", (rule, a_state, b_state)
        for subject, a, b in zip(subjects, a_results, b_results):
            assert a == b, ("unexpected portable-subset difference", rule, repr(subject), a, b)
            compared += 1
    print(f"portable differential corpus: {len(corpus)} rules / {compared} matching results agree", flush=True)

    # These two accepted patterns have mathematically valid matches in libc.
    # The unchanged PCRE2 100000-match / 1000-depth budgets instead return
    # MATCHLIMIT (-47), mapped to false by the public bool API. The PCRE2-only
    # regex_budget_profile.h unit independently verifies the actual error code;
    # a driver result of false by itself does not establish a normal no-match.
    operational_budgets = ["regexp:^(a|aa)+a{64}$", "regexp:^(a+)+a{64}$"]
    for rule in operational_budgets:
        a_state, a_results = run(pcre2, rule, ["a" * 65])
        b_state, b_results = run(posix, rule, ["a" * 65])
        assert a_state == b_state == "ok", (rule, a_state, b_state)
        assert a_results == ["0"] and b_results == ["1"], (rule, a_results, b_results)
        print(f"known operational budget difference: {rule}; PCRE2 bool=false / lite=true; "
              "direct MATCHLIMIT(-47) evidence is in the PCRE2 regex_budget_profile.h unit", flush=True)

    differences = []
    for rule, positive, category in intentional_differences():
        a_state, a_results = run(pcre2, rule, [positive])
        b_state, b_results = run(posix, rule, [positive])
        assert a_state == "ok" and a_results == ["1"], (category, a_state, a_results)
        assert "invalid POSIX-lite regexp at " in b_state and b_results == ["0"], (category, b_state, b_results)
        differences.append(category)
        print(f"expected POSIX-lite rejection: {category}", flush=True)
    # These exact expressions formerly compiled in both backends but libc
    # matched "aa" where PCRE2 did not. They must now fail at lite rule loading.
    anchor_regressions = ["regexp:^(a$){2}$", "regexp:(^a){2}",
                          "regexp:^((a$)){2}$", "regexp:((^a)){2}"]
    for rule in anchor_regressions:
        a_state, a_results = run(pcre2, rule, ["aa"])
        b_state, b_results = run(posix, rule, ["aa"])
        assert a_state == "ok" and a_results == ["0"], (rule, a_state, a_results)
        assert "invalid POSIX-lite regexp at " in b_state and b_results == ["0"], (rule, b_state, b_results)
        print(f"former anchor drift rejected: {rule}", flush=True)
    for subject, category in [("é.bytes", "non-ASCII subject"),
                              ("a" * 254, "254-byte subject"),
                              ("a\tbytes", "non-printable subject")]:
        a_state, a_results = run(pcre2, "regexp:^.*$", [subject])
        b_state, b_results = run(posix, "regexp:^.*$", [subject])
        assert a_state == b_state == "ok", (category, a_state, b_state)
        assert a_results == ["1"] and b_results == ["0"], (category, a_results, b_results)
        differences.append(category)
        print(f"expected POSIX-lite fail-closed subject: {category}", flush=True)
    summary = {
        "format_version": 1,
        "pcre2_driver": str(pcre2), "posix_lite_driver": str(posix),
        "production_rules": len(production), "production_assertions_per_backend": production_checks,
        "portable_rules": len(corpus), "portable_comparisons": compared,
        "corpus_sha256": hashlib.sha256(json.dumps(corpus, ensure_ascii=True).encode()).hexdigest(),
        "operational_budget_differences_verified": operational_budgets,
        "operational_budget_difference_count": len(operational_budgets),
        "operational_budget_direct_error_evidence": "PCRE2 regex_budget_profile.h unit: MATCHLIMIT (-47) at match=100000, depth=1000",
        "intentional_differences_verified": differences,
        "anchor_drift_regressions_verified": anchor_regressions,
        "unexpected_differences": 0,
    }
    if args.output:
        args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
