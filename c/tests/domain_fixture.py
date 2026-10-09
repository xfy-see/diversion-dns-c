#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test the no-Unicode PCRE2 contract and the shared ASCII fixture subset."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

driver = str(Path(sys.argv[1]).resolve())
fixture = json.loads((Path(__file__).resolve().parents[2] /
                      "tests/fixtures/matcher_domain.json").read_text())
assert fixture["format_version"] == 1
# 共享 Go/Rust fixture 仅跳过明确列出的语言/Unicode 差异，原因与计数均可见。
skipped = {
    "regexp_go_character_class_capture_and_brace_syntax":
        "Go RE2 character classes, capture names, braces and rejection rules differ from PCRE2",
    "unicode_simple_case_normalization":
        "the C matcher folds ASCII A-Z only; it does not normalize Unicode case",
    "regexp_ascii_classes_unicode_properties_and_quote":
        "mixed fixture requires Unicode properties and RE2 whitespace semantics; ASCII parts tested separately",
    "regexp_ascii_word_boundary":
        "mixed fixture includes raw Unicode subjects outside the ASCII DNS input contract; ASCII boundaries tested separately",
}
assert len(skipped) == 4
assert set(skipped) <= {case["name"] for case in fixture["cases"]}
checks = 0
cases = 0


# 借助预编译 driver 加载规则并逐条查询；加载失败仍可验证此前规则的保留行为。
def run(text, queries):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as rules:
        rules.write(text)
        rules.flush()
        result = subprocess.run([driver, rules.name],
                                input="".join(q["domain"] + "\n" for q in queries),
                                text=True, capture_output=True, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(queries) + 1, result
    if lines[0].startswith("error:"):
        assert rules.name in lines[0], ("missing failing rule path", lines[0])
    return lines[0], lines[1:]


for case in fixture["cases"] + fixture["load_cases"]:
    if case["name"] in skipped:
        print(f"SKIP {case['name']}: {skipped[case['name']]}")
        continue
    text = case.get("text", "\n".join(case.get("rules", [])) + "\n")
    state, results = run(text, case["queries"])
    if case.get("error_line", 0):
        assert state.startswith("error:") and f"line {case['error_line']}:" in state, (case["name"], state)
    else:
        assert state == "ok", (case["name"], state)
    for query, actual in zip(case["queries"], results):
        assert actual == str(int(query["matches"])), (case["name"], query, actual)
        checks += 1
    for invalid in case.get("invalid_rules", []):
        state, _ = run(invalid + "\n", [])
        assert state.startswith("error:"), (case["name"], invalid, state)
        checks += 1
    cases += 1

print(f"shared domain fixture: {cases} cases / {checks} assertions passed; "
      f"{len(skipped)} Unicode/RE2-specific cases explicitly skipped with reasons")

# These are mandatory profile tests, independent of the four historical skips.
ascii_cases = [
    (r"regexp:^\d+\.digits$", [("123.digits", True), ("a.digits", False), ("١.digits", False)]),
    (r"regexp:^\w+\.word$", [("ABC_123.WORD.", True), ("a-b.word", False), ("é.word", False)]),
    (r"regexp:^\Qliteral[a].quoted\E$", [("literal[a].quoted", True), ("literala.quoted", False)]),
    (r"regexp:^\141\.octal$", [("a.octal", True), ("b.octal", False)]),
    (r"regexp:^[\d]+\.class$", [("123.class", True), ("١.class", False)]),
    (r"regexp:\bexample\b", [("example.com", True), ("prefixexample.com", False), ("a-example.test", True)]),
    (r"regexp:^..\.bytes$", [("ab.bytes", True), ("a.bytes", False), ("é.bytes", True), ("中.bytes", False)]),
]
profile_checks = 0
for rule, expected in ascii_cases:
    state, results = run(rule + "\n", [{"domain": domain} for domain, _ in expected])
    assert state == "ok", (rule, state)
    for (domain, matches), actual in zip(expected, results):
        assert actual == str(int(matches)), (rule, domain, actual)
        profile_checks += 1

# 关闭 Unicode 必须拒绝相关表达式，且保留文件行号；不能静默改成 ASCII 匹配。
unsupported = [r"regexp:(*UTF)^example\.test$", r"regexp:(*UCP)^example\.test$",
               r"regexp:^\p{L}+\.test$", r"regexp:^\P{L}+\.test$", r"regexp:^\X\.test$"]
for rule in unsupported:
    state, results = run("# profile rejection\nfull:before.test\n\n" + rule + "\nfull:after.test\n",
                         [{"domain": "before.test"}, {"domain": "after.test"}])
    assert state.startswith("error:") and "line 4:" in state and "invalid PCRE2 regexp at " in state, (rule, state)
    assert results == ["1", "0"], (rule, results)
    profile_checks += 3
print(f"no-Unicode PCRE2 profile: {len(ascii_cases)} byte/ASCII cases and "
      f"{len(unsupported)} required Unicode rejections / {profile_checks} assertions passed")
