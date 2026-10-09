#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reuse the ASCII, shared-syntax subset; PCRE2/Unicode parity is not claimed."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

driver = str(Path(sys.argv[1]).resolve())
fixture = json.loads((Path(__file__).resolve().parents[2] /
                      "tests/fixtures/matcher_domain.json").read_text())
assert fixture["format_version"] == 1
skipped = {
    "regexp_go_character_class_capture_and_brace_syntax",
    "unicode_simple_case_normalization",
    "regexp_ascii_classes_unicode_properties_and_quote",
    "regexp_ascii_word_boundary",
}
checks = 0
cases = 0


def run(text, queries):
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as rules:
        rules.write(text)
        rules.flush()
        result = subprocess.run([driver, rules.name],
                                input="".join(q["domain"] + "\n" for q in queries),
                                text=True, capture_output=True, check=True)
    lines = result.stdout.splitlines()
    assert len(lines) == len(queries) + 1, result
    return lines[0], lines[1:]


for case in fixture["cases"] + fixture["load_cases"]:
    if case["name"] in skipped:
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
      f"{len(skipped)} Unicode/RE2-specific cases explicitly skipped")
