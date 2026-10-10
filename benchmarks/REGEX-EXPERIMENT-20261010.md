# POSIX-lite experiment: local results, 2026-10-10

> Historical component-level experiment: the results and publication status below refer to the original isolated run. See [the integrated validation record](../docs/integrated-validation-20261010.md) for the combined branch and its fresh tests.

## Status and scope

- Local branch: `experiment/musl-regex-20261010`
- Base: `9227dc7fc6a1cbe1bfa9dd4729e4c01910cda25b` (`specialize/fixed-splitter`)
- Default build and release workflow still select PCRE2; this is an opt-in experiment
- No push, CI dispatch, merge, router deployment, or target-device acceptance
- Independent final review is not complete; these results do not establish production readiness
- Backend grammar, public input restrictions, locale/lifetime contract and resource limits:
  [`c/REGEX-POSIX-LITE.md`](../c/REGEX-POSIX-LITE.md)

## Same-toolchain static executable sizes

Official Zig 0.14.1, pinned PCRE2 10.48, Unicode/JIT disabled. Both modes use
`-O2 -ffunction-sections -fdata-sections -UNDEBUG`, static musl, section GC,
stripped output and 1 MiB ELF default stack size. PCRE2 was freshly built for
both targets; this compares final executables, not library archive sizes.

| Target | PCRE2 reference | POSIX-lite | Saved | Reduction |
| --- | ---: | ---: | ---: | ---: |
| aarch64-linux-musl | 224,216 B | 167,168 B (163.25 KiB) | 57,048 B | 25.4433% |
| x86_64-linux-musl | 245,320 B | 164,640 B (160.78125 KiB) | 80,680 B | 32.8877% |

These are freshly built same-source A/B references. They are not a relabeling
of previously published 224,248/245,256-byte artifacts. ELF machine type,
static linkage and absence of a PCRE2 dependency in lite were checked.

## Exact link-map disk attribution

| Component | ARM64 lite | x86_64 lite |
| --- | ---: | ---: |
| Project object files | 57,116 B | 59,674 B |
| musl libc, including regex | 92,243 B | 93,354 B |
| CRT startup | 68 B | 52 B |
| Compiler runtime | 7,852 B | 1,019 B |
| Shared merged constants | 7,380 B | 7,422 B |
| Linker-generated sections | 836 B | 684 B |
| Alignment / ELF metadata | 1,673 B | 2,435 B |
| Unattributed | 0 B | 0 B |
| Total | 167,168 B | 164,640 B |

The exact LLD link was replayed with a map, and the complete stripped ELF SHA256
matched the measured executable in all four builds. Unstripped diagnostic
allocated section shapes also matched. Object ownership is not semantic
ownership: inlined libc can appear in project objects and pooled constants
cannot be attributed uniquely. The categories sum to the whole file.

On ARM, removing 101,831 linked PCRE2 bytes also brings in another 41,841 musl
libc bytes; libc regex is not free in a static executable. On x86, those figures
are 127,553 PCRE2 bytes removed and 44,173 musl bytes added.

Lite BSS is 5,072 bytes on ARM and 2,728 on x86. BSS is not runtime RSS, heap,
compiled-rule memory, per-query allocations, or thread-stack usage. No runtime
RAM reduction, latency, throughput, QPS, or performance improvement was measured.

## Functional verification

The final production source passed these local Linux x86_64 checks:

- Full native glibc suites in both modes
- Full application ASan/UBSan suites in both modes, with leak detection disabled
- Full native x86_64 musl suites in both modes
- Each full suite includes five C unit binaries, shared domain fixtures,
  157 mock netlink assertions, 18 nft CLI checks, and 12 loopback integration tests
- All eight unchanged CN expressions and all 72 match assertions pass in each mode
- Eight concurrent readers perform 43,200 matches per run against a shared frozen
  rule set, with independent caller buffers and restored C/UTF-8 thread locales
- Lite mandatory tests include 96 syntax/resource rejections, exact pattern,
  depth, repetition, expansion and rule-count boundaries, source file/line errors,
  printable-ASCII/length limits, and preservation of non-regex behavior
- Deterministic differential corpus: 131 supported rules and 81,089 comparisons,
  with zero unexpected discrepancies in the tested normal-budget corpus
- 31 intentional syntax/subject differences and four former anchored-group
  regressions are explicitly verified; they are not hidden fixture skips
- Two additional operational budget differences are verified separately:
  PCRE2 directly returns `PCRE2_ERROR_MATCHLIMIT` (-47), which its existing
  boolean API turns into a miss; libc can correctly match those subjects
- All 67 Python verifier/build-isolation tests pass
- Original default-PCRE2 Unicode/JIT, quoting, octal, bracket-escape,
  word-boundary and arbitrary-byte profile checks remain intact

The shared historical fixture still explicitly names its four pre-existing
RE2/Unicode-specific exclusions. Lite-only unsupported features are required to
fail loading, not silently reinterpreted.

After adding the direct-budget diagnostic unit tests, all four native/ASan
cache-domain binaries were rebuilt and rerun, and the final native differential
suite was rerun. The final musl freeze includes those diagnostic tests too.

## Important restrictions and incomplete checks

- Repeated groups containing anchors and zero-upper-bound repeats (`{0}`,
  `{0,0}`) are rejected because libc corner-case behavior differs
- Only printable ASCII subjects up to 253 normalized bytes enter the lite
  regex engine; full/domain/keyword behavior remains unchanged
- PCRE2 backtracking limits and libc resource behavior are different. The
  parser's compile-expansion guard is not an interruptible CPU or memory budget
- LeakSanitizer terminated with its documented ptrace/container restriction.
  Its failed logs are preserved. ASan/UBSan passed with `detect_leaks=0`; no
  successful leak-check result is claimed
- GCC required the existing `-Wno-error=misleading-indentation` waiver for
  unchanged `nft_netlink.h`; Zig builds kept the strict warning flags
- ARM was cross-compiled and checked as ELF/map data, never executed
- No macOS test, TSan run, device/kernel nftables test, target traffic test,
  runtime-RAM benchmark, or speed benchmark was performed
- Earlier failed/intermediate evidence remains separate; it is not presented
  as the final frozen build

## Reproducible evidence

`benchmarks/compare-regex-backends.py` is a separate experimental build entrypoint;
the ordinary release scripts and workflow are unchanged. It accepts local,
checksum-verified official Zig and pinned PCRE2 source archives, freezes source,
builds fresh target dependencies, retains every command/log, verifies exact
maps, and only executes binaries matching the Linux host architecture.

Final raw evidence root:
`.build/regex-musl-comparison-20261010-03/`

- `manifest.json`: complete, `source_unchanged=true`, 36 successful commands
- `summary.json`: exact A/B byte counts
- `{target}/{backend}/mosdns-c`: measured stripped ELF
- `{target}/{backend}/size/{mosdns-c.map,mosdns-c.unstripped,attribution.json}`
- `x86_64-linux-musl/differential.json`: final semantic/budget results
- `logs/`: distinct dependency, application, test and linker logs
- Native/sanitizer evidence: `.build/evidence/*restricted-final.log`,
  `*-final-cache.log`, `native-final-differential.json`,
  `python-final-verifiers.log`

Frozen input-tree SHA256:
`232bef70b87a61ce5f27343feb4754e22be70e235e903cc4b303190550235f5a`

Final executable SHA256:

- ARM PCRE2: `01d10795cc2feebebaf0f84d8a22f94348aab74c0e496caa5f1db8548b4ddd00`
- ARM lite: `a5d9518354c36a88c816349fff3860c85958809a5cd1af69bce97ac81ec0cf00`
- x86 PCRE2: `1901ab06417105ee96c80dfd6e6af78244f36e3a697553f82b434e49723a188c`
- x86 lite: `2421bf341297330da30588d959de9eb7b655be7c3a225a1132fcb69b2206fd5a`
