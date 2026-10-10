# Experimental POSIX-lite regex backend

This branch adds an **opt-in experiment**, not a replacement for PCRE2. The
normal build and existing release workflow continue to select pinned PCRE2
10.48, with Unicode and JIT disabled. `REGEX_BACKEND=posix-lite` instead uses
`regcomp`/`regexec` from libc (musl in the static cross-build). It does not link
PCRE2. Native glibc results alone do not validate musl or target hardware.

## Build selection

```
make -C c REGEX_BACKEND=pcre2 PCRE2_PREFIX=/path/to/pinned/pcre2 test
make -C c REGEX_BACKEND=posix-lite test
```

The default output directories are different. Use a fresh directory for each
backend when overriding `BUILD`; a recorded backend mismatch or nonempty
unstamped output directory is an error.
The existing GCC `-Wmisleading-indentation` warnings in `nft_netlink.h` may need
`-Wno-error=misleading-indentation` for a GCC-only local run. The experiment
keeps those unrelated sources unchanged. No workflow is switched by this patch.

## Accepted syntax

A small recursive parser validates **all** input before libc compiles it.
Unknown/ambiguous constructs are rejected; there is no fallback, silent rewrite
of arbitrary PCRE syntax, or global search-and-replace.

- Non-whitespace ASCII literals (`!` through `~`), with ERE metacharacters
  interpreted only in the positions described below
- `.` for one allowed subject byte
- Ordinary groups `(expr)`, concatenation, and alternatives `expr|expr`
- `^` only at the start of an alternative, `$` only at its end
- Greedy `?`, `*`, `+`, `{m}`, and `{m,n}` on an atom/group that contains no
  anchors (including anchors nested inside child groups)
- Bracket sets `[abc]`, negated sets `[^abc]`, and ordered ranges entirely
  within `A-Z`, `a-z`, or `0-9`; `-` is a literal only first or last
- Outside brackets, `\d` becomes `[0-9]` and `\w` becomes `[A-Za-z0-9_]`
- Outside brackets, escaped ERE punctuation `\\ \. \^ \$ \| \? \* \+ \( \)
  \{ \} \[ \]` means the literal character, emitted in an unambiguous ERE form

No empty patterns, groups, or alternatives; no nested bracket notation,
backslash escapes **inside** brackets, literal `]` in an input bracket set,
POSIX named/collating/equivalence classes, cross-category or descending ranges,
noncapturing/named groups, lookaround, backreferences, flags, Unicode properties,
word boundaries, octal/hex escapes, `\Q...\E`, lazy/possessive/stacked quantifiers,
`{m,}`, `{0}`/`{0,0}`, repeated anchors/groups containing anchors, or unrecognized escapes. E.g. `[\d]` is deliberately rejected; use
`[0-9]`. Escaped literal `\[` and `\]` outside a class remain supported.

Repeated anchored groups are rejected even for `{1}` or `?`: libc implementations
differ on interior assertion semantics (e.g. `^(a$){2}$` on `aa`), so the backend
does not accept this ambiguous corner of ERE.

Zero-upper-bound repeats are also rejected: musl can differ from PCRE2 on empty
branches and nested groups involving `{0}`. Positive-upper-bound `{0,n}` remains
supported within the documented limits.

The eight pinned CN-list expressions in `cache_domain_test.c` are unchanged
and all fit this grammar, including `\d`, `\w`, ordinary groups, and `{5}`.

## Explicit limits and input contract

- Source expression: at most 512 bytes
- Group nesting: at most 16
- Finite repeat maximum: at most 64, with `0 <= m <= n` and `n >= 1`
- Distinct regex rules per `md_domain`: at most 128 (duplicates do not count)
- Expanded-complexity budget: 2048 units. An atom costs 1; concatenation sums;
  each alternative adds 1; a group uses its child cost; `?`, `*`, `+` add 1;
  `{m,n}` costs `(child_cost + 1) * n + 1` (same with `n=m` for `{m}`).
  This is a conservative compile-expansion guard, **not** a hard CPU/RSS bound.
- Regex subjects: printable ASCII bytes `0x20..0x7e`, at most 253 bytes after
  removing one final dot. Out-of-contract subjects return no **regex** match
  through the existing boolean API. Empty subjects are allowed after normalization.

This narrowing is intentional and is a public matcher API difference from
PCRE2 byte mode, whose dot can match arbitrary non-newline bytes and whose
subjects may exceed 253 bytes. Full/domain/keyword rules retain their previous
byte-preserving behavior and can still match these subjects. The DNS wire
question decoder already accepts a stricter subset: `0x21..0x7e` label bytes,
with literal label dots/backslashes rejected and DNS wire length bounded.
Do not adopt this backend for other public matcher callers without reviewing
the contract. Non-regex and suffix normalization are unchanged.

Names still receive ASCII `A-Z` folding and one trailing-dot removal before
regex matching. The pattern itself is not lowercased. There is no `REG_ICASE`.
Matching is boolean and unanchored unless the expression supplies anchors;
POSIX longest-match vs PCRE first-match does not expose captures through this API.

Language agreement does not imply identical behavior when an engine exhausts
its execution budget. The existing PCRE2 backend sets match/depth limits to
100000/1000 and converts execution errors into a miss. For example, both
`^(a|aa)+a{64}$` and `^(a+)+a{64}$` on 65 `a` bytes return
`PCRE2_ERROR_MATCHLIMIT` (-47), so that backend reports false; POSIX-lite can
correctly report true. The direct PCRE2 unit test records this error separately
from an ordinary no-match, and the differential suite classifies these cases
as operational differences. There is no attempt to imitate PCRE2 resource
exhaustion in the libc backend. The resource guards here do not give libc an
interruptible per-query time or memory limit.

## Locale, lifetime, and concurrency

Each rule set owns a C locale. Compilation and execution temporarily select it
with thread-local `uselocale`, then restore the caller's prior thread locale.
No process-global `setlocale` is performed by the backend. `REG_EXTENDED |
REG_NOSUB` is used, without `REG_NEWLINE` or capture output. Compiled objects
are shared read-only; libc owns per-execution state. Finish all loads before
publishing a rule set, and join every reader before freeing it or its locale.
Concurrent mutation/free remains unsupported, as with the existing backend.

All rejection messages identify a source byte offset. File loading adds the
filename and line, stops on the invalid line, and keeps already loaded rules
for the existing caller cleanup semantics. Compilation/execution allocation
failures retain the existing API behavior (load error or match miss).

## Verification and scope

PCRE2 keeps its original profile and arbitrary-byte assertions. POSIX-lite
has separate mandatory accepted/rejected syntax, limits, input-boundary,
file/line, caller-buffer, and locale tests. Fixture omissions are named and
reported; unsupported legacy PCRE features are actively checked for rejection.
Both modes retain all eight actual CN rules and their 72 match assertions.
The shared frozen-rule test uses eight threads and 43,200 matches per run.

`tests/regex_differential.py` compares two built domain drivers against a
seeded supported-subset corpus. `benchmarks/compare-regex-backends.py` builds
fresh musl A/B outputs with the same Zig toolchain and flags; its manifest and
logs distinguish compilation, host-executable x86 tests, and unexecuted ARM.
No router deployment, kernel nftables acceptance, QPS/latency result, or
production safety claim follows from local functional or file-size results.
