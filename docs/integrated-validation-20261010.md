# DNS size/backend integration, 2026-10-10

## Scope and defaults

This branch integrates three previously isolated changes on top of
`9227dc7fc6a1cbe1bfa9dd4729e4c01910cda25b`:

- Strict, explicitly selected POSIX-lite regex (`59b8d4a` local experiment)
- `-Os` and LTO build/profile changes (`e5bf69f` local experiment)
- Optional OpenWrt dynamic-lite recipe and verification (`0c7b41f`, `503070c`)

PCRE2 remains the default backend. The portable Linux release remains static
musl. POSIX-lite is a restricted grammar with bounded inputs and intentional
semantic differences; it is not a drop-in PCRE2 replacement. The OpenWrt package
installs only an executable and has no service, configuration, or autostart.
This publication does not merge main, publish a release, connect to a router,
install the APK, replace libc, or change system DNS/firewall settings.

The older component reports retain their original measurements and chronology.
They are not being retroactively presented as combined-branch tests.

## Fresh combined-source checks

The application and C-test Git subtree used for these new runs is
`7ed5ead527ec45294464ee9e878837b8c47569a2` (local integration checkpoint
`2a3e0e5098fba94d8a55d50d3b8cfa1707fd21d0`). Subsequent integration edits are
limited to CI, verifier coverage, and documentation; publication checks compare
the C subtree and package recipe with these tested inputs.

- Python verifier/build/backend/package contracts: all 98 tests passed after
  the integrated CI/artifact changes, including 20 new lite artifact tests
  and two workflow argument/portability regression tests
- GCC 14 native and ASan/UBSan: both PCRE2 and POSIX-lite freshly built and
  passed the complete Make unit/integration suite in distinct output trees
- Native PCRE2 reused the already verified, unchanged pinned no-Unicode/no-JIT
  dependency; the application and every C harness were rebuilt from this tree
- Zig 0.14.1/musl: both backends rebuilt for x86_64 and AArch64, including every
  test harness, with frozen-source/hash and exact-link replay verification
- x86_64 static musl: both backends executed the full unit/integration suite
- Native and x86_64 musl: each reran 81,089 portable differential comparisons,
  with zero unexpected differences; two documented PCRE2 MATCHLIMIT budget
  differences and the explicit unsupported-syntax/input cases remain visible
- All 32 newly built static application/test ELFs retain a 1 MiB non-executable
  GNU_STACK and have no interpreter; the builder also verifies architecture,
  static identity, dependency inputs, and exact map replay
- Read-only independent review found no blocking parser, bounds, lifetime, or
  default-backend defect; the identified lite CI gap is addressed below

The local GCC sanitizer run disables LSan because ptrace/sandbox restrictions
make it unusable here. Local warning/address-layout overrides remain confined
to test commands; they do not change the product defaults. Local static ARM
binaries were cross-built and inspected, not executed on hardware.

## Fresh OpenWrt package rebuild

The official matching SDK rebuilt the package from the combined C subtree.
The prior SDK staging directory, APK, package payload, and all historical logs
were preserved before package-local cleanup. No system dependencies were
installed and no router was contacted.

| New output | Bytes | SHA-256 |
| --- | ---: | --- |
| Unsigned APK | 33,569 | `c4e4e144a127d2b286d49188315be527ce48ec964f7413e7db03830a5f1d1270` |
| Extracted executable | 65,537 | `a1d76d7dd42ea4beb3d68f8f9a785b87bde4ddc55257fbf1913d4b42466891ba` |

The output is byte-identical to the historical dynamic experiment, established
by a new SDK build and new checks rather than reuse of its success report.
`apk verify --allow-untrusted --no-network` checks archive integrity, not a
publisher signature; this remains an unsigned experimental package.

- New extracted APK executable: all 12 loopback integration checks passed
- Fresh full SDK-flag application and five C unit binaries: all passed under
  QEMU AArch64 with the verified reference firmware loader/libc
- Domain fixtures, 157 mock netlink assertions, 18 nft CLI checks, and all 12
  integration checks passed with those same SDK flags
- After the SDK's final strip/sstrip processing, the test-build executable
  exactly matches the new packaged executable
- Only `libc.so` is dynamically needed; all 102 strong imports resolve in the
  reference firmware, and the 1 MiB non-executable stack request is preserved
- Package metadata declares libc and libpthread, both already installed in the
  verified reference image; this is not a live-device dependency assessment

See the [dynamic evaluation](openwrt-dynamic-evaluation-20261010.md) for pinned
SDK/rootfs provenance, controlled static/dynamic size comparisons, and APK
size accounting. Executable/APK size is not RSS, flash-block use, or throughput.

## CI and downloadable artifacts

The four existing jobs retain PCRE2 build, verified packaging, and full-suite
execution on Linux x86_64, Linux ARM64, and macOS ARM64 as applicable. The same
jobs also explicitly build and test POSIX-lite in isolated output trees:

- Native + ASan/UBSan: Linux x86_64 and macOS ARM64
- Static musl: Linux x86_64 and ARM64, executed on matching CI hardware

Lite bundles use separate `experimental-lite-*` artifact names and explicit
backend metadata. The verifier rejects unknown or inconsistent backend labels
and selects the correct domain contract. Historical bundles without backend
metadata retain their original PCRE2 interpretation. The existing four
`diversion-*` artifacts and main-only delivery selection remain unchanged.
The OpenWrt APK is a separate local SDK output, not one of those CI builds.

The first integrated run, [38026329523](https://github.com/xfy-see/diversion-dns-c/actions/runs/38026329523), passed all three Linux jobs, including lite, and the macOS PCRE2 suite. Its new macOS lite step stopped before C compilation because Bash 3.2 treats an empty array as unset under `set -u`. The follow-up uses a scalar sanitizer selection and a nonempty packaging-options array, with two regression tests. No C source or OpenWrt recipe changed; the original failed log/artifacts are retained.

A workflow definition is not evidence of a passed run. Inspect the exact
published commit's run/attempt and job conclusions before calling CI complete.
Download the matching Actions artifact and verify its commit, run identity,
source tree, and file hashes before executing it. No release is created by
pushing this independent branch.

## Remaining acceptance boundaries

Neither these local tests nor CI mocks establish real router kernel nftables,
routing, CPU/RSS, sustained load, latency, stack high-water use, or stability.
POSIX libc regex has no equivalent interruptible per-match PCRE2 budget;
syntax/input bounds do not prove a device resource ceiling. Device acceptance
and performance tests remain separate work requiring the intended target.

Raw fresh evidence is retained in the integration checkout's ignored `.build/`:
`evidence/`, `integrated-comparison/`, and `openwrt-integrated/`. SDKs, firmware,
archives, private credentials, and generated binaries are excluded from Git.
