# Optional OpenWrt POSIX-lite package

This is an **experimental unsigned APK**, built locally or by the separate
`Experimental OpenWrt lite APK` Actions workflow. It is not a firmware or
release-default change. The normal PCRE2 backend and portable static build remain available.
The application payload is `/usr/sbin/diversion-dns-c-lite` plus normal OpenWrt
package bookkeeping; it does not install
configuration, create an init service, start a listener, or change firewall/DNS
settings. Do not install it on a router as part of the build instructions below.

Read [`c/REGEX-POSIX-LITE.md`](../../c/REGEX-POSIX-LITE.md) first. This backend
intentionally accepts a restricted ASCII regex grammar, not arbitrary PCRE2.
It keeps the existing parser/resource guards and per-rule-set C locale with
thread-local `uselocale`. It must not be replaced with process-global locale
changes. No PCRE2 or libyaml archive is linked into this package.

## Build with an appropriate SDK

Use the SDK/toolchain for the installed OpenWrt userspace. A matching CPU label
alone is insufficient. Kernel-module vermagic is a separate requirement from
this ordinary userspace application's libc ABI. Do not upgrade or replace the
router's libc to make an experimental binary work.

The source staging helper exports committed `c/`, `LICENSE`, and the package recipe into a
fresh package directory and records their hashes. Uncommitted application
changes are not silently included. Commit local application changes first if
they are intended inputs. The helper does not download, compile, install, or
modify the SDK configuration.

```sh
python3 scripts/stage-openwrt-package.py \
  "$SDK/package/diversion-dns-c-lite" --source-ref HEAD
cd "$SDK"
# Select CONFIG_PACKAGE_diversion-dns-c-lite=m using the SDK's configuration.
make defconfig
make -j4 package/diversion-dns-c-lite/compile V=s
```

The workflow generates an unsigned experimental APK. Its content checksum and
payload were verified locally; it is not an authenticated release from a
configured package repository. Do not alter a router's trust configuration or
install it merely to complete this experiment.

The recipe uses the SDK's target compiler, target flags and hardening, enables
package-local LTO and section GC, and explicitly selects `-Os`. It retains the
1 MiB ELF default thread-stack request used by the portable musl build. This
setting matters: omitting it made the DNS unit fixture overflow musl's default
approximately 128 KiB thread stack in the local AArch64 emulator. Stack address
space is not measured RSS. No unwind-removal flag is used.

`-static-libgcc` keeps the small compiler runtime local while linking libc
dynamically. With the evaluated GCC toolchain this both avoids a
`libgcc_s.so.1` runtime dependency and makes the executable slightly smaller.
OpenWrt supplies the ordinary `libc` package dependency; the recipe explicitly
declares `libpthread`. On the evaluated musl firmware, pthread and regex
functions are in the already-installed libc. No extra regex library is needed.

The recipe preserves SDK warning flags and adds normal C warnings. It does not
force all GCC warnings to errors: existing, unchanged `nft_netlink.h` code
emits `-Wmisleading-indentation`. The independent controlled comparison used
`-Werror` with only that pre-existing warning downgraded.

## Check the final packaged ELF

Extract the package payload locally. Supply a verified image/rootfs from the
intended firmware, not an arbitrary SDK directory, to the read-only checker:

```sh
python3 scripts/check-openwrt-elf.py path/to/diversion-dns-c-lite \
  --rootfs path/to/extracted-rootfs
```

The default checker requires ELF64 little-endian AArch64 with loader
`/lib/ld-musl-aarch64.so.1`. For MT7621 pass `--arch mipsel_24kc`: it requires
ELF32 little-endian MIPS32r2/O32/soft-float and `/lib/ld-musl-mipsel-sf.so.1`.
Both modes require only `libc.so` as a shared dependency, an exactly 1 MiB RW
non-executable stack request, and all strong imports exported by the supplied
runtime. It follows dynamic tables even when OpenWrt `sstrip` removes section
headers. Weak optional GCC frame-registration hooks are reported separately.
An ELF check is not a hardware, kernel nftables, network-load or performance test.

If firmware enables `CONFIG_USE_MKLIBS`, inspect the actual installed/reduced
libc: functions absent from the firmware build can have been removed. The
evaluated custom RE-CS-07 image explicitly has MKLIBS disabled. Do not assume
that setting for another image, or assume that a libc version string proves
every imported function is present.

## Size accounting

Keep these quantities separate:

- Executable bytes: exact size of the final stripped package payload
- APK bytes: compressed package archive, including metadata/signature overhead
- Installed increment: payload plus package-database/filesystem overhead and
  any dependencies not already installed
- Whole firmware size, flash block allocation and runtime RSS: separate
  measurements; no reduction is inferred from executable size alone

See [the local evaluation](../../docs/openwrt-dynamic-evaluation-20261010.md)
for verified inputs, measured values, and the current limitations.

## Dual-architecture GitHub Actions

`.github/workflows/openwrt-apk.yml` runs on branch pushes, pull requests and
manual dispatch. It does not itself publish a GitHub Release. The one-version
`v0.1.0` main-only release job waits for these two jobs and all four regular
build/test jobs, independently downloads and verifies their exact artifacts,
and publishes them together without changing the PCRE2 default. Its two independently named artifacts
contain an architecture-suffixed APK, SHA256SUMS, the exact Git source archive,
source manifest, SDK configuration, buildinfo, ABI checks and raw test logs:

- OpenWrt 25.12.5, `qualcommax/ipq60xx`, `aarch64_cortex-a53`
- OpenWrt 25.12.5, `ramips/mt7621`, `mipsel_24kc`

Official SDK URLs, GCC 14.3.0 and archive SHA256s are pinned in `targets.json`.
The cache contains verified download archives only, keyed by OS, architecture,
SDK hash, compiler version and source/recipe/workflow inputs, with no fallback
restore prefixes. Every build extracts a fresh SDK and uses fresh target objects
and fresh PCRE2 reference objects. Download hashes are checked even on cache hits.
No SDK, firmware/rootfs, emulator or key material is uploaded as an artifact.
Host tools come from the runner's official Ubuntu repositories; their versions,
target compiler and emulator identity are recorded in build/test evidence.

The 32-bit MIPS recipe statically links the SDK's libatomic helpers for the
existing 64-bit atomic counter. AArch64 does not receive `-latomic`.
`EXTRA_LDLIBS` also reaches the standalone nft CLI test rule; the production
counter and assertions are unchanged. Both builds retain `-Os`, SDK LTO/GC and
hardening, `-static-libgcc`, and the 1 MiB stack request. With
`DIVERSION_BUILD_TESTS=1` the SDK builds the seven test binaries using the exact
package compiler and flags; only the application is put in the APK.

The verifier checks architecture, package dependencies, a two-file payload
whitelist, all payload hashes and installed-size metadata before extraction.
It expects default signature verification to reject the unsigned APK. Its only
`--allow-untrusted` uses are offline `verify`/`extract` of the just-built,
SHA256-recorded package into an isolated directory with an empty key directory.
These commands do not install a package, execute package scripts or change trust.
There are deliberately no router-install or signature-bypass installation steps.
SHA256 provides content integrity, not publisher authentication; an unsigned APK
is not trusted for normal installation by default.

OpenWrt 25.12.5's SDK has two unconditional APK signing-key prerequisites even
when `CONFIG_SIGNED_PACKAGES` is disabled. Before building, the script changes
only those two dependencies to be conditional, records the patch, disables
signing, and checks for absence of key filenames both before and after the build.
It never creates, imports, reads or publishes keys. An unexpected SDK helper
layout fails closed and needs review before a version update.

Each matrix leg runs, with nonzero exit codes failing the job:

- Five same-SDK C harnesses, including 157 netlink mock assertions and 43,200
  concurrent regex matches across eight threads
- Shared domain fixture and explicit POSIX-lite rejection/locale/limit tests
- 18 nft CLI mock/grammar checks
- 12 loopback integration tests executing the final APK-extracted application
- 81,089 portable-subset differential comparisons against native same-source
  PCRE2 10.48, plus explicit syntax/input differences and the two known PCRE2
  budget differences; PCRE2's budget unit is also executed

The test application is stripped independently and must match the packaged ELF
byte-for-byte. A failed test, source/hash mismatch, unexpected runtime dependency,
wrong ABI, missing import or unexpected signing key prevents a successful artifact.

QEMU uses the libc from that exact official SDK. This proves SDK userspace
compatibility, not compatibility with an installed or reduced (`MKLIBS`) device
libc. Local historical reference-firmware checks are documented separately;
CI does not claim to read or test either user's current router firmware.
The declared `libpthread` package marker may still require the matching package
repository even though pthread symbols are provided by musl's libc.
No real kernel nft writes, device acceptance, RSS/QPS, sustained-load stability
or actual installed flash increase is inferred from these tests.

For an authorized local reproduction with already verified archives:

```sh
python3 scripts/build-openwrt-apk.py --arch mipsel_24kc --source-ref HEAD \
  --sdk-archive /path/to/verified-sdk.tar.zst \
  --pcre2-archive /path/to/pcre2-10.48.tar.gz \
  --work .build/apk-work-mips --output .build/apk-output-mips
```

Both directories must be new. Use `aarch64_cortex-a53` and its SDK for ARM64.
The wrapper freezes committed build inputs and rejects modified helper/recipe
files. It only works on build artifacts and never connects to a router.

## v0.1.0 version and migration

The application version is `0.1.0`; this recipe produces `0.1.0-r1`.
Historical experimental packages used `0.2.0-r1`, so APK version ordering treats
this release as a downgrade, not an automatic upgrade. Back up configuration
and rules before arranging a separate installation. Never force-overwrite user
configuration. The release changes no running device or trust configuration.
See [the release notes](../../docs/release-v0.1.0.md) for exact verification and
hardware-acceptance boundaries.
