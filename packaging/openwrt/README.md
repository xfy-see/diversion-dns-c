# Optional OpenWrt POSIX-lite package

This is a local **packaging experiment**, not a firmware or release-default
change. The normal PCRE2 backend and portable static build remain available.
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

The source staging helper exports committed `c/` and `LICENSE` files into a
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

The evaluation generated an unsigned local APK. Its content checksum and
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

The checker requires ELF64 little-endian AArch64, the musl loader at
`/lib/ld-musl-aarch64.so.1`, only `libc.so` as a shared dependency, the preserved
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
