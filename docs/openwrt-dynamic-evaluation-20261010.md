# OpenWrt dynamic-lite evaluation, 2026-10-10

> Historical component-level experiment: the results and publication status below refer to the original isolated run. See [the integrated validation record](integrated-validation-20261010.md) for the combined branch and its fresh tests.

## Scope

Local cloud experiment based on application commit
`59b8d4a90d9b9b1ee219afd5291b19632423afed`. No push, CI dispatch, merge,
router connection, deployment, firmware change or libc replacement occurred.
The PCRE2 default and portable static path are unchanged by this package patch.

The user additionally reported an ARM64/aarch64 device using musl 1.2.5,
`/lib/libc.so`, `/lib/ld-musl-aarch64.so.1`, and a dynamically linked BusyBox.
That report is useful environment context, not evidence that this application
has passed on the device. The checks below use a verified downloaded firmware
artifact and local AArch64 user-mode emulation.

## Verified reference firmware and tools

- Configuration repo: `xfy-see/OpenWRT-CI-TAIYI`, commit
  `1c42fa27985465ebf33252be42e260eb0e852c48`
- [Firmware run 37488964788](https://github.com/xfy-see/OpenWRT-CI-TAIYI/actions/runs/37488964788),
  attempt 1, artifact `11427663156`
- Artifact ZIP SHA256:
  `16a15158b04337b0ac09b3591b5b9f0c99184b8d7947f9d49805a59d42f51e4d`
- Custom release `25.12.5-nss-recs07.2`, `qualcommax/ipq60xx`,
  `aarch64_cortex-a53`, kernel 6.12.94
- Full config: musl, GCC 14.3.0, APK, external official toolchain;
  `CONFIG_USE_MKLIBS` explicitly disabled
- Manifest: `libc 1.2.5-r5`, `libpthread 1.2.5-r5`, `libgcc1 14.3.0-r5`
- The firmware provenance pins the exact official toolchain used here:
  [OpenWrt 25.12.5 toolchain](https://downloads.openwrt.org/releases/25.12.5/targets/qualcommax/ipq60xx/openwrt-toolchain-25.12.5-qualcommax-ipq60xx_gcc-14.3.0_musl.Linux-x86_64.tar.zst),
  SHA256 `54426b17d70d8e0fb1187a5337f1c4b35f3c143efc2a09076206c54999e24ca6`
- [Official SDK](https://downloads.openwrt.org/releases/25.12.5/targets/qualcommax/ipq60xx/openwrt-sdk-25.12.5-qualcommax-ipq60xx_gcc-14.3.0_musl.Linux-x86_64.tar.zst),
  SHA256 `5ea07bb08e5a21454b37aaf497c876d5ce8fde1742ac8bfbb62beea84ee4e66b`,
  verified against the official release checksum list; this is the official
  SDK, not a recovered custom NSS SDK

The toolchain's libc, after normal `strip` plus SDK `sstrip`, is byte-identical
to the extracted custom firmware libc:
`8afe4bccb74f595fd45e3c499c1e7e2520ac03c0881f439a8ccb994bf8d3ee5b`,
590,852 bytes. This establishes a substantially stronger userspace match than
matching version labels alone. It does not verify the live device's filesystem.

## Controlled static versus dynamic A/B

Both use the same source and OpenWrt GCC 14.3.0 toolchain, POSIX-lite backend,
`-Os -flto`, section GC, Cortex-A53 code generation, stripped output, 4 KiB
maximum ELF page size, and the existing 1 MiB default-thread-stack request.
Static adds `-static`; dynamic adds `-static-libgcc`. This is not a comparison
between different compilers or against an older PCRE2 binary.

| ARM64 executable | Bytes | KiB |
| --- | ---: | ---: |
| Portable static comparison | 153,264 | 149.672 |
| Dynamic libc comparison | 64,272 | 62.766 |
| Difference | 88,992 | 86.906 |

The controlled executable reduction is **58.0645%**. The earlier exploratory
values without the required stack request (153,184/64,192 bytes) are superseded.

The dynamic binary has interpreter `/lib/ld-musl-aarch64.so.1` and only one
`DT_NEEDED`: `libc.so`. All 101 strong undefined symbols are available in the
extracted firmware libc, including `regcomp`, `regexec`, `regfree`, pthread,
`newlocale`, `uselocale`, and `freelocale`. Two optional weak GCC frame hooks
remain unresolved; these are not missing required runtime functions.
Replaying the exact link with a linker map produced an identical ELF SHA256;
the complete loaded-input list contains neither PCRE2 nor libyaml. Libc and libpthread are already installed
in the reference firmware, so additional shared-library payload is zero for
that reference. The 590,852-byte existing libc is not a new application cost.

SHA256 of controlled executables:

- Dynamic: `3272058ddaa05edc6450707b9fef8de642040f7705a6cc30cdeffaef48f2d3ed`
- Static: `179bd4d85c919982ea8b7bada8657c4a8d5e5ec4eadeb2bc40f49dbee50ee050`

## Functional verification

Both variants passed under locally extracted official Debian QEMU AArch64
10.0.13. Dynamic execution uses the actual reference firmware loader/libc:

- Five C unit binaries, including the unchanged POSIX-lite grammar, rule
  limits, locale restoration, and shared frozen-regex concurrency tests
- Domain fixtures: 70 shared assertions, plus 37 lite assertions; the four
  pre-existing Unicode/RE2 fixture exclusions remain explicitly reported
- 157 mock netlink assertions and 18 nft CLI tests
- All 12 loopback integration tests, covering UDP/TCP, fallback, malformed
  clients, repeated connections, timeout/error paths, cache, and lazy refresh
- 72 Python verifier/build/staging tests

The first build omitted the existing 1 MiB musl stack flag and its DNS fixture
overflowed the smaller musl default thread stack. That failed evidence was
retained; final A/B builds and the package recipe explicitly preserve the flag.
No application-source workaround or removal of test cases was made.

## Package status and limitations

The opt-in recipe, frozen-source staging helper, and rootfs ELF checker are
implemented and the **actual official SDK APK build passed**. Its missing host
prerequisites were downloaded from the official Debian repository and extracted
only into the experiment after the user explicitly approved the retry. No
system package installation was performed. The earlier cancelled operation and
failed prerequisite log are retained separately.

Final local package: `diversion-dns-c-lite-0.2.0-r1.apk`, architecture
`aarch64_cortex-a53`, with the SDK's own target flags, hardening and `sstrip -z`:

| Quantity | Bytes |
| --- | ---: |
| Compressed APK archive | 33,569 |
| Final executable payload | 65,537 |
| OpenWrt file-list payload | 31 |
| APK declared installed payload size | 65,568 |
| Additional shared-library payload for the reference firmware | 0 |

The declared installed size is the sum of payload bytes, not a measurement of
flash block use, package-database growth, or compressed overlay space. The final
SDK executable is distinct from the controlled 64,272-byte A/B executable:
SDK hardening and package stripping differ. Do not mix the two measurements.

APK SHA256:
`c4e4e144a127d2b286d49188315be527ce48ec964f7413e7db03830a5f1d1270`

Final executable SHA256:
`a1d76d7dd42ea4beb3d68f8f9a785b87bde4ddc55257fbf1913d4b42466891ba`

The package is unsigned local experimental output. `apk verify` checked content
integrity with unsigned input explicitly allowed; no publisher-signature or
repository-trust claim is made. It was extracted locally, not installed.
Metadata declares exactly `libc` and `libpthread`; both are already installed
in the reference firmware. The only dynamic library remains `libc.so`, with
102 strong imports present in the extracted firmware runtime (the additional
import versus the controlled build comes from SDK stack hardening). The 1 MiB
non-executable default-stack request is preserved.

The **extracted final package ELF** passed all 12 loopback integration tests
under QEMU using the reference firmware libc. Separately, the full application,
five C units, domain fixtures, 157 mock netlink assertions, 18 nft CLI checks and
12 integrations were rebuilt and passed with the exact SDK package flags. That
rebuilt application's final `sstrip -z` hash exactly matches the packaged ELF.
This covers SDK hardening as well as the earlier controlled A/B profile.

No native hardware execution,
kernel nftables acceptance, sustained load, throughput/latency, stack high-water
or RSS benchmark was performed. QEMU loopback success does not establish those.

## Local raw evidence

Kept in the isolated checkout's ignored `.build/` tree:

- `firmware/`: verified ZIP, selected image/buildinfo, extracted rootfs libraries
- `tools/`: checksum-verified official toolchain and SDK archives
- `arm64-stack1m-{static,dynamic}/`: final controlled application/test ELF files
- `evidence/arm64-qemu-stack1m-*-functional.log`: complete functional results
- `evidence/elf-rootfs-check.json`: dependency and symbol comparison
- `evidence/dynamic-comparison.json`: flags, file hashes and exact byte counts
- `evidence/dynamic.map`: complete linked inputs; replay exactly matches the ELF
- `evidence/sdk-*.log`: package prerequisite result, including failed attempts
- `evidence/apk-result.json`, `apk-metadata.txt`, `apk-elf-rootfs-check.json`:
  final archive, payload, declared size and dependency verification
- `evidence/apk-payload-functional.log`: actual extracted payload integration tests
- `evidence/sdk-profile-full-*`: complete SDK-flag functional rerun and hash match
- `deliverables/`: final APK, checksum list and package verification summary

The SDK package path is deliberately separate from normal release packaging.
