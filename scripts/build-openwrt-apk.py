#!/usr/bin/env python3
"""Build/test a frozen, unsigned OpenWrt APK; never install or configure a router.

Only verified download archives are reusable. SDK, target objects, PCRE2 reference,
package extraction and output directories must be fresh for every invocation.
"""
import argparse
import difflib
import gzip
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / "packaging/openwrt/targets.json").read_text())
PCRE2_SHA256 = "ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888"
TESTS = ["dns_test", "cache_domain_test", "fixed_config_test", "fixed_engine_test",
         "nft_netlink_test", "domain_driver", "nft_cli_driver"]
PAYLOAD = {"usr/sbin/diversion-dns-c-lite", "lib/apk/packages/diversion-dns-c-lite.list"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def record(path):
    path = Path(path)
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_script(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def disable_unused_sdk_keys(sdk):
    """Pinned SDK has two unconditional key dependencies even with signing off."""
    path = sdk / "package/Makefile"
    original = path.read_text()
    names = "$(BUILD_KEY_APK_SEC) $(BUILD_KEY_APK_PUB)"
    before = ["  $(curdir)//compile += $(curdir)/system/apk/host/compile " + names,
              "  $(curdir)//compile += " + names]
    dependencies = [line for line in original.splitlines()
                    if "$(curdir)" in line and "$(BUILD_KEY_APK_" in line]
    require(sorted(dependencies) == sorted(before), "unexpected SDK key dependency; review SDK update")
    updated = original
    for line in before:
        require(updated.count(line + "\n") == 1, "unexpected SDK key dependency; review SDK update")
        updated = updated.replace(line + "\n", line.replace(names, "$(if $(CONFIG_SIGNED_PACKAGES)," + names + ")") + "\n")
    path.write_text(updated)
    return "".join(difflib.unified_diff(original.splitlines(True), updated.splitlines(True),
                                        "SDK/package/Makefile.orig", "SDK/package/Makefile"))


def no_signing_keys(sdk):
    # Check names only. Do not read, reuse, create, delete or upload credentials.
    require(not any(sdk.glob("*key*.pem")) and not any(sdk.glob("key-build*")),
            "unexpected signing key in SDK; stop without reading it")


def package_files(metadata, arch):
    info = metadata["info"]
    require(info["name"] == "diversion-dns-c-lite", "wrong package name")
    require(info["arch"] == arch, "wrong APK architecture")
    require(set(info["depends"]) == {"libc", "libpthread"}, "unexpected package dependencies")
    require(type(info["installed-size"]) is int and info["installed-size"] >= 0,
            "invalid APK installed size")
    files = {}
    directories = set()
    allowed_directories = {"", "lib", "lib/apk", "lib/apk/packages", "usr", "usr/sbin"}
    for directory in metadata["paths"]:
        name = directory.get("name", "")
        require(not name.startswith("/") and ".." not in Path(name).parts,
                "unsafe APK directory")
        require(name in allowed_directories and name not in directories, "unexpected/duplicate APK directory")
        require(directory["acl"]["mode"] == 0o755, "unexpected APK directory mode")
        directories.add(name)
        for item in directory.get("files", []):
            leaf = item["name"]
            require(leaf not in {"", ".", ".."} and "/" not in leaf, "unsafe APK filename")
            path = str(Path(name) / leaf)
            require(path in PAYLOAD and path not in files, "unexpected/duplicate APK payload")
            require(not item.get("target"), "APK symlink not permitted")
            require(re.fullmatch(r"[0-9a-f]{64}", item["hash"]) is not None, "invalid APK content hash")
            require(item["acl"]["mode"] == (0o755 if path.startswith("usr/") else 0o644),
                    "unexpected APK file mode")
            require(type(item["size"]) is int and item["size"] >= 0, "invalid APK file size")
            files[path] = {"bytes": item["size"], "sha256": item["hash"]}
    require(set(files) == PAYLOAD, "APK payload whitelist mismatch")
    require(sum(item["bytes"] for item in files.values()) == info["installed-size"],
            "APK installed-size mismatch")
    # OpenWrt's stock postinst/prerm bookkeeping exists, but is never executed.
    require(not any("/etc/init.d" in value for value in metadata.get("scripts", {}).values()),
            "unexpected service script")
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=TARGETS, required=True)
    parser.add_argument("--sdk-archive", type=Path, required=True)
    parser.add_argument("--pcre2-archive", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-ref", default="HEAD")
    parser.add_argument("--qemu", type=Path, help="optional existing emulator path for local testing")
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    require(1 <= args.jobs <= 32, "jobs must be 1..32")
    target = TARGETS[args.arch]
    require(digest(args.sdk_archive) == target["sdk_sha256"], "SDK SHA256 mismatch")
    require(digest(args.pcre2_archive) == PCRE2_SHA256, "PCRE2 SHA256 mismatch")
    commit = subprocess.check_output(["git", "rev-parse", args.source_ref + "^{commit}"], cwd=ROOT, text=True).strip()
    if os.environ.get("GITHUB_SHA"):
        require(commit == os.environ["GITHUB_SHA"], "source commit differs from workflow head")
    # Helpers and recipe must correspond to the same frozen commit as the C code.
    for name in ["scripts/build-openwrt-apk.py", "scripts/check-openwrt-elf.py",
                 "scripts/stage-openwrt-package.py", "packaging/openwrt/Makefile",
                 "packaging/openwrt/targets.json", "c/Makefile", "c/main.c", "VERSION"]:
        expected = subprocess.check_output(["git", "show", commit + ":" + name], cwd=ROOT)
        require((ROOT / name).read_bytes() == expected, "uncommitted build input: " + name)
    version = (ROOT / "VERSION").read_text().strip()
    require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version), "invalid application version")
    recipe = (ROOT / "packaging/openwrt/Makefile").read_text()
    require(f"PKG_VERSION:={version}\n" in recipe and "PKG_RELEASE:=1\n" in recipe,
            "recipe version differs from application version")
    package_version = version + "-r1"
    work, out = args.work.resolve(), args.output.resolve()
    require(not work.exists() and not out.exists(), "fresh work and output directories required")
    work.mkdir(parents=True)
    out.mkdir(parents=True)
    logs = out / "logs"
    logs.mkdir()
    env = os.environ.copy()
    for name in ["CC", "AR", "RANLIB", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "LDLIBS",
                 "MAKEFLAGS", "MFLAGS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH",
                 "CONFIG_SITE", "PYTHONOPTIMIZE"]:
        env.pop(name, None)
    env.update(LC_ALL="C", LANG="C", PYTHONDONTWRITEBYTECODE="1")
    state = {"status": "running", "architecture": args.arch, "target": target,
             "source_commit": commit, "source_tree": subprocess.check_output(["git", "rev-parse", commit + "^{tree}"], cwd=ROOT, text=True).strip(),
             "github": {key: os.environ.get(key) for key in ["GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_SHA"]},
             "sdk_archive": record(args.sdk_archive), "commands": [],
             "application_version": version, "package_version": package_version,
             "unsigned": True, "runtime_scope": "official SDK musl runtime under QEMU; not installed firmware or device acceptance",
             "not_tested": ["router installation", "real kernel nftables", "hardware compatibility", "RSS/QPS", "sustained stability", "actual flash increment"]}
    def save():
        write_json(out / "buildinfo.json", state)
    def run(name, command, cwd=ROOT, timeout=900, check=True, extra_env=None):
        command = list(map(str, command))
        start = time.monotonic()
        try:
            result = subprocess.run(command, cwd=cwd, env={**env, **(extra_env or {})},
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raw = (error.stdout or b"").decode(errors="replace")
            (logs / (name + ".log")).write_text(shlex.join(command) + "\n" + raw + "\nTIMEOUT\n")
            state["commands"].append({"name": name, "argv": command, "exit_code": None,
                                      "timed_out": True, "timeout_seconds": timeout})
            save()
            raise
        raw = result.stdout.decode(errors="replace")
        (logs / (name + ".log")).write_text(shlex.join(command) + "\n" + raw)
        state["commands"].append({"name": name, "argv": command, "exit_code": result.returncode,
                                  "duration_seconds": round(time.monotonic() - start, 3)})
        save()
        print(f"{name}: exit {result.returncode}", flush=True)
        require(not check or result.returncode == 0, f"{name} failed; see {logs / (name + '.log')}")
        return raw, result.returncode
    save()
    try:
        run("extract-sdk", ["tar", "--zstd", "-xf", args.sdk_archive.resolve(), "-C", work])
        sdk = work / target["sdk_filename"].removesuffix(".tar.zst")
        require(sdk.is_dir(), "SDK top-level path mismatch")
        no_signing_keys(sdk)
        (logs / "sdk-no-unused-signing-keys.patch").write_text(disable_unused_sdk_keys(sdk))
        staged = sdk / "package/diversion-dns-c-lite"
        manifest = load_script("stage-openwrt-package").stage(staged, commit)
        write_json(out / "source-manifest.json", manifest)
        archive = subprocess.check_output(["git", "archive", "--format=tar", commit], cwd=ROOT)
        source = work / "source"
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(source, filter="data")
        with (out / ("source-" + commit + ".tar.gz")).open("wb") as stream:
            with gzip.GzipFile(fileobj=stream, mode="wb", mtime=0) as compressed:
                compressed.write(archive)
        with (sdk / ".config").open("a") as stream:
            stream.write("\n# CONFIG_SIGNED_PACKAGES is not set\n# CONFIG_AUTOREMOVE is not set\n"
                         "# CONFIG_ALL_NONSHARED is not set\n# CONFIG_ALL_KMODS is not set\n"
                         "# CONFIG_CCACHE is not set\nCONFIG_PACKAGE_diversion-dns-c-lite=m\n")
        # Optional local rootless ncurses headers are only passed to host defconfig.
        host_env = {name: os.environ[name] for name in ["CPATH", "LIBRARY_PATH"] if name in os.environ}
        run("sdk-defconfig", ["make", "-C", sdk, "defconfig"], extra_env=host_env)
        config = (sdk / ".config").read_text()
        require("# CONFIG_SIGNED_PACKAGES is not set" in config, "SDK signing unexpectedly enabled")
        require("# CONFIG_AUTOREMOVE is not set" in config, "SDK would remove test evidence")
        require("CONFIG_PACKAGE_diversion-dns-c-lite=m" in config, "package not selected")
        (out / "sdk.config").write_text(config)
        run("sdk-build", ["make", "-C", sdk, "-j" + str(args.jobs), "package/diversion-dns-c-lite/compile",
                          "V=s", "DIVERSION_BUILD_TESTS=1"], timeout=1800)
        no_signing_keys(sdk)
        toolchain, = (sdk / "staging_dir").glob("toolchain-*")
        prefix = toolchain / "bin" / target["compiler_prefix"]
        compiler = Path(str(prefix) + "-gcc")
        env["STAGING_DIR"] = str(sdk / "staging_dir")
        state["compiler"] = run("compiler-version", [compiler, "--version"])[0].splitlines()[0]
        state["compiler_binary"] = record(compiler.parent / ("." + compiler.name + ".bin"))
        state["sdk_libc"] = record(toolchain / "lib/libc.so")
        if args.arch == "mipsel_24kc":
            atomic = subprocess.check_output([compiler, "-print-file-name=libatomic.a"], env=env, text=True).strip()
            state["static_libatomic"] = record(atomic)
        lines = (logs / "sdk-build.log").read_text().splitlines()
        flags_line = next(line for line in lines if line.startswith("make ") and "REGEX_BACKEND=posix-lite" in line)
        state["build_flags"] = {field.split("=", 1)[0]: field.split("=", 1)[1] for field in shlex.split(flags_line)
                                if field.startswith(("CFLAGS=", "LDFLAGS=", "EXTRA_LDLIBS="))}
        require(all(flag in state["build_flags"]["CFLAGS"] for flag in
                    ["-Os", "-UNDEBUG", "-flto", "-fstack-protector", "-D_FORTIFY_SOURCE=1",
                     "-Wformat", "-Werror=format-security", "-Wl,-z,now", "-Wl,-z,relro"]),
                "required SDK optimization, hardening or assertions missing")
        require(all(flag in state["build_flags"]["LDFLAGS"] for flag in
                    ["--gc-sections", "-static-libgcc", "-Wl,-z,stack-size=1048576"]),
                "required SDK linker policy missing")
        apks = list((sdk / "bin/packages" / args.arch).rglob("diversion-dns-c-lite-*.apk"))
        require(len(apks) == 1, "expected exactly one built APK")
        apk = out / (apks[0].stem + "_" + args.arch + "_" + commit[:12] + ".apk")
        shutil.copyfile(apks[0], apk)
        state["apk"] = {"filename": apk.name, **record(apk)}
        apktool = sdk / "staging_dir/host/bin/apk"
        raw, _ = run("apk-metadata", [apktool, "adbdump", "--format", "json", apk])
        metadata = json.loads(raw)
        write_json(out / "apk-metadata.json", metadata)
        require(metadata["info"].get("version") == package_version, "APK version mismatch")
        expected_files = package_files(metadata, args.arch)
        empty_keys = work / "empty-trust"
        empty_keys.mkdir()
        raw, code = run("apk-untrusted-as-expected", [apktool, "verify", "--keys-dir", empty_keys, "--no-network", apk], check=False)
        require(code != 0 and "UNTRUSTED" in raw.upper(), "unsigned APK unexpectedly trusted or verification failed for another reason")
        # This exception is strictly offline read/extract of our freshly built hash-
        # checked package. No add/install, scripts, repository or trust changes.
        run("apk-integrity", [apktool, "verify", "--allow-untrusted", "--keys-dir", empty_keys, "--no-network", apk])
        extracted = work / "package-extracted"
        extracted.mkdir()
        run("apk-extract", [apktool, "extract", "--allow-untrusted", "--keys-dir", empty_keys, "--no-network",
                            "--no-chown", "--destination", extracted, apk])
        require(not any(path.is_symlink() for path in extracted.rglob("*")), "unexpected extracted symlink")
        actual_files = {str(path.relative_to(extracted)): record(path) for path in extracted.rglob("*") if path.is_file()}
        require(actual_files == expected_files, "extracted APK file hashes/whitelist mismatch")
        binary = extracted / "usr/sbin/diversion-dns-c-lite"
        checker = load_script("check-openwrt-elf")
        state["elf"] = checker.check(binary, toolchain, args.arch)
        write_json(out / "elf-sdk-runtime.json", state["elf"])
        build, = (sdk / "build_dir").glob("target-*/diversion-dns-c-lite-*/build-openwrt")
        # Independently strip the application built alongside the drivers, then
        # compare every byte against the final APK payload before executing it.
        rebuilt = work / "rebuilt-stripped-app"
        shutil.copyfile(build / "mosdns-c", rebuilt)
        run("strip-rebuilt", [str(prefix) + "-strip", "--strip-all", rebuilt])
        run("sstrip-rebuilt", [sdk / "staging_dir/host/bin/sstrip", "-z", rebuilt])
        require(record(rebuilt) == record(binary), "same-SDK test application differs from APK payload")
        state["same_sdk_application_matches_apk"] = True
        qemu = args.qemu.resolve() if args.qemu else Path(shutil.which(target["qemu"]) or "missing-qemu")
        state["qemu"] = {"version": run("qemu-version", [qemu, "--version"])[0].splitlines()[0], **record(qemu)}
        wrappers = work / "wrappers"
        wrappers.mkdir()
        for name in TESTS + ["packaged-app"]:
            executable = binary if name == "packaged-app" else build / "tests" / name
            require(executable.is_file(), "missing same-SDK test binary: " + name)
            path = wrappers / name
            path.write_text("#!/bin/sh\nexec " + shlex.join([str(qemu), "-L", str(toolchain), str(executable)]) + ' "$@"\n')
            path.chmod(0o755)
        version_output, _ = run("apk-version", [wrappers / "packaged-app", "version"])
        require(version_output.strip() == f"mosdns-c {version} fixed-splitter", "APK CLI version mismatch")
        for name in TESTS[:5]:
            run("qemu-" + name, [wrappers / name])
        run("qemu-domain-fixture", [sys.executable, source / "c/tests/domain_fixture.py", wrappers / "domain_driver", "--backend", "posix-lite"])
        run("qemu-nft-cli", [sys.executable, source / "c/tests/nft_cli_test.py", "--driver", wrappers / "nft_cli_driver", "--output", out / "nft-cli"])
        run("qemu-final-apk-integration", [sys.executable, source / "c/tests/fixed_integration.py", wrappers / "packaged-app"])
        state["host_compiler"] = run("host-compiler-version", ["cc", "--version"])[0].splitlines()[0]
        state["host"] = run("host-uname", ["uname", "-a"])[0].strip()
        native = work / "pcre2-reference"
        run("native-pcre2-build", [sys.executable, source / "scripts/build-native-pcre2.py", "--archive", args.pcre2_archive.resolve(), "--output", native, "--jobs", str(args.jobs)])
        reference = work / "native-reference"
        run("native-reference-drivers", ["make", "-C", source / "c", "-j" + str(args.jobs), "CC=cc", "BUILD=" + str(reference),
             "REGEX_BACKEND=pcre2", "PCRE2_CFLAGS=-I" + str(native / "include"), "PCRE2_LIB=" + str(native / "lib/libpcre2-8.a"),
             "CFLAGS=-Os -flto -UNDEBUG -std=c11 -Wall -Wextra -Wpedantic -Wno-error=misleading-indentation -pthread",
             str(reference / "tests/domain_driver"), str(reference / "tests/cache_domain_test")])
        run("native-reference-budget-unit", [reference / "tests/cache_domain_test"])
        run("qemu-pcre2-differential", [sys.executable, source / "c/tests/regex_differential.py", "--pcre2", reference / "tests/domain_driver",
             "--posix-lite", wrappers / "domain_driver", "--output", out / "regex-differential.json"])
        require("43200 matches passed" in (logs / "qemu-cache_domain_test.log").read_text(), "concurrency corpus missing")
        require('"assertions":157' in (logs / "qemu-nft_netlink_test.log").read_text(), "netlink corpus missing")
        nft = json.loads((out / "nft-cli/result.json").read_text())
        require(nft["ok"] and len(nft["checks"]) == 30 and all(item["passed"] for item in nft["checks"]), "nft CLI corpus changed or failed")
        require("Ran 12 tests" in (logs / "qemu-final-apk-integration.log").read_text(), "final APK integration corpus missing")
        differential = json.loads((out / "regex-differential.json").read_text())
        require(differential["portable_comparisons"] == 81089 and differential["unexpected_differences"] == 0, "differential corpus changed or failed")
        state["tests"] = {"final_apk_loopback_integration": 12, "netlink_mock_assertions": 157, "nft_cli_checks": 30,
                          "regex_concurrent_matches": 43200, "portable_regex_comparisons": 81089,
                          "unexpected_regex_differences": 0, "known_budget_differences": 2,
                          "reference": "native PCRE2 10.48 no-Unicode/no-JIT built from same commit; not target performance"}
        state["pcre2_reference"] = {"driver": record(reference / "tests/domain_driver"), "archive_sha256": PCRE2_SHA256}
        shutil.copyfile(native / "manifest.json", out / "pcre2-reference-build.json")
        for name, expected_hash in manifest["source_files_sha256"].items():
            require(digest(staged / "src" / name) == expected_hash, "staged source changed")
        require(digest(apk) == state["apk"]["sha256"], "APK changed during verification")
        no_signing_keys(sdk)
        state["signing_keys_created"] = False
        state["status"] = "passed"
        save()
        shutil.copyfile(ROOT / "LICENSE", out / "LICENSE")
        (out / "README.txt").write_text(
            f"Experimental unsigned POSIX-lite APK: {args.arch}, OpenWrt {target['openwrt_version']} ({target['target']})\n"
            f"Frozen source: {commit}\nAPK: {state['apk']['bytes']} bytes\nELF payload: {binary.stat().st_size} bytes\n"
            "Verify SHA256SUMS before inspecting files. Checksums verify content, not publisher identity.\n"
            "This unsigned APK is not trusted by default. No signing key, installation instruction, trust change or deployment is included.\n"
            "Payload: /usr/sbin/diversion-dns-c-lite and OpenWrt package bookkeeping only; no config/init/LuCI/autostart.\n"
            "Dependencies: libc and libpthread. Final ELF needs only libc.so; MIPS static libatomic helpers are embedded.\n"
            "The libpthread package marker may still need a matching package repository even though musl exports pthread symbols.\n"
            "Tests execute the extracted APK under QEMU with the official SDK libc, not a router's installed/reduced libc.\n"
            "CPU match alone is insufficient. Never replace libc to make this package work. See c/REGEX-POSIX-LITE.md in the source.\n"
            "No real kernel nftables, RSS/QPS, actual flash increment or hardware/stability acceptance is established.\n"
            "Known PCRE2/lite syntax and two operational-budget differences remain explicit in the logs.\n"
            "GCC runtime portions: GPLv3 with GCC Runtime Library Exception 3.1.\n"
            "https://www.gnu.org/licenses/gcc-exception-3.1.html\n"
            "GCC 14.3.0 source: https://gcc.gnu.org/git/?p=gcc.git;a=tree;hb=releases/gcc-14.3.0\n")
        paths = sorted(path for path in out.rglob("*") if path.is_file())
        (out / "SHA256SUMS").write_text("".join(f"{digest(path)}  {path.relative_to(out)}\n" for path in paths))
        print(json.dumps({"status": "passed", "output": str(out), "apk": state["apk"], "elf": state["elf"]}), flush=True)
    except Exception as error:
        state["status"] = "failed"
        state["error"] = str(error)
        save()
        raise


if __name__ == "__main__":
    main()
