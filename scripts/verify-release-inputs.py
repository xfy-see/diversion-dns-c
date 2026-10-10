#!/usr/bin/env python3
"""Read-only v0.1.0 APK evidence verifier; never compiles or executes payloads.

Precondition: the caller has authenticated the workflow head/run/attempt and
verified the downloaded Actions ZIP against GitHub's artifact SHA256 before
safely extracting it. SHA256SUMS alone does not authenticate the publisher.

The APK container, ELF and SDK runtime were independently inspected in the
matrix job. This helper binds that evidence to the authenticated artifact and
Git source; it does not re-extract the APK, rerun QEMU, or establish device,
kernel, installation, performance, flash-size or sustained-stability results.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import math
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tarfile
import zlib

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.1.0"
PACKAGE_VERSION = VERSION + "-r1"
REPOSITORY = "xfy-see/diversion-dns-c"
APP = "usr/sbin/diversion-dns-c-lite"
LIMIT = 400 * 1024 * 1024
FILE_LIMIT = 64 * 1024 * 1024
COMMANDS = (
    "extract-sdk", "sdk-defconfig", "sdk-build", "compiler-version",
    "apk-metadata", "apk-untrusted-as-expected", "apk-integrity", "apk-extract",
    "strip-rebuilt", "sstrip-rebuilt", "qemu-version", "apk-version",
    "qemu-dns_test", "qemu-cache_domain_test", "qemu-fixed_config_test",
    "qemu-fixed_engine_test", "qemu-nft_netlink_test", "qemu-domain-fixture",
    "qemu-nft-cli", "qemu-final-apk-integration", "host-compiler-version",
    "host-uname", "native-pcre2-build", "native-reference-drivers",
    "native-reference-budget-unit", "qemu-pcre2-differential",
)
# Each tuple is the expected driver exit and the number of recorded mock calls.
NFT_CASES = {
    **{name: (0, 2) for name in ("ipv4-plain", "ipv4-interval", "ipv6-plain",
       "ipv6-interval", "underscore-name", "maximum-name")},
    "no-answer-does-not-spawn": (0, 0),
    **{"reject-" + name: (3, 0) for name in ("table-digit-first", "set-digit-first",
       "hyphen-first", "quote", "semicolon", "slash", "backslash", "too-long")},
    "update-nonzero-exit": (4, 2), "reject-malformed-metadata": (4, 1),
    "update-bounded-timeout": (4, 2),
}
TEST_COUNTS = {"final_apk_loopback_integration": 12, "netlink_mock_assertions": 157,
               "nft_cli_checks": 18, "regex_concurrent_matches": 43200,
               "portable_regex_comparisons": 81089, "unexpected_regex_differences": 0,
               "known_budget_differences": 2}
LIMITATIONS = (__doc__.split("The APK container", 1)[1].strip())
LIMITATIONS = "The APK container " + LIMITATIONS


def require(condition, message):
    if not condition:
        raise ValueError(message)


def load_helper(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


builder = load_helper("build-openwrt-apk")
elf_checker = load_helper("check-openwrt-elf")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    require(isinstance(name, str), "non-string artifact path")
    path = PurePosixPath(name)
    require(name not in ("", ".") and not path.is_absolute() and ".." not in path.parts
            and str(path) == name and "\\" not in name and not any(ord(c) < 32 for c in name),
            "unsafe artifact path: " + repr(name))
    return name


def json_value(raw, label):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key in " + label + ": " + key)
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError("non-finite JSON: " + label)))
    except (json.JSONDecodeError, UnicodeError) as error:
        raise ValueError("invalid JSON in " + label + ": " + str(error)) from error


def record_valid(value, label):
    require(isinstance(value, dict) and type(value.get("bytes")) is int and value["bytes"] > 0
            and isinstance(value.get("sha256"), str)
            and re.fullmatch("[0-9a-f]{64}", value["sha256"]) is not None,
            "invalid file record: " + label)


def read_files(folder):
    require(folder.is_dir() and not folder.is_symlink(), "artifact folder missing or symlink")
    files, total = {}, 0
    for path in sorted(folder.rglob("*")):
        mode = path.lstat().st_mode
        require(stat.S_ISREG(mode) or stat.S_ISDIR(mode), "non-regular artifact entry: " + str(path))
        name = safe_name(path.relative_to(folder).as_posix())
        if stat.S_ISDIR(mode):
            require(name in {"logs", "nft-cli"}, "unexpected artifact directory: " + name)
            continue
        size = path.stat().st_size
        total += size
        require(size <= FILE_LIMIT and total <= LIMIT and len(files) < 500,
                "artifact exceeds size/member bound")
        files[name] = path.read_bytes()
    require("SHA256SUMS" in files, "missing SHA256SUMS")
    checksums = {}
    for line in files["SHA256SUMS"].decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        require(match is not None, "malformed SHA256SUMS line")
        digest, name = match.groups()
        safe_name(name)
        require(name != "SHA256SUMS" and name not in checksums, "duplicate/self checksum entry")
        checksums[name] = digest
    require(set(checksums) == set(files) - {"SHA256SUMS"}, "SHA256SUMS file membership differs")
    for name, expected in checksums.items():
        require(sha256(files[name]) == expected, "SHA256SUMS digest differs: " + name)
    return files


def verify_source(files, commit, checkout, state):
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=checkout)
    require(git("rev-parse", "--verify", commit + "^{commit}").decode().strip() == commit,
            "Git commit differs")
    require(git("rev-parse", commit + "^{tree}").decode().strip() == state["source_tree"],
            "Git source tree differs")
    archive_name = "source-" + commit + ".tar.gz"
    with gzip.GzipFile(fileobj=io.BytesIO(files[archive_name])) as stream:
        archive = stream.read(LIMIT + 1)
    require(len(archive) <= LIMIT, "source archive exceeds bound")
    require(archive == git("archive", "--format=tar", commit), "source archive differs from git archive bytes")
    source = {}
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        names = set()
        for member in tar:
            name = safe_name(member.name.rstrip("/") if member.isdir() else member.name)
            require(name not in names, "duplicate source archive member")
            names.add(name)
            require(member.isdir() or member.isfile(), "non-regular Git source member")
            if member.isfile():
                source[name] = tar.extractfile(member).read()
    manifest = json_value(files["source-manifest.json"], "source-manifest.json")
    require(manifest["source_commit"] == commit, "staged source commit differs")
    expected = {name: sha256(data) for name, data in source.items()
                if name == "LICENSE" or name.startswith("c/")}
    require(manifest["source_files_sha256"] == expected and bool(expected), "staged C/source hashes differ")
    recipe = source["packaging/openwrt/Makefile"]
    require(manifest["recipe_sha256"] == sha256(recipe), "staged package recipe hash differs")
    require(source["VERSION"].strip() == VERSION.encode(), "source VERSION differs")
    require(re.findall(rb"(?m)^PKG_VERSION:=(.+)$", recipe) == [VERSION.encode()]
            and re.findall(rb"(?m)^PKG_RELEASE:=(.+)$", recipe) == [b"1"], "source package version differs")
    require(files["LICENSE"] == source["LICENSE"], "release LICENSE differs from source")
    targets = json_value(source["packaging/openwrt/targets.json"], "source targets")
    require(state["target"] == targets[state["architecture"]]
            == builder.TARGETS[state["architecture"]], "pinned SDK target differs")
    return source


def verify_commands(files, state, apk_name):
    rows = state["commands"]
    require(isinstance(rows, list) and [row["name"] for row in rows] == list(COMMANDS),
            "command sequence missing, duplicated or unexpected")
    commands, logs = {}, {}
    for row in rows:
        name, argv = row["name"], row["argv"]
        require(isinstance(argv, list) and bool(argv) and all(isinstance(v, str) and v for v in argv),
                "invalid command argv: " + name)
        require(type(row.get("exit_code")) is int and row["exit_code"] == (1 if name == "apk-untrusted-as-expected" else 0)
                and not row.get("timed_out"), "failed/timed-out command: " + name)
        require(type(row.get("duration_seconds")) in (int, float)
                and math.isfinite(row["duration_seconds"]) and row["duration_seconds"] >= 0,
                "invalid command duration: " + name)
        raw = files["logs/" + name + ".log"].decode("utf-8")
        first, separator, output = raw.partition("\n")
        require(separator and first == shlex.join(argv), "command/log argv differs: " + name)
        commands[name], logs[name] = argv, output
    apk_argv = commands["apk-metadata"]
    require(len(apk_argv) == 5 and apk_argv[1:4] == ["adbdump", "--format", "json"]
            and Path(apk_argv[-1]).name == apk_name, "APK metadata command target differs")
    apktool, apkpath = apk_argv[0], apk_argv[-1]
    untrusted = commands["apk-untrusted-as-expected"]
    require(len(untrusted) == 6 and untrusted[:3] == [apktool, "verify", "--keys-dir"]
            and untrusted[4:] == ["--no-network", apkpath], "unexpected unsigned verification command")
    trust = untrusted[3]
    require(commands["apk-integrity"] == [apktool, "verify", "--allow-untrusted", "--keys-dir", trust, "--no-network", apkpath],
            "APK integrity command differs")
    extraction = commands["apk-extract"]
    require(len(extraction) == 10 and extraction[:8] == [apktool, "extract", "--allow-untrusted", "--keys-dir", trust,
            "--no-network", "--no-chown", "--destination"] and extraction[-1] == apkpath,
            "APK extraction command differs")
    require(logs["apk-untrusted-as-expected"].strip() == apkpath + ": UNTRUSTED signature",
            "unsigned rejection missing or unrelated APK failure")
    wrapper = commands["apk-version"]
    require(len(wrapper) == 2 and wrapper[1] == "version" and Path(wrapper[0]).name == "packaged-app",
            "packaged application version command differs")
    wrappers = str(PurePosixPath(wrapper[0]).parent)
    require(commands["qemu-final-apk-integration"][2:] == [wrapper[0]]
            and commands["qemu-final-apk-integration"][1].endswith("/source/c/tests/fixed_integration.py"),
            "integration command does not test packaged application")
    for test in builder.TESTS[:5]:
        require(commands["qemu-" + test] == [wrappers + "/" + test], "same-SDK unit command differs: " + test)
    source_prefix = str(PurePosixPath(commands["qemu-final-apk-integration"][1]).parents[2])
    for name, script in (("qemu-domain-fixture", "domain_fixture.py"),
                         ("qemu-nft-cli", "nft_cli_test.py"),
                         ("qemu-pcre2-differential", "regex_differential.py")):
        require(commands[name][1] == source_prefix + "/c/tests/" + script,
                "test harness source path differs: " + name)
    require(commands["qemu-domain-fixture"][2:] == [wrappers + "/domain_driver", "--backend", "posix-lite"],
            "domain fixture does not test lite driver")
    require(commands["qemu-nft-cli"][2:] == ["--driver", wrappers + "/nft_cli_driver", "--output", str(PurePosixPath(apkpath).parent / "nft-cli")],
            "nft CLI driver/output differs")
    require(logs["apk-version"] == "mosdns-c " + VERSION + " fixed-splitter\n", "APK CLI version differs")
    return commands, logs


def verify_tests(files, state, source, commands, logs):
    require(all(type(state["tests"].get(key)) is int and state["tests"][key] == value
                for key, value in TEST_COUNTS.items()), "test summary counts differ")
    endings = {"qemu-dns_test": "dns/upstream tests passed",
               "qemu-cache_domain_test": "domain/cache/nftset parser tests passed",
               "qemu-fixed_config_test": "fixed config: strict keys, bounds, lists, diagnostics and rules preflight passed",
               "qemu-fixed_engine_test": "fixed engine: QNAME split, CNAME, cache+nft, A/AAAA, errors and lazy refresh passed"}
    for name, line in endings.items():
        require(logs[name].splitlines()[-1:] == [line], "missing successful unit evidence: " + name)
    require(re.findall(r"(?m)^shared frozen domain regex: 8 threads / (\d+) matches passed \([0-8] UTF-8 thread locales available\)$",
                       logs["qemu-cache_domain_test"]) == ["43200"], "regex concurrency count differs")
    require("POSIX-lite profile: 96 explicit syntax/complexity rejections; grammar, limits, ASCII and locale checks passed\n"
            in logs["qemu-cache_domain_test"], "POSIX-lite profile checks missing")
    require(json_value(logs["qemu-nft_netlink_test"], "netlink log")
            == {"passed": True, "assertions": 157, "sockets_used": False}, "netlink mock evidence differs")
    domain = logs["qemu-domain-fixture"]
    require("shared domain fixture: 11 cases / 70 assertions passed; 4 Unicode/RE2-specific cases explicitly skipped with reasons\n" in domain
            and domain.endswith("POSIX-lite profile: 7 byte/ASCII cases and 5 required Unicode rejections / 37 assertions passed\n"),
            "domain fixture counts differ")
    integration = logs["qemu-final-apk-integration"]
    expected_tests = re.findall(rb"(?m)^    def (test_[a-z0-9_]+)\(self\):", source["c/tests/fixed_integration.py"])
    actual_tests = re.findall(r"(?m)^(test_[a-z0-9_]+) \([^\n]+\) \.\.\. ok$", integration)
    require(len(expected_tests) == 12 and sorted(actual_tests) == sorted(name.decode() for name in expected_tests)
            and re.findall(r"(?m)^Ran (\d+) tests in [0-9.]+s$", integration) == ["12"]
            and integration.endswith("\nOK\n") and not re.search(r"(?m)^(?:FAILED|ERROR|FAIL|SKIPPED|OK \()", integration),
            "final APK integration corpus failed, skipped or differs")
    nft = json_value(files["nft-cli/result.json"], "nft-cli/result.json")
    require(nft["ok"] is True and nft["count"] == 18 and nft["sanitized"] is False
            and nft["device_or_kernel_evidence"] is False and nft["commands"] == []
            and nft["source_sha256"] == sha256(source["c/plugin/nftset.c"]), "nft CLI source/scope differs")
    require(len(nft["checks"]) == 18 and {row["label"] for row in nft["checks"]} == set(NFT_CASES), "nft CLI cases differ")
    for row in nft["checks"]:
        name = row["label"]
        require(row["passed"] is True and (row["exit"], row["calls"]) == NFT_CASES[name], "failed nft CLI check: " + name)
        if row["calls"]:
            calls = files["nft-cli/" + name + ".calls.jsonl"].splitlines()
            require(len(calls) == row["calls"] and all(isinstance(json_value(line, name), dict) for line in calls),
                    "nft CLI raw call count differs: " + name)
    require(json_value(logs["qemu-nft-cli"], "nft CLI log") == {"ok": True, "checks": 18, "sanitized": False, "device_or_kernel_evidence": False},
            "nft CLI log summary differs")
    differential = json_value(files["regex-differential.json"], "regex-differential.json")
    wanted = {"format_version": 1, "production_rules": 8, "production_assertions_per_backend": 72,
              "portable_rules": 131, "portable_comparisons": 81089, "unexpected_differences": 0,
              "operational_budget_difference_count": 2,
              "corpus_sha256": "2e605ee7c5d61d35e4c360653b60d3b0a6083b1cc3dc89c61661b244f864a968",
              "operational_budget_differences_verified": ["regexp:^(a|aa)+a{64}$", "regexp:^(a+)+a{64}$"]}
    require(all(differential.get(key) == value for key, value in wanted.items()), "regex differential corpus/counts differ")
    require(json_value(logs["qemu-pcre2-differential"].splitlines()[-1], "differential log") == differential,
            "raw differential result differs")
    require("production CN corpus: 8 unchanged rules / 72 assertions passed in both backends\n" in logs["qemu-pcre2-differential"]
            and "portable differential corpus: 131 rules / 81089 matching results agree\n" in logs["qemu-pcre2-differential"],
            "raw differential count evidence missing")
    require("PCRE2 operational budget: 2 direct MATCHLIMIT(-47) errors verified; bool API returns false\n"
            in logs["native-reference-budget-unit"], "PCRE2 budget error evidence missing")
    argv = commands["qemu-pcre2-differential"]
    require(argv[2:] == ["--pcre2", differential["pcre2_driver"], "--posix-lite", differential["posix_lite_driver"],
                         "--output", str(PurePosixPath(commands["apk-metadata"][-1]).parent / "regex-differential.json")]
            and differential["posix_lite_driver"] == commands["qemu-domain-fixture"][2],
            "differential driver/output differs")


def verify_elf(files, state, metadata, arch):
    payload = builder.package_files(metadata, arch)
    require(metadata["info"]["version"] == PACKAGE_VERSION, "APK package version differs")
    require(metadata["info"].get("license") == "GPL-3.0-or-later", "APK license differs")
    elf = json_value(files["elf-sdk-runtime.json"], "elf-sdk-runtime.json")
    require(elf == state["elf"], "ELF evidence copies differ")
    target = elf_checker.ARCHITECTURES[arch]
    require(elf["arch"] == arch and elf["elf"] == target["elf"] and elf["interpreter"] == target["interpreter"],
            "ELF architecture/interpreter differs")
    require({"bytes": elf["binary_bytes"], "sha256": elf["binary_sha256"]} == payload[APP], "ELF evidence differs from APK payload metadata")
    require(elf["libraries"] == {"libc.so": state["sdk_libc"]}
            and elf["missing_strong_symbols"] == [] and type(elf["strong_symbols_checked"]) is int
            and elf["strong_symbols_checked"] > 0, "ELF SDK runtime dependencies/symbols differ")
    require(elf["default_thread_stack_bytes"] == 1048576 and elf["stack_executable"] is False,
            "ELF requires non-executable 1 MiB thread stack")
    if arch == "mipsel_24kc":
        require((elf["isa"], elf["abi"], elf["float"], elf["gpr_bits"]) == ("MIPS32r2", "O32", "soft", 32), "MIPS ABI differs")
        abi = elf["abi_flags"]
        require(len(abi) == 11 and abi[:7] == [0, 32, 2, 1, 0, 0, 3] and abi[7] == 0
                and not abi[8] & ~0x400 and not abi[9] & ~1 and abi[10] == 0
                and type(elf["mips16"]) is bool, "MIPS ABI flags differ")
        record_valid(state["static_libatomic"], "static libatomic")


def _verify_apk(folder, commit, run_id, attempt, arch, checkout):
    require(isinstance(commit, str) and re.fullmatch("[0-9a-f]{40}", commit), "exact lowercase commit SHA required")
    require(type(run_id) is int and run_id > 0 and type(attempt) is int and attempt > 0,
            "positive integer run ID and attempt required")
    require(arch in builder.TARGETS, "unsupported APK architecture")
    files = read_files(Path(folder))
    state = json_value(files["buildinfo.json"], "buildinfo.json")
    require(state["source_commit"] == commit and state["architecture"] == arch
            and state["github"] == {"GITHUB_REPOSITORY": REPOSITORY, "GITHUB_RUN_ID": str(run_id),
                                    "GITHUB_RUN_ATTEMPT": str(attempt), "GITHUB_SHA": commit},
            "APK artifact commit/run/attempt/architecture identity differs")
    require(state["status"] == "passed" and "error" not in state and state["unsigned"] is True
            and state["signing_keys_created"] is False and state["same_sdk_application_matches_apk"] is True,
            "APK build failed, signed, created keys or mismatched tested application")
    require(state["application_version"] == VERSION and state["package_version"] == PACKAGE_VERSION,
            "buildinfo release version differs")
    apk_name = "diversion-dns-c-lite-" + PACKAGE_VERSION + "_" + arch + "_" + commit[:12] + ".apk"
    require(state["apk"]["filename"] == apk_name, "release APK filename differs")
    required = {"SHA256SUMS", apk_name, "source-" + commit + ".tar.gz", "LICENSE", "README.txt",
                "buildinfo.json", "apk-metadata.json", "source-manifest.json", "elf-sdk-runtime.json",
                "sdk.config", "regex-differential.json", "pcre2-reference-build.json",
                "logs/sdk-no-unused-signing-keys.patch", "nft-cli/result.json", "nft-cli/grammar-nft"}
    required.update("logs/" + name + ".log" for name in COMMANDS)
    for name, (_, calls) in NFT_CASES.items():
        required.update("nft-cli/" + name + suffix for suffix in (".stdout", ".stderr"))
        if calls:
            required.add("nft-cli/" + name + ".calls.jsonl")
    require(set(files) == required, "unexpected/missing release artifact files: " + repr(sorted(set(files) ^ required)))
    record_valid(state["apk"], "APK")
    require(state["apk"]["bytes"] == len(files[apk_name]) and state["apk"]["sha256"] == sha256(files[apk_name]), "APK file hash/size differs")
    source = verify_source(files, commit, Path(checkout), state)
    for name in ("sdk_archive", "sdk_libc", "compiler_binary", "qemu"):
        record_valid(state[name], name)
    require(state["sdk_archive"]["sha256"] == state["target"]["sdk_sha256"], "SDK archive digest differs")
    commands, logs = verify_commands(files, state, apk_name)
    metadata = json_value(files["apk-metadata.json"], "apk-metadata.json")
    require(metadata == json_value(logs["apk-metadata"], "APK metadata log"), "raw APK metadata differs")
    verify_elf(files, state, metadata, arch)
    config = files["sdk.config"].decode().splitlines()
    require(all(config.count(line) == 1 for line in ("# CONFIG_SIGNED_PACKAGES is not set",
            "# CONFIG_AUTOREMOVE is not set", "# CONFIG_CCACHE is not set", "CONFIG_PACKAGE_diversion-dns-c-lite=m"))
            and not any(line.startswith("CONFIG_SIGNED_PACKAGES=") for line in config), "SDK signing/cache/package configuration differs")
    flags = state["build_flags"]
    make_lines = [line for line in logs["sdk-build"].splitlines()
                  if line.startswith("make ") and "REGEX_BACKEND=posix-lite" in line]
    require(bool(make_lines), "raw SDK build flags missing")
    actual_flags = {field.split("=", 1)[0]: field.split("=", 1)[1]
                    for field in shlex.split(make_lines[0])
                    if field.startswith(("CFLAGS=", "LDFLAGS=", "EXTRA_LDLIBS="))}
    require(actual_flags == flags, "raw SDK build flags differ from buildinfo")
    for key, required_flags in {"CFLAGS": ("-Os", "-UNDEBUG", "-fstack-protector", "-D_FORTIFY_SOURCE=1", "-Wformat", "-Werror=format-security", "-Wl,-z,now", "-Wl,-z,relro"),
                               "LDFLAGS": ("-Wl,--gc-sections", "-static-libgcc", "-Wl,-z,stack-size=1048576")}.items():
        tokens = shlex.split(flags[key])
        require(all(flag in tokens for flag in required_flags)
                and any(flag == "-flto" or flag.startswith("-flto=") for flag in tokens)
                and "-DNDEBUG" not in tokens, "required build hardening/assertions missing: " + key)
    if arch == "mipsel_24kc":
        require(shlex.split(flags["EXTRA_LDLIBS"]) == ["-Wl,-Bstatic", "-latomic", "-Wl,-Bdynamic"], "MIPS static atomic linkage differs")
    else:
        require(flags["EXTRA_LDLIBS"] == "", "unexpected extra target libraries")
    verify_tests(files, state, source, commands, logs)
    reference = json_value(files["pcre2-reference-build.json"], "pcre2-reference-build.json")
    require(state["pcre2_reference"]["archive_sha256"] == reference["archive"]["sha256"] == builder.PCRE2_SHA256
            and reference["profile"] == "pcre2-8-no-unicode-no-jit" and reference["version"] == "10.48"
            and reference["profile_verified"] == "8-bit only, Unicode disabled, JIT disabled"
            and {"--disable-unicode", "--disable-jit", "--disable-shared", "--enable-static", "--disable-pcre2-16", "--disable-pcre2-32"} <= set(reference["configure_options"])
            and len(reference["commands"]) == 2 and all(type(row["exit_code"]) is int and row["exit_code"] == 0 for row in reference["commands"]),
            "PCRE2 reference build/profile evidence differs")
    record_valid(state["pcre2_reference"]["driver"], "PCRE2 driver")
    require(state["runtime_scope"] == "official SDK musl runtime under QEMU; not installed firmware or device acceptance"
            and set(state["not_tested"]) == {"router installation", "real kernel nftables", "hardware compatibility", "RSS/QPS", "sustained stability", "actual flash increment"},
            "APK verification scope was broadened")
    return state


def verify_apk(folder, commit, run_id, attempt, arch, checkout):
    """Verify authenticated matrix evidence and return its unchanged buildinfo.

    No APK, SDK or target code is executed. See module docstring for the required
    outer GitHub digest check and the limits of this evidence-only verification.
    """
    try:
        return _verify_apk(folder, commit, run_id, attempt, arch, checkout)
    except (KeyError, TypeError, IndexError, AttributeError, UnicodeError, OSError, EOFError,
            RecursionError, zlib.error, tarfile.TarError,
            subprocess.SubprocessError) as error:
        raise ValueError("malformed/missing release evidence: " + str(error)) from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-run-id", type=int, required=True)
    parser.add_argument("--expected-run-attempt", type=int, required=True)
    parser.add_argument("--arch", choices=builder.TARGETS, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    args = parser.parse_args()
    try:
        state = verify_apk(args.folder, args.expected_commit, args.expected_run_id,
                           args.expected_run_attempt, args.arch, args.checkout)
    except ValueError as error:
        parser.error(str(error))
    print(json.dumps({"completed": True, "commit": state["source_commit"],
                      "run_id": args.expected_run_id, "run_attempt": args.expected_run_attempt,
                      "arch": args.arch, "apk": state["apk"], "limits": LIMITATIONS}, sort_keys=True))


if __name__ == "__main__":
    main()
