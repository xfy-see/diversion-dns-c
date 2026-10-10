"""Adversarial release evidence contracts; synthetic bytes, Git and Python only.

No compiler, APK tool, SDK, QEMU or downloaded executable is invoked. These
fixtures exercise the evidence verifier, not the underlying package/runtime.
"""
import copy
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("release_inputs", ROOT / "scripts/verify-release-inputs.py")
verify = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verify)


def record(data=b"synthetic, never executed"):
    return {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}


class Evidence:
    def __init__(self, root, arch="aarch64_cortex-a53"):
        self.root, self.arch = root, arch
        self.checkout, self.folder = root / "checkout", root / "artifact"
        self.checkout.mkdir()
        self.folder.mkdir()
        self.source = {
            "VERSION": b"0.1.0\n", "LICENSE": b"synthetic license\n",
            "packaging/openwrt/Makefile": b"PKG_VERSION:=0.1.0\nPKG_RELEASE:=1\n",
            "packaging/openwrt/targets.json": (ROOT / "packaging/openwrt/targets.json").read_bytes(),
            "c/main.c": b"synthetic C source, never compiled\n",
            "c/plugin/nftset.c": b"synthetic NFT source, never compiled\n",
            "c/tests/fixed_integration.py": (ROOT / "c/tests/fixed_integration.py").read_bytes(),
        }
        for name, data in self.source.items():
            path = self.checkout / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "synthetic evidence fixture")
        self.commit = self.git("rev-parse", "HEAD").decode().strip()
        self.apk_name = "diversion-dns-c-lite-0.1.0-r1_" + arch + "_" + self.commit[:12] + ".apk"
        self.apkpath = "/ci/out/" + self.apk_name
        self.files = {"LICENSE": self.source["LICENSE"], "README.txt": b"Synthetic verifier fixture\n",
                      self.apk_name: b"not a real APK; never execute", "logs/sdk-no-unused-signing-keys.patch": b"synthetic patch\n",
                      "source-" + self.commit + ".tar.gz": gzip.compress(self.git("archive", "--format=tar", self.commit), mtime=0),
                      "sdk.config": b"# CONFIG_SIGNED_PACKAGES is not set\n# CONFIG_AUTOREMOVE is not set\n# CONFIG_CCACHE is not set\nCONFIG_PACKAGE_diversion-dns-c-lite=m\n",
                      "nft-cli/grammar-nft": b"synthetic, never executed\n"}
        self.commands = []
        self.outputs = {name: "" for name in verify.COMMANDS}
        for name in verify.COMMANDS:
            argv = ["synthetic-" + name]
            self.commands.append({"name": name, "argv": argv, "exit_code": 1 if name == "apk-untrusted-as-expected" else 0, "duration_seconds": 0.01})
        self.cmd = {row["name"]: row for row in self.commands}
        def argv(name, values):
            self.cmd[name]["argv"] = values
        argv("apk-metadata", ["/ci/apk", "adbdump", "--format", "json", self.apkpath])
        argv("apk-untrusted-as-expected", ["/ci/apk", "verify", "--keys-dir", "/ci/empty-trust", "--no-network", self.apkpath])
        argv("apk-integrity", ["/ci/apk", "verify", "--allow-untrusted", "--keys-dir", "/ci/empty-trust", "--no-network", self.apkpath])
        argv("apk-extract", ["/ci/apk", "extract", "--allow-untrusted", "--keys-dir", "/ci/empty-trust", "--no-network", "--no-chown", "--destination", "/ci/package-extracted", self.apkpath])
        argv("apk-version", ["/ci/wrappers/packaged-app", "version"])
        for name in verify.builder.TESTS[:5]:
            argv("qemu-" + name, ["/ci/wrappers/" + name])
        argv("qemu-domain-fixture", ["python3", "/ci/source/c/tests/domain_fixture.py", "/ci/wrappers/domain_driver", "--backend", "posix-lite"])
        argv("qemu-nft-cli", ["python3", "/ci/source/c/tests/nft_cli_test.py", "--driver", "/ci/wrappers/nft_cli_driver", "--output", "/ci/out/nft-cli"])
        argv("qemu-final-apk-integration", ["python3", "/ci/source/c/tests/fixed_integration.py", "/ci/wrappers/packaged-app"])
        argv("qemu-pcre2-differential", ["python3", "/ci/source/c/tests/regex_differential.py", "--pcre2", "/ci/reference/domain_driver", "--posix-lite", "/ci/wrappers/domain_driver", "--output", "/ci/out/regex-differential.json"])
        self.outputs.update({
            "apk-version": "mosdns-c 0.1.0 fixed-splitter\n",
            "apk-untrusted-as-expected": self.apkpath + ": UNTRUSTED signature\n",
            "qemu-dns_test": "dns/upstream tests passed\n",
            "qemu-fixed_config_test": "fixed config: strict keys, bounds, lists, diagnostics and rules preflight passed\n",
            "qemu-fixed_engine_test": "fixed engine: QNAME split, CNAME, cache+nft, A/AAAA, errors and lazy refresh passed\n",
            "qemu-cache_domain_test": "POSIX-lite profile: 96 explicit syntax/complexity rejections; grammar, limits, ASCII and locale checks passed\nshared frozen domain regex: 8 threads / 43200 matches passed (4 UTF-8 thread locales available)\ndomain/cache/nftset parser tests passed\n",
            "qemu-nft_netlink_test": '{"passed":true,"assertions":157,"sockets_used":false}\n',
            "qemu-domain-fixture": "shared domain fixture: 11 cases / 70 assertions passed; 4 Unicode/RE2-specific cases explicitly skipped with reasons\nPOSIX-lite profile: 7 byte/ASCII cases and 5 required Unicode rejections / 37 assertions passed\n",
            "native-reference-budget-unit": "PCRE2 operational budget: 2 direct MATCHLIMIT(-47) errors verified; bool API returns false\n",
            "qemu-nft-cli": '{"ok":true,"checks":30,"sanitized":false,"device_or_kernel_evidence":false}\n',
        })
        test_names = verify.re.findall(rb"(?m)^    def (test_[a-z0-9_]+)\(self\):", self.source["c/tests/fixed_integration.py"])
        self.outputs["qemu-final-apk-integration"] = "".join(name.decode() + " (__main__.FixedIntegration." + name.decode() + ") ... ok\n" for name in test_names) + "\nRan 12 tests in 1.234s\n\nOK\n"
        app_record, list_record = record(), record(b"/usr/sbin/diversion-dns-c-lite\n")
        metadata = {"info": {"name": "diversion-dns-c-lite", "arch": arch, "version": "0.1.0-r1", "license": "GPL-3.0-or-later",
                              "depends": ["libc", "libpthread"], "installed-size": app_record["bytes"] + list_record["bytes"]}, "paths": []}
        for name, item in ((verify.APP, app_record), ("lib/apk/packages/diversion-dns-c-lite.list", list_record)):
            metadata["paths"].append({"name": str(Path(name).parent), "acl": {"mode": 0o755}, "files": [
                {"name": Path(name).name, "hash": item["sha256"], "size": item["bytes"], "acl": {"mode": 0o755 if name == verify.APP else 0o644}}]})
        self.metadata = metadata
        elf = {"arch": arch, **{k: verify.elf_checker.ARCHITECTURES[arch][k] for k in ("elf", "interpreter")},
               "binary_bytes": app_record["bytes"], "binary_sha256": app_record["sha256"], "libraries": {"libc.so": record(b"libc")},
               "missing_strong_symbols": [], "strong_symbols_checked": 102, "default_thread_stack_bytes": 1048576, "stack_executable": False}
        if arch == "mipsel_24kc":
            elf.update(isa="MIPS32r2", abi="O32", float="soft", gpr_bits=32,
                       abi_flags=[0, 32, 2, 1, 0, 0, 3, 0, 1024, 1, 0], mips16=True)
        self.state = {"source_commit": self.commit, "source_tree": self.git("rev-parse", "HEAD^{tree}").decode().strip(), "architecture": arch,
                      "github": {"GITHUB_REPOSITORY": verify.REPOSITORY, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": self.commit},
                      "status": "passed", "unsigned": True, "signing_keys_created": False, "same_sdk_application_matches_apk": True,
                      "application_version": "0.1.0", "package_version": "0.1.0-r1", "apk": {"filename": self.apk_name, **record(self.files[self.apk_name])},
                      "target": verify.builder.TARGETS[arch], "commands": self.commands, "elf": elf, "tests": dict(verify.TEST_COUNTS),
                      "sdk_archive": {"bytes": 100, "sha256": verify.builder.TARGETS[arch]["sdk_sha256"]}, "sdk_libc": record(b"libc"),
                      "compiler_binary": record(), "qemu": record(), "static_libatomic": record(),
                      "build_flags": {"CFLAGS": "-Os -UNDEBUG -flto -fstack-protector -D_FORTIFY_SOURCE=1 -Wformat -Werror=format-security -Wl,-z,now -Wl,-z,relro",
                                      "LDFLAGS": "-Wl,--gc-sections -flto -static-libgcc -Wl,-z,stack-size=1048576",
                                      "EXTRA_LDLIBS": "-Wl,-Bstatic -latomic -Wl,-Bdynamic" if arch == "mipsel_24kc" else ""},
                      "pcre2_reference": {"archive_sha256": verify.builder.PCRE2_SHA256, "driver": record()},
                      "runtime_scope": "official SDK musl runtime under QEMU; not installed firmware or device acceptance",
                      "not_tested": ["router installation", "real kernel nftables", "hardware compatibility", "RSS/QPS", "sustained stability", "actual flash increment"]}
        self.manifest = {"source_commit": self.commit, "recipe_sha256": record(self.source["packaging/openwrt/Makefile"])["sha256"],
                         "source_files_sha256": {n: record(d)["sha256"] for n, d in self.source.items() if n == "LICENSE" or n.startswith("c/")}}
        self.nft = {"ok": True, "count": 30, "sanitized": False, "device_or_kernel_evidence": False, "commands": [],
                    "source_sha256": record(self.source["c/plugin/nftset.c"])["sha256"], "checks": []}
        for name, (code, calls) in verify.NFT_CASES.items():
            self.nft["checks"].append({"label": name, "exit": code, "calls": calls, "passed": True})
            for suffix in (".stdout", ".stderr"):
                self.files["nft-cli/" + name + suffix] = b""
            if calls:
                self.files["nft-cli/" + name + ".calls.jsonl"] = b"{}\n" * calls
        self.differential = {"format_version": 1, "production_rules": 8, "production_assertions_per_backend": 72,
                             "portable_rules": 131, "portable_comparisons": 81089, "unexpected_differences": 0,
                             "operational_budget_difference_count": 2,
                             "corpus_sha256": "2e605ee7c5d61d35e4c360653b60d3b0a6083b1cc3dc89c61661b244f864a968",
                             "operational_budget_differences_verified": ["regexp:^(a|aa)+a{64}$", "regexp:^(a+)+a{64}$"],
                             "pcre2_driver": "/ci/reference/domain_driver", "posix_lite_driver": "/ci/wrappers/domain_driver"}
        self.reference = {"archive": {"sha256": verify.builder.PCRE2_SHA256}, "profile": "pcre2-8-no-unicode-no-jit", "version": "10.48",
                          "profile_verified": "8-bit only, Unicode disabled, JIT disabled", "commands": [{"exit_code": 0}, {"exit_code": 0}],
                          "configure_options": ["--disable-unicode", "--disable-jit", "--disable-shared", "--enable-static", "--disable-pcre2-16", "--disable-pcre2-32"]}
        self.refresh()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.checkout, stderr=subprocess.PIPE)

    def refresh(self):
        self.outputs["sdk-build"] = shlex.join(["make", "REGEX_BACKEND=posix-lite"] +
                                               [key + "=" + value for key, value in self.state["build_flags"].items()]) + "\n"
        self.outputs["apk-metadata"] = json.dumps(self.metadata) + "\n"
        self.outputs["qemu-pcre2-differential"] = ("production CN corpus: 8 unchanged rules / 72 assertions passed in both backends\n"
                                                  "portable differential corpus: 131 rules / 81089 matching results agree\n" + json.dumps(self.differential) + "\n")
        for name, value in (("buildinfo.json", self.state), ("apk-metadata.json", self.metadata), ("source-manifest.json", self.manifest),
                            ("elf-sdk-runtime.json", self.state["elf"]), ("nft-cli/result.json", self.nft),
                            ("regex-differential.json", self.differential), ("pcre2-reference-build.json", self.reference)):
            self.files[name] = json.dumps(value).encode() + b"\n"
        for name in verify.COMMANDS:
            self.files["logs/" + name + ".log"] = (shlex.join(self.cmd[name]["argv"]) + "\n" + self.outputs[name]).encode()
        self.save()

    def save(self):
        for name, data in self.files.items():
            path = self.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.folder / "SHA256SUMS").write_text("".join(record(data)["sha256"] + "  " + name + "\n" for name, data in sorted(self.files.items())))

    def check(self, **overrides):
        args = dict(folder=self.folder, commit=self.commit, run_id=123, attempt=2, arch=self.arch, checkout=self.checkout)
        args.update(overrides)
        return verify.verify_apk(**args)


class ReleaseInputs(unittest.TestCase):
    def fixture(self, arch="aarch64_cortex-a53"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        return Evidence(Path(temporary.name), arch)

    def test_both_architectures_accept_exact_evidence_without_execution(self):
        for arch in verify.builder.TARGETS:
            with self.subTest(arch=arch):
                fixture = self.fixture(arch)
                real = subprocess.run
                def git_only(argv, **kwargs):
                    self.assertEqual(argv[0], "git")
                    return real(argv, **kwargs)
                with mock.patch.object(verify.subprocess, "run", side_effect=git_only):
                    self.assertEqual(fixture.check(), fixture.state)

    def test_identity_inputs_must_be_exact(self):
        fixture = self.fixture()
        for value in ({"commit": "a" * 40}, {"commit": "HEAD"}, {"attempt": 1}, {"run_id": 1},
                      {"arch": "mipsel_24kc"}, {"run_id": True}, {"attempt": 0}):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fixture.check(**value)

    def test_checkout_head_may_differ_but_requested_git_object_must_match(self):
        fixture = self.fixture()
        fixture.git("-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "--allow-empty", "-qm", "later checkout")
        self.assertEqual(fixture.check()["source_commit"], fixture.commit)

    def test_tampered_file_and_missing_checksum_members_fail(self):
        fixture = self.fixture()
        (fixture.folder / fixture.apk_name).write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "digest differs"):
            fixture.check()
        fixture.save()
        (fixture.folder / "extra").write_bytes(b"not checksummed")
        with self.assertRaisesRegex(ValueError, "membership differs"):
            fixture.check()

    def test_checksums_reject_traversal_duplicates_and_invalid_hashes(self):
        fixture = self.fixture()
        path = fixture.folder / "SHA256SUMS"
        original = path.read_text()
        for extra in ("a" * 64 + "  ../outside\n", original.splitlines()[0] + "\n", "bad  file\n", "a" * 64 + "  SHA256SUMS\n"):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                path.write_text(original + extra)
                fixture.check()

    def test_even_checksummed_extra_payload_is_rejected(self):
        fixture = self.fixture()
        fixture.files["private-key.pem"] = b"not a real key"
        fixture.save()
        with self.assertRaisesRegex(ValueError, "unexpected/missing"):
            fixture.check()

    def test_symlink_is_rejected_before_target_read(self):
        fixture = self.fixture()
        path = fixture.folder / "LICENSE"
        path.unlink()
        path.symlink_to(fixture.checkout / "LICENSE")
        with self.assertRaisesRegex(ValueError, "non-regular"):
            fixture.check()

    def test_duplicate_json_keys_rejected_even_when_checksummed(self):
        fixture = self.fixture()
        fixture.files["buildinfo.json"] = b'{"status":"failed","status":"passed"}'
        fixture.save()
        with self.assertRaisesRegex(ValueError, "duplicate JSON"):
            fixture.check()

    def test_bad_or_incomplete_json_is_clear_failure(self):
        fixture = self.fixture()
        for raw in (b"null", b"{}", b"{", b'{"duration":NaN}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                fixture.files["buildinfo.json"] = raw
                fixture.save()
                fixture.check()

    def test_bad_status_unsigned_version_and_identity_fail(self):
        fixture = self.fixture()
        original = copy.deepcopy(fixture.state)
        changes = [("status", "failed"), ("unsigned", False), ("signing_keys_created", True),
                   ("same_sdk_application_matches_apk", False), ("application_version", "0.2.0"),
                   ("package_version", "0.1.0-r2"), ("source_tree", "0" * 40), ("error", "stale failure")]
        for name, value in changes:
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixture.state = copy.deepcopy(original)
                fixture.state[name] = value
                fixture.refresh()
                fixture.check()

    def test_apk_hash_size_and_filename_are_checked(self):
        fixture = self.fixture()
        for key, value in (("filename", "old.apk"), ("bytes", 999), ("sha256", "0" * 64)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                old = fixture.state["apk"][key]
                fixture.state["apk"][key] = value
                fixture.refresh()
                fixture.check()
            fixture.state["apk"][key] = old

    def test_source_archive_bytes_must_equal_git_archive(self):
        fixture = self.fixture()
        name = "source-" + fixture.commit + ".tar.gz"
        fixture.files[name] = gzip.compress(gzip.decompress(fixture.files[name]) + bytes(512), mtime=0)
        fixture.save()
        with self.assertRaisesRegex(ValueError, "git archive bytes"):
            fixture.check()

    def test_source_manifest_missing_extra_tampered_and_recipe_hashes(self):
        fixture = self.fixture()
        original = copy.deepcopy(fixture.manifest)
        for mode in ("missing", "extra", "tampered", "recipe", "commit"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                fixture.manifest = copy.deepcopy(original)
                if mode == "missing": del fixture.manifest["source_files_sha256"]["c/main.c"]
                if mode == "extra": fixture.manifest["source_files_sha256"]["c/extra.c"] = "0" * 64
                if mode == "tampered": fixture.manifest["source_files_sha256"]["c/main.c"] = "0" * 64
                if mode == "recipe": fixture.manifest["recipe_sha256"] = "0" * 64
                if mode == "commit": fixture.manifest["source_commit"] = "0" * 40
                fixture.refresh()
                fixture.check()

    def test_every_command_must_succeed_except_exact_unsigned_rejection(self):
        fixture = self.fixture()
        for name in verify.COMMANDS:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "failed/timed-out"):
                old = fixture.cmd[name]["exit_code"]
                fixture.cmd[name]["exit_code"] = 0 if old else 23
                fixture.refresh()
                fixture.check()
            fixture.cmd[name]["exit_code"] = old

    def test_command_cannot_be_missing_duplicate_timed_out_or_boolean_exit(self):
        for mode in ("missing", "duplicate", "timeout", "bool"):
            fixture = self.fixture()
            if mode == "missing": fixture.state["commands"].pop()
            if mode == "duplicate": fixture.state["commands"].append(fixture.commands[0])
            if mode == "timeout": fixture.commands[0]["timed_out"] = True
            if mode == "bool": fixture.commands[0]["exit_code"] = False
            fixture.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                fixture.check()

    def test_log_command_and_failure_reason_must_match(self):
        fixture = self.fixture()
        for name, output in (("logs/apk-version.log", b"other command\nmosdns-c 0.1.0 fixed-splitter\n"),
                             ("logs/apk-untrusted-as-expected.log", (shlex.join(fixture.cmd["apk-untrusted-as-expected"]["argv"]) + "\nUNTRUSTED and corrupted package\n").encode())):
            with self.subTest(name=name), self.assertRaises(ValueError):
                old = fixture.files[name]
                fixture.files[name] = output
                fixture.save()
                fixture.check()
            fixture.files[name] = old

    def test_version_count_skip_failure_and_truncated_logs_rejected(self):
        fixture = self.fixture()
        edits = [("apk-version", "0.1.0", "0.2.0"), ("qemu-cache_domain_test", "43200", "143200"),
                 ("qemu-nft_netlink_test", "157", "156"), ("qemu-domain-fixture", "70 assertions", "7 assertions"),
                 ("qemu-final-apk-integration", "Ran 12", "Ran 11"), ("qemu-final-apk-integration", "... ok", "... skipped 'why'"),
                 ("qemu-final-apk-integration", "\nOK\n", "\nFAILED (failures=1)\n"),
                 ("qemu-dns_test", "tests passed", "tests")]
        for name, before, after in edits:
            with self.subTest(name=name, after=after), self.assertRaises(ValueError):
                old = fixture.outputs[name]
                fixture.outputs[name] = old.replace(before, after)
                fixture.refresh()
                fixture.check()
            fixture.outputs[name] = old

    def test_summary_success_cannot_hide_different_raw_metadata(self):
        fixture = self.fixture()
        old = fixture.files["logs/apk-metadata.log"]
        fixture.files["logs/apk-metadata.log"] = old.replace(b'"0.1.0-r1"', b'"0.2.0-r1"')
        fixture.save()
        with self.assertRaisesRegex(ValueError, "raw APK metadata differs"):
            fixture.check()

    def test_package_version_dependency_whitelist_mode_and_elf_digest(self):
        for mode in ("version", "dependency", "extra", "symlink", "mode", "digest"):
            fixture = self.fixture()
            if mode == "version": fixture.metadata["info"]["version"] = "0.2.0-r1"
            if mode == "dependency": fixture.metadata["info"]["depends"].append("libatomic")
            item = fixture.metadata["paths"][0]["files"][0]
            if mode == "extra": item["name"] = "unexpected"
            if mode == "symlink": item["target"] = "/tmp/binary"
            if mode == "mode": item["acl"]["mode"] = 0o777
            if mode == "digest": item["hash"] = "0" * 64
            fixture.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                fixture.check()

    def test_elf_arch_dependencies_stack_symbols_and_mips_abi(self):
        edits = {"arch": "mipsel_24kc", "interpreter": "/lib64/ld-linux.so", "libraries": {"libatomic.so": record()},
                 "stack_executable": True, "default_thread_stack_bytes": 8192, "missing_strong_symbols": ["regcomp"], "strong_symbols_checked": 0}
        fixture = self.fixture()
        original = copy.deepcopy(fixture.state["elf"])
        for name, value in edits.items():
            with self.subTest(name=name), self.assertRaises(ValueError):
                fixture.state["elf"] = {**original, name: value}
                fixture.refresh()
                fixture.check()
        fixture = self.fixture("mipsel_24kc")
        fixture.state["elf"]["float"] = "hard"
        fixture.refresh()
        with self.assertRaisesRegex(ValueError, "MIPS ABI"):
            fixture.check()

    def test_sdk_pin_signing_assertions_and_reference_profile(self):
        for mode in ("sdk", "signing", "assertions", "unicode", "reference-exit"):
            fixture = self.fixture()
            if mode == "sdk": fixture.state["sdk_archive"]["sha256"] = "0" * 64
            if mode == "signing": fixture.files["sdk.config"] += b"CONFIG_SIGNED_PACKAGES=y\n"
            if mode == "assertions": fixture.state["build_flags"]["CFLAGS"] += " -DNDEBUG"
            if mode == "unicode": fixture.reference["configure_options"].remove("--disable-unicode")
            if mode == "reference-exit": fixture.reference["commands"][1]["exit_code"] = 1
            fixture.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                fixture.check()

    def test_nft_differential_counts_raw_calls_and_source_hash(self):
        for mode in ("nft-failed", "nft-source", "nft-duplicate", "raw-calls", "differential-count", "corpus", "budget"):
            fixture = self.fixture()
            if mode == "nft-failed": fixture.nft["checks"][0]["passed"] = False
            if mode == "nft-source": fixture.nft["source_sha256"] = "0" * 64
            if mode == "nft-duplicate": fixture.nft["checks"][1] = fixture.nft["checks"][0]
            if mode == "raw-calls": fixture.files["nft-cli/ipv4-plain.calls.jsonl"] = b"{}\n"
            if mode == "differential-count": fixture.differential["portable_comparisons"] = 81088
            if mode == "corpus": fixture.differential["corpus_sha256"] = "0" * 64
            if mode == "budget": fixture.differential["operational_budget_difference_count"] = 1
            fixture.refresh()
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                fixture.check()

    def test_raw_build_flags_cannot_disagree_with_summary(self):
        fixture = self.fixture()
        fixture.files["logs/sdk-build.log"] = fixture.files["logs/sdk-build.log"].replace(b"-UNDEBUG", b"-DNDEBUG")
        fixture.save()
        with self.assertRaisesRegex(ValueError, "raw SDK build flags differ"):
            fixture.check()

    def test_test_harness_must_come_from_the_same_source_tree(self):
        fixture = self.fixture()
        fixture.cmd["qemu-nft-cli"]["argv"][1] = "/ci/stale-source/c/tests/nft_cli_test.py"
        fixture.refresh()
        with self.assertRaisesRegex(ValueError, "test harness source path differs"):
            fixture.check()

    def test_integration_must_use_exact_same_packaged_wrapper(self):
        fixture = self.fixture()
        fixture.cmd["qemu-final-apk-integration"]["argv"][-1] = "/ci/wrappers/stale-app"
        fixture.refresh()
        with self.assertRaisesRegex(ValueError, "packaged application"):
            fixture.check()


if __name__ == "__main__":
    unittest.main()
