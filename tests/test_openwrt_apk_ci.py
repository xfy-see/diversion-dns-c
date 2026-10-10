"""Offline APK CI contracts. SDK tools, compilers and target programs never run.

The build harness executes the real Python orchestration over tiny synthetic files
and fail-closed subprocess doubles. It is not an APK/ELF or QEMU runtime test.
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import types
import unittest
from unittest import mock
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
TREE = "b" * 40
APP = "usr/sbin/diversion-dns-c-lite"
LIST = "lib/apk/packages/diversion-dns-c-lite.list"
CONTENTS = {APP: b"synthetic app bytes; never executable\n", LIST: b"/usr/sbin/diversion-dns-c-lite\n"}
KEY_NAMES = "$(BUILD_KEY_APK_SEC) $(BUILD_KEY_APK_PUB)"
SDK_MAKEFILE = ("# pinned upstream fixture\n"
                "ifeq ($(CONFIG_USE_APK),y)\n"
                "  $(curdir)//compile += $(curdir)/system/apk/host/compile " + KEY_NAMES + "\n"
                "else\n"
                "  $(curdir)//compile += " + KEY_NAMES + "\n"
                "endif\n")


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def metadata(arch="aarch64_cortex-a53"):
    return {
        "info": {"name": "diversion-dns-c-lite", "arch": arch, "version": "0.1.0-r1",
                 "depends": ["libc", "libpthread"],
                 "installed-size": sum(map(len, CONTENTS.values()))},
        "paths": [{"name": str(Path(name).parent), "acl": {"mode": 0o755}, "files": [
            {"name": Path(name).name, "size": len(content),
             "hash": hashlib.sha256(content).hexdigest(),
             "acl": {"mode": 0o755 if name == APP else 0o644}}]}
            for name, content in CONTENTS.items()],
        "scripts": {"post-install": "#!/bin/sh\nexit 0\n"},
    }


def source_archive(files):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return output.getvalue()


class PinnedTargetContracts(unittest.TestCase):
    def test_exact_official_sdk_pins_and_architecture(self):
        targets = load("build-openwrt-apk").TARGETS
        expected = {
            "aarch64_cortex-a53": ("qualcommax/ipq60xx", "aarch64-openwrt-linux-musl", "qemu-aarch64",
                                  "5ea07bb08e5a21454b37aaf497c876d5ce8fde1742ac8bfbb62beea84ee4e66b"),
            "mipsel_24kc": ("ramips/mt7621", "mipsel-openwrt-linux-musl", "qemu-mipsel",
                            "9962084f4131610e90e48bc864c6ceade0b238f15f335de5f672910532b20e9c"),
        }
        self.assertEqual(set(targets), set(expected))
        for arch, (target, prefix, qemu, sha) in expected.items():
            with self.subTest(arch=arch):
                row = targets[arch]
                self.assertEqual(row["openwrt_version"], "25.12.5")
                self.assertEqual(row["gcc_version"], "14.3.0")
                self.assertEqual(row["target"], target)
                filename = ("openwrt-sdk-25.12.5-" + target.replace("/", "-") +
                            "_gcc-14.3.0_musl.Linux-x86_64.tar.zst")
                base = "https://downloads.openwrt.org/releases/25.12.5/targets/" + target + "/"
                self.assertEqual(row["sdk_filename"], filename)
                self.assertEqual(row["sdk_url"], base + filename)
                self.assertEqual(row["checksum_url"], base + "sha256sums")
                self.assertEqual(row["sdk_sha256"], sha)
                self.assertEqual(row["compiler_prefix"], prefix)
                self.assertEqual(row["qemu"], qemu)
                parsed = urlsplit(row["sdk_url"])
                self.assertEqual((parsed.scheme, parsed.netloc), ("https", "downloads.openwrt.org"))
                self.assertFalse(parsed.query or parsed.fragment)


class SigningKeyContracts(unittest.TestCase):
    def setUp(self):
        self.module = load("build-openwrt-apk")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sdk = Path(self.tmp.name)
        (self.sdk / "package").mkdir()
        self.makefile = self.sdk / "package/Makefile"

    def test_patch_changes_exactly_two_dependencies_and_preserves_other_text(self):
        self.makefile.write_text(SDK_MAKEFILE)
        diff = self.module.disable_unused_sdk_keys(self.sdk)
        expected = SDK_MAKEFILE.replace(KEY_NAMES, "$(if $(CONFIG_SIGNED_PACKAGES)," + KEY_NAMES + ")")
        self.assertEqual(self.makefile.read_text(), expected)
        added = [line for line in diff.splitlines() if line.startswith("+") and not line.startswith("+++")]
        removed = [line for line in diff.splitlines() if line.startswith("-") and not line.startswith("---")]
        self.assertEqual(len(added), 2)
        self.assertEqual(len(removed), 2)
        self.assertTrue(all("CONFIG_SIGNED_PACKAGES" in line for line in added))

    def test_unknown_key_dependency_variants_fail_without_partial_rewrite(self):
        variants = {
            "missing": SDK_MAKEFILE.replace("  $(curdir)//compile += " + KEY_NAMES + "\n", ""),
            "duplicate": SDK_MAKEFILE + "  $(curdir)//compile += " + KEY_NAMES + "\n",
            "indentation": SDK_MAKEFILE.replace("  $(curdir)", "\t$(curdir)", 1),
            "reordered": SDK_MAKEFILE.replace(KEY_NAMES, "$(BUILD_KEY_APK_PUB) $(BUILD_KEY_APK_SEC)", 1),
            "extra_unknown_dependency": SDK_MAKEFILE + "  $(curdir)/other += $(BUILD_KEY_APK_SEC)\n",
            "already_patched": SDK_MAKEFILE.replace(KEY_NAMES, "$(if $(CONFIG_SIGNED_PACKAGES)," + KEY_NAMES + ")"),
        }
        for name, content in variants.items():
            with self.subTest(variant=name):
                self.makefile.write_text(content)
                with self.assertRaises(ValueError):
                    self.module.disable_unused_sdk_keys(self.sdk)
                self.assertEqual(self.makefile.read_text(), content)

    def test_existing_signing_key_names_fail_without_reading_credentials(self):
        for filename in ("key-build", "key-build.pub", "private-key.pem", "public-key.pem"):
            with self.subTest(filename=filename):
                key = self.sdk / filename
                key.write_text("must not be read or removed")
                with mock.patch.object(Path, "read_bytes", side_effect=AssertionError("credential read")), \
                     mock.patch.object(Path, "read_text", side_effect=AssertionError("credential read")):
                    with self.assertRaisesRegex(ValueError, "signing key"):
                        self.module.no_signing_keys(self.sdk)
                self.assertTrue(key.exists())
                key.unlink()
        self.module.no_signing_keys(self.sdk)


class ApkMetadataContracts(unittest.TestCase):
    def setUp(self):
        self.module = load("build-openwrt-apk")

    def test_exact_manifest_for_both_architectures(self):
        for arch in self.module.TARGETS:
            with self.subTest(arch=arch):
                actual = self.module.package_files(metadata(arch), arch)
                self.assertEqual(actual, {name: {"bytes": len(value), "sha256": hashlib.sha256(value).hexdigest()}
                                          for name, value in CONTENTS.items()})

    def reject(self, change):
        data = metadata()
        change(data)
        with self.assertRaises((ValueError, KeyError, TypeError)):
            self.module.package_files(data, "aarch64_cortex-a53")

    def test_name_arch_dependencies_and_installed_size_fail_closed(self):
        changes = [
            lambda x: x["info"].update(name="another-package"),
            lambda x: x["info"].update(arch="mipsel_24kc"),
            lambda x: x["info"].update(depends=["libc"]),
            lambda x: x["info"].update(depends=["libc", "libpthread", "libpcre2"]),
            lambda x: x["info"].update(depends=["libc", "libpthread", "libatomic"]),
            lambda x: x["info"].update(**{"installed-size": 0}),
        ]
        for number, change in enumerate(changes):
            with self.subTest(change=number):
                self.reject(change)

    def test_payload_missing_extra_duplicate_and_symlink_fail_closed(self):
        self.reject(lambda x: x["paths"].pop())
        self.reject(lambda x: x["paths"].append(copy.deepcopy(x["paths"][0])))
        self.reject(lambda x: x["paths"][0]["files"].append(copy.deepcopy(x["paths"][0]["files"][0])))
        self.reject(lambda x: x["paths"].append({"name": "etc/init.d", "files": [
            dict(x["paths"][0]["files"][0], name="diversion-dns")]}))
        self.reject(lambda x: x["paths"][0]["files"][0].update(target="/bin/sh"))
        self.reject(lambda x: x["scripts"].update(**{"post-install": "/etc/init.d/diversion-dns enable"}))

    def test_directory_and_filename_traversals_rejected(self):
        for name in ("/usr/sbin", "../usr/sbin", "usr/../usr/sbin", "usr/sbin/../../usr/sbin"):
            with self.subTest(directory=name):
                self.reject(lambda x, name=name: x["paths"][0].update(name=name))
        for leaf in ("", ".", "..", "../diversion-dns-c-lite", "/diversion-dns-c-lite", "x/diversion-dns-c-lite"):
            with self.subTest(filename=leaf):
                self.reject(lambda x, leaf=leaf: x["paths"][0]["files"][0].update(name=leaf))

    def test_hash_and_file_modes_are_not_advisory(self):
        for value in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 64 + "\n"):
            with self.subTest(hash=value):
                self.reject(lambda x, value=value: x["paths"][0]["files"][0].update(hash=value))
        for index, modes in ((0, (0o644, 0o4755, 0o777, 0)), (1, (0o755, 0o600, 0o666))):
            for mode in modes:
                with self.subTest(file=index, mode=oct(mode)):
                    self.reject(lambda x, index=index, mode=mode: x["paths"][index]["files"][0]["acl"].update(mode=mode))

    def test_empty_unexpected_duplicate_and_unsafe_directory_modes_rejected(self):
        self.reject(lambda x: x["paths"].append({"name": "etc", "acl": {"mode": 0o755}}))
        self.reject(lambda x: x["paths"].append({"name": "usr/sbin", "acl": {"mode": 0o755}}))
        for mode in (0, 0o644, 0o777, 0o4755):
            with self.subTest(mode=mode):
                self.reject(lambda x, mode=mode: x["paths"][0]["acl"].update(mode=mode))
        for size in (-1, True, 1.0, "1"):
            with self.subTest(installed_size=size):
                self.reject(lambda x, size=size: x["info"].update(**{"installed-size": size}))

    def test_negative_or_boolean_sizes_rejected_even_with_matching_total(self):
        for size in (-1, True, False):
            with self.subTest(size=size):
                def mutate(data):
                    data["paths"][0]["files"][0]["size"] = size
                    data["info"]["installed-size"] = size + len(CONTENTS[LIST])
                self.reject(mutate)


class FrozenSourceContracts(unittest.TestCase):
    def test_recipe_and_application_are_both_taken_from_resolved_git_commit(self):
        module = load("stage-openwrt-package")
        contents = {"c/Makefile": b"frozen makefile\n", "c/example.c": b"frozen C source\n", "LICENSE": b"frozen license\n"}
        recipe = b"frozen package recipe\n"
        calls = []
        def git(argv, **kwargs):
            calls.append(argv)
            if argv == ["git", "rev-parse", "--verify", "requested-ref^{commit}"]:
                return COMMIT + "\n"
            if argv == ["git", "archive", "--format=tar", COMMIT, "c", "LICENSE"]:
                return source_archive(contents)
            if argv == ["git", "show", COMMIT + ":packaging/openwrt/Makefile"]:
                return recipe
            raise AssertionError("unexpected git invocation: " + repr(argv))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "packaging/openwrt").mkdir(parents=True)
            (root / "packaging/openwrt/Makefile").write_bytes(b"dirty working recipe\n")
            with mock.patch.object(module, "ROOT", root), mock.patch.object(module.subprocess, "check_output", side_effect=git):
                manifest = module.stage(root / "staged", "requested-ref")
            self.assertEqual((root / "staged/Makefile").read_bytes(), recipe)
            self.assertEqual(manifest["source_commit"], COMMIT)
            self.assertEqual(manifest["recipe_sha256"], hashlib.sha256(recipe).hexdigest())
            for name, value in contents.items():
                self.assertEqual((root / "staged/src" / name).read_bytes(), value)
                self.assertEqual(manifest["source_files_sha256"][name], hashlib.sha256(value).hexdigest())
            self.assertEqual(len(calls), 3)


class SyntheticBuild:
    """Fake the external SDK interface; exercise real orchestration and files."""
    def __init__(self, root, arch="aarch64_cortex-a53", fail=None, omit_apk=False, mutate_payload=False):
        root = root.resolve()
        self.root = root
        self.module = load("build-openwrt-apk")
        self.arch = arch
        self.target = self.module.TARGETS[arch]
        self.work = root / "work"
        self.out = root / "output"
        self.sdk = self.work / self.target["sdk_filename"].removesuffix(".tar.zst")
        self.toolchain = self.sdk / "staging_dir/toolchain-fixture"
        self.build = self.sdk / "build_dir/target-fixture/diversion-dns-c-lite-fixture/build-openwrt"
        self.fail = fail
        self.omit_apk = omit_apk
        self.mutate_payload = mutate_payload
        self.commands = []
        self.environments = []
        self.git_calls = []
        self.dirty_input = None
        self.github_sha = COMMIT
        self.output_overrides = {}
        self.timeout = None
        self.extract_symlink = False
        self.hashed_extracted_symlink = False
        self.sdk_archive = root / "sdk.tar.zst"
        self.pcre_archive = root / "pcre.tar.gz"
        self.qemu = root / "qemu"
        for path in (self.sdk_archive, self.pcre_archive, self.qemu):
            path.write_bytes(b"fixture archive or tool; not executed")
        self.actual_digest = self.module.digest

    def write(self, path, value=b"synthetic bytes"):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)

    def git(self, command, **kwargs):
        command = list(map(str, command))
        self.git_calls.append(command)
        if command[0] != "git":
            if command[-1] == "-print-file-name=libatomic.a":
                return str(self.toolchain / "lib/libatomic.a") + "\n"
            raise AssertionError("unexpected external check_output: " + repr(command))
        if command[1] == "rev-parse":
            return (TREE if command[-1].endswith("^{tree}") else COMMIT) + "\n"
        if command[1] == "show":
            name = command[2].split(":", 1)[1]
            value = (ROOT / name).read_bytes()
            return value + b"dirty" if name == self.dirty_input else value
        if command[1] == "archive":
            return source_archive({"LICENSE": b"frozen license", "c/fixture.c": b"frozen application"})
        raise AssertionError("unexpected git command: " + repr(command))

    def digest(self, path):
        if Path(path).is_symlink():
            self.hashed_extracted_symlink = True
            raise AssertionError("extracted symlink was read before rejection")
        if Path(path) == self.sdk_archive:
            return self.target["sdk_sha256"]
        if Path(path) == self.pcre_archive:
            return self.module.PCRE2_SHA256
        return self.actual_digest(path)

    def stage(self, destination, commit):
        if commit != COMMIT:
            raise AssertionError("staging was not pinned to the resolved commit")
        value = b"frozen application"
        self.write(destination / "src/c/fixture.c", value)
        return {"source_commit": commit, "source_files_sha256": {"c/fixture.c": hashlib.sha256(value).hexdigest()}}

    def script(self, name):
        if name == "stage-openwrt-package":
            return types.SimpleNamespace(stage=self.stage)
        if name == "check-openwrt-elf":
            return types.SimpleNamespace(check=lambda binary, toolchain, arch: {"arch": arch, "needed": ["libc.so"]})
        raise AssertionError("unexpected helper: " + name)

    def run(self, command, **kwargs):
        command = list(map(str, command))
        self.commands.append(command)
        self.environments.append(kwargs.get("env", {}))
        text, code, label = "", 0, None
        if command[0] == "tar":
            label = "extract-sdk"
            self.write(self.sdk / "package/Makefile", SDK_MAKEFILE.encode())
            self.write(self.sdk / ".config", b"# initial config\n")
            prefix = self.target["compiler_prefix"]
            self.write(self.toolchain / "bin" / ("." + prefix + "-gcc.bin"))
            self.write(self.toolchain / "lib/libc.so")
            self.write(self.toolchain / "lib/libatomic.a")
            self.write(self.build / "mosdns-c", CONTENTS[APP])
            for name in self.module.TESTS:
                self.write(self.build / "tests" / name)
            if not self.omit_apk:
                self.write(self.sdk / "bin/packages" / self.arch / "local/diversion-dns-c-lite-0.1.0-r1.apk", b"fake APK container")
        elif command[0] == "make" and "defconfig" in command:
            label = "sdk-defconfig"
        elif command[0] == "make" and "package/diversion-dns-c-lite/compile" in command:
            label = "sdk-build"
            text = ("make REGEX_BACKEND=posix-lite 'CFLAGS=-Os -flto -UNDEBUG -fstack-protector "
                    "-D_FORTIFY_SOURCE=1 -Wformat -Werror=format-security -Wl,-z,now -Wl,-z,relro' "
                    "'LDFLAGS=-flto -Wl,--gc-sections -static-libgcc -Wl,-z,stack-size=1048576'\n")
        elif command[0] == "make" and "REGEX_BACKEND=pcre2" in command:
            label = "native-reference-drivers"
            self.write(self.work / "native-reference/tests/domain_driver")
            self.write(self.work / "native-reference/tests/cache_domain_test")
        elif command == ["uname", "-a"]:
            label, text = "host-uname", "synthetic host\n"
        elif command[-1] == "--version":
            label = "compiler-version" if command[0].endswith("-gcc") else "qemu-version"
            text = "synthetic version\n"
        elif "adbdump" in command:
            label, text = "apk-metadata", json.dumps(metadata(self.arch))
        elif "verify" in command:
            if "--allow-untrusted" in command:
                label = "apk-integrity"
            else:
                label, code, text = "apk-untrusted-as-expected", 1, "UNTRUSTED signature\n"
        elif "extract" in command:
            label = "apk-extract"
            destination = Path(command[command.index("--destination") + 1])
            for name, value in CONTENTS.items():
                if self.extract_symlink and name == APP:
                    external = self.root / "outside-extracted-package"
                    self.write(external, value)
                    (destination / name).parent.mkdir(parents=True, exist_ok=True)
                    (destination / name).symlink_to(external)
                    continue
                self.write(destination / name, value + (b"corrupt" if self.mutate_payload and name == APP else b""))
                (destination / name).chmod(0o755 if name == APP else 0o644)
        elif command[0].endswith("-strip"):
            label = "strip-rebuilt"
        elif command[0].endswith("/sstrip"):
            label = "sstrip-rebuilt"
        elif command[0].endswith("/wrappers/packaged-app"):
            label, text = "apk-version", "mosdns-c 0.1.0 fixed-splitter\n"
        elif "/wrappers/" in command[0]:
            name = Path(command[0]).name
            label = "qemu-" + name
            text = {"cache_domain_test": "43200 matches passed\n", "nft_netlink_test": '{"assertions":157}\n'}.get(name, "")
        elif len(command) > 1 and command[1].endswith("domain_fixture.py"):
            label = "qemu-domain-fixture"
        elif len(command) > 1 and command[1].endswith("nft_cli_test.py"):
            label = "qemu-nft-cli"
            self.write(self.out / "nft-cli/result.json", json.dumps({"ok": True, "checks": [{"passed": True}] * 18}).encode())
        elif len(command) > 1 and command[1].endswith("fixed_integration.py"):
            label, text = "qemu-final-apk-integration", "Ran 12 tests\n\nOK\n"
        elif len(command) > 1 and command[1].endswith("build-native-pcre2.py"):
            label = "native-pcre2-build"
            self.write(self.work / "pcre2-reference/manifest.json", b"{}")
        elif command[0].endswith("native-reference/tests/cache_domain_test"):
            label = "native-reference-budget-unit"
        elif len(command) > 1 and command[1].endswith("regex_differential.py"):
            label = "qemu-pcre2-differential"
            self.write(self.out / "regex-differential.json", b'{"portable_comparisons":81089,"unexpected_differences":0}')
        else:
            raise AssertionError("an unmocked command would execute: " + repr(command))
        if label == self.timeout:
            raise subprocess.TimeoutExpired(command, kwargs["timeout"], output=b"partial test evidence\n")
        if label in self.output_overrides:
            code, text = self.output_overrides[label]
        if label == self.fail:
            # Keep success-looking output. Exit status must be authoritative.
            code = 23
        return subprocess.CompletedProcess(command, code, text.encode())

    def invoke(self):
        arguments = ["build-openwrt-apk.py", "--arch", self.arch,
                     "--sdk-archive", str(self.sdk_archive), "--pcre2-archive", str(self.pcre_archive),
                     "--work", str(self.work), "--output", str(self.out),
                     "--source-ref", COMMIT, "--qemu", str(self.qemu)]
        with mock.patch.object(sys, "argv", arguments), \
             mock.patch.dict(os.environ, {"GITHUB_SHA": self.github_sha}), \
             mock.patch.object(self.module, "digest", side_effect=self.digest), \
             mock.patch.object(self.module, "load_script", side_effect=self.script), \
             mock.patch.object(self.module.subprocess, "check_output", side_effect=self.git), \
             mock.patch.object(self.module.subprocess, "run", side_effect=self.run), \
             mock.patch("builtins.print"):
            self.module.main()


class BuildOrchestrationContracts(unittest.TestCase):
    def fixture(self, **kwargs):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return SyntheticBuild(Path(tmp.name), **kwargs)

    def test_orchestration_fixture_resolves_symlinked_temporary_directory(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name).resolve()
        physical = root / "physical"
        physical.mkdir()
        alias = root / "alias"
        alias.symlink_to(physical, target_is_directory=True)
        build = SyntheticBuild(alias)
        build.invoke()
        self.assertEqual(build.root, physical)
        wrapper = build.work / "wrappers/packaged-app"
        self.assertIn("-L " + str(build.toolchain), wrapper.read_text())
        self.assertEqual(json.loads((build.out / "buildinfo.json").read_text())["status"], "passed")

    def test_both_architectures_verify_and_run_the_extracted_final_apk(self):
        for arch in ("aarch64_cortex-a53", "mipsel_24kc"):
            with self.subTest(arch=arch):
                build = self.fixture(arch=arch)
                build.invoke()
                state = json.loads((build.out / "buildinfo.json").read_text())
                self.assertEqual(state["status"], "passed")
                self.assertEqual(state["source_commit"], COMMIT)
                self.assertEqual(state["source_tree"], TREE)
                self.assertTrue(state["unsigned"])
                self.assertFalse(state["signing_keys_created"])
                self.assertTrue(state["same_sdk_application_matches_apk"])
                self.assertEqual(state["tests"]["final_apk_loopback_integration"], 12)
                wrapper = build.work / "wrappers/packaged-app"
                self.assertIn(str(build.work / "package-extracted" / APP), wrapper.read_text())
                self.assertIn("-L " + str(build.toolchain), wrapper.read_text())
                commands = {entry["name"]: entry for entry in state["commands"]}
                self.assertEqual(commands["qemu-final-apk-integration"]["argv"][-1], str(wrapper))
                self.assertIn(str(build.work / "source/c/tests/fixed_integration.py"),
                              commands["qemu-final-apk-integration"]["argv"])
                self.assertEqual(commands["qemu-final-apk-integration"]["exit_code"], 0)
                self.assertEqual(commands["apk-untrusted-as-expected"]["exit_code"], 1)
                for name in ("apk-integrity", "apk-extract"):
                    self.assertIn("--no-network", commands[name]["argv"])
                    self.assertIn("--allow-untrusted", commands[name]["argv"])
                for command in build.commands:
                    if Path(command[0]).name == "apk":
                        self.assertIn(command[1], ("adbdump", "verify", "extract"))
                checksum_lines = (build.out / "SHA256SUMS").read_text().splitlines()
                for line in checksum_lines:
                    sha, filename = line.split("  ", 1)
                    self.assertEqual(sha, build.actual_digest(build.out / filename))
                self.assertTrue(any(line.endswith("  " + state["apk"]["filename"]) for line in checksum_lines))
                self.assertTrue((build.out / ("source-" + COMMIT + ".tar.gz")).is_file())

    def test_compile_success_cannot_hide_failing_final_apk_or_driver_exit_status(self):
        for failing in ("qemu-final-apk-integration", "qemu-cache_domain_test", "qemu-nft_netlink_test",
                        "qemu-nft-cli", "qemu-pcre2-differential", "apk-integrity"):
            with self.subTest(failing=failing):
                build = self.fixture(fail=failing)
                with self.assertRaisesRegex(ValueError, re.escape(failing) + " failed"):
                    build.invoke()
                state = json.loads((build.out / "buildinfo.json").read_text())
                self.assertEqual(state["status"], "failed")
                commands = {row["name"]: row for row in state["commands"]}
                self.assertEqual(commands["sdk-build"]["exit_code"], 0)
                self.assertEqual(commands[failing]["exit_code"], 23)
                self.assertFalse((build.out / "SHA256SUMS").exists())

    def test_successful_compile_without_apk_fails(self):
        build = self.fixture(omit_apk=True)
        with self.assertRaisesRegex(ValueError, "exactly one built APK"):
            build.invoke()
        state = json.loads((build.out / "buildinfo.json").read_text())
        self.assertEqual(state["status"], "failed")
        self.assertNotIn("tests", state)

    def test_extracted_hash_mismatch_fails_before_target_execution(self):
        build = self.fixture(mutate_payload=True)
        with self.assertRaisesRegex(ValueError, "file hashes/whitelist mismatch"):
            build.invoke()
        self.assertFalse(any("/wrappers/" in command[0] for command in build.commands))

    def test_extracted_symlink_is_rejected_before_hashing_its_target(self):
        build = self.fixture()
        build.extract_symlink = True
        with self.assertRaisesRegex(ValueError, "extracted symlink"):
            build.invoke()
        self.assertFalse(build.hashed_extracted_symlink)
        self.assertFalse(any("/wrappers/" in command[0] for command in build.commands))

    def test_archive_digest_mismatch_fails_before_git_extract_or_build(self):
        for archive in ("sdk_archive", "pcre_archive"):
            with self.subTest(archive=archive):
                build = self.fixture()
                original_digest = build.digest
                def digest(path):
                    return "0" * 64 if Path(path) == getattr(build, archive) else original_digest(path)
                with mock.patch.object(build, "digest", side_effect=digest):
                    with self.assertRaisesRegex(ValueError, "SHA256 mismatch"):
                        build.invoke()
                self.assertEqual(build.commands, [])
                self.assertEqual(build.git_calls, [])
                self.assertFalse(build.work.exists())

    def test_wrong_workflow_commit_is_rejected_before_build(self):
        build = self.fixture()
        build.github_sha = "c" * 40
        with self.assertRaisesRegex(ValueError, "differs from workflow head"):
            build.invoke()
        self.assertEqual(build.commands, [])
        self.assertFalse(build.work.exists())

    def test_trusted_or_unrelated_verification_failure_is_rejected(self):
        for result in ((0, "OK"), (1, "archive corrupt"), (0, "UNTRUSTED")):
            with self.subTest(result=result):
                build = self.fixture()
                build.output_overrides["apk-untrusted-as-expected"] = result
                with self.assertRaisesRegex(ValueError, "unexpectedly trusted or verification failed"):
                    build.invoke()
                self.assertFalse(any("extract" in command for command in build.commands))

    def test_zero_exit_without_expected_test_corpus_is_rejected(self):
        for name, message in (("qemu-final-apk-integration", "final APK integration corpus missing"),
                              ("qemu-cache_domain_test", "concurrency corpus missing"),
                              ("qemu-nft_netlink_test", "netlink corpus missing")):
            with self.subTest(name=name):
                build = self.fixture()
                build.output_overrides[name] = (0, "some smaller test passed")
                with self.assertRaisesRegex(ValueError, message):
                    build.invoke()
                self.assertEqual(json.loads((build.out / "buildinfo.json").read_text())["status"], "failed")

    def test_timeout_preserves_partial_test_evidence_and_fails(self):
        build = self.fixture()
        build.timeout = "qemu-final-apk-integration"
        with self.assertRaises(subprocess.TimeoutExpired):
            build.invoke()
        state = json.loads((build.out / "buildinfo.json").read_text())
        self.assertEqual(state["status"], "failed")
        entry = next(row for row in state["commands"] if row["name"] == build.timeout)
        self.assertTrue(entry["timed_out"])
        self.assertIsNone(entry["exit_code"])
        self.assertGreater(entry["timeout_seconds"], 0)
        log = (build.out / "logs" / (build.timeout + ".log")).read_text()
        self.assertIn("partial test evidence", log)
        self.assertIn("TIMEOUT", log)
        self.assertFalse((build.out / "SHA256SUMS").exists())

    def test_existing_work_or_output_is_not_cleaned_or_reused(self):
        for directory in ("work", "out"):
            with self.subTest(directory=directory):
                build = self.fixture()
                location = getattr(build, directory)
                location.mkdir()
                sentinel = location / "old-object.o"
                sentinel.write_bytes(b"preserve old evidence")
                with self.assertRaisesRegex(ValueError, "fresh work and output"):
                    build.invoke()
                self.assertEqual(sentinel.read_bytes(), b"preserve old evidence")
                self.assertEqual(build.commands, [])

    def test_dirty_helpers_recipe_targets_and_c_makefile_fail_before_build(self):
        for name in ("scripts/build-openwrt-apk.py", "scripts/check-openwrt-elf.py", "scripts/stage-openwrt-package.py",
                     "packaging/openwrt/Makefile", "packaging/openwrt/targets.json", "c/Makefile"):
            with self.subTest(name=name):
                build = self.fixture()
                build.dirty_input = name
                with self.assertRaisesRegex(ValueError, "uncommitted build input"):
                    build.invoke()
                self.assertEqual(build.commands, [])
                self.assertFalse(build.work.exists())

    def test_inherited_target_flags_do_not_leak_into_sdk_build(self):
        build = self.fixture()
        poisoned = {name: "unexpected-inherited-value" for name in (
            "CC", "AR", "RANLIB", "CFLAGS", "CPPFLAGS", "CXXFLAGS", "LDFLAGS", "LDLIBS", "MAKEFLAGS",
            "MFLAGS", "CPATH", "C_INCLUDE_PATH", "CPLUS_INCLUDE_PATH", "LIBRARY_PATH", "CONFIG_SITE", "PYTHONOPTIMIZE")}
        with mock.patch.dict(os.environ, poisoned):
            build.invoke()
        for command, environment in zip(build.commands, build.environments):
            # Explicit optional host include/library paths are only for defconfig.
            permitted = {"CPATH", "LIBRARY_PATH"} if "defconfig" in command else set()
            for name in poisoned.keys() - permitted:
                self.assertNotIn(name, environment)


class WorkflowContracts(unittest.TestCase):
    def setUp(self):
        self.path = ROOT / ".github/workflows/openwrt-apk.yml"
        self.text = self.path.read_text()

    def test_workflow_is_independent_read_only_and_has_no_release_or_deployment(self):
        self.assertIn("\n  push:\n", self.text)
        self.assertIn("\n  pull_request:\n", self.text)
        self.assertIn("\n  workflow_dispatch:\n", self.text)
        self.assertNotIn("workflow_run:", self.text)
        self.assertNotIn("workflow_call:", self.text)
        self.assertRegex(self.text, r"(?m)^permissions:\n  contents: read\n")
        self.assertNotRegex(self.text, r"(?m)^\s+[\w-]+: write\s*$")
        self.assertNotIn("write-all", self.text)
        self.assertNotIn("secrets.", self.text)
        self.assertNotIn("needs:", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertNotRegex(self.text, r"(?i)(gh\s+release|releases/(?:create|upload)|softprops/action-gh-release|git\s+push)")
        self.assertNotRegex(self.text, r"(?i)\b(?:apk|opkg)\s+(?:add|install|upgrade)\b")
        self.assertNotRegex(self.text, r"(?i)\b(?:ssh|scp|sysupgrade|uci)\s")
        self.assertNotRegex(self.text, r"/etc/(?:init\.d|apk/keys)")
        self.assertIn("fail-fast: false", self.text)
        self.assertIn("arch: [aarch64_cortex-a53, mipsel_24kc]", self.text)
        self.assertNotIn("openwrt-apk", (ROOT / ".github/workflows/build.yml").read_text())

    def test_cache_is_download_only_fully_keyed_without_restore_prefixes(self):
        cache_steps = re.findall(r"(?ms)^      - .*?\n(?=      - |\Z)", self.text)
        cache_steps = [step for step in cache_steps if "uses: actions/cache@" in step]
        self.assertEqual(len(cache_steps), 1)
        cache = cache_steps[0]
        self.assertRegex(cache, r"(?m)^          path: \.build/downloads$")
        self.assertNotIn("restore-keys:", cache)
        key = next(line for line in cache.splitlines() if line.strip().startswith("key:"))
        for required in ("runner.os", "matrix.arch", "gcc_version", "sdk_sha256", "hashFiles(",
                         "c/**", "packaging/openwrt/**", "scripts/*openwrt*", ".github/workflows/openwrt-apk.yml"):
            self.assertIn(required, key)
        self.assertNotRegex(self.text, r"(?m)^\s*(?:path|restore-keys):.*(?:staging_dir|build_dir|ccache|work/)")

    def test_tools_are_immutable_and_upload_is_success_gated(self):
        actions = re.findall(r"(?m)^\s+-?\s*uses:\s+([^\s#]+)", self.text)
        self.assertTrue(actions)
        for action in actions:
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
        self.assertNotIn("continue-on-error:", self.text)
        self.assertNotIn("if: always()", self.text)
        self.assertIn("if: failure()", self.text)
        self.assertIn("if-no-files-found: error", self.text)
        self.assertIn("failure-openwrt-apk-", self.text)
        self.assertIn("experimental-openwrt-apk-", self.text)
        self.assertIn("github.sha", self.text)
        self.assertIn("github.run_attempt", self.text)
        self.assertIn("include-hidden-files: false", self.text)
        build_start = self.text.index("python3 scripts/build-openwrt-apk.py")
        upload_start = self.text.index("- name: Upload tested")
        self.assertLess(build_start, upload_start)
        self.assertIn('--source-ref "$GITHUB_SHA"', self.text)
        self.assertIn('test "$(git rev-parse HEAD)" = "$GITHUB_SHA"', self.text)
        self.assertIn('sha256sum -c SHA256SUMS', self.text)
        self.assertIn('set -euo pipefail', self.text)
        self.assertNotRegex(self.text, r"\|\|\s*(?:true|:)\b")


if __name__ == "__main__":
    unittest.main()
