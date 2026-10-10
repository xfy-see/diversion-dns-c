"""Local OpenWrt source staging and dependency-check contracts; no compiler used."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class OpenWrtPackage(unittest.TestCase):
    def test_snapshot_and_manifest(self):
        stage = load("stage-openwrt-package")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "package"
            manifest = stage.stage(path)
            self.assertEqual(len(manifest["source_commit"]), 40)
            self.assertTrue((path / "src/c/pkg/regex_posix_lite.h").is_file())
            self.assertEqual(manifest, json.loads((path / "source-manifest.json").read_text()))
            with self.assertRaisesRegex(ValueError, "already exists"):
                stage.stage(path)
            self.assertEqual(manifest, json.loads((path / "source-manifest.json").read_text()))

    def test_package_is_explicit_and_does_not_autostart(self):
        text = (ROOT / "packaging/openwrt/Makefile").read_text()
        for required in ["REGEX_BACKEND=posix-lite", "PKG_BUILD_FLAGS:=lto gc-sections",
                         "-static-libgcc", "stack-size=1048576", "-Os -std=c11",
                         "DEPENDS:=+libpthread", "/usr/sbin/diversion-dns-c-lite"]:
            self.assertIn(required, text)
        for excluded in ["-static ", "+libpcre", "+libyaml", "/etc/init.d", "postinst", "DEFAULT:=y"]:
            self.assertNotIn(excluded, text)

    def test_guest_absolute_symlink_stays_in_rootfs(self):
        checker = load("check-openwrt-elf")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "lib").mkdir()
            (root / "lib/libc.so").write_bytes(b"test")
            (root / "lib/ld-musl-aarch64.so.1").symlink_to("/lib/libc.so")
            self.assertEqual(checker.rooted(root, "/lib/ld-musl-aarch64.so.1"), root / "lib/libc.so")
            with self.assertRaisesRegex(ValueError, "traversal"):
                checker.rooted(root, "/lib/../../etc/passwd")

    def test_symbols_preserve_strong_and_optional_distinction(self):
        checker = load("check-openwrt-elf")
        text = ("1: 0000 0 FUNC GLOBAL DEFAULT UND regcomp\n"
                "2: 0000 0 FUNC WEAK DEFAULT UND optional_hook\n"
                "3: 0010 4 FUNC GLOBAL DEFAULT 7 regexec\n")
        with mock.patch.object(checker, "readelf", return_value=text) as read:
            self.assertEqual(checker.symbols(Path("unused")),
                             ({"regcomp"}, {"regexec"}, {"optional_hook"}))
            self.assertEqual(read.call_args.args[1:], ("--use-dynamic", "--symbols"))

    def test_versioned_symbols_do_not_silently_match_by_name(self):
        checker = load("check-openwrt-elf")
        with mock.patch.object(checker, "readelf", return_value=
                               "1: 0000 0 FUNC GLOBAL DEFAULT UND memcpy@GLIBC_2.17\n"):
            with self.assertRaisesRegex(ValueError, "versioned symbol"):
                checker.symbols(Path("unused"))


if __name__ == "__main__":
    unittest.main()
