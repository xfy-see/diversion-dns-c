"""Guard the dependency contract without invoking a compiler."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_pcre2", ROOT / "scripts/build-native-pcre2.py")
native = importlib.util.module_from_spec(spec)
spec.loader.exec_module(native)


# 配置契约测试：mock 在调用构建命令前拦截输入/目录错误，不实际编译依赖。
class PCRE2ProfileTests(unittest.TestCase):
    def test_native_and_static_share_no_unicode_options(self):
        options = native.profiles.PCRE2_CONFIGURE_OPTIONS
        for option in ("--disable-unicode", "--disable-jit", "--disable-pcre2-16",
                       "--disable-pcre2-32", "--disable-shared", "--enable-static"):
            self.assertIn(option, options)
        self.assertNotIn("--enable-unicode", options)
        source = (ROOT / "benchmarks/build-c-profiles.py").read_text()
        self.assertIn('"Unicode disabled"', source)
        self.assertIn('] + PCRE2_CONFIGURE_OPTIONS + [', source)

    def test_size_optimization_flags_are_shared(self):
        self.assertEqual(native.profiles.OPTFLAGS[:2], ["-Os", "-flto"])
        self.assertIn("-flto", native.profiles.STATIC_LDFLAGS)
        self.assertIn("-static", native.profiles.STATIC_LDFLAGS)
        comparison = (ROOT / "benchmarks/compare-regex-backends.py").read_text()
        self.assertIn("OPTFLAGS = PROFILE.OPTFLAGS.copy()", comparison)
        self.assertIn("LDFLAGS = PROFILE.STATIC_LDFLAGS.copy()", comparison)
        makefile = (ROOT / "c/Makefile").read_text()
        self.assertIn("CFLAGS ?= -Os -flto -g", makefile)
        self.assertIn("LDFLAGS ?= -flto", makefile)
        self.assertIn("-UNDEBUG", makefile)
        self.assertNotIn("fno-unwind", makefile)
        standalone = (ROOT / "c/tests/nft_cli_test.py").read_text()
        self.assertIn("['-flto','-UNDEBUG'", standalone)
        self.assertIn("else: flags += ['-Os']", standalone)

    def test_dependency_features_verified_after_configure(self):
        good = "#define SUPPORT_PCRE2_8 1\n"
        native.profiles.verify_pcre2_config(good)
        with self.assertRaises(native.profiles.BuildError):
            native.profiles.verify_pcre2_config("")
        for feature in ("SUPPORT_JIT", "SUPPORT_UNICODE", "SUPPORT_PCRE2_16", "SUPPORT_PCRE2_32"):
            with self.subTest(feature=feature), self.assertRaises(native.profiles.BuildError):
                native.profiles.verify_pcre2_config(good + "#define " + feature + " 1\n")

    def test_lto_dependency_identity_is_not_inferred_from_size(self):
        library = Path("/verified/libpcre2-8.a")
        symbols = "pcre2_compile_8\npcre2_match_8\n"
        verify = native.profiles.verify_backend_link
        result = verify(["-static", str(library)], library, symbols, "pcre2")
        self.assertTrue(result["pcre2_symbols_in_diagnostic"])
        self.assertTrue(verify([str(library)], library, "_pcre2_default_tables_8\n", "pcre2")
                        ["pcre2_symbols_in_diagnostic"])
        self.assertFalse(verify(["-static"], library, "regcomp\nregexec\n", "posix-lite")
                         ["pcre2_symbols_in_diagnostic"])
        bad = [([], symbols, "pcre2"), ([str(library)], "", "pcre2"),
               (["/wrong/libpcre2-8.a"], symbols, "pcre2"),
               ([str(library)], symbols, "posix-lite"), ([], symbols, "posix-lite"),
               (["/bad/libyaml.a"], "", "posix-lite")]
        for args, text, backend in bad:
            with self.subTest(args=args, backend=backend), self.assertRaises(native.profiles.BuildError):
                verify(args, library, text, backend)

    def test_native_make_defaults_are_profile_isolated(self):
        makefile = (ROOT / "c/Makefile").read_text()
        self.assertIn("BUILD ?= ../.build/c-native-no-unicode-no-jit", makefile)
        self.assertIn("PCRE2_PREFIX ?= ../.build/pcre2-8-no-unicode-no-jit", makefile)
        self.assertNotIn("else echo -lpcre2-8", makefile)

    def test_existing_output_cannot_reuse_stale_dependency(self):
        with tempfile.TemporaryDirectory() as folder:
            with mock.patch("sys.argv", ["build", "--archive", "input.tar.gz", "--output", folder]), \
                 mock.patch.object(native.profiles, "record", return_value={"sha256": native.profiles.PCRE2_SHA256}), \
                 mock.patch.object(native.profiles, "extract_archive") as extract:
                with self.assertRaises(FileExistsError):
                    native.main()
                extract.assert_not_called()

    def test_wrong_archive_rejected_before_any_build(self):
        with mock.patch("sys.argv", ["build", "--archive", "input.tar.gz", "--output", "unused"]), \
             mock.patch.object(native.profiles, "record", return_value={"sha256": "wrong"}), \
             mock.patch.object(native.profiles, "extract_archive") as extract:
            with self.assertRaises(SystemExit) as error:
                native.main()
            self.assertEqual(error.exception.code, 2)
            extract.assert_not_called()


if __name__ == "__main__":
    unittest.main()
