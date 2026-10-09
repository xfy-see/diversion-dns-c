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
