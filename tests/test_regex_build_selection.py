"""Backend build isolation checks; no C compiler is run."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which("make"), "make is needed to inspect backend selection")
class RegexBuildSelection(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.build = pathlib.Path(self.temporary.name) / "build"

    def make(self, backend, *args):
        return subprocess.run(["make", "--no-print-directory", "-C", str(ROOT / "c"),
                               "BUILD=" + str(self.build), "REGEX_BACKEND=" + backend, *args],
                              text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    def test_default_goal_is_all(self):
        default = self.make("posix-lite", "-n")
        explicit = self.make("posix-lite", "-n", "all")
        self.assertEqual(default.returncode, 0, default.stdout)
        self.assertEqual(default.stdout, explicit.stdout)
        self.assertIn(str(self.build / "mosdns-c"), default.stdout)
        self.assertIn("-DMD_REGEX_POSIX=1", default.stdout)
        self.assertNotIn("libpcre2-8.a", default.stdout)

    def test_size_flags_apply_to_app_and_standalone_driver(self):
        app = self.make("posix-lite", "-n", "all")
        self.assertEqual(app.returncode, 0, app.stdout)
        self.assertIn("-Os -flto -g -UNDEBUG", app.stdout)
        app_link = next(line for line in app.stdout.splitlines()
                        if " -o " + str(self.build / "mosdns-c") in line)
        self.assertIn("-flto", app_link)
        driver = self.make("posix-lite", "-n", str(self.build / "tests/nft_cli_driver"))
        self.assertEqual(driver.returncode, 0, driver.stdout)
        self.assertIn("-Os -flto -g -UNDEBUG", driver.stdout)
        sanitized = self.make("posix-lite", "-n", "SANITIZE=1", "all")
        self.assertEqual(sanitized.returncode, 0, sanitized.stdout)
        self.assertIn("-O1 -fsanitize=address,undefined -fno-omit-frame-pointer", sanitized.stdout)
        self.assertIn("-flto -fsanitize=address,undefined -o", sanitized.stdout)

    def test_pcre2_is_still_default(self):
        result = subprocess.run(["make", "--no-print-directory", "-C", str(ROOT / "c"),
                                 "BUILD=" + str(self.build), "-n", "all"],
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn("libpcre2-8.a", result.stdout)
        self.assertNotIn("-DMD_REGEX_POSIX=1", result.stdout)

    def test_unknown_backend_rejected(self):
        result = self.make("unknown", "-n", "all")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be pcre2 or posix-lite", result.stdout)

    def test_unstamped_nonempty_build_rejected(self):
        self.build.mkdir()
        old = self.build / "old.o"
        old.write_bytes(b"existing object must not be relabeled")
        result = self.make("posix-lite", "check-backend")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unmarked nonempty", result.stdout)
        self.assertFalse((self.build / "regex-backend").exists())
        self.assertEqual(old.read_bytes(), b"existing object must not be relabeled")

    def test_backend_stamp_cannot_be_changed(self):
        result = self.make("pcre2", "check-backend")
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.make("pcre2", "check-backend")
        self.assertEqual(result.returncode, 0, result.stdout)
        result = self.make("posix-lite", "check-backend")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("backend changed", result.stdout)
        self.assertEqual((self.build / "regex-backend").read_text(), "pcre2\n")


if __name__ == "__main__":
    unittest.main()
