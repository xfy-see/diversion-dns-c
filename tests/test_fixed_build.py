"""Guard the fixed runtime dependency and current/historical artifact boundaries."""
from pathlib import Path
import importlib.util
import subprocess
import tempfile
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import artifacts


class FixedBuildTests(unittest.TestCase):
    def test_complete_current_suite(self):
        profile = {'tests': dict.fromkeys(artifacts.TESTS)}
        self.assertEqual(artifacts.test_suite(profile), 'fixed-splitter')
        profile['suite'] = 'fixed-splitter'
        self.assertEqual(artifacts.test_suite(profile), 'fixed-splitter')

    def test_complete_historical_suite(self):
        profile = {'tests': dict.fromkeys(artifacts.LEGACY_TESTS)}
        self.assertEqual(artifacts.test_suite(profile), 'legacy-plugin')
        profile['suite'] = 'legacy-plugin'
        self.assertEqual(artifacts.test_suite(profile), 'legacy-plugin')

    def test_reject_mixed_incomplete_or_wrong_declaration(self):
        for suite in (artifacts.TESTS, artifacts.LEGACY_TESTS):
            for missing in suite:
                with self.subTest(missing=missing, suite=suite):
                    with self.assertRaises(ValueError):
                        artifacts.test_suite({'tests': {name: None for name in suite if name != missing}})
            correct = 'fixed-splitter' if suite == artifacts.TESTS else 'legacy-plugin'
            for wrong in ('unknown', 'legacy-plugin' if correct == 'fixed-splitter' else 'fixed-splitter'):
                with self.assertRaises(ValueError):
                    artifacts.test_suite({'tests': dict.fromkeys(suite), 'suite': wrong})
        with self.assertRaises(ValueError):
            artifacts.test_suite({'tests': dict.fromkeys((*artifacts.TESTS, *artifacts.LEGACY_TESTS))})
        mixed = list(artifacts.TESTS)
        mixed[mixed.index('fixed_engine_test')] = 'engine_test'
        with self.assertRaises(ValueError):
            artifacts.test_suite({'tests': dict.fromkeys(mixed)})

    def test_no_runtime_yaml_dependency(self):
        makefile = (ROOT / 'c/Makefile').read_text()
        self.assertNotIn('libyaml', makefile)
        self.assertNotIn('YAMLSRC', makefile)
        self.assertNotIn('yaml.h', (ROOT / 'c/coremain/engine.c').read_text())
        builder = (ROOT / 'benchmarks/build-c-profiles.py').read_text()
        self.assertNotIn('vendor/libyaml/src', builder)
        self.assertNotIn('vendor/libyaml/include', builder)
        self.assertIn('size_result["disk_bytes"]["libyaml"] != 0', builder)

    def test_standalone_fixture_bundle_imports_without_checkout(self):
        spec = importlib.util.spec_from_file_location('fixed_profile_builder', ROOT / 'benchmarks/build-c-profiles.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            builder.copy_standalone_test_files(ROOT, output)
            self.assertTrue((output / 'c/tests/integration.py').is_file())
            runner = output / 'c/tests/fixed_integration.py'
            # --help imports the actual dependencies but never launches DNS.
            # -E/-s exclude inherited PYTHONPATH and user site-packages.
            result = subprocess.run([sys.executable, '-E', '-s', str(runner),
                                     'unused-program', '--help'], cwd=output,
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('usage:', result.stdout)
            self.assertNotIn('ModuleNotFoundError', result.stderr)

    def test_current_entry_points_use_fixed_harnesses(self):
        for name in ('c/Makefile', '.github/workflows/build.yml', 'scripts/validate.py'):
            source = (ROOT / name).read_text()
            self.assertIn('fixed_config_test', source)
            self.assertIn('fixed_engine_test', source)
        self.assertIn('fixed_integration.py', (ROOT / 'c/Makefile').read_text())
        self.assertIn('"config.conf"', (ROOT / 'c/main.c').read_text())


if __name__ == '__main__':
    unittest.main()
