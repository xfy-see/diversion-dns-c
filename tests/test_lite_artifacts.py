"""Exercise opt-in backend metadata and packaging without compiling C."""
from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import artifacts as a
import validate

COMMIT = 'a' * 40


class LiteArtifactTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'input.c').write_bytes(b'source bytes\n')
        (self.source / 'VERSION').write_text('0.1.0\n')
        self.tree = {'input.c': {'git_blob': a.blob(b'source bytes\n'), 'mode': 0o644},
                     'VERSION': {'git_blob': a.blob(b'0.1.0\n'), 'mode': 0o644}}
        self.output = self.root / 'bundle.tar.gz'

    def build(self, label='native', backend='posix-lite', licenses=False, stamp=True):
        folder = self.root / label
        (folder / 'tests').mkdir(parents=True)
        (folder / 'mosdns-c').write_bytes(b'application bytes')
        for name in a.TESTS:
            (folder / 'tests' / name).write_bytes(name.encode())
        if stamp:
            (folder / 'regex-backend').write_text(backend + '\n')
        if licenses:
            (folder / 'licenses').mkdir()
            for name in a.PCRE2_LICENSES:
                (folder / 'licenses' / name).write_text('license text\n')
        return folder

    def pack(self, folders, backend='posix-lite'):
        args = SimpleNamespace(profile=[f'{p.name}={p}' for p in folders], regex_backend=backend,
                               target='linux-amd64', kind='static' if folders[0].name == 'static' else 'native',
                               logs=[], runtime_file=[], output=self.output)
        env = {'GITHUB_SHA': COMMIT, 'GITHUB_REPOSITORY': a.REPO,
               'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
        with mock.patch.object(a, 'ROOT', self.source), \
                mock.patch.object(a, 'git_tree', return_value=self.tree), \
                mock.patch.object(a.subprocess, 'check_output', return_value=COMMIT.encode()), \
                mock.patch.dict(os.environ, env), redirect_stdout(io.StringIO()):
            a.pack(args)
        return a.read_archive(self.output, COMMIT, 123)

    def rewrite(self, manifest, contents):
        """Produce a self-consistent archive to isolate semantic rejection."""
        with tarfile.open(self.output, 'w:gz') as archive:
            rows = [('manifest.json', json.dumps(manifest).encode()), *contents.items()]
            for name, data in rows:
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return a.read_archive(self.output, COMMIT, 123)

    @staticmethod
    def set_payload(manifest, contents, name, data, mode=0o644):
        contents[name] = data
        manifest['files'][name] = {'bytes': len(data), 'sha256': a.digest(data), 'mode': mode}

    @staticmethod
    def drop_payload(manifest, contents, name):
        del contents[name]
        del manifest['files'][name]

    def static_manifest(self, folder):
        """Model the existing non-Make PCRE2 builder's complete evidence."""
        app = (folder / 'mosdns-c').read_bytes()
        size = folder / 'size'
        size.mkdir()
        report = {'release': {'sha256': a.digest(app)}, 'disk_bytes': {'other': len(app)},
                  'map_replay': {'sha256': a.digest(app)},
                  'diagnostic': {'alloc_section_shapes_equal': True}}
        files = {'diagnostic': ('mosdns-c.unstripped', app + b'debug'),
                 'mapped': ('mosdns-c.mapped', app), 'map': ('mosdns-c.map', b'link map'),
                 'report': ('attribution.json', json.dumps(report).encode())}
        for name, data in files.values():
            (size / name).write_bytes(data)
        manifest = {'status': 'complete', 'source_unchanged': True, 'commands': [{'exit_code': 0}],
                    'binary': {'sha256': a.digest(app), 'bytes': len(app)}, 'inputs': {},
                    'test_binaries': {name: {'sha256': a.digest((folder / 'tests' / name).read_bytes())}
                                      for name in a.TESTS},
                    'size_attribution': {key: {'sha256': a.digest(data)}
                                         for key, (_, data) in files.items()}}
        (folder / 'manifest.json').write_text(json.dumps(manifest))

    def test_cli_defaults_to_pcre2(self):
        argv = ['artifacts.py', 'pack', '--profile', 'native=unused', '--target', 'linux-amd64',
                '--kind', 'native', '--output', 'unused.tar.gz']
        with mock.patch.object(sys, 'argv', argv), mock.patch.object(a, 'pack') as pack:
            a.main()
        self.assertEqual(pack.call_args.args[0].regex_backend, 'pcre2')

    def test_cli_rejects_unknown_backend(self):
        argv = ['artifacts.py', 'pack', '--profile', 'native=unused', '--target', 'linux-amd64',
                '--kind', 'native', '--output', 'unused.tar.gz', '--regex-backend', 'unknown']
        with mock.patch.object(sys, 'argv', argv), redirect_stdout(io.StringIO()), \
                mock.patch('sys.stderr', new_callable=io.StringIO), self.assertRaises(SystemExit) as error:
            a.main()
        self.assertEqual(error.exception.code, 2)

    def test_backend_enum_and_historical_default(self):
        self.assertEqual(a.regex_backend({}), 'pcre2')
        for backend in a.REGEX_BACKENDS:
            self.assertEqual(a.regex_backend({'regex_backend': backend}), backend)
        for backend in ('unknown', '', None, True, ['pcre2']):
            with self.subTest(backend=backend), self.assertRaisesRegex(ValueError, 'invalid regex backend'):
                a.regex_backend({'regex_backend': backend})

    def test_native_lite_packages_each_profile_without_pcre2_licenses(self):
        m, files = self.pack([self.build('native'), self.build('asan')])
        self.assertEqual(set(m['profiles']), {'native', 'asan'})
        for label, profile in m['profiles'].items():
            self.assertEqual(profile['regex_backend'], 'posix-lite')
            self.assertEqual(files[f'builds/{label}/regex-backend'], b'posix-lite\n')
            self.assertEqual(set(profile['tests']), set(a.TESTS))
        self.assertFalse(any('/licenses/' in name for name in files))
        self.assertEqual(files['source/input.c'], b'source bytes\n')

    def test_static_lite_packages_without_pcre2_or_size_manifest(self):
        m, files = self.pack([self.build('static')])
        self.assertEqual(m['kind'], 'static')
        self.assertEqual(m['profiles']['static']['regex_backend'], 'posix-lite')
        self.assertNotIn('size', m['profiles']['static'])
        self.assertNotIn('builds/static/manifest.ci.json', files)

    def test_native_pcre2_still_packages_licenses_and_stamp(self):
        m, files = self.pack([self.build(backend='pcre2', licenses=True)], 'pcre2')
        self.assertEqual(m['profiles']['native']['regex_backend'], 'pcre2')
        for name in a.PCRE2_LICENSES:
            self.assertIn('builds/native/licenses/' + name, files)

    def test_pcre2_pack_requires_both_licenses(self):
        folder = self.build(backend='pcre2', licenses=True)
        for name in a.PCRE2_LICENSES:
            path = folder / 'licenses' / name
            data = path.read_bytes()
            path.unlink()
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'invalid payload'):
                self.pack([folder], 'pcre2')
            path.write_bytes(data)

    def test_make_profiles_cannot_omit_stamp(self):
        for label, backend in (('native', 'pcre2'), ('asan', 'posix-lite'), ('static', 'posix-lite')):
            folder = self.build(label, backend=backend, licenses=backend == 'pcre2', stamp=False)
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'missing regex backend stamp'):
                self.pack([folder], backend)

    def test_pack_cannot_relabel_stamp_or_follow_symlink(self):
        folder = self.build()
        stamp = folder / 'regex-backend'
        for data in (b'pcre2\n', b'posix-lite', b'unknown\n'):
            stamp.write_bytes(data)
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, 'regex backend stamp differs'):
                self.pack([folder])
        stamp.unlink()
        target = self.root / 'stamp'
        target.write_bytes(b'posix-lite\n')
        stamp.symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'regex backend stamp differs'):
            self.pack([folder])

    def test_existing_static_pcre2_manifest_path_is_preserved(self):
        folder = self.build('static', 'pcre2', licenses=True, stamp=False)
        self.static_manifest(folder)
        m, files = self.pack([folder], 'pcre2')
        self.assertEqual(m['profiles']['static']['regex_backend'], 'pcre2')
        self.assertIn('size', m['profiles']['static'])
        self.assertIn('builds/static/manifest.ci.json', files)
        self.assertNotIn('builds/static/regex-backend', files)

    def test_static_manifest_cannot_claim_a_different_backend(self):
        folder = self.build('static', 'pcre2', licenses=True, stamp=False)
        self.static_manifest(folder)
        path = folder / 'manifest.json'
        manifest = json.loads(path.read_text())
        manifest['backend_verification'] = {'backend': 'posix-lite'}
        path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(ValueError, 'static regex backend differs'):
            self.pack([folder], 'pcre2')

    def test_lite_cannot_reuse_pcre2_build_manifest(self):
        folder = self.build('static')
        self.static_manifest(folder)
        with self.assertRaisesRegex(ValueError, 'PCRE2 build manifest cannot describe posix-lite'):
            self.pack([folder])

    def test_pack_rejects_unknown_backend(self):
        with self.assertRaisesRegex(ValueError, 'invalid regex backend'):
            self.pack([self.build()], 'invalid')

    def test_archive_rejects_unknown_or_changed_backend(self):
        m, files = self.pack([self.build()])
        for backend, error in (('unknown', 'invalid regex backend'), ('pcre2', 'regex backend stamp differs')):
            changed = copy.deepcopy(m)
            changed['profiles']['native']['regex_backend'] = backend
            with self.subTest(backend=backend), self.assertRaisesRegex(ValueError, error):
                self.rewrite(changed, files)

    def test_archive_rejects_lite_missing_or_altered_stamp(self):
        m, files = self.pack([self.build()])
        name = 'builds/native/regex-backend'
        for data, mode in ((b'pcre2\n', 0o644), (b'posix-lite\n', 0o755)):
            changed, payload = copy.deepcopy(m), dict(files)
            self.set_payload(changed, payload, name, data, mode)
            with self.assertRaisesRegex(ValueError, 'regex backend stamp differs'):
                self.rewrite(changed, payload)
        self.drop_payload(m, files, name)
        with self.assertRaisesRegex(ValueError, 'missing regex backend stamp'):
            self.rewrite(m, files)

    def test_archive_requires_explicit_pcre2_license_set(self):
        m, files = self.pack([self.build(backend='pcre2', licenses=True)], 'pcre2')
        for name in a.PCRE2_LICENSES:
            changed, payload = copy.deepcopy(m), dict(files)
            self.drop_payload(changed, payload, 'builds/native/licenses/' + name)
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'PCRE2 licenses missing'):
                self.rewrite(changed, payload)

    def test_archived_pcre2_metadata_needs_neither_enum_nor_stamp(self):
        m, files = self.pack([self.build(backend='pcre2', licenses=True)], 'pcre2')
        del m['profiles']['native']['regex_backend']
        self.drop_payload(m, files, 'builds/native/regex-backend')
        for name in a.PCRE2_LICENSES:
            self.drop_payload(m, files, 'builds/native/licenses/' + name)
        restored, _ = self.rewrite(m, files)
        self.assertEqual(a.regex_backend(restored['profiles']['native']), 'pcre2')

    def test_lite_cannot_claim_legacy_harness_suite(self):
        m, files = self.pack([self.build()])
        profile = m['profiles']['native']
        profile['suite'] = 'legacy-plugin'
        profile['tests'] = dict.fromkeys(a.LEGACY_TESTS)
        with self.assertRaisesRegex(ValueError, 'legacy suite cannot use posix-lite'):
            self.rewrite(m, files)

    def test_lite_extract_and_verification_detect_tampering(self):
        self.pack([self.build()])
        bundle = self.root / 'verified'
        args = SimpleNamespace(archive=self.output, expected_commit=COMMIT, expected_run_id=123,
                               archive_sha256=a.digest(self.output.read_bytes()), checkout=None, output=bundle)
        with redirect_stdout(io.StringIO()):
            a.extract(args)
        self.assertEqual(a.verify_bundle(bundle)['profiles']['native']['regex_backend'], 'posix-lite')
        (bundle / 'builds/native/regex-backend').write_bytes(b'pcre2\n')
        with self.assertRaisesRegex(ValueError, 'verified bundle changed'):
            a.verify_bundle(bundle)

    def test_validator_selects_lite_fixture_only_when_explicit(self):
        driver = Path('/bundle/builds/native/tests/domain_driver')
        expected = [sys.executable, self.source / 'c/tests/domain_fixture.py', driver]
        for profile in ({}, {'regex_backend': 'pcre2'}):
            self.assertEqual(validate.domain_fixture_command(self.source, driver, profile), expected)
        self.assertEqual(validate.domain_fixture_command(self.source, driver, {'regex_backend': 'posix-lite'}),
                         expected + ['--backend', 'posix-lite'])
        with self.assertRaisesRegex(ValueError, 'invalid regex backend'):
            validate.domain_fixture_command(self.source, driver, {'regex_backend': 'invalid'})


if __name__ == '__main__':
    unittest.main()
