"""Independent release APK checks: no network, compiler or package installation."""
import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
spec = importlib.util.spec_from_file_location('release014', ROOT / 'scripts/publish-v0.1.4.py')
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)
helper = pub.load('managed-packages')


class ManagedRelease(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.folder = self.root / 'inputs'; self.folder.mkdir()
        self.work = self.root / 'work'; self.work.mkdir()
        self.output = self.root / 'assets'; self.output.mkdir()
        self.arch = pub.ARCHES[0]
        self.info = {'source_commit': 'a' * 40, 'managed': {'source_commit': 'a' * 40,
                     'version': pub.PACKAGE_VERSION, 'packages': {}}}
        self.metas = {}
        self.payload = b'synthetic configuration'
        for name in (helper.CORE, helper.UI):
            arch = self.arch if name == helper.CORE else 'noarch'
            deps = helper.CORE_DEPS if name == helper.CORE else [helper.CORE + '=' + pub.PACKAGE_VERSION] + helper.UI_DEPS
            data = ('synthetic apk bytes ' + name).encode()
            filename = f'{name}-{pub.PACKAGE_VERSION}_{arch}.apk'
            (self.folder / filename).write_bytes(data)
            files = {'etc/example': {'sha256': pub.a.digest(self.payload), 'bytes': len(self.payload), 'mode': 0o600}}
            self.info['managed']['packages'][name] = {'filename': filename, 'arch': arch, 'depends': deps,
                'sha256': pub.a.digest(data), 'bytes': len(data), 'files': files}
            meta = {'info': {'name': name, 'arch': arch, 'version': pub.PACKAGE_VERSION, 'depends': deps,
                            'installed-size': len(self.payload)},
                    'paths': [{'name': 'etc', 'acl': {'user': 'root', 'group': 'root'}, 'files': [
                        {'name': 'example', 'hash': pub.a.digest(self.payload), 'size': len(self.payload),
                         'acl': {'user': 'root', 'group': 'root', 'mode': 0o600}}]}]}
            (self.folder / (name + '-metadata.json')).write_text(json.dumps(meta))
            self.metas[filename] = meta

    def check(self, corrupt=None):
        calls = []
        def run(argv):
            calls.append(argv)
            if argv[1] == 'adbdump':
                meta = copy.deepcopy(self.metas[Path(argv[-1]).name])
                if corrupt == 'metadata': meta['info']['arch'] = 'wrong'
                return json.dumps(meta).encode()
            if argv[1] == 'extract':
                root = Path(argv[argv.index('--destination') + 1])
                helper.put(root, 'etc/example', b'bad' if corrupt == 'payload' else self.payload, 0o600)
            return b''
        result = subprocess.CompletedProcess([], 0 if corrupt == 'trust' else 1, b'', b'UNTRUSTED signature')
        with mock.patch.object(pub, 'run', side_effect=run), mock.patch.object(pub.subprocess, 'run', return_value=result):
            reports = pub.recheck_managed(self.folder, self.info, self.arch, self.work, Path('/sdk/apk'), self.root / 'empty')
        return reports, calls

    def test_independent_metadata_extraction_and_unsigned_trust(self):
        reports, calls = self.check()
        self.assertEqual(set(reports), {helper.CORE, helper.UI})
        self.assertEqual(len(calls), 6)
        self.assertEqual(reports[helper.UI]['package_architecture'], 'noarch')

    def test_rejects_mutated_apk_before_executing_tools(self):
        row = self.info['managed']['packages'][helper.CORE]
        (self.folder / row['filename']).write_bytes(b'changed')
        with mock.patch.object(pub, 'run') as run, self.assertRaisesRegex(ValueError, 'bytes differ'):
            pub.recheck_managed(self.folder, self.info, self.arch, self.work, Path('/sdk/apk'), self.root / 'empty')
        run.assert_not_called()

    def test_rejects_changed_metadata(self):
        with self.assertRaisesRegex(ValueError, 'metadata differs'): self.check('metadata')

    def test_rejects_changed_extracted_payload(self):
        with self.assertRaisesRegex(ValueError, 'payload differs'): self.check('payload')

    def test_rejects_unexpected_trust_acceptance(self):
        with self.assertRaisesRegex(ValueError, 'trust rejection'): self.check('trust')

    def test_rejects_missing_or_wrong_managed_identity(self):
        for change in ('missing', 'version', 'commit'):
            info = copy.deepcopy(self.info)
            if change == 'missing': del info['managed']
            elif change == 'version': info['managed']['version'] = '0.1.3-r1'
            else: info['managed']['source_commit'] = 'b' * 40
            with self.subTest(change=change), mock.patch.object(pub, 'run') as run, self.assertRaisesRegex(ValueError, 'identity differs'):
                pub.recheck_managed(self.folder, info, self.arch, self.work, Path('/sdk/apk'), self.root / 'empty')
            run.assert_not_called()

    def test_rejects_wrong_sdk_core_or_preview_ui_dependency(self):
        original = copy.deepcopy(self.info)
        for name, key, value in ((helper.CORE, 'arch', pub.ARCHES[1]),
                                 (helper.UI, 'depends', [helper.CORE + '=0.1.3_pre20261019~aaaaaaaaaaaa-r1'] + helper.UI_DEPS)):
            self.info = copy.deepcopy(original)
            self.info['managed']['packages'][name][key] = value
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'name/dependency differs'):
                self.check()

    def test_export_preserves_bytes_and_records_sdk_origin_without_overwrite(self):
        original = copy.deepcopy(self.info)
        manifest = pub.prepare_managed_assets(self.folder, self.info, self.arch, self.output)
        self.assertEqual(self.info, original)
        self.assertEqual(manifest['sdk_target'], self.arch)
        self.assertEqual(manifest['packages'][helper.UI]['arch'], 'noarch')
        for row in manifest['packages'].values():
            self.assertEqual((self.output / row['filename']).read_bytes(), (self.folder / row['artifact_filename']).read_bytes())
        self.assertEqual(json.loads((self.output / f'managed-packages-{self.arch}.json').read_text()), manifest)
        with self.assertRaises(FileExistsError): pub.prepare_managed_assets(self.folder, self.info, self.arch, self.output)

    def test_export_rejects_changed_input(self):
        self.info['managed']['packages'][helper.CORE]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'export bytes differ'):
            pub.prepare_managed_assets(self.folder, self.info, self.arch, self.output)


if __name__ == '__main__': unittest.main()
