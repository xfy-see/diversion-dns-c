"""Smoke-test lite CI shell arguments without invoking compilers or packaging."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def workflow_run(name):
    step = (ROOT / '.github/workflows/build.yml').read_text().split('      - name: ' + name + '\n', 1)[1]
    block = step.split('        run: |\n', 1)[1]
    lines = []
    for line in block.splitlines():
        if line and not line.startswith('          '):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines)) + '\n'


@unittest.skipUnless(shutil.which('bash'), 'bash required for workflow smoke checks')
class LiteWorkflowTests(unittest.TestCase):
    def run_shell(self, script, stubs, env):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'commands.txt'
            result = subprocess.run(['bash', '-c', stubs + '\n' + script], cwd=directory,
                                    env=dict(os.environ, CAPTURE=str(capture), **env),
                                    capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            return capture.read_text().splitlines()

    def test_native_build_uses_explicit_sanitizer_scalar(self):
        script = workflow_run('Build opt-in posix-lite native and ASan/UBSan programs')
        # Bash 3.2 considers an empty array unset under -u, unlike recent Bash.
        self.assertNotRegex(script, r'\b\w+=\(\)')
        self.assertIn('SANITIZE="$sanitize"', script)
        lines = self.run_shell(script, '''
            uname() { printf '%s\\n' Darwin; }
            fake_cc() { printf '%s\\n' 'compiler stub'; }
            make() { printf '%s\\n' "$*" >> "$CAPTURE"; }
        ''', {'CC': 'fake_cc'})
        self.assertEqual(len(lines), 2)
        for line, profile, sanitize in zip(lines, ('native', 'asan'), ('0', '1')):
            self.assertIn('BUILD=../.build/lite/' + profile, line)
            self.assertIn('REGEX_BACKEND=posix-lite', line)
            self.assertIn('SANITIZE=' + sanitize, line)
            self.assertIn('../.build/lite/' + profile + '/tests/nft_cli_driver', line)

    def test_native_pack_options_are_nonempty_on_both_platforms(self):
        script = workflow_run('Package, verify and execute opt-in native lite suite')
        self.assertNotRegex(script, r'\b\w+=\(\)')
        stubs = '''
            uname() { printf '%s\\n' "$HOST_SYSTEM"; }
            cc() { printf '%s\\n' '/mock clang'; }
            python3() { printf '%s\\n' "$*" >> "$CAPTURE"; }
        '''
        for system, target in (('Darwin', 'macos-arm64'), ('Linux', 'linux-amd64')):
            with self.subTest(system=system):
                lines = self.run_shell(script, stubs, {'HOST_SYSTEM': system, 'TARGET': target,
                                                     'GITHUB_SHA': 'a' * 40, 'GITHUB_RUN_ID': '123'})
                self.assertEqual(len(lines), 4)
                packs = [line for line in lines if line.startswith('scripts/artifacts.py pack ')]
                self.assertEqual(len(packs), 2)
                for line in packs:
                    self.assertIn('--regex-backend posix-lite --target ' + target + ' --kind native', line)
                    self.assertEqual('--runtime-file' in line, system == 'Darwin')
                    if system == 'Darwin':
                        self.assertIn('--runtime-file /mock clang/lib/darwin/libclang_rt.asan_osx_dynamic.dylib', line)
                self.assertIn('--checkout .', lines[1])
                self.assertIn('scripts/validate.py --bundle .build/lite-verified', lines[2])


if __name__ == '__main__':
    unittest.main()
