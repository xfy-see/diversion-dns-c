"""Exercise the actual procd init function with isolated dispatch callbacks."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INIT = ROOT / "deployment/openwrt-recovery/diversion-dns-c.init"
DOUBLE = r'''
import fcntl, json, os, pathlib, sys
root = pathlib.Path(os.environ['INIT_TEST_ROOT'])
name = pathlib.Path(sys.argv[0]).name
with (root/'calls').open('a') as f:
    f.write(json.dumps([name]+sys.argv[1:])+'\n')
if name == 'flock':
    fcntl.flock(int(sys.argv[-1]), fcntl.LOCK_EX)
elif name in ('cn-policy.sh', 'cn-data.sh'):
    if os.environ.get('DIVERSION_CN_DEPLOY_LOCK_HELD') != '1':
        sys.exit(97)
    with open(os.environ['DIVERSION_DNS_LOCK'], 'a') as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            sys.exit(98)
    sys.exit(1 if (root/('fail-policy' if name == 'cn-policy.sh' else 'fail-data')).exists() else 0)
'''


class InitFixture(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cn-init-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.base = self.root / "base"
        self.bin = self.root / "bin"
        self.base.mkdir(); self.bin.mkdir()
        (self.base / "active").touch()
        (self.root / "calls").touch()
        for name in ("cn-policy.sh", "cn-data.sh", "apply-policy.sh", "enable-rescue.sh"):
            self.double(self.base / name)
        self.double(self.bin / "flock")
        self.env = dict(os.environ, INIT_TEST_ROOT=str(self.root),
                        DIVERSION_DNS_BASE=str(self.base),
                        DIVERSION_DNS_LOCK=str(self.root / "deploy.lock"),
                        PATH=str(self.bin)+os.pathsep+os.environ["PATH"])

    def double(self, path):
        path.write_text("#!"+sys.executable+"\n"+DOUBLE)
        path.chmod(0o755)

    def managed(self):
        (self.base / "cn-policy/generations").mkdir(parents=True)
        (self.base / "cn-policy/enabled").touch()
        (self.base / "cn-policy/current").symlink_to("generations/approved")

    def call(self, expected=0, inherited=False):
        self.env["INIT_SOURCE"] = str(INIT)
        body = '''
. "$INIT_SOURCE"
record_procd() { printf '%s\n' "$*" >> "$INIT_TEST_ROOT/procd"; }
procd_open_instance() { record_procd open "$@"; }
procd_set_param() { record_procd param "$@"; }
procd_close_instance() { record_procd close; }
'''
        if inherited:
            body += '''
exec 9>"$DIVERSION_DNS_LOCK"
flock 9
export DIVERSION_CN_DEPLOY_LOCK_HELD=1
'''
        result = subprocess.run(["/bin/sh", "-c", body+"start_service\n"],
                                env=self.env, text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, expected, result.stdout+result.stderr)

    def calls(self, name):
        return [x for x in map(json.loads, (self.root / "calls").read_text().splitlines())
                if x[0] == name]

    def test_unmanaged_init_preserves_existing_apply_and_procd_behavior(self):
        self.call()
        self.assertEqual(self.calls("apply-policy.sh"), [["apply-policy.sh"]])
        self.assertFalse(self.calls("cn-policy.sh"))
        self.assertIn("open resolver", (self.root / "procd").read_text())

    def test_managed_boot_verifies_with_lock_then_dispatches_without_raw_apply(self):
        self.managed(); self.call()
        self.assertEqual(self.calls("cn-policy.sh"), [["cn-policy.sh", "audit-runtime"]])
        self.assertEqual(len(self.calls("flock")), 1)
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertIn("open resolver", (self.root / "procd").read_text())

    def test_inherited_deployment_lock_is_not_reacquired_by_init(self):
        self.managed(); self.call(inherited=True)
        # One caller acquisition, no nested acquisition under another descriptor.
        self.assertEqual(len(self.calls("flock")), 1)
        self.assertEqual(self.calls("cn-policy.sh"), [["cn-policy.sh", "audit-runtime"]])
        self.assertTrue((self.root / "procd").exists())

    def test_bad_policy_refuses_procd_start_and_enables_containment(self):
        self.managed(); (self.root / "fail-policy").touch()
        self.call(expected=1)
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertEqual(self.calls("enable-rescue.sh"), [["enable-rescue.sh"]])
        self.assertFalse((self.root / "procd").exists())

    def test_missing_verifier_does_not_revert_to_raw_apply(self):
        self.managed(); (self.base / "cn-policy.sh").unlink()
        self.call(expected=1)
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())

    def test_missing_both_markers_keeps_existing_generation_managed(self):
        self.managed()
        (self.base / "cn-policy/enabled").unlink()
        (self.base / "cn-policy/current").unlink()
        (self.root / "fail-policy").touch()
        self.call(expected=1)
        self.assertTrue(self.calls("cn-policy.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())

    def test_recovering_allows_managed_candidate_start_without_policy_bypass(self):
        self.managed()
        (self.base / "degraded").touch(); (self.base / "recovering").mkdir()
        self.call(inherited=True)
        self.assertTrue(self.calls("cn-policy.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertTrue((self.root / "procd").exists())

    def test_manual_degraded_state_never_dispatches_resolver(self):
        self.managed(); (self.base / "degraded").touch()
        self.call()
        self.assertTrue(self.calls("cn-policy.sh"))
        self.assertFalse((self.root / "procd").exists())

    def managed_data(self):
        (self.base / "cn-data/generations").mkdir(parents=True)
        (self.base / "cn-data/enabled").touch()
        (self.base / "cn-data/current").symlink_to("generations/approved")

    def test_startup_checks_cn_files_before_policy_without_existing_kernel_requirement(self):
        self.managed(); self.managed_data()
        self.call()
        calls = list(map(json.loads, (self.root / "calls").read_text().splitlines()))
        data = calls.index(["cn-data.sh", "check-start"])
        policy = calls.index(["cn-policy.sh", "audit-runtime"])
        self.assertLess(data, policy)
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertTrue((self.root / "procd").exists())

    def test_bad_cn_files_prevent_all_policy_helper_and_procd_dispatch(self):
        self.managed(); self.managed_data()
        (self.root / "fail-data").touch()
        self.call(expected=1)
        self.assertEqual(self.calls("cn-data.sh"), [["cn-data.sh", "check-start"]])
        self.assertFalse(self.calls("cn-policy.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())
        self.assertTrue(self.calls("enable-rescue.sh"))

    def test_missing_cn_verifier_prevents_policy_and_procd_dispatch(self):
        self.managed(); self.managed_data()
        (self.base / "cn-data.sh").unlink()
        self.call(expected=1)
        self.assertFalse(self.calls("cn-policy.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())

    def test_cn_generation_without_markers_still_requires_start_check(self):
        self.managed_data()
        (self.base / "cn-data/enabled").unlink()
        (self.base / "cn-data/current").unlink()
        (self.root / "fail-data").touch()
        self.call(expected=1)
        self.assertTrue(self.calls("cn-data.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())

    def test_recovery_init_with_managed_data_checks_without_nested_lock(self):
        self.managed(); self.managed_data()
        (self.base / "recovering").mkdir(); (self.base / "degraded").touch()
        self.call(inherited=True)
        self.assertEqual(len(self.calls("flock")), 1)
        self.assertTrue(self.calls("cn-data.sh"))
        self.assertTrue((self.root / "procd").exists())

    def test_inactive_init_does_not_touch_policy_or_procd(self):
        self.managed(); (self.base / "active").unlink()
        self.call()
        self.assertFalse(self.calls("cn-policy.sh"))
        self.assertFalse(self.calls("apply-policy.sh"))
        self.assertFalse((self.root / "procd").exists())


if __name__ == "__main__":
    unittest.main()
