"""Exercise the shell transaction with real files and injected command failures.

The separate Lua tests validate the parser/kernel commands. These tests exercise
publication, interrupted transactions, failed restarts and operator-held fallback.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/openwrt-recovery/cn-data.sh"
DOUBLE = r'''
import fcntl, hashlib, json, os, pathlib, shutil, sys
r=pathlib.Path(os.environ['CN_TX_TEST'])
n=pathlib.Path(sys.argv[0]).name
a=sys.argv[1:]
control=json.loads((r/'control').read_text())
with (r/'calls').open('a') as f: f.write(json.dumps([n]+a)+'\n')
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
if n=='sha256sum':
 if not a: print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest()+'  -')
 else:
  for p in a: print(digest(pathlib.Path(p))+'  '+p)
elif n=='flock':
 fcntl.flock(int(a[-1]),fcntl.LOCK_EX)
elif n in ('logger','sync','probe'): pass
elif n=='mv':
 a=[v for v in a if not v.startswith('-')]
 if pathlib.Path(a[1]).name=='current' and control.get('mv_fail_target')==os.readlink(a[0]): sys.exit(1)
 os.replace(a[0],a[1])
elif n=='resolver':
 sys.exit(1 if control.get('check_fail') else 0)
elif n=='diversion-dns-c':
 generation=os.readlink(r/'base/cn-data/current')
 with (r/'restarts').open('a') as f: f.write(generation+'\n')
 sys.exit(1 if control.get('restart_fail')==generation else 0)
elif n=='lua':
 cmd=a[1]; args=a[2:]
 if cmd=='prepare':
  ip,site,template,baseline,out,ih,sh=map(str,args)
  ip,site,template,out=map(pathlib.Path,(ip,site,template,out))
  if digest(ip)!=ih or digest(site)!=sh or not ip.read_bytes() or not site.read_bytes(): sys.exit(1)
  for src,name in [(ip,'cn-ip.txt'),(site,'cn-site.txt'),(template,'sets.nft')]: shutil.copyfile(src,out/name)
  (out/'replace.nft').write_text('replace '+digest(ip))
  m={p.name:digest(p) for p in out.iterdir() if p.is_file() and p.name!='result.json'}
  (out/'manifest.tsv').write_text(json.dumps(m,sort_keys=True))
  print('{}')
 else:
  g=pathlib.Path(args[0])
  try:
   m=json.loads((g/'manifest.tsv').read_text())
   if any(digest(g/name)!=h for name,h in m.items()): sys.exit(1)
  except (OSError,ValueError): sys.exit(1)
  expected=(g/'replace.nft').read_text()
  if cmd=='repair':
   if control.get('repair_fail')==g.name: sys.exit(1)
   (r/'kernel').write_text(expected)
  elif cmd=='audit':
   sys.exit(0 if (r/'kernel').read_text()==expected else 2)
elif n=='wget': sys.exit(1)
else: raise RuntimeError(n)
'''


class CNTransactionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.base = self.root / "base"
        self.bin = self.root / "bin"
        self.init = self.root / "init"
        for p in (self.base, self.bin, self.init):
            p.mkdir()
        for name in ("lua", "flock", "sha256sum", "logger", "sync", "mv", "resolver", "probe", "wget"):
            self.double(self.bin / name)
        self.double(self.init / "diversion-dns-c")
        (self.root / "control").write_text("{}")
        (self.root / "calls").touch()
        (self.root / "uptime").write_text("1234.00 5678.00\n")
        (self.root / "kernel").write_text("")
        (self.base / "cn-ip.txt").write_text("1.0.1.0/24\n2400:3200::/32\n")
        (self.base / "cn-site.txt").write_text("qq.com\nbaidu.com\n")
        (self.base / "sets.nft").write_text("owned and unrelated sets\n")
        (self.base / "config.conf").write_text(f"cn_domain_file={self.base}/cn-site.txt\n")
        (self.base / "unrelated").write_text("must survive")
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ["PATH"],
                        CN_TX_TEST=str(self.root), DIVERSION_DNS_BASE=str(self.base),
                        DIVERSION_DNS_INITDIR=str(self.init), DIVERSION_DNS_LOCK=str(self.root / "lock"),
                        DIVERSION_DNS_RUN=str(self.root / "run"), DIVERSION_CN_BINARY=str(self.bin / "resolver"),
                        DIVERSION_CN_TEST_PROBE=str(self.bin / "probe"), DIVERSION_CN_TEST_UPTIME=str(self.root / "uptime"))

    def double(self, p):
        p.write_text(f"#!{sys.executable}\n" + DOUBLE)
        p.chmod(0o755)

    def call(self, *args, ok=True):
        p = subprocess.run(["sh", str(SCRIPT), *args], env=self.env, text=True, capture_output=True)
        if ok:
            self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        else:
            self.assertNotEqual(p.returncode, 0, p.stdout+p.stderr)
        self.assertEqual((self.base / "unrelated").read_text(), "must survive")
        return p

    def sha(self, p):
        return hashlib.sha256(p.read_bytes()).hexdigest()

    def seed(self):
        ip, site = self.base / "cn-ip.txt", self.base / "cn-site.txt"
        (self.root / "kernel").write_text("replace "+self.sha(ip))
        self.call("seed", self.sha(ip), self.sha(site))
        return self.active()

    def active(self):
        return os.readlink(self.base / "cn-data/current").split("/")[-1]

    def stage(self):
        ip, site = self.root / "next-ip", self.root / "next-site"
        ip.write_text("1.0.1.0/24\n2400:3200::/32\n223.5.5.0/24\n")
        site.write_text("qq.com\nbaidu.com\nnew.example.cn\n")
        return self.call("stage", str(ip), str(site), self.sha(ip), self.sha(site)).stdout.strip()

    def control(self, **values):
        (self.root / "control").write_text(json.dumps(values))

    def test_stage_is_inert_then_activate_and_rollback(self):
        old = self.seed()
        kernel = (self.root / "kernel").read_bytes()
        new = self.stage()
        self.assertEqual(self.active(), old)
        self.assertEqual((self.root / "kernel").read_bytes(), kernel)
        self.call("activate", new)
        self.assertEqual(self.active(), new)
        self.assertIn("new.example.cn", (self.base / "cn-site.txt").read_text())
        self.call("rollback")
        self.assertEqual(self.active(), old)
        self.assertEqual((self.root / "kernel").read_bytes(), kernel)

    def test_bad_hash_empty_and_config_error_leave_live_data(self):
        old = self.seed()
        candidate = self.root / "empty"
        candidate.touch()
        site = self.base / "cn-site.txt"
        self.call("stage", str(candidate), str(site), self.sha(candidate), self.sha(site), ok=False)
        self.call("stage", str(site), str(site), "0"*64, self.sha(site), ok=False)
        self.control(check_fail=True)
        self.call("stage", str(site), str(site), self.sha(site), self.sha(site), ok=False)
        self.assertEqual(self.active(), old)
        self.assertFalse((self.root / "restarts").exists())

    def test_restart_failure_rolls_back_kernel_pointer_and_service(self):
        old = self.seed()
        new = self.stage()
        self.control(restart_fail="generations/"+new)
        self.call("activate", new, ok=False)
        self.assertEqual(self.active(), old)
        self.assertFalse((self.base / "cn-data/pending").exists())
        self.assertEqual((self.root / "restarts").read_text().splitlines(),
                         ["generations/"+new, "generations/"+old])

    def test_kernel_failure_does_not_commit_candidate(self):
        old = self.seed()
        new = self.stage()
        self.control(repair_fail=new)
        self.call("activate", new, ok=False)
        self.assertEqual(self.active(), old)

    def test_pointer_rename_failure_cannot_report_activation_success(self):
        old = self.seed()
        new = self.stage()
        self.control(mv_fail_target="generations/"+new)
        self.call("activate", new, ok=False)
        self.assertEqual(self.active(), old)
        self.assertFalse((self.base / "cn-data/pending").exists())

    def test_interrupted_transaction_is_restored(self):
        old = self.seed()
        new = self.stage()
        pointer = self.base / "cn-data/current"
        pointer.unlink()
        pointer.symlink_to("generations/"+new)
        (self.base / "cn-data/pending").write_text(old+" "+new+"\n")
        (self.root / "kernel").write_text("damaged")
        self.call("reconcile")
        self.assertEqual(self.active(), old)
        self.assertFalse((self.base / "cn-data/pending").exists())

    def test_live_set_damage_and_replaced_file_are_repaired(self):
        old = self.seed()
        (self.root / "kernel").write_text("empty")
        site = self.base / "cn-site.txt"
        site.unlink()
        site.write_text("")
        self.call("audit-runtime", "--force")
        self.assertEqual(self.active(), old)
        self.assertTrue(site.is_symlink())
        self.assertIn("qq.com", site.read_text())
        self.assertTrue((self.root / "kernel").read_text().startswith("replace "))

    def test_corrupt_active_snapshot_restores_independent_seed_copy(self):
        old = self.seed()
        (self.base / "cn-site.txt").write_text("")
        self.call("audit-runtime", "--force")
        self.assertNotEqual(self.active(), old)
        self.assertIn("qq.com", (self.base / "cn-site.txt").read_text())

    def test_repair_reload_failure_is_durable_and_retried(self):
        old = self.seed()
        site = self.base / "cn-site.txt"
        site.unlink()
        site.write_text("")
        self.control(restart_fail="generations/"+old)
        self.call("audit-runtime", "--force", ok=False)
        self.assertTrue((self.base / "cn-data/repair-pending").exists())
        self.control()
        self.call("audit-runtime", "--force")
        self.assertFalse((self.base / "cn-data/repair-pending").exists())
        self.assertEqual(len((self.root / "restarts").read_text().splitlines()), 2)

    def test_reconcile_does_not_replace_requested_candidate(self):
        old = self.seed()
        interrupted = self.stage()
        (self.base / "cn-data/pending").write_text(old+" "+interrupted+"\n")
        ip, site = self.root / "another-ip", self.root / "another-site"
        ip.write_text("1.0.1.0/24\n2400:3200::/32\n119.29.0.0/16\n")
        site.write_text("qq.com\nbaidu.com\nthird.example.cn\n")
        requested = self.call("stage", str(ip), str(site), self.sha(ip), self.sha(site)).stdout.strip()
        self.call("activate", requested)
        self.assertEqual(self.active(), requested)

    def test_manual_fallback_is_not_restarted_by_data_update(self):
        self.seed()
        new = self.stage()
        (self.base / "degraded").touch()
        self.call("activate", new)
        self.assertEqual(self.active(), new)
        self.assertFalse((self.root / "restarts").exists())
        self.assertTrue((self.base / "degraded").exists())

    def test_dns_recovery_transaction_excludes_data_activation(self):
        old = self.seed()
        new = self.stage()
        (self.base / "recovering").mkdir()
        p = self.call("activate", new, ok=False)
        self.assertEqual(p.returncode, 75)
        self.assertEqual(self.active(), old)
        self.assertEqual(self.call("reconcile", ok=False).returncode, 75)
        self.assertEqual(self.call("rollback", ok=False).returncode, 75)

    def test_lost_pointer_recovers_previous_verified_snapshot(self):
        self.seed()
        (self.base / "cn-data/current").unlink()
        self.call("audit-runtime", "--force")
        self.assertTrue((self.base / "cn-data/enabled").exists())
        self.assertIn("qq.com", (self.base / "cn-site.txt").read_text())

    def test_same_id_activation_checks_kernel_and_file_links(self):
        current = self.seed()
        (self.root / "kernel").write_text("empty")
        self.call("activate", current)
        self.assertTrue((self.root / "kernel").read_text().startswith("replace "))


if __name__ == "__main__":
    unittest.main()
