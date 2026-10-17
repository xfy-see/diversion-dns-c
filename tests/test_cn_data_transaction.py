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
REAL_LUA = os.environ.get('LUA_TEST_BIN') or shutil.which('lua5.1') or shutil.which('lua')
DOUBLE = r'''
import fcntl, hashlib, json, os, pathlib, shutil, subprocess, sys
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
 if control.get('standby_publish_fail') and pathlib.Path(a[0]).name.startswith('.standby.'): sys.exit(1)
 os.replace(a[0],a[1])
elif n=='cp':
 if control.get('standby_copy_fail') and '.standby.' in a[-1]: sys.exit(1)
 sys.exit(subprocess.run(['/bin/cp',*a]).returncode)
elif n=='resolver':
 sys.exit(1 if control.get('check_fail') else 0)
elif n=='cn-policy.sh':
 if os.environ.get('DIVERSION_CN_DEPLOY_LOCK_HELD') != '1': sys.exit(97)
 # The child must receive the already-held deployment lock. Opening a new file
 # description must observe it locked; attempting another blocking flock would
 # deadlock a real verifier without the explicit handoff above.
 with open(os.environ['DIVERSION_DNS_LOCK'], 'a') as lock:
  try:
   fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
  except BlockingIOError:
   pass
  else:
   sys.exit(98)
 sys.exit(1 if control.get('policy_fail') else 0)
elif n=='diversion-dns-c':
 if control.get('init_check_start'):
  try:
   checked=subprocess.run(['sh', os.environ['CN_TX_SOURCE'], 'check-start'], env=os.environ,
                          close_fds=False, capture_output=True, timeout=3)
  except subprocess.TimeoutExpired: sys.exit(99)
  if checked.returncode: sys.exit(checked.returncode)
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
  (out/'ranges4.txt').write_text('range4\n')
  (out/'ranges6.txt').write_text('range6\n')
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
        for name in ("lua", "flock", "sha256sum", "logger", "sync", "mv", "cp", "resolver", "probe", "wget"):
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
                        CN_TX_TEST=str(self.root), CN_TX_SOURCE=str(SCRIPT), DIVERSION_DNS_BASE=str(self.base),
                        DIVERSION_DNS_INITDIR=str(self.init), DIVERSION_DNS_LOCK=str(self.root / "lock"),
                        DIVERSION_DNS_RUN=str(self.root / "run"), DIVERSION_CN_BINARY=str(self.bin / "resolver"),
                        DIVERSION_CN_TEST_PROBE=str(self.bin / "probe"), DIVERSION_CN_TEST_UPTIME=str(self.root / "uptime"))

    def double(self, p):
        p.write_text(f"#!{sys.executable}\n" + DOUBLE)
        p.chmod(0o755)

    def call(self, *args, ok=True):
        p = subprocess.run(["sh", str(SCRIPT), *args], env=self.env, text=True, capture_output=True, timeout=15)
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

    def assert_independent_standby(self):
        store=self.base/'cn-data';active=self.active();previous=os.readlink(store/'previous').split('/')[-1]
        self.assertNotEqual(active,previous)
        for name in ('manifest.tsv','cn-ip.txt','cn-site.txt','sets.nft','replace.nft','ranges4.txt','ranges6.txt'):
            a,b=store/'generations'/active/name,store/'generations'/previous/name
            self.assertFalse(a.is_symlink());self.assertFalse(b.is_symlink())
            self.assertNotEqual((a.stat().st_dev,a.stat().st_ino),(b.stat().st_dev,b.stat().st_ino))
        return active,previous

    def test_repeated_corruption_replenishes_two_slots_and_keeps_bad_evidence(self):
        self.seed();store=self.base/'cn-data'
        initial=set(p.name for p in (store/'generations').iterdir())
        for i in range(4):
            prior=self.active();(self.base/'cn-site.txt').write_text('')
            self.call('audit-runtime','--force')
            self.assertNotEqual(self.active(),prior);self.assert_independent_standby()
            self.assertIn('qq.com',(self.base/'cn-site.txt').read_text())
            self.assertEqual(set(p.name for p in (store/'generations').iterdir()),initial)
            bad=list((store/'quarantine').glob('damaged.*/generation/cn-site.txt'))
            self.assertEqual(len(bad),i+1);self.assertTrue(all(p.read_bytes()==b'' for p in bad))
        before=sorted(str(p) for p in store.rglob('*'))
        self.call('audit-runtime','--force')
        self.assertEqual(sorted(str(p) for p in store.rglob('*')),before)

    def test_two_corruptions_after_update_preserve_usable_previous(self):
        self.seed();new=self.stage();self.call('activate',new)
        for _ in range(2):
            (self.base/'cn-site.txt').write_text('')
            self.call('audit-runtime','--force');self.assert_independent_standby()
            self.assertIn('qq.com',(self.base/'cn-site.txt').read_text())
        self.assertEqual((self.base/'cn-data/generations'/new/'cn-site.txt').read_bytes(),b'')

    def test_standby_copy_or_publish_failure_retains_valid_active_and_retries(self):
        for mode in ('standby_copy_fail','standby_publish_fail'):
            with self.subTest(mode=mode):
                case=CNTransactionTest();case.setUp()
                try:
                    case.seed();(case.base/'cn-site.txt').write_text('');case.control(**{mode:True})
                    case.call('audit-runtime','--force',ok=False)
                    self.assertIn('qq.com',(case.base/'cn-site.txt').read_text())
                    self.assertTrue((case.base/'cn-data/repair-pending').is_file())
                    self.assertTrue((case.root/'restarts').exists())
                    self.assertEqual((case.root/'kernel').read_text(),
                        (case.base/'cn-data/generations'/case.active()/'replace.nft').read_text())
                    case.control();case.call('audit-runtime','--force');case.assert_independent_standby()
                    self.assertFalse((case.base/'cn-data/repair-pending').exists())
                finally:case.doCleanups()

    def test_generation_and_payload_symlinks_are_not_trusted_backups(self):
        self.seed();store=self.base/'cn-data';active=self.active()
        old_previous=os.readlink(store/'previous').split('/')[-1]
        previous=store/'generations'/old_previous
        payload=previous/'cn-site.txt';payload.unlink();payload.symlink_to(store/'generations'/active/'cn-site.txt')
        self.call('audit-runtime','--force');self.assert_independent_standby()
        quarantined=list((store/'quarantine').glob('damaged.*/generation/cn-site.txt'))
        self.assertTrue(any(p.is_symlink() for p in quarantined))
        shutil.rmtree(previous);previous.symlink_to(store/'generations'/active,target_is_directory=True)
        self.call('audit-runtime','--force');self.assert_independent_standby()

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

    def managed_policy(self):
        store = self.base / "cn-policy"
        (store / "generations").mkdir(parents=True)
        (store / "enabled").touch()
        (store / "current").symlink_to("generations/approved")
        self.double(self.base / "cn-policy.sh")

    def test_managed_policy_is_checked_with_lock_handoff_before_restart(self):
        self.seed()
        new = self.stage()
        self.managed_policy()
        self.call("activate", new)
        calls = [json.loads(line) for line in (self.root / "calls").read_text().splitlines()]
        policy = next(i for i, call in enumerate(calls) if call[0] == "cn-policy.sh")
        restart = next(i for i, call in enumerate(calls) if call[0] == "diversion-dns-c")
        self.assertLess(policy, restart)
        self.assertEqual(calls[policy], ["cn-policy.sh", "audit-runtime"])

    def test_untrusted_policy_blocks_candidate_and_rollback_restart_until_repaired(self):
        old = self.seed()
        new = self.stage()
        self.managed_policy()
        self.control(policy_fail=True)
        self.call("activate", new, ok=False)
        self.assertEqual(self.active(), old)
        self.assertFalse((self.root / "restarts").exists())
        self.assertTrue((self.base / "cn-data/pending").exists())
        self.control()
        self.call("reconcile")
        self.assertFalse((self.base / "cn-data/pending").exists())
        self.assertEqual((self.root / "restarts").read_text().splitlines(), ["generations/"+old])

    def test_simultaneous_cn_file_and_policy_damage_keeps_c_until_verified_repair(self):
        old = self.seed()
        self.managed_policy()
        site = self.base / "cn-site.txt"
        site.unlink(); site.write_text("")
        self.control(policy_fail=True)
        self.call("audit-runtime", "--force", ok=False)
        self.assertFalse((self.root / "restarts").exists())
        self.assertTrue((self.base / "cn-data/repair-pending").exists())
        self.control()
        self.call("audit-runtime", "--force")
        self.assertFalse((self.base / "cn-data/repair-pending").exists())
        self.assertEqual((self.root / "restarts").read_text().splitlines(), ["generations/"+old])

    def test_missing_managed_policy_script_does_not_fall_back_to_unchecked_init(self):
        self.seed()
        new = self.stage()
        self.managed_policy()
        (self.base / "cn-policy.sh").unlink()
        self.call("activate", new, ok=False)
        self.assertFalse((self.root / "restarts").exists())
        self.assertTrue((self.base / "cn-data/pending").exists())

    def test_lost_policy_markers_do_not_bypass_existing_managed_generation(self):
        self.seed()
        new = self.stage()
        self.managed_policy()
        (self.base / "cn-policy/enabled").unlink()
        (self.base / "cn-policy/current").unlink()
        self.control(policy_fail=True)
        self.call("activate", new, ok=False)
        self.assertFalse((self.root / "restarts").exists())
        self.assertTrue((self.base / "cn-data/pending").exists())

    def test_readonly_start_check_needs_no_kernel_and_makes_no_mutations(self):
        self.seed()
        (self.root / "kernel").unlink()
        before = {str(p.relative_to(self.base)): (p.is_symlink(), p.read_bytes())
                  for p in self.base.rglob("*") if p.is_file()}
        self.call("check-start")
        after = {str(p.relative_to(self.base)): (p.is_symlink(), p.read_bytes())
                 for p in self.base.rglob("*") if p.is_file()}
        self.assertEqual(after, before)
        self.assertFalse((self.root / "kernel").exists())
        self.assertFalse((self.root / "restarts").exists())

    def test_start_check_rejects_corrupt_payload_and_broken_pointer_without_repair(self):
        self.seed()
        site = self.base / "cn-site.txt"
        site.unlink(); site.write_text("")
        self.call("check-start", ok=False)
        self.assertFalse(site.is_symlink())
        self.assertFalse((self.root / "restarts").exists())
        self.assertFalse((self.base / "cn-data/repair-pending").exists())

    def test_start_check_allows_existing_dns_recovery_transaction(self):
        self.seed()
        (self.base / "recovering").mkdir()
        (self.base / "degraded").touch()
        self.call("check-start")
        self.assertTrue((self.base / "recovering").exists())

    def test_nested_init_start_check_inherits_deploy_lock_without_data_lock_deadlock(self):
        self.seed()
        new = self.stage()
        self.managed_policy()
        self.control(init_check_start=True)
        self.call("activate", new)
        self.assertEqual(self.active(), new)
        self.assertEqual((self.root / "restarts").read_text().splitlines(), ["generations/"+new])

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


@unittest.skipUnless(REAL_LUA, 'Lua absent; CI/router validation covers actual manifest engine')
class CNStandbyRealLuaTest(unittest.TestCase):
    def setUp(self):
        # Real shell+Lua+manifest hashes and filesystem copies. Only nft and the
        # resolver/service adapters are doubles; no local C build or kernel write.
        import test_cn_data as engine_fixture
        case=CNTransactionTest();case.setUp();self.case=case;self.addCleanup(case.doCleanups)
        self.fixtures=engine_fixture
        shutil.copy2(ROOT/'deployment/openwrt-recovery/cn-data.lua',case.base/'cn-data.lua')
        (case.base/'cn-ip.txt').write_text(engine_fixture.IP)
        (case.base/'cn-site.txt').write_text(engine_fixture.SITE)
        (case.base/'sets.nft').write_text(engine_fixture.TEMPLATE)
        (case.root/'nft.json').write_text(json.dumps({
            'cn4':[v for v in engine_fixture.IP.splitlines() if ':' not in v],
            'cn6':[v for v in engine_fixture.IP.splitlines() if ':' in v],
            'unrelated':['198.51.100.1']}))
        lua=case.bin/'lua'
        lua.write_text('#!'+sys.executable+'\nimport os,sys\nos.execv('+repr(REAL_LUA)+', ['+repr(REAL_LUA)+']+sys.argv[1:])\n')
        lua.chmod(0o755)
        nft=case.bin/'nft';nft.write_text('#!'+sys.executable+'\n'+engine_fixture.NFT_DOUBLE);nft.chmod(0o755)
        case.env.update(CN_TEST_ROOT=str(case.root),DIVERSION_CN_TABLE='cn_test',
                        DIVERSION_CN_MIN4='2',DIVERSION_CN_MIN6='1',DIVERSION_CN_MINSITE='2')

    def test_real_manifest_two_consecutive_corruptions_after_activation(self):
        c=self.case;c.seed()
        site=c.root/'updated-site';site.write_text(self.fixtures.SITE+'new.cn\n')
        ip=c.base/'cn-ip.txt'
        new=c.call('stage',str(ip),str(site),c.sha(ip),c.sha(site)).stdout.strip()
        c.call('activate',new)
        for _ in range(2):
            (c.base/'cn-site.txt').write_text('')
            c.call('audit-runtime','--force');active,previous=c.assert_independent_standby()
            for value in (active,previous):
                path=c.base/'cn-data/generations'/value
                manifest=c.sha(path/'manifest.tsv')
                alias=hashlib.sha256((manifest+' bootstrap\n').encode()).hexdigest()
                self.assertIn(value,(manifest,alias))
                p=subprocess.run([REAL_LUA,str(c.base/'cn-data.lua'),'verify',str(path)],
                                 env=c.env,capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stdout+p.stderr)
        self.assertEqual((c.base/'cn-data/generations'/new/'cn-site.txt').read_bytes(),b'')
        self.assertEqual(json.loads((c.root/'nft.json').read_text())['unrelated'],['198.51.100.1'])

    def test_real_manifest_tamper_is_quarantined_and_replenished_from_active(self):
        c=self.case;c.seed();store=c.base/'cn-data'
        previous=os.readlink(store/'previous').split('/')[-1]
        p=store/'generations'/previous/'manifest.tsv';p.write_text(p.read_text()+'corrupt\n')
        c.call('audit-runtime','--force');c.assert_independent_standby()
        bad=list((store/'quarantine').glob('damaged.*/generation/manifest.tsv'))
        self.assertEqual(len(bad),1);self.assertTrue(bad[0].read_text().endswith('corrupt\n'))


if __name__ == "__main__":
    unittest.main()
