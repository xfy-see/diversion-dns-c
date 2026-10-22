"""Package-independent upgrade boot recovery; shell fixtures, no root/device access."""
import json,os,shutil,subprocess,tempfile,unittest,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
class BootRecovery(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
  self.root=Path(self.tmp.name);self.base=self.root/'root/diversion-upgrade';self.base.mkdir(parents=True,mode=0o700)
  self.bin=self.root/'bin';self.bin.mkdir();self.src=self.root/'usr/libexec';self.src.mkdir(parents=True)
  (self.root/'etc/rc.d').mkdir(parents=True)
  self.env=dict(os.environ,PATH=str(self.bin)+':'+os.environ['PATH'])
  self.executable(self.bin/'id','#!/bin/sh\necho 0\n')
  self.executable(self.bin/'jsonfilter','#!/usr/bin/env python3\nimport json,sys\nprint(json.load(open(sys.argv[sys.argv.index("-i")+1]))["root"])\n')
  lua_fixture=r"""import os,sys,stat
from pathlib import Path
args=sys.argv[1:]
if args and args[0]=='-':
 script=sys.stdin.read()
 # This fixture emulates the existing nixio dependency, not an optional stat CLI.
 assert "require('nixio.fs').lstat(arg[1])" in script
 assert "string.format('%d:%s:%s',s.uid,s.type,s.modestr)" in script
 assert len(args)==2
 try:s=os.lstat(args[1])
 except OSError:sys.exit(1)
 kind='dir' if stat.S_ISDIR(s.st_mode) else 'reg' if stat.S_ISREG(s.st_mode) else 'lnk' if stat.S_ISLNK(s.st_mode) else 'other'
 mode=stat.filemode(s.st_mode)[1:]
 uid=1 if os.environ.get('MOCK_NONROOT_PATH')==args[1] else 0
 print(str(uid)+':'+kind+':'+mode,end='');sys.exit(0)
assert len(args)==3 and args[2]=='recover-worker',args
with open(CALLS,'a')as f:f.write(' '.join(args)+'\n')
os.remove(ACTIVE)
"""
  self.executable(self.bin/'lua','#!'+sys.executable+'\nCALLS='+repr(str(self.root/'calls'))+'\nACTIVE='+repr(str(self.base/'active.json'))+'\n'+lua_fixture)
  self.executable(self.root/'etc/rc.common','#!/bin/sh\nprocd_open_instance(){ :; }\nprocd_close_instance(){ /bin/sh "'+str(self.base/'recovery/loop')+'"; }\nprocd_set_param(){ :; }\n. "$1"\nstart_service\n')
  for name in ['upgrade-arm','upgrade-recover','upgrade-recovery.init','upgrade-recovery.loop','upgrade-recovery.dispatch']:
   s=(ROOT/'packaging/managed'/name).read_text().replace('/root/diversion-upgrade',str(self.base)).replace('/etc/rc.d',str(self.root/'etc/rc.d')).replace('/etc/rc.common',str(self.root/'etc/rc.common')).replace('/usr/bin/lua',str(self.bin/'lua'))
   self.executable(self.src/('diversion-dns-'+name),s)
  self.arm=self.src/'diversion-dns-upgrade-arm';self.saved=self.base/'recovery';self.entry=self.root/'etc/rc.d/S93diversion-dns-upgrade-recovery'
 def executable(self,p,s):p.write_text(s);p.chmod(0o700)
 def run_arm(self,action,ok=True):
  p=subprocess.run([self.arm,action],env=self.env,text=True,capture_output=True,timeout=5)
  if ok:self.assertEqual(p.returncode,0,p.stdout+p.stderr)
  else:self.assertNotEqual(p.returncode,0)
  return p
 def test_preparation_is_idempotent_and_does_not_start_ui_or_dns(self):
  self.run_arm('prepare');before={p.name:p.read_bytes()for p in self.saved.iterdir()};self.run_arm('prepare')
  self.assertEqual(before,{p.name:p.read_bytes()for p in self.saved.iterdir()})
  self.assertEqual(self.entry.resolve(),(self.saved/'diversion-dns-upgrade-recovery').resolve());self.assertFalse((self.root/'calls').exists())
 def test_prepare_and_start_do_not_require_stat_command(self):
  minimal=self.root/'minimal-bin';minimal.mkdir()
  for name in ['id','dirname','wc','sha256sum','grep','find','readlink','cmp','mkdir','cp','chmod','mv','ln']:
   executable=shutil.which(name,path=self.env['PATH']);self.assertIsNotNone(executable,name)
   (minimal/name).symlink_to(executable)
  self.env['PATH']=str(minimal)
  self.assertIsNone(shutil.which('stat',path=self.env['PATH']))
  self.run_arm('prepare');self.run_arm('prepare');self.run_arm('start')
 def test_nonroot_directory_or_regular_file_is_rejected(self):
  self.env['MOCK_NONROOT_PATH']=str(self.base);self.run_arm('prepare',False)
  self.env['MOCK_NONROOT_PATH']=str(self.src/'diversion-dns-upgrade-recovery.loop');self.run_arm('prepare',False)
 def test_scripts_must_remain_regular_root_only_executables(self):
  self.run_arm('prepare');loop=self.saved/'loop';original=loop.read_bytes()
  loop.chmod(0o755);self.run_arm('start',False);loop.chmod(0o700)
  target=self.root/'saved-loop';target.write_bytes(original);target.chmod(0o700)
  loop.unlink();loop.symlink_to(target);self.run_arm('start',False)
 def test_boot_recovery_works_without_ui_or_package_helpers(self):
  self.run_arm('prepare');tx=self.base/'unit';tx.mkdir();(tx/'guard.lua').write_text('-- frozen guard')
  (self.base/'active.json').write_text(json.dumps({'root':str(tx)}));shutil.rmtree(self.src)
  p=subprocess.run([self.entry,'start'],env=self.env,text=True,capture_output=True,timeout=5)
  self.assertEqual(p.returncode,0,p.stderr);self.assertEqual((self.root/'calls').read_text().strip(),str(tx/'guard.lua')+' '+str(tx)+' recover-worker')
  self.assertFalse((self.base/'active.json').exists())
 def test_no_active_transaction_does_not_launch_recovery(self):
  self.run_arm('prepare');self.run_arm('start');self.assertFalse((self.root/'calls').exists())
 def test_ui_monitor_wrapper_only_requests_independent_service_start(self):
  self.run_arm('prepare');(self.base/'active.json').write_text('{}')
  init=self.saved/'diversion-dns-upgrade-recovery'
  self.executable(init,'#!/bin/sh\nprintf "init:%s\\n" "$*" >> "'+str(self.root/'requests')+'"\n')
  wrapper=self.src/'diversion-dns-upgrade-recover'
  for _ in range(2):subprocess.run([wrapper],env=self.env,check=True,timeout=3)
  self.assertEqual((self.root/'requests').read_text().splitlines(),['init:start','init:start'])
  self.assertFalse((self.root/'calls').exists(),'monitor request must not run frozen Lua guard inline')
 def test_repeated_start_declares_same_procd_instance_without_restart(self):
  self.run_arm('prepare');(self.base/'active.json').write_text('{}')
  setup='procd_open_instance(){ echo "open:$*"; }; procd_close_instance(){ echo close; }; procd_set_param(){ echo "set:$*"; }; '
  script=setup+'. "'+str(self.saved/'diversion-dns-upgrade-recovery')+'"; start_service; start_service'
  p=subprocess.run(['sh','-c',script],env=self.env,text=True,capture_output=True,timeout=3)
  self.assertEqual(p.returncode,0,p.stderr);lines=p.stdout.splitlines();self.assertEqual(lines[:len(lines)//2],lines[len(lines)//2:])
  self.assertEqual(lines[0],'open:recovery');self.assertIn('set:command /bin/sh '+str(self.saved/'loop'),lines)
  self.assertFalse((self.root/'calls').exists(),'procd declaration must not execute recovery in caller')
 def test_unknown_boot_entry_is_never_overwritten(self):
  self.entry.write_text('administrator entry');self.run_arm('prepare',False);self.assertEqual(self.entry.read_text(),'administrator entry')
 def test_modified_recovery_is_never_overwritten(self):
  self.run_arm('prepare');(self.saved/'loop').write_text('administrator edit');self.run_arm('prepare',False)
  self.assertEqual((self.saved/'loop').read_text(),'administrator edit')
 def test_unrecognized_file_and_manifest_paths_are_rejected(self):
  self.run_arm('prepare');extra=self.saved/'other';extra.write_text('keep');self.run_arm('prepare',False);extra.unlink()
  manifest=self.saved/'SHA256SUMS';manifest.write_text(manifest.read_text().replace('  loop','  ../private'))
  self.run_arm('start',False);self.assertFalse((self.root/'calls').exists())
 def test_symlinked_recovery_or_insecure_base_is_rejected(self):
  other=self.root/'other';other.mkdir();self.saved.symlink_to(other,target_is_directory=True);self.run_arm('prepare',False)
  self.saved.unlink();self.base.chmod(0o755);self.run_arm('prepare',False)
 def test_active_transaction_is_not_reconfigured(self):
  self.run_arm('prepare');(self.base/'active.json').write_text('{}');self.run_arm('prepare',False)
 def test_source_must_match_existing_bootstrap(self):
  self.run_arm('prepare');p=self.src/'diversion-dns-upgrade-recovery.loop';p.write_text(p.read_text()+'# changed\n');self.run_arm('prepare',False)
if __name__=='__main__':unittest.main()
