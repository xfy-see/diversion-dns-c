"""Guarded APK preparation/rollback contracts using the real Lua implementation."""
import json,sys,shlex,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from test_control import Harness
SOURCE=(Path(__file__).parents[2]/'upgrade.lua').read_text().split('\n',1)[1]
ROOT='/root/diversion-upgrade/unit'
class Upgrade(unittest.TestCase):
 def setUp(self):
  h=self.h=Harness();self.calls=[];self.bad_hash=False;self.bad_plan=False;self.bad_health=False;self.broken={};self.sim_rc=0;self.sim_text=None
  self.plan={side:{'version':side+'-r1','source_commit':ch*40,'packages':{name:{'filename':name+'.apk','sha256':'d'*64,'files':{'usr/libexec/diversion-dns-c':{'sha256':'d'*64}}}for name in ['diversion-dns-c','luci-app-diversion-dns']}}for side,ch in [('old','a'),('new','b')]}
  h.files[ROOT+'/plan.json']=json.dumps(self.plan)
  for name in ['diversion-dns-c','luci-app-diversion-dns']:h.files['/usr/share/'+name+'/source.json']=json.dumps({'source_commit':'a'*40})
  h.files['/etc/diversion-dns-ui/profile.json']=json.dumps({'dns_host':'127.0.0.1','dns_port':15353})
  h.lua.globals().UP_RUN=self.command;h.lua.globals().arg=h.to_lua({0:'/usr/libexec/diversion-dns-upgrade',1:ROOT,2:'start'})
  h.lua.execute("require('nixio').getuid=function()return 0 end;local f=require('nixio.fs');f.chmod=function(p,m)assert(m=='600');return true end;f.lstat=function(p)return {type=p:match('%.apk$') and 'reg' or 'dir',uid=0,modestr='rwx------'}end;dofile=function()return {dns_query=function()return {ok=true,answers={{address='192.0.2.1'}}}end}end")
  s=SOURCE;start=s.index('local function run(cmd)');end=s.index('local function must(',start);s=s[:start]+'local function run(cmd)return UP_RUN(cmd)end\n'+s[end:];s=s[:s.index("if mode=='status'")]+"return {packages=packages,simulate=simulate,installed=installed,health=health,recover=recover,runtime_files=runtime_files}"
  self.api=h.lua.execute(s)
 def command(self,cmd):
  self.calls.append(cmd);a=shlex.split(cmd)
  if a[0]=='sha256sum':return ('e'if self.bad_hash else'd')*64+'  '+a[1],0
  if a[:2]==['apk','adbdump']:
   side='old'if '/old/'in a[-1]else'new';name=Path(a[-1]).name[:-4];return json.dumps({'info':{'name':name,'version':self.plan[side]['version'],'repo-commit':self.plan[side]['source_commit']}}),0
  if a[:2]==['apk','query']:return json.dumps([{'name':name,'status':['installed',*flags]}for name,flags in self.broken.items()]),0
  if a[:2]==['apk','list']:return a[-1]+'-old-r1 arch [installed]',0
  if a[:2]==['apk','add']:
   if '--simulate'in a:return (self.sim_text or ('(1/1) Upgrading libc (1 -> 2)'if self.bad_plan else'(1/2) Upgrading diversion-dns-c (old -> new)')),self.sim_rc
   self.broken={}
   return 'OK',0
  if a[0].startswith('/etc/init.d/'):
   return '',1 if self.bad_health else 0
  if a[0]=='/usr/libexec/diversion-dns-ui-status':return '{"selected":"aws"}',0
  if a[0]=='tar':return '',0
  raise AssertionError(cmd)
 def state(self):return self.h.to_lua({'running':{'diversion-dns':True,'diversion-dns-ui':True},'protected':{p:'d'*64 for p in ['/etc/config/network','/etc/config/firewall','/etc/config/dhcp']},'configs':{'/etc/config/diversion-dns':'d'*64}})
 def test_warm_file_is_recorded_as_mutable_not_all_config_files(self):
  self.h.files['/etc/demo/config.conf']='cache_warm_file=/etc/demo/warm.txt\ncn_domain_file=/etc/demo/cn.txt\n'
  self.assertEqual(self.h.to_py(self.api.runtime_files('/etc/demo/config.conf')),{'/etc/demo/warm.txt':True})
 def test_no_warm_file_keeps_every_config_immutable(self):
  self.h.files['/etc/demo/config.conf']='cn_domain_file=/etc/demo/cn.txt\n'
  self.assertEqual(self.h.to_py(self.api.runtime_files('/etc/demo/config.conf')),{})
 def test_warm_cannot_exempt_protected_config_or_static_inputs(self):
  for path,extra in [('/etc/config/dhcp',''),('/etc/demo/config.conf',''),('/etc/demo/cn.txt','cn_domain_file=/etc/demo/cn.txt'),('/etc/demo/keep.txt','cache_keep_file=/etc/demo/keep.txt'),('/etc/demo/stale.txt','cache_stale_override=0:/etc/demo/stale.txt')]:
   self.h.files['/etc/demo/config.conf']='cache_warm_file='+path+'\n'+extra+'\n'
   with self.assertRaises(Exception):self.api.runtime_files('/etc/demo/config.conf')
 def test_ambiguous_or_noncanonical_warm_paths_refused(self):
  for value in ['warm.txt','/etc/demo/../config/dhcp','/etc//demo/warm.txt','/etc/demo/./warm.txt','/etc/demo/.','/etc/demo/warm.txt\ncache_warm_file=/etc/demo/other.txt']:
   self.h.files['/etc/demo/config.conf']='cache_warm_file='+value+'\n'
   with self.assertRaises(Exception):self.api.runtime_files('/etc/demo/config.conf')
 def test_verified_pair_prepares_without_service_mutation(self):
  self.api.packages('old');self.api.simulate('new');self.api.installed('old');self.assertFalse(any('/etc/init.d/'in x for x in self.calls));self.assertFalse(any(x.startswith('apk add')and'--simulate'not in x for x in self.calls))
 def test_bad_digest_rejected_before_install(self):
  self.bad_hash=True
  with self.assertRaises(Exception):self.api.packages('new')
  self.assertFalse(any(x.startswith('apk add')for x in self.calls))
 def test_dependency_change_is_rejected(self):
  self.bad_plan=True
  with self.assertRaises(Exception):self.api.simulate('new')
 def test_wrong_installed_version_refuses_upgrade(self):
  with self.assertRaises(Exception):self.api.installed('new')
 def test_failed_service_health_is_not_success(self):
  self.bad_health=True
  with self.assertRaises(Exception):self.api.health(self.state())
 def test_dhcp_or_network_drift_is_not_success(self):
  self.bad_hash=True
  with self.assertRaises(Exception):self.api.health(self.state())
 def test_rollback_reinstalls_old_pair_and_checks_config(self):
  s=self.state();self.assertTrue(self.api.recover(s));self.assertEqual(s.state,'rolled_back');self.assertTrue(any('apk add --force-reinstall --wait 10'in x and'/old/'in x for x in self.calls));self.assertFalse(any('/etc/config/network'in x and not x.startswith('sha256sum')for x in self.calls))
 def test_failed_rollback_remains_visible(self):
  self.bad_health=True;s=self.state();self.assertFalse(self.api.recover(s));self.assertEqual(s.state,'rollback_failed')
 def test_recovery_reinstalls_even_when_old_version_is_still_registered(self):
  self.assertTrue(self.api.recover(self.state()));self.assertTrue(any('apk add --force-reinstall --wait 10'in x for x in self.calls))
 def test_old_config_is_restored_before_reinstall_hooks_execute(self):
  self.assertTrue(self.api.recover(self.state()))
  restore=next(i for i,x in enumerate(self.calls)if x.startswith('tar -xzpf'))
  install=next(i for i,x in enumerate(self.calls)if x.startswith('apk add --force-reinstall --wait'))
  self.assertLess(restore,install)
 def test_owned_broken_script_repair_plan_is_allowed(self):
  self.broken={'diversion-dns-c':['broken-scripts']};self.sim_rc=1;self.sim_text='(1/2) Reinstalling diversion-dns-c (old)\n(2/2) Reinstalling luci-app-diversion-dns (old)\n1 error; 1 MiB in 2 packages'
  self.assertTrue(self.api.recover(self.state()))
 def test_unrelated_broken_package_is_never_bypassed(self):
  self.broken={'libc':['broken-scripts']};self.sim_rc=1;self.sim_text='(1/1) Reinstalling diversion-dns-c (old)\n1 error; 1 MiB in 2 packages'
  self.assertFalse(self.api.recover(self.state()));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_solver_error_is_not_treated_as_repairable_broken_flag(self):
  self.broken={'diversion-dns-c':['broken-scripts']};self.sim_rc=1;self.sim_text='ERROR: unable to select packages\n1 error; 1 MiB in 2 packages'
  self.assertFalse(self.api.recover(self.state()));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_broken_state_rejected_during_normal_preflight(self):
  self.broken={'diversion-dns-c':['broken-scripts']}
  with self.assertRaises(Exception):self.api.installed('old')
 def test_legacy_stale_hook_lock_is_visible_not_false_success(self):
  self.h.dirs.add('/var/run/diversion-dns-package-upgrade.lock')
  self.assertFalse(self.api.recover(self.state()));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_stale_recovery_owner_is_reclaimed(self):
  self.h.dirs.add(ROOT+'/recovery-lock');self.h.files[ROOT+'/recovery-lock/owner.json']=json.dumps({'pid':999,'start':'old','boot':'old-boot'})
  self.assertTrue(self.api.recover(self.state()))
 def test_active_recovery_owner_is_preserved(self):
  self.h.dirs.add(ROOT+'/recovery-lock');self.h.files['/proc/sys/kernel/random/boot_id']='boot-a';self.h.files['/proc/999/stat']='999 (lua) S '+'0 '*18+'12345 0'
  self.h.files[ROOT+'/recovery-lock/owner.json']=json.dumps({'pid':999,'start':'12345','boot':'boot-a'})
  with self.assertRaises(Exception):self.api.recover(self.state())
  self.assertFalse(any(x.startswith('apk add')for x in self.calls))
if __name__=='__main__':unittest.main()
