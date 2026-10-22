"""Guarded APK preparation/rollback contracts using the real Lua implementation."""
import json,sys,shlex,unittest
from contextlib import contextmanager
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from test_control import Harness,ExitCode
SOURCE=(Path(__file__).parents[2]/'upgrade.lua').read_text().split('\n',1)[1]
ROOT='/root/diversion-upgrade/unit'
class Upgrade(unittest.TestCase):
 def setUp(self):
  h=self.h=Harness();self.calls=[];self.killed=[];self.lock_hook=None;self.apk_hook=None;self.sleep_hook=None;self.sleep_count=0;self.locked=False;self.pid=123;self.lock_owner=None;self.lock_held_at_state_save=[];self.local_health_calls=[];self.local_health_error=None;self.forbid_external_dns=False;self.service_running={};self.bad_hash=False;self.bad_plan=False;self.bad_health=False;self.broken={};self.sim_rc=0;self.sim_text=None
  self.plan={side:{'version':side+'-r1','source_commit':ch*40,'packages':{name:{'filename':name+'.apk','sha256':'d'*64,'files':{'usr/libexec/diversion-dns-c':{'sha256':'d'*64}}}for name in ['diversion-dns-c','luci-app-diversion-dns']}}for side,ch in [('old','a'),('new','b')]}
  h.files[ROOT+'/plan.json']=json.dumps(self.plan)
  h.files['/proc/sys/kernel/random/boot_id']='boot-a';h.files['/proc/uptime']='1000.0 0.0'
  h.files['/proc/123/stat']='123 (lua) S '+'0 '*18+'12345 0'
  h.lua.globals().UP_SLEEP=self.sleep;h.lua.globals().UP_PID=lambda:self.pid;h.lua.globals().PY_RENAME=self.rename;h.lua.globals().UP_KILL=self.kill;h.lua.globals().UP_MKDIR=self.mkdir;h.lua.globals().UP_OPEN=self.lock_open
  h.lua.execute("require('nixio').nanosleep=function(...)return UP_SLEEP(...)end;require('nixio').getpid=function()return UP_PID()end;require('nixio').kill=function(pid,sig)return UP_KILL(pid,sig)end;require('nixio').open=function(...)return UP_OPEN(...)end;require('nixio.fs').mkdir=function(p,m)return UP_MKDIR(p,m)end")
  for name in ['diversion-dns-c','luci-app-diversion-dns']:h.files['/usr/share/'+name+'/source.json']=json.dumps({'source_commit':'a'*40})
  h.files['/etc/diversion-dns-ui/profile.json']=json.dumps({'dns_host':'127.0.0.1','dns_port':15353})
  h.lua.globals().UP_LOCAL_HEALTH=self.local_health;h.lua.globals().UP_DNS=self.dns;h.lua.globals().UP_RUN=self.command;h.lua.globals().arg=h.to_lua({0:'/usr/libexec/diversion-dns-upgrade',1:ROOT,2:'start'})
  h.lua.execute("require('nixio').getuid=function()return 0 end;local f=require('nixio.fs');f.chmod=function(p,m)assert(m=='600');return true end;f.lstat=function(p)return {type=p:match('%.apk$') and 'reg' or 'dir',uid=0,modestr='rwx------'}end;dofile=function(p)if p:match('/upgrade%-health.lua$')then return {check=function(profile)return UP_LOCAL_HEALTH(profile)end}end;return {dns_query=function(...)return UP_DNS(...)end}end")
  s=SOURCE;start=s.index('local function run(cmd)');end=s.index('local function must(',start);s=s[:start]+'local function run(cmd)return UP_RUN(cmd)end\n'+s[end:];self.full_source=s;s=s[:s.index("if mode=='status'")]+"return {packages=packages,simulate=simulate,installed=installed,health=health,recover=recover,runtime_files=runtime_files,worker_failed=worker_failed,activate=activate,install_new=install_new,commit=commit,with_lock=with_lock,capture_health=capture_health}"
  self.api=h.lua.execute(s)
 def sleep(self,*args):
  self.sleep_count+=1
  if self.sleep_hook:
   hook=self.sleep_hook;self.sleep_hook=None;hook()
 def local_health(self,profile):
  self.local_health_calls.append(self.h.to_py(profile))
  if self.local_health_error:raise RuntimeError(self.local_health_error)
  return True
 def dns(self,*args):
  if self.forbid_external_dns:raise AssertionError('external upstream is not an upgrade health dependency')
  return self.h.to_lua({'ok':True,'answers':[{'address':'192.0.2.1'}]})
 @contextmanager
 def other_process(self,pid=456):
  previous=self.pid;self.pid=pid
  try:yield
  finally:self.pid=previous
 def lock_open(self,path,*args):
  self.assertEqual(path,'/var/lock/diversion-upgrade.lock');opener=self.pid
  def release():
   # POSIX record locks belong to a process. Closing any fd for the inode
   # releases that process's locks, including locks taken on another fd.
   if self.lock_owner==opener:self.locked=False;self.lock_owner=None
  def lock(_,operation):
   if operation=='ulock':release();return True
   self.assertEqual(operation,'tlock')
   if self.locked and self.lock_owner!=opener:return False
   self.locked=True;self.lock_owner=opener
   if self.lock_hook:
    hook=self.lock_hook;self.lock_hook=None;hook()
   return True
  def close(*args):release();return True
  return self.h.lua.table_from({'lock':lock,'close':close})
 def rename(self,a,b):
  if b==ROOT+'/state.json':self.lock_held_at_state_save.append(self.locked)
  return self.h.rename(a,b)
 def kill(self,pid,sig):
  self.killed.append((pid,sig));self.h.files.pop('/proc/'+str(abs(pid))+'/stat',None);return True
 def mkdir(self,path,mode=None):
  result=self.h.mkdir(path)
  if result and self.lock_hook and 'lock'in path:
   hook=self.lock_hook;self.lock_hook=None;hook()
  return result
 def run_mode(self,mode):
  self.h.lua.globals().arg=self.h.to_lua({0:'/usr/libexec/diversion-dns-upgrade',1:ROOT,2:mode})
  try:self.h.lua.execute(self.full_source);return 0
  except ExitCode as e:return e.args[0]
 def recover(self,*args):
  result=self.api.recover(*args);return result[0]if isinstance(result,tuple)else result
 def save_state(self,s):self.h.files[ROOT+'/state.json']=json.dumps(self.h.to_py(s))
 def saved_state(self):return self.h.get(ROOT+'/state.json')
 def apk_installs(self):return [c for c in self.calls if 'apk add'in c and '--simulate'not in c]
 def command(self,cmd):
  self.calls.append(cmd);a=shlex.split(cmd)
  if a[:2]==['env','-i']:
   assert a[2].startswith('PATH=') and a[3]=='DIVERSION_DNS_GUARDED_UPGRADE=1'
   a=a[4:];assert '--preserve-env'in a
  if a[0]=='sha256sum':return ('e'if self.bad_hash else'd')*64+'  '+a[1],0
  if a[:2]==['apk','adbdump']:
   side='old'if '/old/'in a[-1]else'new';name=Path(a[-1]).name[:-4];return json.dumps({'info':{'name':name,'version':self.plan[side]['version'],'repo-commit':self.plan[side]['source_commit']}}),0
  if a[:2]==['apk','query']:return json.dumps([{'name':name,'status':['installed',*flags]}for name,flags in self.broken.items()]),0
  if a[:2]==['apk','list']:return a[-1]+'-old-r1 arch [installed]',0
  if a[:2]==['apk','add']:
   if '--simulate'in a:return (self.sim_text or ('(1/1) Upgrading libc (1 -> 2)'if self.bad_plan else'(1/2) Upgrading diversion-dns-c (old -> new)')),self.sim_rc
   if self.apk_hook:
    hook=self.apk_hook;self.apk_hook=None;hook()
   self.broken={}
   return 'OK',0
  if a[0].startswith('/etc/init.d/'):
   if a[-1]=='running'and a[0]in self.service_running:return '',0 if self.service_running[a[0]]else 1
   return '',1 if self.bad_health else 0
  if a[0]=='/usr/libexec/diversion-dns-ui-status':return '{"selected":"aws"}',0
  if a[0]in ['tar','rm']:return '',0
  if a[0]=='/root/diversion-upgrade/recovery/diversion-dns-upgrade-recovery':return '',0
  if a[0]=='uci':return '/etc/demo/config.conf',0
  if a[0]=='/usr/libexec/diversion-dns-c':return '',1 if self.bad_health else 0
  raise AssertionError(cmd)
 def state(self):
  s=self.h.to_lua({'state':'installing','pid':123,'start':'12345','boot':'boot-a','deadline':1100,'running':{'diversion-dns':True,'diversion-dns-ui':True},'protected':{p:'d'*64 for p in ['/etc/config/network','/etc/config/firewall','/etc/config/dhcp']},'configs':{'/etc/config/diversion-dns':'d'*64}})
  self.save_state(s);return s
 def test_apk_hooks_get_only_explicitly_whitelisted_environment(self):
  self.h.env['PATH']='/usr/sbin:/usr/bin:/sbin:/bin'
  self.h.env['UNRELATED_SECRET']='never-forward'
  self.api.install_new("'/tmp/old.apk' '/tmp/ui.apk'")
  a=shlex.split(self.calls[-1]);self.assertEqual(a[:4],['env','-i','PATH=/usr/sbin:/usr/bin:/sbin:/bin','DIVERSION_DNS_GUARDED_UPGRADE=1'])
  self.assertIn('--preserve-env',a);self.assertNotIn('never-forward',self.calls[-1])
 def test_dead_or_stopped_worker_detected_without_deadline_wait(self):
  s=self.h.to_lua({'pid':999,'start':'12345'})
  self.assertTrue(self.api.worker_failed(s))
  for state in ['T','t','Z','X','S','R','D']:
   self.h.files['/proc/999/stat']='999 (lua) '+state+' '+'0 '*18+'12345 0'
   self.assertEqual(self.api.worker_failed(s),state in ['T','t','Z','X'])
  self.h.files['/proc/999/stat']='999 (lua) S '+'0 '*18+'77777 0'
  self.assertTrue(self.api.worker_failed(s))
  self.assertFalse(self.api.worker_failed(self.h.to_lua({})))
 def test_changed_configuration_never_stops_live_service(self):
  self.bad_hash=True
  with self.assertRaises(Exception):self.api.activate(self.state())
  self.assertFalse(any('/etc/init.d/'in x for x in self.calls))
 def test_new_binary_rejecting_config_never_stops_live_service(self):
  self.bad_health=True
  with self.assertRaises(Exception):self.api.activate(self.state())
  self.assertFalse(any('/etc/init.d/'in x for x in self.calls))
 def test_activation_checks_before_restart_and_preserves_stopped_services(self):
  s=self.state();s.running['diversion-dns-ui']=False;self.api.activate(s)
  check=next(i for i,x in enumerate(self.calls)if x.startswith('/usr/libexec/diversion-dns-c check'))
  restart=self.calls.index('/etc/init.d/diversion-dns restart')
  self.assertLess(check,restart);self.assertIn('/etc/init.d/diversion-dns-ui stop',self.calls)
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
  s=self.state();self.assertTrue(self.recover('failure'));self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertTrue(any('apk add --force-reinstall --wait 10'in x and'/old/'in x for x in self.calls));self.assertFalse(any('/etc/config/network'in x and not x.startswith('sha256sum')for x in self.calls))
 def test_failed_rollback_remains_visible(self):
  self.bad_health=True;s=self.state();self.assertFalse(self.recover('failure'));self.assertEqual(self.saved_state()['state'],'rollback_failed')
 def test_recovery_reinstalls_even_when_old_version_is_still_registered(self):
  self.state();self.assertTrue(self.recover('failure'));self.assertTrue(any('apk add --force-reinstall --wait 10'in x for x in self.calls))
 def test_old_config_is_restored_before_reinstall_hooks_execute(self):
  self.state();self.assertTrue(self.recover('failure'))
  restore=next(i for i,x in enumerate(self.calls)if x.startswith('tar -xzpf'))
  install=next(i for i,x in enumerate(self.calls)if x.startswith('apk add --force-reinstall --wait'))
  self.assertLess(restore,install)
 def test_owned_broken_script_repair_plan_is_allowed(self):
  self.broken={'diversion-dns-c':['broken-scripts']};self.sim_rc=1;self.sim_text='(1/2) Reinstalling diversion-dns-c (old)\n(2/2) Reinstalling luci-app-diversion-dns (old)\n1 error; 1 MiB in 2 packages'
  self.state();self.assertTrue(self.recover('failure'))
 def test_unrelated_broken_package_is_never_bypassed(self):
  self.broken={'libc':['broken-scripts']};self.sim_rc=1;self.sim_text='(1/1) Reinstalling diversion-dns-c (old)\n1 error; 1 MiB in 2 packages'
  self.state();self.assertFalse(self.recover('failure'));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_solver_error_is_not_treated_as_repairable_broken_flag(self):
  self.broken={'diversion-dns-c':['broken-scripts']};self.sim_rc=1;self.sim_text='ERROR: unable to select packages\n1 error; 1 MiB in 2 packages'
  self.state();self.assertFalse(self.recover('failure'));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_broken_state_rejected_during_normal_preflight(self):
  self.broken={'diversion-dns-c':['broken-scripts']}
  with self.assertRaises(Exception):self.api.installed('old')
 def test_legacy_stale_hook_lock_is_visible_not_false_success(self):
  self.h.dirs.add('/var/run/diversion-dns-package-upgrade.lock')
  self.state();self.assertFalse(self.recover('failure'));self.assertFalse(any('apk add --force-reinstall --wait'in x for x in self.calls))
 def test_live_lock_owner_is_preserved_without_kill_or_install(self):
  self.state();self.locked=True
  self.recover('auto')
  self.assertTrue(self.locked);self.assertEqual(self.killed,[]);self.assertEqual(self.apk_installs(),[])
 def test_released_process_lock_does_not_leave_stale_directory_owner(self):
  self.h.dirs.add(ROOT+'/recovery-lock');self.h.files[ROOT+'/recovery-lock/owner.json']=json.dumps({'pid':999,'start':'old','boot':'old-boot'})
  self.state();self.assertTrue(self.recover('failure'));self.assertEqual(self.saved_state()['state'],'rolled_back')
 def test_committed_on_disk_never_rolls_back_stale_snapshot(self):
  stale=self.state();current=self.h.to_py(stale);current['state']='committed';self.save_state(current)
  self.recover('failure')
  self.assertEqual(self.saved_state()['state'],'committed');self.assertEqual(self.apk_installs(),[]);self.assertEqual(self.killed,[])
 def test_commit_while_recovery_acquires_lock_is_rechecked(self):
  stale=self.state()
  def committed():
   current=self.h.to_py(stale);current['state']='committed';self.save_state(current)
  self.lock_hook=committed
  self.recover('failure')
  self.assertIsNone(self.lock_hook,'fixture must interleave at lock acquisition')
  self.assertEqual(self.saved_state()['state'],'committed');self.assertEqual(self.apk_installs(),[]);self.assertEqual(self.killed,[])
 def test_duplicate_stale_recovery_installs_old_packages_only_once(self):
  stale=self.state();self.recover('failure');self.recover('failure')
  self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertEqual(len(self.apk_installs()),1)
 def test_monitor_does_not_kill_committed_worker_after_stale_observation(self):
  s=self.state();s.pid=999;s.start='99999';s.deadline=900;self.save_state(s);self.h.files['/proc/999/stat']='999 (lua) S '+'0 '*18+'99999 0'
  def committed():
   current=self.h.to_py(s);current['state']='committed';self.save_state(current)
  self.lock_hook=committed
  self.run_mode('recover-worker')
  self.assertIsNone(self.lock_hook,'fixture must interleave at lock acquisition')
  self.assertEqual(self.killed,[]);self.assertEqual(self.apk_installs(),[]);self.assertEqual(self.saved_state()['state'],'committed')
 def test_monitor_during_worker_rollback_does_not_kill_its_apk(self):
  s=self.state();s.pid=123;s.start='12345';self.save_state(s)
  def contender():
   # Guardian/monitor observes the durable rolling_back state while the
   # original worker is inside apk. No process or package mutation is allowed.
   before=len(self.apk_installs())
   with self.other_process():self.assertEqual(self.run_mode('recover-worker'),0)
   self.assertEqual(self.killed,[]);self.assertEqual(len(self.apk_installs()),before)
  self.apk_hook=contender
  self.recover('failure')
  self.assertIsNone(self.apk_hook,'fixture must enter a real rollback APK call')
  self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertEqual(self.killed,[]);self.assertEqual(len(self.apk_installs()),1)
 def test_commit_is_serialized_with_recovery(self):
  self.state()
  def contender():
   with self.other_process():self.recover('auto')
   self.assertEqual(self.killed,[]);self.assertEqual(self.apk_installs(),[])
  self.lock_hook=contender
  self.api.commit()
  self.assertIsNone(self.lock_hook);self.assertEqual(self.saved_state()['state'],'committed')
  self.assertTrue(self.lock_held_at_state_save[-1]);self.assertFalse(self.locked)
 def test_commit_rechecks_deadline_after_acquiring_lock(self):
  self.state();self.lock_hook=lambda:self.h.files.__setitem__('/proc/uptime','1200.0 0.0')
  try:self.api.commit()
  except Exception:pass
  self.assertIsNone(self.lock_hook);self.assertNotEqual(self.saved_state()['state'],'committed');self.assertFalse(self.locked)
 def test_commit_never_overwrites_completed_rollback(self):
  s=self.state()
  def rolled_back():
   current=self.h.to_py(s);current['state']='rolled_back';self.save_state(current)
  self.lock_hook=rolled_back
  try:self.api.commit()
  except Exception:pass
  self.assertIsNone(self.lock_hook);self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertFalse(self.locked)
 def test_commit_requires_current_worker_identity(self):
  s=self.state();s.start='previous-process-start';self.save_state(s)
  try:self.api.commit()
  except Exception:pass
  self.assertNotEqual(self.saved_state()['state'],'committed');self.assertFalse(self.locked)
 def test_health_does_not_depend_on_external_domain_or_aaaa_answers(self):
  self.forbid_external_dns=True;self.api.health(self.state())
  self.assertEqual(self.local_health_calls,[{'dns_host':'127.0.0.1','dns_port':15353}])
 def test_owned_listener_failure_is_not_healthy(self):
  self.local_health_error='configured listener not owned by resolver'
  with self.assertRaises(Exception):self.api.health(self.state())
 def test_stopped_ui_does_not_disable_resolver_health_check(self):
  s=self.state();s.running['diversion-dns-ui']=False;self.service_running['/etc/init.d/diversion-dns-ui']=False
  self.api.health(s);self.assertEqual(len(self.local_health_calls),1)
 def test_stopped_resolver_is_preserved_without_listener_requirement(self):
  s=self.state();s.running['diversion-dns']=False;self.service_running['/etc/init.d/diversion-dns']=False
  self.api.health(s);self.assertEqual(self.local_health_calls,[])
 def test_healthy_worker_before_deadline_is_left_alone(self):
  self.state();before=self.saved_state();self.recover('auto')
  self.assertEqual(self.saved_state(),before);self.assertEqual(self.apk_installs(),[]);self.assertEqual(self.killed,[])
 def test_reused_worker_pid_is_never_signalled(self):
  s=self.state();s.pid=999;s.start='old-start';s.deadline=900;self.save_state(s)
  self.h.files['/proc/999/stat']='999 (unrelated) S '+'0 '*18+'new-start 0'
  self.recover('auto');self.assertEqual(self.killed,[]);self.assertEqual(self.saved_state()['state'],'rolled_back')
 def test_abandoned_rollback_can_resume_without_killing_prior_installer(self):
  s=self.state();s.state='rolling_back';s.recovery=self.h.to_lua({'pid':999,'start':'dead-owner','boot':'boot-a'});self.save_state(s)
  self.recover('auto');self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertEqual(self.killed,[]);self.assertEqual(len(self.apk_installs()),1)
 def test_manual_rollback_of_committed_transaction_remains_available(self):
  s=self.state();s.state='committed';self.save_state(s)
  self.recover('manual');self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertEqual(len(self.apk_installs()),1)
  self.recover('manual');self.assertEqual(len(self.apk_installs()),1)
 def test_failed_rollback_is_not_repeated_automatically(self):
  s=self.state();s.state='rollback_failed';s.error='repair failed';self.save_state(s)
  self.recover('auto');self.assertEqual(self.saved_state()['error'],'repair failed');self.assertEqual(self.apk_installs(),[])
  self.recover('manual');self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertEqual(len(self.apk_installs()),1)
 def test_another_active_transaction_is_not_removed_by_terminal_cleanup(self):
  s=self.state();s.state='committed';self.save_state(s)
  self.h.files['/root/diversion-upgrade/active.json']=json.dumps({'root':'/root/diversion-upgrade/newer'})
  self.recover('auto');self.assertEqual(self.h.get('/root/diversion-upgrade/active.json')['root'],'/root/diversion-upgrade/newer')
 def test_record_lock_mock_models_same_process_reentry_and_close(self):
  first=self.lock_open('/var/lock/diversion-upgrade.lock');second=self.lock_open('/var/lock/diversion-upgrade.lock')
  self.assertTrue(first.lock(first,'tlock'));self.assertTrue(second.lock(second,'tlock'))
  second.close(second);self.assertFalse(self.locked)
 def test_public_recover_only_hands_off_to_independent_service(self):
  self.state();self.h.files['/root/diversion-upgrade/active.json']=json.dumps({'root':ROOT})
  self.assertEqual(self.run_mode('recover'),0)
  self.assertEqual(self.apk_installs(),[]);self.assertEqual(self.killed,[])
  self.assertTrue(any('/root/diversion-upgrade/recovery/diversion-dns-upgrade-recovery' in cmd and 'start' in cmd for cmd in self.calls))
 def test_worker_commit_waits_out_brief_monitor_lock_contention(self):
  self.state();self.locked=True;self.lock_owner=456
  def release():self.locked=False;self.lock_owner=None
  self.sleep_hook=release
  self.api.commit()
  self.assertGreater(self.sleep_count,0);self.assertEqual(self.saved_state()['state'],'committed');self.assertEqual(self.apk_installs(),[])
 def test_worker_activation_waits_out_brief_monitor_lock_contention(self):
  s=self.state();self.locked=True;self.lock_owner=456
  def release():self.locked=False;self.lock_owner=None
  self.sleep_hook=release
  self.api.activate(s)
  self.assertGreater(self.sleep_count,0);self.assertEqual(self.saved_state()['phase'],'activating');self.assertIn('/etc/init.d/diversion-dns restart',self.calls)
 def test_worker_commit_rechecks_state_after_waiting_for_contention(self):
  s=self.state();self.locked=True;self.lock_owner=456
  def finished_rollback():
   self.locked=False;self.lock_owner=None;current=self.h.to_py(s);current['state']='rolled_back';self.save_state(current)
  self.sleep_hook=finished_rollback
  try:self.api.commit()
  except Exception:pass
  self.assertGreater(self.sleep_count,0);self.assertEqual(self.saved_state()['state'],'rolled_back');self.assertFalse(self.locked)
 def test_worker_lock_wait_is_bounded(self):
  self.state();self.locked=True;self.lock_owner=456
  try:self.api.commit()
  except Exception:pass
  self.assertGreater(self.sleep_count,0);self.assertLessEqual(self.sleep_count,250)
  self.assertEqual(self.saved_state()['state'],'installing');self.assertEqual(self.lock_owner,456)
if __name__=='__main__':unittest.main()
