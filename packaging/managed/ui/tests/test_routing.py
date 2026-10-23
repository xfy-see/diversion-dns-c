"""Execute the routing transaction logic under Lua 5.1 without networking."""
import json,sys,unittest,shlex
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from test_control import Harness
S=Path(__file__).parents[1]/'device/routing.lua'
D='/etc/diversion-dns-ui';R='/var/run/diversion-dns-ui'
A='A'*43+'=';B='B'*43+'=';U='C'*43+'='
class Routing(unittest.TestCase):
 def setUp(self):
  self.h=Harness();h=self.h;self.calls=[]
  self.c={'enabled':True,'interface':'wg_test','namespace':'test_ns','table':254,'families':[4,6],'initial':'aws','exits':{'aws':{'peer':A,'ipv4':'198.51.100.1','ipv6':'2001:db8::1'},'nobrand':{'peer':B,'ipv4':'198.51.100.2','ipv6':'2001:db8::2'}}}
  h.files[D+'/routing.json']=json.dumps(self.c);h.files['/proc/uptime']='1000.0 300.0';h.files['/proc/sys/kernel/random/boot_id']='boot-a'
  self.peers={A:['0.0.0.0/0','::/0','10.0.0.1/32'],B:['10.0.0.2/32'],U:['10.0.0.3/32']};self.badroute=False;self.ip={4:'198.51.100.2',6:'2001:db8::2'}
  h.lua.globals().ROUTE_RUN=self.run
  h.lua.execute("require('nixio.fs').chmod=function(p,m)assert(m=='600');return true end;dofile=function()return {canonical_ip=function(ip,af)if type(ip)~='string'then return nil end;if af==4 and ip:match('^%d+%.%d+%.%d+%.%d+$')then return ip end;if af==6 and ip:find(':',1,true)then return ip end end}end")
  s=S.read_text();start=s.index('local function run(c)');end=s.index('local function uptime()',start);self.api=h.lua.execute(s[:start]+'local function run(c)return ROUTE_RUN(c)end\n'+s[end:]);self.t=self.api._test
 def run(self,cmd):
  # unittest also has run(); dispatch TestResult to superclass.
  if not isinstance(cmd,str):return super().run(cmd)
  self.calls.append(cmd);a=shlex.split(cmd);a=a[4:]if a[:3]==['ip','netns','exec']else a
  if a[:2]==['wg','show']:return '\n'.join(k+'\t'+' '.join(v)for k,v in self.peers.items()),0
  if a[:2]==['wg','set']:
   i=3
   while i<len(a):
    assert a[i]=='peer'and a[i+2]=='allowed-ips';self.peers[a[i+1]]=sorted(filter(None,a[i+3].split(',')));i+=4
   return '',0
  if a[0]=='ip':
   return ('default dev '+('wrong'if self.badroute else'wg_test')+'\n'if 'show'in a else '1.1.1.1 dev wg_test src 10.0.0.3 \n'),0
  if a[0]=='uclient-fetch':return 'ip='+self.ip[int(a[1][1:])]+'\n',0
  raise AssertionError(cmd)
 def state(self):
  before=self.h.to_lua({k:sorted(v)for k,v in self.peers.items()});after=self.t.target(self.h.to_lua(self.c),before,'nobrand')
  return self.h.to_lua({'config':self.c,'before':self.h.to_py(before),'after':self.h.to_py(after),'selection_before':{'selected':'aws'},'target':'nobrand','state':'verifying'})
 def test_disabled_and_invalid_config_reject_mutation(self):
  self.h.files[D+'/routing.json']='{"enabled":false}'
  with self.assertRaises(Exception):self.api.start('switch-nobrand')
  self.assertFalse(self.calls)
 def test_upgrade_lock_blocks_route_preparation_without_mutation(self):
  self.h.lua.execute("require('nixio').open=function(p,m,perm)assert(p=='/var/lock/diversion-upgrade.lock');return {lock=function()return false end,close=function()end}end")
  with self.assertRaisesRegex(Exception,'upgrade in progress'):self.api.start('switch-nobrand')
  self.assertNotIn(D+'/transaction.json',self.h.files);self.assertFalse(self.calls)
 def test_upgrade_marker_is_rechecked_after_lock_acquisition(self):
  self.h.lua.globals().MARK=lambda:self.h.files.__setitem__('/root/diversion-upgrade/active.json','{}')
  self.h.lua.execute("require('nixio').open=function()return {lock=function()MARK();return true end,close=function()end}end")
  with self.assertRaisesRegex(Exception,'upgrade in progress'):self.api.start('switch-nobrand')
  self.assertNotIn(D+'/transaction.json',self.h.files);self.assertFalse(self.calls)
 def test_private_config_requires_all_expected_addresses(self):
  del self.c['exits']['aws']['ipv6'];self.h.files[D+'/routing.json']=json.dumps(self.c)
  with self.assertRaises(Exception):self.t.config()
 def test_deep_copy_snapshot_never_aliases_target(self):
  s=self.state();s.after[A][1]='changed';self.assertNotEqual(s.before[A][1],'changed');self.assertNotEqual(s.before[U],s.after[U])
 def test_target_preserves_unmanaged_and_specific_prefixes(self):
  s=self.h.to_py(self.state());self.assertEqual(s['after'][U],s['before'][U]);self.assertEqual(s['after'][A],['10.0.0.1/32']);self.assertIn('10.0.0.2/32',s['after'][B])
 def test_single_family_preserves_other_family(self):
  self.c['families']=[4];s=self.h.to_py(self.state());self.assertIn('::/0',s['after'][A]);self.assertNotIn('::/0',s['after'][B])
 def test_runtime_actual_selection_separate_from_intent(self):
  self.h.files[D+'/selection.json']='{"selected":"nobrand"}'
  r=self.h.to_py(self.t.runtime(self.h.to_lua(self.c)));self.assertEqual(r['selected'],'aws');self.assertFalse(r['ok'])
 def test_wrong_table_device_rejected(self):
  self.badroute=True;self.assertFalse(self.t.runtime(self.h.to_lua(self.c))['ok'])
 def test_mixed_af_default_rejected(self):
  self.peers[A].remove('::/0');self.peers[B].append('::/0');r=self.t.runtime(self.h.to_lua(self.c));self.assertEqual(r['selected'],'mixed');self.assertFalse(r['ok'])
 def test_reachability_does_not_imply_identity(self):
  self.ip[4]='198.51.100.55';r=self.t.probe(self.h.to_lua(self.c),'nobrand');self.assertFalse(r['ok']);self.assertTrue(r.ipv4.reachability)
 def test_correct_dual_stack_identity(self):self.assertTrue(self.t.probe(self.h.to_lua(self.c),'nobrand')['ok'])
 def test_rollback_restores_exact_prefixes_and_selection(self):
  t=self.state();original=self.h.to_py(t.before);self.peers=self.h.to_py(t.after)
  self.assertTrue(self.t.rollback(t));self.assertEqual(self.peers,{k:sorted(v)for k,v in original.items()});self.assertEqual(json.loads(self.h.files[D+'/selection.json'])['selected'],'aws')
 def test_concurrent_peer_edit_not_overwritten(self):
  t=self.state();self.peers[U].append('10.0.0.4/32');self.assertFalse(self.t.rollback(t));self.assertIn('10.0.0.4/32',self.peers[U]);self.assertEqual(t.state,'rollback_failed')
 def test_changed_config_stops_rollback(self):
  t=self.state();self.h.files[D+'/routing.json']='{"enabled":false}';self.assertFalse(self.t.rollback(t));self.assertFalse(any('wg set'in x for x in self.calls))
 def recovery_state(self,role):
  t=self.h.to_py(self.state());t.update(boot='boot-a',deadline=900)
  self.h.files[D+'/transaction.json']=json.dumps(t)
  self.h.dirs.add(R+'/route-lock')
  self.h.files[R+'/route-lock/identity']=json.dumps({'pid':123,'start':'999','role':role})
  self.h.files['/proc/123/stat']='123 (lua) S '+'0 '*18+'999 0'
  self.killed=[]
  self.h.lua.globals().KILL=lambda pid,sig:self.killed.append((pid,sig))or self.h.files.pop('/proc/123/stat',None)or True
  self.h.lua.execute("require('nixio').kill=function(pid,sig) KILL(pid,sig);return true end")
 def test_recovery_does_not_kill_another_recovery(self):
  self.recovery_state('recovery');self.assertFalse(self.api.recover());self.assertEqual(self.killed,[])
 def test_expired_worker_is_killed_before_rollback(self):
  self.recovery_state('worker');self.assertTrue(self.api.recover());self.assertEqual(self.killed,[(-123,9)])
if __name__=='__main__':unittest.main()
