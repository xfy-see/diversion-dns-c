#!/usr/bin/env python3
"""Run the real Lua controller with in-memory files and mocked OS commands.
Requires prebuilt lupa; never sends traffic or mutates a device.
"""
from pathlib import Path
import hashlib, json, re, shlex, unittest
from lupa.lua51 import LuaRuntime

SOURCE = (Path(__file__).parents[1] / 'control.lua').read_text().split('\n', 1)[1]
B='/etc/pnw-control'; R='/var/run/pnw-control'
class ExitCode(Exception): pass
class Harness:
 def __init__(self, selected='aws'):
  self.lua=LuaRuntime(unpack_returned_tuples=True)
  self.files={B+'/emergency.nft':'table inet pnw_emergency { chain local { type filter hook output priority -129; policy accept; meta mark 1 drop; } }\n', '/etc/passwd':'root:x:0:0::/:/bin/sh\n', '/proc/loadavg':'0.1 0.1 0.1', '/proc/meminfo':'MemAvailable: 10000\n', '/etc/config/firewall':'protected firewall', '/etc/config/dhcp':'protected dhcp', B+'/us-exits.json':'private placeholder', B+'/foreign-v4-dns.conf':'filter', '/etc/diversion-dns-c/config.conf':'foreign_interface=wg_vpn\nforeign_mark=1\nforeign_upstream=1.1.1.1:53\nforeign_upstream=8.8.8.8:53\n', '/etc/diversion-dns-c/policy.nft':('oifname != "wg_vpn"\n'*4), '/etc/nftables.d/97-pnw-egress-bind.nft':('chain post { type filter hook postrouting priority 0;\n oifname != "wg_vpn"\n}\nchain forward { type filter hook forward priority 0;\n oifname != "wg_vpn"\n}\n')}
  self.files[B+'/expected-egress.json']=json.dumps({id:{'ipv4':'198.51.100.13','endpoint_ipv4':'203.0.113.13'} for id in ('usss','usvless')})
  self.dirs={R,'/sys/class/net/wg_vpn','/sys/class/net/pnwuss0','/sys/class/net/pnwuvl0'}
  self.config={'network.route_gfw_v4.interface':'wg_vpn','network.route_gfw_v6.interface':'wg_vpn'}
  for name in ('aws','nobrand'):
   self.config.update({f'network.pnw_{name}.allowed_ips': '10.0.0.1/32'+(' 0.0.0.0/0 ::/0' if name==selected else ''), f'network.pnw_{name}.public_key':name+'key',f'network.pnw_{name}.endpoint_host':'198.51.100.1',f'network.pnw_{name}.endpoint_port':'51820'})
  if selected in ('usss','usvless'):
   iface={'usss':'pnw_uss','usvless':'pnw_uvl'}[selected]
   self.config['network.route_gfw_v4.interface']=iface;self.config['network.route_gfw_v6.interface']=iface
   dev='pnwuss0' if selected=='usss' else 'pnwuvl0'
   for p in ('/etc/diversion-dns-c/policy.nft','/etc/nftables.d/97-pnw-egress-bind.nft'):self.files[p]=self.files[p].replace('wg_vpn',dev)
   self.files['/etc/diversion-dns-c/config.conf']='foreign_interface=lo\nforeign_mark=0\nforeign_upstream=127.0.0.1:15364\n'
  self.staged={};self.active=False;self.probe_rules=False;self.events=[];self.fail={};self.env={'DIVERSION_CN_DEPLOY_LOCK_HELD':'1'};self.now=1000000;self.tick=0;self.outputs=[];self.dhcp_extra='';self.dns_server='isp';self.probes=0
  g=self.lua.globals()
  g.PY_OPEN=self.open;g.PY_RENAME=self.rename;g.PY_REMOVE=self.remove;g.PY_RUN=self.run;g.PY_STAT=self.stat;g.PY_MKDIR=self.mkdir;g.PY_RMDIR=self.rmdir;g.PY_ENV=lambda k:self.env.get(k);g.PY_EXIT=self.exit;g.PY_PRINT=self.outputs.append;g.PY_TIME=lambda:self.now;g.PY_CLOCK=self.clock;g.PY_PARSE=lambda s:self.to_lua(json.loads(s));g.PY_JSON=lambda x:json.dumps(self.to_py(x),sort_keys=True);g.PY_DIR=lambda path:self.to_lua([])
  self.lua.execute('''
   package.preload['luci.jsonc']=function() return {parse=function(s)return PY_PARSE(s)end,stringify=function(t)return PY_JSON(t)end} end
   package.preload['nixio']=function() return {gettimeofday=function()return PY_CLOCK()end,getpid=function()return 123 end,nanosleep=function()end,setuid=function()return true end,setgid=function()return true end,exec=function()error('exec not used by mock')end} end
   package.preload['nixio.fs']=function() return {stat=function(p)return PY_STAT(p)end,mkdir=function(p,m)return PY_MKDIR(p)end,rmdir=function(p)return PY_RMDIR(p)end,dir=function(p)local a=PY_DIR(p);local i=0;return function() i=i+1;return a[i] end end} end
   io.open=function(p,m)return PY_OPEN(p,m)end
   os.rename=function(a,b)return PY_RENAME(a,b)end;os.remove=function(p)return PY_REMOVE(p)end
   os.time=function()return PY_TIME()end;os.getenv=function(k)return PY_ENV(k)end;os.exit=function(c)PY_EXIT(c)end
   print=function(s)PY_PRINT(s)end
   dofile=function(p)error('optional module absent in controller unit test')end
  ''')
  start=SOURCE.index('local function run(s)');end=SOURCE.index('local function must(',start)
  self.code=SOURCE[:start]+'local function run(s) return PY_RUN(s) end\n'+SOURCE[end:]
  cut=self.code.index("fs.mkdir(R,'700')\nlocal mode=")
  self.api=self.lua.execute(self.code[:cut]+"return {status=status,health=health,emergency=emergency,switch=switch,restore=restore,public_probe=public_probe,reconcile=reconcile_locked,containment=containment_state,reset=reset_containment}")
 def to_lua(self,x):
  if isinstance(x,dict): return self.lua.table_from({k:self.to_lua(v) for k,v in x.items()})
  if isinstance(x,list): return self.lua.table_from([self.to_lua(v) for v in x])
  return x
 def to_py(self,x):
  if hasattr(x,'items'):
   d={k:self.to_py(v) for k,v in x.items()}
   if d and set(d)==set(range(1,len(d)+1)):return [d[i] for i in range(1,len(d)+1)]
   return d
  return x
 def clock(self): self.tick+=100;return self.now,self.tick
 def open(self,path,mode=None):
  if mode is None and path not in self.files:return None
  if mode=='w':self.files[path]=''
  return self.lua.table_from({'read':lambda *args:self.files[path], 'write':lambda _,s:self.files.__setitem__(path,self.files[path]+str(s)), 'close':lambda *args:True})
 def rename(self,a,b):self.files[b]=self.files.pop(a);return True
 def remove(self,p):self.files.pop(p,None);return True
 def stat(self,p):return self.lua.table_from({'type':'dir'}) if p in self.dirs or p in self.files else None
 def mkdir(self,p):
  if p in self.dirs:return None
  self.dirs.add(p);return True
 def rmdir(self,p):self.dirs.discard(p);return True
 def exit(self,code):raise ExitCode(code)
 def run_mode(self,*args):
  self.lua.globals().arg=self.to_lua(list(args))
  try:self.lua.execute(self.code);return 0
  except ExitCode as e:return e.args[0]
 def current(self):
  intf=self.config['network.route_gfw_v4.interface']
  if intf!='wg_vpn':return 'usss' if intf=='pnw_uss' else 'usvless'
  return 'aws' if '0.0.0.0/0' in self.config['network.pnw_aws.allowed_ips'] else 'nobrand'
 def get(self,p):return json.loads(self.files[p])
 def worker(self,action):
  self.dirs.add(R+'/job');self.files[R+'/job/token']='test';self.files[R+'/result.json']=json.dumps({'time':self.now,'state':'running'})
  return self.run_mode('worker',action,'test')
 def run(self,s):
  self.events.append(s)
  for pattern,result in self.fail.items():
   if pattern in s:return result(s) if callable(result) else result
  a=shlex.split(s)
  if s=='nft list tables':return ('table inet pnw_emergency\n' if self.active else 'table inet fw4\n'),0
  if s.startswith('nft -f '):
   rules=self.files[a[2]]
   if a[2].endswith('/probe.nft'):
    assert self.active;self.probe_rules=True
    assert 'meta skuid 65533 ip daddr 1.1.1.1 tcp dport 443 accept' in rules
    assert 'meta skuid 0 ip daddr 1.1.1.1 udp dport 53 accept' in rules
    assert 'meta skuid 0 ip daddr 8.8.8.8 tcp dport 53 meta mark set 1' in rules
    assert 'priority -128' in rules
    assert 'flush' not in rules and 'delete' not in rules
   elif 'table inet pnw_emergency' in rules:self.active=True;self.probe_rules=False
   return '',0
  if s=='nft delete table inet pnw_emergency':self.active=False;self.probe_rules=False;return '',0
  if s=='uci -q show dhcp':return "dhcp.@dnsmasq[0]=dnsmasq\ndhcp.@dnsmasq[0].server='"+self.dns_server+"'\ndhcp.@dnsmasq[0].cachesize='0'\ndhcp.lan=dhcp\ndhcp.lan.interface='lan'\n"+self.dhcp_extra,0
  if s.startswith('uci -q get '):return self.config[a[-1]],0
  if s=='uci changes network':return '',0
  if s.startswith('uci -t '):
   if 'delete' in a:self.staged[a[-1]]=''
   if 'add_list' in a:
    k,v=a[-1].split('=',1);self.staged[k]=(self.staged.get(k,'')+' '+v).strip()
   if 'set' in a:
    k,v=a[-1].split('=',1);self.staged[k]=v
   if 'commit' in a:self.config.update(self.staged);self.staged={}
   return '',0
  if s.startswith('sha256sum '):return '\n'.join(hashlib.sha256(self.files[p].encode()).hexdigest()+'  '+p for p in a[1:]),0
  if 'route get' in s:return 'default dev pppoe-wan',0
  if s.startswith('ip -') and 'route show' in s:
   dev={'aws':'wg_vpn','nobrand':'wg_vpn','usss':'pnwuss0','usvless':'pnwuvl0'}[self.current()];return 'default dev '+dev,0
  if s=='wg show wg_vpn latest-handshakes':return 'awskey '+str(self.now-1)+'\nnobrandkey '+str(self.now-1),0
  if s.startswith('uclient-fetch ') or 'probe-fetch' in s:
   if 'probe-fetch' in s:assert self.active and self.probe_rules;self.probes+=1
   af='6' if '-6 ' in s or s.endswith(' 6') else '4'
   ip='2001:db8::1' if af=='6' else ('198.51.100.13' if self.current() in ('usss','usvless') else '203.0.113.1')
   return 'ip='+ip+'\n',0
  if 'dns-probe.lua 1.1.1.1 53 example.com' in s and self.active:assert self.probe_rules;self.probes+=1;return 'DNS passed',0
  if 'recover.sh manual' in s:
   assert s.startswith('DIVERSION_DNS_LOCK=/var/lock/pnw-control-nested.lock ') and s.endswith(' 8>&9')
   self.files.pop('/etc/diversion-dns-c/degraded',None);self.dns_server='127.0.0.1#15363';return '',0
  if 'rollback.sh manual' in s:self.files['/etc/diversion-dns-c/degraded']='manual';self.dns_server='isp';return '',0
  if s.startswith('(') and 'flock -n 9' in s:return '',75
  return '',0

class ControllerTests(unittest.TestCase):
 def test_dns_status_failure_is_explicit_without_hiding_control_status(self):
  h=Harness();s=h.to_py(h.api.status());self.assertFalse(s['dns_upstreams']['cn']['available']);self.assertIn('dns-status unavailable',s['dns_upstreams']['foreign']['reason']);self.assertEqual(s['selected'],'aws')
 def test_health_persists_domestic_observation_separately(self):
  h=Harness();h.lua.globals().OBS=h.to_lua({'time':h.now,'ipv4':{'ip':'198.51.100.8','reachability':True,'identity_status':'wan_matched','checked_at':h.now}})
  h.lua.execute("dofile=function(p) if p:match('/public%-status.lua$') then return {probe=function() return OBS end} end; error('absent') end")
  h.api.health();self.assertEqual(h.get(R+'/public-domestic.json')['ipv4']['ip'],'198.51.100.8');self.assertEqual(h.get(R+'/health.json')['public_exit']['domestic']['ipv4']['ip'],'198.51.100.8')
  h.files[R+'/public-exit.json']=json.dumps({'time':h.now+1,'selected':'aws','ipv4':{'ip':'203.0.113.9'}})
  s=h.to_py(h.api.status());self.assertEqual(s['public_exit']['ipv4']['ip'],'203.0.113.9');self.assertEqual(s['public_exit']['domestic']['ipv4']['ip'],'198.51.100.8')
 def test_domestic_observation_failure_does_not_fail_foreign_routing_check(self):
  h=Harness();h.lua.execute("dofile=function(p) error('display module unavailable') end")
  h.api.health();s=h.get(R+'/health.json');self.assertTrue(s['ok']);self.assertFalse(s['public_exit']['domestic']['ipv6']['reachability']);self.assertIn('unavailable',s['public_exit']['domestic']['ipv6']['error'])
 def test_status_correlates_real_table_and_durable_marker(self):
  h=Harness();h.active=True;s=h.to_py(h.api.status());self.assertTrue(s['emergency']);self.assertFalse(s['containment']['marker']);self.assertTrue(s['containment']['active']);self.assertEqual(s['version'],'2026.10.18.2')
 def test_filter_failure_preserves_detail_and_duration(self):
  h=Harness('usss');h.fail['dns-v4-check.lua']=('filter failed',1);h.api.health();s=h.get(R+'/health.json');self.assertFalse(s['ok']);self.assertFalse(s['checks']['foreign_ipv4_only']);self.assertIn('filter failed',s['details']['foreign_ipv4_only']['error']);self.assertGreaterEqual(s['duration_ms'],0);self.assertEqual(s['checks']['https_ipv6'],'disabled')
 def test_public_identity_has_explicit_unconfigured_state(self):
  h=Harness();r=h.to_py(h.api.public_probe('4',False));self.assertTrue(r['reachability']);self.assertEqual(r['identity_status'],'unconfigured');self.assertEqual(r['ip'],'203.0.113.1')
 def test_wrong_expected_identity_fails_check(self):
  h=Harness();h.files[B+'/expected-egress.json']=json.dumps({'aws':{'ipv4':'198.51.100.99'}});h.api.health();s=h.get(R+'/health.json');self.assertFalse(s['checks']['https_ipv4']);self.assertEqual(s['public_exit']['ipv4']['identity_status'],'mismatch')
 def test_proxy_identity_and_endpoint_are_independent_local_configuration(self):
  h=Harness();h.files[B+'/expected-egress.json']=json.dumps({'usss':{'ipv4':'198.51.100.13','endpoint_ipv4':'203.0.113.77'}})
  h.api.switch('usss');self.assertTrue(any("route get '203.0.113.77' mark 512" in e for e in h.events))
  self.assertEqual(h.get(R+'/public-exit.json')['ipv4']['identity_status'],'verified')
 def test_proxy_missing_or_invalid_configuration_refuses_before_route_changes(self):
  for config in [None,{}, {'usss':{'ipv4':'198.51.100.13'}}, {'usss':{'endpoint_ipv4':'203.0.113.13'}}, {'usss':{'ipv4':'198.51.100.13','endpoint_ipv4':'203.0.113.13;id'}}, {'usss':{'ipv4':'999.1.1.1','endpoint_ipv4':'203.0.113.13'}}]:
   h=Harness()
   if config is None:h.files.pop(B+'/expected-egress.json')
   else:h.files[B+'/expected-egress.json']=json.dumps(config)
   with self.assertRaises(Exception):h.api.switch('usss')
   self.assertEqual(h.current(),'aws');self.assertNotIn(B+'/pending.json',h.files)
   self.assertFalse(any(e.startswith('uci -t ') or e.startswith('wg set ') for e in h.events))
 def test_proxy_missing_identity_never_becomes_reachability_only(self):
  h=Harness('usss');h.files.pop(B+'/expected-egress.json')
  with self.assertRaises(Exception):h.api.public_probe('4',False)
 def test_failed_recover_creates_and_keeps_marker_and_containment(self):
  h=Harness();h.fail['probe-fetch']=('network unreachable',1);h.worker('recover');s=h.get(R+'/result.json');self.assertEqual(s['state'],'failed');self.assertTrue(h.active);self.assertIn(B+'/emergency',h.files);self.assertFalse(h.probe_rules);self.assertNotIn('nft delete table inet pnw_emergency',h.events)
 def test_recovery_only_releases_after_isolated_probes(self):
  h=Harness();h.api.emergency(False);self.assertEqual(h.probes,3);self.assertFalse(h.active);self.assertNotIn(B+'/emergency',h.files);self.assertFalse(h.probe_rules);self.assertGreater(h.events.index('nft delete table inet pnw_emergency'),max(i for i,s in enumerate(h.events) if ' probe-' in s))
 def test_emergency_alternate_switch_retains_block_until_success(self):
  h=Harness();h.active=True;h.files[B+'/emergency']='operator';h.files['/etc/diversion-dns-c/degraded']='manual';h.worker('switch-nobrand');s=h.get(R+'/result.json');self.assertEqual(s['state'],'success',s);self.assertEqual(h.current(),'nobrand');self.assertEqual(h.probes,3);self.assertFalse(h.active);self.assertNotIn(B+'/pending.json',h.files)
 def test_failed_emergency_candidate_rolls_back_under_containment(self):
  h=Harness();h.active=True;h.files[B+'/emergency']='operator';h.files['/etc/diversion-dns-c/degraded']='manual';h.fail['probe-fetch']=('timeout',1);h.worker('switch-nobrand');s=h.get(R+'/result.json');self.assertEqual(s['state'],'failed');self.assertEqual(s['rollback']['state'],'success',s);self.assertEqual(h.current(),'aws');self.assertTrue(h.active);self.assertIn('/etc/diversion-dns-c/degraded',h.files);self.assertNotIn(B+'/pending.json',h.files)
 def test_rollback_failure_is_reported_and_contained(self):
  h=Harness();h.files[B+'/pending.json']=json.dumps({'invalid':True});h.worker('retry-recovery');s=h.get(R+'/result.json');self.assertEqual(s['rollback']['state'],'failed');self.assertIn('invalid saved transaction',s['rollback']['error']);self.assertTrue(h.active)
 def test_outer_reconcile_propagates_lock_busy(self):
  h=Harness();h.env={};self.assertEqual(h.run_mode('reconcile'),75);self.assertNotIn(R+'/reconcile.json',h.files)
 def test_reconcile_three_failures_pause_and_preserve_reason(self):
  h=Harness();h.files[B+'/pending.json']=json.dumps({'invalid':True})
  for i in range(1,4):self.assertEqual(h.run_mode('reconcile'),1);self.assertEqual(h.get(R+'/reconcile.json')['failures'],i)
  self.assertEqual(h.run_mode('reconcile'),76);s=h.get(R+'/reconcile.json');self.assertTrue(s['paused']);self.assertIn('invalid saved transaction',s['last_error'])
 def test_reconcile_clears_crashed_probe_before_rollback_failure(self):
  h=Harness();h.active=True;h.probe_rules=True;h.files[R+'/probe-active']='123';h.files[B+'/pending.json']=json.dumps({'invalid':True});self.assertEqual(h.run_mode('reconcile'),1);self.assertFalse(h.probe_rules);self.assertTrue(h.active);self.assertIn(B+'/emergency',h.files)
 def test_successful_check_does_not_unpause_failed_recovery(self):
  h=Harness();h.files[R+'/reconcile.json']=json.dumps({'failures':3,'paused':True});h.worker('check');self.assertEqual(h.get(R+'/reconcile.json')['failures'],3)
 def test_busy_active_worker_does_not_count_as_failure(self):
  h=Harness();h.dirs.add(R+'/job');h.files[R+'/job/pid']='55';h.files['/proc/55/cmdline']='/usr/libexec/pnw-control worker';self.assertEqual(h.run_mode('reconcile'),75);self.assertNotIn(R+'/reconcile.json',h.files)
 def test_emergency_cross_profile_switch_checks_and_releases(self):
  for initial,target in [('aws','usss'),('usss','aws')]:
   with self.subTest(initial=initial,target=target):
    h=Harness(initial);h.active=True;h.files[B+'/emergency']='operator';h.files['/etc/diversion-dns-c/degraded']='manual';h.worker('switch-'+target);s=h.get(R+'/result.json');self.assertEqual(s['state'],'success',s);self.assertEqual(h.current(),target);self.assertFalse(h.active);self.assertNotIn(B+'/pending.json',h.files)
 def test_emergency_cross_profile_failure_restores_original_config(self):
  h=Harness();h.active=True;h.files[B+'/emergency']='operator';h.files['/etc/diversion-dns-c/degraded']='manual';old=h.files['/etc/diversion-dns-c/config.conf'];h.fail['probe-fetch']=('timeout',1);h.worker('switch-usss');s=h.get(R+'/result.json');self.assertEqual(s['rollback']['state'],'success',s);self.assertEqual(h.current(),'aws');self.assertEqual(h.files['/etc/diversion-dns-c/config.conf'],old);self.assertTrue(h.active)
 def test_emergency_can_replace_missing_old_tunnel_defaults(self):
  h=Harness('usss');h.active=True;h.files[B+'/emergency']='operator';h.dirs.discard('/sys/class/net/pnwuss0');h.fail['route show table 100 default']=('',0);h.worker('switch-aws');s=h.get(R+'/result.json');self.assertEqual(s['state'],'success',s);self.assertEqual(h.current(),'aws')
 def test_emergency_refuses_conflicting_default(self):
  h=Harness();h.active=True;h.files[B+'/emergency']='operator';h.fail['route show table 100 default']=('default via 192.0.2.1 dev eth9',0);h.worker('switch-nobrand');s=h.get(R+'/result.json');self.assertEqual(s['state'],'failed');self.assertEqual(h.current(),'aws');self.assertTrue(h.active);self.assertNotIn(B+'/pending.json',h.files)
 def test_uid_collision_refuses_probe_without_releasing_isolation(self):
  h=Harness();h.files['/etc/passwd']+='app:x:65533:65533::/:/bin/false\n';h.worker('recover');s=h.get(R+'/result.json');self.assertEqual(s['state'],'failed');self.assertIn('UID already assigned',s['message']);self.assertTrue(h.active);self.assertFalse(h.probe_rules)
 def test_paused_recovery_still_removes_crashed_probe_exceptions(self):
  h=Harness();h.active=True;h.probe_rules=True;h.files[R+'/probe-active']='123';h.files[B+'/emergency']='operator';h.files[R+'/reconcile.json']=json.dumps({'failures':3,'paused':True});self.assertEqual(h.run_mode('reconcile'),76);self.assertTrue(h.active);self.assertFalse(h.probe_rules);self.assertNotIn(R+'/probe-active',h.files);self.assertEqual(h.get(R+'/reconcile.json')['failures'],3)
 def test_reconcile_invalid_transaction_isolates_before_pausing(self):
  h=Harness();h.files[B+'/pending.json']=json.dumps({'invalid':True});self.assertEqual(h.run_mode('reconcile'),1);self.assertTrue(h.active);self.assertIn(B+'/emergency',h.files)
 def test_uncommitted_dhcp_edits_are_not_committed_by_recovery(self):
  h=Harness();h.fail['uci changes dhcp']=("dhcp.lan.start='50'",0);h.worker('recover');s=h.get(R+'/result.json');self.assertEqual(s['state'],'failed');self.assertIn('uncommitted DHCP edits',s['message']);self.assertFalse(any('recover.sh manual' in c for c in h.events));self.assertTrue(h.active)
 def test_concurrent_protected_config_is_preserved_on_rollback_refusal(self):
  h=Harness();h.active=True;h.files[B+'/emergency']='operator'
  def fail_probe(command):h.files['/etc/config/firewall']='external edit';return 'candidate failed',1
  h.fail['probe-fetch']=fail_probe;h.worker('switch-usss');s=h.get(R+'/result.json');self.assertEqual(s['rollback']['state'],'failed');self.assertEqual(h.files['/etc/config/firewall'],'external edit');self.assertIn(B+'/pending.json',h.files);self.assertTrue(h.active)
if __name__=='__main__':unittest.main(verbosity=2)

class GameRecoveryIsolationTests(unittest.TestCase):
 def test_main_restore_precedes_throwing_optional_game_module(self):
  h=Harness();h.files[B+'/pending.json']='pending';h.files[B+'/game-tunnel.lua']='installed'
  h.lua.execute("dofile=function()assert(PY_OPEN('/etc/pnw-control/pending.json')==nil,'main restore must run first');error('game failure')end")
  code=h.code.replace("if read(B..'/pending.json') then restore() end", "if read(B..'/pending.json') then os.remove(B..'/pending.json') end")
  cut=code.index("fs.mkdir(R,'700')\nlocal mode=")
  api=h.lua.execute(code[:cut]+'return {reconcile=reconcile_locked}')
  self.assertTrue(api.reconcile());self.assertNotIn(B+'/pending.json',h.files)

class GameLaunchTests(unittest.TestCase):
 def test_prepare_failure_reports_original_error_and_never_starts_worker(self):
  h=Harness();h.env={};h.dirs.add(R+'/job');h.files[R+'/job/token']='owned'
  h.lua.execute("dofile=function()return {prepare=function()error('download timed out')end}end")
  h.run_mode('launch','game-on','owned')
  result=h.get(R+'/result.json');self.assertEqual(result['state'],'failed');self.assertEqual(result['phase'],'prepare')
  self.assertIn('download timed out',result['message']);self.assertNotIn(R+'/job/token',h.files)
  self.assertFalse(any(' worker ' in c for c in h.events))
 def test_launcher_prepares_before_lock_and_then_invokes_worker(self):
  h=Harness();h.env={};h.dirs.add(R+'/job');h.files[R+'/job/token']='owned'
  h.lua.execute("dofile=function()return {prepare=function()assert(os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')==nil);print('prepared')end}end")
  h.run_mode('launch','game-refresh','owned')
  self.assertIn('prepared',h.outputs);self.assertTrue(any('flock -n 9' in c and ' worker ' in c for c in h.events))
 def test_recovery_error_is_recorded_without_failing_main_reconcile(self):
  h=Harness();h.files[B+'/game-tunnel.lua']='present'
  h.lua.execute("dofile=function()error('broken game journal')end")
  self.assertEqual(h.run_mode('reconcile'),0)
  result=h.get(R+'/reconcile.json');self.assertEqual(result['failures'],0)
  self.assertEqual(result['game_recovery']['state'],'failed');self.assertIn('broken game journal',result['game_recovery']['error'])
 def test_start_shell_returns_before_slow_background_launch(self):
  import subprocess,time
  h=Harness();h.env={};h.run_mode('start','game-on')
  cmd=next(c for c in h.events if ' launch ' in c)
  self.assertNotIn('game-prepare',cmd)
  cmd=cmd.replace('/usr/libexec/pnw-control launch', 'sleep 1; :').replace('>'+R+'/job.log','>/dev/null')
  started=time.monotonic();subprocess.run(['/bin/sh','-c',cmd],check=True,capture_output=True,timeout=0.5)
  self.assertLess(time.monotonic()-started,0.5)

class GameOffPreconditionTests(unittest.TestCase):
 def test_unknown_containment_still_blocks_off(self):
  h=Harness();h.fail['nft list tables']=('permission denied',1)
  h.lua.execute("dofile=function()return {status=function()return {available=true,enabled=true,consistent=false}end}end")
  status=h.to_py(h.api.status());self.assertFalse(status['actions']['game-off']['allowed'])
  self.assertEqual(status['actions']['game-off']['reason'],'cannot inspect emergency containment')
