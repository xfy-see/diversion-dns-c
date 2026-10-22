import sys,json,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_control import Harness,ExitCode
S=Path(__file__).resolve().parents[1]/'device'
SHARED=S.parent
class Device(unittest.TestCase):
 def setUp(self):
  self.h=Harness();h=self.h
  h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-local.example.json').read_text();h.files['/proc/loadavg']='0.1 0.2 0.3';h.files['/proc/meminfo']='MemAvailable: 30000\n'
  self.calls=[]
  h.lua.globals().DEV_RUN=lambda c:(self.calls.append(c) or ('',1))
  h.lua.globals().REAL_QUERY=h.lua.execute((SHARED/'query.lua').read_text())
  h.lua.execute("dofile=function(p) if p:match('query.lua$') then return REAL_QUERY elseif p:match('window.lua$') then return {status=function()return {stats={available=true}}end} elseif p:match('telemetry.lua$') then return {status=function() return {stats={available=true}} end,collect=function()return true end} elseif p:match('dns%-status.lua$') then return {get=function()return {cn={},foreign={}}end} end error('unexpected module '..p) end")
  s=(S/'device.lua').read_text();start=s.index('local function run(c)');end=s.index('local function ms()',start)
  self.api=h.lua.execute(s[:start]+'local function run(c)return DEV_RUN(c)end\n'+s[end:])
 def test_legacy_profile_ids_and_local_listener_addresses_remain_supported(self):
  for name,legacy in [('profile-local.example.json','122'),('profile-listener.example.json','131')]:
   p=json.loads((S/name).read_text());p['device']=legacy
   if legacy=='131':p['dns_host']='192.0.2.88'
   self.h.files['/etc/diversion-dns-ui/profile.json']=json.dumps(p)
   self.assertEqual(self.h.to_py(self.api.status())['device_profile'],legacy)
 def test_actions_fail_closed(self):
  for action in ['switch-aws','switch-nobrand','switch-usss','switch-usvless','rescue','recover','rollback','retry-recovery','check;reboot','unknown']:
   with self.assertRaises(Exception):self.api.main(self.h.to_lua(['start',action]))
  self.assertEqual(self.calls,[])
 def test_unknown_and_extra_args_rejected(self):
  for args in [['start','check','extra'],['foo'],['query','1.1.1.1','router','extra']]:
   with self.assertRaises(Exception):self.api.main(self.h.to_lua(args))
 def test_invalid_profile_rejected(self):
  for field,value in [('device','1'),('config','/etc/shadow'),('service','dnsmasq'),('dns_host','evil'),('dns_port',53)]:
   p=json.loads((S/'profile-local.example.json').read_text());p[field]=value;self.h.files['/etc/diversion-dns-ui/profile.json']=json.dumps(p)
   with self.assertRaises(Exception):self.api.status()
 def test_status_has_real_mode_and_disabled_actions(self):
  r=self.h.to_py(self.api.status());self.assertIn('需要重新核对',r['mode_text']);self.assertFalse(r['actions']['recover']['allowed']);self.assertTrue(r['actions']['check']['allowed'])
  self.assertFalse(r['dns_upstreams']['cn']['available']);self.assertFalse(r['topology_verified']);self.assertNotIn('pnw_aws',str(self.calls))
 def test_routing_public_probe_has_no_shared_json_table(self):
  h=self.h;h.files['/etc/diversion-dns-ui/routing.json']='{"enabled":true}'
  h.lua.execute("local previous=dofile;dofile=function(p)if p:match('routing.lua$')then return {status=function()return {enabled=true,runtime={ok=true,selected='aws',configured_selected='aws'},scope='isolated',pending=false,public_exit={ok=true,ipv4={identity_status='verified'},ipv6={identity_status='verified'}}}end}else return previous(p)end end")
  result=self.api.status();r=h.to_py(result);self.assertTrue(r['public_exit']['ok']);self.assertNotIn('public_exit',r['routing'])
  # lua-cjson/jsonc detects aliasing even when Python's serializer does not.
  h.lua.globals().DEVICE_RESULT=result
  h.lua.execute("local seen={};local function unique(t)if type(t)~='table'then return end;assert(not seen[t],'shared JSON table');seen[t]=true;for _,v in pairs(t)do unique(v)end end;unique(DEVICE_RESULT)")
 def test_131_does_not_claim_tunnel(self):
  self.h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-listener.example.json').read_text();r=self.h.to_py(self.api.status());self.assertIn('未部署隧道',r['mode_text']);self.assertEqual(r['selected'],'upstream')
 def test_input_injection_and_unknown_source(self):
  self.assertFalse(self.api.query('x; reboot','router')['ok']);self.assertFalse(self.api.query('1.1.1.1','192.168.50.19')['ok']);self.assertEqual(self.calls,[])
 def test_changed_policy_does_not_guess(self):
  r=self.h.to_py(self.api.query('1.1.1.1','router'));self.assertEqual(r['answers'][0]['expected_path'],'unknown')
 def test_131_route_is_upstream_unknown(self):
  self.h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-listener.example.json').read_text();r=self.h.to_py(self.api.query('1.1.1.1','lan'));self.assertEqual(r['answers'][0]['expected_path'],'unknown');self.assertIn('上级',r['answers'][0]['reason'])
 def test_generic_profile_never_claims_verified_routing(self):
  p=json.loads((S.parents[1]/'profile.json').read_text());self.h.files['/etc/diversion-dns-ui/profile.json']=json.dumps(p)
  r=self.h.to_py(self.api.status());self.assertEqual(r['selected'],'unmanaged');self.assertIn('按本机配置',r['mode_text'])
  r=self.h.to_py(self.api.query('1.1.1.1','router'));self.assertEqual(r['answers'][0]['expected_path'],'unknown');self.assertIn('未验证本机策略',r['answers'][0]['reason'])
 def async_parent(self):
  self.h.lua.execute("require('nixio').fork=function()return 456 end")
  self.h.files['/proc/123']='live'
  return self.h.to_py(self.api.main(self.h.to_lua(['query-start','example.com','lan'])))
 def test_async_query_returns_ticket_without_executing_lookup(self):
  r=self.async_parent();self.assertTrue(r['accepted']);self.assertEqual(self.calls,[])
  task=self.h.to_py(self.api.main(self.h.to_lua(['query-status',r['query_id']])))
  self.assertEqual(task['state'],'running')
  with self.assertRaises(Exception):self.api.main(self.h.to_lua(['query-start','example.net','router']))
 def test_async_query_rejects_invalid_input_before_fork(self):
  for args in [['query-start','x;reboot','router'],['query-start','example.com','bypass'],['query-start','example.com','router','extra'],['query-status','../../x'],['query-status','1-2','extra'],['start','query']]:
   with self.assertRaises(Exception):self.api.main(self.h.to_lua(args))
  self.assertNotIn('/var/run/diversion-dns-ui/lock',self.h.dirs);self.assertEqual(self.calls,[])
 def test_async_query_dead_worker_and_wrong_ticket_fail(self):
  r=self.async_parent();del self.h.files['/proc/123']
  task=self.h.to_py(self.api.main(self.h.to_lua(['query-status',r['query_id']])))
  self.assertEqual(task['state'],'failed');self.assertIn('进程已退出',task['error'])
  with self.assertRaises(Exception):self.api.main(self.h.to_lua(['query-status','1-2']))
 def test_async_query_timeout_keeps_live_lock(self):
  r=self.async_parent();self.h.now+=121
  task=self.h.to_py(self.api.main(self.h.to_lua(['query-status',r['query_id']])))
  self.assertEqual(task['state'],'failed');self.assertIn('120',task['error'])
  self.assertIn('/var/run/diversion-dns-ui/lock',self.h.dirs)
 def test_async_query_child_saves_complete_result_then_unlocks(self):
  self.h.lua.execute("local n=require('nixio');n.fork=function()return 0 end;n.setsid=function()end;n.open=function()return nil end")
  self.api.query=self.h.lua.eval("function(input,source)return {ok=true,input=input,source=source,answers={{address='192.0.2.1'}}}end")
  with self.assertRaises(ExitCode):self.api.main(self.h.to_lua(['query-start','example.com','lan']))
  task=json.loads(self.h.files['/var/run/diversion-dns-ui/query.json'])
  self.assertEqual(task['state'],'complete');self.assertEqual(task['result']['source'],'lan')
  self.assertNotIn('/var/run/diversion-dns-ui/lock',self.h.dirs)
 def test_async_query_child_error_and_fork_failure_release_lock(self):
  self.h.lua.execute("local n=require('nixio');n.fork=function()return nil end")
  with self.assertRaises(Exception):self.api.main(self.h.to_lua(['query-start','example.com','router']))
  self.assertNotIn('/var/run/diversion-dns-ui/lock',self.h.dirs)
  self.h.lua.execute("local n=require('nixio');n.fork=function()return 0 end;n.setsid=function()end;n.open=function()return nil end")
  self.api.query=self.h.lua.eval("function()error('fixture lookup failure')end")
  with self.assertRaises(ExitCode):self.api.main(self.h.to_lua(['query-start','example.com','router']))
  task=json.loads(self.h.files['/var/run/diversion-dns-ui/query.json'])
  self.assertEqual(task['state'],'failed');self.assertIn('fixture lookup failure',task['error'])
  self.assertNotIn('/var/run/diversion-dns-ui/lock',self.h.dirs)
if __name__=='__main__':unittest.main()
