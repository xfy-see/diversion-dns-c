import sys,json,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_control import Harness
S=Path(__file__).resolve().parents[1]/'device'
SHARED=S.parent
class Device(unittest.TestCase):
 def setUp(self):
  self.h=Harness();h=self.h
  h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-122.example.json').read_text();h.files['/proc/loadavg']='0.1 0.2 0.3';h.files['/proc/meminfo']='MemAvailable: 30000\n'
  self.calls=[]
  h.lua.globals().DEV_RUN=lambda c:(self.calls.append(c) or ('',1))
  h.lua.execute("dofile=function(p) if p:match('query.lua$') then return {validate_input=function(s) if s=='1.1.1.1' then return s,'ipv4' end return nil,'invalid input' end} elseif p:match('window.lua$') then return {status=function()return {stats={available=true}}end} elseif p:match('telemetry.lua$') then return {status=function() return {stats={available=true}} end,collect=function()return true end} elseif p:match('dns%-status.lua$') then return {get=function()return {cn={},foreign={}}end} end error('unexpected module '..p) end")
  s=(S/'device.lua').read_text();start=s.index('local function run(c)');end=s.index('local function ms()',start)
  self.api=h.lua.execute(s[:start]+'local function run(c)return DEV_RUN(c)end\n'+s[end:])
 def test_actions_fail_closed(self):
  for action in ['switch-aws','switch-nobrand','switch-usss','switch-usvless','rescue','recover','rollback','retry-recovery','check;reboot','unknown']:
   with self.assertRaises(Exception):self.api.main(self.h.to_lua(['start',action]))
  self.assertEqual(self.calls,[])
 def test_unknown_and_extra_args_rejected(self):
  for args in [['start','check','extra'],['foo'],['query','1.1.1.1','router','extra']]:
   with self.assertRaises(Exception):self.api.main(self.h.to_lua(args))
 def test_invalid_profile_rejected(self):
  for field,value in [('device','1'),('config','/etc/shadow'),('service','dnsmasq'),('dns_host','evil'),('dns_port',53)]:
   p=json.loads((S/'profile-122.example.json').read_text());p[field]=value;self.h.files['/etc/diversion-dns-ui/profile.json']=json.dumps(p)
   with self.assertRaises(Exception):self.api.status()
 def test_status_has_real_mode_and_disabled_actions(self):
  r=self.h.to_py(self.api.status());self.assertIn('需要重新核对',r['mode_text']);self.assertFalse(r['actions']['recover']['allowed']);self.assertTrue(r['actions']['check']['allowed'])
  self.assertFalse(r['dns_upstreams']['cn']['available']);self.assertFalse(r['topology_verified']);self.assertNotIn('pnw_aws',str(self.calls))
 def test_131_does_not_claim_tunnel(self):
  self.h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-131.example.json').read_text();r=self.h.to_py(self.api.status());self.assertIn('未部署隧道',r['mode_text']);self.assertEqual(r['selected'],'upstream')
 def test_input_injection_and_unknown_source(self):
  self.assertFalse(self.api.query('x; reboot','router')['ok']);self.assertFalse(self.api.query('1.1.1.1','192.168.100.19')['ok']);self.assertEqual(self.calls,[])
 def test_changed_policy_does_not_guess(self):
  r=self.h.to_py(self.api.query('1.1.1.1','router'));self.assertEqual(r['answers'][0]['expected_path'],'unknown')
 def test_131_route_is_upstream_unknown(self):
  self.h.files['/etc/diversion-dns-ui/profile.json']=(S/'profile-131.example.json').read_text();r=self.h.to_py(self.api.query('1.1.1.1','lan'));self.assertEqual(r['answers'][0]['expected_path'],'unknown');self.assertIn('上级',r['answers'][0]['reason'])
 def test_generic_profile_never_claims_verified_routing(self):
  p=json.loads((S.parents[1]/'profile.json').read_text());self.h.files['/etc/diversion-dns-ui/profile.json']=json.dumps(p)
  r=self.h.to_py(self.api.status());self.assertEqual(r['selected'],'unmanaged');self.assertIn('按本机配置',r['mode_text'])
  r=self.h.to_py(self.api.query('1.1.1.1','router'));self.assertEqual(r['answers'][0]['expected_path'],'unknown');self.assertIn('未验证本机策略',r['answers'][0]['reason'])
if __name__=='__main__':unittest.main()
