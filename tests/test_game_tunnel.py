"""Pure Lua/profile and deployment transformation tests; no device/network/C build."""
from pathlib import Path
import copy, importlib.util,json,unittest
try:
 from lupa.lua51 import LuaRuntime
except ImportError:
 LuaRuntime=None
ROOT=Path(__file__).resolve().parents[1]
BASE=ROOT/'deployment/game-tunnel'
spec=importlib.util.spec_from_file_location('game_integrate',BASE/'integrate.py');integrate=importlib.util.module_from_spec(spec);spec.loader.exec_module(integrate)
class GameHarness:
 def __init__(self):
  self.lua=LuaRuntime(unpack_returned_tuples=True);self.files={};self.commands=[];self.failure=None
  def parse(s):
   try:return self.table(json.loads(s))
   except Exception:return None
  def serial(t):return json.dumps(self.python(t))
  def command(s):
   self.commands.append(s)
   if self.failure and self.failure in s:return '\nGAME_RC=1\n'
   if s.startswith('(nft list set'):return 'table inet diversion_dns { set game_enabled { type inet_proto; } }\nGAME_RC=0\n'
   return '\nGAME_RC=0\n'
  g=self.lua.globals();g.pyread=lambda p:self.files.get(p);g.pywrite=lambda p,s:self.files.__setitem__(p,s);g.pyremove=lambda p:self.files.pop(p,None) is not None;g.pyrename=lambda a,b:self.files.__setitem__(b,self.files.pop(a))or True;g.pyparse=parse;g.pyserial=serial;g.pycommand=command
  self.lua.execute('''package.preload['luci.jsonc']=function()return {parse=pyparse,stringify=pyserial}end
package.preload['nixio.fs']=function()return {}end
io.open=function(p,mode)
 if mode=='w' then return {write=function(_,s)pywrite(p,s);return true end,close=function()return true end}end
 local v=pyread(p);if not v then return nil end
 return {read=function(_,n)return type(n)=='number'and v:sub(1,n)or v end,close=function()return true end}
end
io.popen=function(c)local s=pycommand(c);return {read=function()return s end,close=function()return true end}end
os.remove=pyremove;os.rename=pyrename;os.getenv=function()return '1'end
''')
  q=self.lua.execute((ROOT/'packaging/managed/ui/query.lua').read_text());g.querymodule=q;self.lua.execute('dofile=function()return querymodule end')
  self.module=self.lua.execute((BASE/'game-tunnel.lua').read_text())
 def table(self,x):
  if isinstance(x,dict):return self.lua.table_from({k:self.table(v)for k,v in x.items()})
  if isinstance(x,list):return self.lua.table_from([self.table(v)for v in x])
  return x
 def python(self,x):
  if hasattr(x,'items'):
   d={k:self.python(v)for k,v in x.items()}
   if d and set(d)==set(range(1,len(d)+1)):return [d[i]for i in range(1,len(d)+1)]
   return d
  return x
 def feeds(self):
  s={'success':True,'revision':100,'pops':{'lab':{'relays':[{'ipv4':'9.9.9.9','port_range':[27014+i,27060]}for i in range(1,11)]}}}
  c={'response':{'success':True,'serverlist':[{'type':'netfilter','endpoint':f'8.8.8.8:{27016+i}'}for i in range(1,3)]}}
  return s,c
@unittest.skipIf(LuaRuntime is None, "prebuilt lupa required; never compile locally")
class GameTests(unittest.TestCase):
 def setUp(self):self.h=GameHarness()
 def parse(self,s=None,c=None):
  a,b=self.h.feeds();return self.h.module.parse_feeds(self.h.table(s if s is not None else a),self.h.table(c if c is not None else b))
 def test_public_feeds_to_precise_tuples(self):
  d=self.parse();text=self.h.module.runtime(True,d)
  self.assertIn('9.9.9.9 . 27015-27060',text);self.assertIn('8.8.8.8 . 27017',text);self.assertNotIn('dport 27000-',text)
  self.assertEqual(self.h.python(d)['revision'],100)
 def test_disabled_gate_is_empty(self):
  text=self.h.module.runtime(False,None);self.assertIn('flush set inet diversion_dns game_enabled',text);self.assertNotIn('add element',text)
 def test_invalid_sdr_variants_are_rejected(self):
  for change in ['empty','private','port','shell','type','success']:
   with self.subTest(change=change):
    s,c=self.h.feeds();r=s['pops']['lab']['relays'][0]
    if change=='empty':s['pops']={}
    elif change=='private':r['ipv4']='127.0.0.1'
    elif change=='port':r['port_range']=[1,65535]
    elif change=='shell':r['ipv4']='9.9.9.9; reboot'
    elif change=='type':r['port_range']=['27015',27060]
    else:s['success']=False
    with self.assertRaises(Exception):self.parse(s,c)
 def test_cm_failures_rejected(self):
  for change in ['empty','private','endpoint','success']:
   with self.subTest(change=change):
    s,c=self.h.feeds()
    if change=='empty':c['response']['serverlist']=[]
    elif change=='private':c['response']['serverlist'][0]['endpoint']='192.168.50.1:27017'
    elif change=='endpoint':c['response']['serverlist'][0]['endpoint']='host.invalid:27017'
    else:c['response']['success']=False
    with self.assertRaises(Exception):self.parse(s,c)
 def test_config_roundtrip_preserves_other_settings(self):
  old='cn_upstream=127.0.0.1:5301\nforeign_upstream=127.0.0.1:5302\n'
  on=self.h.module.config(old,True);self.assertIn('tunnel_domain_file=',on)
  self.assertEqual(self.h.module.config(on,True),on);self.assertEqual(self.h.module.config(on,False),old)
 def test_config_rejects_partial_duplicate_and_unmanaged(self):
  for s in ['# BEGIN PNW GAME TUNNEL\n','tunnel_domain_file=/other\n','# END PNW GAME TUNNEL\n']:
   with self.assertRaises(Exception):self.h.module.config(s,True)
 def test_disabled_status_does_not_fetch(self):
  self.h.files['/etc/diversion-dns-c/config.conf']='cn_upstream=127.0.0.1\n'
  d=self.h.python(self.h.module.status());self.assertTrue(d['consistent']);self.assertFalse(d['enabled']);self.assertFalse(any('uclient' in c for c in self.h.commands))
 def test_detects_config_runtime_disagreement(self):
  self.h.files['/etc/diversion-dns-c/config.conf']=self.h.module.config('cache_size=10\n',True)
  self.assertFalse(self.h.python(self.h.module.status())['consistent'])
 def test_recover_refuses_external_config_changes(self):
  self.h.files['/etc/pnw-control/game-tunnel/pending.json']=json.dumps({'state':'applying','before':'old','after':'new','old':{'enabled':False}})
  self.h.files['/etc/diversion-dns-c/config.conf']='external'
  with self.assertRaises(Exception):self.h.module.recover()
  self.assertEqual(self.h.files['/etc/diversion-dns-c/config.conf'],'external')
 def test_recover_is_idempotent(self):
  self.h.files['/etc/pnw-control/game-tunnel/pending.json']=json.dumps({'state':'applying','before':'old','after':'new','old':{'enabled':False}})
  self.h.files['/etc/diversion-dns-c/config.conf']='new'
  self.assertTrue(self.h.module.recover());self.assertFalse(self.h.module.recover());self.assertEqual(self.h.files['/etc/diversion-dns-c/config.conf'],'old')
 def test_recovery_failure_preserves_journal(self):
  self.h.files['/etc/pnw-control/game-tunnel/pending.json']=json.dumps({'state':'applying','before':'old','after':'new','old':{'enabled':False}})
  self.h.files['/etc/diversion-dns-c/config.conf']='new';self.h.failure='diversion-dns-c restart'
  with self.assertRaises(Exception):self.h.module.recover()
  self.assertIn('/etc/pnw-control/game-tunnel/pending.json',self.h.files)
 def test_profile_does_not_include_download_domains(self):
  rules=(BASE/'domains.txt').read_text().splitlines();active=[r for r in rules if r and not r.startswith('#')]
  for name in ['steamcontent.com','steamstatic.com','steamusercontent.com','client-download.steampowered.com','steampowered.com']:
   self.assertNotIn('domain:'+name,active);self.assertNotIn('full:'+name,active)
 def test_policy_exceptions_stay_before_game_before_cn(self):
  text=''.join('add rule inet diversion_dns '+chain+' '+body+'\n'for chain in ['split','router_output']for body in ['fib daddr type local return','ip daddr @cn4 return','meta mark set 1'])
  changed=integrate.policy(text)
  for chain in ['split','router_output']:
   section='\n'.join(x for x in changed.splitlines()if ' '+chain+' 'in x)
   self.assertLess(section.index('fib daddr'),section.index('@game_site4'));self.assertLess(section.index('@game_site4'),section.index('@cn4'));self.assertIn('@game_enabled',section)
  with self.assertRaises(ValueError):integrate.policy('unsupported')
 def test_helper_bootstrap_precedes_policy(self):
  text=integrate.helper('cat "$base/policy.nft" >> "$file"\nnft -f "$file"')
  self.assertLess(text.index('game-tunnel-render'),text.index('cat "$base/policy'))
if __name__=='__main__':unittest.main()
