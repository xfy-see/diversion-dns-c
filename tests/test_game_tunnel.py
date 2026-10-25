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
  self.lua=LuaRuntime(unpack_returned_tuples=True);self.files={};self.commands=[];self.failure=None;self.failure_once=None;self.gate=False
  def parse(s):
   try:return self.table(json.loads(s))
   except Exception:return None
  def serial(t):return json.dumps(self.python(t))
  def command(s):
   self.commands.append(s)
   if self.failure and self.failure in s:return '\nGAME_RC=1\n'
   if self.failure_once and self.failure_once in s:
    self.failure_once=None;return '\nGAME_RC=1\n'
   if 'uclient-fetch' in s:
    a,b=self.feeds()
    self.files['/etc/pnw-control/game-tunnel/'+('sdr.download'if 'GetSDR' in s else 'cm.download')]=json.dumps(a if 'GetSDR' in s else b)
   if s.startswith('(nft -f /etc/pnw-control/game-tunnel/runtime.nft'):
    self.gate='game_enabled { tcp, udp }'in self.files['/etc/pnw-control/game-tunnel/runtime.nft']
   if s.startswith('(nft list set'):return 'table inet diversion_dns { set game_enabled { type inet_proto; '+('elements = { tcp, udp };'if self.gate else '')+' } }\nGAME_RC=0\n'
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
os.remove=pyremove;os.rename=pyrename;os.getenv=function(k)if k=='PNW_GAME_PREPARED'then return '/var/run/pnw-control/job/game-data'elseif k=='DIVERSION_CN_DEPLOY_LOCK_HELD'then return '1'end end
''')
  q=self.lua.execute((ROOT/'packaging/managed/ui/query.lua').read_text());g.querymodule=q;self.lua.execute('dofile=function()return querymodule end')
  self.module=self.lua.execute((BASE/'game-tunnel.lua').read_text())
  self.files['/var/run/pnw-control/job/game-data']=json.dumps(self.python(self.module.parse_feeds(*[self.table(x)for x in self.feeds()])))
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
 def test_toggle_on_off_roundtrip(self):
  path='/etc/diversion-dns-c/config.conf';self.h.files[path]='cache_size=64\n'
  self.h.module.set(True);d=self.h.python(self.h.module.status());self.assertTrue(d['enabled']);self.assertTrue(d['consistent']);self.assertTrue(self.h.gate)
  self.h.module.set(False);self.assertEqual(self.h.files[path],'cache_size=64\n');self.assertFalse(self.h.gate);self.assertTrue(self.h.python(self.h.module.status())['consistent'])
 def test_download_failure_does_not_mutate_config(self):
  path='/etc/diversion-dns-c/config.conf';self.h.files[path]='original';self.h.files.pop('/var/run/pnw-control/job/game-data',None)
  with self.assertRaises(Exception):self.h.module.set(True)
  self.assertEqual(self.h.files[path],'original');self.assertNotIn('/etc/pnw-control/game-tunnel/pending.json',self.h.files)
 def test_nft_failure_restores_before_config_and_mode(self):
  path='/etc/diversion-dns-c/config.conf';self.h.files[path]='original\n';self.h.failure_once='nft -f /etc/pnw-control/game-tunnel/runtime.nft'
  with self.assertRaises(Exception):self.h.module.set(True)
  self.assertEqual(self.h.files[path],'original\n');self.assertFalse(self.h.gate);self.assertNotIn('/etc/pnw-control/game-tunnel/pending.json',self.h.files)
 def test_dns_startup_probe_retries_before_committing(self):
  self.h.files['/etc/diversion-dns-c/config.conf']='original\n'
  self.h.failure_once='lua /etc/diversion-dns-c/dns-probe.lua'
  self.h.module.set(True)
  probes=[c for c in self.h.commands if 'dns-probe.lua'in c]
  self.assertEqual(len(probes),2);self.assertTrue(self.h.gate)
  self.assertNotIn('/etc/pnw-control/game-tunnel/pending.json',self.h.files)
 def test_persistent_dns_failure_keeps_recovery_journal(self):
  self.h.files['/etc/diversion-dns-c/config.conf']='original\n'
  self.h.failure='lua /etc/diversion-dns-c/dns-probe.lua'
  with self.assertRaises(Exception):self.h.module.set(True)
  self.assertEqual(len([c for c in self.h.commands if 'dns-probe.lua'in c]),10)
  self.assertIn('/etc/pnw-control/game-tunnel/pending.json',self.h.files)
  self.assertEqual(self.h.files['/etc/diversion-dns-c/config.conf'],'original\n')
 def test_refresh_failure_retains_previous_list(self):
  path='/etc/pnw-control/game-tunnel/data.json';self.h.files[path]='last-good';self.h.files.pop('/var/run/pnw-control/job/game-data',None)
  with self.assertRaises(Exception):self.h.module.refresh()
  self.assertEqual(self.h.files[path],'last-good')
 def test_invalid_journal_is_not_silently_ignored(self):
  self.h.files['/etc/pnw-control/game-tunnel/pending.json']='{}'
  with self.assertRaises(Exception):self.h.module.recover()
 def test_reconcile_never_downloads_under_lock(self):
  self.h.files['/etc/pnw-control/game-tunnel/state.json']='{"enabled":true}'
  self.assertTrue(self.h.module.reconcile())
  self.assertFalse(any('uclient-fetch' in c for c in self.h.commands))
 def test_off_works_during_emergency_and_without_prepared_data(self):
  self.h.files['/etc/diversion-dns-c/config.conf']='original\n'
  self.h.module.set(True)
  self.h.files['/etc/pnw-control/emergency']='1'
  self.h.files['/etc/diversion-dns-c/degraded']='1'
  self.h.files.pop('/var/run/pnw-control/job/game-data')
  self.h.failure='audit-runtime'
  self.h.module.set(False);self.assertFalse(self.h.gate)
 def test_failed_enable_restores_exact_old_data(self):
  self.h.files['/etc/diversion-dns-c/config.conf']='original\n'
  path='/etc/pnw-control/game-tunnel/data.json';self.h.files[path]='{"old":true}'
  self.h.failure_once='nft -f /etc/pnw-control/game-tunnel/runtime.nft'
  with self.assertRaises(Exception):self.h.module.set(True)
  self.assertEqual(self.h.files[path],'{"old":true}')
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
 def test_transport_tuple_precedes_dynamic_protocol_gate(self):
  text=integrate.policy('add rule inet diversion_dns split ip daddr @cn4 return\nadd rule inet diversion_dns router_output ip daddr @cn4 return\n')
  for line in text.splitlines():
   if ' dport 'in line:self.assertLess(line.index(' dport '),line.index('meta l4proto @game_enabled'))
 def test_helper_bootstrap_precedes_policy(self):
  text=integrate.helper('cat "$base/policy.nft" >> "$file"\nnft -f "$file"')
  self.assertLess(text.index('game-tunnel-render'),text.index('cat "$base/policy'))
if __name__=='__main__':unittest.main()

@unittest.skipIf(LuaRuntime is None, 'prebuilt lupa required')
class DedicatedTests(unittest.TestCase):
 def setup_module(self):
  h=GameHarness();self.h=h;self.peer='A'*43+'='
  h.files['/etc/pnw-control/game-tunnel/egress.json']=json.dumps(dict(interface='wg_game',mark=2,table=20234,peer=self.peer))
  self.bad=None
  def command(c):
   if self.bad and self.bad in c:return ''
   if 'nft -j list chain'in c:return json.dumps({'nftables':[{'rule':{'comment':'Dedicated game fail closed'}}]})
   if c.startswith('ip -'):return '1.1.1.1 dev wg_game table 20234 src 192.0.2.1\n'
   if 'allowed-ips'in c:return self.peer+'\t0.0.0.0/0 ::/0\n'
   if 'latest-handshakes'in c:return self.peer+'\t'+str(int(h.lua.eval('os.time()')))+'\n'
   if 'router_output'in c or ' split'in c:return ''.join('@'+name+' meta mark set 0x00000002\n'for name in ('game_site4','game_site6','game_relay4','game_cm4'))
   return 'ct direction original meta mark 0x00000002 oifname != "wg_game" drop comment "Dedicated game fail closed"\n'
  h.lua.globals().pycommand=command
  return h.lua.execute((BASE/'game-egress.lua').read_text())
 def test_actual_routes_peer_guard_and_handshake_required(self):
  m=self.setup_module();self.assertTrue(self.h.python(m.status())['ready'])
  for bad in ['ip -4','ip -6','allowed-ips','router_output',' split',' guard','router_guard','latest-handshakes']:
   self.bad=bad;self.assertFalse(self.h.python(m.status())['ready'],bad)
 def test_missing_identity_cannot_masquerade_as_current_exit(self):
  h=GameHarness();h.files['/etc/diversion-dns-c/policy.nft']='Dedicated game fail closed'
  d=h.python(h.module.status());self.assertFalse(d['consistent']);self.assertFalse(d['egress']['ready'])
 def test_invalid_config_refuses_shell_input(self):
  m=self.setup_module();self.h.files['/etc/pnw-control/game-tunnel/egress.json']='{"interface":"wg_game; reboot"}'
  with self.assertRaises(Exception):m.status()
 def test_upgrade_is_precise_and_keeps_global_mark(self):
  text='add chain inet diversion_dns guard\nadd chain inet diversion_dns router_guard\n'
  text+='add rule inet diversion_dns router_output ct direction reply return\n'
  for c in ('split','router_output'):text+='add rule inet diversion_dns '+c+' ip daddr @cn4 return\nadd rule inet diversion_dns '+c+' meta mark set 1 ct mark set 1\n'
  out=integrate.dedicated_policy(integrate.policy(text))
  self.assertEqual(out.count('meta mark set 2 ct mark set 2'),11)
  self.assertEqual(out.count('meta mark set 1 ct mark set 1'),2)
  self.assertEqual(out.count('Dedicated game fail closed'),2)
  with self.assertRaises(ValueError):integrate.dedicated_policy(out)
 def test_emergency_covers_both_marks(self):
  self.assertEqual(integrate.dedicated_emergency('meta mark 1 counter drop\n'*2).count('meta mark { 1, 2 }'),2)
  with self.assertRaises(ValueError):integrate.dedicated_emergency('other')

@unittest.skipIf(LuaRuntime is None,'prebuilt lupa required')
class ReviewRegressionTests(unittest.TestCase):
 def test_broken_egress_keeps_status_available(self):
  h=GameHarness();h.files['/etc/pnw-control/game-tunnel/egress.json']='broken'
  h.lua.execute("dofile=function()error('invalid identity')end")
  status=h.python(h.module.status());self.assertTrue(status['available']);self.assertFalse(status['consistent']);self.assertFalse(status['egress']['ready'])
 def test_expired_preparation_cannot_enable(self):
  h=GameHarness();h.files['/etc/diversion-dns-c/config.conf']='original'
  d=json.loads(h.files['/var/run/pnw-control/job/game-data']);d['updated']=1
  h.files['/var/run/pnw-control/job/game-data']=json.dumps(d)
  with self.assertRaises(Exception):h.module.set(True)
  self.assertEqual(h.files['/etc/diversion-dns-c/config.conf'],'original')
 def test_guards_insert_before_existing_accept(self):
  text='add chain inet diversion_dns guard\nadd chain inet diversion_dns router_guard\nadd rule inet diversion_dns guard accept\nadd rule inet diversion_dns router_guard accept\nadd rule inet diversion_dns router_output ct direction reply return\n'
  text+=''.join('add rule inet diversion_dns '+c+' ip daddr @cn4 return\n'for c in ('split','router_output'))
  out=integrate.dedicated_policy(integrate.policy(text))
  for c in ('guard','router_guard'):self.assertIn('insert rule inet diversion_dns '+c+' ct direction original meta mark 2',out)

@unittest.skipIf(LuaRuntime is None,'prebuilt lupa required')
class PreparationTests(unittest.TestCase):
 def test_download_failure_records_reason_and_does_not_prepare(self):
  h=GameHarness();h.files.pop('/var/run/pnw-control/job/game-data');h.failure='uclient-fetch'
  h.lua.execute("os.getenv=function()return nil end")
  with self.assertRaises(Exception):h.module.prepare('/var/run/pnw-control/job/game-data')
  status=json.loads(h.files['/etc/pnw-control/game-tunnel/refresh.json'])
  self.assertEqual(status['state'],'failed');self.assertIn('game tunnel operation failed',status['error'])
  self.assertNotIn('/var/run/pnw-control/job/game-data',h.files)
 def test_successful_prepare_and_apply_have_terminal_status(self):
  h=GameHarness();h.files['/etc/diversion-dns-c/config.conf']='original'
  h.lua.execute("os.getenv=function()return nil end")
  h.module.prepare('/var/run/pnw-control/job/game-data')
  self.assertEqual(json.loads(h.files['/etc/pnw-control/game-tunnel/refresh.json'])['state'],'prepared')
  h.lua.execute("os.getenv=function(k)if k=='PNW_GAME_PREPARED'then return '/var/run/pnw-control/job/game-data'else return '1'end end")
  h.module.set(True)
  self.assertEqual(json.loads(h.files['/etc/pnw-control/game-tunnel/refresh.json'])['state'],'success')

@unittest.skipIf(LuaRuntime is None,'prebuilt lupa required')
class GuardOrderTests(unittest.TestCase):
 setup_module=DedicatedTests.setup_module
 def test_guard_after_accept_is_not_ready(self):
  m=self.setup_module();prior=self.h.lua.globals().pycommand
  self.h.lua.globals().pycommand=lambda c: json.dumps({'nftables':[{'rule':{'expr':[{'accept':None}]}},{'rule':{'comment':'Dedicated game fail closed'}}]})if 'nft -j list chain'in c else prior(c)
  self.assertFalse(self.h.python(m.status())['consistent'])
