"""Execute the production Lua module with deterministic IO, clock and kernel counters."""
import importlib.util,json,pathlib,re,sys,unittest
try:
 from lupa.lua51 import LuaRuntime
except ImportError:
 LuaRuntime=None
ROOT=pathlib.Path(__file__).resolve().parents[1]
SOURCE=(ROOT/'deployment/dota-egress/dota-egress.lua').read_text()
class Harness:
 def __init__(self):
  self.lua=LuaRuntime(unpack_returned_tuples=True);self.now=10000;self.up=100;self.commands=[];self.files={'/proc/uptime':'100 0','/proc/sys/kernel/random/boot_id':'boot1'};self.handle=1;self.n=0;self.fail=False
  g=self.lua.globals();g.parse=lambda x:self.t(json.loads(x));g.json=lambda x:json.dumps(self.py(x));g.openfile=self.open;g.rename=self.rename;g.remove=lambda p:self.files.pop(p,None);g.PY_RUN=self.run;g.clock=lambda:self.now
  self.lua.execute("""package.preload['luci.jsonc']=function()return{parse=function(s)return parse(s)end,stringify=function(s)return json(s)end}end
io.open=function(p,m)return openfile(p,m)end;os.rename=function(a,b)return rename(a,b)end;os.remove=function(p)return remove(p)end;os.time=function()return clock()end;os.getenv=function()return '1'end""")
  a=SOURCE.index('local function run(c)');b=SOURCE.index('local function must(c)',a)
  self.api=self.lua.execute(SOURCE[:a]+'local function run(c)return PY_RUN(c)end\n'+SOURCE[b:])
 def t(self,v):
  if isinstance(v,dict):return self.lua.table_from({k:self.t(x)for k,x in v.items()})
  if isinstance(v,list):return self.lua.table_from([self.t(x)for x in v])
  return v
 def py(self,v):
  if hasattr(v,'items'):return{k:self.py(x)for k,x in v.items()}
  return v
 def open(self,p,m=None):
  if not m and p not in self.files:return None
  if m=='w':self.files[p]=''
  def write(_,s):self.files[p]+=str(s);return True
  return self.lua.table_from({'read':lambda *a:self.files[p],'write':write,'close':lambda *a:True})
 def rename(self,a,b):self.files[b]=self.files.pop(a);return True
 def run(self,c):
  self.commands.append(c)
  if self.fail:return '',1
  if c=='nft -a -j list table inet pnw_dota_egress':
   values=[{'table':{'handle':self.handle}}]+[{'counter':{'name':id+'_'+d,'bytes':self.n,'packets':self.n//10}}for id in('aws','hk','game')for d in('up','down')]+[{'counter':{'name':'rejected','bytes':0,'packets':0}}]
   return json.dumps({'nftables':values}),0
  if c=='ip -4 rule show':return '',0
  if c.startswith('ip -N -4 route show table'):return '',0
  return '',0
@unittest.skipIf(LuaRuntime is None,'prebuilt lupa required')
class DotaTests(unittest.TestCase):
 def test_delta_resets_and_restarts(self):
  h=Harness();self.assertEqual(h.api.delta(100,140,True),40);self.assertEqual(h.api.delta(100,20,True),20);self.assertEqual(h.api.delta(100,140,False),140)
  with self.assertRaises(Exception):h.api.delta(100,-1,True)
 def test_totals_direction_and_per_exit(self):
  h=Harness();h.n=100;h.api.collect(False);h.n=150;h.now+=5;h.files['/proc/uptime']='105 0';x=h.py(h.api.collect(False));self.assertEqual(x['totals']['aws']['up'],150);self.assertEqual(x['totals']['hk']['down'],150);self.assertEqual(x['rates']['game']['down'],10)
  h.api.collect(False);x=json.loads(h.files['/var/run/pnw-dota-egress/traffic.json']);self.assertEqual(x['totals']['aws']['up'],150)
 def test_counter_recreation_does_not_subtract_or_double_count(self):
  h=Harness();h.n=100;h.api.collect(True);h.handle=2;h.n=150;x=h.py(h.api.collect(False));self.assertEqual(x['totals']['aws']['up'],250);self.assertEqual(x['resets'],1)
 def test_reboot_uses_checkpoint_and_new_generation(self):
  h=Harness();h.n=100;h.api.collect(True);h.files.pop('/var/run/pnw-dota-egress/traffic.json');h.files['/proc/sys/kernel/random/boot_id']='boot2';h.n=30;x=h.py(h.api.collect(False));self.assertEqual(x['totals']['aws']['up'],130)
 def test_read_failure_preserves_previous_snapshot(self):
  h=Harness();h.n=100;h.api.collect(True);before=dict(h.files);h.fail=True
  with self.assertRaises(Exception):h.api.collect(False)
  self.assertEqual(before,h.files)
 def test_persistence_interval_and_forced_checkpoint(self):
  h=Harness();h.n=100;h.api.collect(False);initial=h.files['/etc/pnw-control/dota-egress/traffic.json'];h.n=150;h.now+=5;h.api.collect(False);self.assertEqual(initial,h.files['/etc/pnw-control/dota-egress/traffic.json']);h.api.collect(True);self.assertNotEqual(initial,h.files['/etc/pnw-control/dota-egress/traffic.json'])
 def test_unknown_exit_never_executes(self):
  h=Harness()
  with self.assertRaises(Exception):h.api.switch('hk; touch /tmp/injected')
  self.assertEqual(h.commands,[])
 def test_invalid_relay_no_partial_output(self):
  h=Harness();good={'relay':[{'ip':'198.51.100.1','first':27015,'last':27020}for _ in range(10)]};self.assertIn('27015-27020',h.api.relays(h.t(good)))
  for ip in ['127.0.0.1','10.0.0.1','224.1.1.1','1.1.1.1;bad']:
   good['relay'][0]['ip']=ip
   with self.assertRaises(Exception):h.api.relays(h.t(good))
 def ready(self,h):
  h.files['/etc/pnw-control/dota-egress/config.json']=json.dumps({'version':1,'selected':'game'})
  h.files['/etc/pnw-control/game-tunnel/state.json']='{"enabled":true}'
  h.files['/etc/pnw-control/game-tunnel/data.json']=json.dumps({'relay':[{'ip':'198.51.100.1','first':27015,'last':27020}for _ in range(10)]})
 def test_all_exits_switch_and_checkpoint_under_lock(self):
  for id in ('aws','hk','game'):
   h=Harness();self.ready(h);h.api.switch(id);self.assertEqual(json.loads(h.files['/etc/pnw-control/dota-egress/config.json'])['selected'],id);self.assertNotIn('/etc/pnw-control/dota-egress/pending.json',h.files);self.assertIn('/etc/pnw-control/dota-egress/traffic.json',h.files)
 def test_switch_apply_failure_restores_old_exit(self):
  h=Harness();self.ready(h);original=h.run;failed=[False]
  def run(c):
   if c=='nft -f /var/run/pnw-dota-egress/apply.nft' and not failed[0]:failed[0]=True;return '',1
   return original(c)
  h.lua.globals().PY_RUN=run
  with self.assertRaises(Exception):h.api.switch('aws')
  self.assertEqual(json.loads(h.files['/etc/pnw-control/dota-egress/config.json'])['selected'],'game');self.assertNotIn('/etc/pnw-control/dota-egress/pending.json',h.files)
 def test_pending_emergency_and_degraded_refuse_switch(self):
  for path in ('/etc/pnw-control/dota-egress/pending.json','/etc/pnw-control/pending.json','/etc/pnw-control/game-tunnel/pending.json','/etc/pnw-control/emergency','/etc/diversion-dns-c/degraded'):
   h=Harness();self.ready(h);h.files[path]='{}'
   with self.assertRaises(Exception):h.api.switch('aws')
   self.assertEqual(h.commands,[])
 def test_interrupted_switch_recovers_old_exit(self):
  h=Harness();self.ready(h);h.files['/etc/pnw-control/dota-egress/config.json']='{"version":1,"selected":"aws"}'
  h.files['/etc/pnw-control/dota-egress/pending.json']='{"old":{"version":1,"selected":"game"},"new":{"version":1,"selected":"aws"}}'
  h.api.tick(False);self.assertEqual(json.loads(h.files['/etc/pnw-control/dota-egress/config.json'])['selected'],'game');self.assertNotIn('/etc/pnw-control/dota-egress/pending.json',h.files)
 def test_fixed_schema_and_guards(self):
  s=Harness().api.schema();self.assertIn('priority -124',s);self.assertIn('priority -23',s);self.assertIn('priority 10',s);self.assertEqual(s.count('counter name rejected reject'),3);self.assertEqual(s.count('counter name aws_up'),1);self.assertNotIn('output priority',s);self.assertIn('iifname "br-lan"',s)
 def test_transform_preserves_existing_game_branches(self):
  p=ROOT/'deployment/dota-egress/integrate.py';sp=importlib.util.spec_from_file_location('dota_transform',p);m=importlib.util.module_from_spec(sp);sp.loader.exec_module(m)
  base="local allowed={['game-refresh']=true}\n st.pending=st.pending or st.game_tunnel.pending==true\n  st.actions[action]={allowed=reason==nil,reason=reason}\n local ok,result=pcall(function()\n  if action:match('^game%-') then\n   return game.set(action=='game-on')\n end)"
  patched=m.controller(base);self.assertIn("['dota-hk']=true",patched);self.assertIn("return game.set(action=='game-on')",patched);self.assertNotIn("d.pending or not d.consistent",patched)
  with self.assertRaises(ValueError):m.controller(patched)
  e=m.emergency('chain a { meta mark { 1, 2, 7 } counter drop }\nchain b { meta mark { 1, 2, 7 } counter drop }');self.assertEqual(e.count('16, 17, 18'),3);self.assertIn('hook forward priority -129',e)
if __name__=='__main__':unittest.main()
