import sys,json,copy,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_control import Harness
S=Path(__file__).resolve().parents[1]/'device'
SHARED=S.parent
class Window(unittest.TestCase):
 def setUp(self):
  self.h=Harness();self.raw=json.loads((Path(__file__).parent/'fixtures/device-stats.json').read_text());self.h.now=self.raw['snapshot_unix'];self.t=self.h.lua.execute((SHARED/'telemetry.lua').read_text());self.t.process_identity=self.h.lua.eval("function()return '42'end")
  self.h.lua.globals().TEST_T=self.t;self.h.lua.execute('dofile=function()return TEST_T end');self.w=self.h.lua.execute((S/'window.lua').read_text());self.null=self.h.lua.eval('newproxy(true)')
 def convert(self,raw):
  v=self.h.to_lua(raw);v['histogram_upper_ms'][len(raw['histogram_upper_ms'])]=self.null
  out=self.w.convert(v,'boot');return out if isinstance(out,tuple) else (out,None)
 def test_real_snapshot_conversion_and_cache_denominator(self):
  p,e=self.convert(self.raw);self.assertIsNone(e);self.assertEqual(p['totals']['completed'],self.raw['total']['completed']);self.assertEqual(p['cache']['cn']['fresh_hit'],self.raw['cache_engine']['cn']['fresh_hit']);self.assertTrue(p['identity'].endswith(':42'))
 def test_invalid_engine_counter_rejected(self):
  r=copy.deepcopy(self.raw);r['cache_engine']['cn']['fresh_hit']=-1;p,e=self.convert(r);self.assertIsNone(p)
 def test_stale_final_and_bad_histogram_rejected(self):
  for field,val in [('snapshot_unix',0),('final',True)]:
   r=copy.deepcopy(self.raw);r[field]=val;p,e=self.convert(r);self.assertIsNone(p)
  r=copy.deepcopy(self.raw);r['total']['rt']['histogram'][0]+=1;p,e=self.convert(r);self.assertIsNone(p)
 def test_process_exit_rejected(self):
  self.t.process_identity=self.h.lua.eval("function()return nil,'exited'end");p,e=self.convert(self.raw);self.assertIsNone(p);self.assertEqual(e,'exited')
 def test_restarted_process_cannot_be_differenced(self):
  a,_=self.convert(self.raw);r=copy.deepcopy(self.raw);r['pid']+=1;r['uptime_seconds']+=20;r['snapshot_unix']+=20;self.h.now+=20;b,_=self.convert(r);out=self.t.delta(a,b);self.assertIsNone(out[0])
 def test_zero_completions_no_fabricated_success(self):
  a,_=self.convert(self.raw);r=copy.deepcopy(self.raw);r['uptime_seconds']+=20;r['snapshot_unix']+=20;self.h.now+=20;b,_=self.convert(r);v=self.t.delta(a,b);self.assertIsNone(v['dns']['success_rate_pct']);self.assertEqual(v['dns']['completed'],0)
if __name__=='__main__':unittest.main()
