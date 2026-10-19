"""Stats adapter tests: synthetic inputs, no router access or C compilation."""
import copy
import json
import unittest
from test_control import Harness
from pathlib import Path
BASE=Path(__file__).parents[1]
ERRORS='queue_full queue_timeout upstream_failure upstream_timeout nft_failure execution_deadline invalid_response memory send_failure client_disconnected shutdown'.split()
EVENTS='invalid_udp invalid_tcp tcp_read_timeout tcp_write_timeout tcp_limit_rejected tcp_evicted allocation_failure'.split()

def metric(n=10):
    h=dict(samples=n,avg_ms=1 if n else None,max_ms=1 if n else 0,histogram=[0,n,0])
    return dict(completed=n,success=n,noerror=n,nxdomain=0,cache=dict(fresh=n,stale=0,miss=0,disabled_or_unchecked=0),errors=dict.fromkeys(ERRORS,0),rt=copy.deepcopy(h),queue=copy.deepcopy(h),service=copy.deepcopy(h))

def sample():
    groups=[dict(group=g,qtype=q,transport=t,metrics=metric(0)) for g in ['cn','foreign'] for q in ['A','AAAA','other'] for t in ['udp','tcp']]
    groups[0]['metrics']=metric()
    return dict(schema='diversion-dns-stats-v1',pid=999,started_unix=999900,snapshot_unix=1000000,uptime_seconds=100,interval_seconds=60,final=False,received_valid=10,inflight=0,histogram_upper_ms=[.1,1,None],total=metric(),events=dict.fromkeys(EVENTS,0),breakdown=groups,recent_intervals=[dict(start_uptime_seconds=0,duration_seconds=60,metrics=metric())],top50=dict(algorithm='space-saving',capacity=1024,replacements=0,exact=True,domains=[dict(domain='example.test',count_estimate=10,count_lower_bound=10,error_bound=0)]))

class StatsDashboard(unittest.TestCase):
    def setUp(self):
        self.h=Harness()
        self.t=self.h.lua.execute((BASE/'telemetry.lua').read_text())
    def check(self,d,now=1000000):
        r=self.t.validate_stats(self.h.to_lua(d),now)
        return (None,r[1]) if isinstance(r,tuple) else (self.h.to_py(r),None)
    def test_valid_and_recomputed_rates_bounds(self):
        d=sample();d['total']['success_rate']=0;d['total']['rt']['p99_upper_ms']=999
        r,e=self.check(d);self.assertIsNone(e)
        self.assertEqual(r['total']['success_rate_pct'],100)
        self.assertEqual(r['total']['rt']['p99_ms'],1)
        self.assertAlmostEqual(r['intervals'][0]['qps'],10/60)
    def test_final_missing_unsupported_and_stale(self):
        for key,val in [('final',True),('schema','unknown'),('snapshot_unix',999700),('interval_seconds',0)]:
            with self.subTest(key=key):
                d=sample();d[key]=val;self.assertIsNone(self.check(d)[0])
        self.assertIsNone(self.check(None)[0]);self.assertIsNone(self.check(sample(),1000200)[0])
    def test_clock_jump(self):
        d=sample();d['uptime_seconds']=1;self.assertIsNone(self.check(d)[0])
        self.assertIsNone(self.check(sample(),999990)[0])
    def test_interval_config_controls_freshness(self):
        d=sample();d['interval_seconds']=3600
        self.assertIsNotNone(self.check(d,1004000)[0])
        self.assertIsNone(self.check(d,1008000)[0])
    def test_counter_and_group_invariants(self):
        for path in ['success','cache','histogram','inflight','group','duplicate']:
            with self.subTest(path=path):
                d=sample()
                if path=='success':d['total']['success']=11
                if path=='cache':d['total']['cache']['fresh']=9
                if path=='histogram':d['total']['rt']['histogram']=[1,10,0]
                if path=='inflight':d['inflight']=1
                if path=='group':d['breakdown'][0]['metrics']=metric(9)
                if path=='duplicate':d['breakdown'][1]=copy.deepcopy(d['breakdown'][0])
                self.assertIsNone(self.check(d)[0])
    def test_zero_queries_not_zero_percent(self):
        d=sample();d['total']=metric(0);d['received_valid']=0;d['breakdown'][0]['metrics']=metric(0);d['recent_intervals'][0]['metrics']=metric(0);d['top50']['domains']=[]
        r,e=self.check(d);self.assertIsNone(e)
        self.assertNotIn('success_rate_pct',r['total']);self.assertNotIn('avg_ms',r['total']['rt'])
    def test_histogram_overflow(self):
        d=sample();d['total']['rt']['histogram']=[0,0,10];d['total']['rt']['avg_ms']=2;d['total']['rt']['max_ms']=2
        r,e=self.check(d);self.assertIsNone(e);self.assertTrue(r['total']['rt']['p99_overflow']);self.assertEqual(r['total']['rt']['p99_lower_ms'],1)
    def test_negative_nan_and_missing_fields(self):
        for value in [-1,float('nan'),float('inf'),'10',None]:
            d=sample();d['total']['rt']['avg_ms']=value;self.assertIsNone(self.check(d)[0])
    def test_interval_order_and_bounded_history(self):
        for field,val in [('duration_seconds',0),('start_uptime_seconds',80)]:
            d=sample();d['recent_intervals'][0][field]=val;self.assertIsNone(self.check(d)[0])
        d=sample();d['recent_intervals']*=2;self.assertIsNone(self.check(d)[0])
        d=sample();d['recent_intervals']*=61;self.assertIsNone(self.check(d)[0])
    def test_approximate_top_bounds_and_text(self):
        d=sample();d['top50'].update(exact=False,replacements=1);r=d['top50']['domains'][0];r.update(domain='<img src=x onerror=alert(1)>',count_lower_bound=8,error_bound=2)
        out,e=self.check(d);self.assertIsNone(e);self.assertFalse(out['top50']['exact']);self.assertEqual(out['top50']['domains'][0]['count_lower_bound'],8)
        r['count_lower_bound']=9;self.assertIsNone(self.check(d)[0])
    def test_top_limit_duplicates_and_control_characters(self):
        for kind in ['size','duplicate','control','exact']:
            d=sample()
            if kind=='size':d['top50']['domains']*=51
            if kind=='duplicate':d['top50']['domains']*=2
            if kind=='control':d['top50']['domains'][0]['domain']='a\nb'
            if kind=='exact':d['top50']['exact']=False
            self.assertIsNone(self.check(d)[0])
    def test_status_does_not_break_legacy_when_stats_invalid(self):
        self.h.files['/tmp/diversion-dns-stats.json']=json.dumps({'schema':'invalid'})
        r=self.h.to_py(self.t.status());self.assertFalse(r['stats']['available']);self.assertIn('dns',r);self.assertIn('cache',r)
    def test_status_checks_live_process_and_final(self):
        h=self.h;d=sample();h.files['/tmp/diversion-dns-stats.json']=json.dumps(d)
        self.assertFalse(h.to_py(self.t.stats_status())['available'])
        h.files['/proc/999/stat']='999 (diversion-dns-c) S '+' '.join(['0']*18+['500'])
        h.lua.execute("require('nixio.fs').readlink=function() return '/usr/sbin/diversion-dns-c' end")
        self.assertTrue(h.to_py(self.t.stats_status())['available'])
        d['final']=True;h.files['/tmp/diversion-dns-stats.json']=json.dumps(d)
        self.assertFalse(h.to_py(self.t.stats_status())['available'])
    def test_rcode_counts_and_error_total(self):
        d=sample();d["total"]["rcode"]={str(i):0 for i in range(16)};d["total"]["rcode"].update({"0":10,"extended":0})
        self.assertEqual(self.check(d)[0]["total"]["rcode"]["0"],10)
        d["total"]["rcode"]["2"]=1;self.assertIsNone(self.check(d)[0])
        d=sample();d["total"]["errors"]["queue_full"]=1;self.assertIsNone(self.check(d)[0])
    def test_oversized_file_is_unavailable(self):
        self.h.files['/tmp/diversion-dns-stats.json']=' '*1048577
        self.assertFalse(self.h.to_py(self.t.stats_status())['available'])

if __name__=='__main__':unittest.main()
