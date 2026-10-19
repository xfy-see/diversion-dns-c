#!/usr/bin/env python3
"""Wire the real controller and observation modules together in an in-memory OS."""
import json
import pathlib
import sys
import unittest
BASE=pathlib.Path(__file__).parents[1]
from test_control import Harness, B, R

class Integration(unittest.TestCase):
    def setUp(self):
        self.h=Harness();h=self.h
        h.files['/proc/sys/kernel/random/boot_id']='fixture-boot'
        h.files['/proc/999/stat']='999 (diversion-dns-c) S '+' '.join(['0']*18+['500'])
        h.lua.execute("require('nixio.fs').readlink=function(path) if path=='/proc/999/exe' then return '/usr/sbin/diversion-dns-c' end end")
        h.lua.globals().TELEMETRY=h.lua.execute((BASE/'telemetry.lua').read_text())
        h.lua.globals().QUERY=h.lua.execute((BASE/'query.lua').read_text())
        h.lua.execute("dofile=function(path) if path=='/etc/pnw-control/telemetry.lua' then return TELEMETRY elseif path=='/etc/pnw-control/query.lua' then return QUERY else error('unexpected module') end end")

    def snapshot(self, seq, elapsed, completed, success, fresh):
        h=self.h
        group=dict(fresh_hit=fresh,stale_hit=0,miss_cold=completed-fresh,miss_evicted=0,miss_expired=0,bypass=0)
        raw=dict(version=1,pid=999,started_unix=999990,sequence=seq,updated_unix_ms=h.now*1000,uptime_ms=elapsed,final=False,
                 totals=dict(requests=completed+1,completed=completed,success=success,failed=completed-success,
                 latency_count=completed,latency_sum_us=completed*2000,latest_latency_us=2000,latest_completion_unix_ms=h.now*1000,
                 latency_buckets=[0,completed,0]),latency_bucket_upper_us=[100,2500,None],cache=dict(cn=group,foreign=group))
        h.files['/var/run/diversion-dns-c/metrics.json']=json.dumps(raw)
        return raw

    def populate(self):
        self.snapshot(1,10000,10,10,8);self.h.run_mode('telemetry')
        self.h.now+=20;self.snapshot(2,30000,30,28,24);self.h.run_mode('telemetry')

    def test_real_status_contract_and_duration_hooks(self):
        self.populate();h=self.h
        s=h.to_py(h.api.status());t=s['telemetry']
        self.assertTrue(t['dns']['available']);self.assertEqual(t['dns']['success_rate_pct'],90)
        self.assertEqual(t['dns']['avg_ms'],2);self.assertEqual(t['cache']['groups']['all']['cache_hit_rate_pct'],80)
        h.worker('check')
        self.assertIn(R+'/telemetry-last-health.json',h.files)
        self.assertIn(R+'/telemetry-last-operation.json',h.files)
        self.assertEqual(h.get(R+'/telemetry-last-operation.json')['state'],'success')

    def test_final_snapshot_invalidates_before_next_collection(self):
        self.populate();h=self.h
        path='/var/run/diversion-dns-c/metrics.json';raw=h.get(path);raw['final']=True;h.files[path]=json.dumps(raw)
        self.assertFalse(h.to_py(h.api.status())['telemetry']['dns']['available'])
        h.run_mode('telemetry');self.assertIn('final snapshot',h.get(R+'/telemetry-state.json')['error'])

    def test_process_exit_and_stale_source(self):
        self.populate();h=self.h
        h.files.pop('/proc/999/stat')
        self.assertFalse(h.to_py(h.api.status())['telemetry']['dns']['available'])
        h.files['/proc/999/stat']='999 (diversion-dns-c) S '+' '.join(['0']*18+['500'])
        h.now+=91
        self.assertFalse(h.to_py(h.api.status())['telemetry']['dns']['available'])

    def test_query_mode_rejects_injection_with_real_module(self):
        h=self.h
        self.assertEqual(h.run_mode('query','example.com;id','router'),0)
        result=json.loads(h.outputs[-1]);self.assertFalse(result['ok'])
        self.assertFalse(any('example.com;id' in event for event in h.events))

if __name__=='__main__': unittest.main(verbosity=2)
