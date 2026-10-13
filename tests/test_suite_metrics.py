import copy
import sys
import unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import suite_metrics as m


def raw():
    return dict(rate=2, seconds=2, offered=4, sent=4, success=4, unsent=0, errors={},
                samples=[dict(i=i, ms=i+1, late_ms=0) for i in range(4)])

class MetricsTests(unittest.TestCase):
    def test_unsent_is_not_success_even_when_all_responses_work(self):
        r=raw(); r['samples'][0]['error']='inflight_limit'; r.update(sent=3,success=3,unsent=1,errors={'inflight_limit':1})
        result=m.measure(r)
        self.assertTrue(result['response_success']); self.assertFalse(result['strict_qps_pass']); self.assertEqual(result['status'],'fail')
    def test_late_send_separate_from_latency(self):
        r=raw(); r['samples'][0]['error']='scheduler_late_over_10ms'; r.update(sent=3,success=3,unsent=1,errors={'scheduler_late_over_10ms':1})
        self.assertEqual(m.measure(r)['unsent'],1)
    def test_worker_late_dispatch_fails_even_without_dropped_slot(self):
        r=raw();r['samples'][0]['late_ms']=11
        result=m.measure(r)
        self.assertTrue(result['response_success']);self.assertFalse(result['strict_qps_pass'])
        self.assertEqual(result['late_send_count'],1)
    def test_missing_duplicate_nan_and_false_counters_rejected(self):
        for mutate in (lambda r:r['samples'].pop(), lambda r:r['samples'][1].update(i=0), lambda r:r['samples'][0].update(ms=float('nan')), lambda r:r.update(success=99), lambda r:r.update(errors={'timeout':1})):
            r=raw(); mutate(r)
            with self.assertRaises(ValueError):m.measure(r)
    def test_latency_gate_and_percentile_definition(self):
        result=m.measure(raw(),2.0)
        self.assertEqual(result['p99_ms'],3); self.assertFalse(result['latency_pass']);self.assertEqual(result['status'],'fail')
    def test_aux_window_does_not_change_original(self):
        r=raw(); original=copy.deepcopy(r); result=m.window(r,1,2)
        self.assertEqual(result['offered'],2);self.assertTrue(result['auxiliary']);self.assertEqual(r,original)
    def test_medians_balanced_not_pooled(self):
        rows=[]
        for repeat in range(1,4):
            for direction in ('forward','reverse'):
                metrics=m.measure(raw());metrics['p99_ms']=repeat
                rows.append(dict(version='v1',scenario='cold',rate=2,seconds=2,workers=1,repeat=repeat,direction=direction,metrics=metrics,case_pass=True))
        result=m.aggregate(rows)[0]
        self.assertTrue(result['balanced']);self.assertEqual(result['p99_median_ms'],2)
        self.assertFalse(m.aggregate(rows[:-1])[0]['comparable'])
        self.assertTrue(m.aggregate(rows[:-1])[0]['strict_qps_pass'])
        with self.assertRaises(ValueError):m.aggregate(rows+[rows[0]])
    def test_missing_send_timestamp_cannot_pass_strict_rate(self):
        r=raw();r['samples'][0].pop('late_ms')
        with self.assertRaisesRegex(ValueError,'send delay'):m.measure(r)
    def test_failed_set_write_is_not_comparable(self):
        rows=[dict(version='v1',scenario='cold',rate=2,seconds=2,workers=1,repeat=1,direction=d,metrics=m.measure(raw()),case_pass=False) for d in ('forward','reverse')]
        result=m.aggregate(rows,repeats=1)[0]
        self.assertTrue(result['strict_qps_pass']);self.assertFalse(result['comparable'])
    def test_different_workloads_are_not_combined(self):
        row=dict(version='v1',scenario='cold',rate=2,seconds=2,workers=1,repeat=1,direction='forward',metrics=m.measure(raw()),case_pass=True)
        other=dict(row,rate=3)
        self.assertEqual(len(m.aggregate([row,other])),2)

if __name__=='__main__': unittest.main()
