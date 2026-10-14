import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))
import tail_attribution as ta  # noqa: E402

MS = 10**6


def trace_line(kind='Q', lane=1, flags=0, id_=1, qtype=1, qname='q0.cn.test', resends=0, attempts=1, **t):
    times = [t.get(k, 0) for k in ta.TRACE_FIELDS[8:]]
    return '\t'.join(str(x) for x in [kind, lane, flags, id_, qtype, qname, resends, attempts] + times)


class TailAttributionTest(unittest.TestCase):
    def test_parse_and_join_by_identity_and_time(self):
        lines = ['#diversion-trace v1 ...',
                 trace_line(id_=1, recv=100 * MS, dispatched=100 * MS + 10, enqueue=100 * MS + 20, pickup=105 * MS,
                            engine0=105 * MS, up_send=105 * MS, up_recv=108 * MS, nft0=108 * MS, nft_io=109 * MS,
                            nft1=110 * MS, engine1=110 * MS, reply=110 * MS + 50),
                 # same identity, wrong time window: must not match
                 trace_line(id_=1, recv=900 * MS, reply=901 * MS)]
        trace = ta.parse_trace(lines)
        self.assertEqual(len(trace), 2)
        client = dict(net='udp', rate=1, seconds=1, workers=1, start_ns=90 * MS, samples=[
            dict(i=0, id=1, name='q0.cn.test', type=1, worker=0, slot_ns=95 * MS, pickup_ns=99 * MS,
                 send_ns=99 * MS + 500, recv_ns=111 * MS)])
        r = ta.analyze(client, trace)
        self.assertEqual(r['matched'], 1)
        a = r['all']
        self.assertAlmostEqual(a['client_late']['max_ms'], 4.0)
        self.assertAlmostEqual(a['srv_queue_wait']['max_ms'], 5.0, places=3)
        self.assertAlmostEqual(a['upstream']['max_ms'], 3.0)
        self.assertAlmostEqual(a['nft_wait']['max_ms'], 1.0)
        self.assertEqual(r['tail']['dominant'], {'srv_queue_wait': 1})
        self.assertEqual(list(r['by_class']), ['miss/cn'])

    def test_unsent_and_tcp_connect_exclusion(self):
        samples = [dict(i=0, id=1, name='a', type=1, worker=0, slot_ns=0, pickup_ns=0, connect0_ns=0,
                        connect1_ns=8 * MS, send_ns=8 * MS, recv_ns=9 * MS, conn_first=True),
                   dict(i=1, id=2, name='a', type=1, worker=0, slot_ns=10 * MS, pickup_ns=10 * MS,
                        send_ns=10 * MS, recv_ns=11 * MS),
                   dict(i=2, slot_ns=20 * MS, pickup_ns=40 * MS, unsent='scheduler_late')]
        r = ta.analyze(dict(net='tcp', start_ns=0, samples=samples), [])
        self.assertEqual(r['unsent'], {'scheduler_late': 1})
        self.assertEqual(r['all']['e2e_from_slot']['count'], 2)
        self.assertEqual(r['tcp_excluding_connect']['e2e_from_slot']['count'], 1)
        self.assertAlmostEqual(r['tcp_excluding_connect']['e2e_from_slot']['max_ms'], 1.0)
        self.assertEqual(r['all']['client_connect']['max_ms'], 8.0)
        self.assertEqual(r['series'][-1]['unsent'], 1)

    def test_percentile_convention_matches_suite_metrics(self):
        import suite_metrics
        vals = list(range(1, 1001))
        for p in (.5, .99, .999, 1):
            self.assertEqual(ta.percentile(vals, p), suite_metrics.percentile(vals, p))

    def test_refresh_records_reported(self):
        trace = ta.parse_trace([trace_line(kind='R', flags=ta.FLAGS['refresh_job'], engine0=1 * MS, up_send=1 * MS,
                                           up_recv=3 * MS, engine1=4 * MS)])
        r = ta.analyze(dict(net='udp', start_ns=0, samples=[]), trace)
        self.assertEqual(r['refresh_records'][0]['upstream_ms'], 2.0)
        self.assertEqual(r['refresh_records'][0]['total_ms'], 3.0)

    def test_bad_line_rejected(self):
        with self.assertRaises(ValueError):
            ta.parse_trace(['Q\t1\t2'])


if __name__ == '__main__':
    unittest.main()
