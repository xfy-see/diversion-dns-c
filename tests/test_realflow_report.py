import base64
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import struct
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / 'scripts' / 'realflow_report.py'
spec = importlib.util.spec_from_file_location('realflow_report', MODULE)
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
NS = 10**9
START = 1700000000 * NS
MONO = 800000 * NS


def wire(name, qtype=1, qid=19):
    out = struct.pack('!HHHHHH', qid, 256, 1, 0, 0, 0)
    out += b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
    return base64.b64encode(out + struct.pack('!HH', qtype, 1)).decode()


def trace(name, qtype=1, qid=19, flags=0, kind='Q', stamp=MONO + NS, **kwargs):
    row = dict(kind=kind, lane=2, flags=flags, id=qid, qtype=qtype, qname=name,
               resends=0, attempts=1, recv=stamp, engine0=stamp + 20,
               engine1=stamp + 1000000, reply=stamp + 1100000)
    row.update(kwargs)
    return '\t'.join(str(row.get(k, 0)) for k in r.TRACE_FIELDS) + '\n'


def jsonl(path, rows):
    path.write_text(''.join(json.dumps(x) + '\n' for x in rows))


class TestReport(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = b'k' * 32
        (self.root / 'hmac.key').write_bytes(self.key)
        (self.root / 'metadata.json').write_text(json.dumps(dict(start_unix_ns=START,
                start_mono_ns=MONO, duration_seconds=86400, probe_hosts={'probe.secret.test': True})))
        self.rules = self.root / 'rules.txt'
        self.rules.write_text('domain:cn.test\nfull:exact.test\nkeyword:inside\n')

    def tearDown(self):
        self.temp.cleanup()

    def report(self):
        return r.build_report(self.root, [self.rules])

    def pair(self, sequence=1, delta=NS, name='private.foreign.test', a_success=True,
             b_success=True, a_ms=45, b_ms=2, disposition='sent', **kwargs):
        row = dict(type='dns_mirror', sequence=sequence, capture_sequence=sequence,
                   arrival_unix_ns=START + delta, qtype=1, qclass=1,
                   query_transport='udp', disposition=disposition,
                   question_hmac=r.digest_name(self.key, name, 1, 1), probe_host=False)
        for arm, good, duration in (('a', a_success, a_ms), ('b', b_success, b_ms)):
            row[arm] = dict(success=good, duration_ms=duration, rcode=0 if good else -1,
                            error='' if good else 'read udp: timeout private.foreign.test',
                            arrival_to_send_ms=0.25, sent_mono_ns=MONO + delta - 1000, wire_sent=True, transport_response=good,
                            addresses=[dict(ip='203.0.113.1', family=4)], min_answer_ttl=30)
        row.update(kwargs)
        return row

    def capture(self, sequence=1, name='private.foreign.test', delta=NS):
        return dict(type='dns_query', sequence=sequence, ts_unix_ns=START + delta,
                    receive_mono_ns=MONO + delta + 100,
                    name=name, qtype=1, wire_b64=wire(name))

    def test_quantiles_exact_success_only_convention(self):
        out = r.quantiles([1, 2, 100, float('nan')])
        self.assertEqual(out['sample_count'], 3)
        self.assertEqual(out['p99_ms'], 2)
        self.assertFalse(out['p99_sample_sufficient'])
        self.assertTrue(r.quantiles(list(range(1000)))['p99_sample_sufficient'])
        self.assertEqual(r.quantiles([])['max_ms'], None)

    def test_rules_do_not_guess_regex_and_label_boundary(self):
        rules = r.Rules([self.rules])
        for name in ('cn.test', 'A.CN.TEST.', 'exact.test', 'xinsidey.test'):
            self.assertEqual(rules.classify(name), 'cn')
        self.assertEqual(rules.classify('notcn.test'), 'foreign')
        self.assertEqual(rules.classify('child.exact.test'), 'foreign')
        self.rules.write_text('regexp:^foo.*\nfull:exact.test\n')
        rules = r.Rules([self.rules])
        self.assertEqual(rules.classify('foo.test'), 'unknown')
        self.assertEqual(rules.classify('exact.test'), 'cn')
        self.assertEqual(r.Rules().classify('anything'), 'unknown')

    def test_dns_parse_and_hmac_do_not_expose_name(self):
        self.assertEqual(r.parse_question(wire('Mixed.Case.test', 28, 42)),
                         ('mixed.case.test', 28, 1, 42))
        self.assertEqual(r.digest_name(self.key, 'Mixed.Case.test.', 28),
                         r.digest_name(self.key, 'mixed.case.test', 28))
        self.assertNotIn('mixed', r.digest_name(self.key, 'mixed.case.test', 28))
        with self.assertRaises(ValueError):
            r.parse_question(base64.b64encode(b'\0').decode())

    def test_cache_stats_handles_reset_not_negative_delta(self):
        def line(value, group='foreign'):
            return 'cache stats %s: entries=5 bytes=100 ' % group + ' '.join(
                '%s=%d' % (key, value) for key in r.CACHE_COUNTERS)
        stats = r.parse_cache_stats([line(10), line(15), line(2), line(3), 'cache stats cn: entries=2'])
        foreign = stats['groups']['foreign']
        self.assertEqual(foreign['totals']['fresh_hit'], 18)
        self.assertEqual(foreign['counter_resets'], 1)
        self.assertFalse(stats['time_windows']['available'])
        self.assertEqual(stats['invalid_stats_lines'], 1)
        self.assertFalse(stats['groups']['cn']['available'])

    def test_complete_bad_line_and_partial_tail_are_separate(self):
        p = self.root / 'partial.jsonl'
        p.write_bytes(b'{"ok":1}\nnot-json\n{"still":')
        audit = {}
        self.assertEqual(list(r.read_jsonl(p, audit)), [{'ok': 1}])
        self.assertEqual(audit['invalid_complete_lines'], 1)
        self.assertEqual(audit['partial_tail_lines'], 1)
        self.assertEqual(p.read_bytes(), b'{"ok":1}\nnot-json\n{"still":')

    def test_period_boundaries_and_probe_exclusion(self):
        rows = [self.pair(1), self.pair(2, 3600 * NS), self.pair(3, 5 * NS,
                probe_host=True, name='probe.secret.test'),
                self.pair(4, 6 * NS, disposition='unsent', reason='queue_full')]
        jsonl(self.root / 'dns-results.jsonl', rows)
        jsonl(self.root / 'capture-private.jsonl', [self.capture(1), self.capture(2, delta=3600 * NS),
               self.capture(3, name='probe.secret.test'), self.capture(4)])
        result = self.report()
        self.assertEqual(result['balance']['main_flow_arrivals'], 3)
        self.assertEqual(result['balance']['main_flow_unsent_pairs'], 1)
        self.assertTrue(result['balance']['main_flow_arrivals_equal_dispatched_plus_unsent'])
        self.assertEqual(result['periods']['first_hour']['arms']['a']['attempted'], 1)
        self.assertEqual(result['periods']['stable_after_first_hour']['arms']['a']['attempted'], 1)
        self.assertIn('window_004', result['periods'])
        self.assertEqual(result['excluded']['probe_host_pairs'], 1)

    def test_failures_and_timeouts_do_not_disappear_in_latency(self):
        jsonl(self.root / 'dns-results.jsonl', [self.pair(1), self.pair(2, a_success=False, a_ms=2000)])
        result = self.report()
        arm = result['periods']['all']['arms']['a']
        self.assertEqual(arm['failed'], 1)
        self.assertEqual(arm['timeouts'], 1)
        self.assertEqual(arm['success_latency']['sample_count'], 1)
        self.assertEqual(arm['success_latency']['max_ms'], 45)
        self.assertEqual(arm['all_latency']['max_ms'], 2000)
        pair = result['periods']['all']['paired']
        self.assertEqual(pair['counts']['failure/success'], 1)
        self.assertEqual(pair['b_minus_a_success_latency_ms']['mean_ms'], -43)

    def test_trace_flags_not_latency_determine_hits_and_background_cost(self):
        jsonl(self.root / 'capture-private.jsonl', [self.capture()])
        jsonl(self.root / 'dns-results.jsonl', [self.pair(a_ms=45)])
        (self.root / 'a.trace.tsv').write_text('# header\n' + trace('private.foreign.test', flags=r.HIT_FRESH)
                + trace('private.foreign.test', kind='R', flags=1 << 13,
                        stamp=MONO + 2 * NS, resends=2, attempts=1)
                + trace('probe.secret.test', stamp=MONO + 3 * NS)
                + trace('old.secret.test', stamp=MONO - NS))
        result = self.report()['trace']['a']
        self.assertEqual(result['classes_by_region']['foreign']['fresh_hit'], 1)
        self.assertEqual(result['counts']['runner_trace_joined'], 1)
        self.assertEqual(result['counts']['probe_records_excluded'], 1)
        self.assertEqual(result['counts']['before_start_records_excluded'], 1)
        self.assertEqual(result['upstream_transactions']['background_refresh']['udp_resends'], 2)
        self.assertEqual(result['joined_success_latency_by_cache_class']['fresh_hit/foreign']['mean_ms'], 45)
        self.assertFalse(result['fine_miss_reasons']['available'])

    def test_no_exact_trace_windows_without_exact_monotonic_mapping(self):
        meta = json.loads((self.root / 'metadata.json').read_text())
        del meta['start_mono_ns']
        (self.root / 'metadata.json').write_text(json.dumps(meta))
        jsonl(self.root / 'capture-private.jsonl', [self.capture()])
        (self.root / 'a.trace.tsv').write_text(trace('private.foreign.test', flags=r.HIT_FRESH))
        result = self.report()
        self.assertFalse(result['clock_alignment']['exact_start_mapping'])
        self.assertFalse(result['trace']['a']['exact_time_window_classes']['available'])
        self.assertEqual(result['trace']['a']['counts']['foreground_query'], 1)

    def test_duplicate_capture_and_result_and_sequence_gaps_are_reported(self):
        jsonl(self.root / 'capture-private.jsonl', [self.capture(1), self.capture(1), self.capture(3),
               dict(type='capture_stats', final=True, kernel_packets=10, kernel_drops=2,
                    counters={'events_queue_full': 1})])
        jsonl(self.root / 'dns-results.jsonl', [self.pair(1), self.pair(1)])
        balance = self.report()['balance']
        self.assertEqual(balance['duplicate_capture_sequences'], 1)
        self.assertEqual(balance['capture_sequence_gaps'], 1)
        self.assertEqual(balance['duplicate_runner_results'], 1)
        self.assertEqual(balance['capture_minus_runner_records'], 1)
        self.assertEqual(balance['capture_kernel_totals']['kernel_drops'], 2)

    def test_privacy_aggregate_no_names_addresses_wire_or_error(self):
        jsonl(self.root / 'capture-private.jsonl', [self.capture()])
        jsonl(self.root / 'dns-results.jsonl', [self.pair(a_success=False,
                disposition='unsent', reason='error private.foreign.test')])
        jsonl(self.root / 'https-results.jsonl', [dict(type='https_probe', site=dict(
               host='business.secret.test', path='/secret-token'), arm='a', address_family=4,
               connected_ip='203.0.113.1', error='private error', success=False, coverage='attempted')])
        result = self.report()
        text = json.dumps(result) + r.markdown(result)
        for private in ('private.foreign.test', 'business.secret.test', '/secret-token', '203.0.113.1',
                        'private error', 'wire_b64', 'kkkkkkkk'):
            self.assertNotIn(private, text)
        self.assertFalse(result['https']['paired']['available'])

    def test_resources_numeric_summaries_and_no_raw_id(self):
        jsonl(self.root / 'resources.jsonl', [dict(ts_unix_s=START // NS + 1, boot_id='sensitive-boot-id',
                mem_available_kib=1000, a=dict(rss_kib=100, fd_count=20), command='private.host.test'),
                dict(ts_unix_s=START // NS + 2, boot_id='sensitive-boot-id', mem_available_kib=900,
                     a=dict(rss_kib=120, fd_count=21))])
        result = self.report()['resources']
        self.assertEqual(result['sample_count'], 2)
        self.assertEqual(result['boot_id_count'], 1)
        self.assertEqual(result['numeric_metrics']['a.rss_kib']['max'], 120)
        self.assertNotIn('sensitive-boot-id', json.dumps(result))
        self.assertFalse(result['queue_depth']['available'])

    def test_cli_new_private_output_never_overwrites_inputs(self):
        jsonl(self.root / 'dns-results.jsonl', [self.pair()])
        output = self.root / 'snapshot'
        env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        command = [sys.executable, str(MODULE), '--input', str(self.root), '--output', str(output),
                   '--rules', str(self.rules)]
        success = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual((output.stat().st_mode & 0o777), 0o700)
        self.assertEqual(((output / 'report.json').stat().st_mode & 0o777), 0o600)
        failed = subprocess.run(command, capture_output=True, text=True, env=env)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(len(list(output.iterdir())), 2)

    def test_exact_https_cycle_pairing_and_success_delta(self):
        rows = []
        for arm, duration in (('a', 100), ('b', 60)):
            rows.append(dict(type='https_probe', cycle_id=1,
                    site=dict(host='business.secret.test', path='/'), arm=arm,
                    started_unix_ns=START + NS, address_family=4, success=True,
                    certificate_verified=True, tls_handshake_success=True,
                    connected_ip='203.0.113.1', dns_and_http_total_ms=duration,
                    dns=dict(duration_ms=duration / 2)))
        jsonl(self.root / 'https-results.jsonl', rows)
        summary = self.report()['https']
        self.assertTrue(summary['paired']['available'])
        pair = summary['paired']['groups'][0]
        self.assertEqual(pair['counts']['success/success'], 1)
        self.assertEqual(pair['b_minus_a_success_metrics']['dns_and_http_total_ms']['mean_ms'], -40)
        self.assertEqual({x['period'] for x in summary['groups']}, {'all', 'first_hour', 'window_000'})
        self.assertNotIn('business.secret.test', json.dumps(summary))

    def test_capture_stderr_final_receipt_overrides_earlier_stdout(self):
        jsonl(self.root / 'capture-private.jsonl', [dict(type='capture_stats', final=False,
                                                       kernel_packets=1, kernel_drops=0)])
        receipt = dict(type='capture_stats', final=True, kernel_packets=9, kernel_drops=2,
                       counters={'stdout_drain_timeout': 1})
        (self.root / 'capture.stderr.log').write_text('capture_final ' + json.dumps(receipt) + '\n')
        summary = self.report()['balance']['capture_kernel_totals']
        self.assertEqual(summary['kernel_packets'], 9)
        self.assertEqual(summary['kernel_drops'], 2)
        self.assertTrue(summary['final_receipt'])

    def test_actual_wire_send_not_confused_with_attempted_or_dispatch(self):
        pair = self.pair()
        pair['a']['wire_sent'] = False
        pair['a']['success'] = False
        pair['a']['error'] = 'socket creation failed'
        pair['a']['transport_response'] = False
        jsonl(self.root / 'dns-results.jsonl', [pair])
        result = self.report()
        self.assertEqual(result['balance']['main_flow_dispatched_pairs'], 1)
        self.assertEqual(result['balance']['main_flow_both_wire_sent_pairs'], 0)
        self.assertEqual(result['balance']['main_flow_partial_wire_sent_pairs'], 1)
        self.assertEqual(result['periods']['all']['arms']['a']['attempted'], 1)
        self.assertEqual(result['periods']['all']['arms']['a']['wire_sent'], 0)

    def test_past_deadline_and_probe_not_used_to_extend_main_flow(self):
        jsonl(self.root / 'dns-results.jsonl', [self.pair(), self.pair(2, 86400 * NS),
                                                self.pair(3, 86399 * NS, probe_host=True)])
        result = self.report()
        self.assertEqual(result['observed_main_flow_span_seconds'], 1)
        self.assertEqual(result['excluded']['after_deadline_pairs'], 1)
        self.assertEqual(result['balance']['main_flow_arrivals'], 1)

    def test_bad_trace_and_negative_timestamps_are_rejected(self):
        with self.assertRaises(ValueError):
            r.parse_trace_line('Q\t1\t2')
        with self.assertRaises(ValueError):
            r.parse_trace_line(trace('private.test', stamp=-10))


if __name__ == '__main__':
    unittest.main()
