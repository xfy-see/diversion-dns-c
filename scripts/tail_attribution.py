#!/usr/bin/env python3
"""Join diagload client samples with a DIVERSION_TRACE server trace and attribute latency.

Pure Python, no host side effects. Times are CLOCK_MONOTONIC nanoseconds on both sides, so the
client (benchmarks/suite/diagload.go) and the server (DIVERSION_TRACE=<file>) must run on the
same host/kernel clock. Percentiles use the historical floor((N-1)*p) convention of
suite_metrics.percentile so numbers are comparable with existing reports.
"""
import argparse
import json
import sys
from collections import Counter, defaultdict

TRACE_FIELDS = ['kind', 'lane', 'flags', 'id', 'qtype', 'qname', 'resends', 'attempts',
                'recv', 'dispatched', 'enqueue', 'pickup', 'engine0', 'up_send', 'up_recv',
                'nft0', 'nft_io', 'nft1', 'engine1', 'reply']
FLAGS = {'hit_fresh': 1 << 0, 'hit_stale': 1 << 1, 'refresh_start': 1 << 2, 'up_tcp': 1 << 3,
         'up_tc_fallback': 1 << 4, 'nft_fast': 1 << 5, 'nft_cli': 1 << 6, 'nft_leader': 1 << 7,
         'follower': 1 << 8, 'error': 1 << 9, 'stale_drop': 1 << 10, 'loop_reply': 1 << 11,
         'tcp': 1 << 12, 'refresh_job': 1 << 13, 'nft_skip': 1 << 14}
LANES = {0: 'cached', 1: 'cn', 2: 'foreign', 3: 'reply'}
# Server stages: (name, start field, end field). Missing (0) endpoints skip the stage.
SERVER_STAGES = [('srv_dispatch', 'recv', 'dispatched'), ('srv_queue_wait', 'enqueue', 'pickup'),
                 ('srv_engine', 'engine0', 'engine1'), ('upstream', 'up_send', 'up_recv'),
                 ('nft_total', 'nft0', 'nft1'), ('nft_wait', 'nft0', 'nft_io'), ('nft_io', 'nft_io', 'nft1'),
                 ('srv_reply_tail', 'engine1', 'reply'), ('srv_total', 'recv', 'reply')]
# Components that partition client end-to-end time for dominant-cause attribution.
PARTS = ['client_late', 'client_connect', 'net_and_kernel', 'srv_dispatch', 'srv_queue_wait',
         'upstream', 'nft_total', 'srv_other']


def percentile(values, fraction):
    values = sorted(values)
    return values[int((len(values) - 1) * fraction)] if values else None


def stats(values_ns):
    ms = [v / 1e6 for v in values_ns]
    return dict(count=len(ms), p50_ms=percentile(ms, .5), p99_ms=percentile(ms, .99),
                p999_ms=percentile(ms, .999), max_ms=max(ms) if ms else None)


def parse_trace(lines):
    out = []
    for line in lines:
        line = line.rstrip('\n')
        if not line or line.startswith('#'):
            continue
        parts = line.split('\t')
        if len(parts) != len(TRACE_FIELDS):
            raise ValueError('bad trace line: %r' % line[:120])
        rec = dict(zip(TRACE_FIELDS, parts))
        for k in TRACE_FIELDS:
            if k not in ('kind', 'qname'):
                rec[k] = int(rec[k])
        rec['qname'] = rec['qname'].lower().rstrip('.')
        out.append(rec)
    return out


def flag_names(flags):
    return [k for k, v in FLAGS.items() if flags & v]


def join(samples, trace):
    """Match each sent client sample to the server record with the same (id, qname, qtype)
    whose recv lies in [send, recv] of the client; nearest to send wins. Each trace record is
    used once."""
    index = defaultdict(list)
    for t in trace:
        if t['kind'] == 'Q':
            index[(t['id'], t['qname'], t['qtype'])].append(t)
    used = set()
    pairs = []
    for s in samples:
        if s.get('unsent') or not s.get('send_ns'):
            pairs.append((s, None))
            continue
        end = s.get('recv_ns') or (s['send_ns'] + 10 * 10**9)
        best = None
        for t in index.get((s['id'], s['name'].lower().rstrip('.'), s['type']), ()):
            if id(t) in used or not (s['send_ns'] - 10**6 <= t['recv'] <= end):
                continue
            if best is None or abs(t['recv'] - s['send_ns']) < abs(best['recv'] - s['send_ns']):
                best = t
        if best is not None:
            used.add(id(best))
        pairs.append((s, best))
    return pairs


def components(s, t):
    """Per-request durations in ns. Client parts always present for answered samples."""
    c = {}
    c['client_late'] = max(0, s['pickup_ns'] - s['slot_ns'])
    c['client_connect'] = (s['connect1_ns'] - s['connect0_ns']) if s.get('connect1_ns') else 0
    if s.get('recv_ns'):
        c['client_rtt'] = s['recv_ns'] - s['send_ns']
        c['e2e_from_slot'] = s['recv_ns'] - s['slot_ns']
        c['loadgo_equiv'] = s['recv_ns'] - s['pickup_ns']  # what load.go reports as ms
    if t is None:
        return c
    for name, a, b in SERVER_STAGES:
        if t[a] and t[b] and t[b] >= t[a]:
            c[name] = t[b] - t[a]
    if 'client_rtt' in c and 'srv_total' in c:
        c['net_and_kernel'] = max(0, c['client_rtt'] - c['srv_total'])
        known = sum(c.get(k, 0) for k in ('srv_dispatch', 'srv_queue_wait', 'upstream', 'nft_total'))
        c['srv_other'] = max(0, c['srv_total'] - known)
    return c


def analyze(client, trace, bin_ms=100, tail_fraction=.99):
    samples = client['samples']
    pairs = join(samples, trace)
    tcp = client.get('net') == 'tcp'
    unsent = Counter(s['unsent'] for s in samples if s.get('unsent'))
    errors = Counter(s['error'] for s in samples if s.get('error'))
    rows = []
    for s, t in pairs:
        if s.get('unsent'):
            continue
        rows.append((s, t, components(s, t)))
    answered = [r for r in rows if 'client_rtt' in r[2] and not r[0].get('error')]

    def block(sel):
        keys = ['client_late', 'client_connect', 'client_rtt', 'loadgo_equiv', 'e2e_from_slot', 'net_and_kernel',
                'srv_other'] + [n for n, _, _ in SERVER_STAGES]
        out = {}
        for k in keys:
            vals = [r[2][k] for r in sel if k in r[2]]
            if vals:
                out[k] = stats(vals)
        return out

    result = dict(schema='diversion-tail-attribution-v1', net=client.get('net'), rate=client.get('rate'),
                  seconds=client.get('seconds'), workers=client.get('workers'), predial=client.get('predial'),
                  planned=len(samples), unsent=dict(unsent), errors=dict(errors), answered=len(answered),
                  matched=sum(1 for r in answered if r[1] is not None),
                  server_records=sum(1 for t in trace if t['kind'] == 'Q'),
                  refresh_records=[dict(qname=t['qname'], qtype=t['qtype'], upstream_ms=(t['up_recv'] - t['up_send']) / 1e6 if t['up_send'] and t['up_recv'] else None,
                                        nft_ms=(t['nft1'] - t['nft0']) / 1e6 if t['nft0'] and t['nft1'] else None,
                                        total_ms=(t['engine1'] - t['engine0']) / 1e6, flags=flag_names(t['flags']))
                                   for t in trace if t['kind'] == 'R'])
    result['all'] = block(answered)
    if tcp:
        # Auxiliary TCP view: drop samples that paid connection establishment.
        result['tcp_excluding_connect'] = block([r for r in answered if not r[0].get('conn_first')])
    by_class = defaultdict(list)
    for r in answered:
        t = r[1]
        if t is None:
            cls = 'unmatched'
        else:
            f = t['flags']
            cls = 'fresh_hit' if f & FLAGS['hit_fresh'] else 'stale_hit' if f & FLAGS['hit_stale'] else \
                'follower' if f & FLAGS['follower'] else 'miss'
            cls += '/' + LANES.get(t['lane'], str(t['lane']))
        by_class[cls].append(r)
    result['by_class'] = {k: dict(count=len(v), stages=block(v)) for k, v in sorted(by_class.items())}
    # Dominant cause of the slow tail (e2e_from_slot >= tail percentile).
    e2e = [r[2]['e2e_from_slot'] for r in answered]
    threshold = percentile(e2e, tail_fraction) if e2e else None
    dominant = Counter()
    share = defaultdict(int)
    tail = [r for r in answered if threshold is not None and r[2]['e2e_from_slot'] >= threshold]
    for r in tail:
        parts = {k: r[2].get(k, 0) for k in PARTS}
        if r[1] is None:
            parts['unmatched_rtt'] = r[2]['client_rtt']
        k = max(parts, key=parts.get)
        dominant[k] += 1
        for k2, v in parts.items():
            share[k2] += v
    total = sum(share.values()) or 1
    result['tail'] = dict(fraction=tail_fraction, threshold_ms=threshold / 1e6 if threshold else None, count=len(tail),
                          dominant=dict(dominant.most_common()),
                          time_share_percent={k: round(100 * v / total, 2) for k, v in sorted(share.items(), key=lambda x: -x[1])})
    # Time series by scheduled slot for spike correlation.
    start = client.get('start_ns') or (min(s['slot_ns'] for s in samples) if samples else 0)
    bins = defaultdict(list)
    for r in rows:
        bins[(r[0]['slot_ns'] - start) // (bin_ms * 10**6)].append(r)
    unsent_bins = Counter((s['slot_ns'] - start) // (bin_ms * 10**6) for s in samples if s.get('unsent'))
    series = []
    for b in sorted(set(bins) | set(unsent_bins)):
        rs = bins.get(b, [])
        ok = [r for r in rs if 'client_rtt' in r[2] and not r[0].get('error')]

        def mx(k):
            vals = [r[2][k] for r in ok if k in r[2]]
            return round(max(vals) / 1e6, 3) if vals else None
        series.append(dict(t_ms=b * bin_ms, sent=len(rs), answered=len(ok), unsent=unsent_bins.get(b, 0),
                           errors=sum(1 for r in rs if r[0].get('error')),
                           e2e_p99_ms=round(percentile([r[2]['e2e_from_slot'] for r in ok], .99) / 1e6, 3) if ok else None,
                           e2e_max_ms=mx('e2e_from_slot'), client_late_max_ms=mx('client_late'),
                           queue_max_ms=mx('srv_queue_wait'), upstream_max_ms=mx('upstream'), nft_max_ms=mx('nft_total'),
                           net_max_ms=mx('net_and_kernel'),
                           stale_hits=sum(1 for r in ok if r[1] and r[1]['flags'] & FLAGS['hit_stale']),
                           refresh_started=sum(1 for r in ok if r[1] and r[1]['flags'] & FLAGS['refresh_start']),
                           misses=sum(1 for r in ok if r[1] and not r[1]['flags'] & (FLAGS['hit_fresh'] | FLAGS['hit_stale']))))
    result['series_bin_ms'] = bin_ms
    result['series'] = series
    spikes = sorted((x for x in series if x['e2e_max_ms'] is not None), key=lambda x: -x['e2e_max_ms'])[:10]
    result['top_spike_bins'] = spikes
    return result


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--client', required=True)
    ap.add_argument('--trace', required=True)
    ap.add_argument('--output', required=True)
    ap.add_argument('--bin-ms', type=int, default=100)
    args = ap.parse_args(argv)
    with open(args.client) as f:
        client = json.load(f)
    with open(args.trace) as f:
        trace = parse_trace(f)
    result = analyze(client, trace, args.bin_ms)
    with open(args.output, 'w') as f:
        json.dump(result, f, indent=1)
        f.write('\n')
    summary = {k: result[k] for k in ('planned', 'answered', 'matched', 'unsent', 'errors')}
    summary['tail'] = result['tail']
    print(json.dumps(summary))
    return 0


if __name__ == '__main__':
    sys.exit(main())
