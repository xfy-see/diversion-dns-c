#!/usr/bin/env python3
"""Auditable fixed-arrival DNS metrics. No host/network side effects."""
import math
import statistics
from collections import Counter, defaultdict

UNSENT = {'scheduler_late_over_10ms', 'inflight_limit'}

def require(value, message):
    if not value:
        raise ValueError(message)


def percentile(values, fraction):
    """Historical harness convention: lower order statistic, floor((N-1)*p)."""
    values = sorted(values)
    return values[int((len(values) - 1) * fraction)] if values else None


def measure(raw, max_p99_ms=None):
    samples = raw['samples']
    rate, seconds = raw['rate'], raw['seconds']
    require(type(rate) is int and rate > 0 and type(seconds) is int and seconds > 0, 'invalid workload')
    require(len(samples) == rate * seconds == raw['offered'], 'missing planned slots')
    require([s['i'] for s in samples] == list(range(len(samples))), 'duplicate/out-of-order/missing sample')
    errors = Counter(s.get('error') for s in samples if s.get('error'))
    unsent = sum(errors[e] for e in UNSENT)
    success = [s for s in samples if not s.get('error')]
    sent = len(samples) - unsent
    require(raw['success'] == len(success) and raw['sent'] == sent and raw['unsent'] == unsent, 'counter/sample mismatch')
    require(dict(errors) == raw.get('errors', {}), 'error histogram mismatch')
    latency = [s['ms'] for s in success]
    require(all(isinstance(v, (float, int)) and math.isfinite(v) and v >= 0 for v in latency), 'invalid latency')
    delays = [s.get('late_ms') for s in samples if s.get('error') not in UNSENT]
    require(all(isinstance(v, (float, int)) and math.isfinite(v) and v >= 0 for v in delays), 'invalid send delay')
    result = dict(offered=len(samples), sent=sent, success=len(success), unsent=unsent,
                  response_errors=sent-len(success), errors=dict(errors),
                  response_success=(sent > 0 and sent == len(success)),
                  strict_qps_pass=(len(samples) == sent == len(success) and all(v <= 10 for v in delays)),
                  late_send_count=sum(v > 10 for v in delays), send_late_max_ms=max(delays) if delays else None,
                  success_qps=len(success)/seconds,
                  p50_ms=percentile(latency, .50), p95_ms=percentile(latency, .95),
                  p99_ms=percentile(latency, .99), max_ms=max(latency) if latency else None,
                  send_late_p99_ms=percentile(delays, .99),
                  percentile_method='floor((N-1)*p); successful responses only')
    result['latency_pass'] = (result['p99_ms'] <= max_p99_ms) if max_p99_ms is not None and latency else None
    result['status'] = 'pass' if result['strict_qps_pass'] and result['latency_pass'] is not False else 'fail'
    return result


def window(raw, start_seconds, end_seconds):
    require(0 <= start_seconds < end_seconds <= raw['seconds'], 'invalid window')
    lo, hi = int(start_seconds*raw['rate']), int(end_seconds*raw['rate'])
    samples = raw['samples'][lo:hi]
    latency = [s['ms'] for s in samples if not s.get('error')]
    return dict(start_seconds=start_seconds, end_seconds=end_seconds, offered=len(samples), success=len(latency),
                p50_ms=percentile(latency, .5), p99_ms=percentile(latency, .99), max_ms=max(latency) if latency else None,
                success_qps=len(latency)/(end_seconds-start_seconds),
                auxiliary=True, replaces_full_run=False)


def aggregate(rows, repeats=3):
    """Never pool samples across runs; require balanced runs for comparison."""
    groups = defaultdict(list)
    for row in rows:
        key = (row['version'], row['scenario'], row['rate'], row['seconds'], row['workers'])
        groups[key].append(row)
    result = []
    for key, values in sorted(groups.items()):
        identity = [(v['repeat'], v['direction']) for v in values]
        require(len(identity) == len(set(identity)), 'duplicate repeat/direction')
        expected = {(i, d) for i in range(1, repeats+1) for d in ('forward', 'reverse')}
        balanced = set(identity) == expected
        summary = dict(zip(('version', 'scenario', 'rate', 'seconds', 'workers'), key))
        summary.update(runs=len(values), balanced=balanced, comparable=balanced and all(v.get('case_pass') is True and v['metrics']['strict_qps_pass'] for v in values),
                       strict_qps_pass=all(v['metrics']['strict_qps_pass'] for v in values),
                       p50_median_ms=statistics.median([v['metrics']['p50_ms'] for v in values if v['metrics']['p50_ms'] is not None]) if any(v['metrics']['p50_ms'] is not None for v in values) else None,
                       p99_median_ms=statistics.median([v['metrics']['p99_ms'] for v in values if v['metrics']['p99_ms'] is not None]) if any(v['metrics']['p99_ms'] is not None for v in values) else None,
                       worst_max_ms=max([v['metrics']['max_ms'] for v in values if v['metrics']['max_ms'] is not None], default=None),
                       unsent=sum(v['metrics']['unsent'] for v in values))
        result.append(summary)
    return result
