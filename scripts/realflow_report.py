#!/usr/bin/env python3
"""Private, offline snapshot reporting for realflow_capture/realflow_runner.

Never changes input files or copies DNS names, addresses, wire data, error text or
HMAC keys into a report. The output directory must be new. Quantiles are exact
floor((N-1)*p) over successful answers; errors remain separate. Input files may
still be growing: an unfinished final line is counted and ignored.
"""
import argparse
import base64
import collections
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import statistics
import struct
import time

TRACE_FIELDS = ('kind lane flags id qtype qname resends attempts recv dispatched enqueue '
                'pickup engine0 up_send up_recv nft0 nft_io nft1 engine1 reply').split()
HIT_FRESH, HIT_STALE, FOLLOWER, ERROR = 1, 2, 1 << 8, 1 << 9
LOOP_REPLY = 1 << 11
STAGES = {'server_total': ('recv', 'reply'), 'dispatch': ('recv', 'dispatched'),
          'queue_wait': ('enqueue', 'pickup'), 'engine': ('engine0', 'engine1'),
          'upstream': ('up_send', 'up_recv'), 'nft': ('nft0', 'nft1')}
CACHE_COUNTERS = ('fresh_hit stale_hit miss_cold miss_evicted miss_expired bypass '
                  'refresh_ok refresh_fail refresh_kept_old prefetch evictions warm').split()
UNAVAILABLE = {'available': False}
NS = 10**9


def normalized(name):
    return str(name).lower().rstrip('.')


def digest_name(key, name, qtype=0, qclass=1):
    return hmac.new(key, ('%s\0%d\0%d' % (normalized(name), qtype, qclass)).encode(),
                    hashlib.sha256).hexdigest()


def finite(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value)


def quantiles(values):
    ordered = sorted(x for x in values if finite(x))
    n = len(ordered)
    out = {'sample_count': n, 'percentile_method': 'floor((N-1)*p), exact',
           'p99_sample_sufficient': n >= 1000,
           'p99_note': None if n >= 1000 else 'fewer than 1000 samples; tail estimate is sparse'}
    for name, p in (('p50_ms', .5), ('p90_ms', .9), ('p99_ms', .99)):
        out[name] = ordered[int((n - 1) * p)] if n else None
    out.update(mean_ms=statistics.fmean(ordered) if n else None,
               max_ms=ordered[-1] if n else None)
    return out


class Rules:
    """Rules follow the C matcher's full/domain/suffix/keyword semantics.

    PCRE2 expressions are intentionally not translated into Python expressions.
    A nonmatching name is unknown when regex or unrecognized rules are present.
    """
    def __init__(self, paths=()):
        self.full, self.domains, self.keywords = set(), set(), []
        self.unsupported, self.files = collections.Counter(), []
        for path in paths:
            data = Path(path).read_bytes()
            self.files.append({'name': Path(path).name, 'sha256': hashlib.sha256(data).hexdigest()})
            for raw in data.decode('utf-8').splitlines():
                line = raw.split('#', 1)[0].strip()
                if not line or line.startswith(('#', ';')):
                    continue
                if any(c.isspace() for c in line):
                    self.unsupported['invalid_space'] += 1
                    continue
                if ':' in line:
                    mode, name = line.split(':', 1)
                else:
                    mode, name = 'domain', line
                name = normalized(name)
                if mode == 'full':
                    self.full.add(name)
                elif mode in ('domain', 'suffix'):
                    self.domains.add(name.lstrip('.'))
                elif mode == 'keyword':
                    self.keywords.append(name)
                else:
                    self.unsupported[mode if mode in ('regexp', 'regex') else 'other'] += 1

    def classify(self, name):
        name = normalized(name)
        if '' in self.domains or name in self.full or any(k in name for k in self.keywords):
            return 'cn'
        labels = name.split('.')
        if any('.'.join(labels[i:]) in self.domains for i in range(len(labels))):
            return 'cn'
        if not self.files or self.unsupported:
            return 'unknown'
        return 'foreign'


def trace_route(row):
    """Route evidence from the immutable engine/server contract, never latency.

    MD_LANE_CN=1 / MD_LANE_FOREIGN=2 are dispatch route decisions. Only
    MD_LANE_REPLY=3 with BOTH HIT_FRESH and LOOP_REPLY proves the engine's
    foreign-only immediate fresh-cache response. TCP release_quota also changes
    ordinary worker jobs to lane 3, so lane 3 plus HIT_FRESH alone proves nothing.
    Background refresh jobs do not carry a useful dispatch lane.
    """
    if row['kind'] != 'Q':
        return None
    if row['lane'] == 1:
        return 'cn'
    if row['lane'] == 2:
        return 'foreign'
    if row['lane'] == 3 and row['flags'] & HIT_FRESH and row['flags'] & LOOP_REPLY:
        return 'foreign'
    return None


class RegionEvidence:
    def __init__(self, rules):
        self.rules = rules
        self.routes = collections.defaultdict(set)
        self.records = collections.Counter()

    def add(self, row, arm):
        route = trace_route(row)
        if route is not None:
            self.routes[normalized(row['qname'])].add(route)
            self.records[arm + '/' + route] += 1

    def classify(self, name):
        name = normalized(name)
        rule = self.rules.classify(name)
        evidence = self.routes.get(name, set())
        if len(evidence) > 1:
            return 'unknown'
        if evidence:
            route = next(iter(evidence))
            if rule != 'unknown' and rule != route:
                return 'unknown'
            return route
        return rule

    def summary(self):
        conflicts = sum(len(routes) > 1 for routes in self.routes.values())
        rule_conflicts = sum(self.rules.classify(name) != 'unknown' and
                             any(route != self.rules.classify(name) for route in routes)
                             for name, routes in self.routes.items())
        classes = collections.Counter(self.classify(name) for name in self.routes)
        return {'unique_names_with_trace_evidence': len(self.routes),
                'resolved_evidence_names_by_region': dict(classes),
                'trace_route_conflict_names': conflicts,
                'rule_trace_conflict_names': rule_conflicts,
                'evidence_records_by_arm_and_region': dict(self.records),
                'contract': 'Q lane1=CN; Q lane2=foreign; Q lane3 requires HIT_FRESH and LOOP_REPLY for foreign',
                'method': 'normalized name; evidence shared across A/B; any route or rule conflict remains unknown; no latency inference'}


def read_jsonl(path, audit):
    path = Path(path)
    if not path.exists():
        return
    # Limit this snapshot to the byte size observed at open, even if a writer appends.
    remaining = path.stat().st_size
    audit['snapshot_bytes'] = remaining
    with path.open('rb') as stream:
        while remaining:
            raw = stream.readline(remaining)
            remaining -= len(raw)
            if not raw.endswith(b'\n'):
                audit['partial_tail_lines'] = audit.get('partial_tail_lines', 0) + 1
                break
            try:
                row = json.loads(raw)
                if not isinstance(row, dict):
                    raise ValueError('not object')
            except (ValueError, UnicodeError):
                audit['invalid_complete_lines'] = audit.get('invalid_complete_lines', 0) + 1
                continue
            audit['valid_lines'] = audit.get('valid_lines', 0) + 1
            yield row


def parse_trace_line(line):
    if not line.strip() or line.startswith('#'):
        return None
    fields = line.rstrip('\n').split('\t')
    if len(fields) != len(TRACE_FIELDS):
        raise ValueError('invalid trace column count')
    row = dict(zip(TRACE_FIELDS, fields))
    if row['kind'] not in ('Q', 'R'):
        raise ValueError('invalid trace kind')
    for name in TRACE_FIELDS:
        if name not in ('kind', 'qname'):
            row[name] = int(row[name])
            if row[name] < 0:
                raise ValueError('negative trace number')
    row['qname'] = normalized(row['qname'])
    return row


def read_trace(path, audit):
    path = Path(path)
    if not path.exists():
        return
    remaining = path.stat().st_size
    audit['snapshot_bytes'] = remaining
    with path.open('rb') as stream:
        while remaining:
            raw = stream.readline(remaining)
            remaining -= len(raw)
            if not raw.endswith(b'\n'):
                audit['partial_tail_lines'] = audit.get('partial_tail_lines', 0) + 1
                break
            try:
                row = parse_trace_line(raw.decode())
            except (ValueError, UnicodeError):
                audit['invalid_complete_lines'] = audit.get('invalid_complete_lines', 0) + 1
                continue
            if row is not None:
                audit['valid_lines'] = audit.get('valid_lines', 0) + 1
                yield row


def parse_cache_stats(lines):
    groups = {g: {'snapshots': 0, 'counter_resets': 0, 'totals': collections.Counter(),
                  'last': None} for g in ('cn', 'foreign')}
    invalid = 0
    for line in lines:
        match = re.search(r'cache stats (cn|foreign):\s*(.*)', line)
        if not match:
            continue
        values = {k: int(v) for k, v in re.findall(r'([a-z_]+)=(\d+)', match[2])}
        if not all(k in values for k in CACHE_COUNTERS):
            invalid += 1
            continue
        group = groups[match[1]]
        previous = group['last']
        reset = previous is not None and any(values[k] < previous[k] for k in CACHE_COUNTERS)
        if reset:
            group['counter_resets'] += 1
        for k in CACHE_COUNTERS:
            group['totals'][k] += values[k] if previous is None or reset else values[k] - previous[k]
        group['last'] = values
        group['snapshots'] += 1
    for group in groups.values():
        group['available'] = group['snapshots'] > 0
        group['totals'] = dict(group['totals'])
    return {'groups': groups, 'invalid_stats_lines': invalid,
            'time_windows': {'available': False, 'reason': 'stderr counters have no event timestamps'},
            'scope': 'whole process cumulative snapshots, includes HTTPS probes and any preflight queries'}


def cache_class(flags):
    if flags & HIT_FRESH:
        return 'fresh_hit'
    if flags & HIT_STALE:
        return 'stale_hit'
    if flags & FOLLOWER:
        return 'follower'
    return 'miss_or_bypass'


def parse_question(wire_b64):
    wire = base64.b64decode(wire_b64, validate=True)
    if len(wire) < 12 or struct.unpack('!H', wire[4:6])[0] != 1:
        raise ValueError('not one question')
    pos, labels, seen = 12, [], set()
    end = None
    for _ in range(256):
        if pos >= len(wire) or pos in seen:
            raise ValueError('invalid name')
        seen.add(pos)
        length = wire[pos]
        pos += 1
        if length == 0:
            end = pos if end is None else end
            break
        if length & 0xc0 == 0xc0:
            if pos >= len(wire):
                raise ValueError('invalid pointer')
            end = pos + 1 if end is None else end
            pos = (length & 63) * 256 + wire[pos]
        elif length > 63 or pos + length > len(wire):
            raise ValueError('invalid label')
        else:
            labels.append(wire[pos:pos + length].decode('ascii'))
            pos += length
    if end is None or end + 4 > len(wire):
        raise ValueError('truncated question')
    qtype, qclass = struct.unpack('!HH', wire[end:end + 4])
    return normalized('.'.join(labels)), qtype, qclass, struct.unpack('!H', wire[:2])[0]


class Arm:
    def __init__(self):
        self.counts = collections.Counter()
        self.rcodes = collections.Counter()
        self.values = collections.defaultdict(list)

    def add(self, result):
        self.counts['attempted'] += 1
        if isinstance(result.get('wire_sent'), bool):
            self.counts['wire_status_known'] += 1
            self.counts['wire_sent'] += result['wire_sent']
        if isinstance(result.get('transport_response'), bool):
            self.counts['transport_response'] += result['transport_response']
        success = result.get('success') is True
        self.counts['successful' if success else 'failed'] += 1
        error = str(result.get('error', '')).lower()
        if not success and (result.get('timed_out') is True or 'timeout' in error or 'deadline' in error):
            self.counts['timeouts'] += 1
        if result.get('truncated'):
            self.counts['truncated'] += 1
        self.rcodes[str(result.get('rcode', 'unavailable'))] += 1
        for key, source in (('all_latency', 'duration_ms'), ('arrival_to_send', 'arrival_to_send_ms')):
            if finite(result.get(source)):
                self.values[key].append(result[source])
        if success and finite(result.get('duration_ms')):
            self.values['success_latency'].append(result['duration_ms'])
        if finite(result.get('min_answer_ttl')):
            self.values['min_answer_ttl_seconds'].append(result['min_answer_ttl'])

    def view(self):
        out = {key: self.counts[key] for key in ('attempted', 'successful', 'failed', 'timeouts', 'truncated')}
        out['wire_sent'] = self.counts['wire_sent'] if self.counts['wire_status_known'] else None
        out['wire_status_unknown'] = self.counts['attempted'] - self.counts['wire_status_known']
        out['transport_responses'] = self.counts['transport_response']
        out['rcodes'] = dict(self.rcodes)
        for key in ('success_latency', 'all_latency', 'arrival_to_send'):
            out[key] = quantiles(self.values[key])
        ttls = self.values['min_answer_ttl_seconds']
        out['min_answer_ttl_seconds'] = {'sample_count': len(ttls), 'min': min(ttls) if ttls else None,
                                          'max': max(ttls) if ttls else None}
        return out


class Period:
    def __init__(self):
        self.counts, self.reasons = collections.Counter(), collections.Counter()
        self.arms = {'a': Arm(), 'b': Arm()}
        self.by = collections.defaultdict(lambda: {'a': Arm(), 'b': Arm()})
        self.paired = collections.Counter()
        self.deltas = []

    def add(self, row, region):
        self.counts['arrivals'] += 1
        if row.get('disposition') != 'sent':
            self.counts['unsent_pairs'] += 1
            reason = str(row.get('reason', 'unspecified'))
            # Reason enum only; never copy arbitrary exception text.
            self.reasons[reason if re.fullmatch(r'[a-z_]{1,64}', reason) else 'other'] += 1
            return
        self.counts['dispatched_pairs'] += 1
        wire_status = [(row.get(arm) or {}).get('wire_sent') for arm in ('a', 'b')]
        if all(isinstance(v, bool) for v in wire_status):
            self.counts['both_wire_sent_pairs' if all(wire_status) else 'partial_wire_sent_pairs' if any(wire_status) else 'no_wire_sent_pairs'] += 1
        else:
            self.counts['wire_sent_status_unavailable_pairs'] += 1
        for arm in ('a', 'b'):
            result = row.get(arm)
            if not isinstance(result, dict):
                self.counts['missing_arm_results'] += 1
                continue
            self.arms[arm].add(result)
            for key in ('region/' + region, 'qtype/' + str(row.get('qtype', 0)),
                        'transport/' + str(row.get('query_transport', 'unknown'))):
                if not re.fullmatch(r'[a-z0-9_/]{1,64}', key):
                    key = 'transport/unknown'
                self.by[key][arm].add(result)
        a, b = row.get('a'), row.get('b')
        if not isinstance(a, dict) or not isinstance(b, dict):
            return
        state = ('success' if a.get('success') else 'failure') + '/' + ('success' if b.get('success') else 'failure')
        self.paired[state] += 1
        if a.get('success') and b.get('success'):
            if finite(a.get('duration_ms')) and finite(b.get('duration_ms')):
                delta = b['duration_ms'] - a['duration_ms']
                self.deltas.append(delta)
                self.paired['b_faster' if delta < 0 else 'a_faster' if delta > 0 else 'equal_latency'] += 1
            self.paired['rcode_equal' if a.get('rcode') == b.get('rcode') else 'rcode_different'] += 1
            aa = {(v.get('family'), v.get('ip')) for v in a.get('addresses', [])}
            ba = {(v.get('family'), v.get('ip')) for v in b.get('addresses', [])}
            self.paired['address_set_equal' if aa == ba else 'address_set_different'] += 1

    def view(self):
        return {'counts': dict(self.counts), 'unsent_reasons': dict(self.reasons),
                'arms': {a: v.view() for a, v in self.arms.items()},
                'by': {k: {a: v.view() for a, v in arms.items()} for k, arms in sorted(self.by.items())},
                'paired': {'counts': dict(self.paired), 'b_minus_a_success_latency_ms': quantiles(self.deltas)}}


def periods_for(ts, start):
    relative = max(0, ts - start)
    return ('all', 'first_hour' if relative < 3600 * NS else 'stable_after_first_hour',
            'window_%03d' % (relative // (900 * NS)))


def parse_resources(rows, start=None, end=None):
    values = collections.defaultdict(list)
    period_values = collections.defaultdict(lambda: collections.defaultdict(list))
    boots, degraded, prod_pids = set(), collections.Counter(), set()
    samples, excluded = 0, 0
    for row in rows:
        stamp = row.get('ts_unix_ns')
        if not finite(stamp) and finite(row.get('ts_unix_s')):
            stamp = int(row['ts_unix_s'] * NS)
        if finite(stamp) and ((start and stamp < start) or (end and stamp >= end)):
            excluded += 1
            continue
        samples += 1
        sample_periods = periods_for(int(stamp), start) if start and finite(stamp) else ()
        if row.get('boot_id'):
            boots.add(str(row['boot_id']))
        if 'degraded' in row:
            degraded[str(bool(row['degraded']))] += 1
        if row.get('production_pid'):
            prod_pids.add(row['production_pid'])
        def walk(value, path):
            if isinstance(value, dict):
                for key, v in value.items():
                    # whitelist metric keys; omit domain/IP/command/string values.
                    if re.fullmatch(r'[a-zA-Z0-9_]{1,64}', str(key)):
                        walk(v, path + '.' + str(key) if path else str(key))
            elif finite(value):
                values[path].append(value)
                for period in sample_periods:
                    period_values[period][path].append(value)
        walk(row, '')
    summaries = {k: {'sample_count': len(v), 'first': v[0], 'last': v[-1],
                     'min': min(v), 'max': max(v), 'mean': statistics.fmean(v)}
                 for k, v in sorted(values.items())}
    return {'available': samples > 0, 'sample_count': samples, 'boot_id_count': len(boots),
            'production_pid_count': len(prod_pids), 'samples_outside_window_excluded': excluded, 'degraded_sample_counts': dict(degraded),
            'numeric_metrics': summaries,
            'periods': {period: {k: {'sample_count': len(v), 'first': v[0], 'last': v[-1],
                                    'min': min(v), 'max': max(v), 'mean': statistics.fmean(v)}
                                 for k, v in metrics.items()}
                        for period, metrics in period_values.items()},
            'queue_depth': dict(UNAVAILABLE)}


def https_summary(rows, key, start, end=None):
    groups = collections.defaultdict(lambda: {'counts': collections.Counter(),
                                              'values': collections.defaultdict(list)})
    cycles, pair_duplicates, unpaired = {}, 0, 0
    window_counts = collections.Counter()
    outside_outcomes = collections.defaultdict(collections.Counter)
    for row in rows:
        if row.get('type') != 'https_probe':
            continue
        window_counts['total_probe_records'] += 1
        stamp = row.get('started_unix_ns')
        outside = ('timestamp_unavailable' if not isinstance(stamp, int) else
                   'before_observation_window' if stamp < start else
                   'after_observation_window' if end and stamp >= end else None)
        if outside is not None:
            window_counts[outside] += 1
            outcome = outside_outcomes[outside]
            outcome['attempts'] += 1
            outcome['successful' if row.get('success') else 'failed'] += 1
            error = str(row.get('error', '')).lower()
            outcome['cancelled'] += 'cancel' in error
            outcome['timeouts'] += 'timeout' in error or 'deadline' in error
            outcome['certificate_verified'] += bool(row.get('certificate_verified'))
            outcome['uncovered'] += str(row.get('coverage', '')).startswith('uncovered')
            continue
        window_counts['in_observation_window'] += 1
        site = row.get('site') or {}
        # Stable private host ID supports per-site comparison without names/paths/IPs.
        site_id = digest_name(key, site.get('host', 'unknown'))[:20]
        arm = row.get('arm') if row.get('arm') in ('a', 'b') else 'unknown'
        family = row.get('address_family') if row.get('address_family') in (4, 6) else 0
        periods = periods_for(stamp, start)
        for period in periods:
            group = groups[(period, site_id, arm, family)]
            count = group['counts']
            count['attempts'] += 1
            count['successful' if row.get('success') else 'failed'] += 1
            for flag in ('tls_handshake_success', 'certificate_verified', 'body_complete', 'body_limited'):
                count[flag] += bool(row.get(flag))
            if row.get('success') and not row.get('certificate_verified'):
                count['success_without_verified_certificate'] += 1
            if str(row.get('coverage', '')).startswith('uncovered'):
                count['uncovered'] += 1
            if row.get('success'):
                for metric in ('tcp_ms', 'tls_ms', 'ttfb_ms', 'http_total_ms', 'dns_and_http_total_ms'):
                    if finite(row.get(metric)):
                        group['values'][metric].append(row[metric])
                dns = row.get('dns') or {}
                if finite(dns.get('duration_ms')):
                    group['values']['dns_ms'].append(dns['duration_ms'])
        cycle = row.get('cycle_id')
        if isinstance(cycle, int) and cycle > 0 and arm in ('a', 'b'):
            pair = cycles.setdefault((cycle, site_id, family), {})
            if arm in pair:
                pair_duplicates += 1
            pair[arm] = row
        else:
            unpaired += 1
    pairs = collections.defaultdict(lambda: {'counts': collections.Counter(),
                                            'values': collections.defaultdict(list)})
    for (_, site_id, family), pair in cycles.items():
        group = pairs[(site_id, family)]
        if 'a' not in pair or 'b' not in pair:
            group['counts']['incomplete_pairs'] += 1
            continue
        a, b = pair['a'], pair['b']
        state = ('success' if a.get('success') else 'failure') + '/' + ('success' if b.get('success') else 'failure')
        group['counts'][state] += 1
        if a.get('success') and b.get('success'):
            group['counts']['connected_ip_equal' if a.get('connected_ip') == b.get('connected_ip') else 'connected_ip_different'] += 1
            for metric in ('tcp_ms', 'tls_ms', 'ttfb_ms', 'http_total_ms', 'dns_and_http_total_ms'):
                if finite(a.get(metric)) and finite(b.get(metric)):
                    group['values'][metric].append(b[metric] - a[metric])
            ad, bd = a.get('dns') or {}, b.get('dns') or {}
            if finite(ad.get('duration_ms')) and finite(bd.get('duration_ms')):
                group['values']['dns_ms'].append(bd['duration_ms'] - ad['duration_ms'])
    paired = {'available': bool(cycles), 'records_without_cycle_id': unpaired,
              'duplicate_cycle_arm_records': pair_duplicates,
              'groups': [dict(site_hmac=site_id, address_family=family, counts=dict(v['counts']),
                              b_minus_a_success_metrics={k: quantiles(x) for k, x in v['values'].items()})
                         for (site_id, family), v in sorted(pairs.items())]}
    if not cycles:
        paired['reason'] = 'no explicit shared HTTPS cycle ID; do not infer pairing by time'
    return {'available': bool(groups), 'scope': 'fixed-IP, Host/SNI preserved, certificate-verified HTTP GET; browser rendering not covered',
            'window_assignment': 'probe started_unix_ns in [start_unix_ns, expected_end_unix_ns); excluded raw outcomes remain in original logs',
            'window_counts': {name: window_counts[name] for name in
                              ('total_probe_records', 'in_observation_window', 'before_observation_window',
                               'after_observation_window', 'timestamp_unavailable')},
            'out_of_window_outcomes': {name: dict(value) for name, value in outside_outcomes.items()},
            'groups': [dict(period=period, site_hmac=site_id, arm=arm, address_family=family,
                            counts=dict(value['counts']),
                            success_metrics={k: quantiles(v) for k, v in value['values'].items()})
                       for (period, site_id, arm, family), value in sorted(groups.items())],
            'paired': paired}


def file_map(input_dir, overrides):
    files = {'runner': input_dir / 'dns-results.jsonl', 'capture': input_dir / 'capture-private.jsonl',
             'https': input_dir / 'https-results.jsonl', 'resources': input_dir / 'resources.jsonl',
             'capture_stderr': input_dir / 'capture.stderr.log',
             'a_trace': input_dir / 'a.trace.tsv', 'b_trace': input_dir / 'b.trace.tsv',
             'a_stderr': input_dir / 'a.stderr.log', 'b_stderr': input_dir / 'b.stderr.log'}
    for name, value in overrides.items():
        if value is not None:
            files[name] = Path(value)
    return files


def build_report(input_dir, rules_paths=(), start_unix_ns=None, start_mono_ns=None, overrides=None):
    root = Path(input_dir)
    metadata_path = root / 'metadata.json'
    metadata = json.loads(metadata_path.read_text()) if metadata_path.exists() else {}
    start = start_unix_ns or metadata.get('start_unix_ns')
    if not isinstance(start, int) or start <= 0:
        raise ValueError('start_unix_ns must be supplied or present in metadata.json')
    start_mono = start_mono_ns or metadata.get('start_mono_ns')
    expected_end = metadata.get('expected_end_unix_ns')
    if not isinstance(expected_end, int) and finite(metadata.get('duration_seconds')):
        expected_end = start + int(metadata['duration_seconds'] * NS)
    files = file_map(root, overrides or {})
    rules = Rules(rules_paths)
    key_path = root / 'hmac.key'
    key = key_path.read_bytes() if key_path.exists() else os.urandom(32)
    audit = collections.defaultdict(dict)
    probe_hosts = {normalized(x) for x in metadata.get('probe_hosts', {})}
    region_evidence = RegionEvidence(rules)
    # Scan both immutable trace snapshots before classifying captures or either
    # arm. A late cold query can prove the route of earlier cached same-name
    # queries, while disagreements across arms remain visibly unknown.
    for arm in ('a', 'b'):
        for row in read_trace(files[arm + '_trace'], audit[arm + '_trace_route_evidence']):
            stamp = row['recv'] or row['engine0']
            if row['qname'] in probe_hosts:
                continue
            if start_mono and stamp and stamp < start_mono:
                continue
            if start_mono and expected_end and stamp >= start_mono + expected_end - start:
                continue
            region_evidence.add(row, arm)
    classification = region_evidence.summary()
    audit['region_classification'] = {
        'trace_route_conflict_names': classification['trace_route_conflict_names'],
        'rule_trace_conflict_names': classification['rule_trace_conflict_names']}
    capture = {}
    last_capture_stats = None
    capture_sequences = set()
    capture_window_sequences = collections.defaultdict(set)
    duplicate_sequences = 0
    clock_offsets = []
    for row in read_jsonl(files['capture'], audit['capture']):
        if row.get('type') == 'capture_stats':
            last_capture_stats = row
        if row.get('type') != 'dns_query':
            continue
        seq = row.get('sequence')
        if seq in capture_sequences:
            duplicate_sequences += 1
        capture_sequences.add(seq)
        timestamp = row.get('ts_unix_ns')
        window = ('timestamp_unavailable' if not isinstance(timestamp, int) else
                  'before_observation_window' if timestamp < start else
                  'after_observation_window' if expected_end and timestamp >= expected_end else
                  'in_observation_window')
        capture_window_sequences[window].add(seq)
        try:
            name, qt, qc, qid = parse_question(row['wire_b64'])
            capture[seq] = {'region': region_evidence.classify(name), 'id': qid,
                            'identity': digest_name(key, name, qt, qc), 'qtype': qt, 'qclass': qc,
                            'probe': name in probe_hosts}
        except (ValueError, KeyError, UnicodeError, struct.error):
            audit['capture']['unparsed_dns_messages'] = audit['capture'].get('unparsed_dns_messages', 0) + 1
        mono, unix = row.get('receive_mono_ns'), row.get('ts_unix_ns')
        if finite(mono) and finite(unix):
            clock_offsets.append(mono - unix)
    # An observed read-time mapping is approximate; only an explicit CLOCK_MONOTONIC
    # start mapping is used to claim exact server time windows.
    approximate_offset = min(clock_offsets) if clock_offsets else None
    clock = {'exact_start_mapping': bool(start_mono), 'approximate_offset_ns': approximate_offset,
             'offset_spread_ns': max(clock_offsets) - min(clock_offsets) if clock_offsets else None}
    periods = collections.defaultdict(Period)
    excluded = collections.Counter()
    observed_end = start
    runner_sequences = set()
    runner_window_records = set()
    runner_window_capture_sequences = set()
    duplicate_results = 0
    join_targets = {'a': collections.defaultdict(list), 'b': collections.defaultdict(list)}
    for row in read_jsonl(files['runner'], audit['runner']):
        if row.get('type') != 'dns_mirror':
            continue
        sequence = row.get('sequence')
        if sequence in runner_sequences:
            duplicate_results += 1
            continue
        runner_sequences.add(sequence)
        source = capture.get(row.get('capture_sequence'), {})
        if source and row.get('question_hmac') != source['identity']:
            audit['runner']['capture_identity_mismatches'] = audit['runner'].get('capture_identity_mismatches', 0) + 1
            source = {}
        ts = row.get('arrival_unix_ns', start)
        if not isinstance(ts, int):
            audit['runner']['invalid_arrival_timestamp'] = audit['runner'].get('invalid_arrival_timestamp', 0) + 1
            continue
        if ts >= start and (not expected_end or ts < expected_end):
            runner_window_records.add(sequence)
            runner_window_capture_sequences.add(row.get('capture_sequence'))
        if row.get('probe_host') or source.get('probe'):
            excluded['probe_host_pairs'] += 1
            continue
        if ts < start:
            excluded['before_start_pairs'] += 1
            continue
        if expected_end and ts >= expected_end:
            excluded['after_deadline_pairs'] += 1
            continue
        observed_end = max(observed_end, ts)
        for period in periods_for(ts, start):
            periods[period].add(row, source.get('region', 'unknown'))
        if row.get('disposition') == 'sent':
            for arm in ('a', 'b'):
                result = row.get(arm)
                if not isinstance(result, dict) or not source:
                    continue
                sent_mono = result.get('send_started_mono_ns') or result.get('sent_mono_ns')
                if finite(sent_mono):
                    join_targets[arm][(source['identity'], source['id'])].append(
                        (sent_mono, result.get('finished_mono_ns') or (sent_mono + max(0, result.get('duration_ms', 0)) * 10**6),
                         result, source.get('region', 'unknown')))
    trace_out = {}
    for arm in ('a', 'b'):
        counts, class_regions = collections.Counter(), collections.defaultdict(collections.Counter)
        stages, upstream_by_kind = collections.defaultdict(list), collections.defaultdict(collections.Counter)
        trace_windows, joined_latencies = collections.defaultdict(collections.Counter), collections.defaultdict(list)
        used = set()
        for row in read_trace(files[arm + '_trace'], audit[arm + '_trace']):
            if row['qname'] in probe_hosts:
                counts['probe_records_excluded'] += 1
                continue
            region = region_evidence.classify(row['qname'])
            stamp = row['recv'] or row['engine0']
            if start_mono and stamp and stamp < start_mono:
                counts['before_start_records_excluded'] += 1
                continue
            if start_mono and expected_end and stamp >= start_mono + expected_end - start:
                counts['after_deadline_records_excluded'] += 1
                continue
            kind = 'background_refresh' if row['kind'] == 'R' else 'foreground_query'
            counts[kind] += 1
            upstream_by_kind[kind]['upstream_attempts'] += row['attempts']
            upstream_by_kind[kind]['udp_resends'] += row['resends']
            upstream_by_kind[kind]['queries_with_upstream_send'] += bool(row['up_send'])
            upstream_by_kind[kind]['errors'] += bool(row['flags'] & ERROR)
            cls = cache_class(row['flags']) if row['kind'] == 'Q' else 'background_refresh'
            class_regions[region][cls] += 1
            if start_mono and stamp:
                for period in periods_for(start + stamp - start_mono, start):
                    trace_windows[period][cls] += 1
            for stage, (first, last) in STAGES.items():
                if row[first] and row[last] >= row[first]:
                    stages[stage].append((row[last] - row[first]) / 1e6)
            if row['kind'] != 'Q':
                continue
            ident = digest_name(key, row['qname'], row['qtype'], 1)
            targets = join_targets[arm].get((ident, row['id']), ())
            choices = [(abs(row['recv'] - target[0]), i, target) for i, target in enumerate(targets)
                       if (ident, row['id'], i) not in used and
                       target[0] <= row['recv'] <= target[1] + 10**6]
            if choices:
                _, index, target = min(choices, key=lambda x: x[0])
                used.add((ident, row['id'], index))
                counts['runner_trace_joined'] += 1
                if target[2].get('success') and finite(target[2].get('duration_ms')):
                    joined_latencies[cls + '/' + target[3]].append(target[2]['duration_ms'])
        trace_out[arm] = {'available': files[arm + '_trace'].exists(), 'counts': dict(counts),
                         'classes_by_region': {k: dict(v) for k, v in class_regions.items()},
                         'upstream_transactions': {k: dict(v) for k, v in upstream_by_kind.items()},
                         'stage_latency': {k: quantiles(v) for k, v in stages.items()},
                         'exact_time_window_classes': {k: dict(v) for k, v in trace_windows.items()} if start_mono else dict(UNAVAILABLE),
                         'joined_success_latency_by_cache_class': {k: quantiles(v) for k, v in joined_latencies.items()},
                         'fine_miss_reasons': dict(UNAVAILABLE),
                         'notes': ['cache class derives only from trace flags; miss_or_bypass is not a guessed first miss',
                                   'trace is stdio-buffered; an active-process snapshot can lag',
                                   'upstream counters are C transactions/resends, not exact network packet counts',
                                   'probe domain filtering also excludes refreshes for those domains']}
        queries = counts['foreground_query']
        transactions = sum(v['upstream_attempts'] + v['udp_resends'] for v in upstream_by_kind.values())
        trace_out[arm]['upstream_transactions_per_1000_foreground_trace_queries'] = transactions * 1000 / queries if queries else None
    cache_stats = {}
    for arm in ('a', 'b'):
        path = files[arm + '_stderr']
        cache_stats[arm] = parse_cache_stats(path.read_text(errors='replace').splitlines()) if path.exists() else dict(UNAVAILABLE)
    resources = parse_resources(read_jsonl(files['resources'], audit['resources']), start, expected_end)
    https = https_summary(read_jsonl(files['https'], audit['https']), key, start, expected_end)
    status_path = root / ('final.json' if (root / 'final.json').exists() else 'status.json')
    status = json.loads(status_path.read_text()) if status_path.exists() else {}
    if last_capture_stats is None:
        last_capture_stats = status.get('last_capture_stats')
    if files['capture_stderr'].exists():
        for line in files['capture_stderr'].read_text(errors='replace').splitlines():
            if line.startswith('capture_final '):
                try:
                    receipt = json.loads(line[len('capture_final '):])
                    if isinstance(receipt, dict):
                        last_capture_stats = receipt
                        audit['capture_stderr']['final_receipt_parsed'] = True
                except ValueError:
                    audit['capture_stderr']['invalid_receipt'] = True
    capture_totals = {}
    if isinstance(last_capture_stats, dict):
        for metric in ('kernel_packets', 'kernel_drops', 'elapsed_seconds'):
            if finite(last_capture_stats.get(metric)):
                capture_totals[metric] = last_capture_stats[metric]
        capture_totals['counters'] = {k: v for k, v in last_capture_stats.get('counters', {}).items()
                                      if re.fullmatch(r'[a-z0-9_]{1,64}', k) and finite(v)}
        capture_totals['final_receipt'] = bool(last_capture_stats.get('final'))
    all_counts = periods['all'].counts
    numeric_sequences = [s for s in capture_sequences if isinstance(s, int)]
    capture_gaps = max(numeric_sequences) - min(numeric_sequences) + 1 - len(numeric_sequences) if numeric_sequences else 0
    balance = {'capture_dns_records_in_snapshot': len(capture_sequences),
               'runner_unique_result_records': len(runner_sequences),
               'capture_minus_runner_records': len(capture_sequences) - len(runner_sequences),
               'capture_in_observation_window': len(capture_window_sequences['in_observation_window']),
               'capture_before_observation_window': len(capture_window_sequences['before_observation_window']),
               'capture_after_observation_window': len(capture_window_sequences['after_observation_window']),
               'capture_timestamp_unavailable': len(capture_window_sequences['timestamp_unavailable']),
               'runner_in_observation_window': len(runner_window_records),
               'capture_window_minus_runner_records': len(capture_window_sequences['in_observation_window']) - len(runner_window_records),
               'capture_in_window_without_runner_result': len(capture_window_sequences['in_observation_window'] - runner_window_capture_sequences),
               'runner_in_window_without_capture_record': len(runner_window_capture_sequences - capture_window_sequences['in_observation_window']),
               'capture_sequence_gaps': capture_gaps,
               'duplicate_capture_sequences': duplicate_sequences, 'duplicate_runner_results': duplicate_results,
               'main_flow_arrivals': all_counts['arrivals'], 'main_flow_dispatched_pairs': all_counts['dispatched_pairs'],
               'main_flow_both_wire_sent_pairs': all_counts['both_wire_sent_pairs'],
               'main_flow_partial_wire_sent_pairs': all_counts['partial_wire_sent_pairs'],
               'main_flow_no_wire_sent_pairs': all_counts['no_wire_sent_pairs'],
               'wire_sent_status_unavailable_pairs': all_counts['wire_sent_status_unavailable_pairs'],
               'main_flow_unsent_pairs': all_counts['unsent_pairs'],
               'main_flow_arrivals_equal_dispatched_plus_unsent': all_counts['arrivals'] == all_counts['dispatched_pairs'] + all_counts['unsent_pairs'],
               'capture_kernel_totals': capture_totals,
               'note': 'total capture_minus_runner includes separately counted before/after-window records; only window-matched missing results may be in flight while runner is active; kernel_drops counts known socket loss, not all possible capture loss'}
    integrity_issues = []
    if classification['trace_route_conflict_names']:
        integrity_issues.append('trace_route_classification_conflict')
    if classification['rule_trace_conflict_names']:
        integrity_issues.append('rule_trace_classification_conflict')
    if balance['runner_in_window_without_capture_record']:
        integrity_issues.append('runner_observation_window_capture_record_missing')
    if status.get('finished') and balance['capture_in_window_without_runner_result']:
        integrity_issues.append('capture_observation_window_result_missing')
    if balance['capture_timestamp_unavailable']:
        integrity_issues.append('capture_timestamp_unavailable')
    if capture_totals.get('kernel_drops', 0):
        integrity_issues.append('capture_kernel_drops')
    for counter, count in capture_totals.get('counters', {}).items():
        if count and any(token in counter for token in ('queue_full', 'failed', 'timeout', 'unsupported',
                                                        'incomplete', 'without_syn', 'buffer_limit',
                                                        'flow_limit_evicted', 'gap_or_pending_limit',
                                                        'gap_expired', 'conflicting_overlap')):
            integrity_issues.append('capture_' + counter)
    if capture_gaps:
        integrity_issues.append('capture_sequence_gaps')
    if duplicate_sequences or duplicate_results:
        integrity_issues.append('duplicate_sequence_or_results')
    for stream_name, counters in audit.items():
        if counters.get('invalid_complete_lines') or counters.get('capture_identity_mismatches'):
            integrity_issues.append(stream_name + '_invalid_records')
    if resources['boot_id_count'] > 1:
        integrity_issues.append('device_boot_changed')
    if all_counts['unsent_pairs']:
        integrity_issues.append('runner_unsent_pairs')
    if all_counts['partial_wire_sent_pairs'] or all_counts['no_wire_sent_pairs']:
        integrity_issues.append('runner_wire_send_failed')
    result = {'schema': 'diversion-realflow-report-v1', 'snapshot_unix_ns': time.time_ns(),
              'start_unix_ns': start, 'observed_last_arrival_unix_ns': observed_end,
              'expected_duration_seconds': metadata.get('duration_seconds'),
              'runner_finished': bool(status.get('finished')), 'runner_complete': status.get('complete'),
              'observed_main_flow_span_seconds': (observed_end - start) / NS,
              'privacy': 'aggregate only; no DNS names, wire, client identities, destination IPs or raw errors',
              'integrity': {'known_issues': sorted(set(integrity_issues)),
                            'final_capture_receipt_present': capture_totals.get('final_receipt', False),
                            'note': 'No automatic pass grade: inspect known issues, final receipts, timing and coverage'},
              'rules': {'files': rules.files, 'unsupported_modes': dict(rules.unsupported),
                        'nonmatching_class': 'unknown' if not rules.files or rules.unsupported else 'foreign'},
              'region_classification': classification,
              'clock_alignment': clock, 'excluded': dict(excluded), 'balance': balance,
              'periods': {k: v.view() for k, v in sorted(periods.items())},
              'trace': trace_out, 'cache_stats': cache_stats, 'resources': resources,
              'https': https, 'input_audit': dict(audit),
              'limitations': ['A and AAAA query types do not prove IPv6 DNS transport or website transport',
                              'shared recursive upstream can cross-warm A/B first queries',
                              'shadow DNS mirrors do not reproduce the original persistent TCP connection',
                              'cache process counters include probe queries; use filtered trace for workload hit comparison',
                              'no WAN/WireGuard interruption or reboot is inferred from this report',
                              'no 24-hour pass/fail is inferred from elapsed time alone']}
    return result


def markdown(report):
    counts = report['balance']
    lines = ['# 24 小时真实流量 DNS 对照快照', '',
             '本报告仅含聚合数据。增量快照不代表 24 小时测试已完成；错误与超时单列，延迟分位数只看成功回答。', '',
             '- Runner 已结束：%s；采集完整性状态：%s。' % (report['runner_finished'], report['runner_complete']),
             '- 主流量：%d 对；已调度 %d 对；队列拒绝/未调度 %d 对；双方完整写出 %d 对。' % (counts['main_flow_arrivals'], counts['main_flow_dispatched_pairs'], counts['main_flow_unsent_pairs'], counts['main_flow_both_wire_sent_pairs']),
             '- 窗内捕获 %d 条，窗内结果 %d 条，窗内差值 %d；窗前 %d 条、窗后尾段 %d 条单列；capture sequence 缺口 %d。' %
             (counts['capture_in_observation_window'], counts['runner_in_observation_window'],
              counts['capture_window_minus_runner_records'], counts['capture_before_observation_window'],
              counts['capture_after_observation_window'], counts['capture_sequence_gaps']), '',
             '| 时段 | 组 | 已尝试 | 失败 | 超时 | 成功均值 ms | P50 | P90 | P99 | 最大值 |',
             '|---|---|---:|---:|---:|---:|---:|---:|---:|---:|']
    def fmt(value):
        return '—' if value is None else '%.3f' % value
    for period in ('all', 'first_hour', 'stable_after_first_hour'):
        if period not in report['periods']:
            continue
        for arm, row in report['periods'][period]['arms'].items():
            latency = row['success_latency']
            lines.append('| %s | %s | %d | %d | %d | %s | %s | %s | %s | %s |' %
                         (period, arm.upper(), row['attempted'], row['failed'], row['timeouts'],
                          *(fmt(latency[x]) for x in ('mean_ms', 'p50_ms', 'p90_ms', 'p99_ms', 'max_ms'))))
    lines += ['', '少于 1000 个成功样本的 P99 标记为稀疏估计；15 分钟窗口、CN/境外、A/AAAA、UDP/TCP及成对差值见 report.json。', '',
              '命中分类只依据 C trace 标志，不从延迟推断。国内/境外先看固定规则；不支持的正则由无冲突的实际 dispatch lane 证据补足；规则或 trace 冲突保留 unknown。基线无法区分首次、淘汰、到期与绕过时，保留 unavailable。', '',
              'HTTPS 为保留 Host/SNI 并校验证书的固定 IP HTTP GET。报告不代表浏览器完整渲染；正文不输出域名、IP 或请求历史。', '',
              '上游计数为 C 事务及重传，不等同于抓包精确报文数。普通 stderr 缓存累计指标包含业务探测；无法精确分配到 15 分钟窗口。', '',
              '运行中的 trace 有 stdio 缓冲延迟；窗内缺失结果可能包含尚未完成请求，窗后采集尾段单列。必须结合最终 receipt、漏采计数及进程状态判定完整性。', '']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True, help='must be a new directory')
    parser.add_argument('--rules', action='append', type=Path, default=[])
    parser.add_argument('--start-unix-ns', type=int)
    parser.add_argument('--start-mono-ns', type=int)
    for name in ('runner', 'capture', 'capture-stderr', 'https', 'resources', 'a-trace', 'b-trace', 'a-stderr', 'b-stderr'):
        parser.add_argument('--' + name, type=Path)
    args = parser.parse_args()
    overrides = {name: getattr(args, name) for name in ('runner', 'capture', 'capture_stderr', 'https', 'resources', 'a_trace', 'b_trace', 'a_stderr', 'b_stderr')}
    result = build_report(args.input, args.rules, args.start_unix_ns, args.start_mono_ns, overrides)
    args.output.mkdir(mode=0o700, parents=False, exist_ok=False)
    for name, contents in (('report.json', json.dumps(result, ensure_ascii=False, indent=2) + '\n'),
                           ('SUMMARY.md', markdown(result))):
        fd = os.open(args.output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            stream.write(contents)
    print('wrote aggregate report.json and SUMMARY.md')


if __name__ == '__main__':
    main()
