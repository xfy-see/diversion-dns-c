#!/usr/bin/env python3
"""Owned-netns runner for tail-latency attribution (diagnostic; never targets a router).

Must run as root inside a freshly created network namespace, exactly like the kernel test
profile, e.g.:

  sudo -n unshare --net --pid --fork --mount-proc --kill-child sh -c \\
    'ip link set lo up; exec env DIVERSION_OWNED_NETNS=1 python3 scripts/tail_attribution_run.py \\
       --app head=<static bundle>/diversion --helpers <suite-helpers>/amd64 --output <fresh dir> --plan full'

It reproduces the device-profile setup of scripts/suite_device.py on loopback (same config keys,
cn.test rules, inet table with cn4/cn6 timeout sets, nftset_fast=1, cache_size=8192, synthetic
fixture upstream with TTL 30) and the five device scenarios plus the 500 QPS stability load.
Original load.go runs (trace off) are judged with the unchanged suite_metrics criteria; diagload
runs with DIVERSION_TRACE are attribution-only and never feed pass/fail.
"""
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import suite_device  # noqa: E402
import tail_attribution  # noqa: E402

TABLE = 'diversion_tail'
LISTEN = '127.0.0.1:15353'
FIXTURE = '127.0.0.1:15531'
SCENARIOS = {x['id']: dict(x) for x in suite_device.SCENARIOS}
SCENARIOS['stability-hot-udp-mixed-500'] = dict(id='stability-hot-udp-mixed-500', net='udp', type='mixed',
                                                  rate=500, seconds=60, unique=False)


def sh(cmd, **kw):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout


def nft_setup(fast=True):
    sh(['nft', '-f', '-'], input=f'''table inet {TABLE} {{
set cn4 {{ type ipv4_addr; flags timeout; size 16384; }}
set cn6 {{ type ipv6_addr; flags timeout; size 16384; }}
}}
''')


def nft_reset():
    subprocess.run(['nft', 'delete', 'table', 'inet', TABLE], capture_output=True)
    nft_setup()


def config(folder, extra=()):
    (folder / 'cn.txt').write_text('domain:cn.test\n')
    lines = ['listen_udp=' + LISTEN, 'listen_tcp=' + LISTEN, 'cache_size=8192',
             f'nftset_ipv4=inet,{TABLE},cn4,ipv4_addr,32', f'nftset_ipv6=inet,{TABLE},cn6,ipv6_addr,128',
             'nftset_fast=1', 'cn_domain_file=' + str(folder / 'cn.txt'),
             'cn_upstream=' + FIXTURE, 'foreign_upstream=' + FIXTURE]
    for item in extra:  # later keys override (e.g. nftset_fast=0 for the CLI-path variant)
        key = item.split('=', 1)[0]
        lines = [x for x in lines if not x.startswith(key + '=')] + [item]
    (folder / 'config.conf').write_text('\n'.join(lines) + '\n')


def wait_port():
    host, port = LISTEN.rsplit(':', 1)
    for _ in range(200):
        try:
            with socket.create_connection((host, int(port)), .1):
                return
        except OSError:
            time.sleep(.02)
    raise TimeoutError('application readiness')


class App:
    def __init__(self, app, folder, cpu, trace):
        env = dict(os.environ)
        env.pop('DIVERSION_TRACE', None)
        env['DIVERSION_NFT_STATS'] = '1'  # builds with the counters print applies/skipped/transactions at exit
        if trace:
            env['DIVERSION_TRACE'] = str(folder / 'trace.tsv')
        self.log = (folder / 'app.log').open('w')
        self.proc = subprocess.Popen([str(app), 'start', '-c', str(folder / 'config.conf'), '--cpu', str(cpu)],
                                     stdout=self.log, stderr=self.log, env=env)
        wait_port()

    def stop(self):
        self.proc.terminate()
        self.proc.wait(timeout=15)
        self.log.close()


def load_args(helpers, tool, spec, extra=()):
    argv = [str(helpers / tool), '-addr', LISTEN, '-net', spec['net'], '-type', spec['type'],
            '-rate', str(spec['rate']), '-seconds', str(spec['seconds'])]
    argv += ['-unique', '-offset', '20000'] if spec['unique'] else ['-name', 'hot.cn.test']
    return argv + list(extra)


def run_one(args, name, app, spec, tool, folder, trace, cfg_extra=(), load_extra=()):
    folder.mkdir(parents=True)
    nft_reset()
    config(folder, cfg_extra)
    a = App(app, folder, args.cpu, trace)
    row = dict(app=name, scenario=spec['id'], tool=tool, trace=trace, config_extra=list(cfg_extra),
               load_extra=list(load_extra), folder=str(folder))
    try:
        if not spec['unique']:
            warm = dict(spec, net='udp', type='mixed', rate=2, seconds=1)
            w = subprocess.run(load_args(args.helpers, 'load', warm, ['-workers', '32']), capture_output=True,
                               text=True, timeout=30, check=True)
            (folder / 'warmup.json').write_text(w.stdout)
            require_warm = suite_device.summarize_raw(json.loads(w.stdout), warm)
            row['warmup_strict_pass'] = require_warm['strict_rate_pass']
        p = subprocess.run(load_args(args.helpers, tool, spec, load_extra), capture_output=True, text=True,
                           timeout=spec['seconds'] + 60, check=True)
        raw_name = 'load.json' if tool == 'load' else 'client.json'
        (folder / raw_name).write_text(p.stdout)
        raw = json.loads(p.stdout)
        sets = json.loads(sh(['nft', '-j', 'list', 'table', 'inet', TABLE]))
        (folder / 'sets.json').write_text(json.dumps(sets))
    finally:
        a.stop()
    if tool == 'load':
        m = suite_device.summarize_raw(raw, spec)
        actual = suite_device.nft_addresses(sets, TABLE)
        expected = suite_device.expected_addresses(raw['samples'], spec['unique'])
        m['nftset_exact_addresses_pass'] = actual == expected
        m['pass'] = m['functional_pass'] and m['strict_rate_pass'] and m['nftset_exact_addresses_pass']
        m.pop('samples', None)
        (folder / 'metrics.json').write_text(json.dumps(m, indent=1))
        row['metrics'] = {k: m.get(k) for k in ('pass', 'functional_pass', 'strict_rate_pass', 'nftset_exact_addresses_pass',
                                               'offered', 'sent', 'success', 'unsent', 'errors', 'p50_ms', 'p99_ms',
                                               'p999_ms', 'max_ms', 'send_late_max_ms', 'late_send_count', 'first10', 'last10')}
    stats = re.search(r'applies=(\d+) skipped=(\d+) transactions=(\d+)', (folder / 'app.log').read_text())
    if stats:
        row['nft_stats'] = dict(zip(('applies', 'skipped', 'transactions'), map(int, stats.groups())))
    if trace:
        with open(folder / 'trace.tsv') as f:
            tr = tail_attribution.parse_trace(f)
        q = [t for t in tr if t['kind'] == 'Q' and t['reply']]
        row['trace_counts'] = dict(
            replies=len(q), nft_applies=sum(1 for t in q if t['nft0']),
            nft_kernel_io=sum(1 for t in q if t['nft_io']),
            nft_skip=sum(1 for t in q if t['flags'] & tail_attribution.FLAGS['nft_skip']),
            srv_over_2ms=sum(1 for t in q if t['reply'] - t['recv'] > 2_000_000),
            nft_over_2ms=sum(1 for t in q if t['nft0'] and t['nft1'] - t['nft0'] > 2_000_000))
        if tool == 'diagload':
            res = tail_attribution.analyze(raw, tr)
            (folder / 'attribution.json').write_text(json.dumps(res, indent=1))
            row['attribution'] = {k: res[k] for k in ('planned', 'answered', 'matched', 'unsent', 'errors', 'tail')}
            row['attribution']['all'] = {k: res['all'].get(k) for k in (
                'client_late', 'client_rtt', 'e2e_from_slot', 'srv_total', 'srv_queue_wait', 'upstream', 'nft_total',
                'nft_wait', 'nft_io', 'net_and_kernel', 'client_connect')}
            if 'tcp_excluding_connect' in res:
                row['attribution']['tcp_excluding_connect'] = {k: res['tcp_excluding_connect'].get(k) for k in (
                    'e2e_from_slot', 'client_rtt', 'srv_total')}
            row['attribution']['refresh_records'] = res['refresh_records']
    print(json.dumps({k: row[k] for k in ('app', 'scenario', 'tool', 'trace', 'config_extra', 'load_extra')}
                     | {'pass': row.get('metrics', {}).get('pass'), 'tail': row.get('attribution', {}).get('tail')}), flush=True)
    return row


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--app', action='append', required=True, help='name=path; first is the attribution target')
    ap.add_argument('--helpers', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--cpu', type=int, default=4)
    ap.add_argument('--plan', choices=('full', 'regression', 'smoke', 'compare'), default='full')
    ap.add_argument('--repeats', type=int, default=3)
    args = ap.parse_args()
    assert os.geteuid() == 0 and os.environ.get('DIVERSION_OWNED_NETNS') == '1', 'owned netns root required'
    tables = json.loads(sh(['nft', '-j', 'list', 'tables']))
    assert not any('table' in x for x in tables['nftables']), 'namespace must initially contain no tables'
    out = args.output.resolve()
    assert not out.exists(), 'fresh output required'
    out.mkdir(parents=True)
    apps = [(x.split('=', 1)[0], Path(x.split('=', 1)[1]).resolve()) for x in args.app]
    fixture = subprocess.Popen([str(args.helpers / 'fixture'), '-addr', FIXTURE],
                               stdout=(out / 'fixture.log').open('w'), stderr=subprocess.STDOUT)
    time.sleep(.5)
    rows = []
    n = 0

    def go(name, app, sid, tool, trace, cfg_extra=(), load_extra=(), tag='', spec_over=None):
        nonlocal n
        n += 1
        spec = dict(SCENARIOS[sid], **(spec_over or {}))
        label = '%03d-%s-%s-%s%s' % (n, name, spec['id'], tool, tag)
        try:
            rows.append(run_one(args, name, app, spec, tool, out / label, trace, cfg_extra, load_extra))
        except Exception as e:  # keep going; raw folder retained
            rows.append(dict(app=name, scenario=spec['id'], tool=tool, folder=str(out / label), error=repr(e)))
            print(json.dumps(rows[-1]), flush=True)
        (out / 'rows.json').write_text(json.dumps(rows, indent=1))
    try:
        target_name, target = apps[0]
        if args.plan in ('full', 'smoke'):
            ids = list(SCENARIOS) if args.plan == 'full' else ['cold-udp-a', 'hot-tcp-mixed']
            for sid in ids:
                over = dict(rate=20, seconds=1) if args.plan == 'smoke' else None
                go(target_name, target, sid, 'load', False, spec_over=over)                       # original criteria
                go(target_name, target, sid, 'load', True, tag='-traced', spec_over=over)          # trace overhead check
                go(target_name, target, sid, 'diagload', True, load_extra=['-workers', '32'], tag='-w32', spec_over=over)
                if args.plan == 'full':
                    go(target_name, target, sid, 'diagload', True, load_extra=['-workers', '512', '-predial'], tag='-w512p')
                    go(target_name, target, sid, 'diagload', True, cfg_extra=['nftset_fast=0'],
                       load_extra=['-workers', '512', '-predial'], tag='-w512p-nftcli')
            if args.plan == 'full':
                for rate in (500, 1000, 2000, 3000, 4000):   # diagnostic step loads only
                    go(target_name, target, 'hot-udp-mixed', 'diagload', True, load_extra=['-workers', '512', '-predial'],
                       tag='-step%d' % rate, spec_over=dict(rate=rate, seconds=10))
                for rate in (250, 500, 1000, 2000):
                    go(target_name, target, 'cold-udp-a', 'diagload', True, load_extra=['-workers', '512', '-predial'],
                       tag='-step%d' % rate, spec_over=dict(rate=rate, seconds=5))
        if args.plan == 'compare':   # Stage 1/4 comparison: every app, rotated order per repeat
            for r in range(args.repeats):
                order = apps[r % len(apps):] + apps[:r % len(apps)]
                for name, app in order:
                    for sid in ('hot-udp-mixed', 'hot-tcp-mixed', 'stability-hot-udp-mixed-500',
                                'cold-udp-a', 'cold-udp-aaaa', 'cold-tcp-mixed'):
                        over = dict(seconds=20) if sid in ('hot-udp-mixed', 'stability-hot-udp-mixed-500') else None
                        go(name, app, sid, 'load', False, tag='-cmp%d' % r, spec_over=over)
                        go(name, app, sid, 'diagload', True, load_extra=['-workers', '32'], tag='-cmp%d-w32' % r,
                           spec_over=over)
                    for sid in ('hot-udp-mixed', 'cold-udp-a'):
                        over = dict(seconds=20) if sid == 'hot-udp-mixed' else None
                        go(name, app, sid, 'load', False, cfg_extra=['nftset_fast=0'], tag='-cmp%d-nftcli' % r,
                           spec_over=over)
                        go(name, app, sid, 'diagload', True, cfg_extra=['nftset_fast=0'], load_extra=['-workers', '32'],
                           tag='-cmp%d-nftcli-w32' % r, spec_over=over)
        if args.plan in ('full', 'regression'):
            for r in range(args.repeats):
                order = apps if r % 2 == 0 else apps[::-1]
                for name, app in order:
                    for sid in ('hot-udp-mixed', 'hot-tcp-mixed', 'stability-hot-udp-mixed-500'):
                        go(name, app, sid, 'load', False, tag='-reg%d' % r,
                           spec_over=dict(seconds=20) if sid != 'hot-tcp-mixed' else None)
    finally:
        fixture.terminate()
        fixture.wait(timeout=10)
        subprocess.run(['nft', 'delete', 'table', 'inet', TABLE], capture_output=True)
        (out / 'rows.json').write_text(json.dumps(rows, indent=1))
    return 0 if all('error' not in r for r in rows) else 1


if __name__ == '__main__':
    sys.exit(main())
