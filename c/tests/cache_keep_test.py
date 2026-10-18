#!/usr/bin/env python3
"""Fixed-list scheduled DNS cache maintenance; existing binary only, loopback.
All upstream packets, client responses, logs and failures are retained.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
import traceback
from cache_refresh_safety_test import Suite, OLD, NEW, Policy, question


class KeepSuite(Suite):
    def listing(self, label, text):
        path = self.output / (label + '.list')
        path.write_text(text)
        return str(path)

    def stats(self, label):
        text = (self.output / label / 'stderr.log').read_text()
        line = next(line for line in text.splitlines() if line.startswith('cache stats foreign:'))
        return {k: int(v) for k, v in re.findall(r'(\w+)=(\d+)', line)}

    def idle_refresh(self):
        name = 'idle.keep.test'
        text = f'0 1 {name}\n0 28 {name}\n0 1 {name.upper()}\n0 1 skip.cn.test\n'
        path = self.listing('idle', text)
        self.upstream.set(name, ttl=8)
        with self.running('idle', cache_keep_file=path):
            self.wait_tx([name], 2, timeout=4)
            self.require(len(self.tx(['skip.cn.test'])) == 0, 'CN entry was queried')
            self.upstream.set(name, ttl=8, changed=True)
            # No frontend query before both address families refresh.
            self.wait_tx([name], 4, timeout=10)
            for typ in (1, 28):
                a = self.ask(name, typ)
                self.require(a['addresses'] == [NEW[typ]], 'idle refresh did not replace address')
                self.require(0 < min(a['ttls']) <= 8, 'TTL was extended')
            self.require(len(self.tx([name])) == 4, 'duplicate row/query or foreground miss')
        self.require(Path(path).read_text() == text, 'fixed list was rewritten')
        stats = self.stats('idle')
        self.require(stats['keep_query'] == stats['keep_ok'] == 4, 'keep stats differ')
        self.require(stats['fresh_hit'] == 2 and stats['miss_cold'] == 0, 'synthetic queries polluted user stats')
        self.require(stats['prefetch'] == 0 and stats['warm'] == 0, 'maintenance misclassified')

    def failure_recovery(self):
        name = 'recover.keep.test'
        path = self.listing('recover', f'0 1 {name}\n')
        self.upstream.set(name, ttl=6)
        with self.running('recover', cache_keep_file=path):
            self.wait_tx([name], 1)
            self.upstream.set(name, mode='servfail')
            self.wait_tx([name], 2, timeout=8)
            time.sleep(2)
            self.require(len(self.tx([name])) == 2, 'failure caused immediate retry storm')
            self.old(name)  # retained stale positive, background backoff respected
            self.upstream.set(name, ttl=30, changed=True)
            self.wait_tx([name], 3, timeout=8)
            self.require(self.ask(name)['addresses'] == [NEW[1]], 'no recovery after failure')
        stats = self.stats('recover')
        self.require(stats['keep_fail'] >= 1 and stats['keep_ok'] >= 2, 'failure/recovery not counted')

    def rate_and_fairness(self):
        names = [f'rate{i}.keep.test' for i in range(6)]
        path = self.listing('rate', ''.join(f'0 1 {n}\n' for n in names))
        for n in names:
            self.upstream.set(n, ttl=60)
        with self.running('rate', cache_keep_file=path, cache_keep_qps=2):
            self.wait_tx(names, 6, timeout=6)
            events = sorted(self.tx(names), key=lambda x: x['time'])
            self.require(all(b['time'] - a['time'] >= .45 for a, b in zip(events, events[1:])), 'pacing exceeded 2 QPS')
            self.require(len({e['name'] for e in events}) == 6, 'scheduler starved keys')
            self.old('foreground.unlisted.test')

    def negative_and_zero(self):
        names = ['negative.keep.test', 'zero.keep.test']
        path = self.listing('negative', ''.join(f'0 28 {n}\n' for n in names))
        self.upstream.set(names[0], mode='nodata_soa', ttl=2)
        self.upstream.set(names[1], ttl=0)
        with self.running('negative', cache_keep_file=path):
            self.wait_tx(names, 2)
            time.sleep(3)
            self.require(len(self.tx(names)) == 2, 'negative/TTL0 polled repeatedly')

    def disabled(self):
        name = 'disabled.keep.test'
        self.upstream.set(name, ttl=1)
        with self.running('disabled', cache_stale_ttl=0):
            self.old(name)
            time.sleep(2)
            self.require(len(self.tx([name])) == 1, 'default caused unsolicited query')
        self.require(self.stats('disabled')['keep_query'] == 0, 'disabled keep counters nonzero')

    def rejected(self):
        root = self.output / 'rejected'
        root.mkdir()
        rules = root / 'cn.txt'; rules.write_text('domain:cn.test\n')
        valid = root / 'valid'; valid.write_text('0 1 valid.keep.test\n')
        symlink = root / 'link'; symlink.symlink_to(valid)
        fifo = root / 'fifo'; os.mkfifo(fifo)
        cases = [
            ('wildcard', b'0 1 *.google.com\n', {}),
            ('literal', b'0 1 8.8.8.8\n', {}),
            ('nul', b'0 1 valid.keep.test\x00oops\n', {}),
            ('trailing', b'0 1 valid.keep.test extra\n', {}),
            ('type', b'0 65 valid.keep.test\n', {}),
            ('limit', ''.join(f'0 1 n{i}.keep.test\n' for i in range(257)).encode(), {}),
            ('oversize', b'#' * 65537, {}),
            ('rows', b'\n' * 1025, {}),
            ('emptycache', None, {'cache_size': 0}),
            ('smallcache', None, {'cache_size': 1}),
            ('qps', None, {'cache_keep_qps': 3}),
            ('percent', None, {'cache_keep_percent': 0}),
            ('alias', None, {'cache_warm_file': str(valid)}),
            ('symlink', None, {'cache_keep_file': str(symlink)}),
            ('fifo', None, {'cache_keep_file': str(fifo)}),
            ('missing', None, {'cache_keep_file': str(root / 'missing')}),
        ]
        for label, content, extra in cases:
            listing = valid
            if content is not None:
                listing = root / (label + '.list'); listing.write_bytes(content)
            config = dict(listen_udp='127.0.0.1:1', cn_domain_file=str(rules),
                          cn_upstream=f'127.0.0.1:{self.upstream.udp_port}',
                          foreign_upstream=f'127.0.0.1:{self.upstream.udp_port}',
                          cache_size=1024, cache_keep_file=str(listing))
            config.update(extra)
            conf = root / (label + '.conf')
            conf.write_text(''.join(f'{k}={v}\n' for k, v in config.items()))
            p = subprocess.run([self.application, 'check', '-c', conf], capture_output=True, timeout=5)
            (root / (label + '.stderr')).write_bytes(p.stderr)
            self.require(p.returncode != 0, f'invalid config accepted: {label}')
        self.require(valid.read_text() == '0 1 valid.keep.test\n', 'check changed file')


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--application', required=True, type=Path)
    p.add_argument('--output', required=True, type=Path)
    a = p.parse_args()
    suite = KeepSuite(a.application, a.output)
    result = dict(ok=False, binary_sha256=hashlib.sha256(a.application.read_bytes()).hexdigest(), cases=[])
    try:
        for case in ('rejected', 'disabled', 'idle_refresh', 'failure_recovery', 'rate_and_fairness', 'negative_and_zero'):
            getattr(suite, case)()
            result['cases'].append(case)
        result['ok'] = True
    except BaseException:
        result['error'] = traceback.format_exc()
        raise
    finally:
        # Only remove the two special fixture nodes we created, retaining their
        # identity as JSON. CI archives intentionally reject special files.
        nodes = []
        for name in ('link', 'fifo'):
            path = a.output / 'rejected' / name
            if path.is_symlink() or path.exists():
                nodes.append(dict(name=name, symlink=path.is_symlink(),
                                  target=os.readlink(path) if path.is_symlink() else None))
                path.unlink()
        (a.output / 'special-fixtures.json').write_text(json.dumps(nodes, indent=2))
        suite.upstream.close()
        (a.output / 'upstream.json').write_text(json.dumps(suite.upstream.snapshot(), indent=2))
        (a.output / 'clients.json').write_text(json.dumps(suite.clients, indent=2))
        (a.output / 'result.json').write_text(json.dumps(result, indent=2))
    print(json.dumps(result))


if __name__ == '__main__':
    main()
