#!/usr/bin/env python3
"""Real-kernel regression for the default (nftset_fast=0) path and worker lanes.

Run only inside a fresh, owned network namespace. Never compiles. Uses a
caller-supplied application and isolated loopback UDP upstreams.

Checks:
  cli-external-writers   H3: concurrent external nft writers vs. CLI-path CN writes
  foreign-blackhole-lanes H1: dead foreign upstream must not delay CN/foreign cache hits
  small-thread-stack      M3: RLIMIT_STACK=128 KiB (glibc default thread stack) CN write
  foreign-lane-recovery   R1: stale queued jobs are dropped; identical in-flight queries coalesce
  tcp-slow-readers        R2: TCP clients that never read cannot make UDP CN cache hits SERVFAIL
  tcp-connection-limits   M5: 1-byte TCP clients cannot lock out new TCP clients; read/write deadlines
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import resource
import socket
import struct
import subprocess
import threading
import time


def question(name, qtype=1, ident=0x1234):
    wire = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
    return struct.pack('!6H', ident, 0x100, 1, 0, 0, 0) + wire + struct.pack('!2H', qtype, 1)


def decode_question(q):
    pos, labels = 12, []
    while q[pos]:
        n = q[pos]; labels.append(q[pos+1:pos+1+n].decode()); pos += n+1
    return '.'.join(labels), struct.unpack_from('!H', q, pos+1)[0], pos+5


def address(name, qtype):
    """Stable per-name test address inside documentation/benchmark ranges."""
    h = int.from_bytes(name.encode()[-8:].rjust(8, b'\0'), 'big') ^ sum(name.encode()) * 2654435761
    if qtype == 1:
        return str(ipaddress.ip_address(int(ipaddress.ip_address('198.18.0.0')) + 1 + h % 131000))
    return str(ipaddress.ip_address(int(ipaddress.ip_address('2001:db8::')) + 1 + h % (1 << 40)))


class Upstream:
    """UDP authoritative double. blackhole=True silently drops every query; names
    starting with "dead" are always dropped; "big" A names get 4000 records (~64 KB)."""
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('127.0.0.1', 0)); self.port = self.sock.getsockname()[1]
        self.blackhole = False; self.closed = False
        self.lock = threading.Lock(); self.counts = {}
        threading.Thread(target=self.serve, daemon=True).start()

    def count(self, name):
        with self.lock:
            return self.counts.get(name, 0)

    def serve(self):
        while not self.closed:
            try:
                q, peer = self.sock.recvfrom(65535)
            except OSError:
                return
            try:
                name, qt, end = decode_question(q)
            except (IndexError, UnicodeDecodeError):
                continue
            with self.lock:
                self.counts[name] = self.counts.get(name, 0) + 1
            if self.blackhole or name.startswith('dead'):
                continue
            if name.startswith('big') and qt == 1:
                answer = struct.pack('!6H', struct.unpack('!H', q[:2])[0], 0x8180, 1, 4000, 0, 0) + q[12:end]
                answer += b''.join(b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 300, 4) + bytes([10, 0, k >> 8, k & 255])
                                   for k in range(4000))
                try:
                    self.sock.sendto(answer, peer)
                except OSError:
                    pass
                continue
            answer = struct.pack('!6H', struct.unpack('!H', q[:2])[0], 0x8180, 1, 1, 0, 0) + q[12:end]
            data = ipaddress.ip_address(address(name, qt)).packed
            answer += b'\xc0\x0c' + struct.pack('!HHIH', qt, 1, 300, len(data)) + data
            try:
                self.sock.sendto(answer, peer)
            except OSError:
                pass

    def close(self):
        self.closed = True; self.sock.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--application', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--queries', type=int, default=600)
    ap.add_argument('--max-servfail', type=int, default=0)
    ap.add_argument('--max-p99-ms', type=float, default=200.0)
    ap.add_argument('--only', choices=['cli-external-writers', 'foreign-blackhole-lanes', 'small-thread-stack',
                                       'foreign-lane-recovery', 'tcp-slow-readers', 'tcp-connection-limits'])
    ap.add_argument('--max-recovery-s', type=float, default=15.0,
                    help='R1: longest tolerated healthy-foreign failure window after a blackhole burst')
    ap.add_argument('--no-assert', action='store_true', help='measure only (for before/after comparisons)')
    args = ap.parse_args()
    app, out = args.application.resolve(), args.output.resolve()
    assert os.geteuid() == 0, 'requires namespace root'
    assert os.environ.get('DIVERSION_OWNED_NETNS') == '1', 'explicit isolated namespace required'
    assert not out.exists(), 'fresh evidence directory required'
    out.mkdir(parents=True)
    commands, checks, metrics = [], [], {}
    table = 'nft_cli_review'

    def nft(text, json_args=None, record=True):
        cmd = ['nft', '-j'] + json_args if json_args else ['nft', '-f', '-']
        p = subprocess.run(cmd, input=None if json_args else text, text=True, capture_output=True, timeout=10)
        if record:
            commands.append({'command': cmd, 'input': text, 'rc': p.returncode, 'err': p.stderr})
        assert p.returncode == 0, (cmd, text, p.stderr)
        return json.loads(p.stdout) if json_args else None

    assert not any('table' in x for x in nft('', ['list', 'tables'])['nftables']), 'namespace must initially contain no tables'
    nft(f'''table inet {table} {{
set learn4 {{ type ipv4_addr; }}
set learn6 {{ type ipv6_addr; }}
set unrelated {{ type ipv4_addr; flags timeout; }}
}}\n''')
    (out/'cn.txt').write_text('domain:cn\n')
    cn_up, foreign_up = Upstream(), Upstream()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]; sock.close()

    def config(name, extra=''):
        path = out/(name+'.conf')
        path.write_text(f'''listen_udp=127.0.0.1:{port}
listen_tcp=127.0.0.1:{port}
cn_domain_file={out}/cn.txt
cn_upstream=127.0.0.1:{cn_up.port}
foreign_upstream=127.0.0.1:{foreign_up.port}
cache_size=4096
nftset_ipv4=inet,{table},learn4,ipv4_addr,32
nftset_ipv6=inet,{table},learn6,ipv6_addr,128
nftset_fast=0
{extra}''')
        return path

    def query(name, qtype=1, timeout=7.0, source='127.0.0.1'):
        q = question(name, qtype)
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind((source, 0))
            s.settimeout(timeout); s.sendto(q, ('127.0.0.1', port))
            try:
                r = s.recv(65535)
            except socket.timeout:
                return 'TIMEOUT', (time.monotonic()-started)*1000
        return {0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN'}.get(r[3] & 15, str(r[3] & 15)), (time.monotonic()-started)*1000

    def tcp_query(name, qtype=1, timeout=7.0, source='127.0.0.1'):
        q = question(name, qtype)
        started = time.monotonic()
        try:
            with socket.socket() as s:
                s.settimeout(timeout); s.bind((source, 0)); s.connect(('127.0.0.1', port))
                s.sendall(struct.pack('!H', len(q)) + q)
                data = b''
                while len(data) < 2 or len(data) < 2 + struct.unpack('!H', data[:2])[0]:
                    chunk = s.recv(65537)
                    if not chunk:
                        return 'CLOSED', (time.monotonic()-started)*1000
                    data += chunk
        except socket.timeout:
            return 'TIMEOUT', (time.monotonic()-started)*1000
        except OSError as e:
            return type(e).__name__, (time.monotonic()-started)*1000
        r = data[2:]
        return {0: 'NOERROR', 2: 'SERVFAIL', 3: 'NXDOMAIN'}.get(r[3] & 15, str(r[3] & 15)), (time.monotonic()-started)*1000

    def established():
        """Server-side established TCP connections on the service port."""
        p = subprocess.run(['ss', '-tnH', 'state', 'established', f'( sport = :{port} )'],
                           capture_output=True, text=True, timeout=10)
        return len([x for x in p.stdout.splitlines() if x.strip()])

    class App:
        def __init__(self, name, stack=None, cpu='4', extra=''):
            self.log = (out/(name+'.log')).open('w')
            def limit():
                if stack:
                    resource.setrlimit(resource.RLIMIT_STACK, (stack, stack))
            self.proc = subprocess.Popen([str(app), 'start', '-c', str(config(name, extra)), '--cpu', cpu],
                                         stdout=self.log, stderr=self.log, preexec_fn=limit)
            for _ in range(200):
                assert self.proc.poll() is None, f'application exited: see {name}.log'
                try:
                    with socket.create_connection(('127.0.0.1', port), .1): return
                except OSError: time.sleep(.02)
            raise TimeoutError('application readiness')

        def stop(self):
            rc = self.proc.poll()
            if rc is None:
                self.proc.terminate(); rc = self.proc.wait(timeout=15)
            self.log.close(); return rc

    def percentile(values, p):
        values = sorted(values)
        return values[min(len(values)-1, int(len(values)*p/100))] if values else None

    def elements(name):
        data = nft('', ['list', 'set', 'inet', table, name], record=False)
        value = next(x['set'] for x in data['nftables'] if 'set' in x)
        return {x if isinstance(x, str) else x.get('elem', x).get('val') for x in value.get('elem', [])}

    def run_check(label, fn):
        if args.only and args.only != label:
            return
        result = fn(); metrics[label] = result
        if not args.no_assert:
            assert result['ok'], (label, result)
        checks.append(label)
        print(json.dumps({label: result}), flush=True)

    def cli_external_writers():
        nft(f'flush set inet {table} learn4\nflush set inet {table} learn6')
        a = App('cli-external-writers')
        stop, writes, errors = threading.Event(), [0], []
        def writer(seed):
            i = 0
            while not stop.is_set():
                i += 1
                p = subprocess.run(['nft', 'add', 'element', 'inet', table, 'unrelated',
                                    f'{{ 10.{seed}.{(i >> 8) & 255}.{i & 255} timeout 30s }}'], capture_output=True, text=True)
                if p.returncode: errors.append(p.stderr); return
                writes[0] += 1
        writers = [threading.Thread(target=writer, args=(k,)) for k in (1, 2)]
        for w in writers: w.start()
        time.sleep(.2)
        names = [(f'w{i}.cn', 1 if i % 4 else 28) for i in range(args.queries)]
        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda nq: query(*nq), names))
        elapsed = time.monotonic() - started
        stop.set()
        for w in writers: w.join()
        rc = a.stop()
        rcodes = {}
        for code, _ in results: rcodes[code] = rcodes.get(code, 0) + 1
        learned4, learned6 = elements('learn4'), elements('learn6')
        missing = [n for (n, qt), (code, _) in zip(names, results) if code == 'NOERROR'
                   and address(n, qt) not in (learned4 if qt == 1 else learned6)]
        failures = rcodes.get('SERVFAIL', 0) + rcodes.get('TIMEOUT', 0)
        log = (out/'cli-external-writers.log').read_text().splitlines()
        reasons = {}
        for line in log:
            if line.startswith('query failed: '): reasons[line[14:]] = reasons.get(line[14:], 0) + 1
        return {'ok': failures <= args.max_servfail and not missing and not errors and writes[0] > 50 and rc == 0,
                'queries': len(names), 'rcodes': rcodes, 'external_writes': writes[0], 'writer_errors': errors[:3],
                'elapsed_s': round(elapsed, 3), 'missing_learned': len(missing), 'failure_reasons': reasons, 'exit': rc}

    def foreign_blackhole_lanes():
        a = App('foreign-blackhole-lanes')
        warm_cn = [f'hit{i}.cn' for i in range(40)]
        for n in warm_cn: assert query(n)[0] == 'NOERROR', n
        assert query('warm.example')[0] == 'NOERROR'
        foreign_up.blackhole = True
        try:
            pool = concurrent.futures.ThreadPoolExecutor(max_workers=100)
            stuck = [pool.submit(query, f'dead{i}.example') for i in range(80)]
            time.sleep(.5)
            hits, foreign_hits, misses = [], [], []
            for round_ in range(5):
                for n in warm_cn: hits.append(query(n))
                foreign_hits.append(query('warm.example'))
                misses.append(query(f'miss{round_}.cn'))
            stuck_codes = {}
            for f in stuck:
                code = f.result()[0]; stuck_codes[code] = stuck_codes.get(code, 0) + 1
            pool.shutdown()
        finally:
            foreign_up.blackhole = False
        rc = a.stop()
        lat = [ms for _, ms in hits]; codes = {c for c, _ in hits + foreign_hits + misses}
        p99 = percentile(lat, 99)
        return {'ok': codes == {'NOERROR'} and p99 < args.max_p99_ms and percentile([m for _, m in foreign_hits], 99) < args.max_p99_ms and rc == 0,
                'cn_cache_hits': len(hits), 'cn_hit_p50_ms': round(percentile(lat, 50), 2), 'cn_hit_p99_ms': round(p99, 2),
                'cn_hit_max_ms': round(max(lat), 2), 'foreign_cache_hit_max_ms': round(max(m for _, m in foreign_hits), 2),
                'cn_miss_max_ms': round(max(m for _, m in misses), 2), 'rcodes_seen': sorted(codes),
                'blackholed_foreign_rcodes': stuck_codes, 'exit': rc}

    def small_thread_stack():
        a = App('small-thread-stack', stack=128*1024)
        results = [query(f'stack{i}.cn', 1 if i % 2 else 28) for i in range(4)]
        time.sleep(.2)
        alive = a.proc.poll() is None
        rc = a.stop()
        codes = [c for c, _ in results]
        return {'ok': alive and codes == ['NOERROR']*4 and rc == 0, 'rlimit_stack_kib': 128,
                'rcodes': codes, 'alive_after_queries': alive, 'exit': rc}

    def foreign_lane_recovery():
        # R1: 68 distinct never-answered foreign queries fill the foreign lane
        # (4 workers each blocked for the 5 s upstream budget + 64-job quota).
        # Previously the queue drained 4 jobs per 5 s (~80 s outage); stale jobs
        # are now answered SERVFAIL without upstream I/O once queue_timeout_ms passes.
        a = App('foreign-lane-recovery')
        assert query('warm.example')[0] == 'NOERROR'
        pool = concurrent.futures.ThreadPoolExecutor(max_workers=80)
        stuck = [pool.submit(query, f'dead{i}.example', 1, 3.0) for i in range(68)]
        time.sleep(.5)
        started, probes, recovered = time.monotonic(), {}, None
        i = 0
        while time.monotonic() - started < args.max_recovery_s + 30:
            i += 1
            code, ms = query(f'healthy{i}.example', 1, 1.0)
            probes[code] = probes.get(code, 0) + 1
            if code == 'NOERROR':
                recovered = time.monotonic() - started; break
            time.sleep(max(0, .25 - ms/1000))
        for f in stuck: f.result()
        # Coalescing: identical retries of one dead name share a single upstream
        # exchange, so the other foreign workers stay free for healthy queries.
        time.sleep(1)
        dup = [pool.submit(query, 'deadsame.example', 1, 3.0) for _ in range(30)]
        time.sleep(.5)
        dup_probe = query('healthy-during-dup.example', 1, 2.0)
        dup_codes = {}
        for f in dup:
            code = f.result()[0]; dup_codes[code] = dup_codes.get(code, 0) + 1
        pool.shutdown()
        time.sleep(.3)
        upstream_dup = foreign_up.count('deadsame.example')
        rc = a.stop()
        log = (out/'foreign-lane-recovery.log').read_text()
        dropped = log.count('query dropped: queued ')
        return {'ok': recovered is not None and recovered <= args.max_recovery_s and dropped > 0
                      and dup_probe[0] == 'NOERROR' and dup_probe[1] < 1000 and upstream_dup <= 8 and rc == 0,
                'healthy_failure_window_s': None if recovered is None else round(recovered, 2), 'probe_rcodes': probes,
                'stale_jobs_dropped': dropped, 'duplicate_burst_rcodes': dup_codes,
                'healthy_during_duplicates': [dup_probe[0], round(dup_probe[1], 2)],
                'upstream_packets_for_30_identical_queries': upstream_dup, 'exit': rc}

    def frame(name, ident=7):
        q = question(name, 1, ident)
        return struct.pack('!H', len(q)) + q

    def tcp_slow_readers():
        # R2: 70 TCP clients pipeline 80 queries for a cached ~64 KB foreign answer
        # and never read. Their pending replies used to hold the cached-lane quota
        # that UDP CN cache hits need. Per-IP limit and write deadline are relaxed
        # here so only the quota separation is under test.
        a = App('tcp-slow-readers', extra='tcp_max_connections_per_ip=128\ntcp_write_timeout=300\ntcp_idle_timeout=300\n')
        warm = [f'slowhit{i}.cn' for i in range(20)]
        for n in warm: assert query(n)[0] == 'NOERROR', n
        assert tcp_query('big.example')[0] == 'NOERROR'
        conns = []
        for _ in range(70):
            s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
            s.connect(('127.0.0.1', port)); s.sendall(frame('big.example') * 80); conns.append(s)
        time.sleep(1.5)
        held = established()
        udp = [query(n, 1, 3.0) for n in warm]
        tcp_new = tcp_query('slowhit0.cn', 1, 3.0)
        for s in conns: s.close()
        rc = a.stop()
        codes = {}
        for c, _ in udp: codes[c] = codes.get(c, 0) + 1
        return {'ok': codes == {'NOERROR': len(warm)} and tcp_new[0] == 'NOERROR' and held >= 64 and rc == 0,
                'slow_reader_connections': len(conns), 'server_established': held,
                'udp_cn_cache_hit_rcodes': codes, 'udp_cn_hit_max_ms': round(max(ms for _, ms in udp), 2),
                'new_tcp_cn_query': [tcp_new[0], round(tcp_new[1], 2)], 'exit': rc}

    def tcp_connection_limits():
        # M5: connections that send one byte and stall used to fill all 128 slots.
        a = App('tcp-connection-limits', extra='tcp_read_timeout=2\ntcp_write_timeout=2\ntcp_idle_timeout=300\n')
        assert query('limit.cn')[0] == 'NOERROR'
        result = {}
        same = []
        for _ in range(140):
            s = socket.socket(); s.connect(('127.0.0.1', port)); s.send(b'\xff'); same.append(s)
        time.sleep(.3)
        result['same_ip_held'] = established()
        result['same_ip_new_client'] = tcp_query('limit.cn', 1, 3.0)[0]
        many = []
        for i in range(200):
            s = socket.socket(); s.bind((f'127.0.{1 + i // 250}.{2 + i % 250}', 0))
            s.connect(('127.0.0.1', port)); s.send(b'\xff'); many.append(s)
        time.sleep(.3)
        result['multi_ip_held'] = established()
        result['multi_ip_new_client'] = tcp_query('limit.cn', 1, 3.0, source='127.0.9.9')[0]
        time.sleep(3.5)
        result['after_read_timeout_established'] = established()
        for s in same + many: s.close()
        # Write deadline: a client that pipelines large answers and never reads is
        # closed after tcp_write_timeout even though the kernel accepted some bytes.
        assert tcp_query('big.example')[0] == 'NOERROR'
        slow = socket.socket(); slow.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        slow.connect(('127.0.0.1', port)); slow.sendall(frame('big.example') * 40)
        time.sleep(.5)
        result['slow_reader_established'] = established()
        time.sleep(3.5)
        result['slow_reader_after_write_timeout'] = established()
        slow.close()
        result['udp_after'] = query('limit2.cn')[0]
        result['exit'] = a.stop()
        result['ok'] = (result['same_ip_held'] <= 32 and result['same_ip_new_client'] == 'NOERROR'
                        and result['multi_ip_held'] <= 128 and result['multi_ip_new_client'] == 'NOERROR'
                        and result['after_read_timeout_established'] == 0 and result['slow_reader_established'] == 1
                        and result['slow_reader_after_write_timeout'] == 0 and result['udp_after'] == 'NOERROR'
                        and result['exit'] == 0)
        return result

    complete = False
    try:
        run_check('cli-external-writers', cli_external_writers)
        run_check('foreign-blackhole-lanes', foreign_blackhole_lanes)
        run_check('small-thread-stack', small_thread_stack)
        run_check('foreign-lane-recovery', foreign_lane_recovery)
        run_check('tcp-slow-readers', tcp_slow_readers)
        run_check('tcp-connection-limits', tcp_connection_limits)
        complete = True
    finally:
        cn_up.close(); foreign_up.close()
        (out/'result.json').write_text(json.dumps({'passed': complete, 'checks': checks, 'count': len(checks), 'metrics': metrics,
            'kernel': os.uname().release, 'application': str(app), 'commit': os.environ.get('GITHUB_SHA'),
            'run_id': os.environ.get('GITHUB_RUN_ID'), 'commands': commands}, indent=2))
        nft(f'delete table inet {table}')
    print(json.dumps({'passed': True, 'checks': checks, 'kernel': os.uname().release}))


if __name__ == '__main__': main()
