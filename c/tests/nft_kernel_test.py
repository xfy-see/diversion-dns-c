#!/usr/bin/env python3
"""Real nf_tables regression. Run only inside a fresh, owned network namespace.

Never compiles. Uses a caller-supplied built application and an isolated local
TCP DNS upstream. No public resolvers, production sets or network sysctls.
"""
import argparse
import concurrent.futures
import ipaddress
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import threading
import time


def receive(s, n):
    out = bytearray()
    while len(out) < n:
        part = s.recv(n-len(out))
        if not part:
            raise EOFError("short TCP DNS frame")
        out.extend(part)
    return bytes(out)


def question(name, qtype):
    wire = b''.join(bytes([len(x)]) + x.encode() for x in name.split('.')) + b'\0'
    return struct.pack('!6H', 1234, 0x100, 1, 0, 0, 0) + wire + struct.pack('!2H', qtype, 1)


def decode_question(q):
    pos, labels = 12, []
    while q[pos]:
        n = q[pos]; labels.append(q[pos+1:pos+1+n].decode()); pos += n+1
    return '.'.join(labels), struct.unpack_from('!H', q, pos+1)[0], pos+5


def address(index, qtype):
    base = int(ipaddress.ip_address('198.18.0.0' if qtype == 1 else '2001:db8::'))
    return str(ipaddress.ip_address(base + index))


class Upstream(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class Answer(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            q = receive(self.request, struct.unpack('!H', receive(self.request, 2))[0])
            name, qt, end = decode_question(q)
            tag = name.split('.')[0]
            ttl, count, index = 60, 1, 2
            if tag == 'permanent': index = 1
            elif tag == 'short': ttl = 1
            elif tag == 'long': ttl = 600
            elif tag == 'high': ttl, index = 0xffffffff, 3
            elif tag == 'cap': ttl, index = 0x7fffffff, 4
            elif tag.startswith('bulk'):
                _, number, start = tag.split('-'); count, index = int(number), int(start)
            elif tag.startswith('race'): index = 10000 + int(tag[4:])
            elif tag.startswith('win'): index = 30000 + int(tag[3:])
            # Echo the query ID: the application sends a random upstream ID (M4).
            answer = q[:2] + struct.pack('!5H', 0x8180, 1, count, 0, 0) + q[12:end]
            for i in range(count):
                data = ipaddress.ip_address(address(index+i, qt)).packed
                answer += b'\xc0\x0c' + struct.pack('!HHIH', qt, 1, ttl, len(data)) + data
            self.request.sendall(struct.pack('!H', len(answer)) + answer)
        except (OSError, EOFError):
            pass


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--application', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    app, out = args.application.resolve(), args.output.resolve()
    assert os.geteuid() == 0, 'requires namespace root'
    assert os.environ.get('DIVERSION_OWNED_NETNS') == '1', 'explicit isolated namespace required'
    assert not out.exists(), 'fresh evidence directory required'
    out.mkdir(parents=True)
    checks, commands = [], []
    complete = False
    def nft(text, json_args=None):
        cmd = ['nft', '-j'] + json_args if json_args else ['nft', '-f', '-']
        p = subprocess.run(cmd, input=None if json_args else text, text=True, capture_output=True, timeout=10)
        commands.append({'command':cmd, 'input':text, 'rc':p.returncode, 'out':p.stdout, 'err':p.stderr})
        assert p.returncode == 0, (cmd, text, p.stderr)
        return json.loads(p.stdout) if json_args else None
    assert not any('table' in x for x in nft('', ['list','tables'])['nftables']), 'namespace must initially contain no tables'
    table = 'nft_review'
    setup = f'''table inet {table} {{
set learn4 {{ type ipv4_addr; flags timeout; size 16384; }}
set learn6 {{ type ipv6_addr; flags timeout; size 16384; }}
set unrelated {{ type ipv4_addr; }}
}}\n'''
    nft(setup)
    upstream = Upstream(('127.0.0.1', 0), Answer)
    worker = threading.Thread(target=upstream.serve_forever, daemon=True); worker.start()
    sock = socket.socket(); sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]; sock.close()
    (out/'cn.txt').write_text('domain:test\n')
    def write_config(fast=1, window='nftset_hit_window_ms=0\n'):
        # The historical sequence below runs with the hit-skip window disabled (0):
        # every CN answer is verified/written exactly as before Stage 1. The window
        # phase at the end re-runs the flush/delete/recreate/renew cases with the
        # default window (key omitted = 1000 ms) on both the fast and CLI paths.
        (out/'config.conf').write_text(f'''listen_tcp=127.0.0.1:{port}
cn_domain_file={out}/cn.txt
cn_upstream=tcp://127.0.0.1:{upstream.server_address[1]}
foreign_upstream=tcp://127.0.0.1:{upstream.server_address[1]}
cache_size=0
nftset_ipv4=inet,{table},learn4,ipv4_addr,32
nftset_ipv6=inet,{table},learn6,ipv6_addr,128
nftset_fast={fast}
{window}''')
    write_config()
    os.environ['DIVERSION_NFT_STATS'] = '1'  # shutdown counters in application.log
    proc = None
    log = (out/'application.log').open('w')
    def start():
        nonlocal proc
        proc = subprocess.Popen([str(app),'start','-c',str(out/'config.conf'),'--cpu','32'], stdout=log, stderr=log)
        for _ in range(100):
            assert proc.poll() is None, 'application exited: see application.log'
            try:
                with socket.create_connection(('127.0.0.1',port), .1): return
            except OSError: time.sleep(.02)
        raise TimeoutError('application readiness')
    def stop():
        nonlocal proc
        if proc is not None:
            proc.terminate(); proc.wait(timeout=10); proc = None
    def query(name, qt=1, rcode=0):
        q = question(name+'.test', qt)
        with socket.create_connection(('127.0.0.1',port), 6) as s:
            s.settimeout(6); s.sendall(struct.pack('!H', len(q))+q)
            response = receive(s, struct.unpack('!H',receive(s,2))[0])
        assert (response[3]&15) == rcode, (name, qt, rcode, response.hex())
        return response
    def elements(qt):
        data = nft('', ['list','set','inet',table,'learn4' if qt==1 else 'learn6'])
        value = next(x['set'] for x in data['nftables'] if 'set' in x)
        return value.get('elem', [])
    def expiry(qt, ip):
        for elem in elements(qt):
            if elem == ip: return None
            if isinstance(elem, dict):
                value = elem.get('elem',elem)
                if value.get('val') == ip: return value.get('expires')
        raise AssertionError(('missing element',qt,ip))
    def passed(name): checks.append(name)
    def stats():
        # Last "nftset stats:" line written by the stopped process (DIVERSION_NFT_STATS=1).
        lines = [x for x in (out/'application.log').read_text().splitlines() if x.startswith('nftset stats:')]
        assert lines, 'missing nftset stats line'
        return {k: int(v) for k, v in (kv.split('=') for kv in lines[-1].split(':', 1)[1].split())}
    observations = []
    def window_phase():
        """Stage 1 hit-skip window (default 1000 ms) on both paths.

        Accepted tradeoff (documented): after an external flush/delete/recreate the
        same address may stay unlearned for at most the window after this process
        last verified it; it is always relearned on the first answer after the
        window. Renewal never shortens and a longer TTL is never skipped."""
        W = 1.0
        def present(qt, ip):
            return any((x if isinstance(x, str) else x.get('elem', x).get('val')) == ip for x in elements(qt))
        for fast in (1, 0):
            label = 'fast' if fast else 'cli'
            stop(); write_config(fast, ''); nft(f'flush set inet {table} learn4\nflush set inet {table} learn6')
            start()
            # Write-count contract: 100 identical hot answers inside ~1 s.
            began = time.monotonic()
            for i in range(100): query('win1', 1 if i % 2 == 0 else 28)
            elapsed = time.monotonic() - began
            stop(); st = stats(); observations.append(dict(case=label+'-hot-100', elapsed_s=round(elapsed, 3), **st))
            assert st['applies'] == 100, st
            windows = int(elapsed / W) + 1
            # Per window at most one verifying pass per family (fast: one transaction for the
            # first write of each family; CLI: one transaction per family per window).
            assert st['skipped'] >= 100 - 2 * windows - 2, (st, elapsed)
            assert st['transactions'] <= 2 * windows + 2, (st, elapsed)
            assert present(1, address(30001, 1)) and present(28, address(30001, 28))
            passed(f'window-{label}-write-count-contract')
            start()
            for qt in (1, 28):
                tgt = 'learn4' if qt == 1 else 'learn6'
                for case, action in (('flush', f'flush set inet {table} {tgt}'),
                                     ('delete-element', f'delete element inet {table} {tgt} {{ {address(30002, qt)} }}'),
                                     ('recreate', f'delete table inet {table}\n' + setup)):
                    query('win2', qt); assert present(qt, address(30002, qt))
                    t0 = time.monotonic(); nft(action)
                    query('win2', qt); within = present(qt, address(30002, qt)); dt = time.monotonic() - t0
                    observations.append(dict(case=f'{label}-{case}-{qt}', relearned_within_window=within, seconds_after_change=round(dt, 3)))
                    time.sleep(W + 0.2)
                    query('win2', qt); assert present(qt, address(30002, qt)), (label, case, qt)
                    passed(f'window-{label}-{case}-relearn-after-window-{qt}')
            if fast:
                for qt in (1, 28):
                    # Short then long inside the window: the longer lease is never skipped.
                    nft(f'flush set inet {table} learn4\nflush set inet {table} learn6'); time.sleep(W + 0.2)
                    query('short', qt); query('long', qt); assert expiry(qt, address(2, qt)) > 590
                    # Long then short inside the window: never shortened (skip or verify).
                    query('short', qt); assert expiry(qt, address(2, qt)) > 590
                    passed(f'window-fast-renew-no-shorten-{qt}')
                    for _ in range(3): query('cap', qt)
                    e = expiry(qt, address(4, qt)); assert 0 < e <= 86400 + 15
                    passed(f'window-fast-ttl-cap-{qt}')
                # Stage 4: 64 concurrent cold A/AAAA answers -> every address learned, and
                # cohorts share transactions (fewer transactions than answers).
                stop(); start()
                with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                    list(pool.map(lambda i: query(f'win{100+i}', 1 if i % 2 == 0 else 28), range(64)))
                stop(); st = stats(); observations.append(dict(case='fast-cold-mixed-64', **st))
                assert st['applies'] == 64 and st['transactions'] <= 64, st
                for i in range(64):
                    qt = 1 if i % 2 == 0 else 28
                    assert present(qt, address(30100 + i, qt)), i
                passed('window-fast-cold-mixed-64-all-learned')
                start()
            else:
                # Interval target on the CLI path: the window applies to the raw address.
                stop()
                nft(f'delete set inet {table} learn4\nadd set inet {table} learn4 {{ type ipv4_addr; flags interval; auto-merge; }}')
                start()
                for _ in range(5): query('win3', 1)
                stop(); st = stats(); observations.append(dict(case='cli-interval-5', **st))
                assert st['applies'] == 5 and st['skipped'] >= 3, st
                assert present(1, address(30003, 1)) or any(isinstance(x, dict) and 'prefix' in x for x in elements(1))
                passed('window-cli-interval-skip')
                nft(f'delete set inet {table} learn4\nadd set inet {table} learn4 {{ type ipv4_addr; flags timeout; size 16384; }}')
                start()
        (out/'window-observations.json').write_text(json.dumps(observations, indent=2))
    try:
        start()
        for qt in [1,28]:
            target = 'learn4' if qt==1 else 'learn6'
            nft(f'add element inet {table} {target} {{ {address(1,qt)} }}')
            query('permanent',qt); query('permanent',qt)
            assert expiry(qt,address(1,qt)) is None
            passed(f'permanent-{qt}')
            query('short',qt); initial = expiry(qt,address(2,qt)); assert 0 < initial <= 16
            query('long',qt); long = expiry(qt,address(2,qt)); assert long > 590
            query('short',qt); assert expiry(qt,address(2,qt)) > 590
            passed(f'renew-no-shorten-{qt}')
            for name,wanted in [('high',0),('cap',86400)]:
                answer = query(name,qt); _,_,end = decode_question(answer)
                assert struct.unpack_from('!I',answer,end+6)[0] == wanted
                index = 3 if name=='high' else 4
                e = expiry(qt,address(index,qt)); assert 0 < e <= wanted+15
                passed(f'ttl-{name}-{qt}')
        stop(); start()
        for qt in [1,28]:
            query('permanent',qt); assert expiry(qt,address(1,qt)) is None
            query('short',qt); assert expiry(qt,address(2,qt)) > 580
        passed('restart-preserves-permanent-and-longer-leases')
        nft(f'flush set inet {table} learn4\nflush set inet {table} learn6')
        for qt in [1,28]: query('short',qt); assert expiry(qt,address(2,qt)) > 0
        passed('flush-relearn-both-families')
        nft(f'delete table inet {table}\n'+setup)
        for qt in [1,28]: query('short',qt); assert expiry(qt,address(2,qt)) > 0
        passed('recreate-relearn-both-families')
        # Make only IPv6 invalid. Mixed requests must not sacrifice IPv4 members.
        nft(f'delete set inet {table} learn6\nadd set inet {table} learn6 {{ type ipv6_addr; flags interval; }}')
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(query,'short',1 if i%2==0 else 28,0 if i%2==0 else 2) for i in range(64)]
            for f in futures: f.result()
        passed('mixed-family-failure-isolation-64-queries')
        nft(f'delete set inet {table} learn6\nadd set inet {table} learn6 {{ type ipv6_addr; flags timeout; size 16384; }}')
        query('short',28); passed('metadata-failure-recovery')
        # N2: an answer with more than 256 A/AAAA records is still answered
        # (NOERROR); exactly its first 256 addresses are learned.
        def present(qt):
            return {x if isinstance(x,str) else x.get('elem',x).get('val') for x in elements(qt)}
        for qt in [1,28]:
            for count,first in [(257,100),(1000,20000)]:
                answer = query(f'bulk-{count}-{first}',qt)
                assert struct.unpack_from('!H',answer,6)[0] == count, (count, answer[:12].hex())
                learned = present(qt)
                assert all(address(first+i,qt) in learned for i in range(256)), (qt,count)
                assert not any(address(first+i,qt) in learned for i in range(256,count)), (qt,count)
            query('short',qt)
        passed('oversized-answer-first-256-learned-noerror')
        for qt in [1,28]:
            barrier = threading.Barrier(32)
            def bulk(i):
                barrier.wait(); query(f'bulk-200-{1000+i*200}',qt)
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(bulk,range(32)))
            actual = elements(qt)
            assert len(actual) >= 6400, (qt,len(actual))
            passed(f'6400-addresses-32-clients-{qt}')
        errors = []
        def external():
            try:
                for i in range(40):
                    nft(f'add element inet {table} unrelated {{ 10.0.0.{i+1} }}')
                    time.sleep(.01)
            except BaseException as e: errors.append(repr(e))
        writer = threading.Thread(target=external); writer.start()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: query(f'race{i}',1 if i%2==0 else 28),range(200)))
        writer.join(); assert not errors,errors
        passed('external-writer-200-queries')
        window_phase()
        complete = True
    finally:
        stop(); upstream.shutdown(); upstream.server_close(); log.close()
        (out/'result.json').write_text(json.dumps({'passed':complete,'checks':checks,'count':len(checks),'kernel':os.uname().release,'application':str(app),'commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'commands':commands},indent=2))
        nft(f'delete table inet {table}')
    print(json.dumps({'passed':True,'checks':checks,'kernel':os.uname().release}))


if __name__ == '__main__': main()
