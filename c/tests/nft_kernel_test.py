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
            answer = struct.pack('!6H', 1234, 0x8180, 1, count, 0, 0) + q[12:end]
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
    (out/'config.conf').write_text(f'''listen_tcp=127.0.0.1:{port}
cn_domain_file={out}/cn.txt
cn_upstream=tcp://127.0.0.1:{upstream.server_address[1]}
foreign_upstream=tcp://127.0.0.1:{upstream.server_address[1]}
cache_size=0
nftset_ipv4=inet,{table},learn4,ipv4_addr,32
nftset_ipv6=inet,{table},learn6,ipv6_addr,128
nftset_fast=1
''')
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
    try:
        start()
        for qt in [1,28]:
            target = 'learn4' if qt==1 else 'learn6'
            nft(f'add element inet {table} {target} {{ {address(1,qt)} }}')
            query('permanent',qt); query('permanent',qt)
            assert expiry(qt,address(1,qt)) is None
            passed(f'permanent-{qt}')
            query('short',qt); initial = expiry(qt,address(2,qt)); assert 0 < initial <= 16000
            query('long',qt); long = expiry(qt,address(2,qt)); assert long > 590000
            query('short',qt); assert expiry(qt,address(2,qt)) > 590000
            passed(f'renew-no-shorten-{qt}')
            for name,wanted in [('high',0),('cap',86400)]:
                answer = query(name,qt); _,_,end = decode_question(answer)
                assert struct.unpack_from('!I',answer,end+6)[0] == wanted
                index = 3 if name=='high' else 4
                e = expiry(qt,address(index,qt)); assert 0 < e <= (wanted+15)*1000
                passed(f'ttl-{name}-{qt}')
        stop(); start()
        for qt in [1,28]:
            query('permanent',qt); assert expiry(qt,address(1,qt)) is None
            query('short',qt); assert expiry(qt,address(2,qt)) > 580000
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
        for qt in [1,28]:
            query('bulk-257-100',qt,2)
            query('short',qt)
        passed('oversized-answer-rejected-with-healthy-recovery')
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
        complete = True
    finally:
        stop(); upstream.shutdown(); upstream.server_close(); log.close()
        (out/'result.json').write_text(json.dumps({'passed':complete,'checks':checks,'count':len(checks),'kernel':os.uname().release,'application':str(app),'commit':os.environ.get('GITHUB_SHA'),'run_id':os.environ.get('GITHUB_RUN_ID'),'commands':commands},indent=2))
        nft(f'delete table inet {table}')
    print(json.dumps({'passed':True,'checks':checks,'kernel':os.uname().release}))


if __name__ == '__main__': main()
