#!/usr/bin/env python3
"""Real UDP fixtures + real server: hedging, quarantine, recovery and CN isolation."""
import argparse, concurrent.futures, json, socket, struct, subprocess, threading, time
from pathlib import Path

def wire(name, ident=1234):
    return struct.pack('!6H',ident,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0\0\1\0\1'
class Fixture:
    def __init__(self, address):
        self.sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.sock.bind(('127.0.0.1',0));self.sock.settimeout(.05)
        self.port=self.sock.getsockname()[1];self.address=socket.inet_aton(address);self.mode='good';self.count=0;self.ids=[];self.stop=False
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        while not self.stop:
            try:q,peer=self.sock.recvfrom(65535)
            except socket.timeout:continue
            except OSError:return
            self.count+=1;self.ids.append((struct.unpack_from('!H',q)[0],peer[1]));mode=self.mode
            if mode=='drop':continue
            code=2 if mode=='servfail' else 3 if mode=='nxdomain' else 0
            r=q[:2]+struct.pack('!5H',0x8180|code,1,0 if code else 1,0,0)+q[12:]
            if not code:r+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+self.address
            if mode=='wrongid':r=bytes([r[0]^1])+r[1:]
            try:self.sock.sendto(r,peer)
            except OSError:return
    def close(self):self.stop=True;self.thread.join(timeout=2);self.sock.close()
def exact(s,n):
    b=b''
    while len(b)<n:
        x=s.recv(n-len(b));assert x;b+=x
    return b

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--application',required=True);ap.add_argument('--output',required=True);args=ap.parse_args()
    out=Path(args.output);out.mkdir(parents=True,exist_ok=False);app=Path(args.application).resolve()
    bad=Fixture('198.18.0.1');good=Fixture('198.18.0.2');cn=Fixture('198.18.0.3');rows=[];proc=None;log=None;port=0
    def start(extra=''):
        nonlocal proc,log,port
        with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
        (out/'cn.txt').write_text('cn.test\n')
        text=f'listen_udp=127.0.0.1:{port}\nlisten_tcp=127.0.0.1:{port}\ncn_domain_file={out.resolve()}/cn.txt\ncn_upstream=127.0.0.1:{cn.port}\nforeign_upstream=127.0.0.1:{bad.port}\nforeign_upstream=127.0.0.1:{good.port}\ncache_size=0\n'+extra
        (out/'config.conf').write_text(text);log=(out/f'app-{len(rows)}.log').open('w')
        proc=subprocess.Popen([str(app),'start','-c',str(out/'config.conf'),'--cpu','1'],stdout=log,stderr=log)
        for _ in range(100):
            assert proc.poll() is None,'server exited'
            try:
                with socket.create_connection(('127.0.0.1',port),.05):return
            except OSError:time.sleep(.02)
        raise AssertionError('server readiness')
    def stop():
        nonlocal proc,log
        if proc:
            proc.terminate();rc=proc.wait(timeout=10);assert rc==0,rc;proc=None;log.close()
    def query(name,tcp=False):
        q=wire(name);t=time.monotonic()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
            s.settimeout(7);s.connect(('127.0.0.1',port))
            if tcp:s.sendall(struct.pack('!H',len(q))+q);r=exact(s,struct.unpack('!H',exact(s,2))[0])
            else:s.send(q);r=s.recv(65535)
        assert r[:2]==q[:2] and r[12:len(q)]==q[12:],r.hex()
        return {'rcode':r[3]&15,'ms':(time.monotonic()-t)*1000,'address':socket.inet_ntoa(r[-4:]) if struct.unpack_from('!H',r,6)[0] else None}
    def record(case,**data):
        rows.append(dict(case=case,**data));(out/'results.json').write_text(json.dumps(rows,indent=2));print(json.dumps(rows[-1]),flush=True)
    settings='cn_upstream_hedge_ms=50\ncn_upstream_timeout_ms=300\nforeign_upstream_hedge_ms=80\nforeign_upstream_timeout_ms=400\n'
    try:
        bad.mode='drop';start(settings)
        hits=[query(f'h{i}.foreign.test',i%2==1) for i in range(8)]
        assert all(x['rcode']==0 and x['address']=='198.18.0.2' and x['ms']<1500 for x in hits),hits
        assert bad.count==2,(bad.count,hits)
        record('hedge-and-quarantine',queries=hits,bad_attempts=bad.count)
        before=bad.count;bad.mode='good';cool=[query(f'cool{i}.foreign.test') for i in range(4)]
        assert bad.count==before and all(x['address']=='198.18.0.2' for x in cool)
        time.sleep(5.1);probe=query('probe.foreign.test');assert probe['address']=='198.18.0.1',probe
        recovered=[query(f'recovered{i}.foreign.test') for i in range(4)]
        assert any(x['address']=='198.18.0.1' for x in recovered)
        record('cooldown-and-probe-recovery',probe=probe,queries=recovered)
        bad.mode=good.mode='drop'
        for i in range(4):query(f'black{i}.foreign.test')
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            foreign=[pool.submit(query,f'pressure{i}.foreign.test') for i in range(24)]
            domestic=[query(f'fresh{i}.cn.test',i%2==1) for i in range(20)]
            failed=[f.result() for f in foreign]
        assert all(x['rcode']==0 and x['address']=='198.18.0.3' and x['ms']<1000 for x in domestic),domestic
        assert all(x['rcode']==2 and x['ms']<1500 for x in failed),failed
        record('all-down-bounded-and-cn-independent',cn=domestic,foreign=failed)
        stop();bad.mode='servfail';good.mode='good';start(settings)
        fallback=query('rcode.foreign.test');assert fallback['rcode']==0 and fallback['address']=='198.18.0.2',fallback
        record('servfail-fallback',query=fallback);stop()
        bad.mode='nxdomain';start(settings);negative=query('negative.foreign.test');assert negative['rcode']==3,negative
        record('nxdomain-is-final',query=negative);stop()
        bad.mode='wrongid';start(settings);invalid=query('spoof.foreign.test');assert invalid['rcode']==0 and invalid['address']=='198.18.0.2',invalid
        record('invalid-id-cannot-win',query=invalid);stop()
        bad.mode='drop';start();legacy=query('legacy.foreign.test');assert legacy['rcode']==2 and legacy['ms']>=4500,legacy
        record('default-retains-legacy',query=legacy);stop()
        assert sum(i==1234 for i,_ in bad.ids+good.ids+cn.ids)<=2,'upstream ID randomization regressed'
        (out/'summary.json').write_text(json.dumps({'status':'pass','checks':len(rows)},indent=2))
    finally:
        stop()
        for f in (bad,good,cn):f.close()
if __name__=='__main__':main()
