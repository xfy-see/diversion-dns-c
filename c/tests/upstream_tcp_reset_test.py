#!/usr/bin/env python3
"""Deterministic pooled TCP reset race; no retry after partial or fresh failure."""
import argparse,json,socket,struct,subprocess,threading,time
from pathlib import Path

HOST='127.0.0.1'
def exact(s,n):
    data=b''
    while len(data)<n:
        part=s.recv(n-len(data))
        if not part:raise EOFError
        data+=part
    return data

def question(name):
    return struct.pack('!6H',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0\0\1\0\1'

class ResetFixture:
    def __init__(self,mode):
        self.mode=mode;self.connections=0;self.queries=0;self.stop=False;self.clients=[];self.threads=[];self.errors=[]
        self.sock=socket.socket();self.sock.bind((HOST,0));self.port=self.sock.getsockname()[1];self.sock.listen(16);self.sock.settimeout(.05)
        self.thread=threading.Thread(target=self.run);self.thread.start()
    def run(self):
        while not self.stop:
            try:c,peer=self.sock.accept()
            except socket.timeout:continue
            except OSError:return
            self.connections+=1;index=self.connections;self.clients.append(c);c.settimeout(5)
            t=threading.Thread(target=self.handle,args=(c,index));self.threads.append(t);t.start()
    def handle(self,c,index):
        try:
            local=0
            while not self.stop:
                q=exact(c,struct.unpack('!H',exact(c,2))[0]);local+=1;self.queries+=1
                if index==1 and (self.mode=='fresh' or local==2):
                    if self.mode=='partial':
                        c.sendall(b'\0');time.sleep(.05)
                    c.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0));return
                r=q[:2]+struct.pack('!5H',0x8180,1,1,0,0)+q[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('198.18.0.8')
                c.sendall(struct.pack('!H',len(r))+r)
        except (OSError,EOFError):pass
        except BaseException as e:self.errors.append(repr(e))
        finally:c.close()
    def close(self):
        self.stop=True;self.sock.close();self.thread.join(2)
        for c in self.clients:
            try:c.shutdown(socket.SHUT_RDWR)
            except OSError:pass
        for t in self.threads:t.join(2)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--application',required=True);ap.add_argument('--output',required=True);a=ap.parse_args()
    out=Path(a.output);out.mkdir(parents=True,exist_ok=False);rows=[]
    for policy in [False,True]:
        for mode in ['pooled','partial','fresh']:
            label=('managed' if policy else 'default')+'-'+mode;fixture=ResetFixture(mode);proc=None
            with socket.socket() as s:s.bind((HOST,0));port=s.getsockname()[1]
            folder=out/label;folder.mkdir();(folder/'cn.txt').write_text('cn.test\n')
            settings=f'listen_udp={HOST}:{port}\nlisten_tcp={HOST}:{port}\ncn_domain_file={folder.resolve()}/cn.txt\ncn_upstream=tcp://{HOST}:{fixture.port}\nforeign_upstream=tcp://{HOST}:{fixture.port}\ncache_size=0\n'
            if policy:settings+='foreign_upstream_timeout_ms=1000\n'
            (folder/'config.conf').write_text(settings);log=(folder/'application.log').open('w')
            try:
                proc=subprocess.Popen([a.application,'start','-c',str(folder/'config.conf'),'--cpu','1'],stdout=log,stderr=log)
                for _ in range(100):
                    assert proc.poll() is None,'application exited'
                    try:
                        with socket.create_connection((HOST,port),.05):break
                    except OSError:time.sleep(.02)
                else:raise AssertionError('readiness')
                def query(i):
                    q=question(f'q{i}.foreign.test');started=time.monotonic()
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
                        s.settimeout(3);s.sendto(q,(HOST,port));r=s.recv(65535)
                    assert r[:2]==q[:2] and r[12:len(q)]==q[12:],r.hex()
                    return dict(rcode=r[3]&15,ms=(time.monotonic()-started)*1000)
                if mode!='fresh':assert query(0)['rcode']==0
                # Let the first reply return its socket to the same worker's pool.
                time.sleep(.02);result=query(1)
                row=dict(case=label,result=result,connections=fixture.connections,queries=fixture.queries,fixture_errors=fixture.errors);rows.append(row);(out/'results.json').write_text(json.dumps(rows,indent=2));print(json.dumps(row),flush=True)
                assert not fixture.errors,row
                assert result['rcode']==(0 if mode=='pooled' else 2),row
                assert fixture.connections==(2 if mode=='pooled' else 1),row
                assert fixture.queries==(3 if mode=='pooled' else 2 if mode=='partial' else 1),row
            finally:
                if proc:proc.terminate();assert proc.wait(timeout=10)==0
                log.close();fixture.close()
    (out/'summary.json').write_text(json.dumps(dict(status='pass',checks=len(rows)),indent=2))
if __name__=='__main__':main()
