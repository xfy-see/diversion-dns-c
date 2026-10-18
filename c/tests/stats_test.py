#!/usr/bin/env python3
"""Black-box runtime stats correctness/safety tests, existing binary only."""
import argparse
from collections import Counter
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import traceback
from cache_refresh_safety_test import Suite, query, unused_port

class StatsSuite(Suite):
    def read(self, label):
        s=json.loads((self.output/(label+'.json')).read_text())
        self.require(s['schema']=='diversion-dns-stats-v1','schema')
        t=s['total']
        self.require(s['received_valid']==t['completed']+s['inflight'],'accounting mismatch')
        self.require(sum(x['metrics']['completed'] for x in s['breakdown'])==t['completed'],'split mismatch')
        self.require(sum(t['cache'].values())==t['completed'],'cache accounting')
        self.require(sum(h['samples'] for h in t['rt_by_cache'].values())==t['completed'],'cache RT accounting')
        self.require(sum(x['metrics']['completed'] for x in s['recent_intervals'])==t['completed'],'interval accounting')
        for h in (t['rt'], t['queue'], t['service']):
            self.require(sum(h['histogram'])==h['samples']==t['completed'],'histogram sample accounting')
            ps=[h[k] for k in ('p50_upper_ms','p90_upper_ms','p95_upper_ms','p99_upper_ms')]
            self.require(all(a<=b for a,b in zip(ps,ps[1:]) if a is not None and b is not None),'quantiles')
        return s

    def basic(self):
        path=self.output/'basic.json'
        for n in ('a.cn.test','hot.foreign.test','v6.foreign.test'):
            self.upstream.set(n,ttl=60)
        with self.running('basic',stats_file=path,stats_interval=5):
            self.old('a.cn.test');self.old('a.cn.test',tcp=True)
            self.old('hot.foreign.test');self.old('hot.foreign.test');self.old('hot.foreign.test',tcp=True)
            self.old('v6.foreign.test',28);self.old('v6.foreign.test',28,tcp=True)
            self.upstream.set('error.foreign.test',mode='servfail')
            self.require(self.ask('error.foreign.test')['rcode']==2,'SERVFAIL fixture')
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:sock.sendto(b'invalid',('127.0.0.1',self.port))
            deadline=time.monotonic()+7
            while self.read('basic')['total']['completed']<8:
                self.require(time.monotonic()<deadline,'snapshot not refreshed');time.sleep(.05)
            p=subprocess.run([self.application,'stats','--file',path],capture_output=True,timeout=3)
            self.require(p.returncode==0 and json.loads(p.stdout)['total']['completed']==8,'CLI')
        s=self.read('basic');t=s['total']
        self.require(s['final'] and s['inflight']==0,'final snapshot')
        self.require(t['completed']==8 and t['success']==7 and t['rcode']['2']==1,'success accounting')
        self.require(t['cache']['fresh']==4 and t['cache']['miss']==4,'hot/cold accounting')
        self.require(s['events']['invalid_udp']==1,'invalid packet')
        self.require(s['top50']['exact'],'small top must be exact')
        self.require(s['top50']['domains'][0]['domain']=='hot.foreign.test' and s['top50']['domains'][0]['count_estimate']==3,'top order/count')
        self.require((path.stat().st_mode & 0o777)==0o600,'snapshot mode')

    def queue_and_followers(self):
        path=self.output/'queue.json'
        for i in range(80):self.upstream.set(f'q{i}.foreign.test',mode='silent')
        self.upstream.set('same.foreign.test',mode='silent')
        with self.running('queue',stats_file=path,stats_interval=5,queue_timeout_ms=100):
            with concurrent.futures.ThreadPoolExecutor(max_workers=80) as pool:
                rows=list(pool.map(lambda i:self.ask(f'q{i}.foreign.test'),range(80)))
            self.require(all(x['rcode']==2 for x in rows),'queue responses')
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
                rows=list(pool.map(lambda _:self.ask('same.foreign.test'),range(16)))
            self.require(all(x['rcode']==2 for x in rows),'follower responses')
        s=self.read('queue');t=s['total'];e=t['errors']
        self.require(t['completed']==96 and t['success']==0,'queue totals')
        self.require(e['queue_full']>0 and e['queue_timeout']>0 and e['upstream_timeout']>0,'queue/timeout classes')
        self.require(t['coalesced']>0,'coalesced missing')

    def bounded_top(self):
        path=self.output/'top.json';counts=Counter()
        with self.running('top',stats_file=path,stats_interval=5,cache_size=0,cache_stale_ttl=None):
            for i in range(1100):
                name=f'cold{i}.foreign.test';self.ask(name);counts[name]+=1
            for _ in range(60):self.ask('popular.foreign.test');counts['popular.foreign.test']+=1
        s=self.read('top')
        self.require(s['total']['completed']==1160 and s['total']['cache']['disabled_or_unchecked']==1160,'disabled cache')
        self.require(not s['top50']['exact'] and s['top50']['replacements']>0 and len(s['top50']['domains'])==50,'bounded top')
        self.require(s['top50']['domains'][0]['domain']=='popular.foreign.test','heavy hitter lost')
        for item in s['top50']['domains']:
            self.require(item['count_lower_bound']<=counts[item['domain']]<=item['count_estimate'],'estimate bounds')

    def background(self):
        path=self.output/'background.json';listing=self.output/'keep.txt'
        listing.write_text('0 1 scheduled.foreign.test\n')
        self.upstream.set('scheduled.foreign.test',ttl=60)
        with self.running('background',stats_file=path,stats_interval=5,cache_keep_file=listing):
            self.wait_tx(['scheduled.foreign.test'],1)
            self.old('scheduled.foreign.test')
        s=self.read('background')
        self.require(s['received_valid']==1 and s['total']['cache']['fresh']==1,'background counted as user')
        self.require(s['cache_engine']['foreign']['keep_query']==1,'keep stats missing')

    def safety(self):
        path=self.output/'safety.json'
        with self.running('safety',stats_file=path,stats_interval=5):
            original=(self.output/'safety/config.conf').read_text()
            port=unused_port()
            conf=self.output/'second.conf';conf.write_text(original.replace(f'127.0.0.1:{self.port}',f'127.0.0.1:{port}'))
            p=subprocess.run([self.application,'start','-c',conf],capture_output=True,timeout=5)
            self.require(p.returncode!=0 and b'exclusive snapshot lock' in p.stderr,'second writer accepted')
            self.old('still-alive.foreign.test')
        before=path.read_bytes()
        p=subprocess.run([self.application,'check','-c',self.output/'safety/config.conf'],capture_output=True,timeout=5)
        self.require(p.returncode==0 and path.read_bytes()==before,'check mutated snapshot')
        foreign=self.output/'unrelated.json';foreign.write_text('{"private":"untouched"}')
        conf=self.output/'unsafe.conf';conf.write_text(original.replace(str(path),str(foreign)))
        p=subprocess.run([self.application,'start','-c',conf],capture_output=True,timeout=5)
        self.require(p.returncode!=0 and foreign.read_text()=='{"private":"untouched"}','unrelated file overwritten')
        link=self.output/'link.json';link.symlink_to(foreign)
        try:
            conf.write_text(original.replace(str(path),str(link)))
            p=subprocess.run([self.application,'start','-c',conf],capture_output=True,timeout=5)
            self.require(p.returncode!=0 and foreign.read_text()=='{"private":"untouched"}','symlink followed')
        finally:link.unlink()
        # A new process is a new epoch; no silently concatenated counters.
        with self.running('restart',stats_file=path,stats_interval=5):self.old('new-epoch.foreign.test')
        self.require(self.read('safety')['received_valid']==1,'restart retained old counters')


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--application',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    suite=StatsSuite(a.application,a.output);result=dict(ok=False,binary_sha256=hashlib.sha256(a.application.read_bytes()).hexdigest(),cases=[])
    try:
        for case in ('basic','queue_and_followers','bounded_top','background','safety'):
            getattr(suite,case)();result['cases'].append(case)
        result['ok']=True
    except BaseException:
        result['error']=traceback.format_exc();raise
    finally:
        suite.upstream.close()
        (a.output/'upstream.json').write_text(json.dumps(suite.upstream.snapshot(),indent=2))
        (a.output/'clients.json').write_text(json.dumps(suite.clients,indent=2))
        (a.output/'result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result))
if __name__=='__main__':main()
