#!/usr/bin/env python3
"""Real loopback DNS request accounting against verified binary; no compilation."""
import argparse
import json
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import tempfile
import threading
import unittest

parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--application',type=Path,required=True)
parser.add_argument('--output',type=Path,required=True)
args,remaining=parser.parse_known_args()
args.output.mkdir(parents=True,exist_ok=False)
sys.argv=[sys.argv[0],str(args.application.resolve()),*remaining]
import fixed_integration as support

class DNS(support.MockDNS):
    def __init__(self,*args,**kwargs):
        self.entered=threading.Event()
        self.release=threading.Event()
        super().__init__(*args,**kwargs)

    def reply(self,packet,transport):
        name,_,_,end=support.question(packet)
        response=super().reply(packet,transport)
        if name.startswith('held.'):
            self.entered.set()
            # Tests release this only after observing the intended server
            # state; timeout is a fixture escape hatch, not synchronization.
            self.release.wait(8)
        if name.startswith('negative.'):
            return response[:2]+bytes([0x81,0x83])+response[4:6]+bytes(6)+packet[12:end]
        if name.startswith('badvers.'):
            # Full RCODE=16: header low RCODE=0, OPT extended RCODE=1.
            return (packet[:2]+struct.pack('!5H',0x8180,1,0,0,1)+packet[12:end]+
                    b'\0'+struct.pack('!HHIH',41,1232,0x01000000,0))
        return response

class Metrics(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='dns-metrics-')
        self.root=Path(self.tmp.name)
        self.path=self.root/'metrics.json'
        self.up=DNS('203.0.113.9')
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.up.close)
        self.addCleanup(self.up.release.set)

    def config(self):
        port=support.support.unused_port()
        return dict(listen_udp=f'127.0.0.1:{port}',listen_tcp=f'127.0.0.1:{port}',
                    cn_upstream=f'127.0.0.1:{self.up.port}',foreign_upstream=f'127.0.0.1:{self.up.port}',cache_size=64)

    def snapshot(self,name):
        data=json.loads(self.path.read_text())
        (args.output/(name+'.json')).write_text(json.dumps(data,indent=2)+'\n')
        self.assertEqual(data['version'],1)
        self.assertTrue(data['final'])
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode),0o600)
        t=data['totals']
        self.assertEqual(t['completed'],t['success']+t['failed'])
        self.assertEqual(t['completed'],t['latency_count'])
        self.assertEqual(t['completed'],sum(t['latency_buckets']))
        self.assertEqual(len(t['latency_buckets']),len(data['latency_bucket_upper_us']))
        self.assertFalse(list(self.root.glob('metrics.json.tmp.*')))
        self.assertNotIn('foreign.test',self.path.read_text())
        return data

    def test_real_requests_cache_tcp_udp_and_failures(self):
        with support.running(self.config(),env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
            for ident in range(3):
                self.assertEqual(support.udp_exchange(port,support.query('cached.foreign.test',ident))[3]&15,0)
            self.assertEqual(support.tcp_exchange(port,support.query('cached.foreign.test',11))[3]&15,0)
            self.assertEqual(support.udp_exchange(port,support.query('negative.foreign.test',12))[3]&15,3)
            self.up.mode='servfail'
            self.assertEqual(support.udp_exchange(port,support.query('broken.foreign.test',13))[3]&15,2)
        s=self.snapshot('mixed');t=s['totals']
        self.assertEqual((t['requests'],t['completed'],t['success'],t['failed']),(6,6,5,1))
        self.assertEqual((t['udp'],t['tcp']),(5,1))
        self.assertEqual((t['noerror'],t['nxdomain'],t['servfail']),(4,1,1))
        self.assertEqual(s['cache']['foreign']['fresh_hit'],3)
        self.assertGreater(t['latency_sum_us'],0)

    def test_extended_rcode_is_not_counted_as_noerror(self):
        with support.running(self.config(),env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
            for exchange in (support.udp_exchange,support.tcp_exchange):
                response=exchange(port,support.query('badvers.foreign.test',edns=1232))
                self.assertEqual(response[3]&15,0)
                self.assertEqual(struct.unpack_from('!H',response,10)[0],1)
                self.assertEqual(response[-6],1)
        t=self.snapshot('extended-rcode')['totals']
        self.assertEqual((t['requests'],t['completed'],t['success'],t['failed']),(2,2,0,2))
        self.assertEqual((t['noerror'],t['other_rcode']),(0,2))

    def test_gated_followers_and_queue_rejections_count_each_client_once(self):
        # One held leader plus 63 byte-identical followers fills the lane's
        # 64 slots. Seeing 16 SERVFAILs before releasing the upstream proves
        # all 80 queries were accepted while the first result was unavailable.
        # This cannot silently pass as 79 fast-cache hits.
        config=self.config()
        # A TCP upstream avoids retransmission retries becoming extra mock
        # calls if the hosted test runner is briefly descheduled at the gate.
        config['foreign_upstream']=f'tcp://127.0.0.1:{self.up.port}'
        with support.running(config,env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,256*1024)
                sock.settimeout(3)
                target=('127.0.0.1',port)
                name='held.shared.foreign.test'
                sock.sendto(support.query(name,0),target)
                self.assertTrue(self.up.entered.wait(2),'leader did not reach gated upstream')
                try:
                    for ident in range(1,80):
                        sock.sendto(support.query(name,ident),target)
                    rejected=[sock.recv(65535) for _ in range(16)]
                    self.assertTrue(all(r[3]&15==2 for r in rejected))
                finally:
                    self.up.release.set()
                succeeded=[sock.recv(65535) for _ in range(64)]
                self.assertTrue(all(r[3]&15==0 for r in succeeded))
                self.assertEqual({struct.unpack_from('!H',r)[0] for r in rejected+succeeded},set(range(80)))
        t=self.snapshot('followers-and-overload')['totals']
        self.assertEqual((t['requests'],t['completed'],t['success'],t['failed']),(80,80,64,16))
        self.assertEqual((t['queue_rejected'],t['servfail']),(16,16))
        self.assertEqual(self.up.count('held.shared.foreign.test'),1)

    def test_reset_tcp_client_has_one_failed_terminal_completion(self):
        with support.running(self.config(),env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
            client=socket.create_connection(('127.0.0.1',port),timeout=3)
            try:
                packet=support.query('held.reset.foreign.test',900)
                client.sendall(struct.pack('!H',len(packet))+packet)
                self.assertTrue(self.up.entered.wait(2),'TCP query was not accepted')
                # Reset only after upstream admission, so an incomplete frame
                # or rejected handshake cannot masquerade as a counted query.
                client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0))
            finally:
                client.close()
                self.up.release.set()
            self.assertEqual(support.udp_exchange(port,support.query('barrier.foreign.test',901))[3]&15,0)
        t=self.snapshot('tcp-reset')['totals']
        self.assertEqual((t['requests'],t['completed'],t['success'],t['failed']),(2,2,1,1))
        self.assertEqual((t['tcp'],t['udp'],t['send_errors']),(1,1,1))

    def test_restart_identity_and_counters_reset(self):
        snapshots=[]
        for i in range(2):
            with support.running(self.config(),env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
                support.udp_exchange(port,support.query('restart.foreign.test',i))
            snapshots.append(self.snapshot('restart-'+str(i)))
        self.assertNotEqual(snapshots[0]['pid'],snapshots[1]['pid'])
        self.assertEqual(snapshots[1]['totals']['requests'],1)

    def test_symlink_and_disabled_export_do_not_damage_target(self):
        target=self.root/'sentinel';target.write_text('keep')
        self.path.symlink_to(target)
        with support.running(self.config(),env={'DIVERSION_METRICS_FILE':str(self.path)}) as port:
            support.udp_exchange(port,support.query('safe.foreign.test'))
        self.assertEqual(target.read_text(),'keep');self.assertTrue(self.path.is_symlink())
        self.path.unlink()
        with support.running(self.config(),env={'DIVERSION_METRICS_FILE':''}) as port:
            support.udp_exchange(port,support.query('disabled.foreign.test'))
        self.assertFalse(self.path.exists())

suite=unittest.defaultTestLoader.loadTestsFromTestCase(Metrics)
result=unittest.TextTestRunner(verbosity=2).run(suite)
(args.output/'result.json').write_text(json.dumps(dict(ok=result.wasSuccessful(),tests=result.testsRun,
    errors=len(result.errors),failures=len(result.failures),compilers_invoked=False),indent=2)+'\n')
sys.exit(0 if result.wasSuccessful() else 1)
