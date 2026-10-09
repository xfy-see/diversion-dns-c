import errno
import importlib.util
from pathlib import Path
import socket
import sys
import unittest
from unittest.mock import patch

spec=importlib.util.spec_from_file_location('loopback_fixture',Path(__file__).resolve().parents[1]/'c/tests/integration.py')
fixture=importlib.util.module_from_spec(spec)
with patch.object(sys,'argv',['integration.py','unused-program']): spec.loader.exec_module(fixture)


class SocketPairTests(unittest.TestCase):
    def test_both_transports_reserved(self):
        tcp,udp,port=fixture.bound_loopback_pair()
        try:
            self.assertEqual(tcp.getsockname(),('127.0.0.1',port))
            self.assertEqual(udp.getsockname(),('127.0.0.1',port))
            for kind in (socket.SOCK_STREAM,socket.SOCK_DGRAM):
                with socket.socket(socket.AF_INET,kind) as other:
                    with self.assertRaises(OSError): other.bind(('127.0.0.1',port))
        finally: tcp.close(); udp.close()

    def test_udp_collision_releases_both_and_reserves_next_pair(self):
        self.inject_failure(errno.EADDRINUSE,True)

    def test_non_collision_error_releases_both_and_propagates(self):
        self.inject_failure(errno.EACCES,False)

    def inject_failure(self,code,recover):
        original=socket.socket; opened=[]
        class FailedUDP:
            def __init__(self): self.closed=False
            def bind(self,address): raise OSError(code,'injected bind error')
            def close(self): self.closed=True
        def create(*args):
            value=FailedUDP() if len(opened)==1 else original(*args)
            opened.append(value); return value
        with patch.object(fixture.socket,'socket',side_effect=create):
            if recover:
                tcp,udp,_=fixture.bound_loopback_pair()
                tcp.close(); udp.close()
                self.assertEqual(len(opened),4)
            else:
                with self.assertRaises(OSError) as caught: fixture.bound_loopback_pair()
                self.assertEqual(caught.exception.errno,code)
                self.assertEqual(len(opened),2)
        self.assertEqual(opened[0].fileno(),-1)
        self.assertTrue(opened[1].closed)


if __name__=='__main__': unittest.main()
