#!/usr/bin/env python3
"""Additional layer-1 DNS semantics and shutdown checks from testing-plan-131.

Uses only ephemeral IPv4 loopback fixtures. Passing does not establish Linux
nft/mark behaviour, performance, real-network egress or device stability.
"""
import contextlib
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

import integration as base  # Reuses its CLI binary argument and framing helpers.


# 独立解析响应压缩名，并拒绝循环/前向指针，以免只断言最后几个地址字节。
def read_name(packet, start):
    labels, at, end, visited = [], start, None, set()
    while True:
        if at >= len(packet) or at in visited:
            raise ValueError("invalid DNS name")
        visited.add(at)
        n = packet[at]
        if n & 0xc0 == 0xc0:
            if at + 1 >= len(packet):
                raise ValueError("short DNS pointer")
            if end is None:
                end = at + 2
            target = ((n & 0x3f) << 8) | packet[at + 1]
            if target >= at:
                raise ValueError("forward DNS pointer")
            at = target
        elif n == 0:
            return ".".join(labels), end if end is not None else at + 1
        else:
            if n > 63 or at + 1 + n > len(packet):
                raise ValueError("invalid DNS label")
            labels.append(packet[at + 1:at + 1 + n].decode("ascii"))
            at += n + 1


def parse_response(packet):
    header = struct.unpack_from("!6H", packet)
    name, at = read_name(packet, 12)
    typ, cls = struct.unpack_from("!2H", packet, at)
    at += 4
    rr = []
    for section, count in enumerate(header[3:]):
        for _ in range(count):
            owner, at = read_name(packet, at)
            rt, rc, ttl, size = struct.unpack_from("!HHIH", packet, at)
            data_at = at + 10
            data = packet[data_at:data_at + size]
            if len(data) != size:
                raise ValueError("short DNS RDATA")
            item = {"section": section, "owner": owner, "type": rt, "class": rc, "ttl": ttl, "data": data}
            if rt == 6:
                mname, pos = read_name(packet, data_at)
                rname, pos = read_name(packet, pos)
                item["soa"] = (mname, rname, *struct.unpack_from("!5I", packet, pos))
                if pos + 20 != data_at + size:
                    raise ValueError("invalid SOA RDATA length")
            rr.append(item)
            at = data_at + size
    if at != len(packet):
        raise ValueError("trailing DNS bytes")
    return header, (name, typ, cls), rr


# 通过事件精确控制刷新开始与释放，测试旧响应副本和退出等待生命周期。
class SemanticDNS(base.MockDNS):
    def __init__(self):
        self.refresh_started = threading.Event()
        self.refresh_release = threading.Event()
        super().__init__("192.0.2.9", ttl=60)

    def reply(self, packet, transport):
        name, typ, cls, end = base.question(packet)
        with self.lock:
            self.counts[name, transport] = self.counts.get((name, transport), 0) + 1
            count = sum(v for (n, _), v in self.counts.items() if n == name)
        flags = 0x84a0 | (struct.unpack_from("!H", packet, 2)[0] & 0x0110)
        if name == "missing.zone.test":
            response = struct.pack("!6H", struct.unpack_from("!H", packet)[0], flags | 3, 1, 0, 1, 0)
            response += packet[12:end]
            response += b"\xc0\x14" + struct.pack("!HHIH", 6, cls, 120, 24)
            return response + b"\xc0\x14\xc0\x14" + struct.pack("!5I", 7, 30, 10, 90, 15)
        if name in {"lazy-copy.test", "shutdown.test"} and count > 1:
            self.refresh_started.set()
            if not self.refresh_release.wait(5):
                raise AssertionError("refresh release timed out")
        ttl = 1 if name in {"lazy-copy.test", "shutdown.test"} and count == 1 else 60
        address = "192.0.2.10" if name == "lazy-copy.test" and count > 1 else self.address
        data = socket.inet_pton(socket.AF_INET6, "2001:db8::9") if typ == 28 else socket.inet_aton(address)
        response = struct.pack("!6H", struct.unpack_from("!H", packet)[0], flags, 1, 1, 0, 0) + packet[12:end]
        return response + b"\xc0\x0c" + struct.pack("!HHIH", typ, cls, ttl, len(data)) + data

    def close(self):
        self.refresh_release.set()
        super().close()


@contextlib.contextmanager
def running(config):
    with tempfile.TemporaryDirectory(prefix="mosdns-c-plan-") as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config))
        proc = subprocess.Popen([str(base.BIN), "start", "-c", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        port = int(config["plugins"][-1]["args"]["listen"].rsplit(":", 1)[1])
        try:
            deadline = time.monotonic() + 5
            while True:
                if proc.poll() is not None:
                    raise AssertionError(proc.communicate()[1].decode())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("server startup timed out")
                    time.sleep(0.025)
            yield port, proc
        finally:
            if proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
            out, err = proc.communicate(timeout=8)
            if proc.returncode != 0:
                raise AssertionError(f"server exit {proc.returncode}: {err.decode()} {out.decode()}")


class PlanIntegration(unittest.TestCase):
    def setUp(self):
        self.mock = SemanticDNS()

    def tearDown(self):
        self.mock.close()

    def config(self, lazy=0, idle=2):
        c = {"log": {"level": "error"}, "plugins": base.plugins(self.mock, self.mock, base.unused_port(), lazy)}
        c["plugins"][-1]["args"]["idle_timeout"] = idle
        return c

    def assert_dns(self, packet, ident, name, typ, cls, flags):
        header, question, records = parse_response(packet)
        self.assertEqual(header[:3], (ident, flags, 1))
        self.assertEqual(question, (name, typ, cls))
        return records

    def test_full_a_aaaa_and_chaos_semantics(self):
        with running(self.config()) as (port, _):
            for exchange in (base.udp_exchange, base.tcp_exchange):
                for typ, cls in ((1, 1), (28, 1), (1, 3)):
                    with self.subTest(transport=exchange.__name__, type=typ, cls=cls):
                        name = f"identity-{exchange.__name__}-{typ}-{cls}.test"
                        q = base.query(name, 123 + typ + cls, qtype=typ, qclass=cls, flags=0x0110)
                        rr = self.assert_dns(exchange(port, q), 123 + typ + cls, name, typ, cls, 0x85b0)
                        self.assertEqual(len(rr), 1)
                        self.assertEqual((rr[0]["owner"], rr[0]["type"], rr[0]["class"], rr[0]["ttl"]), (name, typ, cls, 60))
                        self.assertEqual(rr[0]["data"], socket.inet_pton(socket.AF_INET6, "2001:db8::9") if typ == 28 else socket.inet_aton("192.0.2.9"))
                        self.assertEqual(self.mock.count(name), 1)

    def test_nxdomain_soa_cached_udp_tcp_preserves_semantics(self):
        with running(self.config(lazy=30)) as (port, _):
            for ident, exchange in ((991, base.udp_exchange), (992, base.tcp_exchange)):
                rr = self.assert_dns(exchange(port, base.query("missing.zone.test", ident, flags=0x0110)), ident, "missing.zone.test", 1, 1, 0x85b3)
                self.assertEqual(len(rr), 1)
                self.assertEqual((rr[0]["section"], rr[0]["owner"], rr[0]["type"], rr[0]["class"]), (1, "zone.test", 6, 1))
                self.assertGreaterEqual(rr[0]["ttl"], 119)
                self.assertLessEqual(rr[0]["ttl"], 120)
                self.assertEqual(rr[0]["soa"], ("zone.test", "zone.test", 7, 30, 10, 90, 15))
            self.assertEqual(self.mock.count("missing.zone.test"), 1)

    def test_lazy_stale_response_and_refresh_replace_independent_copy(self):
        with running(self.config(lazy=30)) as (port, _):
            first = base.udp_exchange(port, base.query("lazy-copy.test", 600))
            time.sleep(2.05)
            stale = base.tcp_exchange(port, base.query("lazy-copy.test", 601))
            rr = self.assert_dns(stale, 601, "lazy-copy.test", 1, 1, 0x85a0)
            self.assertEqual(rr[0]["ttl"], 5)
            self.assertEqual(rr[0]["data"], socket.inet_aton("192.0.2.9"))
            self.assertTrue(self.mock.refresh_started.wait(1))
            self.mock.refresh_release.set()
            deadline = time.monotonic() + 2
            while True:
                refreshed = base.udp_exchange(port, base.query("lazy-copy.test", 602))
                rr = self.assert_dns(refreshed, 602, "lazy-copy.test", 1, 1, 0x85a0)
                if rr[0]["data"] == socket.inet_aton("192.0.2.10"):
                    break
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.025)
            self.assertGreaterEqual(rr[0]["ttl"], 59)
            self.assertEqual(self.mock.count("lazy-copy.test"), 2)
            self.assertEqual(parse_response(first)[2][0]["data"], socket.inet_aton("192.0.2.9"))
            self.assertEqual(parse_response(stale)[2][0]["data"], socket.inet_aton("192.0.2.9"))

    # 主动阻塞刷新后发送 SIGTERM：进程需等待刷新结束，防止释放仍被使用的缓存。
    def test_sigterm_joins_active_lazy_refresh_before_cache_free(self):
        with running(self.config(lazy=30)) as (port, proc):
            base.udp_exchange(port, base.query("shutdown.test"))
            time.sleep(2.05)
            stale = base.udp_exchange(port, base.query("shutdown.test", 880))
            self.assertEqual(parse_response(stale)[2][0]["ttl"], 5)
            self.assertTrue(self.mock.refresh_started.wait(1))
            proc.send_signal(signal.SIGTERM)
            time.sleep(0.2)
            self.assertIsNone(proc.poll(), "engine must wait for the in-flight refresh")
            self.mock.refresh_release.set()
            proc.wait(timeout=3)
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(self.mock.count("shutdown.test"), 2)

    def test_tcp_idle_and_partial_body_close_release_listener(self):
        config = self.config(idle=1)
        with running(config) as (port, _):
            with socket.create_connection(("127.0.0.1", port), timeout=3) as idle, socket.create_connection(("127.0.0.1", port), timeout=3) as partial:
                q = base.query("closed-client.test")
                partial.sendall(struct.pack("!H", len(q)) + q[:4])
                self.assertEqual(idle.recv(1), b"")
                self.assertEqual(partial.recv(1), b"")
                self.assertEqual(self.mock.count("closed-client.test"), 0)
            self.assertEqual(base.address(base.tcp_exchange(port, base.query("after-idle.test"))), "192.0.2.9")
        # Exact cleanup permits binding both transports on the former port.
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            tcp.bind(("127.0.0.1", port))
            udp.bind(("127.0.0.1", port))


if __name__ == "__main__":
    unittest.main(verbosity=2)
