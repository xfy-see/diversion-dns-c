#!/usr/bin/env python3
"""Fixed-config loopback tests. No public DNS, routers, or kernel nft writes.

Shared wire/socket fixtures are imported from the retained legacy suite; none
of its YAML/plugin tests are selected by this test module.
"""
import concurrent.futures
import contextlib
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import time
import unittest

import integration as support

BIN = support.BIN
query = support.query
question = support.question
receive_exact = support.receive_exact
address = support.address
RULES = "# All four original rule kinds\ndomain:cn\nfull:exact.test\nkeyword:needle\nregexp:^asset-[0-9]+\\.test$\n"


def udp_exchange(port, packet, timeout=8):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, ("127.0.0.1", port))
        return sock.recv(65535)


def tcp_exchange(port, packet):
    with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
        sock.sendall(struct.pack("!H", len(packet)) + packet)
        return receive_exact(sock, struct.unpack("!H", receive_exact(sock, 2))[0])


def config_text(config, rules):
    values = dict(config)
    values.setdefault("cn_domain_file", str(rules))
    return "".join(f"{key}={item}\n" for key, value in values.items()
                   for item in (value if isinstance(value, list) else [value]))


@contextlib.contextmanager
def running(config):
    with tempfile.TemporaryDirectory(prefix="fixed-dns-integration-") as tmp:
        root = Path(tmp)
        rules = root / "cn.txt"
        rules.write_text(RULES)
        path = root / "config.conf"
        path.write_text(config_text(config, rules))
        process = subprocess.Popen([str(BIN), "start", "-c", str(path), "--cpu", "4"],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        port = int(config["listen_tcp"].rsplit(":", 1)[1])
        try:
            deadline = time.monotonic() + 5
            while True:
                if process.poll() is not None:
                    raise AssertionError(process.communicate()[1].decode())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise AssertionError("fixed server startup timed out")
                    time.sleep(0.025)
            yield port
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                out, err = process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                out, err = process.communicate()
                raise AssertionError(f"server failed to stop: {out!r} {err!r}")
            if process.returncode != 0:
                raise AssertionError(f"server exit {process.returncode}: {err.decode()} {out.decode()}")


class MockDNS(support.MockDNS):
    """Cross-group CNAME targets plus malformed/wrong upstream replies."""
    def __init__(self, ip, ttl=60, mode="normal"):
        self.mode = mode
        super().__init__(ip, ttl)

    def reply(self, packet, transport):
        response = super().reply(packet, transport)
        name, typ, cls, end = question(packet)
        if name.startswith("alias."):
            target = "target.foreign.test" if self.address.startswith("192.") else "target.cn"
            wire = b"".join(bytes([len(label)]) + label.encode() for label in target.split(".")) + b"\0"
            cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, self.ttl, len(wire)) + wire
            address_rr = struct.pack("!H", 0xC000 | (end + 12)) + response[end + 2:]
            response = response[:6] + struct.pack("!H", 2) + response[8:end] + cname + address_rr
        return response

    def serve_udp(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                if len(packet) < 12:
                    continue
                response = self.reply(packet, "udp")
                if self.mode == "silent":
                    continue
                name = question(packet)[0]
                if name.startswith("spoof.") or self.mode == "wrong_only":
                    self.udp.sendto(bytes([response[0] ^ 0x80]) + response[1:], peer)
                    altered = bytearray(response)
                    altered[13] ^= 1  # Valid wire question with the wrong QNAME.
                    self.udp.sendto(altered, peer)
                    if self.mode == "wrong_only":
                        continue
                self.udp.sendto(response, peer)
            except socket.timeout:
                continue
            except OSError:
                return


class FixedIntegration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cn, cls.foreign = MockDNS("192.0.2.9"), MockDNS("203.0.113.9")

    @classmethod
    def tearDownClass(cls):
        cls.cn.close()
        cls.foreign.close()

    def config(self, **extra):
        port = support.unused_port()
        config = {"listen_udp": f"127.0.0.1:{port}", "listen_tcp": f"127.0.0.1:{port}",
                  "cn_upstream": f"127.0.0.1:{self.cn.port}",
                  "foreign_upstream": f"127.0.0.1:{self.foreign.port}",
                  "cache_size": 64, "tcp_idle_timeout": 2}
        config.update(extra)
        return config

    def check(self, config, rules_text=RULES):
        with tempfile.TemporaryDirectory(prefix="fixed-dns-check-") as tmp:
            root = Path(tmp)
            rules = root / "cn.txt"
            rules.write_text(rules_text)
            path = root / "config.conf"
            path.write_text(config_text(config, rules))
            return subprocess.run([str(BIN), "check", "-c", str(path)], capture_output=True, timeout=5)

    def test_split_cname_and_cross_transport_cache(self):
        cases = [("www.cn", True), ("exact.test", True), ("sub.exact.test", False),
                 ("badcn", False), ("hayneedle.test", True), ("asset-12.test", True),
                 ("alias.cn", True), ("alias.foreign.test", False)]
        with running(self.config()) as port:
            for i, (name, cn) in enumerate(cases):
                with self.subTest(name=name):
                    before_cn, before_foreign = self.cn.count(name), self.foreign.count(name)
                    response = udp_exchange(port, query(name, 200+i))
                    self.assertEqual(address(response), "192.0.2.9" if cn else "203.0.113.9")
                    response = tcp_exchange(port, query(name, 300+i))
                    self.assertEqual(struct.unpack_from("!H", response)[0], 300+i)
                    self.assertEqual(address(response), "192.0.2.9" if cn else "203.0.113.9")
                    self.assertEqual(self.cn.count(name), before_cn + int(cn))
                    self.assertEqual(self.foreign.count(name), before_foreign + int(not cn))
                    self.assertEqual(struct.unpack_from("!H", response, 6)[0], 2 if name.startswith("alias.") else 1)
            self.assertEqual(address(udp_exchange(port, query("v6.cn", qtype=28))), "2001:db8::9")
            self.assertEqual(address(tcp_exchange(port, query("v6.foreign.test", qtype=28))), "2001:db8::9")

    def test_udp_truncation_tcp_fallback_and_wrong_response_filter(self):
        with running(self.config()) as port:
            before_udp = self.foreign.count("tc.fixed.test", "udp")
            before_tcp = self.foreign.count("tc.fixed.test", "tcp")
            response = udp_exchange(port, query("tc.fixed.test", 991))
            self.assertFalse(struct.unpack_from("!H", response, 2)[0] & 0x0200)
            self.assertEqual(address(response), "203.0.113.9")
            self.assertEqual(self.foreign.count("tc.fixed.test", "udp"), before_udp+1)
            self.assertEqual(self.foreign.count("tc.fixed.test", "tcp"), before_tcp+1)
            response = udp_exchange(port, query("spoof.fixed.test", 992))
            self.assertEqual(struct.unpack_from("!H", response)[0], 992)
            self.assertEqual(question(response)[0], "spoof.fixed.test")
            self.assertEqual(address(response), "203.0.113.9")

    def test_client_udp_limit_and_tcp_full_answer(self):
        with running(self.config()) as port:
            response = udp_exchange(port, query("big.fixed.test"))
            self.assertLessEqual(len(response), 512)
            self.assertTrue(struct.unpack_from("!H", response, 2)[0] & 0x0200)
            response = tcp_exchange(port, query("big.fixed.test", 101))
            self.assertEqual(struct.unpack_from("!H", response, 6)[0], 40)
            response = udp_exchange(port, query("big.fixed.test", 102, edns=1232))
            self.assertEqual(struct.unpack_from("!H", response, 6)[0], 40)

    def test_negative_cache_flags_types_and_disabled_cache(self):
        with running(self.config()) as port:
            before = self.foreign.count("nx.fixed.test")
            for ident in (130, 131):
                response = udp_exchange(port, query("nx.fixed.test", ident))
                self.assertEqual(struct.unpack_from("!H", response, 2)[0] & 15, 3)
                self.assertEqual(struct.unpack_from("!H", response, 6)[0], 0)
            self.assertEqual(self.foreign.count("nx.fixed.test"), before+1)
            before = self.foreign.count("flags.fixed.test")
            for flags, do in ((0x0100, False), (0x0120, False), (0x0110, False), (0x0100, True)):
                for ident in (140, 141):
                    udp_exchange(port, query("flags.fixed.test", ident, flags=flags, edns=1232, do=do))
            self.assertEqual(self.foreign.count("flags.fixed.test"), before+4)
            udp_exchange(port, query("flags.fixed.test", qtype=28))
            self.assertEqual(self.foreign.count("flags.fixed.test"), before+5)
        with running(self.config(cache_size=0)) as port:
            before = self.cn.count("uncached.cn")
            udp_exchange(port, query("uncached.cn"))
            tcp_exchange(port, query("uncached.cn", 900))
            self.assertEqual(self.cn.count("uncached.cn"), before+2)

    def test_repeated_connections_partial_frames_and_pipeline(self):
        with running(self.config()) as port:
            for i in range(48):
                typ = 28 if i % 3 == 0 else 1
                name = f"cold-{i}.cn" if i % 2 else f"cold-{i}.foreign.test"
                response = (tcp_exchange if i % 2 else udp_exchange)(port, query(name, 1000+i, qtype=typ))
                self.assertEqual(struct.unpack_from("!H", response)[0], 1000+i)
                self.assertEqual(question(response)[:3], (name, typ, 1))
            with socket.create_connection(("127.0.0.1", port), timeout=8) as sock:
                first = query("persistent.cn", 120)
                frame = struct.pack("!H", len(first)) + first
                sock.sendall(frame[:1]); sock.sendall(frame[1:5]); sock.sendall(frame[5:])
                response = receive_exact(sock, struct.unpack("!H", receive_exact(sock, 2))[0])
                self.assertEqual(struct.unpack_from("!H", response)[0], 120)
                frames = [query("pipeline.cn", 121), query("pipeline.foreign.test", 122)]
                sock.sendall(b"".join(struct.pack("!H", len(packet)) + packet for packet in frames))
                for ident in (121, 122):
                    response = receive_exact(sock, struct.unpack("!H", receive_exact(sock, 2))[0])
                    self.assertEqual(struct.unpack_from("!H", response)[0], ident)

    def test_tcp_upstream_and_parallel_clients(self):
        config = self.config(foreign_upstream=f"tcp://127.0.0.1:{self.foreign.port}")
        with running(config) as port:
            def client(i):
                name = f"parallel-{i}.cn" if i % 2 else f"parallel-{i}.foreign.test"
                response = (tcp_exchange if i % 2 else udp_exchange)(port, query(name, 2000+i))
                return struct.unpack_from("!H", response)[0], address(response)
            with concurrent.futures.ThreadPoolExecutor(max_workers=12) as executor:
                actual = list(executor.map(client, range(36)))
            self.assertEqual(actual, [(2000+i, "192.0.2.9" if i % 2 else "203.0.113.9") for i in range(36)])

    def test_idle_timeout_does_not_cancel_active_query(self):
        mock = MockDNS("203.0.113.9")
        try:
            with running(self.config(tcp_idle_timeout=1, foreign_upstream=f"127.0.0.1:{mock.port}")) as port:
                self.assertEqual(address(tcp_exchange(port, query("slow.fixed.test"))), "203.0.113.9")
        finally:
            mock.close()

    def test_upstream_timeout_wrong_only_and_transport_failure(self):
        for mode in ("silent", "wrong_only"):
            with self.subTest(mode=mode):
                mock = MockDNS("203.0.113.9", mode=mode)
                try:
                    name = f"failure-{mode}.foreign.test"
                    before_cn = self.cn.count(name)
                    with running(self.config(foreign_upstream=f"127.0.0.1:{mock.port}")) as port:
                        response = udp_exchange(port, query(name, 6000))
                        self.assertEqual(struct.unpack_from("!H", response)[0], 6000)
                        self.assertEqual(struct.unpack_from("!H", response, 2)[0] & 15, 2)
                        self.assertEqual(struct.unpack_from("!H", response, 6)[0], 0)
                        self.assertGreaterEqual(mock.count(name), 1)
                        self.assertEqual(self.cn.count(name), before_cn)
                finally:
                    mock.close()
        closed = support.unused_port(22000, 23024)
        with running(self.config(foreign_upstream=f"tcp://127.0.0.1:{closed}")) as port:
            for ident in (6001, 6002):
                response = tcp_exchange(port, query("closed.foreign.test", ident))
                self.assertEqual(struct.unpack_from("!H", response)[0], ident)
                self.assertEqual(struct.unpack_from("!H", response, 2)[0] & 15, 2)
            self.assertEqual(address(udp_exchange(port, query("after-failure.cn"))), "192.0.2.9")

    def test_lazy_refresh(self):
        mock = MockDNS("203.0.113.77", ttl=1)
        try:
            with running(self.config(cache_lazy_ttl=30, foreign_upstream=f"127.0.0.1:{mock.port}")) as port:
                udp_exchange(port, query("lazy.fixed.test"))
                time.sleep(2.05)
                responses = [udp_exchange(port, query("lazy.fixed.test", 700+i)) for i in range(4)]
                for response in responses:
                    self.assertEqual(struct.unpack_from("!I", response, question(response)[3]+6)[0], 5)
                deadline = time.monotonic()+3
                while mock.count("lazy.fixed.test") < 2 and time.monotonic() < deadline:
                    time.sleep(0.025)
                time.sleep(0.2)
                self.assertEqual(mock.count("lazy.fixed.test"), 2)
        finally:
            mock.close()

    def test_check_loads_rules_without_binding_or_nft_writes(self):
        config = self.config(nftset_ipv4="inet,not_created,cn4,ipv4_addr,32",
                             nftset_ipv6="ip6,not_created,cn6,ipv6_addr,128")
        port = int(config["listen_tcp"].rsplit(":", 1)[1])
        with socket.socket() as tcp, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", port)); tcp.listen(); udp.bind(("127.0.0.1", port))
            result = self.check(config)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
        missing = self.config(cn_domain_file="/definitely/missing/fixed-cn-rules.txt")
        result = self.check(missing)
        self.assertNotEqual(result.returncode, 0)
        self.assertRegex(result.stderr.decode(), r"config\.conf:\d+:")
        result = self.check(self.config(), "full:valid.test\nregexp:[\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cn.txt", result.stderr.decode())
        self.assertRegex(result.stderr.decode(), r"config\.conf:\d+:")

    def test_invalid_cli_and_legacy_configuration(self):
        arguments = [("unknown",), ("version", "unexpected"), ("check", "-c"),
                     ("check", "--cpu", "2"), ("start", "--cpu", "0"),
                     ("start", "--cpu", "65"), ("start", "--cpu", "-1"),
                     ("start", "--cpu", "invalid"), ("start", "--unknown", "x")]
        for args in arguments:
            with self.subTest(args=args):
                result = subprocess.run([str(BIN), *args], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr)
        for text in ("plugins: []\n", '{"plugins": []}\n', "include=old.yaml\n"):
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "config.yaml"
                path.write_text(text)
                result = subprocess.run([str(BIN), "check", "-c", str(path)], capture_output=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertRegex(result.stderr.decode(), r"config\.yaml:\d+:")

    def test_malformed_client_does_not_stop_server(self):
        with running(self.config()) as port:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"bad", ("127.0.0.1", port))
                cyclic = struct.pack("!6H", 12, 0x100, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1"
                sock.sendto(cyclic, ("127.0.0.1", port))
            with socket.create_connection(("127.0.0.1", port), timeout=4) as sock:
                sock.sendall(b"\0\x03bad")
            self.assertEqual(address(udp_exchange(port, query("after-bad.cn"))), "192.0.2.9")


if __name__ == "__main__":
    unittest.main(verbosity=2)
