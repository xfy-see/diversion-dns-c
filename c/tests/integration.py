#!/usr/bin/env python3
"""Deterministic loopback tests; no public DNS or production listeners."""
import concurrent.futures
import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest

BIN = Path(sys.argv.pop(1)).resolve()
ROOT = Path(__file__).resolve().parents[2]


def query(name, ident=100, qtype=1, flags=0x0100, edns=None, do=False, qclass=1):
    wire = b"".join(bytes([len(x)]) + x.encode() for x in name.rstrip(".").split(".")) + b"\0"
    packet = struct.pack("!6H", ident, flags, 1, 0, 0, int(edns is not None))
    packet += wire + struct.pack("!2H", qtype, qclass)
    if edns is not None:
        packet += b"\0" + struct.pack("!HHIH", 41, edns, 0x8000 if do else 0, 0)
    return packet


def question(packet):
    pos, labels = 12, []
    while packet[pos]:
        length = packet[pos]
        labels.append(packet[pos + 1:pos + 1 + length].decode())
        pos += length + 1
    end = pos + 5
    typ, cls = struct.unpack_from("!2H", packet, pos + 1)
    return ".".join(labels), typ, cls, end


def receive_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("short DNS TCP frame")
        data += chunk
    return data


def udp_exchange(port, packet):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(4)
        s.sendto(packet, ("127.0.0.1", port))
        return s.recv(65535)


def tcp_exchange(port, packet):
    with socket.create_connection(("127.0.0.1", port), timeout=4) as s:
        s.sendall(struct.pack("!H", len(packet)) + packet)
        return receive_exact(s, struct.unpack("!H", receive_exact(s, 2))[0])


def bound_loopback_pair():
    # TCP and UDP ephemeral allocations are independent. Hold both sockets
    # before starting a fixture; a collision here has not run a product test.
    for _ in range(128):
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            udp.bind(("127.0.0.1", port))
            return tcp, udp, port
        except BaseException as error:
            tcp.close()
            udp.close()
            if isinstance(error, OSError) and error.errno == errno.EADDRINUSE:
                continue
            raise
    raise RuntimeError("could not reserve a TCP+UDP mock port in 128 attempts")


class MockDNS:
    def __init__(self, address, ttl=60):
        self.address, self.ttl = address, ttl
        self.tcp, self.udp, self.port = bound_loopback_pair()
        self.tcp.listen()
        self.tcp.settimeout(0.1)
        self.udp.settimeout(0.1)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = {}
        self.threads = [threading.Thread(target=self.serve_udp), threading.Thread(target=self.serve_tcp)]
        for t in self.threads:
            t.start()

    def count(self, name=None, transport=None):
        with self.lock:
            return sum(v for (n, p), v in self.counts.items()
                       if (name is None or n == name) and (transport is None or p == transport))

    def reply(self, packet, transport):
        name, typ, cls, end = question(packet)
        with self.lock:
            self.counts[name, transport] = self.counts.get((name, transport), 0) + 1
            count = self.counts[name, transport]
        if name.startswith("lazy.") and count > 1:
            self.stop.wait(0.15)
        if name.startswith("slow."):
            self.stop.wait(2.25)
        rcode = 3 if name.startswith("nx.") else 0
        tc = transport == "udp" and name.startswith("tc.")
        answers = 0 if tc or rcode else (40 if name.startswith("big.") else 1)
        flags = 0x8180 | (0x0200 if tc else 0) | rcode
        response = struct.pack("!6H", struct.unpack_from("!H", packet)[0], flags, 1, answers, 0, 0)
        response += packet[12:end]
        addr = socket.inet_pton(socket.AF_INET6, "2001:db8::9") if typ == 28 else socket.inet_aton(self.address)
        for _ in range(answers):
            response += b"\xc0\x0c" + struct.pack("!HHIH", typ, cls, self.ttl, len(addr)) + addr
        return response

    def serve_udp(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                if len(packet) < 12:
                    continue
                response = self.reply(packet, "udp")
                if question(packet)[0].startswith("spoof."):
                    wrong = bytes([response[0] ^ 0x80]) + response[1:]
                    self.udp.sendto(wrong, peer)
                self.udp.sendto(response, peer)
            except socket.timeout:
                continue
            except OSError:
                return

    def serve_tcp(self):
        while not self.stop.is_set():
            try:
                s, _ = self.tcp.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with s:
                s.settimeout(0.3)
                while not self.stop.is_set():
                    try:
                        size = struct.unpack("!H", receive_exact(s, 2))[0]
                        response = self.reply(receive_exact(s, size), "tcp")
                        framed = struct.pack("!H", len(response)) + response
                        # Exercise partial reads in the C upstream.
                        s.sendall(framed[:1])
                        s.sendall(framed[1:])
                    except (EOFError, OSError):
                        break

    def close(self):
        self.stop.set()
        for t in self.threads:
            t.join(2)
        self.tcp.close()
        self.udp.close()
        if any(t.is_alive() for t in self.threads):
            raise RuntimeError("mock DNS worker did not stop")


def unused_port(low=20000, high=21024):
    # Probe both listener transports while held together. This selects a port
    # before a test starts; it never retries a failed product test.
    if not (type(low) is int and type(high) is int and 1 <= low < high <= 65536):
        raise ValueError("invalid test service port range")
    for port in range(low, high):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            try:
                tcp.bind(("127.0.0.1", port))
                udp.bind(("127.0.0.1", port))
            except OSError as error:
                if error.errno != errno.EADDRINUSE:
                    raise
                continue
            return port
    raise RuntimeError("no free TCP+UDP test service port in bounded range")


def plugins(a, b, port, lazy=0):
    return [
        {"tag": "cn", "type": "domain_set", "args": {"exps": ["domain:cn", "full:exact.test", "keyword:needle", "regexp:^asset-[0-9]+\\.test$"]}},
        {"tag": "cache", "type": "cache", "args": {"size": 64, "lazy_cache_ttl": lazy}},
        {"tag": "direct", "type": "forward", "args": {"upstreams": [{"addr": f"127.0.0.1:{a.port}"}]}},
        {"tag": "foreign", "type": "forward", "args": {"upstreams": [{"addr": f"127.0.0.1:{b.port}"}]}},
        {"tag": "main", "type": "sequence", "args": [
            {"exec": "$cache"},
            {"matches": ["has_resp"], "exec": "accept"},
            {"matches": ["qname $cn"], "exec": "goto domestic"},
            {"exec": "$foreign"}]},
        {"tag": "domestic", "type": "sequence", "args": [{"exec": "$direct"}]},
        {"type": "udp_server", "args": {"entry": "main", "listen": f"127.0.0.1:{port}"}},
        {"type": "tcp_server", "args": {"entry": "main", "listen": f"127.0.0.1:{port}", "idle_timeout": 2}},
    ]


@contextlib.contextmanager
def running(config):
    with tempfile.TemporaryDirectory(prefix="mosdns-c-test-") as tmp:
        path = Path(tmp) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen([str(BIN), "start", "-c", str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        port = int(config["plugins"][-1]["args"]["listen"].rsplit(":", 1)[1])
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
                        raise AssertionError("server startup timed out")
                    time.sleep(0.025)
            yield port
        finally:
            process.send_signal(signal.SIGTERM) if process.poll() is None else None
            out, err = process.communicate(timeout=8)
            if process.returncode != 0:
                raise AssertionError(f"server exit {process.returncode}: {err.decode()} {out.decode()}")


def address(response):
    return socket.inet_ntop(socket.AF_INET6 if question(response)[1] == 28 else socket.AF_INET, response[-16:] if question(response)[1] == 28 else response[-4:])


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.a, cls.b = MockDNS("192.0.2.9"), MockDNS("203.0.113.9")

    @classmethod
    def tearDownClass(cls):
        cls.a.close()
        cls.b.close()

    def config(self, lazy=0):
        return {"log": {"level": "error"}, "plugins": plugins(self.a, self.b, unused_port(), lazy)}

    def check(self, config):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.json"
            path.write_text(json.dumps(config))
            return subprocess.run([str(BIN), "check", "-c", str(path)], capture_output=True, timeout=5)

    def test_site_split_cache_udp_tcp(self):
        config = self.config()
        with running(config) as port:
            cases = [("www.cn", "192.0.2.9"), ("exact.test", "192.0.2.9"),
                     ("badcn", "203.0.113.9"), ("sub.exact.test", "203.0.113.9"),
                     ("hayneedle.test", "192.0.2.9"), ("asset-12.test", "192.0.2.9")]
            for i, (name, expected) in enumerate(cases):
                with self.subTest(name=name):
                    before = self.a.count(name) + self.b.count(name)
                    r = udp_exchange(port, query(name, 200 + i))
                    self.assertEqual(address(r), expected)
                    r = tcp_exchange(port, query(name, 300 + i))
                    self.assertEqual(struct.unpack_from("!H", r)[0], 300 + i)
                    self.assertEqual(address(r), expected)
                    self.assertEqual(self.a.count(name) + self.b.count(name), before + 1)
            self.assertEqual(address(udp_exchange(port, query("v6.cn", qtype=28))), "2001:db8::9")

    def test_udp_tc_fallback_and_spoof_filter(self):
        with running(self.config()) as port:
            before_udp, before_tcp = self.b.count("tc.test", "udp"), self.b.count("tc.test", "tcp")
            r = udp_exchange(port, query("tc.test", 991))
            self.assertFalse(struct.unpack_from("!H", r, 2)[0] & 0x0200)
            self.assertEqual(address(r), "203.0.113.9")
            self.assertEqual(self.b.count("tc.test", "udp"), before_udp + 1)
            self.assertEqual(self.b.count("tc.test", "tcp"), before_tcp + 1)
            r = udp_exchange(port, query("spoof.test", 992))
            self.assertEqual(struct.unpack_from("!H", r)[0], 992)

    def test_udp_edns_size_and_tcp_full_answer(self):
        with running(self.config()) as port:
            r = udp_exchange(port, query("big.test"))
            self.assertLessEqual(len(r), 512)
            self.assertTrue(struct.unpack_from("!H", r, 2)[0] & 0x0200)
            r = tcp_exchange(port, query("big.test", 101))
            self.assertEqual(struct.unpack_from("!H", r, 6)[0], 40)
            r = udp_exchange(port, query("big.test", 102, edns=1232))
            self.assertEqual(struct.unpack_from("!H", r, 6)[0], 40)

    def test_reused_jobs_keep_packet_lengths_and_client_identity(self):
        # Alternate large/small, A/AAAA, UDP/TCP and negative replies so reused
        # storage cannot leak a previous packet tail, ID or destination.
        cases = [("big.reuse.test", 28, 40), ("short.cn", 1, 1),
                 ("nx.reuse.test", 1, 0), ("v6.reuse.cn", 28, 1)]
        with running(self.config()) as port:
            for i in range(96):
                name, typ, answers = cases[i % len(cases)]
                packet = query(name, 1000 + i, qtype=typ, edns=1232)
                exchange = tcp_exchange if (i // len(cases)) % 2 else udp_exchange
                r = exchange(port, packet)
                self.assertEqual(struct.unpack_from("!H", r)[0], 1000 + i)
                self.assertEqual(question(r)[:3], (name, typ, 1))
                self.assertEqual(struct.unpack_from("!H", r, 6)[0], answers)
                self.assertEqual(struct.unpack_from("!H", r, 2)[0] & 15, 3 if not answers else 0)
                self.assertEqual(len(r), question(r)[3] + answers * (28 if typ == 28 else 16))

    def test_cold_worker_buffers_preserve_lengths_ids_and_fallback(self):
        # Every name is unique: all requests must traverse the worker/upstream
        # path, even when the cache fast path is enabled. Repeat an ID across
        # different questions to exercise connection retirement as well.
        kinds = [("big", 28, 40), ("small", 1, 1), ("nx", 1, 0),
                 ("spoof", 28, 1), ("tc", 1, 1), ("small", 28, 1)]
        before = self.b.count()
        with running(self.config()) as port:
            for i in range(96):
                prefix, typ, answers = kinds[i % len(kinds)]
                name = f"{prefix}.cold-{i}.test"
                ident = 2000 + i % 12
                packet = query(name, ident, qtype=typ, edns=1232)
                exchange = tcp_exchange if (i // len(kinds)) % 2 else udp_exchange
                r = exchange(port, packet)
                self.assertEqual(struct.unpack_from("!H", r)[0], ident)
                self.assertEqual(question(r)[:3], (name, typ, 1))
                self.assertEqual(struct.unpack_from("!H", r, 6)[0], answers)
                self.assertEqual(struct.unpack_from("!H", r, 2)[0] & 15, 3 if not answers else 0)
                self.assertFalse(struct.unpack_from("!H", r, 2)[0] & 0x0200)
                self.assertEqual(len(r), question(r)[3] + answers * (28 if typ == 28 else 16))
                self.assertEqual(self.b.count(name), 2 if prefix == "tc" else 1)
        self.assertEqual(self.b.count() - before, 96 + 16)

    def test_persistent_tcp_partial_frames_and_pipeline(self):
        with running(self.config()) as port, socket.create_connection(("127.0.0.1", port), timeout=4) as s:
            first = query("persistent.cn", 120)
            frame = struct.pack("!H", len(first)) + first
            s.sendall(frame[:1])
            s.sendall(frame[1:5])
            s.sendall(frame[5:])
            self.assertEqual(struct.unpack_from("!H", receive_exact(s, struct.unpack("!H", receive_exact(s, 2))[0]))[0], 120)
            frames = b"".join(struct.pack("!H", len(q)) + q for q in [query("pipeline.cn", 121), query("pipeline.test", 122)])
            s.sendall(frames)
            for ident in [121, 122]:
                r = receive_exact(s, struct.unpack("!H", receive_exact(s, 2))[0])
                self.assertEqual(struct.unpack_from("!H", r)[0], ident)

    def test_negative_cache_and_flag_isolation(self):
        with running(self.config()) as port:
            before = self.b.count("nx.test")
            for ident in [130, 131]:
                r = udp_exchange(port, query("nx.test", ident))
                self.assertEqual(struct.unpack_from("!H", r, 2)[0] & 15, 3)
            self.assertEqual(self.b.count("nx.test"), before + 1)
            before = self.b.count("flags.test")
            for flags, do in [(0x0100, False), (0x0120, False), (0x0110, False), (0x0100, True)]:
                udp_exchange(port, query("flags.test", flags=flags, edns=1232, do=do))
            self.assertEqual(self.b.count("flags.test"), before + 4)

    def test_tcp_idle_timeout_does_not_cancel_active_query(self):
        # This UDP upstream deliberately sleeps while handling each query.
        # Retries can leave duplicate slow queries queued after the first reply;
        # isolate that backlog from later tests while retaining the UDP path.
        mock = MockDNS("203.0.113.9")
        c = self.config()
        c["plugins"][-1]["args"]["idle_timeout"] = 1
        c["plugins"][3]["args"]["upstreams"][0]["addr"] = f"127.0.0.1:{mock.port}"
        try:
            with running(c) as port:
                self.assertEqual(address(tcp_exchange(port, query("slow.test"))), "203.0.113.9")
        finally:
            mock.close()

    def test_tcp_upstream_and_tag_selection(self):
        c = self.config()
        c["plugins"][3]["args"]["upstreams"] = [
            {"tag": "chosen", "addr": f"tcp://127.0.0.1:{self.b.port}"},
            {"tag": "other", "addr": f"127.0.0.1:{self.a.port}"}]
        c["plugins"][4]["args"][-1]["exec"] = "$foreign chosen"
        with running(c) as port:
            self.assertEqual(address(udp_exchange(port, query("tcp-upstream.test"))), "203.0.113.9")

    def test_sequence_jump_goto_return_and_negation(self):
        config = self.config()
        config["plugins"][4]["args"] = [
            {"matches": ["_true", "! _false"], "exec": "jump sub"},
            {"exec": "$foreign"}]
        config["plugins"].insert(6, {"tag": "sub", "type": "sequence", "args": [{"exec": "return"}, {"exec": "reject 5"}]})
        with running(config) as port:
            self.assertEqual(address(udp_exchange(port, query("return.test"))), "203.0.113.9")
        config["plugins"][4]["args"][0]["exec"] = "goto domestic"
        with running(config) as port:
            self.assertEqual(address(udp_exchange(port, query("goto.test"))), "192.0.2.9")
        config["plugins"][4]["args"] = [{"matches": ["_true", "_false"], "exec": "reject 5"}, {"exec": "reject 3"}]
        with running(config) as port:
            self.assertEqual(struct.unpack_from("!H", udp_exchange(port, query("and.test")), 2)[0] & 15, 3)

    def test_parallel_clients(self):
        with running(self.config()) as port:
            def run(i):
                q = query(f"parallel-{i}.cn", 1000 + i)
                r = (tcp_exchange if i % 2 else udp_exchange)(port, q)
                return struct.unpack_from("!H", r)[0], address(r)
            with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
                responses = list(ex.map(run, range(48)))
            self.assertEqual(responses, [(1000 + i, "192.0.2.9") for i in range(48)])

    def test_lazy_refresh(self):
        mock = MockDNS("203.0.113.77", ttl=1)
        config = self.config(lazy=30)
        config["plugins"][3]["args"]["upstreams"][0]["addr"] = f"127.0.0.1:{mock.port}"
        try:
            with running(config) as port:
                udp_exchange(port, query("lazy.test"))
                time.sleep(2.05)
                q = query("lazy.test", 700)
                responses = [udp_exchange(port, q) for _ in range(4)]
                for r in responses:
                    self.assertEqual(struct.unpack_from("!I", r, question(r)[3] + 6)[0], 5)
                deadline = time.monotonic() + 2
                while mock.count("lazy.test") < 2 and time.monotonic() < deadline:
                    time.sleep(0.025)
                time.sleep(0.2)
                self.assertEqual(mock.count("lazy.test"), 2)
        finally:
            mock.close()

    def test_check_example_no_rule_files_or_sockets(self):
        p = subprocess.run([str(BIN), "check", "-c", str(ROOT / "docs/go-profiles-site-only.yaml")], capture_output=True, timeout=5)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        config = self.config()
        config["plugins"][0]["args"] = {"files": ["/missing/read-only-test.txt"]}
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", int(config["plugins"][-1]["args"]["listen"].split(":")[-1])))
            occupied.listen()
            p = self.check(config)
            self.assertEqual(p.returncode, 0, p.stderr.decode())

    def test_profile_rejects_unsupported_features(self):
        changes = [
            lambda c: c.update(api={"http": "127.0.0.1:9091"}),
            lambda c: c["plugins"][1]["args"].update(dump_file="cache.gz"),
            lambda c: c["plugins"][1]["args"].update(dump_interval=-1),
            lambda c: c["plugins"][3]["args"]["upstreams"][0].update(addr="https://1.1.1.1/dns-query"),
            lambda c: c["plugins"][3]["args"]["upstreams"][0].update(addr="dns.example:53"),
            lambda c: c["plugins"][3]["args"].update(socks5="127.0.0.1:1080"),
            lambda c: c["plugins"][-1]["args"].update(cert="cert.pem"),
            lambda c: c["plugins"][0].update(type="ip_set"),
            lambda c: c["plugins"][4]["args"][0].update(exec="$missing"),
            lambda c: c["plugins"][4]["args"][0].update(matches=["qtype 1"]),
        ]
        for change in changes:
            with self.subTest(change=change):
                c = self.config()
                change(c)
                p = self.check(c)
                self.assertNotEqual(p.returncode, 0, p.stdout.decode())
                self.assertTrue(p.stderr)

    def test_file_rules_and_include(self):
        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "rules.txt"
            rules.write_text("# comment\n\ndomain:file-cn.test # inline\nfull:file-only.test\n")
            fragment = Path(tmp) / "extra.yaml"
            fragment.write_text("plugins:\n  - tag: file_set\n    type: domain_set\n    args:\n      files: [\"" + str(rules) + "\"]\n")
            c = self.config()
            c["include"] = [str(fragment)]
            c["plugins"][4]["args"][2]["matches"] = ["qname $file_set"]
            with running(c) as port:
                self.assertEqual(address(udp_exchange(port, query("sub.file-cn.test"))), "192.0.2.9")
                self.assertEqual(address(udp_exchange(port, query("sub.file-only.test"))), "203.0.113.9")

    def test_malformed_datagram_does_not_stop_server(self):
        with running(self.config()) as port:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(b"bad", ("127.0.0.1", port))
                cyclic = struct.pack("!6H", 12, 0x100, 1, 0, 0, 0) + b"\xc0\x0c\0\1\0\1"
                s.sendto(cyclic, ("127.0.0.1", port))
            self.assertEqual(address(udp_exchange(port, query("after-bad.cn"))), "192.0.2.9")


if __name__ == "__main__":
    unittest.main(verbosity=2)
