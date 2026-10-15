#!/usr/bin/env python3
"""Loopback black-box cache refresh regressions; never builds C or writes nft.

Run with --application /path/to/verified/mosdns-c --output results-directory.
The output directory must not exist. DNS request/response bytes, upstream unique
transactions, application output, configuration and failed assertions are kept.
Only standard-library modules are used; fixtures can be imported without argv or
network side effects. `tests/test_cache_refresh_safety_fixture.py` tests the wire
builders and the retransmission-aware accounting without running the application.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import dataclasses
import errno
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import threading
import time
import traceback


OLD = {1: "203.0.113.10", 28: "2001:db8::10"}
NEW = {1: "203.0.113.99", 28: "2001:db8::99"}


def wire_name(name):
    labels = name.rstrip(".").split(".")
    encoded = [label.encode("ascii") for label in labels]
    if any(not label or len(label) > 63 for label in encoded):
        raise ValueError("invalid DNS label")
    result = b"".join(bytes([len(label)]) + label for label in encoded) + b"\0"
    if len(result) > 255:
        raise ValueError("DNS name too long")
    return result


def query(name, qtype=1, ident=100):
    return struct.pack("!6H", ident, 0x0100, 1, 0, 0, 0) + wire_name(name) + struct.pack("!HH", qtype, 1)


def read_name(packet, offset):
    labels, visited, end = [], set(), None
    for _ in range(256):
        if offset in visited or offset >= len(packet):
            raise ValueError("invalid DNS name pointer")
        visited.add(offset)
        size = packet[offset]
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("truncated pointer")
            if end is None:
                end = offset + 2
            offset = ((size & 63) << 8) | packet[offset + 1]
            continue
        if size & 0xC0 or offset + 1 + size > len(packet):
            raise ValueError("invalid DNS label")
        offset += 1
        if not size:
            return ".".join(labels), end if end is not None else offset
        labels.append(packet[offset:offset + size].decode("ascii"))
        offset += size
    raise ValueError("name too long")


def question(packet):
    if len(packet) < 12 or struct.unpack_from("!H", packet, 4)[0] != 1:
        raise ValueError("one question required")
    name, offset = read_name(packet, 12)
    typ, cls = struct.unpack_from("!HH", packet, offset)
    return name, typ, cls, offset + 4


@dataclasses.dataclass(frozen=True)
class Policy:
    mode: str = "normal"
    ttl: int = 1
    changed: bool = False
    records: int = 1


def answer(packet, policy):
    _, typ, cls, end = question(packet)
    if policy.mode == "silent":
        return None
    rcode = 2 if policy.mode == "servfail" else 0
    nodata = policy.mode in ("nodata", "nodata_soa")
    count = 0 if rcode or nodata else policy.records
    authority = int(policy.mode == "nodata_soa")
    result = struct.pack("!6H", struct.unpack_from("!H", packet)[0], 0x8180 | rcode,
                         1, count, authority, 0) + packet[12:end]
    addr = ipaddress.ip_address((NEW if policy.changed else OLD)[typ]).packed
    for _ in range(count):
        result += b"\xc0\x0c" + struct.pack("!HHIH", typ, cls, policy.ttl, len(addr)) + addr
    if authority:
        rdata = wire_name("ns.test") + wire_name("hostmaster.test") + struct.pack("!5I", 1, 60, 60, 60, policy.ttl)
        result += b"\xc0\x0c" + struct.pack("!HHIH", 6, 1, policy.ttl, len(rdata)) + rdata
    if policy.mode == "malformed":
        result = result[:-1]  # Valid header, truncated RDATA, never a replacement.
    if policy.mode == "mismatch":
        result = result[:13] + bytes([result[13] ^ 1]) + result[14:]
    return result


def decode(packet):
    _, _, _, end = question(packet)
    header = struct.unpack_from("!6H", packet)
    addresses, ttls = [], []
    for index in range(sum(header[3:])):
        _, end = read_name(packet, end)
        typ, _, ttl, length = struct.unpack_from("!HHIH", packet, end)
        end += 10
        data = packet[end:end + length]
        if len(data) != length:
            raise ValueError("short RDATA")
        end += length
        if index < header[3]:
            ttls.append(ttl)
            if typ in (1, 28):
                addresses.append(str(ipaddress.ip_address(data)))
    if end != len(packet):
        raise ValueError("trailing DNS bytes")
    return {"rcode": header[1] & 15, "answers": header[3], "addresses": addresses, "ttls": ttls}


def transactions(events, *, names=None, since=0):
    """UDP retransmissions retain source port/ID; do not count them as refreshes."""
    groups = {}
    for event in events:
        if event["time"] < since or (names is not None and event["name"] not in names):
            continue
        key = (event["transport"], tuple(event["peer"]), event["id"], event["name"], event["qtype"])
        item = groups.setdefault(key, {**event, "packets": 0})
        item["packets"] += 1
    return list(groups.values())


def rate_bound(start, last, rate=64, burst=8, allowance=2):
    # Two arrivals of tolerance cover scheduling around fractional token refill;
    # the contract itself remains 64/s with an eight-query burst.
    return math.ceil(burst + rate * max(0, last - start)) + allowance


def exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = sock.recv(size - len(chunks))
        if not chunk:
            raise EOFError("short TCP frame")
        chunks.extend(chunk)
    return bytes(chunks)


def unused_port():
    """Probe TCP and UDP together; never retry a failed product startup."""
    for _ in range(128):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            tcp.bind(("127.0.0.1", 0))
            port = tcp.getsockname()[1]
            try:
                udp.bind(("127.0.0.1", port))
            except OSError as error:
                if error.errno == errno.EADDRINUSE:
                    continue
                raise
            return port
    raise RuntimeError("could not reserve a TCP/UDP test port")


class Upstream:
    def __init__(self):
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.policies, self.events, self.errors, self.connections = {}, [], [], set()
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp.bind(("127.0.0.1", 0))
        self.tcp.bind(("127.0.0.1", 0))
        self.udp_port, self.tcp_port = self.udp.getsockname()[1], self.tcp.getsockname()[1]
        self.udp.settimeout(.1)
        self.tcp.settimeout(.1)
        self.tcp.listen(64)
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=32)
        self.threads = [threading.Thread(target=self._udp), threading.Thread(target=self._tcp)]
        for thread in self.threads:
            thread.start()

    def set(self, name, **values):
        with self.lock:
            self.policies[name] = Policy(**values)

    def snapshot(self):
        with self.lock:
            return list(self.events)

    def _reply(self, packet, peer, transport):
        name, typ, _, _ = question(packet)
        with self.lock:
            policy = self.policies.get(name, Policy())
            event = {"time": time.monotonic(), "transport": transport, "peer": list(peer),
                     "name": name, "qtype": typ, "id": struct.unpack_from("!H", packet)[0],
                     "mode": policy.mode, "query_hex": packet.hex()}
            self.events.append(event)
        response = answer(packet, policy)
        event["response_hex"] = None if response is None else response.hex()
        return response

    def _udp(self):
        while not self.stop.is_set():
            try:
                packet, peer = self.udp.recvfrom(65535)
                response = self._reply(packet, peer, "udp")
                if response is not None:
                    self.udp.sendto(response, peer)
            except socket.timeout:
                continue
            except OSError:
                if not self.stop.is_set():
                    self.errors.append(traceback.format_exc())
                break
            except Exception:
                self.errors.append(traceback.format_exc())

    def _tcp(self):
        while not self.stop.is_set():
            try:
                conn, peer = self.tcp.accept()
                with self.lock:
                    self.connections.add(conn)
                self.pool.submit(self._client, conn, peer)
            except socket.timeout:
                continue
            except OSError:
                break

    def _client(self, conn, peer):
        conn.settimeout(.2)
        try:
            # Keep pooled upstream connections alive between queries. A fixture
            # that closes after one answer introduces unrelated reset races.
            while not self.stop.is_set():
                try:
                    prefix = exact(conn, 2)
                except socket.timeout:
                    continue
                packet = exact(conn, struct.unpack("!H", prefix)[0])
                response = self._reply(packet, peer, "tcp")
                if response is not None:
                    conn.sendall(struct.pack("!H", len(response)) + response)
        except (OSError, EOFError):
            pass
        except Exception:
            self.errors.append(traceback.format_exc())
        finally:
            with self.lock:
                self.connections.discard(conn)
            conn.close()

    def close(self):
        self.stop.set()
        self.udp.close()
        self.tcp.close()
        with self.lock:
            conns = list(self.connections)
        for conn in conns:
            with contextlib.suppress(OSError):
                conn.shutdown(socket.SHUT_RDWR)
        for thread in self.threads:
            thread.join(2)
        self.pool.shutdown(wait=True)
        if self.errors:
            raise AssertionError("fixture errors: " + repr(self.errors))


class Suite:
    def __init__(self, application, output):
        self.application, self.output = Path(application).resolve(), Path(output).resolve()
        self.output.mkdir(parents=True, exist_ok=False)
        self.rows, self.clients, self.ident = [], [], 100
        self.upstream = Upstream()
        self.port = None

    @staticmethod
    def require(condition, message):
        if not condition:
            raise AssertionError(message)

    def ask(self, name, typ=1, tcp=False):
        # Concurrent callers need only distinct IDs, not a stable launch order.
        with self.upstream.lock:
            self.ident = (self.ident + 1) & 0xFFFF
            ident = self.ident
        packet = query(name, typ, ident)
        record = {"name": name, "type": typ, "tcp": tcp, "time": time.monotonic(), "query_hex": packet.hex()}
        self.clients.append(record)
        if tcp:
            with socket.create_connection(("127.0.0.1", self.port), 8) as sock:
                sock.sendall(struct.pack("!H", len(packet)) + packet)
                response = exact(sock, struct.unpack("!H", exact(sock, 2))[0])
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(8)
                sock.sendto(packet, ("127.0.0.1", self.port))
                response = sock.recv(65535)
        record.update(response_hex=response.hex(), elapsed=time.monotonic() - record["time"])
        self.require(response[:2] == packet[:2], "wrong client DNS ID")
        self.require(question(response)[:3] == question(packet)[:3], "wrong client question")
        return decode(response)

    def old(self, name, typ=1, tcp=False):
        response = self.ask(name, typ, tcp)
        self.require(response["rcode"] == 0 and response["addresses"] == [OLD[typ]],
                     f"{name}: expected retained old answer, got {response}")
        return response

    def tx(self, names, since=0):
        return transactions(self.upstream.snapshot(), names=set(names), since=since)

    def wait_tx(self, names, count, since=0, timeout=3):
        deadline = time.monotonic() + timeout
        while len(self.tx(names, since)) < count:
            if time.monotonic() >= deadline:
                raise AssertionError(f"expected {count} upstream transactions for {names}")
            time.sleep(.01)
        # An observed upstream send precedes the application's cache commit.
        time.sleep(.15)

    @contextlib.contextmanager
    def running(self, label, tcp_upstream=False, **extra):
        root = self.output / label
        root.mkdir()
        (root / "cn.txt").write_text("domain:cn.test\n")
        (root / "override.txt").write_text("domain:override.test\n")
        self.port = unused_port()
        config = {"listen_udp": f"127.0.0.1:{self.port}", "listen_tcp": f"127.0.0.1:{self.port}",
                  "cn_domain_file": str(root / "cn.txt"),
                  "cn_upstream": f"127.0.0.1:{self.upstream.udp_port}",
                  "foreign_upstream": f"127.0.0.1:{self.upstream.udp_port}", "cache_size": 1024,
                  "cache_stale_ttl": 60, "tcp_idle_timeout": 2}
        if tcp_upstream:
            config["foreign_upstream"] = f"tcp://127.0.0.1:{self.upstream.tcp_port}"
        if extra.pop("override", False):
            config["cache_stale_override"] = f"0:{root / 'override.txt'}"
        config.update(extra)
        path = root / "config.conf"
        path.write_text("".join(f"{key}={value}\n" for key, value in config.items()))
        with (root / "stdout.log").open("wb") as stdout, (root / "stderr.log").open("wb") as stderr:
            process = subprocess.Popen([str(self.application), "start", "-c", str(path), "--cpu", "4"],
                                       stdout=stdout, stderr=stderr, env={**os.environ, "DIVERSION_CACHE_STATS": "1"})
            try:
                deadline = time.monotonic() + 5
                while True:
                    self.require(process.poll() is None, f"application exited during startup; see {root}")
                    try:
                        with socket.create_connection(("127.0.0.1", self.port), .1):
                            break
                    except OSError:
                        self.require(time.monotonic() < deadline, "application startup timed out")
                        time.sleep(.02)
                yield
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                try:
                    process.wait(8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                    raise AssertionError("application shutdown timed out")
                self.require(process.returncode == 0, f"application exit {process.returncode}; see {root}")

    def replacements(self):
        cases = [(f"{mode}-{typ}.replace.test", typ, mode) for typ in (1, 28)
                 for mode in ("ttl0", "nodata", "nodata_soa")]
        with self.running("replacements"):
            for name, typ, _ in cases:
                self.upstream.set(name, ttl=1)
                self.old(name, typ)
            time.sleep(1.2)
            for name, typ, mode in cases:
                self.upstream.set(name, mode="normal" if mode == "ttl0" else mode, ttl=0, changed=True)
                self.old(name, typ)
            self.wait_tx([x[0] for x in cases], 12)
            for name, typ, mode in cases:
                result = self.ask(name, typ)
                expected = [NEW[typ]] if mode == "ttl0" else []
                self.require(result["rcode"] == 0 and result["addresses"] == expected,
                             f"{mode} type {typ} failed to revoke old positive: {result}")
                if mode == "ttl0":
                    self.require(result["ttls"] == [0], "TTL zero must remain zero")
        return {"replacements": 6}

    def oversized(self):
        name = "large.replace.test"
        with self.running("oversized", tcp_upstream=True, cache_max_bytes=4096):
            self.upstream.set(name, ttl=1)
            self.old(name, tcp=True)
            time.sleep(1.2)
            self.upstream.set(name, ttl=30, changed=True, records=300)
            self.old(name, tcp=True)
            self.wait_tx([name], 2)
            result = self.ask(name, tcp=True)
            self.require(result["answers"] == 300 and set(result["addresses"]) == {NEW[1]},
                         "uncacheable large valid answer left the old positive cached")
        return {"new_answer_count": 300, "cache_max_bytes": 4096}

    def failure_preservation(self):
        cases = [(f"{mode}-{typ}.failure.test", typ, mode) for typ in (1, 28)
                 for mode in ("servfail", "silent", "malformed", "mismatch")]
        with self.running("failure-preservation", cache_stale_ttl=8):
            for name, typ, _ in cases:
                self.upstream.set(name, ttl=1)
                self.old(name, typ)
            seeded = time.monotonic()
            time.sleep(1.2)
            for name, typ, mode in cases:
                self.upstream.set(name, mode=mode, changed=True, ttl=30)
                self.old(name, typ)
            self.wait_tx([x[0] for x in cases], 16)
            for name, typ, _ in cases:
                self.old(name, typ)
            # Original TTL(1) + stale(8), plus margin, relative to last seed.
            time.sleep(max(0, seeded + 9.5 - time.monotonic()))
            for name, _, _ in cases:
                self.upstream.set(name, mode="servfail")
            for name, typ, _ in cases:
                result = self.ask(name, typ)
                self.require(result["rcode"] == 2 and not result["addresses"],
                             f"{name}: old positive escaped its hard deadline")
        return {"preservation_cases": 8, "stale_seconds": 8}

    def prefetch_override(self):
        names = [(f"prefetch-{typ}.override.test", typ) for typ in (1, 28)]
        with self.running("prefetch-override", cache_stale_ttl=0, cache_prefetch_percent=50, override=True):
            for name, typ in names:
                self.upstream.set(name, ttl=8)
                self.old(name, typ)
                self.old(name, typ)
                self.old(name, typ)
            time.sleep(5.1)  # Minimum jittered 50% threshold for TTL=8 is 3.
            for name, typ in names:
                self.upstream.set(name, ttl=0, changed=True)
                response = self.old(name, typ)
                self.require(response["ttls"][0] > 0, "prefetch test did not hit a fresh entry")
            self.wait_tx([name for name, _ in names], 4)
            for name, typ in names:
                result = self.ask(name, typ)
                self.require(result["addresses"] == [NEW[typ]] and result["ttls"] == [0],
                             "prefetch with stale override zero failed to revoke fresh old entry")
        return {"types": [1, 28], "stale_override": 0}

    def same_key_backoff(self):
        name = "hot.backoff.test"
        with self.running("same-key-backoff"):
            self.upstream.set(name, ttl=1)
            self.old(name)
            time.sleep(1.2)
            self.upstream.set(name, mode="servfail")
            start = time.monotonic()
            for index in range(20):
                time.sleep(max(0, start + index / 20 - time.monotonic()))
                self.old(name)
            self.wait_tx([name], 1, start)
            self.require(len(self.tx([name], start)) == 1, "20 QPS caused repeated same-key refreshes")
            time.sleep(max(0, start + 3.8 - time.monotonic()))
            self.old(name)
            time.sleep(.1)
            self.require(len(self.tx([name], start)) == 1, "first retry occurred before four-second quantized minimum")
            # Whole-second application clock makes a nominal five-second delay
            # observable at 4..5 seconds. Poll through six seconds, preserving
            # the arrival time of the actual retry for the next assertion.
            deadline = start + 6.5
            while len(self.tx([name], start)) < 2 and time.monotonic() < deadline:
                self.old(name)
                time.sleep(.1)
            tx = self.tx([name], start)
            self.require(len(tx) == 2, "refresh did not retry after first backoff")
            second = tx[1]["time"]
            self.require(second - tx[0]["time"] >= 3.8, "first backoff interval too short")
            time.sleep(max(0, second + 8.7 - time.monotonic()))
            self.old(name)
            time.sleep(.1)
            self.require(len(self.tx([name], start)) == 2, "second backoff did not grow to ten seconds")
            self.upstream.set(name, ttl=1, changed=True)
            deadline = second + 11.5
            while len(self.tx([name], start)) < 3 and time.monotonic() < deadline:
                self.old(name)
                time.sleep(.1)
            self.wait_tx([name], 3, start)
            result = self.ask(name)
            self.require(result["addresses"] == [NEW[1]], "successful retry did not update cache")
            # Success must reset the failure state, not retain the prior 10s delay.
            time.sleep(1.2)
            self.upstream.set(name, mode="servfail")
            self.require(self.ask(name)["addresses"] == [NEW[1]], "successful answer not retained")
            self.wait_tx([name], 4, start)
        return {"refreshes": len(self.tx([name], start)), "target_qps": 20,
                "retry_intervals": [b["time"] - a["time"] for a, b in zip(self.tx([name], start), self.tx([name], start)[1:])]}

    def global_refresh_budget(self):
        names = [f"key-{index}.budget.test" for index in range(256)]
        with self.running("global-refresh-budget"):
            for name in names:
                self.upstream.set(name, ttl=1)
                self.old(name)
            time.sleep(1.2)
            for name in names:
                self.upstream.set(name, mode="servfail")
            start = time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
                list(pool.map(self.old, names))
            time.sleep(.3)
            tx = self.tx(names, start)
            self.require(tx, "no background refresh reached the fixture")
            bound = rate_bound(start, max(item["time"] for item in tx))
            self.require(len(tx) <= bound, f"global refresh rate exceeded 64/s burst8: {len(tx)} > {bound}")
            served = {item["name"] for item in tx}
            denied = next((name for name in names if name not in served), None)
            self.require(denied is not None, "fixture load did not exercise refresh budget rejection")
            # A denied refresh must become eligible after refill, not stay claimed.
            time.sleep(.2)
            self.old(denied)
            self.wait_tx([denied], 1, start)
        return {"keys": len(names), "refreshes_in_burst": len(tx), "observed_bound_with_tolerance": bound,
                "dispatch_to_last_arrival_seconds": max(item["time"] for item in tx) - start}

    def run(self):
        cases = [("valid_replacement_revokes", self.replacements), ("oversized_replacement_revokes", self.oversized),
                 ("temporary_failure_preserves_until_deadline", self.failure_preservation),
                 ("prefetch_override_zero_revokes", self.prefetch_override),
                 ("same_key_exponential_backoff", self.same_key_backoff),
                 ("global_refresh_rate_budget", self.global_refresh_budget)]
        try:
            for name, method in cases:
                start = time.monotonic()
                row = {"case": name}
                try:
                    row.update(details=method(), passed=True)
                except Exception:
                    row.update(passed=False, error=traceback.format_exc())
                row["seconds"] = time.monotonic() - start
                self.rows.append(row)
                print(f"{name}: {'PASS' if row['passed'] else 'FAIL'}", flush=True)
        finally:
            try:
                self.upstream.close()
            except Exception:
                self.rows.append({"case": "fixture_shutdown", "passed": False, "error": traceback.format_exc()})
            (self.output / "upstream.json").write_text(json.dumps(self.upstream.snapshot(), indent=2) + "\n")
            (self.output / "clients.json").write_text(json.dumps(self.clients, indent=2) + "\n")
            result = {"application": str(self.application), "application_sha256": hashlib.sha256(self.application.read_bytes()).hexdigest(),
                      "script_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                      "passed": sum(row["passed"] for row in self.rows), "total": len(self.rows), "cases": self.rows}
            (self.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return all(row["passed"] for row in self.rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--application", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    return 0 if Suite(args.application, args.output).run() else 1


if __name__ == "__main__":
    raise SystemExit(main())
