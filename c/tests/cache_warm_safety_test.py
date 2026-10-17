#!/usr/bin/env python3
"""Warm-file safety regressions against an existing binary; no compilation/nft.

Run: python3 c/tests/cache_warm_safety_test.py --application /path/to/mosdns-c --output /tmp/warm-report
All files, symlinks, FIFOs, ports and subprocesses belong to a temporary fixture.
"""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import sys
import stat
import subprocess
import tempfile
import time
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", nargs="?", type=Path)
parser.add_argument("--application", type=Path)
parser.add_argument("--output", type=Path)
args, remaining = parser.parse_known_args()
application = args.application or args.binary
if application is None:
    parser.error("provide --application PATH (or positional binary)")
application = application.resolve()
if not application.is_file():
    parser.error(f"application does not exist: {application}")
OUTPUT = args.output.resolve() if args.output else None
if OUTPUT:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    if (OUTPUT / "result.json").exists():
        parser.error(f"refusing to overwrite existing result: {OUTPUT}")
# The shared integration fixtures consume their binary argument at import time.
sys.argv = [sys.argv[0], str(application), *remaining]
import fixed_integration as support


class WarmFileSafety(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="cache-warm-safety-")
        self.root = Path(self.tmp.name)
        self.warm = self.root / "warm.txt"
        self.upstream = support.MockDNS("203.0.113.19")
        self.run_number = 0
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(self.upstream.close)

    @contextlib.contextmanager
    def running(self, config, **options):
        self.run_number += 1
        prefix = f"{self._testMethodName}-{self.run_number}"
        output = options.setdefault("output", {})
        if OUTPUT:
            (OUTPUT / f"{prefix}-config.json").write_text(json.dumps(config, indent=2) + "\n")
        try:
            with support.running(config, **options) as port:
                yield port
        except BaseException as error:
            if OUTPUT:
                (OUTPUT / f"{prefix}-exception.txt").write_text(str(error) + "\n")
            raise
        finally:
            if OUTPUT:
                (OUTPUT / f"{prefix}-stderr.log").write_text(output.get("stderr", ""))

    def config(self, **extra):
        port = support.support.unused_port()
        result = dict(listen_udp=f"127.0.0.1:{port}", listen_tcp=f"127.0.0.1:{port}",
                      cn_upstream=f"127.0.0.1:{self.upstream.port}",
                      foreign_upstream=f"127.0.0.1:{self.upstream.port}", cache_size=64,
                      cache_warm_file=str(self.warm), cache_warm_qps=100)
        result.update(extra)
        return result

    def wait_count(self, name, count):
        deadline = time.monotonic() + 4
        while self.upstream.count(name) < count and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertEqual(self.upstream.count(name), count, name)
        # The fixture counts before it sends; let the response enter the cache.
        time.sleep(0.05)

    def hot(self, port, name, qtype=1):
        for ident in (100, 101):
            response = support.udp_exchange(port, support.query(name, ident, qtype=qtype))
            self.assertEqual(response[3] & 15, 0)

    def start_rejected(self, config):
        rules = self.root / "cn.txt"
        rules.write_text("domain:cn\n")
        config_file = self.root / "bad.conf"
        config_file.write_text(support.config_text(config, rules))
        result = subprocess.run([str(support.BIN), "start", "-c", str(config_file), "--cpu", "1"],
                                capture_output=True, timeout=5)
        if OUTPUT:
            prefix = self._testMethodName
            (OUTPUT / f"{prefix}-stdout.log").write_bytes(result.stdout)
            (OUTPUT / f"{prefix}-stderr.log").write_bytes(result.stderr)
            (OUTPUT / f"{prefix}-config.conf").write_text(config_file.read_text())
        self.assertNotEqual(result.returncode, 0, result.stderr.decode())
        return result

    def test_predictable_temp_symlink_cannot_truncate_target(self):
        sentinel = self.root / "sentinel"
        sentinel.write_bytes(b"owned sentinel: do not replace\n")
        process = {}
        with self.running(self.config(), process_info=process) as port:
            old_temp = Path(f"{self.warm}.tmp.{process['pid']}")
            old_temp.symlink_to(sentinel)
            self.hot(port, "safe.foreign.test")
        self.assertEqual(sentinel.read_bytes(), b"owned sentinel: do not replace\n")
        self.assertTrue(old_temp.is_symlink())
        self.assertIn("0 1 safe.foreign.test\n", self.warm.read_text())
        self.assertEqual(stat.S_IMODE(self.warm.stat().st_mode), 0o600)
        self.assertEqual(list(self.root.glob("warm.txt.tmp.*")), [old_temp])

    def test_warm_file_symlink_is_neither_read_nor_replaced(self):
        sentinel = self.root / "names-target"
        content = b"0 1 symlink-read.foreign.test\n"
        sentinel.write_bytes(content)
        self.warm.symlink_to(sentinel)
        output = {}
        with self.running(self.config(), output=output) as port:
            self.hot(port, "live.foreign.test")
            time.sleep(0.15)
        self.assertTrue(self.warm.is_symlink())
        self.assertEqual(sentinel.read_bytes(), content)
        self.assertEqual(self.upstream.count("symlink-read.foreign.test"), 0)
        self.assertIn("refusing non-regular save path", output["stderr"])

    def test_fifo_is_rejected_and_sigterm_stops_promptly(self):
        os.mkfifo(self.warm, 0o600)
        output = {}
        started = time.monotonic()
        with self.running(self.config(), output=output) as port:
            self.hot(port, "fifo.foreign.test")
        self.assertLess(time.monotonic() - started, 3)
        self.assertTrue(stat.S_ISFIFO(self.warm.lstat().st_mode))
        self.assertIn("refusing non-regular or oversized file", output["stderr"])

    def test_invalid_config_keeps_existing_warm_file(self):
        content = b"# previous run\n0 1 keep.foreign.test\n"
        self.warm.write_bytes(content)
        self.start_rejected(self.config(udp_sport_reuse=2))
        self.assertEqual(self.warm.read_bytes(), content)
        self.assertEqual(self.upstream.count("keep.foreign.test"), 0)

    def test_failed_bind_keeps_file_and_does_not_prewarm(self):
        content = b"# previous run\n0 1 keep-bind.foreign.test\n"
        self.warm.write_bytes(content)
        tcp, udp, port = support.support.bound_loopback_pair()
        try:
            tcp.listen()
            self.start_rejected(self.config(listen_udp=f"127.0.0.1:{port}",
                                            listen_tcp=f"127.0.0.1:{port}"))
        finally:
            tcp.close()
            udp.close()
        self.assertEqual(self.warm.read_bytes(), content)
        self.assertEqual(self.upstream.count("keep-bind.foreign.test"), 0)

    def test_oversized_file_is_not_read(self):
        with self.warm.open("wb") as output:
            output.write(b"0 1 oversized.foreign.test\n")
            output.truncate(4 * 1024 * 1024 + 1)
        logs = {}
        with self.running(self.config(), output=logs) as port:
            self.hot(port, "live.foreign.test")
        self.assertEqual(self.upstream.count("oversized.foreign.test"), 0)
        self.assertIn("refusing non-regular or oversized file", logs["stderr"])

    def test_bad_rows_are_discarded_whole_and_valid_rows_survive(self):
        # A former fgets(400) implementation treated the suffix at byte 399 as
        # a new row. NUL also must not turn a malformed row into a valid prefix.
        self.warm.write_bytes(b"0 1 before.foreign.test\n" + b"x" * 399 +
                              b"0 1 suffix.foreign.test\n" +
                              b"0 1 nul.foreign.test\x00junk\n" +
                              b"bad row\n9 1 flags.foreign.test\n0 5 type.foreign.test\n" +
                              b"0 1 after.foreign.test")
        logs = {}
        with self.running(self.config(), output=logs):
            self.wait_count("before.foreign.test", 1)
            self.wait_count("after.foreign.test", 1)
        for name in ("suffix", "nul", "flags", "type"):
            self.assertEqual(self.upstream.count(f"{name}.foreign.test"), 0)
        self.assertIn("cache warm: prewarmed 2 names", logs["stderr"])

    def test_row_limit_counts_empty_and_invalid_rows(self):
        # Valid sentinels at rows 1 and 20000 prove that loading started and
        # traversed the empty/invalid rows before checking row 20001 exclusion.
        self.warm.write_bytes(b"0 1 begin-limit.foreign.test\n" +
                              b"\ninvalid\n" * 9999 +
                              b"0 1 at-limit.foreign.test\n" +
                              b"0 1 past-limit.foreign.test\n")
        logs = {}
        with self.running(self.config(), output=logs):
            self.wait_count("begin-limit.foreign.test", 1)
            self.wait_count("at-limit.foreign.test", 1)
        self.assertEqual(self.upstream.count("past-limit.foreign.test"), 0)
        self.assertIn("cache warm: prewarmed 2 names", logs["stderr"])

    def test_normal_restart_prewarm_a_aaaa_names_only(self):
        config = self.config()
        with self.running(config) as port:
            self.hot(port, "restart-a.foreign.test")
            self.hot(port, "restart-aaaa.foreign.test", 28)
        text = self.warm.read_text()
        self.assertIn("0 1 restart-a.foreign.test\n", text)
        self.assertIn("0 28 restart-aaaa.foreign.test\n", text)
        self.assertNotIn("203.0.113", text)
        self.assertNotIn("2001:db8", text)
        self.assertEqual(stat.S_IMODE(self.warm.stat().st_mode), 0o600)
        self.upstream.address = "203.0.113.77"
        with self.running(config) as port:
            self.wait_count("restart-a.foreign.test", 2)
            self.wait_count("restart-aaaa.foreign.test", 2)
            response = support.udp_exchange(port, support.query("restart-a.foreign.test"))
            self.assertEqual(support.address(response), "203.0.113.77")
            self.hot(port, "restart-aaaa.foreign.test", 28)
            self.assertEqual(self.upstream.count("restart-a.foreign.test"), 2)
            self.assertEqual(self.upstream.count("restart-aaaa.foreign.test"), 2)


if __name__ == "__main__":
    class Tee:
        def __init__(self, log):
            self.log = log
        def write(self, text):
            sys.stderr.write(text)
            if self.log:
                self.log.write(text)
        def flush(self):
            sys.stderr.flush()
            if self.log:
                self.log.flush()

    class Result(unittest.TextTestResult):
        def __init__(self, *values, **kwargs):
            super().__init__(*values, **kwargs)
            self.cases = []
        def addSuccess(self, test):
            super().addSuccess(test)
            self.cases.append(dict(name=test.id(), passed=True))
        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.cases.append(dict(name=test.id(), passed=False, error=self.failures[-1][1]))
        def addError(self, test, err):
            super().addError(test, err)
            self.cases.append(dict(name=test.id(), passed=False, error=self.errors[-1][1]))

    log = (OUTPUT / "unittest.log").open("w") if OUTPUT else None
    try:
        runner = unittest.TextTestRunner(stream=Tee(log), verbosity=2, resultclass=Result)
        outcome = unittest.main(testRunner=runner, exit=False).result
        if OUTPUT:
            (OUTPUT / "result.json").write_text(json.dumps(dict(
                application=str(application), sha256=hashlib.sha256(application.read_bytes()).hexdigest(),
                passed=outcome.wasSuccessful(), total=outcome.testsRun,
                failures=len(outcome.failures), errors=len(outcome.errors), cases=outcome.cases,
            ), indent=2) + "\n")
    finally:
        if log:
            log.close()
    raise SystemExit(0 if outcome.wasSuccessful() else 1)
