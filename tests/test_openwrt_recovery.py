"""Exercise the router recovery shell scripts with isolated command doubles.

No router, compiler, root privileges, network access or real UCI configuration is
used.  The doubles model persistent DNS options and failed actions so assertions
cover the recovery transaction, rather than just shell source spelling.
"""
import json
import os
from pathlib import Path
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "deployment/openwrt-recovery"

DOUBLE = r'''
import fcntl, json, os, pathlib, signal, sys, time
root = pathlib.Path(os.environ["RECOVERY_TEST_ROOT"])
statefile = root / "mock-state.json"
state = json.loads(statefile.read_text())
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as stream:
    stream.write(json.dumps([name] + args) + "\n")
control = json.loads((root / "control.json").read_text())
def save():
    statefile.write_text(json.dumps(state))
def finish(code=0):
    save()
    sys.exit(code)
def pause_at(point):
    if control.get("pause_at") == point:
        save()
        (root / "paused").write_text(point)
        while True:
            time.sleep(1)
if name == "uci":
    args = [a for a in args if a not in ("-q", "-Q")]
    if not args:
        finish(1)
    operation, *values = args
    if operation == "get":
        key = values[0]
        if key not in state["uci"]:
            finish(1)
        value = state["uci"][key]
        print(" ".join(value) if isinstance(value, list) else value)
    elif operation in ("set", "add_list"):
        key, value = values[0].split("=", 1)
        state.setdefault("mutation_markers", []).append(
            (root / "base/recovering/switching").is_file())
        if operation == "set":
            state["uci"][key] = value
        else:
            state["uci"].setdefault(key, []).append(value)
    elif operation == "delete":
        state["uci"].pop(values[0], None)
    elif operation == "commit":
        state["commits"] = state.get("commits", 0) + 1
        if state["commits"] in control.get("fail_commit_calls", []):
            finish(1)
    else:
        print("unsupported mock uci operation: " + operation, file=sys.stderr)
        finish(97)
    finish()
elif name == "lua":
    # Script, host, port, question name, question type, health mode.
    if len(args) < 5:
        finish(96)
    _, host, port, domain, qtype, *rest = args
    state["probes"] = state.get("probes", 0) + 1
    for rule in control.get("fail_probes", []):
        if (str(rule.get("port", port)) == port
                and domain.rstrip(".").endswith(rule.get("suffix", domain.rstrip(".")))
                and rule.get("qtype", qtype) == qtype
                and rule.get("mode", rest[0] if rest else "") == (rest[0] if rest else "")):
            finish(rule.get("rc", 1))
    print("OK")
    finish()
elif name == "diversion-dns-c":
    action = args[0]
    if action == "start":
        state["start_snapshot_complete"] = all(
            (root / "base/recovering" / part).is_file()
            for part in ("servers", "cachesize"))
        state["start_kept_degraded"] = (root / "base/degraded").is_file()
        if control.get("fail_c_start"):
            finish(1)
        state["c_running"] = True
        if control.get("fail_switching_marker"):
            (root / "base/recovering/switching").mkdir()
        pause_at("c-start")
    elif action == "stop":
        state["c_running"] = False
    elif action == "status":
        finish(0 if state["c_running"] else 1)
    finish()
elif name == "dnsmasq":
    state["dnsmasq_restarts"] = state.get("dnsmasq_restarts", 0) + 1
    pause_at("dnsmasq-restart-" + str(state["dnsmasq_restarts"]))
    finish(1 if state["dnsmasq_restarts"] in control.get("fail_restart_calls", []) else 0)
elif name == "sleep":
    if args == ["20"]:
        state["guard_intervals"] = state.get("guard_intervals", 0) + 1
        if state["guard_intervals"] == control.get("stop_after_intervals"):
            (root / "base/active").unlink()
    if control.get("advance_sleep"):
        clock = root / "time"
        clock.write_text(str(int(clock.read_text()) + int(args[0])) + "\n")
    finish()
elif name in ("logger", "sync"):
    finish()
elif name == "mv":
    if len(args) != 2:
        finish(94)
    os.rename(args[0], args[1])
    if pathlib.Path(args[0]).name == "recovering" and control.get("term_after_retire"):
        save()
        os.kill(os.getppid(), signal.SIGTERM)
        sys.exit(0)
    finish()
elif name == "nft":
    finish()
elif name == "flock":
    fd = int(args[-1])
    operation = fcntl.LOCK_UN if "-u" in args else fcntl.LOCK_EX
    if "-n" in args:
        operation |= fcntl.LOCK_NB
    try:
        fcntl.flock(fd, operation)
    except BlockingIOError:
        finish(1)
    finish()
elif name == "pidof":
    if state["c_running"]:
        print("12345")
        finish()
    finish(1)
else:
    print("unsupported mock command: " + name, file=sys.stderr)
    finish(95)
'''


class RecoveryFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="dns-recovery-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.base = self.root / "base"
        self.run = self.root / "run"
        self.initdir = self.root / "init.d"
        self.bin = self.root / "bin"
        self.lock = self.root / "recover.lock"
        for directory in (self.base, self.run, self.initdir, self.bin):
            directory.mkdir()
        for path in SCRIPTS.iterdir():
            if path.is_file():
                shutil.copy2(path, self.base / path.name)
                (self.base / path.name).chmod(0o755)
        # Only clock sources differ from the shipped scripts.  Deterministic
        # uptime permits testing deadlines without sleep or Linux /proc on macOS.
        with (self.base / "common.sh").open("a") as stream:
            stream.write('\nnow_seconds() { cat "$RECOVERY_TEST_ROOT/time"; }\n'
                         'boot_id() { printf "%s\\n" test-boot; }\n')
        (self.root / "time").write_text("100\n")
        self.initial_servers = ["192.0.2.53", "198.51.100.53"]
        self.initial_options = {
            "dhcp.@dnsmasq[0].server": self.initial_servers,
            "dhcp.@dnsmasq[0].cachesize": "1500",
            "dhcp.@dnsmasq[0].filter_aaaa": "0",
            "network.lan.ipaddr": "192.168.100.1",
        }
        self.statefile = self.root / "mock-state.json"
        self.statefile.write_text(json.dumps({"uci": self.initial_options,
                                              "c_running": False}))
        (self.root / "control.json").write_text("{}")
        (self.root / "calls.jsonl").touch()
        for name in ("uci", "lua", "logger", "sleep", "sync", "mv", "pidof", "flock", "nft"):
            self.write_double(self.bin / name)
        for name in ("diversion-dns-c", "dnsmasq"):
            self.write_double(self.initdir / name)
        self.env = dict(os.environ,
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"],
                        RECOVERY_TEST_ROOT=str(self.root),
                        DIVERSION_DNS_BASE=str(self.base),
                        DIVERSION_DNS_RUN=str(self.run),
                        DIVERSION_DNS_INITDIR=str(self.initdir),
                        DIVERSION_DNS_LOCK=str(self.lock))
        # The existing router fallback implementation is separate from this
        # overlay.  Make its behavior observable without touching live files.
        (self.base / "dns-mode.sh").write_text(
            '#!/bin/sh\n'
            'fallback_dns() {\n'
            'printf "%s\\n" "fallback:$*" >> "$RECOVERY_TEST_ROOT/fallback.log"\n'
            ': > "$DIVERSION_DNS_BASE/degraded"\n'
            '}\n')
        (self.base / "dns-mode.sh").chmod(0o755)
        for name in ("apply-policy.sh", "refresh-monitor.sh", "enable-rescue.sh"):
            (self.base / name).write_text("#!/bin/sh\nexit 0\n")
            (self.base / name).chmod(0o755)
        (self.base / "active").touch()
        (self.base / "degraded").touch()
        (self.base / "recovery-auto").write_text("service-health\n")

    def write_double(self, path):
        path.write_text("#!" + sys.executable + "\n" + DOUBLE)
        path.chmod(0o755)

    def control(self, **values):
        (self.root / "control.json").write_text(json.dumps(values))

    def state(self):
        return json.loads(self.statefile.read_text())

    def calls(self, name=None):
        result = [json.loads(line) for line in
                  (self.root / "calls.jsonl").read_text().splitlines()]
        return [item for item in result if name is None or item[0] == name]

    def execute(self, script, *args, expected=None):
        result = subprocess.run(["/bin/sh", str(self.base / script), *args],
                                env=self.env, text=True, capture_output=True,
                                timeout=15)
        if expected is not None:
            self.assertEqual(result.returncode, expected,
                             result.stdout + "\n" + result.stderr)
        return result

    def shell(self, body, expected=0):
        result = subprocess.run(["/bin/sh", "-c",
                                 '. "$DIVERSION_DNS_BASE/common.sh"\n' + body],
                                env=self.env, text=True, capture_output=True,
                                timeout=10)
        self.assertEqual(result.returncode, expected,
                         result.stdout + "\n" + result.stderr)
        return result.stdout.strip()

    def assert_original_dns(self):
        state = self.state()
        self.assertEqual(state["uci"], self.initial_options)

    def test_automatic_recovery_requires_degraded_marker(self):
        (self.base / "degraded").unlink()
        self.execute("recover.sh", "--automatic")
        self.assertFalse(self.calls("lua"))
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assert_original_dns()

    def test_automatic_recovery_respects_manual_hold(self):
        (self.base / "recovery-auto").unlink()
        self.execute("recover.sh", "--automatic")
        self.assertFalse(self.calls("lua"))
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assert_original_dns()
        self.assertTrue((self.base / "degraded").exists())

    def test_success_checks_both_routes_and_families_before_switching(self):
        self.execute("recover.sh", "--automatic", expected=0)
        calls = self.calls()
        preflight = [item for item in calls if item[0] == "lua" and item[3] == "15363"
                     and item[-1] == "health"]
        self.assertEqual(len(preflight), 12)
        for suffix in ("qq.com", "example.com"):
            for qtype in ("A", "AAAA"):
                matching = [item for item in preflight
                            if item[4].rstrip(".").endswith(suffix) and item[5] == qtype]
                self.assertEqual(len(matching), 3, (suffix, qtype, matching))
                # A distinct, uncached name is needed in every round.
                self.assertEqual(len({item[4] for item in matching}), 3)
        frontend = [item for item in calls if item[0] == "lua" and item[3] == "53"
                    and item[-1] in ("health", "positive")]
        self.assertEqual(len(frontend), 8)
        first_mutation = next(i for i, call in enumerate(calls)
                              if call[0] == "uci" and any(
                                  value in ("set", "delete", "add_list", "commit")
                                  for value in call[1:]))
        self.assertTrue(all(calls.index(item) < first_mutation for item in preflight))
        state = self.state()
        self.assertTrue(state["c_running"])
        self.assertTrue(state["start_snapshot_complete"])
        self.assertTrue(state["start_kept_degraded"])
        self.assertTrue(all(state["mutation_markers"]))
        self.assertEqual(state["uci"]["dhcp.@dnsmasq[0].server"], ["127.0.0.1#15363"])
        self.assertEqual(state["uci"]["dhcp.@dnsmasq[0].cachesize"], "0")
        self.assertEqual(state["uci"]["dhcp.@dnsmasq[0].filter_aaaa"], "0")
        self.assertEqual(state["uci"]["network.lan.ipaddr"], "192.168.100.1")
        self.assertFalse((self.base / "degraded").exists())
        self.assertFalse((self.base / "recovery-auto").exists())
        self.assertFalse((self.base / "recovering").exists())

    def test_manual_recovery_is_allowed_while_automatic_is_held(self):
        (self.base / "recovery-auto").unlink()
        self.execute("recover.sh", expected=0)
        self.assertTrue(self.state()["c_running"])
        self.assertFalse((self.base / "degraded").exists())

    def test_each_preflight_route_and_family_failure_leaves_fallback_live(self):
        for suffix in ("qq.com", "example.com"):
            for qtype in ("A", "AAAA"):
                with self.subTest(suffix=suffix, qtype=qtype):
                    self.control(fail_probes=[{"port": "15363", "suffix": suffix,
                                               "qtype": qtype, "mode": "health"}])
                    result = self.execute("recover.sh", "--automatic")
                    self.assertNotEqual(result.returncode, 0)
                    self.assert_original_dns()
                    self.assertFalse(self.state()["c_running"])
                    self.assertFalse(self.calls("dnsmasq"))
                    self.assertTrue((self.base / "degraded").exists())
                    self.assertFalse((self.base / "recovering").exists())

    def test_c_start_failure_preserves_live_fallback(self):
        self.control(fail_c_start=True)
        result = self.execute("recover.sh", "--automatic")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.calls("dnsmasq"))
        self.assertFalse(self.calls("lua"))

    def test_frontend_probe_failure_restores_saved_dns_before_stopping_c(self):
        self.control(fail_probes=[{"port": "53", "suffix": "example.com", "qtype": "AAAA"}])
        result = self.execute("recover.sh", "--automatic")
        self.assertNotEqual(result.returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertEqual(len(self.calls("dnsmasq")), 2)
        calls = self.calls()
        self.assertGreater(calls.index(["diversion-dns-c", "stop"]),
                           max(i for i, call in enumerate(calls) if call[0] == "dnsmasq"))
        self.assertTrue((self.base / "degraded").exists())
        self.assertFalse((self.base / "recovering").exists())

    def test_failed_dns_restore_keeps_c_available_and_transaction_for_retry(self):
        self.control(fail_probes=[{"port": "53", "mode": "health"}],
                     fail_restart_calls=[2])
        result = self.execute("recover.sh", "--automatic")
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(self.state()["c_running"])
        self.assertTrue((self.base / "recovering" / "switching").exists())
        self.assertTrue((self.base / "degraded").exists())
        self.assertNotIn(["diversion-dns-c", "stop"], self.calls())
        self.control()
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse((self.base / "recovering").exists())

    def make_transaction(self, switching):
        transaction = self.base / "recovering"
        transaction.mkdir()
        (transaction / "servers").write_text(" ".join(self.initial_servers) + "\n")
        (transaction / "cachesize").write_text("1500\n")
        if switching:
            (transaction / "switching").touch()
        state = self.state()
        state["c_running"] = True
        if switching:
            state["uci"]["dhcp.@dnsmasq[0].server"] = ["127.0.0.1#15363"]
            state["uci"]["dhcp.@dnsmasq[0].cachesize"] = "0"
        self.statefile.write_text(json.dumps(state))

    def test_reconcile_interrupted_switch_restores_without_upstream_probe(self):
        self.make_transaction(switching=True)
        # Recovery of an unfinished transaction must work even when deliberately
        # held in fallback, and without depending on public DNS availability.
        (self.base / "recovery-auto").unlink()
        self.control(fail_probes=[{"mode": "health"}])
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertEqual([(item[3], item[4]) for item in self.calls("lua")],
                         [("53", "localhost")])
        self.assertFalse((self.base / "recovering").exists())
        self.assertTrue((self.base / "degraded").exists())

    def test_reconcile_preflight_only_does_not_restart_dnsmasq(self):
        self.make_transaction(switching=False)
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse(self.calls("dnsmasq"))
        self.assertFalse(self.calls("lua"))
        self.assertFalse((self.base / "recovering").exists())

    def test_concurrent_recovery_lock_is_nonblocking(self):
        holder = subprocess.Popen(
            [sys.executable, "-c", "import fcntl, sys; "
             "f=open(sys.argv[1], 'w'); fcntl.flock(f, fcntl.LOCK_EX); "
             "print('locked', flush=True); sys.stdin.read()", str(self.lock)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")
            self.execute("recover.sh", "--automatic", expected=75)
            self.assertFalse(self.calls("lua"))
            self.assertFalse(self.calls("diversion-dns-c"))
            self.assert_original_dns()
        finally:
            holder.communicate("", timeout=3)

    def test_service_health_fallback_arms_automatic_recovery(self):
        (self.base / "recovery-auto").unlink()
        self.execute("rollback.sh", "service-health", expected=0)
        self.assertTrue((self.base / "recovery-auto").exists())
        self.assertTrue((self.base / "degraded").exists())
        self.assertTrue((self.root / "fallback.log").exists())

    def test_manual_rollback_holds_automatic_recovery(self):
        self.execute("rollback.sh", expected=0)
        self.assertFalse((self.base / "recovery-auto").exists())
        self.assertTrue((self.base / "degraded").exists())

    def test_missing_active_marker_prevents_recovery(self):
        (self.base / "active").unlink()
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assertFalse(self.calls("lua"))
        self.assert_original_dns()

    def test_unrecognized_automatic_marker_does_not_override_operator(self):
        (self.base / "recovery-auto").write_text("manual\n")
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assert_original_dns()

    def test_positive_answer_probe_failure_restores_fallback(self):
        self.control(fail_probes=[{"port": "53", "mode": "positive"}])
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertTrue((self.base / "degraded").exists())

    def test_switching_marker_write_failure_prevents_all_dns_mutation(self):
        self.control(fail_switching_marker=True)
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse(self.calls("dnsmasq"))
        self.assertFalse(self.state().get("mutation_markers"))
        self.assertTrue((self.base / "degraded").exists())

    def test_term_after_atomic_retirement_does_not_stop_restored_service(self):
        self.control(term_after_retire=True)
        self.execute("recover.sh", "--automatic", expected=143)
        self.assertTrue(self.state()["c_running"])
        self.assertFalse((self.base / "degraded").exists())
        self.assertFalse((self.base / "recovering").exists())
        self.assertEqual(self.state()["uci"]["dhcp.@dnsmasq[0].server"],
                         ["127.0.0.1#15363"])
        self.assertNotIn(["diversion-dns-c", "stop"], self.calls())
        self.assertEqual(len(self.calls("dnsmasq")), 1)
        # Retired evidence may survive interrupted cleanup, but cannot act as
        # an unfinished transaction on the next guard/recovery invocation.
        self.assertTrue(list(self.base.glob(".recovery-retired.*")))
        self.control()
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assertTrue(self.state()["c_running"])
        self.assertFalse((self.base / "degraded").exists())

    def test_failed_switch_restart_restores_before_stopping_c(self):
        self.control(fail_restart_calls=[1])
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertEqual(len(self.calls("dnsmasq")), 2)
        self.assertFalse((self.base / "recovering").exists())

    def test_failed_switch_commit_restores_before_stopping_c(self):
        self.control(fail_commit_calls=[1])
        self.assertNotEqual(self.execute("recover.sh", "--automatic").returncode, 0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse((self.base / "recovering").exists())

    def kill_recovery_at(self, point):
        self.control(pause_at=point)
        process = subprocess.Popen(["/bin/sh", str(self.base / "recover.sh"), "--automatic"],
                                   env=self.env, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True,
                                   start_new_session=True)
        try:
            deadline = time.monotonic() + 10
            while not (self.root / "paused").exists() and time.monotonic() < deadline:
                if process.poll() is not None:
                    self.fail("recovery exited before crash point: " + str(process.communicate()))
                time.sleep(0.01)
            self.assertTrue((self.root / "paused").exists(), "crash point was not reached")
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)
        self.control()

    def test_sigkill_during_preflight_is_reconciled_without_dns_restart(self):
        self.kill_recovery_at("c-start")
        self.assertTrue((self.base / "recovering").exists())
        self.assertTrue(self.state()["c_running"])
        self.assert_original_dns()
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assertFalse(self.state()["c_running"])
        self.assertFalse(self.calls("dnsmasq"))
        self.assertFalse((self.base / "recovering").exists())

    def test_sigkill_during_switch_is_reconciled_from_persistent_snapshot(self):
        self.kill_recovery_at("dnsmasq-restart-1")
        self.assertTrue((self.base / "recovering/switching").exists())
        self.assertEqual(self.state()["uci"]["dhcp.@dnsmasq[0].server"],
                         ["127.0.0.1#15363"])
        # Emulate a reboot losing /var/run state but preserving /etc transaction.
        shutil.rmtree(self.run)
        self.run.mkdir()
        (self.base / "recovery-auto").unlink()
        self.execute("recover.sh", "--reconcile", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse((self.base / "recovering").exists())

    def test_guard_held_degraded_never_starts_automatic_recovery(self):
        (self.base / "recovery-auto").unlink()
        self.execute("guard.sh", "--once", expected=0)
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assertEqual([item[3] for item in self.calls("lua")], ["53"])
        self.assert_original_dns()

    def test_guard_reconciles_interrupted_switch_even_during_manual_hold(self):
        self.make_transaction(switching=True)
        (self.base / "recovery-auto").unlink()
        self.execute("guard.sh", "--once", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse((self.base / "recovering").exists())
        self.assertTrue((self.base / "degraded").exists())

    def test_guard_waits_initial_cooldown_then_recovers(self):
        self.execute("guard.sh", "--once", expected=0)
        self.assertFalse(self.calls("diversion-dns-c"))
        self.assertEqual((self.run / "state").read_text().split(),
                         ["test-boot", "0", "220", "0"])
        (self.root / "time").write_text("219\n")
        self.execute("guard.sh", "--once", expected=0)
        self.assertFalse(self.calls("diversion-dns-c"))
        (self.root / "time").write_text("220\n")
        self.execute("guard.sh", "--once", expected=0)
        self.assertTrue(self.state()["c_running"])
        self.assertFalse((self.base / "degraded").exists())
        self.assertEqual((self.run / "state").read_text().split(),
                         ["test-boot", "1", "0", "220"])

    def test_guard_failed_attempt_persists_backoff_without_switching_dns(self):
        (self.run / "state").write_text("test-boot 0 100 0\n")
        self.control(fail_probes=[{"port": "15363", "mode": "health"}])
        self.execute("guard.sh", "--once", expected=0)
        self.assert_original_dns()
        self.assertFalse(self.state()["c_running"])
        self.assertFalse(self.calls("dnsmasq"))
        self.assertEqual((self.run / "state").read_text().split(),
                         ["test-boot", "1", "160", "0"])

    def test_guard_requires_three_consecutive_bad_health_rounds_for_fallback(self):
        (self.base / "degraded").unlink()
        (self.base / "recovery-auto").unlink()
        self.control(fail_probes=[{"port": "15363", "mode": "health"}],
                     stop_after_intervals=3, advance_sleep=True)
        self.execute("guard.sh", expected=0)
        self.assertEqual(len([item for item in self.calls("lua")
                              if item[3] == "15363"]), 3)
        self.assertTrue((self.base / "degraded").exists())
        self.assertEqual((self.base / "recovery-auto").read_text(), "service-health\n")
        self.assertEqual(len((self.root / "fallback.log").read_text().splitlines()), 1)

    def test_retry_delay_is_exponential_and_bounded(self):
        result = self.shell('for recovery_failures in 1 2 3 4 5 6 99; do recovery_delay; done')
        self.assertEqual(result.split(), ["60", "120", "240", "480", "900", "900", "900"])

    def test_scheduler_persists_attempt_before_start_and_uses_end_time_for_retry(self):
        result = self.shell('''
read_state
schedule_recovery 100; printf '%s ' "$?"
cat "$run/state"
schedule_recovery 219; printf '%s ' "$?"
cat "$run/state"
schedule_recovery 220; printf '%s ' "$?"
cat "$run/state"
record_recovery_result 1 270
cat "$run/state"
schedule_recovery 329; printf '%s ' "$?"
cat "$run/state"
schedule_recovery 330; printf '%s ' "$?"
cat "$run/state"
record_recovery_result 1 380
cat "$run/state"
''')
        self.assertEqual(result.splitlines(), [
            "1 test-boot 0 220 0", "1 test-boot 0 220 0",
            "0 test-boot 1 280 0", "test-boot 1 330 0",
            "1 test-boot 1 330 0", "0 test-boot 2 450 0",
            "test-boot 2 500 0",
        ])

    def test_retry_failure_count_resets_only_after_ten_stable_minutes(self):
        result = self.shell('''
read_state
recovery_failures=5
record_recovery_result 0 1000
normal_tick 1599
cat "$run/state"
normal_tick 1600
cat "$run/state"
''')
        self.assertEqual(result.splitlines(), ["test-boot 5 0 1000", "test-boot 0 0 1000"])

    def test_scheduler_failure_count_is_capped_after_many_outages(self):
        result = self.shell('''
read_state
recovery_failures=5; recovery_next=1
schedule_recovery 1000
cat "$run/state"
record_recovery_result 1 1100
cat "$run/state"
''')
        self.assertEqual(result.splitlines(), ["test-boot 5 1900 0", "test-boot 5 2000 0"])

    def test_state_roundtrip_and_reboot_reset(self):
        (self.root / "time").write_text("1000\n")
        (self.run / "state").write_text("test-boot 4 1800 900\n")
        self.assertEqual(self.shell('read_state; save_state; cat "$run/state"'),
                         "test-boot 4 1800 900")
        (self.run / "state").write_text("previous-boot 4 1800 900\n")
        self.assertEqual(self.shell('read_state; save_state; cat "$run/state"'),
                         "test-boot 0 0 0")

    def test_malformed_state_is_not_executed_or_accepted(self):
        for contents in ("", "test-boot 1 nope 0\n", "test-boot 6 20 0\n",
                         "test-boot -1 20 0\n", "test-boot 1 999999999999 0\n",
                         "test-boot 1 20 0 extra\n", "test-boot 1 20\n",
                         "test-boot 01 20 0\n", "test-boot 1 08 0\n",
                         "test-boot 1 1001 0\n", "test-boot 1 20 101\n",
                         "test-boot 1 $(touch_bad) 0\n"):
            with self.subTest(contents=contents):
                (self.run / "state").write_text(contents)
                result = self.shell('read_state; save_state; cat "$run/state"')
                self.assertEqual(result, "test-boot 0 0 0")


if __name__ == "__main__":
    unittest.main()
