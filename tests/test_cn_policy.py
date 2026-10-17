"""Policy integrity transaction tests: command doubles, no firewall or compiler."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/openwrt-recovery/cn-policy.sh"
BUSYBOX = shutil.which("busybox")
CHAINS = ("split", "classify", "guard", "router_output", "router_guard", "dns_redirect")
DOUBLE = r'''
import fcntl, hashlib, json, os, pathlib, sys
root = pathlib.Path(os.environ["POLICY_TEST_ROOT"])
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / "calls.jsonl").open("a") as f:
    f.write(json.dumps([name] + args) + "\n")
state = json.loads((root / "state.json").read_text())
def save():
    (root / "state.json").write_text(json.dumps(state))
if name == "nft":
    if args[:2] != ["-s", "-nn"] or args[2:5] != ["list", "chain", "inet"]:
        sys.exit(90)
    if args[5] != "ddns_p0_policy":
        sys.exit(91)
    value = state["live"].get(args[6])
    if value is None:
        sys.exit(1)
    print(value, end="")
elif name == "apply-policy.sh":
    state["applied"] += 1
    if state.get("fail_apply"):
        save(); sys.exit(1)
    state["live"] = dict(state["approved"])
    if state.get("incomplete_apply"):
        state["live"]["split"] = "table inet ddns_p0_policy {\n chain split {\n }\n}\n"
    save()
elif name == "sha256sum":
    if not args:
        print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest() + "  -")
    for filename in args:
        try:
            digest = hashlib.sha256(pathlib.Path(filename).read_bytes()).hexdigest()
        except OSError:
            sys.exit(1)
        print(digest + "  " + filename)
elif name == "mv":
    args = [v for v in args if not v.startswith("-")]
    os.replace(*args)
elif name == "flock":
    operation = fcntl.LOCK_UN if "-u" in args else fcntl.LOCK_EX
    if "-n" in args:
        operation |= fcntl.LOCK_NB
    try:
        fcntl.flock(int(args[-1]), operation)
    except BlockingIOError:
        sys.exit(1)
elif name == "lua":
    if args[0].endswith("dns-probe.lua"):
        print("OK")
    else:
        # The shell wrappers are real; Lua's independently tested manifest
        # verifier is modelled with actual six-file hashes in this fixture.
        if args[1] not in ("verify", "audit"):
            sys.exit(93)
        if os.environ.get("DIVERSION_CN_DEPLOY_LOCK_HELD") != "1":
            sys.exit(94)
        with open(os.environ["DIVERSION_DNS_LOCK"], "a") as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                sys.exit(95)
        generation = pathlib.Path(args[2])
        try:
            lines = (generation / "manifest.tsv").read_text().splitlines()
            if len(lines) != 6:
                sys.exit(96)
            for line in lines:
                filename, expected = line.split("\t")
                if hashlib.sha256((generation / filename).read_bytes()).hexdigest() != expected:
                    sys.exit(1)
        except (OSError, ValueError):
            sys.exit(1)
elif name in ("logger", "sync"):
    pass
else:
    sys.exit(92)
'''


class PolicyFixture(unittest.TestCase):
    shell = ("/bin/sh",)

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="cn-policy-test-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.base = self.root / "base"
        self.bin = self.root / "bin"
        self.base.mkdir(); self.bin.mkdir()
        shutil.copy2(SCRIPT, self.base / "cn-policy.sh")
        self.env = dict(os.environ, POLICY_TEST_ROOT=str(self.root),
                        DIVERSION_DNS_BASE=str(self.base),
                        DIVERSION_DNS_POLICY_TABLE="ddns_p0_policy",
                        DIVERSION_DNS_LOCK=str(self.root / "deploy.lock"),
                        PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        for name in ("nft", "sha256sum", "mv", "flock", "logger", "sync"):
            self.double(self.bin / name)
        self.double(self.base / "apply-policy.sh")
        self.policy = "".join("add chain inet ddns_p0_policy " + c + "\n"
                              "add rule inet ddns_p0_policy " + c + " counter return\n"
                              for c in CHAINS)
        (self.base / "policy.nft").write_text(self.policy)
        approved = {c: "table inet ddns_p0_policy {\n chain " + c
                    + " {\n  counter return\n }\n}\n" for c in CHAINS}
        (self.root / "state.json").write_text(json.dumps(
            {"approved": approved, "live": approved, "applied": 0}))
        (self.root / "calls.jsonl").touch()

    def double(self, path):
        path.write_text("#!" + sys.executable + "\n" + DOUBLE)
        path.chmod(0o755)

    def state(self):
        return json.loads((self.root / "state.json").read_text())

    def change(self, **values):
        state = self.state(); state.update(values)
        (self.root / "state.json").write_text(json.dumps(state))

    def run_script(self, *args, expected=0):
        result = subprocess.run([*self.shell, str(self.base / "cn-policy.sh"), *args],
                                env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def snapshot(self):
        return (self.base / "cn-policy/current").resolve()

    def managed_data(self):
        """Real check-start/current/manifest/link checks, no router or compiler."""
        shutil.copy2(SCRIPT.parent / "cn-data.sh", self.base / "cn-data.sh")
        (self.base / "cn-data.sh").chmod(0o755)
        self.double(self.bin / "lua")
        store = self.base / "cn-data"
        draft = store / "generations/draft"
        draft.mkdir(parents=True)
        payloads = {
            "cn-ip.txt": "223.5.5.0/24\n2400:3200::/32\n",
            "cn-site.txt": "qq.com\nbaidu.com\n",
            "sets.nft": "approved owned sets\n",
            "replace.nft": "flush set inet ddns_p0_policy cn4\nflush set inet ddns_p0_policy cn6\n",
            "ranges4.txt": "df050500 df0505ff\n",
            "ranges6.txt": "24003200000000000000000000000000 24003200ffffffffffffffffffffffff\n",
        }
        for name, content in payloads.items():
            (draft / name).write_text(content)
        manifest = "".join(name + "\t" + hashlib.sha256(content.encode()).hexdigest() + "\n"
                           for name, content in payloads.items())
        (draft / "manifest.tsv").write_text(manifest)
        identity = hashlib.sha256(manifest.encode()).hexdigest()
        current = draft.with_name(identity); draft.rename(current)
        rescue = current.with_name(hashlib.sha256((identity + " bootstrap\n").encode()).hexdigest())
        shutil.copytree(current, rescue)
        (store / "current").symlink_to("generations/" + current.name)
        (store / "previous").symlink_to("generations/" + rescue.name)
        (store / "enabled").touch()
        for name in ("cn-ip.txt", "cn-site.txt", "sets.nft"):
            (self.base / name).symlink_to("cn-data/current/" + name)
        return current, rescue

    def test_seed_and_unchanged_audit_do_not_apply_or_change_source(self):
        self.run_script("seed")
        self.assertTrue((self.base / "cn-policy/enabled").is_file())
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["applied"], 0)
        self.assertEqual((self.base / "policy.nft").read_text(), self.policy)
        calls = [json.loads(x) for x in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertTrue(all(c[1:3] == ["-s", "-nn"] for c in calls if c[0] == "nft"))

    def test_existing_base_chain_syntax_can_be_adopted(self):
        source = self.policy
        for chain, declaration in (
                ("classify", "type filter hook prerouting priority -130; policy accept;"),
                ("router_output", "type route hook output priority 0; policy accept;"),
                ("dns_redirect", "type nat hook prerouting priority 100; policy drop;")):
            source = source.replace(
                "add chain inet ddns_p0_policy " + chain + "\n",
                "add chain inet ddns_p0_policy " + chain + " { " + declaration + " }\n")
        (self.base / "policy.nft").write_text(source)
        self.run_script("seed")
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["applied"], 0)

    def test_empty_changed_and_missing_owned_chains_are_restored(self):
        self.run_script("seed")
        for damage in ("empty", "changed", "missing"):
            with self.subTest(damage=damage):
                live = dict(self.state()["approved"])
                if damage == "empty":
                    live["split"] = "table inet ddns_p0_policy {\n chain split {\n }\n}\n"
                elif damage == "changed":
                    live["split"] = live["split"].replace("return", "drop")
                else:
                    live.pop("split")
                self.change(live=live)
                self.run_script("audit-runtime")
                self.assertEqual(self.state()["live"], self.state()["approved"])
        self.assertEqual(self.state()["applied"], 3)

    def test_corrupt_source_restores_verified_snapshot_before_apply(self):
        self.run_script("seed")
        (self.base / "policy.nft").write_text("flush ruleset\n")
        self.run_script("audit-runtime")
        self.assertEqual((self.base / "policy.nft").read_text(), self.policy)
        self.assertEqual(self.state()["applied"], 1)

    def test_corrupt_snapshot_refuses_repair_without_touching_live_policy(self):
        self.run_script("seed")
        (self.snapshot() / "policy.nft").write_text("flush ruleset\n")
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.state()["applied"], 0)
        self.assertEqual((self.base / "policy.nft").read_text(), self.policy)

    def test_corrupt_manifest_refuses_even_if_payload_hashes_are_changed_together(self):
        self.run_script("seed")
        (self.snapshot() / "SHA256SUMS").write_text("garbage\n")
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.state()["applied"], 0)

    def test_changed_helper_is_never_executed(self):
        self.run_script("seed")
        with (self.base / "apply-policy.sh").open("a") as f:
            f.write("\n# operator change\n")
        self.run_script("audit-runtime", "--repair", expected=1)
        self.assertEqual(self.state()["applied"], 0)

    def test_failed_apply_is_retried_and_does_not_change_baseline(self):
        self.run_script("seed")
        original = self.snapshot()
        live = dict(self.state()["live"]); live.pop("guard")
        self.change(live=live, fail_apply=True)
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.snapshot(), original)
        self.change(fail_apply=False)
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["live"], self.state()["approved"])
        self.assertEqual(self.state()["applied"], 2)

    def test_incomplete_repair_fails_post_apply_verification(self):
        self.run_script("seed")
        self.change(incomplete_apply=True)
        self.run_script("audit-runtime", "--repair", expected=1)
        self.assertEqual(self.state()["applied"], 1)
        self.change(incomplete_apply=False)
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["live"], self.state()["approved"])

    def test_existing_baseline_requires_explicit_readoption(self):
        self.run_script("seed")
        self.run_script("seed", expected=1)
        live = {c: v.replace("return", "accept") for c, v in self.state()["live"].items()}
        self.change(live=live, approved=live)
        (self.base / "policy.nft").write_text(self.policy.replace("return", "accept"))
        self.run_script("seed", "--replace")
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["applied"], 0)

    def test_empty_chain_cannot_be_adopted(self):
        live = self.state()["live"]
        live["split"] = "table inet ddns_p0_policy {\n chain split {\n }\n}\n"
        self.change(live=live)
        self.run_script("seed", expected=1)
        self.assertFalse((self.base / "cn-policy/current").exists())
        self.assertFalse((self.base / "cn-policy/enabled").exists())

    def test_unrelated_table_or_command_cannot_be_adopted(self):
        for source in ("flush ruleset\n", "add chain inet other split\n",
                       "add chain inet ddns_p0_policy unrelated\n",
                       "add rule inet ddns_p0_policy split counter return; flush ruleset\n",
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; }; flush ruleset\n",
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; policy accept; }; delete table inet other; add chain inet other x {}\n",
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; policy accept;\n",
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; policy accept; }}\n",
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; policy accept; } unexpected\n"):
            with self.subTest(source=source):
                (self.base / "policy.nft").write_text(source)
                self.run_script("seed", expected=1)
                self.assertFalse((self.base / "cn-policy/current").exists())

    def test_policy_audit_can_repair_during_dns_transaction_but_seed_is_held(self):
        self.run_script("seed")
        (self.base / "recovering").mkdir()
        self.run_script("audit-runtime", "--repair")
        self.assertEqual(self.state()["applied"], 1)
        self.run_script("seed", "--replace", expected=75)
        self.assertEqual(self.state()["applied"], 1)

    def test_changed_table_binding_refuses_snapshot(self):
        self.run_script("seed")
        self.env["DIVERSION_DNS_POLICY_TABLE"] = "unrelated"
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.state()["applied"], 0)

    def test_double_corrupt_cn_snapshots_block_policy_rebuild_before_helper(self):
        self.run_script("seed")
        current, previous = self.managed_data()
        for generation in (current, previous):
            (generation / "sets.nft").write_text("")
        self.change(live={})
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.state()["applied"], 0)
        self.assertEqual(self.state()["live"], {})

    def test_missing_cn_verifier_and_lost_markers_cannot_bypass_policy_rebuild(self):
        self.run_script("seed")
        self.managed_data()
        (self.base / "cn-data.sh").unlink()
        (self.base / "cn-data/current").unlink()
        (self.base / "cn-data/enabled").unlink()
        self.change(live={})
        self.run_script("audit-runtime", expected=1)
        self.assertEqual(self.state()["applied"], 0)

    def test_healthy_cn_policy_repair_with_pending_journals_and_data_lock_held(self):
        self.run_script("seed")
        current, _ = self.managed_data()
        store = self.base / "cn-data"
        (store / "pending").write_text(current.name + " " + current.name + "\n")
        (store / "repair-pending").write_text(current.name + "\n")
        (self.base / "recovering").mkdir()
        self.change(live={})
        with (store / "lock").open("w") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            self.run_script("audit-runtime")
        self.assertEqual(self.state()["applied"], 1)
        self.assertEqual(self.state()["live"], self.state()["approved"])
        self.assertTrue((store / "pending").is_file())
        self.assertTrue((store / "repair-pending").is_file())

    def test_guard_keeps_c_and_enables_rescue_when_cn_and_policy_are_damaged(self):
        self.run_script("seed")
        current, previous = self.managed_data()
        for generation in (current, previous):
            (generation / "sets.nft").write_text("")
        for name in ("common.sh", "guard.sh"):
            shutil.copy2(SCRIPT.parent / name, self.base / name)
        with (self.base / "common.sh").open("a") as stream:
            stream.write('\nnow_seconds() { echo 100; }\nboot_id() { echo fixture-boot; }\n')
        (self.root / "uptime").write_text("100.0 0.0\n")
        self.env.update(DIVERSION_DNS_RUN=str(self.root / "run"),
                        DIVERSION_CN_TEST_UPTIME=str(self.root / "uptime"),
                        DIVERSION_CN_AUDIT_INTERVAL="0", DIVERSION_DNS_INITDIR=str(self.base))
        (self.base / "active").touch()
        for name in ("enable-rescue", "refresh-monitor", "diversion-dns-c", "dnsmasq"):
            script = self.base / (name + ".sh" if name in ("enable-rescue", "refresh-monitor") else name)
            script.write_text('#!/bin/sh\nprintf "%s\\n" ' + shlex.quote(name)
                              + ' >> "$POLICY_TEST_ROOT/service-actions"\n')
            script.chmod(0o755)
        self.change(live={})
        result = subprocess.run([*self.shell, str(self.base / "guard.sh"), "--once"],
                                env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.state()["applied"], 0)
        self.assertEqual((self.root / "service-actions").read_text().splitlines(),
                         ["enable-rescue", "refresh-monitor"])
        self.assertFalse((self.base / "degraded").exists())
        self.assertFalse((self.base / "recovering").exists())


@unittest.skipUnless(BUSYBOX, "BusyBox absent locally; Linux suite CI installs it")
class BusyBoxPolicyFixture(PolicyFixture):
    """Run every policy transaction test with actual BusyBox ash and awk."""
    shell = (BUSYBOX, "ash")

    def setUp(self):
        super().setUp()
        wrapper = self.bin / "awk"
        wrapper.write_text("#!/bin/sh\nexec " + shlex.quote(BUSYBOX) + " awk \"$@\"\n")
        wrapper.chmod(0o755)

    def test_all_recovery_shell_files_parse_with_busybox_ash(self):
        directory = SCRIPT.parent
        for path in sorted(directory.iterdir()):
            if path.suffix not in (".sh", ".init"):
                continue
            with self.subTest(script=path.name):
                result = subprocess.run([BUSYBOX, "ash", "-n", str(path)],
                                        text=True, capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
