"""Policy integrity transaction tests: command doubles, no firewall or compiler."""
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deployment/openwrt-recovery/cn-policy.sh"
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
    fcntl.flock(int(args[-1]), fcntl.LOCK_EX)
elif name in ("logger", "sync"):
    pass
else:
    sys.exit(92)
'''


class PolicyFixture(unittest.TestCase):
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
        result = subprocess.run(["/bin/sh", str(self.base / "cn-policy.sh"), *args],
                                env=self.env, text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def snapshot(self):
        return (self.base / "cn-policy/current").resolve()

    def test_seed_and_unchanged_audit_do_not_apply_or_change_source(self):
        self.run_script("seed")
        self.assertTrue((self.base / "cn-policy/enabled").is_file())
        self.run_script("audit-runtime")
        self.assertEqual(self.state()["applied"], 0)
        self.assertEqual((self.base / "policy.nft").read_text(), self.policy)
        calls = [json.loads(x) for x in (self.root / "calls.jsonl").read_text().splitlines()]
        self.assertTrue(all(c[1:3] == ["-s", "-nn"] for c in calls if c[0] == "nft"))

    def test_existing_base_chain_syntax_can_be_adopted(self):
        source = self.policy.replace(
            "add chain inet ddns_p0_policy classify\n",
            "add chain inet ddns_p0_policy classify { type filter hook prerouting priority -130; policy accept; }\n")
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
                       "add chain inet ddns_p0_policy guard { type filter hook forward priority 0; policy accept; }; delete table inet other; add chain inet other x {}\n"):
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


if __name__ == "__main__":
    unittest.main()
