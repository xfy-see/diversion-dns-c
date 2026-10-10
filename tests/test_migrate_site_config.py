"""Pure Python tests of conservative offline migration; no C build or sockets."""
import contextlib
import copy
import importlib.util
import io
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("migrate_site", ROOT / "scripts/migrate-site-config.py")
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


@unittest.skipIf(migration.yaml is None, "optional migration tests require PyYAML")
class SiteMigrationTests(unittest.TestCase):
    def setUp(self):
        self.text = (ROOT / "docs/go-profiles-site-only.yaml").read_text()
        self.config = migration.yaml.safe_load(self.text)

    def convert(self, config=None):
        if config is None:
            config = self.config
        return migration.migrate(migration.yaml.safe_dump(config, sort_keys=False), "source.yaml")

    def rejected(self, config=None, message=None):
        with self.assertRaises(migration.MigrationError) as error:
            self.convert(config)
        self.assertRegex(str(error.exception), r"source.yaml:\d+:")
        if message:
            self.assertIn(message, str(error.exception))

    def plugin(self, tag):
        return next(p for p in self.config["plugins"] if p.get("tag") == tag)

    def test_actual_historical_fixture(self):
        output = migration.migrate(self.text, "docs/go-profiles-site-only.yaml")
        self.assertIn("listen_udp=127.0.0.1:15361\n", output)
        self.assertIn("listen_tcp=127.0.0.1:15361\n", output)
        self.assertIn("cn_domain_file=/etc/mosdns/cn-site.txt\n", output)
        self.assertIn("cn_mark=16777216\ncn_interface=br-lan\n", output)
        self.assertIn("foreign_mark=33554432\nforeign_interface=c131tm\n", output)
        self.assertIn("tcp_idle_timeout=10\n", output)
        self.assertIn("nftset_ipv4=inet,mosdns_cn,cn_site4,ipv4_addr,32\n", output)
        self.assertIn("nftset_ipv6=inet,mosdns_cn,cn_site6,ipv6_addr,128\n", output)
        self.assertNotIn("plugins:", output)
        self.assertEqual(len(output.splitlines()), 17)

    def test_checked_in_linux_example_matches_migration(self):
        output = migration.migrate(self.text)
        example = (ROOT / "c/examples/site-only.conf").read_text()
        self.assertTrue(example.endswith(output))

    def test_arbitrary_tags_inferred_from_graph_and_plugin_order(self):
        text = self.text
        for old, new in (("router_default_forward", "direct2"), ("foreign_forward", "remote2"),
                         ("resolve_cn_site", "resolve2"), ("cn_site", "domain2"),
                         ("finalize", "finish2"), ("main", "entry2")):
            text = re.sub(r"\b" + re.escape(old) + r"\b", new, text)
        config = migration.yaml.safe_load(text)
        config["plugins"].reverse()
        output = self.convert(config)
        self.assertIn("cn_upstream=192.168.100.1:53\n", output)
        self.assertIn("foreign_upstream=1.1.1.1:53\n", output)

    def test_repeatable_files_listeners_upstreams_preserve_order(self):
        self.plugin("cn_site")["args"]["files"] += ["rules with spaces.txt", "x=y#z.txt"]
        self.plugin("router_default_forward")["args"]["upstreams"] += [
            {"addr": "tcp://[2001:db8::1]:5353"}, {"addr": "udp://203.0.113.9"}]
        extra = copy.deepcopy(self.config["plugins"][-2])
        extra["args"]["listen"] = "[::1]:15362"
        self.config["plugins"].append(extra)
        output = self.convert()
        self.assertLess(output.index("cn_domain_file=/etc/"), output.index("cn_domain_file=rules with spaces.txt"))
        self.assertLess(output.index("cn_upstream=192.168."), output.index("cn_upstream=tcp://"))
        self.assertLess(output.index("cn_upstream=tcp://"), output.index("cn_upstream=udp://"))
        self.assertLess(output.index("listen_udp=127."), output.index("listen_udp=[::1]"))
        self.assertIn("cn_domain_file=x=y#z.txt\n", output)

    def test_representable_options_and_hex_numbers(self):
        direct = self.plugin("router_default_forward")["args"]
        direct["so_mark"] = "0xFFFFFFFF"
        direct["concurrent"] = 3
        self.plugin("cache")["args"] = {"size": 17, "lazy_cache_ttl": 7200}
        self.config["plugins"][-1]["args"]["idle_timeout"] = 45
        output = self.convert()
        self.assertIn("cn_mark=4294967295\n", output)
        self.assertIn("cn_concurrent=3\n", output)
        self.assertIn("cache_size=17\ncache_lazy_ttl=7200\n", output)
        self.assertIn("tcp_idle_timeout=45\n", output)

    def test_single_address_type_nft_preserved(self):
        self.plugin("finalize")["args"][0]["exec"] = "nftset ip,table,addresses,ipv4_addr,24"
        output = self.convert()
        self.assertIn("nftset_ipv4=ip,table,addresses,ipv4_addr,24\n", output)
        self.assertNotIn("nftset_ipv6=", output)

    def test_optional_defaults_are_explicit(self):
        self.config.pop("log")
        self.plugin("cache")["args"] = {}
        for tag in ("router_default_forward", "foreign_forward"):
            args = self.plugin(tag)["args"]
            del args["so_mark"]
            del args["bind_to_device"]
        self.assertIn("cn_mark=0\ncn_concurrent=1\n", self.convert())
        self.assertNotIn("cn_interface=", self.convert())

    def test_tcp_only_and_udp_only(self):
        for kind in ("udp_server", "tcp_server"):
            with self.subTest(kind=kind):
                config = copy.deepcopy(self.config)
                config["plugins"] = [p for p in config["plugins"] if p["type"] != kind]
                output = self.convert(config)
                self.assertEqual("tcp_idle_timeout=" in output, kind == "udp_server")

    def test_unknown_fields_at_every_mapping_level(self):
        targets = [self.config, self.plugin("cache"), self.plugin("cn_site")["args"],
                   self.plugin("cache")["args"], self.plugin("router_default_forward")["args"],
                   self.plugin("router_default_forward")["args"]["upstreams"][0],
                   self.plugin("main")["args"][0], self.config["plugins"][-1]["args"],
                   self.config["log"]]
        for target in targets:
            with self.subTest(target=repr(target)):
                target["unknown"] = "false"
                self.rejected(message="unsupported field")
                del target["unknown"]

    def test_explicit_unsupported_options_even_default_values(self):
        for name, value in (("dial_addr", "192.0.2.3"), ("enable_pipeline", False),
                            ("socks5", ""), ("tag", "unused"), ("so_mark", 0),
                            ("idle_timeout", 0), ("max_conns", 0)):
            with self.subTest(name=name):
                target = self.plugin("foreign_forward")["args"]["upstreams"][0]
                target[name] = value
                self.rejected(message="unsupported field")
                del target[name]
        self.config["include"] = []
        self.rejected(message="unsupported field")

    def test_duplicate_mapping_keys_everywhere(self):
        for text in ("plugins: []\nplugins: []\n", self.text.replace("size: 1024", "size: 1024\n      size: 1"),
                     "{plugins: [], 'plugins': []}"):
            with self.subTest(text=text):
                with self.assertRaisesRegex(migration.MigrationError, "duplicate mapping key"):
                    migration.migrate(text)

    def test_yaml_aliases_anchors_tags_merges_and_documents_rejected(self):
        for text in ("plugins: &p []", "plugins: *p", "plugins: !!seq []", "<<: {}\nplugins: []",
                     "%YAML 1.1\n---\nplugins: []", self.text + "\n---\nplugins: []",
                     "? [a, b]\n: value", "!!python/object/apply:os.system ['id']"):
            with self.subTest(text=text):
                with self.assertRaises(migration.MigrationError):
                    migration.migrate(text)

    def test_nondefault_logging_rejected(self):
        self.config["log"]["level"] = "debug"
        self.rejected(message="logging")

    def test_inline_domain_rules_and_composition_rejected(self):
        for key, value in (("exps", ["domain:cn"]), ("sets", ["other"])):
            self.plugin("cn_site")["args"][key] = value
            self.rejected()
            del self.plugin("cn_site")["args"][key]

    def test_graph_changes_rejected(self):
        original = copy.deepcopy(self.config)
        changes = [lambda: self.plugin("main")["args"].reverse(),
                   lambda: self.plugin("main")["args"].append({"exec": "accept"}),
                   lambda: self.plugin("main")["args"][1].update(exec="accept"),
                   lambda: self.plugin("main")["args"][2].update(matches=["!qname $cn_site"]),
                   lambda: self.plugin("main")["args"][3].update(exec="$foreign_forward primary"),
                   lambda: self.plugin("main")["args"][4].update(exec="return"),
                   lambda: self.plugin("resolve_cn_site")["args"][1].update(exec="goto main"),
                   lambda: self.plugin("finalize")["args"][0].update(matches=["_true"]),
                   lambda: self.plugin("finalize")["args"][1].update(exec="reject 3"),
                   lambda: self.plugin("main")["args"][0].update(exec="$cache\u2003"),
                   lambda: self.plugin("main")["args"][0].update(matches=[])]
        for index, change in enumerate(changes):
            with self.subTest(index=index):
                self.config = copy.deepcopy(original)
                change()
                self.rejected()

    def test_duplicate_or_unreachable_plugins_rejected(self):
        extra = copy.deepcopy(self.plugin("cache"))
        self.config["plugins"].append(extra)
        self.rejected(message="duplicate")
        extra["tag"] = "unused_cache"
        self.rejected(message="unreachable")

    def test_different_listener_entries_and_timeouts_rejected(self):
        self.config["plugins"][-1]["args"]["entry"] = "resolve_cn_site"
        self.rejected(message="same entry")
        self.config["plugins"][-1]["args"]["entry"] = "main"
        extra = copy.deepcopy(self.config["plugins"][-1])
        extra["args"]["idle_timeout"] = 20
        self.config["plugins"].append(extra)
        self.rejected(message="TCP idle timeouts")

    def test_listener_limits_and_duplicate_addresses(self):
        original = copy.deepcopy(self.config)
        for index in range(62):
            listener = copy.deepcopy(self.config["plugins"][-2])
            listener["args"]["listen"] = f"127.0.0.1:{20000 + index}"
            self.config["plugins"].append(listener)
        self.convert()
        extra = copy.deepcopy(self.config["plugins"][-1])
        extra["args"]["listen"] = "127.0.0.1:30000"
        self.config["plugins"].append(extra)
        self.rejected()
        self.config = original
        extra = copy.deepcopy(self.config["plugins"][-2])
        extra["args"]["listen"] = "127.0.0.1:015361"
        self.config["plugins"].append(extra)
        self.rejected(message="duplicate numeric listener")
        self.config["plugins"].pop()
        self.config["plugins"][-1]["args"]["listen"] = "127.0.0.1:0"
        self.rejected(message="invalid socket port")

    def test_missing_listeners_or_required_files_rejected(self):
        config = copy.deepcopy(self.config)
        config["plugins"] = [p for p in config["plugins"] if p["type"] not in ("udp_server", "tcp_server")]
        self.rejected(config)
        self.plugin("cn_site")["args"]["files"] = []
        self.rejected()

    def test_bounds_and_legacy_fallback_values_rejected(self):
        cases = [("cache", "size", [0, -1, 10000001, True, "1.0", "1_024", "1e3"]),
                 ("cache", "lazy_cache_ttl", [-1, 4294967296]),
                 ("router_default_forward", "concurrent", [0, 4, 4294967295]),
                 ("router_default_forward", "so_mark", [-1, 4294967296])]
        for tag, key, values in cases:
            args = self.plugin(tag)["args"]
            old = args.get(key)
            for value in values:
                with self.subTest(tag=tag, key=key, value=value):
                    args[key] = value
                    self.rejected()
            if old is None:
                del args[key]
            else:
                args[key] = old
        for value in (0, -1, 86401):
            self.config["plugins"][-1]["args"]["idle_timeout"] = value
            self.rejected()

    def test_interface_bounds(self):
        for value in ("", "x" * 64, "has space", "br-\tlan", "网卡", "bad/interface", "bad\\interface"):
            self.plugin("foreign_forward")["args"]["bind_to_device"] = value
            self.rejected()

    def test_invalid_addresses_rejected(self):
        for address in ("dns.example", "https://1.1.1.1/dns-query", "1.1.1.1:0", "1.1.1.1:65536",
                        ":53", "[127.0.0.1]:53", "2001:db8::g", "fe80::1%eth0", "1.1.1.1#x"):
            with self.subTest(address=address):
                self.plugin("foreign_forward")["args"]["upstreams"][0]["addr"] = address
                self.rejected()

    def test_nft_specs_reject_defaults_duplicates_and_unknown_types(self):
        for value in ("inet,t,s,ipv4_addr,0", "inet,t,s,ipv4_addr,33", "inet,t,s,ipv6_addr,129",
                      "inet,t,s,ipv4_addr", "inet,t,s,ether_addr,32", "bogus,t,s,ipv4_addr,32",
                      "inet,1bad,s,ipv4_addr,32", "ip6,t,s,ipv4_addr,32", "ip,t,s,ipv6_addr,64", "inet,t,s,ipv4_addr,32 inet,t,s2,ipv4_addr,24"):
            with self.subTest(value=value):
                self.plugin("finalize")["args"][0]["exec"] = "nftset " + value
                self.rejected()

    def test_repeatable_limit(self):
        self.plugin("cn_site")["args"]["files"] = ["rules.txt"] * 64
        self.assertEqual(self.convert().count("cn_domain_file="), 64)
        self.plugin("cn_site")["args"]["files"].append("extra.txt")
        self.rejected()

    def test_path_injection_and_whitespace_rejected(self):
        for path in (" padded", "padded ", "a\ncache_size=0", "nul\x00name", "rules\tfile"):
            self.plugin("cn_site")["args"]["files"] = [path]
            self.rejected()

    def test_input_and_output_line_bounds(self):
        with self.assertRaisesRegex(migration.MigrationError, "1 MiB"):
            migration.migrate("#" + "x" * migration.MAX_BYTES)
        self.plugin("cn_site")["args"]["files"] = ["x" * (4096 - len("cn_domain_file="))]
        self.convert()
        self.plugin("cn_site")["args"]["files"][0] += "x"
        self.rejected(message="4096")

    def test_huge_numbers_fail_with_source_line_without_traceback(self):
        for text in (self.text.replace("size: 1024", "size: " + "9" * 5000),
                     self.text.replace("ipv4_addr,32", "ipv4_addr," + "9" * 5000)):
            with self.subTest(text=text[:80]):
                with self.assertRaisesRegex(migration.MigrationError, r"source.yaml:\d+: integer"):
                    migration.migrate(text, "source.yaml")
        text = self.text.replace("size: 1024", "size: " + "0" * 5000 + "1024")
        self.assertIn("cache_size=1024\n", migration.migrate(text))

    def test_long_zero_prefixed_nft_mask_normalized(self):
        for zeros in (500, 5000):
            text = self.text.replace("ipv4_addr,32", "ipv4_addr," + "0" * zeros + "32")
            output = migration.migrate(text)
            self.assertIn("nftset_ipv4=inet,mosdns_cn,cn_site4,ipv4_addr,32\n", output)
            for line in output.splitlines():
                if line.startswith("nftset_"):
                    self.assertLess(len(line.split("=", 1)[1]), 512)

    def test_unicode_surrogate_rejected_with_source_line(self):
        text = self.text.replace('/etc/mosdns/cn-site.txt', r"\uD800")
        with self.assertRaisesRegex(migration.MigrationError, r"source.yaml:\d+: surrogate"):
            migration.migrate(text, "source.yaml")
        with self.assertRaisesRegex(migration.MigrationError, r"source.yaml:1: YAML input must be valid UTF-8"):
            migration.migrate("\ud800", "source.yaml")

    def test_deep_nesting_and_bad_shapes_rejected_cleanly(self):
        for value in ("", "[]", "plugins: null", "plugins: [true]", "plugins: " + "[" * 100 + "]" * 100):
            with self.assertRaises(migration.MigrationError):
                migration.migrate(value)

    def test_cli_no_output_for_unsupported_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "bad.yaml", Path(directory) / "new.conf"
            source.write_text(self.text + "include: other.yaml\n")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                self.assertEqual(migration.main([str(source)]), 1)
                self.assertEqual(migration.main([str(source), "-o", str(destination)]), 1)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(destination.exists())
            self.assertIn("unsupported field", stderr.getvalue())

    def test_cli_creates_new_file_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as directory:
            source, destination = Path(directory) / "site.yaml", Path(directory) / "site.conf"
            source.write_text(self.text)
            self.assertEqual(migration.main([str(source), "-o", str(destination)]), 0)
            output = destination.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(migration.main([str(source), "-o", str(destination)]), 1)
            self.assertEqual(destination.read_bytes(), output)

    def test_missing_pyyaml_has_actionable_error(self):
        with mock.patch.object(migration, "yaml", None):
            with self.assertRaisesRegex(migration.MigrationError, "optional PyYAML"):
                migration.migrate(self.text)


if __name__ == "__main__":
    unittest.main()
