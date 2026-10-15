"""Pure Python fixture checks: no application launch, socket, or C build."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("cache_refresh_safety", ROOT / "c/tests/cache_refresh_safety_test.py")
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)


class CacheRefreshSafetyFixture(unittest.TestCase):
    def test_positive_and_ttl_zero_both_families(self):
        for typ in (1, 28):
            packet = fixture.query("case.test", typ, 512)
            result = fixture.answer(packet, fixture.Policy(ttl=0, changed=True))
            self.assertEqual(result[:2], packet[:2])
            self.assertEqual(fixture.decode(result), {"rcode": 0, "answers": 1,
                                                     "addresses": [fixture.NEW[typ]], "ttls": [0]})

    def test_nodata_without_and_with_zero_soa(self):
        packet = fixture.query("empty.test")
        for mode, authority in (("nodata", 0), ("nodata_soa", 1)):
            result = fixture.answer(packet, fixture.Policy(mode=mode, ttl=0))
            self.assertEqual(struct.unpack_from("!H", result, 8)[0], authority)
            self.assertEqual(fixture.decode(result)["addresses"], [])
            self.assertEqual(fixture.decode(result)["rcode"], 0)

    def test_large_answer_exceeds_budget(self):
        result = fixture.answer(fixture.query("large.test"), fixture.Policy(records=300, changed=True, ttl=30))
        self.assertGreater(len(result), 4096)
        parsed = fixture.decode(result)
        self.assertEqual(parsed["answers"], 300)
        self.assertEqual(set(parsed["addresses"]), {fixture.NEW[1]})

    def test_invalid_and_mismatched_answers_are_distinct(self):
        packet = fixture.query("wrong.test")
        malformed = fixture.answer(packet, fixture.Policy(mode="malformed"))
        with self.assertRaises(ValueError):
            fixture.decode(malformed)
        mismatch = fixture.answer(packet, fixture.Policy(mode="mismatch"))
        self.assertNotEqual(fixture.question(packet)[0], fixture.question(mismatch)[0])
        self.assertEqual(fixture.decode(mismatch)["addresses"], [fixture.OLD[1]])

    def test_servfail_and_silence(self):
        packet = fixture.query("failure.test")
        self.assertIsNone(fixture.answer(packet, fixture.Policy(mode="silent")))
        parsed = fixture.decode(fixture.answer(packet, fixture.Policy(mode="servfail")))
        self.assertEqual(parsed["rcode"], 2)
        self.assertEqual(parsed["answers"], 0)

    def test_pointer_cycle_and_truncation_rejected(self):
        with self.assertRaises(ValueError):
            fixture.read_name(b"\xc0\x00", 0)
        with self.assertRaises(ValueError):
            fixture.read_name(b"\xc0", 0)
        with self.assertRaises(ValueError):
            fixture.wire_name("x" * 64 + ".test")

    def test_retransmissions_count_as_one_refresh(self):
        event = {"time": 10, "transport": "udp", "peer": ["127.0.0.1", 5000], "id": 1,
                 "name": "key.test", "qtype": 1}
        events = [event, {**event, "time": 11}, {**event, "time": 12},
                  {**event, "time": 13, "id": 2}, {**event, "time": 13, "qtype": 28}]
        result = fixture.transactions(events, names={"key.test"}, since=10)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0]["packets"], 3)
        self.assertEqual(len(fixture.transactions(events, names={"absent.test"})), 0)
        self.assertEqual(len(fixture.transactions(events, since=13)), 2)

    def test_rate_bound_uses_measured_time_and_explicit_tolerance(self):
        self.assertEqual(fixture.rate_bound(5, 5), 10)
        self.assertEqual(fixture.rate_bound(5, 6), 74)
        self.assertEqual(fixture.rate_bound(5, 5, allowance=0), 8)


if __name__ == "__main__":
    unittest.main()
