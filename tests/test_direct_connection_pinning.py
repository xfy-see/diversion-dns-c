import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("pin", Path(__file__).parents[1] / "scripts/pin-openwrt-direct-connections.py")
pin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pin)


class DirectPinTests(unittest.TestCase):
    def original(self):
        rules = [f"        {family} daddr @{name}_{'v4' if family == 'ip' else 'v6'} counter return"
                 for family, name in pin.TARGETS]
        return "# retained prefix\n" + "\n".join(rules) + "\n# retained suffix\n"

    def test_all_direct_classes_and_families_save_both_marks(self):
        output = pin.patch(self.original())
        self.assertEqual(output.count("ct mark set"), 6)
        self.assertEqual(output.count("meta mark set"), 6)
        self.assertEqual(output.count("$MARK_CLEAR_HEX"), 12)
        self.assertEqual(output.count("$BYPASS_MARK_HEX"), 12)
        self.assertTrue(output.startswith("# retained prefix\n"))
        self.assertTrue(output.endswith("# retained suffix\n"))
        self.assertEqual(pin.patch(output), output)

    def test_partial_or_duplicate_input_is_rejected(self):
        text = self.original()
        for bad in [text.replace("@direct_v4", "@other_v4"), text + text,
                    text.replace("@direct_v4 counter return", "@direct_v4 " + pin.ACTION)]:
            with self.assertRaises(ValueError):
                pin.patch(bad)

    def test_mark_operation_preserves_unrelated_bits(self):
        mask, direct = 0xF00, 0x200
        for current in [0, 0x100, 0xABCDEF12, 0xFFFFFFFF]:
            updated = (current & (~mask & 0xFFFFFFFF)) | direct
            self.assertEqual(updated & mask, direct)
            self.assertEqual(updated & ~mask, current & ~mask)


if __name__ == "__main__":
    unittest.main()
