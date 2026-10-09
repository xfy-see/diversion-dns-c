"""Check LLD map classification without compiling or executing target code."""

import importlib.util
from pathlib import Path
import tempfile
import unittest


PATH = Path(__file__).resolve().parents[1] / "benchmarks" / "size-attribution.py"
SPEC = importlib.util.spec_from_file_location("size_attribution", PATH)
SIZE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SIZE)
BUILD_PATH = Path(__file__).resolve().parents[1] / "benchmarks" / "build-c-profiles.py"
BUILD_SPEC = importlib.util.spec_from_file_location("build_c_profiles", BUILD_PATH)
BUILD = importlib.util.module_from_spec(BUILD_SPEC)
BUILD_SPEC.loader.exec_module(BUILD)


class SizeAttributionTests(unittest.TestCase):
    def test_sources_are_distinct(self):
        cases = {
            "/work/objects/main.c.o": "project",
            "/work/libmosdns-c.a(engine.c.o)": "project",
            "/work/libmosdns-c.a(scanner.c.o)": "libyaml",
            "/work/libpcre2-8.a(pcre2_compile.c.o)": "pcre2",
            "/zig/lib/libc.a(memcpy.o)": "musl_startup_compiler",
            "/zig/lib/libubsan_rt.a(ubsan.o)": "musl_startup_compiler",
            "<internal>": "linker_generated",
            "/unexpected/libother.a(example.o)": "unattributed",
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                self.assertEqual(SIZE.category(source), expected)
        self.assertEqual(SIZE.category("<internal>", ".rodata.str1.1"),
                         "shared_merged_constants")

    def test_map_retained_ranges(self):
        lines = """             VMA              LMA     Size Align Out     In      Symbol
            1000             1000       20     4 .text
            1000             1000       10     4         /work/objects/main.c.o:(.text.main)
            1000             1000        0     1                 main
            1010             1010       10     4         /work/libpcre2-8.a(pcre2.c.o):(.text.pcre)
"""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "link.map"
            path.write_text(lines)
            rows = SIZE.parse_map(path, {".text": {"addr": 0x1000, "size": 0x20}})
        self.assertEqual([row["category"] for row in rows[".text"]], ["project", "pcre2"])
        self.assertEqual(sum(row["size"] for row in rows[".text"]), 0x20)

    def test_zig_verbose_link_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "link.log"
            path.write_text("ld.lld -static -o '/tmp/diagnostic elf' /tmp/main.o /tmp/libc.a\n")
            self.assertEqual(BUILD.verbose_lld_command(path),
                             ["-static", "-o", "/tmp/diagnostic elf", "/tmp/main.o", "/tmp/libc.a"])


if __name__ == "__main__":
    unittest.main()
