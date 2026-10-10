"""Sectionless ELF ABI and runtime checks using synthetic bytes; no compiler used."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("openwrt_elf", ROOT / "scripts/check-openwrt-elf.py")
checker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(checker)
ARCHES = tuple(checker.ARCHITECTURES)
MIPS = "mipsel_24kc"
SOFT_FLOAT_ABI = (0, 32, 2, 1, 0, 0, 3, 0, 1024, 1, 0)


def elf(arch=checker.DEFAULT_ARCH, *, interpreter=None, flags=None, abi=SOFT_FLOAT_ABI,
        stack_size=1048576, stack_flags=6, omit=(), duplicate=()):
    """Construct ELF32/ELF64 with program headers and no section headers."""
    is_64 = arch != MIPS
    header_size, phsize = (64, 56) if is_64 else (52, 32)
    target = checker.ARCHITECTURES[arch]
    if interpreter is None:
        interpreter = target["interpreter"].encode() + b"\0"
    if flags is None:
        flags = 0 if is_64 else 0x74001005
    definitions = [
        (checker.PT_INTERP, interpreter, len(interpreter), 4),
        (checker.PT_DYNAMIC, bytes(32), 32, 6),
        (checker.PT_GNU_STACK, b"", stack_size, stack_flags),
    ]
    if not is_64:
        definitions.append((checker.PT_MIPS_ABIFLAGS, struct.pack("<H6B4I", *abi), 24, 4))
    definitions = [entry for entry in definitions if entry[0] not in omit]
    definitions += [entry for entry in definitions if entry[0] in duplicate]
    ident = b"\x7fELF" + bytes((target["class"], 1, 1)) + bytes(9)
    header_format = "<HHIQQQIHHHHHH" if is_64 else "<HHIIIIIHHHHHH"
    header = struct.pack(header_format, 2, target["machine"], 1, 0, header_size,
                         0, flags, header_size, phsize, len(definitions), 0, 0, 0)
    payload = bytearray()
    programs = bytearray()
    for kind, content, memsz, permissions in definitions:
        offset = header_size + phsize * len(definitions) + len(payload)
        if is_64:
            programs += struct.pack("<IIQQQQQQ", kind, permissions, offset, 0, 0,
                                    len(content), memsz, 8)
        else:
            programs += struct.pack("<8I", kind, offset, 0, 0, len(content), memsz,
                                    permissions, 4)
        payload += content
    return bytearray(ident + header + programs + payload)


class OpenWrtELF(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name).resolve()
        self.binary = self.directory / "diversion-dns-c-lite"
        self.root = self.directory / "rootfs"
        (self.root / "lib").mkdir(parents=True)
        self.libc = self.root / "lib/libc.so"

    def install(self, arch=checker.DEFAULT_ARCH, **changes):
        self.binary.write_bytes(elf(arch, **changes))
        self.libc.write_bytes(elf(arch))
        self.loader = self.root / checker.ARCHITECTURES[arch]["interpreter"].lstrip("/")
        self.loader.symlink_to("/lib/libc.so")

    def readelf(self, path, *options):
        if options == ("--dynamic",):
            return "0x0001 (NEEDED) Shared library: [libc.so]\n" if path == self.binary else ""
        self.assertEqual(options, ("--use-dynamic", "--symbols"))
        if path == self.binary:
            return (" 1: 000000 0 FUNC GLOBAL DEFAULT UND regcomp\n"
                    " 2: 000000 0 FUNC WEAK DEFAULT UND optional_hook\n"
                    " 3: 000010 4 FUNC GLOBAL DEFAULT 7 main\n")
        return " 1: 000010 4 FUNC GLOBAL DEFAULT 7 regcomp\n"

    def check(self, arch=checker.DEFAULT_ARCH):
        with mock.patch.object(checker, "readelf", side_effect=self.readelf):
            return checker.check(self.binary, self.root, arch)

    def test_fixture_resolves_symlinked_temporary_directory(self):
        # macOS exposes /var/folders through /private/var/folders. Reproduce
        # that alias on any host so path-sensitive readelf doubles stay exact.
        alias = self.directory / "temporary-alias"
        alias.symlink_to(self.directory, target_is_directory=True)
        with mock.patch.object(tempfile, "tempdir", str(alias)):
            case = OpenWrtELF("test_default_aarch64_sectionless_binary")
            result = unittest.TestResult()
            case.run(result)
        self.assertTrue(result.wasSuccessful(), result.errors + result.failures)

    def test_default_aarch64_sectionless_binary(self):
        self.install()
        with mock.patch.object(checker, "readelf", side_effect=self.readelf):
            result = checker.check(self.binary, self.root)
        self.assertEqual(result["arch"], checker.DEFAULT_ARCH)
        self.assertEqual(result["elf"], "ELF64 little-endian AArch64")
        self.assertEqual(result["strong_symbols_checked"], 1)
        self.assertEqual(result["missing_strong_symbols"], [])
        self.assertEqual(result["unresolved_weak_symbols"], ["optional_hook"])
        self.assertEqual(result["default_thread_stack_bytes"], 1048576)
        self.assertFalse(result["stack_executable"])
        self.assertEqual(set(result["libraries"]), {"libc.so"})
        self.assertEqual(len(result["binary_sha256"]), 64)

    def test_explicit_mips_sectionless_binary(self):
        self.install(MIPS)
        result = self.check(MIPS)
        self.assertEqual(result["elf"], "ELF32 little-endian MIPS32r2 O32 soft-float")
        self.assertEqual(result["interpreter"], "/lib/ld-musl-mipsel-sf.so.1")
        self.assertEqual((result["isa"], result["abi"], result["float"], result["gpr_bits"]),
                         ("MIPS32r2", "O32", "soft", 32))
        self.assertEqual(result["abi_flags"], list(SOFT_FLOAT_ABI))
        self.assertTrue(result["mips16"])

    def test_mips_without_mips16_is_allowed(self):
        self.install(MIPS, flags=0x70001005, abi=SOFT_FLOAT_ABI[:8] + (0, 1, 0))
        self.assertFalse(self.check(MIPS)["mips16"])

    def test_wrong_class_endianness_and_ident_version(self):
        for arch in ARCHES:
            for offset, value in [(4, 3 - checker.ARCHITECTURES[arch]["class"]), (5, 2), (6, 0)]:
                with self.subTest(arch=arch, offset=offset):
                    data = elf(arch)
                    data[offset] = value
                    self.binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "expected ELF"):
                        checker.elf_info(self.binary, arch)

    def test_wrong_machine_on_each_arch(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                data = elf(arch)
                struct.pack_into("<H", data, 18, 62)  # EM_X86_64
                self.binary.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "machine"):
                    checker.elf_info(self.binary, arch)

    def test_mips_o32_and_isa_flags(self):
        for flags in [0x60001005, 0x80001005, 0x74000005, 0x74002005,
                      0x74001025, 0x74001045, 0x74001205]:
            with self.subTest(flags=hex(flags)):
                self.binary.write_bytes(elf(MIPS, flags=flags))
                with self.assertRaisesRegex(ValueError, "MIPS32r2 O32 soft-float ELF flags"):
                    checker.elf_info(self.binary, MIPS)

    def test_aarch64_reserved_flags_rejected(self):
        self.binary.write_bytes(elf(flags=1))
        with self.assertRaisesRegex(ValueError, "AArch64 ELF flags"):
            checker.elf_info(self.binary, checker.DEFAULT_ARCH)

    def test_mips_soft_float_register_and_isa_attributes(self):
        for index, value in [(0, 1), (1, 64), (2, 1), (3, 2), (4, 1), (5, 1),
                             (6, 0), (6, 1), (6, 2), (6, 5), (6, 7)]:
            with self.subTest(index=index, value=value):
                abi = list(SOFT_FLOAT_ABI)
                abi[index] = value
                self.binary.write_bytes(elf(MIPS, abi=abi))
                with self.assertRaisesRegex(ValueError, "MIPS32r2 O32 soft-float ABI"):
                    checker.elf_info(self.binary, MIPS)

    def test_mips_header_rejects_unsupported_architectural_extensions(self):
        for extension in (0x01000000, 0x02000000, 0x08000000, 0x0b000000):
            with self.subTest(extension=hex(extension)):
                self.binary.write_bytes(elf(MIPS, flags=0x74001005 | extension))
                with self.assertRaisesRegex(ValueError, "unsupported MIPS architectural extension"):
                    checker.elf_info(self.binary, MIPS)

    def test_mips_abi_rejects_unsupported_extensions_and_reserved_flags(self):
        cases = [(7, 1), (7, 0xffffffff), (9, 2), (9, 0xffffffff)]
        cases += [(8, 0x400 | (1 << bit)) for bit in range(32) if bit != 10]
        cases += [(10, 1 << bit) for bit in range(32)]
        for index, value in cases:
            with self.subTest(index=index, value=hex(value)):
                abi = list(SOFT_FLOAT_ABI)
                abi[index] = value
                self.binary.write_bytes(elf(MIPS, abi=abi))
                with self.assertRaisesRegex(ValueError, "unsupported MIPS ABI extensions or reserved flags"):
                    checker.elf_info(self.binary, MIPS)

    def test_mips_abi_allows_zero_flags1(self):
        self.install(MIPS, abi=SOFT_FLOAT_ABI[:9] + (0, 0))
        self.assertEqual(self.check(MIPS)["abi_flags"][9:], [0, 0])

    def test_mips_runtime_unsupported_extensions_are_rejected(self):
        self.install(MIPS)
        for changes in ({"flags": 0x76001005},
                        {"abi": SOFT_FLOAT_ABI[:8] + (0xc00, 1, 0)},
                        {"abi": SOFT_FLOAT_ABI[:8] + (0x401, 1, 0)},
                        {"abi": SOFT_FLOAT_ABI[:7] + (1, 0x400, 1, 0)},
                        {"abi": SOFT_FLOAT_ABI[:10] + (1,)}):
            with self.subTest(changes=changes):
                self.libc.write_bytes(elf(MIPS, **changes))
                with self.assertRaisesRegex(ValueError, "unsupported MIPS"):
                    self.check(MIPS)

    def test_mips_abiflags_required_and_unique(self):
        for keyword in ("omit", "duplicate"):
            with self.subTest(keyword=keyword):
                self.binary.write_bytes(elf(MIPS, **{keyword: (checker.PT_MIPS_ABIFLAGS,)}))
                with self.assertRaisesRegex(ValueError, "exactly one MIPS ABI flags"):
                    checker.elf_info(self.binary, MIPS)

    def test_mips_abiflags_truncation_and_wrong_size(self):
        for size in (23, 25):
            with self.subTest(size=size):
                data = elf(MIPS)
                # ABIFLAGS is the fourth ELF32 program header; p_filesz is word 4.
                struct.pack_into("<I", data, 52 + 3 * 32 + 16, size)
                self.binary.write_bytes(data + b"\0")
                with self.assertRaisesRegex(ValueError, "invalid MIPS ABI flags size"):
                    checker.elf_info(self.binary, MIPS)
        self.binary.write_bytes(elf(MIPS)[:-1])
        with self.assertRaisesRegex(ValueError, "truncated ELF segment data"):
            checker.elf_info(self.binary, MIPS)

    def test_invalid_and_truncated_headers(self):
        for data in (b"", b"\x7fELF", b"not an ELF" + bytes(100), elf()[:63], elf(MIPS)[:51]):
            with self.subTest(length=len(data)):
                self.binary.write_bytes(data)
                arch = MIPS if len(data) == 51 else checker.DEFAULT_ARCH
                with self.assertRaisesRegex(ValueError, "invalid or truncated ELF|truncated ELF header"):
                    checker.elf_info(self.binary, arch)

    def test_invalid_type_version_and_header_size(self):
        for arch in ARCHES:
            ehsize_offset = 40 if arch == MIPS else 52
            for fmt, offset, value in [("<H", 16, 1), ("<I", 20, 0), ("<H", ehsize_offset, 0)]:
                with self.subTest(arch=arch, offset=offset):
                    data = elf(arch)
                    struct.pack_into(fmt, data, offset, value)
                    self.binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "invalid ELF type, version or header size"):
                        checker.elf_info(self.binary, arch)

    def test_invalid_program_header_table(self):
        for arch in ARCHES:
            fields = [("<I", 28, 0), ("<I", 28, 0xffffffff), ("<H", 42, 0),
                      ("<H", 44, 0), ("<H", 44, 0xffff)] if arch == MIPS else [
                      ("<Q", 32, 0), ("<Q", 32, 0xffffffffffffffff), ("<H", 54, 0),
                      ("<H", 56, 0), ("<H", 56, 0xffff)]
            for fmt, offset, value in fields:
                with self.subTest(arch=arch, offset=offset, value=value):
                    data = elf(arch)
                    struct.pack_into(fmt, data, offset, value)
                    self.binary.write_bytes(data)
                    with self.assertRaisesRegex(ValueError, "invalid or truncated ELF program headers"):
                        checker.elf_info(self.binary, arch)

    def test_dynamic_segment_required_and_unique(self):
        for arch in ARCHES:
            for keyword in ("omit", "duplicate"):
                with self.subTest(arch=arch, keyword=keyword):
                    self.binary.write_bytes(elf(arch, **{keyword: (checker.PT_DYNAMIC,)}))
                    with self.assertRaisesRegex(ValueError, "exactly one dynamic segment"):
                        checker.elf_info(self.binary, arch)

    def test_interpreter_must_match_arch_and_be_nul_terminated(self):
        self.install()
        for interpreter in [b"/lib/ld-musl-mipsel-sf.so.1\0", b"/lib/ld-musl-aarch64.so.1",
                            b"/lib/ld-musl-aarch64.so.1\0extra\0"]:
            with self.subTest(interpreter=interpreter):
                self.binary.write_bytes(elf(interpreter=interpreter))
                with self.assertRaisesRegex(ValueError, "expected OpenWrt musl interpreter"):
                    self.check()

    def test_interpreter_must_exist_once(self):
        self.install()
        for keyword in ("omit", "duplicate"):
            with self.subTest(keyword=keyword):
                self.binary.write_bytes(elf(**{keyword: (checker.PT_INTERP,)}))
                with self.assertRaisesRegex(ValueError, "exactly one interpreter"):
                    self.check()

    def test_stack_requires_exactly_one_rw_nonexec_one_mib_segment(self):
        self.install()
        cases = [{"stack_size": size} for size in (0, 1048575, 1048577, 2097152)]
        cases += [{"stack_flags": flags} for flags in (0, 2, 4, 5, 7, 14)]
        cases += [{keyword: (checker.PT_GNU_STACK,)} for keyword in ("omit", "duplicate")]
        for changes in cases:
            with self.subTest(changes=changes):
                self.binary.write_bytes(elf(**changes))
                with self.assertRaisesRegex(ValueError, "thread stack|GNU_STACK"):
                    self.check()

    def test_missing_rootfs_loader(self):
        self.install()
        self.libc.unlink()
        with self.assertRaisesRegex(ValueError, "interpreter missing"):
            self.check()

    def test_runtime_class_endianness_and_machine_are_checked(self):
        self.install()
        for offset, value in [(4, 1), (5, 2), (18, 8)]:
            with self.subTest(offset=offset):
                data = elf()
                data[offset] = value
                self.libc.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "expected ELF64 little-endian AArch64"):
                    self.check()

    def test_mips_runtime_abi_is_checked(self):
        self.install(MIPS)
        self.libc.write_bytes(elf(MIPS, abi=SOFT_FLOAT_ABI[:6] + (1,) + SOFT_FLOAT_ABI[7:]))
        with self.assertRaisesRegex(ValueError, "MIPS32r2 O32 soft-float ABI"):
            self.check(MIPS)

    def test_distinct_libc_is_checked_as_well_as_loader(self):
        self.install()
        self.loader.unlink()
        self.loader.write_bytes(elf())
        self.libc.write_bytes(elf(MIPS))
        with self.assertRaisesRegex(ValueError, "expected ELF64"):
            self.check()

    def test_only_libc_dependency_allowed(self):
        self.install()
        for name in ("libgcc_s.so.1", "libpcre2-8.so.0", "libpthread.so.0", "../../libc.so"):
            with self.subTest(name=name):
                with mock.patch.object(checker, "readelf", return_value=
                                       "0x0001 (NEEDED) Shared library: [" + name + "]"):
                    with self.assertRaisesRegex(ValueError, "unexpected lite runtime dependency"):
                        checker.check(self.binary, self.root)

    def test_missing_libc_dependency(self):
        self.install()
        self.loader.unlink()
        self.loader.write_bytes(elf())
        self.libc.unlink()
        with self.assertRaisesRegex(ValueError, "missing library: libc.so"):
            self.check()

    def test_rpath_and_runpath_rejected(self):
        self.install()
        for tag in ("RPATH", "RUNPATH"):
            with self.subTest(tag=tag):
                with mock.patch.object(checker, "readelf", return_value="0x001d (" + tag + ") [/tmp]"):
                    with self.assertRaisesRegex(ValueError, "search-path override"):
                        checker.check(self.binary, self.root)

    def test_unresolved_strong_symbols_rejected(self):
        self.install()
        original = self.readelf

        def missing_symbol(path, *options):
            text = original(path, *options)
            return text.replace("regcomp", "other") if path == self.libc else text

        with mock.patch.object(checker, "readelf", side_effect=missing_symbol):
            with self.assertRaisesRegex(ValueError, "missing strong symbols: regcomp"):
                checker.check(self.binary, self.root)

    def test_missing_dynamic_symbols_cannot_silently_pass(self):
        for text in ("", "There are no dynamic symbols in this file.\n"):
            with self.subTest(text=text):
                with mock.patch.object(checker, "readelf", return_value=text):
                    with self.assertRaisesRegex(ValueError, "no dynamic symbols found"):
                        checker.symbols(self.binary)

    def test_truncated_dynamic_segment_is_rejected(self):
        for arch in ARCHES:
            with self.subTest(arch=arch):
                data = elf(arch)
                # Move PT_DYNAMIC file data beyond EOF.
                offset = 52 + 32 + 4 if arch == MIPS else 64 + 56 + 8
                fmt = "<I" if arch == MIPS else "<Q"
                struct.pack_into(fmt, data, offset, len(data) + 1)
                self.binary.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "truncated ELF segment data"):
                    checker.elf_info(self.binary, arch)

    def test_unknown_architecture_rejected(self):
        with self.assertRaisesRegex(ValueError, "unsupported architecture"):
            checker.check(self.binary, self.root, "mips_24kc")

    def test_cli_defaults_and_explicit_arch(self):
        for arch, arguments in [(checker.DEFAULT_ARCH, []), (MIPS, ["--arch", MIPS])]:
            with self.subTest(arch=arch):
                argv = ["check-openwrt-elf.py", "binary", "--rootfs", "rootfs"] + arguments
                output = io.StringIO()
                with mock.patch("sys.argv", argv), mock.patch.object(checker, "check", return_value={
                        "arch": arch}) as check, contextlib.redirect_stdout(output):
                    checker.main()
                check.assert_called_once_with(Path("binary"), Path("rootfs"), arch)
                self.assertEqual(json.loads(output.getvalue()), {"arch": arch})

    def test_cli_invalid_arch_and_validation_error_are_clean_failures(self):
        for args, error in [(["--arch", "unknown"], None), ([], ValueError("bad ABI"))]:
            with self.subTest(args=args):
                argv = ["check-openwrt-elf.py", "binary", "--rootfs", "rootfs"] + args
                with mock.patch("sys.argv", argv), mock.patch.object(checker, "check", side_effect=error), \
                        contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as failure:
                    checker.main()
                self.assertEqual(failure.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
