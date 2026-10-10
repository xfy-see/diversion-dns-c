#!/usr/bin/env python3
"""Read-only OpenWrt ELF/runtime compatibility check (not a device test)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess


def readelf(path, *options):
    return subprocess.check_output(["readelf", *options, "--wide", str(path)], text=True)


def symbols(path):
    needed, exported, weak = set(), set(), set()
    symbol_count = 0
    # OpenWrt sstrip can remove section headers. Follow PT_DYNAMIC rather than
    # depending on a .dynsym section header still being present.
    for line in readelf(path, "--use-dynamic", "--symbols").splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        symbol_count += 1
        name = fields[7]
        if "@" in name:
            raise ValueError("versioned symbol requires separate ABI review: " + name)
        if fields[6] == "UND":
            (weak if fields[4] == "WEAK" else needed).add(name)
        elif fields[4] in {"GLOBAL", "WEAK"} and fields[5] in {"DEFAULT", "PROTECTED"}:
            exported.add(name)
    if not symbol_count:
        raise ValueError("no dynamic symbols found: " + str(path))
    return needed, exported, weak


def rooted(root, absolute):
    """Resolve absolute guest symlinks inside the rootfs, never on the host."""
    relative = Path(absolute.lstrip("/"))
    for _ in range(16):
        if ".." in relative.parts:
            raise ValueError("parent traversal in rootfs path")
        current = root
        for index, part in enumerate(relative.parts):
            current /= part
            if current.is_symlink():
                target = current.readlink()
                relative = ((Path(str(target).lstrip("/")) if target.is_absolute()
                             else current.parent.relative_to(root) / target)
                            .joinpath(*relative.parts[index + 1:]))
                break
        else:
            return current
    raise ValueError("too many rootfs symlinks")


ARCHITECTURES = {
    "aarch64_cortex-a53": {
        "class": 2, "machine": 183,
        "elf": "ELF64 little-endian AArch64",
        "interpreter": "/lib/ld-musl-aarch64.so.1",
    },
    "mipsel_24kc": {
        "class": 1, "machine": 8,
        "elf": "ELF32 little-endian MIPS32r2 O32 soft-float",
        "interpreter": "/lib/ld-musl-mipsel-sf.so.1",
    },
}
DEFAULT_ARCH = "aarch64_cortex-a53"
PT_INTERP, PT_DYNAMIC, PT_GNU_STACK = 3, 2, 0x6474e551
PT_MIPS_ABIFLAGS = 0x70000003


def elf_info(path, arch):
    """Validate the ELF and program headers without needing section headers.

    OpenWrt sstrip removes section headers, including .MIPS.abiflags. Its
    PT_MIPS_ABIFLAGS program header remains authoritative for the MIPS ABI.
    """
    if arch not in ARCHITECTURES:
        raise ValueError("unsupported architecture: " + arch)
    target = ARCHITECTURES[arch]
    data = Path(path).read_bytes()
    if len(data) < 16 or data[:4] != b"\x7fELF":
        raise ValueError("invalid or truncated ELF: " + str(path))
    if data[4:7] != bytes((target["class"], 1, 1)):
        raise ValueError("expected " + target["elf"] + ": " + str(path))
    is_64 = target["class"] == 2
    header_format = "<HHIQQQIHHHHHH" if is_64 else "<HHIIIIIHHHHHH"
    header_size = 16 + struct.calcsize(header_format)
    if len(data) < header_size:
        raise ValueError("truncated ELF header: " + str(path))
    header = struct.unpack_from(header_format, data, 16)
    elf_type, machine, version, _, phoff, _, flags, ehsize, phsize, phnum = header[:10]
    if machine != target["machine"]:
        raise ValueError("expected " + target["elf"] + " machine: " + str(path))
    if elf_type not in {2, 3} or version != 1 or ehsize != header_size:
        raise ValueError("invalid ELF type, version or header size: " + str(path))
    phformat = "<IIQQQQQQ" if is_64 else "<8I"
    expected_phsize = struct.calcsize(phformat)
    if (phsize != expected_phsize or phnum in {0, 0xffff} or
            phoff < header_size or phoff + phsize * phnum > len(data)):
        raise ValueError("invalid or truncated ELF program headers: " + str(path))
    segments = []
    for index in range(phnum):
        values = struct.unpack_from(phformat, data, phoff + index * phsize)
        if is_64:
            kind, permissions, offset, _, _, filesz, memsz, _ = values
        else:
            kind, offset, _, _, filesz, memsz, permissions, _ = values
        segment = {"type": kind, "offset": offset, "filesz": filesz,
                   "memsz": memsz, "flags": permissions}
        if filesz:
            segment_data(data, segment)
        segments.append(segment)
    abi = {}
    if arch == "mipsel_24kc":
        # EF_MIPS_ARCH_32R2 and EF_MIPS_ABI_O32; explicitly reject ABI2/ON32
        # and 64-bit FP register mode even if a conflicting O32 flag is set.
        if (flags & 0xf0000000 != 0x70000000 or
                flags & 0x0000f000 != 0x1000 or flags & (0x20 | 0x40 | 0x200)):
            raise ValueError("expected MIPS32r2 O32 soft-float ELF flags: " + str(path))
        # The 24Kc profile supports MIPS16, not microMIPS, MDMX or other ASEs.
        if flags & 0x0f000000 & ~0x04000000:
            raise ValueError("unsupported MIPS architectural extension flags: " + str(path))
        abiflags = segment_data(data, only_segment(segments, PT_MIPS_ABIFLAGS,
                                                  "MIPS ABI flags"))
        if len(abiflags) != 24:
            raise ValueError("invalid MIPS ABI flags size: " + str(path))
        values = struct.unpack("<H6B4I", abiflags)
        # Version 0, MIPS32r2, GPR32, no FP/coprocessor registers, soft float.
        if values[:7] != (0, 32, 2, 1, 0, 0, 3):
            raise ValueError("expected MIPS32r2 O32 soft-float ABI: " + str(path))
        # No processor-specific ISA, only optional MIPS16 ASE, and no
        # reserved ABI flags. flags1 bit 0 (ODDSPREG) occurs in the SDK ABI.
        if values[7] != 0 or values[8] & ~0x400 or values[9] & ~1 or values[10] != 0:
            raise ValueError("unsupported MIPS ABI extensions or reserved flags: " + str(path))
        abi = {"isa": "MIPS32r2", "abi": "O32", "float": "soft",
               "gpr_bits": 32, "mips16": bool(flags & 0x04000000),
               "abi_flags": list(values)}
    elif flags != 0:
        raise ValueError("expected AArch64 ELF flags to be zero: " + str(path))
    only_segment(segments, PT_DYNAMIC, "dynamic segment")
    return data, segments, abi


def only_segment(segments, kind, label):
    matches = [segment for segment in segments if segment["type"] == kind]
    if len(matches) != 1:
        raise ValueError("expected exactly one " + label)
    return matches[0]


def segment_data(data, segment):
    start, size = segment["offset"], segment["filesz"]
    if start > len(data) or size > len(data) - start:
        raise ValueError("truncated ELF segment data")
    return data[start:start + size]


def check(binary, rootfs, arch=DEFAULT_ARCH):
    binary, rootfs = Path(binary).resolve(), Path(rootfs).resolve()
    data, segments, abi = elf_info(binary, arch)
    target = ARCHITECTURES[arch]
    interpreter = segment_data(data, only_segment(segments, PT_INTERP, "interpreter"))
    # Permit alignment padding after the terminating NUL, but no second string.
    if (not interpreter.endswith(b"\0") or
            interpreter.rstrip(b"\0") != target["interpreter"].encode("ascii")):
        raise ValueError("expected OpenWrt musl interpreter: " + target["interpreter"])
    stack = only_segment(segments, PT_GNU_STACK, "GNU_STACK segment")
    if stack["memsz"] != 1048576 or stack["flags"] != 6:
        raise ValueError("required non-executable RW 1 MiB default thread stack missing")
    loader = rooted(rootfs, target["interpreter"])
    if not loader.is_file():
        raise ValueError("interpreter missing from supplied rootfs")
    libraries, needed, exports, weak = {}, set(), set(), set()
    pending = [binary, loader]
    visited = set()
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        elf_info(path, arch)
        dynamic = readelf(path, "--dynamic")
        if re.search(r"\((?:RPATH|RUNPATH)\)", dynamic):
            raise ValueError("runtime search-path override requires separate review")
        for name in re.findall(r"\(NEEDED\).*?\[([^]]+)\]", dynamic):
            if name != "libc.so":
                raise ValueError("unexpected lite runtime dependency: " + name)
            matches = [rooted(rootfs, directory + name) for directory in ["/lib/", "/usr/lib/"]]
            found = next((candidate for candidate in matches if candidate.is_file()), None)
            if found is None:
                raise ValueError("missing library: " + name)
            libraries[name] = {"bytes": found.stat().st_size,
                               "sha256": hashlib.sha256(found.read_bytes()).hexdigest()}
            pending.append(found)
        required, provided, optional = symbols(path)
        needed |= required
        exports |= provided
        weak |= optional
    missing = sorted(needed - exports)
    if missing:
        raise ValueError("missing strong symbols: " + ", ".join(missing))
    return {"arch": arch, "elf": target["elf"], **abi, "interpreter": target["interpreter"],
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "libraries": libraries, "strong_symbols_checked": len(needed),
            "unresolved_weak_symbols": sorted(weak - exports), "missing_strong_symbols": missing,
            "default_thread_stack_bytes": stack["memsz"], "stack_executable": False,
            "scope": "ELF/rootfs compatibility check only; not device/kernel/performance acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--rootfs", type=Path, required=True)
    parser.add_argument("--arch", choices=ARCHITECTURES, default=DEFAULT_ARCH,
                        help="OpenWrt package architecture (default: %(default)s)")
    args = parser.parse_args()
    try:
        result = check(args.binary, args.rootfs, args.arch)
    except (ValueError, subprocess.CalledProcessError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
