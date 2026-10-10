#!/usr/bin/env python3
"""Read-only AArch64 ELF check against an extracted OpenWrt rootfs (not a device test)."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def readelf(path, *options):
    return subprocess.check_output(["readelf", *options, "--wide", str(path)], text=True)


def symbols(path):
    needed, exported, weak = set(), set(), set()
    # OpenWrt sstrip can remove section headers. Follow PT_DYNAMIC rather than
    # depending on a .dynsym section header still being present.
    for line in readelf(path, "--use-dynamic", "--symbols").splitlines():
        fields = line.split()
        if len(fields) < 8 or not fields[0].rstrip(":").isdigit():
            continue
        name = fields[7]
        if "@" in name:
            raise ValueError("versioned symbol requires separate ABI review: " + name)
        if fields[6] == "UND":
            (weak if fields[4] == "WEAK" else needed).add(name)
        elif fields[4] in {"GLOBAL", "WEAK"} and fields[5] in {"DEFAULT", "PROTECTED"}:
            exported.add(name)
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


def check(binary, rootfs):
    binary, rootfs = Path(binary).resolve(), Path(rootfs).resolve()
    header = readelf(binary, "--file-header")
    if not all(value in header for value in ["ELF64", "little endian", "AArch64"]):
        raise ValueError("expected ELF64 little-endian AArch64")
    program = readelf(binary, "--program-headers")
    interpreter = re.search(r"Requesting program interpreter: ([^]]+)", program)
    if not interpreter or interpreter.group(1) != "/lib/ld-musl-aarch64.so.1":
        raise ValueError("expected OpenWrt AArch64 musl interpreter")
    stack = next((line.split() for line in program.splitlines() if "GNU_STACK" in line), None)
    if not stack or int(stack[5], 16) < 1048576 or "E" in stack[6]:
        raise ValueError("required non-executable >=1 MiB default thread stack missing")
    loader = rooted(rootfs, interpreter.group(1))
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
        if "AArch64" not in readelf(path, "--file-header"):
            raise ValueError("non-AArch64 runtime: " + str(path))
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
    return {"elf": "ELF64 little-endian AArch64", "interpreter": interpreter.group(1),
            "binary_bytes": binary.stat().st_size,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "libraries": libraries, "strong_symbols_checked": len(needed),
            "unresolved_weak_symbols": sorted(weak - exports), "missing_strong_symbols": missing,
            "default_thread_stack_bytes": int(stack[5], 16),
            "scope": "ELF/rootfs compatibility check only; not device/kernel/performance acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--rootfs", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(args.binary, args.rootfs)
    except (ValueError, subprocess.CalledProcessError, OSError) as exc:
        parser.error(str(exc))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
