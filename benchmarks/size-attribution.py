#!/usr/bin/env python3
"""Attribute retained ELF sections using an LLD map; never execute the ELF."""

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import re
import struct


YAML_MEMBERS = {f"{name}.c.o" for name in
                ("api", "dumper", "emitter", "loader", "parser", "reader", "scanner", "writer")}
PROJECT_MEMBERS = {f"{name}.c.o" for name in
                   ("engine", "dns", "upstream", "domain", "util", "cache", "nftset")}
CATEGORIES = ("project", "libyaml", "pcre2", "musl_startup_compiler", "shared_merged_constants", "linker_generated",
              "alignment_metadata", "unattributed")
MAP_ROW = re.compile(r"^\s*([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+(\d+)\s+(\S.*)$")
INPUT_ROW = re.compile(r"^(.*):\(([^()]*)\)$")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# 直接读取 ELF64 小端节表，校验边界；不执行被分析的目标文件。
def elf_sections(path):
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise ValueError("expected little-endian ELF64: " + str(path))
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    if header[2] not in (62, 183):
        raise ValueError("unexpected ELF architecture")
    shoff, shentsize, shnum, shstrndx = header[6], header[11], header[12], header[13]
    if shentsize != 64 or not 0 < shnum < 1000 or shstrndx >= shnum:
        raise ValueError("unsupported ELF section table")
    if shoff + shentsize * shnum > len(data):
        raise ValueError("truncated ELF section table")
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + n * shentsize)
           for n in range(shnum)]
    names = raw[shstrndx]
    if names[4] + names[5] > len(data):
        raise ValueError("truncated ELF section names")
    names_data = data[names[4]:names[4] + names[5]]
    sections = {}
    for row in raw:
        start = row[0]
        end = names_data.find(b"\0", start)
        if end < 0:
            raise ValueError("invalid ELF section name")
        name = names_data[start:end].decode("ascii")
        if not name:
            continue
        kind, flags, addr, offset, size = row[1:6]
        if kind != 8 and offset + size > len(data):
            raise ValueError("truncated ELF section: " + name)
        if name in sections:
            raise ValueError("duplicate ELF section: " + name)
        sections[name] = dict(type=kind, flags=flags, addr=addr, offset=offset, size=size,
                              sha256=sha256(data[offset:offset + size]) if kind != 8 and flags & 2 else None)
    return dict(bytes=len(data), sha256=sha256(data), machine=header[2], sections=sections)


# 仅按已知链接输入分类；合并常量和未知输入单列，避免强行归属给项目代码。
def category(source, input_section=""):
    if source.startswith("<internal>"):
        if input_section.startswith((".rodata.str", ".rodata.cst")):
            return "shared_merged_constants"
        return "linker_generated"
    if source.startswith("*fill*"):
        return "alignment_metadata"
    if "libpcre2-8.a(" in source:
        return "pcre2"
    archive = re.search(r"libmosdns-c\.a\(([^()]*)\)", source)
    if archive:
        member = Path(archive[1]).name
        if member in YAML_MEMBERS:
            return "libyaml"
        if member in PROJECT_MEMBERS:
            return "project"
        return "unattributed"
    if source.endswith(("/main.c.o", "/server.c.o")) and "/objects/" in source:
        return "project"
    if re.search(r"(?:^|/)(?:libc(?:_nonshared)?\.a|libcompiler_rt\.a|libubsan_rt\.a|libunwind\.a|libclang_rt[^/]*\.a)\(", source):
        return "musl_startup_compiler"
    if re.search(r"(?:^|/)(?:crt1|Scrt1|rcrt1|crti|crtn)\.o(?::|$)", source):
        return "musl_startup_compiler"
    if "/musl/" in source or "/compiler_rt/" in source:
        return "musl_startup_compiler"
    return "unattributed"


# 只累计保留在输出节中的输入区间；符号行不重复计入字节。
def parse_map(path, sections):
    if path.stat().st_size == 0:
        raise ValueError("empty LLD map")
    rows = defaultdict(list)
    current = None
    for line in path.read_text(errors="replace").splitlines():
        match = MAP_ROW.match(line)
        if not match:
            continue
        addr, _, size, _, body = match.groups()
        addr, size = int(addr, 16), int(size, 16)
        body = body.strip()
        if body in sections and addr == sections[body]["addr"] and size == sections[body]["size"]:
            current = body
            continue
        source = INPUT_ROW.fullmatch(body)
        if current and source and size:
            rows[current].append(dict(addr=addr, size=size, source=source[1], input_section=source[2],
                                      category=category(source[1], source[2])))
        elif body.startswith(".") and not source:
            current = None
    return rows


# map 必须来自与发布文件字节完全相同的重放链接；诊断文件只辅助比较节布局。
def analyze(release_path, debug_path, mapped_path, map_path):
    release, debug, mapped = (elf_sections(p) for p in (release_path, debug_path, mapped_path))
    if release["machine"] != debug["machine"] or release["sha256"] == debug["sha256"]:
        raise ValueError("diagnostic ELF architecture or strip state differs")
    if release["sha256"] != mapped["sha256"]:
        raise ValueError("map-linked stripped ELF does not match release SHA256: "
                         + release["sha256"] + " != " + mapped["sha256"])
    release_alloc = {n: {k: v[k] for k in ("type", "flags", "addr", "size", "sha256")}
                     for n, v in release["sections"].items() if v["flags"] & 2}
    debug_alloc = {n: {k: v[k] for k in ("type", "flags", "addr", "size", "sha256")}
                   for n, v in debug["sections"].items() if v["flags"] & 2}
    release_shapes = {n: {k: v[k] for k in ("type", "flags", "addr", "size")}
                      for n, v in release_alloc.items()}
    debug_shapes = {n: {k: v[k] for k in ("type", "flags", "addr", "size")}
                    for n, v in debug_alloc.items()}
    if release_shapes != debug_shapes:
        differences = {name: dict(release=release_alloc.get(name), diagnostic=debug_alloc.get(name))
                       for name in sorted(set(release_alloc) | set(debug_alloc))
                       if release_alloc.get(name) != debug_alloc.get(name)}
        raise ValueError("diagnostic and release ELF allocated section shapes differ: "
                         + json.dumps(differences, sort_keys=True))
    rows = parse_map(map_path, mapped["sections"])
    # BSS 只在加载后占空间，与磁盘字节分开计数；填充和元数据也必须对账。
    disk = dict.fromkeys(CATEGORIES, 0)
    bss = dict.fromkeys(CATEGORIES, 0)
    inputs = defaultdict(lambda: dict(disk_bytes=0, bss_bytes=0))
    output_sections = []
    for name, section in release["sections"].items():
        if not section["flags"] & 2:
            continue
        target = bss if section["type"] == 8 else disk
        start, end = section["addr"], section["addr"] + section["size"]
        cursor = start
        per_category = dict.fromkeys(CATEGORIES, 0)
        for item in sorted(rows[name], key=lambda item: (item["addr"], item["size"])):
            if item["addr"] < cursor or item["addr"] + item["size"] > end:
                raise ValueError("overlapping/out-of-range map input in " + name)
            gap = item["addr"] - cursor
            target["alignment_metadata"] += gap
            per_category["alignment_metadata"] += gap
            target[item["category"]] += item["size"]
            per_category[item["category"]] += item["size"]
            source = inputs[(item["source"], item["category"])]
            source["bss_bytes" if section["type"] == 8 else "disk_bytes"] += item["size"]
            cursor = item["addr"] + item["size"]
        tail = end - cursor
        target["alignment_metadata"] += tail
        per_category["alignment_metadata"] += tail
        output_sections.append(dict(name=name, type="bss" if section["type"] == 8 else "file",
                                    bytes=section["size"], categories=per_category,
                                    map_input_rows=len(rows[name])))
    if disk["project"] == 0 or disk["pcre2"] == 0 or not rows:
        raise ValueError("LLD map did not identify project and PCRE2 input sections")
    loadable_file_bytes = sum(s["size"] for s in release["sections"].values()
                              if s["flags"] & 2 and s["type"] != 8)
    # 磁盘归因覆盖整个 ELF 文件，节表、文件头和对齐余量作为单独开销。
    overhead = release["bytes"] - loadable_file_bytes
    if overhead < 0:
        raise ValueError("ELF file is smaller than its loadable sections")
    disk["alignment_metadata"] += overhead
    if sum(disk.values()) != release["bytes"]:
        raise ValueError("disk attribution does not add up")
    return dict(schema=1, release=dict(bytes=release["bytes"], sha256=release["sha256"],
                                       machine=release["machine"]),
                diagnostic=dict(bytes=debug["bytes"], sha256=debug["sha256"],
                                alloc_section_shapes_equal=True,
                                alloc_section_contents_equal=release_alloc == debug_alloc),
                map_replay=dict(sha256=mapped["sha256"], matches_release=True,
                                map_sha256=sha256(map_path.read_bytes())),
                methods=dict(disk="retained LLD map input ranges in SHF_ALLOC file-backed ELF sections; gaps and non-section bytes separate",
                             bss="retained LLD map input ranges in SHF_ALLOC SHT_NOBITS sections; not disk bytes",
                             caveat="map replay is byte-identical to release; unstripped ELF may differ in contents despite equal allocated section shapes; pooled constants, inlining, linker synthesis and padding limit semantic ownership"),
                disk_bytes=disk, bss_bytes=bss, loadable_file_section_bytes=loadable_file_bytes,
                non_section_file_bytes=overhead, sections=output_sections,
                linked_inputs=[dict(source=source, category=cat, **value)
                               for (source, cat), value in sorted(inputs.items())])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path, required=True)
    parser.add_argument("--diagnostic", type=Path, required=True)
    parser.add_argument("--mapped", type=Path, required=True)
    parser.add_argument("--map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = analyze(args.release, args.diagnostic, args.mapped, args.map)
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps(dict(release=result["release"], disk_bytes=result["disk_bytes"],
                          bss_bytes=result["bss_bytes"])))


if __name__ == "__main__":
    main()
