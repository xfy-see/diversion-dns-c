#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Isolated, same-source PCRE2 versus experimental posix-lite size comparison.

Supply local, checksum-verified official Zig 0.14.1 and PCRE2 10.48 archives.
This experimental script neither downloads nor publishes anything and leaves
normal CI/release builds untouched. It freezes inputs once, builds fresh PCRE2
for each musl target, records commands and ELF identities, and optionally runs
functional tests on matching Linux hardware. It does not measure performance.
An existing output directory is never overwritten.
"""
import argparse
from collections import defaultdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
from datetime import datetime, timezone

sys.dont_write_bytecode = True
PROFILE_PATH = Path(__file__).with_name("build-c-profiles.py")
SPEC = importlib.util.spec_from_file_location("release_profile", PROFILE_PATH)
PROFILE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PROFILE)
SIZE_SPEC = importlib.util.spec_from_file_location("release_size", Path(__file__).with_name("size-attribution.py"))
SIZE = importlib.util.module_from_spec(SIZE_SPEC)
SIZE_SPEC.loader.exec_module(SIZE)

ZIG_VERSION = "0.14.1"
ZIG_ARCHIVES = {
    "zig-x86_64-linux-0.14.1.tar.xz": "24aeeec8af16c381934a6cd7d95c807a8cb2cf7df9fa40d359aa884195c4716c",
    "zig-aarch64-linux-0.14.1.tar.xz": "f7a654acc967864f7a050ddacfaa778c7504a0eca8d2b678839c21eea47c992b",
}
TARGETS = ("x86_64-linux-musl", "aarch64-linux-musl")
BACKENDS = ("pcre2", "posix-lite")
OPTFLAGS = PROFILE.OPTFLAGS.copy()
CFLAGS = OPTFLAGS + ["-UNDEBUG", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread"]
LDFLAGS = PROFILE.STATIC_LDFLAGS.copy()
TESTS = ("dns_test", "cache_domain_test", "fixed_config_test", "fixed_engine_test", "nft_netlink_test")
DRIVERS = ("domain_driver", "nft_cli_driver")


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def record(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError("not a regular file: " + str(path))
    return {"bytes": path.stat().st_size, "sha256": digest(path)}


def snapshot_inputs(root):
    names = {"c/" + name: value for name, value in PROFILE.tree(root / "c").items()}
    for directory in ("tests",):
        names.update({directory + "/" + name: value for name, value in PROFILE.tree(root / directory).items()})
    for name in ("benchmarks/build-c-profiles.py", "benchmarks/compare-regex-backends.py", "benchmarks/size-attribution.py", ".github/workflows/build.yml"):
        names[name] = record(root / name)
    return dict(sorted(names.items()))


def write_json(path, value):
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
    temporary.replace(path)


def verify_zig(zig, archive, index):
    expected = ZIG_ARCHIVES.get(archive.name)
    if expected is None or digest(archive) != expected:
        raise RuntimeError("Zig archive differs from the pinned official 0.14.1 checksum")
    official = json.loads(index.read_text())[ZIG_VERSION]
    host = "aarch64-linux" if "aarch64" in archive.name else "x86_64-linux"
    release = official[host]
    origin = "https://ziglang.org/download/0.14.1/" + archive.name
    if release["tarball"] != origin or release["shasum"] != expected or int(release["size"]) != archive.stat().st_size:
        raise RuntimeError("official Zig download index does not match pinned archive")
    with tarfile.open(archive) as source:
        member = source.getmember(archive.name.removesuffix(".tar.xz") + "/zig")
        if not member.isfile():
            raise RuntimeError("official archive compiler is not a regular file")
        compiler_hash = hashlib.file_digest(source.extractfile(member), "sha256").hexdigest()
    if compiler_hash != digest(zig):
        raise RuntimeError("Zig executable differs from the verified archive")
    return {"version": ZIG_VERSION, "path": str(zig), "executable": record(zig),
            "origin": origin, "archive": {"path": str(archive), **record(archive)},
            "official_index": {"origin": "https://ziglang.org/download/index.json", "path": str(index), **record(index)},
            "checksum_validation": "pinned checksum and official release index agree; executable matches archive",
            "signature_verified": False}


def size_category(source, section, build):
    """Classify known link inputs; pooled constants and ELF overhead stay separate."""
    if source.endswith(".lto.o"):
        return "mixed_lto"
    if source.startswith("<internal>"):
        return "shared_merged_constants" if section.startswith((".rodata.str", ".rodata.cst")) else "linker_generated"
    if source.startswith("*fill*"):
        return "alignment_metadata"
    if source.startswith(str(build / "libmosdns-c.a") + "(") or source in {
            str(build / "main.o"), str(build / "pkg/server.o")}:
        return "project"
    if "libpcre2-8.a(" in source:
        return "pcre2"
    if re.search(r"(?:^|/)(?:libc(?:_nonshared)?\.a)\(", source) or "/musl/" in source:
        return "musl_libc"
    if re.search(r"(?:^|/)(?:crt1|Scrt1|rcrt1|crti|crtn)\.o$", source):
        return "crt_startup"
    if re.search(r"(?:^|/)(?:libcompiler_rt\.a|libubsan_rt\.a|libunwind\.a|libclang_rt[^/]*\.a)\(", source) or "/compiler_rt/" in source:
        return "compiler_runtime"
    return "unattributed"


def analyze_size(release_path, diagnostic_path, mapped_path, map_path, build):
    """Reconcile every on-disk byte against a byte-identical stripped map link."""
    release, diagnostic, mapped = (SIZE.elf_sections(p) for p in (release_path, diagnostic_path, mapped_path))
    if release["sha256"] != mapped["sha256"]:
        raise RuntimeError("map-linked ELF differs from the measured release")
    if release["machine"] != diagnostic["machine"] or release["sha256"] == diagnostic["sha256"]:
        raise RuntimeError("unexpected diagnostic architecture or stripping")
    def shapes(elf):
        return {name: {key: row[key] for key in ("type", "flags", "addr", "size")}
                for name, row in elf["sections"].items() if row["flags"] & 2}
    if shapes(release) != shapes(diagnostic):
        raise RuntimeError("diagnostic allocated section shapes differ")
    categories = ("mixed_lto", "project", "pcre2", "musl_libc", "crt_startup", "compiler_runtime",
                  "shared_merged_constants", "linker_generated", "alignment_metadata", "unattributed")
    disk, bss = dict.fromkeys(categories, 0), dict.fromkeys(categories, 0)
    linked = defaultdict(lambda: {"disk_bytes": 0, "bss_bytes": 0})
    rows = SIZE.parse_map(map_path, mapped["sections"])
    sections = []
    for name, section in release["sections"].items():
        if not section["flags"] & 2:
            continue
        target = bss if section["type"] == 8 else disk
        cursor, end = section["addr"], section["addr"] + section["size"]
        totals = dict.fromkeys(categories, 0)
        for row in sorted(rows[name], key=lambda r: (r["addr"], r["size"])):
            if row["addr"] < cursor or row["addr"] + row["size"] > end:
                raise RuntimeError("overlapping or out-of-range map row in " + name)
            category = size_category(row["source"], row["input_section"], build)
            gap = row["addr"] - cursor
            target["alignment_metadata"] += gap
            totals["alignment_metadata"] += gap
            target[category] += row["size"]
            totals[category] += row["size"]
            linked[(row["source"], category)]["bss_bytes" if section["type"] == 8 else "disk_bytes"] += row["size"]
            cursor = row["addr"] + row["size"]
        target["alignment_metadata"] += end - cursor
        totals["alignment_metadata"] += end - cursor
        sections.append({"name": name, "kind": "bss" if section["type"] == 8 else "file", "bytes": section["size"], "categories": totals})
    loadable = sum(s["size"] for s in release["sections"].values() if s["flags"] & 2 and s["type"] != 8)
    overhead = release["bytes"] - loadable
    if overhead < 0 or not rows or (not disk["mixed_lto"] and (not disk["project"] or not disk["musl_libc"])):
        raise RuntimeError("incomplete ELF size attribution")
    disk["alignment_metadata"] += overhead
    if sum(disk.values()) != release["bytes"]:
        raise RuntimeError("disk attribution does not reconcile to the measured ELF")
    return {"schema_version": 1, "release": record(release_path), "diagnostic": record(diagnostic_path),
            "map_replay_matches_release": True, "diagnostic_allocated_shapes_equal": True,
            "disk_bytes": disk, "bss_bytes": bss, "loadable_file_section_bytes": loadable,
            "non_section_file_bytes": overhead, "sections": sections,
            "linked_inputs": [{"source": source, "category": category, **counts} for (source, category), counts in sorted(linked.items())],
            "method": "Retained LLD map input intervals; stripped map link is byte-identical to measured release. BSS is excluded from disk bytes.",
            "limits": "LTO merges project, dependencies and runtime under mixed_lto; their separate retained byte counts are unavailable. Dependency identity is verified separately. Object ownership is not semantic ownership: inline library code can reside in project objects; merged constants, linker-generated sections and alignment/ELF metadata are separate. musl_libc includes regex. No installed libc or archive size is treated as linked app cost."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--zig-archive", type=Path, required=True)
    parser.add_argument("--zig-index", type=Path, required=True)
    parser.add_argument("--pcre2-archive", type=Path, required=True)
    parser.add_argument("--target", choices=TARGETS, action="append", help="repeat to select targets; default both")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--run-native-tests", action="store_true", help="run matching Linux binaries only; no emulator")
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be 1 through 32")
    for name in ("root", "output", "zig", "zig_archive", "zig_index", "pcre2_archive"):
        setattr(args, name, getattr(args, name).resolve())
    compiler = verify_zig(args.zig, args.zig_archive, args.zig_index)
    if digest(args.pcre2_archive) != PROFILE.PCRE2_SHA256:
        parser.error("PCRE2 archive differs from pinned 10.48 checksum")
    args.output.mkdir(mode=0o700)
    out = args.output
    logs = out / "logs"
    logs.mkdir()
    env = os.environ.copy()
    # Avoid global caches, inherited build flags, locale-dependent regex behavior,
    # and Python bytecode written into the checked-in source tree.
    for key in ("CFLAGS", "CPPFLAGS", "LDFLAGS", "LDLIBS", "CC", "AR", "RANLIB", "MAKEFLAGS", "MFLAGS", "CONFIG_SITE", "CPATH", "C_INCLUDE_PATH", "LIBRARY_PATH", "ZIG_LIB_DIR"):
        env.pop(key, None)
    for key in ("ZIG_GLOBAL_CACHE_DIR", "ZIG_LOCAL_CACHE_DIR", "TMPDIR"):
        directory = out / "work" / key.lower()
        directory.mkdir(parents=True)
        env[key] = str(directory)
    env.update({"LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
                "ZIG_LIB_DIR": str(args.zig.parent / "lib")})
    manifest = {"schema_version": 1, "status": "building", "created_utc": now(), "source_root": str(args.root),
                "scope": "Experimental same-source size and functional comparison. No performance, router or kernel-nft claims.",
                "compiler": compiler, "host": {"system": platform.system(), "machine": platform.machine()},
                "flags": {"c": CFLAGS, "link": LDFLAGS, "pcre2": OPTFLAGS}, "commands": [], "targets": {}}
    manifest_path = out / "manifest.json"

    def run(cmd, cwd, name, timeout=900, extra_env=None):
        if (logs / (name + ".log")).exists():
            raise RuntimeError("duplicate command log name: " + name)
        item = {"command": [str(v) for v in cmd], "cwd": str(cwd), "started_utc": now(), "log": str(logs / (name + ".log"))}
        if extra_env:
            item["environment_overrides"] = extra_env
        manifest["commands"].append(item)
        write_json(manifest_path, manifest)
        try:
            result = subprocess.run(cmd, cwd=cwd, env={**env, **(extra_env or {})}, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", timeout=timeout)
            item["exit_code"] = result.returncode
            output = result.stdout
        except subprocess.TimeoutExpired as error:
            output = error.stdout or b""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            item["timeout_seconds"] = timeout
            item["exit_code"] = None
        item["finished_utc"] = now()
        output = re.sub(r"(https?://)[^/\s@]+@", r"\1<redacted>@", output)
        Path(item["log"]).write_text(output)
        write_json(manifest_path, manifest)
        if item["exit_code"] != 0:
            raise RuntimeError("command failed, see " + item["log"])
        return output

    try:
        if run([str(args.zig), "version"], out, "zig-version").strip() != ZIG_VERSION:
            raise RuntimeError("unexpected Zig version")
        inputs = snapshot_inputs(args.root)
        manifest["inputs"] = inputs
        manifest["input_tree_sha256"] = hashlib.sha256(json.dumps(inputs, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        frozen = out / "source"
        PROFILE.freeze(args.root, frozen, inputs)
        deps = out / "deps"
        deps.mkdir()
        archive = deps / "pcre2-10.48.tar.gz"
        shutil.copyfile(args.pcre2_archive, archive)
        archive.chmod(0o444)
        pcre_source = PROFILE.extract_archive(archive, deps / "source")
        pcre_inputs = PROFILE.tree(pcre_source)
        for path in pcre_source.rglob("*"):
            if path.is_file():
                path.chmod(0o555 if path.stat().st_mode & 0o100 else 0o444)
        manifest["pcre2"] = {"version": "10.48", "origin": "https://github.com/PCRE2Project/pcre2/releases/download/pcre2-10.48/pcre2-10.48.tar.gz",
                             "archive": record(archive), "inputs": pcre_inputs, "configure_options": PROFILE.PCRE2_CONFIGURE_OPTIONS}
        licenses = out / "licenses"
        licenses.mkdir()
        for name in ("LICENCE.md", "AUTHORS.md"):
            shutil.copyfile(pcre_source / name, licenses / ("PCRE2-" + name))
        shutil.copyfile(args.zig.parent / "LICENSE", licenses / "Zig-LICENSE")
        # Zig distributes the musl copyright with its libc sources.
        musl_copyright = args.zig.parent / "lib/libc/musl/COPYRIGHT"
        if musl_copyright.is_file():
            shutil.copyfile(musl_copyright, licenses / "musl-COPYRIGHT")
        for target in list(dict.fromkeys(args.target or TARGETS)):
            print("Building " + target, flush=True)
            work = out / "work" / target
            work.mkdir()
            wrappers = work / "tools"
            wrappers.mkdir()
            for name, suffix in (("cc", ["cc", "-target", target]), ("ar", ["ar"]), ("ranlib", ["ranlib"])):
                wrapper = wrappers / name
                wrapper.write_text("#!/bin/sh\nexec " + shlex.join([str(args.zig)] + suffix) + ' "$@"\n')
                wrapper.chmod(0o755)
            pcre_build = work / "pcre2-8-no-unicode-no-jit"
            pcre_build.mkdir()
            result = {"pcre2": {}, "backends": {}}
            manifest["targets"][target] = result
            run([str(pcre_source / "configure"), "--host=" + target] + PROFILE.PCRE2_CONFIGURE_OPTIONS +
                ["CC=" + str(wrappers / "cc"), "AR=" + str(wrappers / "ar"), "RANLIB=" + str(wrappers / "ranlib"), "CFLAGS=" + " ".join(OPTFLAGS)],
                pcre_build, target + "-pcre2-dependency-configure")
            run(["make", "-j" + str(args.jobs), "libpcre2-8.la"], pcre_build, target + "-pcre2-dependency-build")
            pcre_lib = pcre_build / ".libs/libpcre2-8.a"
            config_text = (pcre_build / "src/config.h").read_text()
            PROFILE.verify_pcre2_config(config_text)
            result["pcre2"] = {"static_library": {"path": str(pcre_lib), **record(pcre_lib)}, "config_header": record(pcre_build / "src/config.h"),
                               "profile_verified": "8-bit only, Unicode disabled, JIT disabled"}
            native = platform.system() == "Linux" and platform.machine() in ({"x86_64", "amd64"} if target.startswith("x86_64") else {"aarch64", "arm64"})
            for backend in BACKENDS:
                build = out / target / backend
                prefix = target + "-" + backend
                common = ["make", "-C", str(frozen / "c"), "-j" + str(args.jobs), "CC=" + str(wrappers / "cc"),
                          "AR=" + str(wrappers / "ar"), "BUILD=" + str(build), "REGEX_BACKEND=" + backend,
                          "CFLAGS=" + " ".join(CFLAGS), "LDFLAGS=" + " ".join(LDFLAGS),
                          "PCRE2_CFLAGS=-I" + str(pcre_build / "src") + " -I" + str(pcre_source / "src"), "PCRE2_LIB=" + str(pcre_lib)]
                run(common + ["all"] + [str(build / "tests" / name) for name in TESTS + DRIVERS], work, prefix + "-build")
                app = build / "mosdns-c"
                release_record = record(app)
                # Repeat the exact Make link with verbosity, then ask the same
                # LLD inputs for a map and an unstripped diagnostic. Neither may
                # change the measured stripped ELF, enforced by full hashes.
                link = [str(wrappers / "cc")] + LDFLAGS + ["-o", str(app), str(build / "main.o"),
                       str(build / "pkg/server.o"), str(build / "libmosdns-c.a")]
                if backend == "pcre2":
                    link.append(str(pcre_lib))
                run(link + ["-pthread"], work, prefix + "-verbose-link", extra_env={"ZIG_VERBOSE_LINK": "1"})
                if record(app) != release_record:
                    raise RuntimeError("verbose replay changed the measured ELF")
                size_dir = build / "size"
                size_dir.mkdir()
                mapped, diagnostic, link_map = (size_dir / name for name in ("mosdns-c.mapped", "mosdns-c.unstripped", "mosdns-c.map"))
                lld = PROFILE.verbose_lld_command(logs / (prefix + "-verbose-link.log"), app)
                mapped_args = lld.copy()
                mapped_args[mapped_args.index("-o") + 1] = str(mapped)
                run([str(args.zig), "ld.lld"] + mapped_args + ["-Map=" + str(link_map)], work, prefix + "-map-link")
                run([str(args.zig), "ld.lld"] + PROFILE.unstripped_lld_args(lld, diagnostic), work, prefix + "-diagnostic-link")
                attribution = analyze_size(app, diagnostic, mapped, link_map, build)
                write_json(size_dir / "attribution.json", attribution)
                identity = run(["file", str(app)], work, prefix + "-file").strip()
                elf = run(["readelf", "--file-header", "--program-headers", "--dynamic", str(app)], work, prefix + "-readelf")
                expected_machine = "Advanced Micro Devices X86-64" if target.startswith("x86_64") else "AArch64"
                if expected_machine not in elf or "INTERP" in elf or "NEEDED" in elf or "statically linked" not in identity:
                    raise RuntimeError("unexpected static target identity: " + identity)
                symbols = run(["readelf", "--wide", "--symbols", str(diagnostic)], work, prefix + "-diagnostic-symbols")
                backend_verification = PROFILE.verify_backend_link(lld, pcre_lib, symbols, backend)
                item = {"binary": {"path": str(app), **record(app)}, "file": identity,
                        "static_elf_verified": True, "backend_verification": backend_verification,
                        "size_attribution": {"report": record(size_dir / "attribution.json"), "disk_bytes": attribution["disk_bytes"],
                                             "bss_bytes": attribution["bss_bytes"], "map": record(link_map), "mapped": record(mapped),
                                             "diagnostic": record(diagnostic), "map_replay_matches_release": True},
                        "test_binaries": {name: record(build / "tests" / name) for name in TESTS + DRIVERS},
                        "execution": "not requested" if native else "not run: no matching native hardware; no emulator used"}
                result["backends"][backend] = item
                print(json.dumps({"target": target, "backend": backend, "binary": item["binary"]}), flush=True)
                if args.run_native_tests and native:
                    # Make unit selects the correct backend-specific fixture.
                    run(common + ["unit", "integration"], work, prefix + "-functional", timeout=600)
                    item["execution"] = "native unit and loopback integration passed"
                write_json(manifest_path, manifest)
            base = result["backends"]["pcre2"]["binary"]["bytes"]
            lite = result["backends"]["posix-lite"]["binary"]["bytes"]
            result["size_comparison"] = {"pcre2_bytes": base, "posix_lite_bytes": lite, "saved_bytes": base - lite,
                                         "saved_percent": round(100 * (base - lite) / base, 6), "performance_measured": False}
            # Independent multi-process PCRE2 differential runner, when present.
            differential = frozen / "c/tests/regex_differential.py"
            if args.run_native_tests and native and differential.is_file():
                run([sys.executable, str(differential), "--pcre2", str(out / target / "pcre2/tests/domain_driver"),
                     "--posix-lite", str(out / target / "posix-lite/tests/domain_driver"),
                     "--output", str(out / target / "differential.json")], work, target + "-differential", timeout=600)
                result["differential_execution"] = "passed"
                result["differential_report"] = record(out / target / "differential.json")
        if snapshot_inputs(args.root) != inputs or PROFILE.tree(frozen) != inputs:
            raise RuntimeError("application source changed during comparison; frozen results retained but not final")
        if PROFILE.tree(pcre_source) != pcre_inputs or record(archive)["sha256"] != PROFILE.PCRE2_SHA256:
            raise RuntimeError("PCRE2 inputs changed during comparison")
        manifest["source_unchanged"] = True
        manifest["status"] = "complete"
        manifest["finished_utc"] = now()
        write_json(out / "summary.json", {target: result["size_comparison"] for target, result in manifest["targets"].items()})
        print(json.dumps({"status": "complete", "manifest": str(manifest_path)}), flush=True)
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        raise
    finally:
        write_json(manifest_path, manifest)


if __name__ == "__main__":
    main()
