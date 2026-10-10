#!/usr/bin/env python3
"""Freeze and cross-build C minimal for Linux musl; all inputs are local.

This script never downloads dependencies or runs a target binary. Supply a
release PCRE2 source archive and its independently verified SHA256 explicitly.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
from datetime import datetime, timezone


# Compile and link with LTO together; keep unwind/debug policy unchanged.
OPTFLAGS = ["-Os", "-flto", "-ffunction-sections", "-fdata-sections"]
STATIC_LDFLAGS = ["-flto", "-static", "-Wl,--gc-sections", "-Wl,-s", "-Wl,-z,stack-size=1048576"]

# One explicit dependency contract for native CI and static release profiles.
PCRE2_SHA256 = "ebcc25aadf2a51fa1fefa9b8bc9e7a79b3dae86870a0f1152a22e42befd46888"
PCRE2_CONFIGURE_OPTIONS = [
    "--disable-shared", "--enable-static", "--disable-pcre2-16",
    "--disable-pcre2-32", "--disable-jit", "--disable-unicode",
    "--disable-dependency-tracking", "--disable-pcre2grep-libz",
    "--disable-pcre2grep-libbz2",
]
# The fixed runner imports the retained protocol/mock helpers in integration.py.
# Copy support modules as well as selected runners so this tree is standalone.
STANDALONE_TEST_FILES = (
    "c/tests/domain_fixture.py", "c/tests/fixed_integration.py", "c/tests/integration.py",
    "c/tests/nft_cli_test.py", "c/plugin/nftset.c", "c/plugin/nft_fast.h", "tests/fixtures/matcher_domain.json",
)


class BuildError(RuntimeError):
    pass


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def record(path):
    if path.is_symlink() or not path.is_file():
        raise BuildError("not a regular file: " + str(path))
    data = path.read_bytes()
    return {"bytes": len(data), "sha256": digest(data)}


def tree(root):
    result = {}
    for directory, directories, names in os.walk(root, followlinks=False):
        directories[:] = sorted(d for d in directories if d != "__pycache__")
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise BuildError("source symlink directory")
        for name in sorted(names):
            if name == ".DS_Store":
                continue
            p = Path(directory) / name
            result[p.relative_to(root).as_posix()] = record(p)
    return result


# 冻结与 C 构建相关的源码和 fixture；额外记录构建/尺寸脚本，保证记录可复核。
def inputs(root):
    result = {"c/" + name: value for name, value in tree(root / "c").items()}
    for name in ("tests/fixtures/matcher_domain.json", "benchmarks/build-c-profiles.py",
                 "benchmarks/size-attribution.py"):
        result[name] = record(root / name)
    return dict(sorted(result.items()))


def write_json(path, data):
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    tmp.replace(path)


def copy_standalone_test_files(frozen, output):
    for name in STANDALONE_TEST_FILES:
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(frozen / name, path)


# 逐文件确认读取期间内容没变化，再以只读文件固定本次构建输入。
def freeze(root, destination, expected):
    destination.mkdir()
    for name, item in expected.items():
        data = (root / name).read_bytes()
        if {"bytes": len(data), "sha256": digest(data)} != item:
            raise BuildError("input changed while freezing: " + name)
        p = destination / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(0o444)
    if tree(destination) != expected:
        raise BuildError("source snapshot mismatch")


# 依赖包只接受普通文件/目录，不接受可逃逸的路径和链接。
def extract_archive(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            name = Path(member.name)
            if name.is_absolute() or ".." in name.parts or not (member.isdir() or member.isfile()):
                raise BuildError("unsafe source archive entry: " + member.name)
        tar.extractall(destination, members=members)
    roots = list(destination.iterdir())
    if len(roots) != 1 or not roots[0].is_dir():
        raise BuildError("PCRE2 archive must contain one source directory")
    return roots[0]


def command(command, cwd, env, log):
    start = utc_now()
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, errors="replace")
    # No account/proxy environment is logged; redact any URL userinfo in tool diagnostics.
    output = re.sub(r"(https?://)[^/\s@]+@", r"\1<redacted>@", result.stdout)
    log.write_text(output)
    value = {"command": [str(v) for v in command], "cwd": str(cwd),
             "started_at": start, "finished_at": utc_now(),
             "exit_code": result.returncode, "log": str(log)}
    if result.returncode:
        error = BuildError("command failed, see " + str(log))
        error.command_record = value
        raise error
    return value


def verbose_lld_command(log, output):
    """Recover Zig's exact LLD inputs; zig cc does not accept -Wl,-Map."""
    matches = []
    for line in log.read_text().splitlines():
        try:
            parts = shlex.split(line)
        except ValueError:
            continue
        for index, part in enumerate(parts):
            if part == "ld.lld" or part.endswith("/ld.lld"):
                matches.append(parts[index + 1:])
                break
    expected = str(output)
    matches = [args for args in matches if "-o" in args
               and args.index("-o") + 1 < len(args)
               and args[args.index("-o") + 1] == expected]
    if len(matches) != 1:
        raise BuildError("expected one verbose ld.lld command for " + expected + " in " + str(log))
    return matches[0]


def unstripped_lld_args(release_args, output):
    """Keep release CRT/libc/compiler-rt inputs; only retain symbol sections."""
    if "-s" not in release_args or "-o" not in release_args:
        raise BuildError("expected stripped release LLD command")
    args = [arg for arg in release_args if arg != "-s"]
    args[args.index("-o") + 1] = str(output)
    return args


def verify_pcre2_config(config):
    """Validate the configured dependency, including when LTO hides provenance."""
    if not re.search(r"^#define SUPPORT_PCRE2_8\b", config, re.M):
        raise BuildError("PCRE2 8-bit support was not enabled")
    for feature in ("SUPPORT_JIT", "SUPPORT_UNICODE", "SUPPORT_PCRE2_16", "SUPPORT_PCRE2_32"):
        if re.search(r"^#define " + feature + r"\b", config, re.M):
            raise BuildError("unexpected PCRE2 feature: " + feature)


def verify_backend_link(lld_args, pcre_lib, symbols, backend):
    """Check exact dependency inputs and final symbols, never LLVM bitcode via readelf."""
    if backend not in ("pcre2", "posix-lite"):
        raise BuildError("unknown regex backend")
    pcre_inputs = [arg for arg in lld_args if "pcre2" in Path(arg).name]
    expected = [str(pcre_lib)] if backend == "pcre2" else []
    if pcre_inputs != expected:
        raise BuildError("unexpected PCRE2 link inputs: " + repr(pcre_inputs))
    if any("libyaml" in Path(arg).name for arg in lld_args):
        raise BuildError("unexpected libyaml link input")
    names = set(re.findall(r"\b(_?pcre2_[A-Za-z0-9_]+)\b", symbols))
    if backend == "pcre2":
        # LTO may inline public entry points, including pcre2_match_8.
        # Require retained PCRE2 symbols plus the exact verified archive input;
        # executable domain tests establish compile/match behavior separately.
        if not names:
            raise BuildError("PCRE2 implementation absent from diagnostic ELF")
    elif names:
        raise BuildError("posix-lite diagnostic ELF unexpectedly contains PCRE2")
    return {"backend": backend, "pcre2_link_inputs": pcre_inputs,
            "pcre2_symbols_in_diagnostic": bool(names), "retained_pcre2_symbols": sorted(names),
            "method": "Exact release LLD inputs and unstripped replay symbols; valid for LTO objects"}


# GitHub 静态交叉构建入口；创建新目录并保存成功/失败记录，不运行目标程序。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True, help="fresh output directory")
    parser.add_argument("--zig", type=Path, required=True)
    parser.add_argument("--target", choices=["aarch64-linux-musl", "x86_64-linux-musl"], default="aarch64-linux-musl")
    parser.add_argument("--pcre2-archive", type=Path, required=True)
    parser.add_argument("--pcre2-sha256", required=True)
    parser.add_argument("--pcre2-origin", required=True)
    parser.add_argument("--pcre2-release-metadata", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    args.root = args.root.resolve()
    args.output = args.output.resolve()
    args.zig = args.zig.resolve()
    if args.jobs < 1 or args.jobs > 32:
        parser.error("--jobs must be 1 through 32")
    archive_record = record(args.pcre2_archive)
    if args.pcre2_sha256 != PCRE2_SHA256 or archive_record["sha256"] != PCRE2_SHA256:
        parser.error("PCRE2 archive SHA256 differs from pinned 10.48 checksum")
    args.output.mkdir(mode=0o700)
    out = args.output
    manifest = {"schema_version": 1, "status": "building", "created_utc": utc_now(),
                "target": args.target, "source_root": str(args.root), "commands": [],
                "scope": "Linked static C minimal and test harnesses; target execution is separate evidence."}
    try:
        expected = inputs(args.root)
        manifest["inputs"] = expected
        manifest["input_tree_sha256"] = digest(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode())
        frozen = out / "source"
        freeze(args.root, frozen, expected)
        deps = out / "deps"
        deps.mkdir()
        frozen_archive = deps / args.pcre2_archive.name
        shutil.copyfile(args.pcre2_archive, frozen_archive)
        frozen_archive.chmod(0o444)
        manifest["pcre2"] = {"origin": args.pcre2_origin, "archive": str(frozen_archive), **archive_record,
                              "checksum_validation": "matched explicit expected SHA256", "signature_verified": False}
        if args.pcre2_release_metadata:
            metadata = json.loads(args.pcre2_release_metadata.read_text())
            matched = [v for v in metadata.get("assets", []) if v.get("name") == args.pcre2_archive.name
                       and v.get("digest") == "sha256:" + args.pcre2_sha256
                       and v.get("browser_download_url") == args.pcre2_origin]
            if len(matched) != 1:
                raise BuildError("release metadata does not match archive checksum and origin")
            shutil.copyfile(args.pcre2_release_metadata, deps / "release-metadata.json")
            manifest["pcre2"]["release_metadata"] = record(deps / "release-metadata.json")
            manifest["pcre2"]["checksum_validation"] += "; matched official release API asset digest"
        pcre_source = extract_archive(frozen_archive, deps / "source")
        licenses = out / "licenses"
        licenses.mkdir()
        for name in ("LICENCE.md", "AUTHORS.md"):
            shutil.copyfile(pcre_source / name, licenses / ("PCRE2-" + name))
        manifest["licenses"] = {p.name: record(p) for p in sorted(licenses.iterdir())}
        pcre_inputs = tree(pcre_source)
        manifest["pcre2"]["inputs"] = pcre_inputs
        for p in pcre_source.rglob("*"):
            if p.is_file():
                p.chmod(0o555 if p.stat().st_mode & stat.S_IXUSR else 0o444)
        work = out / "work"
        work.mkdir()
        logs = out / "logs"
        logs.mkdir()
        env = os.environ.copy()
        # 缓存限于本轮 work 目录，清理构建产物时无需触碰其他项目缓存。
        env["ZIG_GLOBAL_CACHE_DIR"] = str(work / "zig-global-cache")
        env["ZIG_LOCAL_CACHE_DIR"] = str(work / "zig-local-cache")
        wrappers = work / "tools"
        wrappers.mkdir()
        for name, suffix in (("cc", ["cc", "-target", args.target]), ("ar", ["ar"]), ("ranlib", ["ranlib"])):
            wrapper = wrappers / name
            wrapper.write_text("#!/bin/sh\nexec " + " ".join(shlex.quote(str(v)) for v in [args.zig] + suffix) + ' "$@"\n')
            wrapper.chmod(0o755)
        flags = OPTFLAGS.copy()
        manifest["build"] = {"compiler": {"path": str(args.zig), **record(args.zig)},
                              "flags": flags + ["-UNDEBUG", "-std=c11", "-pthread"] + STATIC_LDFLAGS,
                              "compile_flags": flags, "link_flags": STATIC_LDFLAGS,
                              "pcre2_options": ["8-bit", "Unicode disabled", "JIT disabled", "static"],
                              "application_workers": "runtime --cpu; planned tests use --cpu 2",
                              "stack_size_reason": "1 MiB ELF default thread stack: regression mock threads hold two 65 KiB DNS packets; musl default stack may be too small."}
        version = subprocess.run([str(args.zig), "version"], capture_output=True, text=True, check=True)
        manifest["build"]["compiler"]["version"] = version.stdout.strip()
        write_json(out / "manifest.json", manifest)
        pcre_build = work / "pcre2-8-no-unicode-no-jit"
        pcre_build.mkdir()
        configure = [str(pcre_source / "configure"), "--host=" + args.target] + PCRE2_CONFIGURE_OPTIONS + [
                     "CC=" + str(wrappers / "cc"), "AR=" + str(wrappers / "ar"), "RANLIB=" + str(wrappers / "ranlib"),
                     "CFLAGS=" + " ".join(flags)]
        manifest["commands"].append(command(configure, pcre_build, env, logs / "pcre2-configure.log"))
        manifest["commands"].append(command(["make", "-j" + str(args.jobs), "libpcre2-8.la"], pcre_build, env, logs / "pcre2-build.log"))
        verify_pcre2_config((pcre_build / "src/config.h").read_text())
        manifest["pcre2"]["config_header"] = record(pcre_build / "src/config.h")
        manifest["pcre2"]["profile_verified"] = "8-bit only, Unicode disabled, JIT disabled"
        pcre_lib = pcre_build / ".libs/libpcre2-8.a"
        manifest["pcre2"]["static_library"] = {"path": str(pcre_lib), **record(pcre_lib)}
        c_root = frozen / "c"
        cpp = ["-I" + str(c_root / "include"),
               "-I" + str(pcre_build / "src"), "-I" + str(pcre_source / "src"), "-D_POSIX_C_SOURCE=200809L", "-D_DEFAULT_SOURCE"]
        # Zig's optimized C mode defines NDEBUG. Assertions in the harnesses
        # also perform required calls, so explicitly keep them enabled.
        cflags = flags + ["-UNDEBUG", "-std=c11", "-Wall", "-Wextra", "-Wpedantic", "-Werror", "-pthread"]
        libsrc = ["coremain/engine.c", "pkg/dns.c", "pkg/upstream.c", "pkg/domain.c", "pkg/util.c", "plugin/cache.c", "plugin/nftset.c"]
        sources = libsrc + ["main.c", "pkg/server.c"]
        objects = {}

        def compile_source(name):
            obj = work / "objects" / (name + ".o")
            obj.parent.mkdir(parents=True, exist_ok=True)
            cmd = [str(args.zig), "cc", "-target", args.target] + cpp + cflags + ["-c", str(c_root / name), "-o", str(obj)]
            return name, obj, command(cmd, work, env, logs / ("compile-" + name.replace("/", "_") + ".log"))

        # 每个源文件写独立对象和日志，可并行编译；链接等待全部对象完成。
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            for name, obj, item in pool.map(compile_source, sources):
                objects[name] = obj
                manifest["commands"].append(item)
        lib = work / "libmosdns-c.a"
        manifest["commands"].append(command([str(args.zig), "ar", "rcs", str(lib)] + [str(objects[v]) for v in libsrc], work, env, logs / "archive.log"))
        ldflags = STATIC_LDFLAGS.copy()
        app = out / "mosdns-c"
        verbose_env = env.copy()
        verbose_env["ZIG_VERBOSE_LINK"] = "1"
        normal_link_log = logs / "link-app.log"
        manifest["commands"].append(command([str(args.zig), "cc", "-target", args.target] + ldflags + ["-o", str(app), str(objects["main.c"]), str(objects["pkg/server.c"]), str(lib), str(pcre_lib), "-pthread"], work, verbose_env, normal_link_log))
        manifest["binary"] = {"path": str(app), **record(app), "stripped": True, "static": True}
        # Keep the published link flags unchanged. Zig cc rejects -Wl,-Map, so
        # replay its exact verbose LLD command with a map and verify that the
        # resulting stripped ELF has the same full SHA256 as the published ELF.
        size_dir = out / "size"
        size_dir.mkdir()
        diagnostic = size_dir / "mosdns-c.unstripped"
        mapped = size_dir / "mosdns-c.mapped"
        link_map = size_dir / "mosdns-c.map"
        size_json = size_dir / "attribution.json"
        lld_args = verbose_lld_command(normal_link_log, app)
        lld_args[lld_args.index("-o") + 1] = str(mapped)
        manifest["commands"].append(command([str(args.zig), "ld.lld"] + lld_args
                                            + ["-Map=" + str(link_map)], work, env,
                                            logs / "link-app-map.log"))
        if record(mapped) != {k: manifest["binary"][k] for k in ("bytes", "sha256")}:
            raise BuildError("map-linked stripped ELF differs from published program")
        # Reuse the release's exact CRT/libc/compiler-rt inputs. A second zig cc
        # invocation without -s can select different cached runtime objects and
        # change allocated section shapes (observed on x86_64 without Unicode).
        # Only remove LLD's strip flag; retain all strict layout/hash checks.
        diagnostic_args = unstripped_lld_args(lld_args, diagnostic)
        manifest["commands"].append(command([str(args.zig), "ld.lld"] + diagnostic_args,
                                            work, env, logs / "link-app-diagnostic.log"))
        symbol_log = logs / "diagnostic-symbols.log"
        manifest["commands"].append(command(["readelf", "--wide", "--symbols", str(diagnostic)],
                                            work, env, symbol_log))
        manifest["backend_verification"] = verify_backend_link(lld_args, pcre_lib, symbol_log.read_text(), "pcre2")
        manifest["commands"].append(command(["python3", str(frozen / "benchmarks/size-attribution.py"),
                                             "--release", str(app), "--diagnostic", str(diagnostic),
                                             "--mapped", str(mapped), "--map", str(link_map),
                                             "--output", str(size_json)],
                                            work, env, logs / "size-attribution.log"))
        size_result = json.loads(size_json.read_text())
        if size_result["disk_bytes"]["libyaml"] != 0 or size_result["bss_bytes"]["libyaml"] != 0:
            raise BuildError("specialized binary unexpectedly retains libyaml sections")
        size_result["versions"] = {"zig": manifest["build"]["compiler"]["version"],
                                   "pcre2": "10.48",
                                   "musl": "bundled with the pinned Zig distribution; upstream version not recorded"}
        size_result["historical_source_only"] = {"libyaml": "0.2.5; retained source/license, not built or linked"}
        size_result["explicit_link_inputs"] = {
            "main.c.o": record(objects["main.c"]), "pkg/server.c.o": record(objects["pkg/server.c"]),
            "libmosdns-c.a": record(lib), "libpcre2-8.a": record(pcre_lib)}
        write_json(size_json, size_result)
        manifest["size_attribution"] = {"map_replay_matches_release": True,
                                        "diagnostic": record(diagnostic), "mapped": record(mapped),
                                        "map": record(link_map),
                                        "report": record(size_json)}
        testdir = out / "tests"
        testdir.mkdir()
        manifest["test_binaries"] = {}
        names = ["dns_test", "cache_domain_test", "fixed_config_test", "fixed_engine_test",
                 "domain_driver", "nft_netlink_test"]
        for name in names:
            binary = testdir / name
            cmd = [str(args.zig), "cc", "-target", args.target] + cpp + cflags + ldflags + [str(c_root / ("tests/" + name + ".c")), str(lib), str(pcre_lib), "-pthread", "-o", str(binary)]
            manifest["commands"].append(command(cmd, work, env, logs / ("link-" + name + ".log")))
            manifest["test_binaries"][name] = {"path": str(binary), **record(binary)}
        driver = testdir / "nft_cli_driver"
        cmd = [str(args.zig), "cc", "-target", args.target] + cpp + cflags + ldflags + [str(c_root / "tests/nft_cli_driver.c"), str(c_root / "pkg/dns.c"), "-pthread", "-o", str(driver)]
        manifest["commands"].append(command(cmd, work, env, logs / "link-nft-cli-driver.log"))
        manifest["test_binaries"]["nft_cli_driver"] = {"path": str(driver), **record(driver)}
        copy_standalone_test_files(frozen, out)
        # file 只识别文件格式，目标机执行和网络/性能测试必须另行记录。
        for artifact in [app] + list(testdir.iterdir()):
            file_result = subprocess.run(["file", str(artifact)], capture_output=True, text=True, check=True)
            manifest.setdefault("file_identification", {})[artifact.relative_to(out).as_posix()] = file_result.stdout.strip()
        if inputs(args.root) != expected or tree(frozen) != expected:
            raise BuildError("application source changed during build")
        if tree(pcre_source) != pcre_inputs or record(frozen_archive) != archive_record:
            raise BuildError("PCRE2 source changed during build")
        manifest["source_unchanged"] = True
        manifest["status"] = "complete"
        manifest["finished_utc"] = utc_now()
        print(json.dumps({"status": manifest["status"], "binary": manifest["binary"], "tests": list(manifest["test_binaries"])}))
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = str(error)
        if hasattr(error, "command_record"):
            manifest["commands"].append(error.command_record)
        raise
    # 即使构建中途失败，也保留 manifest 和失败命令，便于追溯具体输入与步骤。
    finally:
        write_json(out / "manifest.json", manifest)


if __name__ == "__main__":
    main()
