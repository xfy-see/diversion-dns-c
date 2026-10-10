#!/usr/bin/env python3
"""Build the pinned 8-bit, no-Unicode/no-JIT PCRE2 dependency; never download.

The output must be fresh. No archive, compiler, or configuration can reuse a
previous dependency cache. Native and static builds share configure options.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("profiles", ROOT / "benchmarks/build-c-profiles.py")
profiles = importlib.util.module_from_spec(spec)
spec.loader.exec_module(profiles)


# 供 GitHub 原生 job 使用；本地复测直接运行下载产物，不调用本构建入口。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    if not 1 <= args.jobs <= 32:
        parser.error("--jobs must be 1 through 32")
    # 先核对固定版本摘要，再解包/构建；与静态 profile 共用同一组选项。
    archive = profiles.record(args.archive)
    if archive["sha256"] != profiles.PCRE2_SHA256:
        parser.error("PCRE2 archive SHA256 differs from pinned 10.48 checksum")
    out = args.output.resolve()
    out.mkdir()  # Deliberately reject stale output rather than reuse it.
    source = profiles.extract_archive(args.archive, out / "source")
    work = out / "work"
    work.mkdir()
    logs = out / "logs"
    logs.mkdir()
    env = os.environ.copy()
    flags = profiles.OPTFLAGS.copy()
    commands = []
    # 源目录与工作目录分离，日志和最终库摘要保留在本次输出中。
    commands.append(profiles.command([str(source / "configure")] +
                    profiles.PCRE2_CONFIGURE_OPTIONS + ["CFLAGS=" + " ".join(flags)],
                    work, env, logs / "configure.log"))
    commands.append(profiles.command(["make", "-j" + str(args.jobs), "libpcre2-8.la"],
                                    work, env, logs / "build.log"))
    profiles.verify_pcre2_config((work / "src/config.h").read_text())
    (out / "include").mkdir()
    (out / "lib").mkdir()
    shutil.copyfile(work / "src/pcre2.h", out / "include/pcre2.h")
    library = out / "lib/libpcre2-8.a"
    shutil.copyfile(work / ".libs/libpcre2-8.a", library)
    licenses = out / "licenses"
    licenses.mkdir()
    for name in ("LICENCE.md", "AUTHORS.md"):
        shutil.copyfile(source / name, licenses / ("PCRE2-" + name))
    manifest = {"profile": "pcre2-8-no-unicode-no-jit", "version": "10.48",
                "archive": archive, "configure_options": profiles.PCRE2_CONFIGURE_OPTIONS,
                "compile_flags": flags, "config_header": profiles.record(work / "src/config.h"),
                "profile_verified": "8-bit only, Unicode disabled, JIT disabled",
                "commands": commands, "library": profiles.record(library),
                "licenses": {p.name: profiles.record(p) for p in sorted(licenses.iterdir())}}
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(str(out))


if __name__ == "__main__":
    main()
