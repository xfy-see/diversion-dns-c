#!/usr/bin/env python3
"""One-version, main-only release. Verify exact CI bytes; never overwrite a tag.

This script is run only by the main push job using its ephemeral Actions token.
No build, router operation, package installation, or credential creation occurs.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import time
import zipfile

import artifacts as a

ROOT = Path(__file__).resolve().parents[1]
TAG = "v0.1.0"
VERSION = "0.1.0"
REPO = "xfy-see/diversion-dns-c"
ARCHES = ("aarch64_cortex-a53", "mipsel_24kc")
BUILD_JOBS = ["Native / macos-arm64", "Native / linux-amd64", "Static / linux-amd64", "Static / linux-arm64"]


def run(argv, **kwargs):
    return subprocess.run(list(map(str, argv)), check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, **kwargs).stdout


def api(path):
    return json.loads(run(["gh", "api", f"repos/{REPO}/{path}"]))


def absent(path):
    result = subprocess.run(["gh", "api", f"repos/{REPO}/{path}"], capture_output=True)
    if result.returncode == 0:
        return False
    a.require(b"(HTTP 404)" in result.stderr, "GitHub read failed; absence is unconfirmed")
    return True


def existing_release():
    """Only a fully uploaded stable release is a safe no-op; partial state fails."""
    rows = []
    for page in range(1, 21):
        chunk = api(f"releases?per_page=100&page={page}")
        rows.extend(row for row in chunk if row["tag_name"] == TAG)
        if len(chunk) < 100:
            break
    else:
        raise ValueError("release enumeration exceeded bound; absence unconfirmed")
    tag_missing = absent(f"git/ref/tags/{TAG}")
    if tag_missing and not rows:
        return None
    a.require(not tag_missing and len(rows) == 1,
              "partial/conflicting v0.1.0 tag/release exists; review without overwriting")
    release = rows[0]
    a.require(not release["draft"] and not release["prerelease"] and release["published_at"],
              "v0.1.0 draft or prerelease exists; review without overwriting")
    tag = api(f"git/ref/tags/{TAG}")
    a.require(tag["object"]["type"] == "commit" and release["target_commitish"] == tag["object"]["sha"],
              "existing release/tag identity conflict")
    assets = api(f"releases/{release['id']}/assets?per_page=100")
    expected = {"SHA256SUMS", "RELEASE-NOTES.md", "release-verification.json"}
    for arch in ARCHES:
        expected.update({f"diversion-dns-c-lite-0.1.0-r1_{arch}.apk", f"buildinfo-{arch}.json",
                         f"verification-{arch}-{TAG}.tar.gz"})
    for backend in ("pcre2", "posix-lite"):
        for kind, target in (("native", "linux-amd64"), ("native", "macos-arm64"),
                             ("static", "linux-amd64"), ("static", "linux-arm64")):
            expected.add(f"{backend}-{kind}-{target}-{TAG}.tar.gz")
    a.require(len(assets) == len(expected) and {r["name"] for r in assets} == expected
              and all(r["state"] == "uploaded" and r["size"] > 0
                      and re.fullmatch(r"sha256:[0-9a-f]{64}", r.get("digest", "")) for r in assets),
              "existing release assets incomplete; review without overwriting")
    by_name = {row["name"]: row for row in assets}
    def read_asset(name):
        row = by_name[name]
        data = run(["gh", "api", f"repos/{REPO}/releases/assets/{row['id']}",
                    "-H", "Accept: application/octet-stream"])
        a.require(len(data) == row["size"] and "sha256:" + a.digest(data) == row["digest"],
                  "existing release metadata download differs")
        return data
    sums = {}
    for line in read_asset("SHA256SUMS").decode().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([^/]+)", line)
        a.require(match and match[2] not in sums, "existing release checksums malformed")
        sums[match[2]] = "sha256:" + match[1]
    a.require(sums == {name: row["digest"] for name, row in by_name.items() if name != "SHA256SUMS"},
              "existing release checksums disagree with uploaded assets")
    verification = json.loads(read_asset("release-verification.json"))
    a.require(verification["release"] == TAG and verification["commit"] == tag["object"]["sha"]
              and len(verification["jobs"]) == 6 and all(j["conclusion"] == "success" for j in verification["jobs"]),
              "existing release verification identity differs")
    return release


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def checked_jobs(run_id, expected):
    jobs = api(f"actions/runs/{run_id}/jobs?filter=latest&per_page=100")
    rows = [row for row in jobs["jobs"] if row["name"] in expected]
    a.require(jobs["total_count"] <= 100 and len(rows) == len(expected)
              and {row["name"] for row in rows} == set(expected)
              and all(row["status"] == "completed" and row["conclusion"] == "success" for row in rows),
              "required exact-commit build/test jobs are not all successful")
    return [{key: row[key] for key in ("id", "name", "html_url", "conclusion")} for row in rows]


def fetch_artifacts(run_id, attempt, commit, directory, expected):
    data = api(f"actions/runs/{run_id}/artifacts?per_page=100")
    a.require(data["total_count"] <= 100, "artifact pagination required")
    selected = [row for row in data["artifacts"] if row["name"] in expected]
    a.require(len(selected) == len(expected) and {r["name"] for r in selected} == set(expected),
              "exact artifact set missing")
    receipts = []
    for row in selected:
        a.require(not row["expired"] and re.fullmatch(r"sha256:[0-9a-f]{64}", row.get("digest", "")),
                  "artifact expired or digest unavailable")
        a.require(row["workflow_run"]["id"] == run_id and row["workflow_run"]["head_sha"] == commit,
                  "artifact run/source differs")
        archive = directory / (str(row["id"]) + ".zip")
        with archive.open("xb") as stream:
            subprocess.run(["gh", "api", f"repos/{REPO}/actions/artifacts/{row['id']}/zip"],
                           check=True, stdout=stream, stderr=subprocess.PIPE)
        a.require(archive.stat().st_size == row["size_in_bytes"]
                  and a.digest(archive.read_bytes()) == row["digest"].split(":", 1)[1], "Actions ZIP digest differs")
        destination = directory / row["name"]
        destination.mkdir()
        with zipfile.ZipFile(archive) as zipped:
            seen = set()
            total = 0
            for item in zipped.infolist():
                name = item.filename.rstrip("/")
                a.safe_path(name)
                mode = (item.external_attr >> 16) & 0xffff
                a.require(name not in seen and not stat.S_ISLNK(mode), "unsafe or duplicate ZIP entry")
                seen.add(name)
                total += item.file_size
                a.require(len(seen) <= 3000 and total <= a.LIMIT and item.file_size <= 64 * 1024 * 1024, "ZIP exceeds bound")
                target = destination / name
                if item.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(zipped.read(item))
        receipts.append({key: row[key] for key in ("id", "name", "size_in_bytes", "digest")})
    return receipts


def recheck_apk(folder, info, arch, work):
    """Independently read the downloaded APK with tools from the pinned SDK."""
    builder = load("build-openwrt-apk")
    target = builder.TARGETS[arch]
    directory = work / arch
    directory.mkdir()
    archive = directory / "sdk.tar.zst"
    run(["curl", "--fail", "--location", "--retry", "3", target["sdk_url"], "-o", archive])
    a.require(builder.digest(archive) == target["sdk_sha256"], "independent SDK download mismatch")
    run(["tar", "--zstd", "-xf", archive, "-C", directory])
    sdk = directory / target["sdk_filename"].removesuffix(".tar.zst")
    builder.no_signing_keys(sdk)
    apktool = sdk / "staging_dir/host/bin/apk"
    toolchain, = (sdk / "staging_dir").glob("toolchain-*")
    apk = folder / info["apk"]["filename"]
    metadata = json.loads(run([apktool, "adbdump", "--format", "json", apk]))
    a.require(metadata == json.loads((folder / "apk-metadata.json").read_text()), "downloaded APK metadata differs")
    payload = builder.package_files(metadata, arch)
    a.require(metadata["info"]["version"] == VERSION + "-r1", "downloaded APK version differs")
    empty = directory / "empty-trust"
    empty.mkdir()
    result = subprocess.run(list(map(str, [apktool, "verify", "--keys-dir", empty, "--no-network", apk])), capture_output=True)
    a.require(result.returncode != 0 and b"UNTRUSTED" in (result.stdout + result.stderr).upper(),
              "unsigned APK trust rejection differs")
    run([apktool, "verify", "--allow-untrusted", "--keys-dir", empty, "--no-network", apk])
    extracted = directory / "extracted"
    extracted.mkdir()
    run([apktool, "extract", "--allow-untrusted", "--keys-dir", empty, "--no-network", "--no-chown", "--destination", extracted, apk])
    a.require(not any(p.is_symlink() for p in extracted.rglob("*")), "APK payload has symlink")
    actual = {p.relative_to(extracted).as_posix(): builder.record(p) for p in extracted.rglob("*") if p.is_file()}
    a.require(actual == payload, "downloaded APK payload differs")
    binary = extracted / "usr/sbin/diversion-dns-c-lite"
    elf = load("check-openwrt-elf").check(binary, toolchain, arch)
    a.require(elf == info["elf"], "downloaded APK ELF/runtime differs")
    version = run([target["qemu"], "-L", toolchain, binary, "version"]).decode().strip()
    a.require(version == "mosdns-c 0.1.0 fixed-splitter", "downloaded APK CLI version differs")
    wrapper = directory / "packaged-app"
    import shlex
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join([target["qemu"], "-L", str(toolchain), str(binary)]) + ' "$@"\n')
    wrapper.chmod(0o755)
    integration = subprocess.run(["python3", str(ROOT / "c/tests/fixed_integration.py"), str(wrapper)],
                                 check=True, capture_output=True, timeout=300)
    integration_log = integration.stdout + integration.stderr
    a.require(b"Ran 12 tests" in integration_log and b"OK" in integration_log,
              "independent APK integration corpus missing")
    (directory / "independent-integration.log").write_bytes(integration_log)
    a.require(builder.digest(apk) == info["apk"]["sha256"], "APK changed during independent recheck")
    return {"architecture": arch, "metadata_and_payload": "passed", "elf": elf,
            "cli_version": version, "loopback_integration": "12 tests passed", "loopback_log": integration_log.decode(), "compilers_invoked": False,
            "runtime_scope": "official SDK libc under QEMU, not a user's device", "apk": info["apk"]}


def verify_bundle(folder, commit, run_id, attempt, backend):
    archive = folder / "bundle.tar.gz"
    manifest, contents = a.read_archive(archive, commit, run_id)
    a.source_matches(ROOT, manifest)
    a.require(manifest["run_attempt"] == attempt and manifest.get("application_version") == VERSION,
              "bundle attempt/application version differs")
    a.require(all(a.regex_backend(p) == backend for p in manifest["profiles"].values()), "bundle backend differs")
    log = "lite-ci-validation" if backend == "posix-lite" else "ci-validation"
    result = json.loads(contents[f"ci-logs/{log}/result.json"])
    a.require(result["completed"] and result["commit"] == commit and result["run_id"] == run_id
              and result["target"] == manifest["target"] and not result["compilers_invoked"]
              and result["commands"] and all(c["exit_code"] == 0 for c in result["commands"]), "bundle tests incomplete")
    for label, profile in manifest["profiles"].items():
        a.require(b"mosdns-c 0.1.0 fixed-splitter" in contents[profile["application"]], "bundle CLI version stamp differs")
    return manifest


def main():
    commit = os.environ["GITHUB_SHA"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    a.require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == "refs/heads/main"
              and os.environ.get("GITHUB_EVENT_NAME") == "push", "only this repository's main push may release")
    a.require(run(["git", "rev-parse", "HEAD"]).decode().strip() == commit
              and (ROOT / "VERSION").read_text().strip() == VERSION, "release checkout/version differs")
    prior = existing_release()
    if prior:
        print("Complete stable v0.1.0 already exists; no changes: " + prior["html_url"])
        return
    a.require(api("git/ref/heads/main")["object"]["sha"] == commit, "main moved; do not publish stale commit")
    own = api(f"actions/runs/{run_id}")
    a.require(own["head_sha"] == commit and own["head_branch"] == "main" and own["event"] == "push"
              and own["run_attempt"] == attempt and own["path"] == ".github/workflows/build.yml", "build run identity differs")
    build_jobs = checked_jobs(run_id, BUILD_JOBS)
    deadline = time.monotonic() + 35 * 60
    while True:
        candidates = api(f"actions/workflows/openwrt-apk.yml/runs?head_sha={commit}&event=push&per_page=100")
        rows = [r for r in candidates["workflow_runs"] if r["head_sha"] == commit and r["head_branch"] == "main" and r["event"] == "push"]
        a.require(len(rows) <= 1, "multiple main APK runs need human review")
        if rows and rows[0]["status"] == "completed":
            apk_run = rows[0]
            a.require(apk_run["conclusion"] == "success", "APK workflow failed; do not publish")
            break
        a.require(time.monotonic() < deadline, "APK workflow did not complete within its build window")
        time.sleep(20)
    apk_id, apk_attempt = apk_run["id"], apk_run["run_attempt"]
    apk_jobs = checked_jobs(apk_id, [f"APK / {arch}" for arch in ARCHES])
    work = ROOT / ".build/release-v0.1.0"
    a.require(not work.exists(), "release work directory must be fresh")
    inputs = work / "inputs"
    output = work / "assets"
    inputs.mkdir(parents=True)
    output.mkdir()
    build_names = {}
    for kind, target in (("native", "linux-amd64"), ("native", "macos-arm64"), ("static", "linux-amd64"), ("static", "linux-arm64")):
        for prefix, backend in (("diversion", "pcre2"), ("experimental-lite", "posix-lite")):
            build_names[f"{prefix}-{kind}-{target}-{commit}-attempt-{attempt}"] = (kind, target, backend)
    apk_names = {f"experimental-openwrt-apk-{arch}-{commit}-attempt-{apk_attempt}": arch for arch in ARCHES}
    receipts = fetch_artifacts(run_id, attempt, commit, inputs, build_names)
    receipts += fetch_artifacts(apk_id, apk_attempt, commit, inputs, apk_names)
    for name, (kind, target, backend) in build_names.items():
        manifest = verify_bundle(inputs / name, commit, run_id, attempt, backend)
        a.require((manifest["kind"], manifest["target"]) == (kind, target), "bundle architecture differs")
        shutil.copyfile(inputs / name / "bundle.tar.gz", output / f"{backend}-{kind}-{target}-{TAG}.tar.gz")
    reports = []
    for name, arch in apk_names.items():
        folder = inputs / name
        info = load("verify-release-inputs").verify_apk(folder, commit, apk_id, apk_attempt, arch, ROOT)
        reports.append(recheck_apk(folder, info, arch, work))
        shutil.copyfile(folder / info["apk"]["filename"], output / f"diversion-dns-c-lite-0.1.0-r1_{arch}.apk")
        shutil.copyfile(folder / "buildinfo.json", output / f"buildinfo-{arch}.json")
        # Retain original matrix evidence and its own checksums without editing paths/logs.
        with tarfile.open(output / f"verification-{arch}-{TAG}.tar.gz", "w:gz") as archive:
            for path in sorted(folder.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(folder).as_posix(), recursive=False)
    report = {"release": TAG, "commit": commit, "source_tree": run(["git", "rev-parse", "HEAD^{tree}"]).decode().strip(),
              "build_run_id": run_id, "build_run_attempt": attempt, "apk_run_id": apk_id, "apk_run_attempt": apk_attempt,
              "jobs": build_jobs + apk_jobs, "actions_artifacts": receipts, "independent_download_checks": reports,
              "unsigned_apk": True, "hardware_acceptance": False}
    (output / "release-verification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    shutil.copyfile(ROOT / "docs/release-v0.1.0.md", output / "RELEASE-NOTES.md")
    assets = sorted(output.iterdir())
    (output / "SHA256SUMS").write_text("".join(f"{a.digest(p.read_bytes())}  {p.name}\n" for p in assets))
    assets = sorted(output.iterdir())
    # Re-read everything immediately before the only external mutation.
    a.require(api("git/ref/heads/main")["object"]["sha"] == commit, "main moved before publication")
    a.require(existing_release() is None, "v0.1.0 appeared; never overwrite it")
    checked_jobs(apk_id, [f"APK / {arch}" for arch in ARCHES])
    a.require(api(f"actions/runs/{apk_id}")["run_attempt"] == apk_attempt
              and api(f"actions/runs/{run_id}")["run_attempt"] == attempt, "run attempt changed")
    notes = (ROOT / "docs/release-v0.1.0.md").read_text() + f"\n\n发布提交：{commit}\n\nCI：{own['html_url']} · {apk_run['html_url']}\n"
    publish_assets(assets, commit, notes, run_id, attempt, apk_id, apk_attempt)


def publish_assets(assets, commit, notes, run_id, attempt, apk_id, apk_attempt):
    # Creating refs never force-updates an existing tag. A partial failure leaves a draft for review.
    run(["gh", "api", f"repos/{REPO}/git/refs", "--method", "POST", "--input", "-"],
        input=json.dumps({"ref": "refs/tags/" + TAG, "sha": commit}).encode())
    release = json.loads(run(["gh", "api", f"repos/{REPO}/releases", "--method", "POST", "--input", "-"],
                             input=json.dumps({"tag_name": TAG, "target_commitish": commit, "name": TAG,
                                               "body": notes, "draft": True, "prerelease": False}).encode()))
    run(["gh", "release", "upload", TAG, *assets, "--repo", REPO])
    uploaded = api(f"releases/{release['id']}/assets?per_page=100")
    expected = {p.name: (p.stat().st_size, "sha256:" + a.digest(p.read_bytes())) for p in assets}
    a.require(len(uploaded) == len(expected) and {r["name"]: (r["size"], r["digest"]) for r in uploaded} == expected,
              "uploaded release assets differ; leave draft unpublished")
    a.require(api(f"git/ref/tags/{TAG}")["object"]["sha"] == commit
              and api("git/ref/heads/main")["object"]["sha"] == commit, "tag/main differs before publication")
    final_build, final_apk = api(f"actions/runs/{run_id}"), api(f"actions/runs/{apk_id}")
    a.require(final_build["head_sha"] == final_apk["head_sha"] == commit
              and final_build["run_attempt"] == attempt and final_apk["run_attempt"] == apk_attempt
              and final_apk["status"] == "completed" and final_apk["conclusion"] == "success",
              "CI run or attempt changed during upload; leave draft unpublished")
    checked_jobs(run_id, BUILD_JOBS)
    checked_jobs(apk_id, [f"APK / {arch}" for arch in ARCHES])
    published = json.loads(run(["gh", "api", f"repos/{REPO}/releases/{release['id']}", "--method", "PATCH", "--input", "-"],
                              input=json.dumps({"draft": False, "prerelease": False, "make_latest": "true"}).encode()))
    a.require(not published["draft"] and not published["prerelease"], "stable publication not confirmed")
    print(published["html_url"])


if __name__ == "__main__":
    main()
