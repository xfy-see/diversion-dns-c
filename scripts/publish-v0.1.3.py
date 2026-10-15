#!/usr/bin/env python3
"""One-version, main-only v0.1.3 release. Verify exact CI bytes; never overwrite a tag.

Preserves the archived publishers and their fail-closed artifact checks.
Adds exact-commit kernel, delivery and automation-suite gates plus a separate
source-bound recovery overlay; APK contents and installation behavior stay unchanged.
This script is run only by the main push job using its ephemeral Actions token.
No build, router operation, package installation, or credential creation occurs.
"""
import gzip
import hashlib
import io
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
VERSION = "0.1.3"
TAG = "v" + VERSION
PACKAGE_VERSION = VERSION + "-r1"
CLI_VERSION = f"mosdns-c {VERSION} fixed-splitter"
NOTES = Path("docs") / f"release-{TAG}.md"
WORK = Path(".build") / f"release-{TAG}"
REPO = "xfy-see/diversion-dns-c"
ARCHES = ("aarch64_cortex-a53", "mipsel_24kc")
BUILD_JOBS = ["Native / macos-arm64", "Native / linux-amd64", "Static / linux-amd64", "Static / linux-arm64",
              "Real kernel / GCC 14", "delivery"]
SUITE_JOBS = ["python", "helpers"]
APK_JOBS = [f"APK / {arch}" for arch in ARCHES]
OVERLAY_NAME = f"openwrt-recovery-{TAG}.tar.gz"
OVERLAY_PREFIX = "deployment/openwrt-recovery/"
OVERLAY_FILES = {"LICENSE": 0o644, **{OVERLAY_PREFIX + name: mode for name, mode in (
    ("README.md", 0o644), ("common.sh", 0o755), ("guard.sh", 0o755),
    ("recover.sh", 0o755), ("rollback.sh", 0o755), ("dns-probe.lua", 0o644),
    ("diversion-dns-c.init", 0o755))}}
OVERLAY_LIMIT = 2 * 1024 * 1024


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


def expected_asset_names():
    """The exact 18 stable assets, checked both for an existing release and before upload."""
    expected = {"SHA256SUMS", "RELEASE-NOTES.md", "release-verification.json", OVERLAY_NAME}
    for arch in ARCHES:
        expected.update({f"diversion-dns-c-lite-{PACKAGE_VERSION}_{arch}.apk", f"buildinfo-{arch}.json",
                         f"verification-{arch}-{TAG}.tar.gz"})
    for backend in ("pcre2", "posix-lite"):
        for kind, target in (("native", "linux-amd64"), ("native", "macos-arm64"),
                             ("static", "linux-amd64"), ("static", "linux-arm64")):
            expected.add(f"{backend}-{kind}-{target}-{TAG}.tar.gz")
    return expected


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
              f"partial/conflicting {TAG} tag/release exists; review without overwriting")
    release = rows[0]
    a.require(not release["draft"] and not release["prerelease"] and release["published_at"],
              f"{TAG} draft or prerelease exists; review without overwriting")
    tag = api(f"git/ref/tags/{TAG}")
    a.require(tag["object"]["type"] == "commit" and release["target_commitish"] == tag["object"]["sha"],
              "existing release/tag identity conflict")
    assets = api(f"releases/{release['id']}/assets?per_page=100")
    expected = expected_asset_names()
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
              and len(verification["jobs"]) == 10
              and {j["name"] for j in verification["jobs"]} == set(BUILD_JOBS + APK_JOBS + SUITE_JOBS)
              and all(j["conclusion"] == "success" for j in verification["jobs"]),
              "existing release verification identity differs")
    overlay = verification["recovery_overlay"]
    a.require(overlay["filename"] == OVERLAY_NAME
              and "sha256:" + overlay["sha256"] == by_name[OVERLAY_NAME]["digest"]
              and overlay["bytes"] == by_name[OVERLAY_NAME]["size"]
              and overlay["manifest"]["commit"] == verification["commit"]
              and overlay["manifest"]["source_tree"] == verification["source_tree"]
              and set(overlay["manifest"]["files"]) == set(OVERLAY_FILES),
              "existing recovery overlay identity differs")
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
    a.require(metadata["info"]["version"] == PACKAGE_VERSION, "downloaded APK version differs")
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
    a.require(version == CLI_VERSION, "downloaded APK CLI version differs")
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
        a.require(CLI_VERSION.encode() in contents[profile["application"]], "bundle CLI version stamp differs")
    return manifest



def recovery_source(commit):
    """Read only the immutable commit, with a bounded, explicit runtime file set."""
    a.require(re.fullmatch(r"[0-9a-f]{40}", commit), "invalid overlay commit")
    tree = run(["git", "-C", ROOT, "rev-parse", commit + "^{tree}"]).decode().strip()
    a.require(re.fullmatch(r"[0-9a-f]{40}", tree), "invalid overlay source tree")
    raw = run(["git", "-C", ROOT, "-c", "tar.umask=0022", "archive", "--format=tar", commit,
               "LICENSE", "deployment/openwrt-recovery"])
    a.require(len(raw) <= OVERLAY_LIMIT, "overlay source archive exceeds bound")
    files, seen = {}, set()
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            name = member.name
            a.require(name not in seen and len(seen) < 10, "duplicate or excessive overlay source member")
            seen.add(name)
            if member.isdir():
                a.require(name in {"deployment", "deployment/openwrt-recovery"}, "unexpected overlay directory")
                continue
            a.require(member.isfile() and name in OVERLAY_FILES
                      and member.mode == OVERLAY_FILES[name] and 0 < member.size <= OVERLAY_LIMIT,
                      "unexpected overlay source file, mode or type")
            files[name] = archive.extractfile(member).read()
    a.require(set(files) == set(OVERLAY_FILES), "overlay source file set differs")
    return tree, files


def recovery_manifest(commit, tree, files):
    return {"schema_version": 1, "release": TAG, "commit": commit, "source_tree": tree,
            "scope": "Custom .1 deployment overlay; not an APK installer and not installed by the APK",
            "files": {name: {"sha256": a.digest(data), "bytes": len(data),
                             "mode": format(OVERLAY_FILES[name], "04o")}
                      for name, data in sorted(files.items())}}


def verify_recovery_overlay(path, commit):
    tree, source = recovery_source(commit)
    a.require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= OVERLAY_LIMIT,
              "invalid recovery overlay file")
    with gzip.GzipFile(fileobj=io.BytesIO(path.read_bytes())) as zipped:
        raw = zipped.read(OVERLAY_LIMIT + 1)
    a.require(len(raw) <= OVERLAY_LIMIT, "recovery overlay expands beyond bound")
    contents, modes = {}, {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        for member in archive:
            a.require(member.isfile() and member.name in set(OVERLAY_FILES) | {"manifest.json"}
                      and member.name not in contents and 0 < member.size <= OVERLAY_LIMIT,
                      "unexpected recovery overlay member")
            contents[member.name] = archive.extractfile(member).read()
            modes[member.name] = member.mode
    a.require(set(contents) == set(OVERLAY_FILES) | {"manifest.json"}, "recovery overlay file set differs")
    a.require(modes == {**OVERLAY_FILES, "manifest.json": 0o644}, "recovery overlay modes differ")
    a.require(all(contents[name] == source[name] for name in OVERLAY_FILES), "recovery overlay differs from Git source")
    manifest = recovery_manifest(commit, tree, source)
    expected = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    a.require(contents["manifest.json"] == expected, "recovery overlay manifest differs")
    return {"filename": path.name, "sha256": a.digest(path.read_bytes()),
            "bytes": path.stat().st_size, "manifest": manifest}


def prepare_recovery_overlay(output, commit):
    tree, files = recovery_source(commit)
    manifest = recovery_manifest(commit, tree, files)
    files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, data in sorted(files.items()):
            member = tarfile.TarInfo(name)
            member.size, member.mode = len(data), OVERLAY_FILES.get(name, 0o644)
            member.mtime = 0
            archive.addfile(member, io.BytesIO(data))
    path = output / OVERLAY_NAME
    with path.open("xb") as stream:
        stream.write(gzip.compress(raw.getvalue(), mtime=0))
    return verify_recovery_overlay(path, commit)


def wait_workflow(workflow, commit, deadline):
    """Accept exactly one completed successful main-push workflow for this SHA."""
    while True:
        candidates = api(f"actions/workflows/{workflow}/runs?head_sha={commit}&event=push&per_page=100")
        a.require(candidates["total_count"] <= 100, "workflow pagination required")
        rows = [r for r in candidates["workflow_runs"]
                if r["head_sha"] == commit and r["head_branch"] == "main" and r["event"] == "push"]
        a.require(len(rows) <= 1, "multiple main workflow runs need human review")
        if rows and rows[0]["status"] == "completed":
            result = rows[0]
            a.require(result["path"] == ".github/workflows/" + workflow
                      and result["conclusion"] == "success", "required workflow failed or identity differs")
            return result
        a.require(time.monotonic() < deadline, "required workflow did not complete within its build window")
        time.sleep(20)


def recheck_ci(commit, run_id, attempt, apk_id, apk_attempt, suite_id, suite_attempt):
    for identity, expected_attempt, workflow, jobs, completed in (
            (run_id, attempt, "build.yml", BUILD_JOBS, False),
            (apk_id, apk_attempt, "openwrt-apk.yml", APK_JOBS, True),
            (suite_id, suite_attempt, "test-suite.yml", SUITE_JOBS, True)):
        state = api(f"actions/runs/{identity}")
        a.require(state["head_sha"] == commit and state["head_branch"] == "main" and state["event"] == "push"
                  and state["path"] == ".github/workflows/" + workflow
                  and state["run_attempt"] == expected_attempt
                  and (not completed or (state["status"] == "completed" and state["conclusion"] == "success")),
                  "CI run or attempt changed; leave unpublished")
        checked_jobs(identity, jobs)


def main():
    commit = os.environ["GITHUB_SHA"]
    run_id = int(os.environ["GITHUB_RUN_ID"])
    attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
    a.require(os.environ.get("GITHUB_REPOSITORY") == REPO and os.environ.get("GITHUB_REF") == "refs/heads/main"
              and os.environ.get("GITHUB_EVENT_NAME") == "push", "only this repository's main push may release")
    a.require(run(["git", "rev-parse", "HEAD"]).decode().strip() == commit, "release checkout differs")
    # One-version publisher: never label any other source tree as this tag.
    if (ROOT / "VERSION").read_text().strip() != VERSION:
        print(f"{TAG} publisher skipped for a different source version")
        return
    a.require((ROOT / NOTES).is_file() and (ROOT / NOTES).read_text().strip(),
              f"{NOTES} missing; never publish without release notes")

    prior = existing_release()
    if prior:
        print(f"Complete stable {TAG} already exists; no changes: " + prior["html_url"])
        return
    a.require(api("git/ref/heads/main")["object"]["sha"] == commit, "main moved; do not publish stale commit")
    own = api(f"actions/runs/{run_id}")
    a.require(own["head_sha"] == commit and own["head_branch"] == "main" and own["event"] == "push"
              and own["run_attempt"] == attempt and own["path"] == ".github/workflows/build.yml", "build run identity differs")
    build_jobs = checked_jobs(run_id, BUILD_JOBS)
    deadline = time.monotonic() + 35 * 60
    apk_run = wait_workflow("openwrt-apk.yml", commit, deadline)
    suite_run = wait_workflow("test-suite.yml", commit, deadline)
    apk_id, apk_attempt = apk_run["id"], apk_run["run_attempt"]
    suite_id, suite_attempt = suite_run["id"], suite_run["run_attempt"]
    apk_jobs = checked_jobs(apk_id, APK_JOBS)
    suite_jobs = checked_jobs(suite_id, SUITE_JOBS)
    work = ROOT / WORK
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
        shutil.copyfile(folder / info["apk"]["filename"], output / f"diversion-dns-c-lite-{PACKAGE_VERSION}_{arch}.apk")
        shutil.copyfile(folder / "buildinfo.json", output / f"buildinfo-{arch}.json")
        # Retain original matrix evidence and its own checksums without editing paths/logs.
        with tarfile.open(output / f"verification-{arch}-{TAG}.tar.gz", "w:gz") as archive:
            for path in sorted(folder.rglob("*")):
                if path.is_file():
                    archive.add(path, arcname=path.relative_to(folder).as_posix(), recursive=False)
    overlay = prepare_recovery_overlay(output, commit)
    report = {"release": TAG, "commit": commit, "source_tree": run(["git", "rev-parse", "HEAD^{tree}"]).decode().strip(),
              "build_run_id": run_id, "build_run_attempt": attempt, "apk_run_id": apk_id, "apk_run_attempt": apk_attempt,
              "suite_run_id": suite_id, "suite_run_attempt": suite_attempt,
              "recovery_overlay": overlay, "jobs": build_jobs + apk_jobs + suite_jobs, "actions_artifacts": receipts, "independent_download_checks": reports,
              "unsigned_apk": True, "hardware_acceptance": False}
    (output / "release-verification.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    shutil.copyfile(ROOT / NOTES, output / "RELEASE-NOTES.md")
    assets = sorted(output.iterdir())
    (output / "SHA256SUMS").write_text("".join(f"{a.digest(p.read_bytes())}  {p.name}\n" for p in assets))
    assets = sorted(output.iterdir())
    a.require({p.name for p in assets} == expected_asset_names()
              and all(p.is_file() and p.stat().st_size > 0 for p in assets),
              "prepared release asset set differs; do not publish")
    # Re-read everything immediately before the only external mutation.
    a.require(api("git/ref/heads/main")["object"]["sha"] == commit, "main moved before publication")
    a.require(existing_release() is None, f"{TAG} appeared; never overwrite it")
    recheck_ci(commit, run_id, attempt, apk_id, apk_attempt, suite_id, suite_attempt)
    a.require(verify_recovery_overlay(output / OVERLAY_NAME, commit) == overlay,
              "recovery overlay changed before upload")
    notes = (ROOT / NOTES).read_text() + f"\n\n发布提交：{commit}\n\nCI：{own['html_url']} · {apk_run['html_url']} · {suite_run['html_url']}\n"
    publish_assets(assets, commit, notes, run_id, attempt, apk_id, apk_attempt, suite_id, suite_attempt)


def publish_assets(assets, commit, notes, run_id, attempt, apk_id, apk_attempt, suite_id, suite_attempt):
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
    recheck_ci(commit, run_id, attempt, apk_id, apk_attempt, suite_id, suite_attempt)
    published = json.loads(run(["gh", "api", f"repos/{REPO}/releases/{release['id']}", "--method", "PATCH", "--input", "-"],
                              input=json.dumps({"draft": False, "prerelease": False, "make_latest": "true"}).encode()))
    a.require(not published["draft"] and not published["prerelease"], "stable publication not confirmed")
    print(published["html_url"])


if __name__ == "__main__":
    main()
