#!/usr/bin/env python3
"""One-release cleanup: verified Actions backup before exact approved asset deletes.

Uses only the existing ephemeral main-push job token. Never modifies refs,
recreates a release, uploads release assets, or touches other releases/artifacts.
Repeated runs accept only a subset of the pinned removal list plus both original
APKs; unknown assets, replaced bytes, conflicting notes or identities fail closed.
"""
import argparse
import io
import json
import os
from pathlib import Path
import time
import zipfile

import importlib.util
spec = importlib.util.spec_from_file_location("publisher", Path(__file__).with_name("publish-v0.1.0.py"))
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)
a = pub.a
ROOT = pub.ROOT
PINNED = {row["id"]: row for row in pub.PINNED["assets"]}
KEEP = {row["id"] for row in pub.APK_ASSETS.values()}
REMOVE = set(PINNED) - KEEP
RELEASE_ID = pub.PINNED["release_id"]
BACKUP = ROOT / ".build/release-v0.1.0-cleanup/backup"
RECEIPT = BACKUP / "cleanup-receipt.json"


def identity():
    a.require(os.environ.get("GITHUB_REPOSITORY") == pub.REPO
              and os.environ.get("GITHUB_REF") == "refs/heads/main"
              and os.environ.get("GITHUB_EVENT_NAME") == "push", "cleanup requires this repository's main push")
    commit = os.environ["GITHUB_SHA"]
    run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
    a.require(pub.run(["git", "rev-parse", "HEAD"]).decode().strip() == commit,
              "cleanup checkout differs")
    a.require(pub.api("git/ref/heads/main")["object"]["sha"] == commit, "main moved; cleanup stopped")
    tag = pub.api(f"git/ref/tags/{pub.TAG}")
    a.require(tag["object"] == {"type": "commit", "sha": pub.ORIGINAL_COMMIT,
                               "url": f"https://api.github.com/repos/{pub.REPO}/git/commits/{pub.ORIGINAL_COMMIT}"},
              "original release tag differs")
    own = pub.api(f"actions/runs/{run_id}")
    a.require(own["head_sha"] == commit and own["head_branch"] == "main"
              and own["event"] == "push" and own["run_attempt"] == attempt
              and own["path"] == ".github/workflows/build.yml", "cleanup run differs")
    return commit, run_id, attempt


def state():
    release = pub.api(f"releases/{RELEASE_ID}")
    a.require(release["id"] == RELEASE_ID and release["tag_name"] == pub.TAG
              and release["target_commitish"] == pub.ORIGINAL_COMMIT
              and not release["draft"] and not release["prerelease"] and release["published_at"],
              "original release identity differs")
    rows = pub.api(f"releases/{RELEASE_ID}/assets?per_page=100")
    ids = {row["id"] for row in rows}
    a.require(len(rows) == len(ids) and KEEP <= ids <= set(PINNED), "unexpected or missing release assets")
    a.require(all(row.get("state") == "uploaded"
                  and all(row.get(key) == expected for key, expected in PINNED[row["id"]].items())
                  for row in rows), "pinned release asset metadata differs")
    return release, ids


def download(asset_id):
    row = PINNED[asset_id]
    data = pub.run(["gh", "api", f"repos/{pub.REPO}/releases/assets/{asset_id}",
                    "-H", "Accept: application/octet-stream"])
    a.require(len(data) == row["size"] and "sha256:" + a.digest(data) == row["digest"],
              "original release asset bytes differ")
    return data


def required_builds(commit, run_id):
    pub.checked_jobs(run_id, pub.BUILD_JOBS)
    deadline = time.monotonic() + 35 * 60
    while True:
        runs = pub.api(f"actions/workflows/openwrt-apk.yml/runs?head_sha={commit}&event=push&per_page=100")
        a.require(runs["total_count"] <= 100, "APK run enumeration exceeded bound")
        rows = [r for r in runs["workflow_runs"] if r["head_sha"] == commit
                and r["head_branch"] == "main" and r["event"] == "push"]
        a.require(len(rows) <= 1, "multiple main APK runs need review")
        if rows and rows[0]["status"] == "completed":
            row = rows[0]
            a.require(row["conclusion"] == "success", "APK workflow failed; no cleanup")
            pub.checked_jobs(row["id"], [f"APK / {arch}" for arch in pub.ARCHES])
            return
        a.require(time.monotonic() < deadline, "APK workflow exceeded cleanup build window")
        time.sleep(20)


def prepare():
    commit, run_id, attempt = identity()
    release, ids = state()
    original_body = a.digest(release["body"].encode()) == pub.PINNED["original_body_sha256"]
    if ids == KEEP and not original_body:
        for asset_id in sorted(KEEP):
            download(asset_id)
        with open(os.environ["GITHUB_OUTPUT"], "a") as output:
            print("needed=false", file=output)
        print("Exactly two original APKs already remain; no cleanup or notes mutation")
        return
    a.require(original_body, "release notes changed since cleanup approval; review required")
    required_builds(commit, run_id)
    a.require(not BACKUP.exists(), "cleanup backup must be fresh")
    BACKUP.mkdir(parents=True)
    for asset_id in sorted(ids):
        (BACKUP / PINNED[asset_id]["name"]).write_bytes(download(asset_id))
    # A retry backs up every still-present removal candidate before deleting it.
    receipt = {"release_id": RELEASE_ID, "tag_commit": pub.ORIGINAL_COMMIT,
               "workflow_commit": commit, "run_id": run_id, "attempt": attempt,
               "assets": [PINNED[i] for i in sorted(ids)],
               "prior_body": release["body"], "body_sha256": a.digest(release["body"].encode())}
    RECEIPT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    with open(os.environ["GITHUB_OUTPUT"], "a") as output:
        print("needed=true", file=output)
    print(f"Verified backup prepared: {len(ids & REMOVE)} removal candidates and both original APKs")


def verify_backup(commit, run_id, attempt):
    receipt_bytes = RECEIPT.read_bytes()
    receipt = json.loads(receipt_bytes)
    a.require((receipt["release_id"], receipt["tag_commit"], receipt["workflow_commit"],
               receipt["run_id"], receipt["attempt"]) ==
              (RELEASE_ID, pub.ORIGINAL_COMMIT, commit, run_id, attempt), "backup receipt identity differs")
    rows = receipt["assets"]
    ids = {r["id"] for r in rows}
    a.require(len(rows) == len(ids) and KEEP <= ids <= set(PINNED)
              and all(r == PINNED[r["id"]] for r in rows), "backup receipt asset set differs")
    artifact_id = int(os.environ["CLEANUP_BACKUP_ARTIFACT_ID"])
    artifact = pub.api(f"actions/artifacts/{artifact_id}")
    a.require(artifact["name"] == f"release-v0.1.0-cleanup-backup-{commit}-attempt-{attempt}"
              and artifact["workflow_run"]["id"] == run_id and artifact["workflow_run"]["head_sha"] == commit
              and not artifact["expired"] and 0 < artifact["size_in_bytes"] < 64 * 1024 * 1024,
              "uploaded backup artifact identity differs")
    data = pub.run(["gh", "api", f"repos/{pub.REPO}/actions/artifacts/{artifact_id}/zip"])
    a.require(len(data) == artifact["size_in_bytes"]
              and "sha256:" + a.digest(data) == artifact["digest"], "uploaded backup ZIP digest differs")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        expected = {r["name"] for r in rows} | {RECEIPT.name}
        a.require(len(archive.infolist()) == len(expected) and set(archive.namelist()) == expected,
                  "uploaded backup ZIP members differ")
        a.require(archive.read(RECEIPT.name) == receipt_bytes, "uploaded backup receipt differs")
        for row in rows:
            info = archive.getinfo(row["name"])
            a.require(info.file_size == row["size"], "uploaded backup asset size differs")
            saved = archive.read(row["name"])
            a.require("sha256:" + a.digest(saved) == row["digest"], "uploaded backup asset digest differs")
    return receipt, ids


def apply():
    commit, run_id, attempt = identity()
    required_builds(commit, run_id)
    receipt, saved_ids = verify_backup(commit, run_id, attempt)
    release, ids = state()
    a.require(ids <= saved_ids, "release asset set changed after backup")
    notes = (ROOT / "docs/release-v0.1.0.md").read_text()
    a.require(release["body"] in (receipt["prior_body"], notes), "release notes changed after backup")
    for asset_id in sorted(KEEP):
        download(asset_id)
    removed = []
    for asset_id in sorted(ids & REMOVE):
        identity()
        live, current = state()
        a.require(live["body"] in (receipt["prior_body"], notes), "release notes changed during cleanup")
        a.require(current <= ids - set(removed), "release asset set changed during cleanup")
        if asset_id in current:
            pub.run(["gh", "api", f"repos/{pub.REPO}/releases/assets/{asset_id}", "--method", "DELETE"])
            removed.append(asset_id)
            _, after = state()
            a.require(asset_id not in after, "asset deletion not confirmed")
    identity()
    release, after = state()
    a.require(after == KEEP, "cleanup incomplete; extra release attachments remain")
    for asset_id in sorted(KEEP):
        download(asset_id)
    identity()
    release, after = state()
    a.require(after == KEEP, "release asset set changed before notes update")
    a.require(release["body"] in (receipt["prior_body"], notes), "release notes changed during cleanup")
    if release["body"] != notes:
        pub.run(["gh", "api", f"repos/{pub.REPO}/releases/{RELEASE_ID}", "--method", "PATCH", "--input", "-"],
                input=json.dumps({"body": notes}).encode())
    final, after = state()
    a.require(after == KEEP and final["body"] == notes, "final release state not confirmed")
    identity()
    report = {"release_id": RELEASE_ID, "tag_commit": pub.ORIGINAL_COMMIT,
              "removed_ids_this_attempt": removed, "retained": [PINNED[i] for i in sorted(KEEP)],
              "backup_artifact_id": int(os.environ["CLEANUP_BACKUP_ARTIFACT_ID"])}
    (BACKUP.parent / "result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"Cleanup verified: {len(removed)} attachments deleted this attempt; exactly two original APKs remain")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "apply"))
    args = parser.parse_args()
    (prepare if args.mode == "prepare" else apply)()
