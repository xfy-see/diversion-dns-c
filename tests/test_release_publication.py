"""The one-version publisher has no network or executable side effects in tests."""
import importlib.util
import io
import zipfile
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("publish_010", ROOT / "scripts/publish-v0.1.0.py")
pub = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pub)


class VersionContracts(unittest.TestCase):
    def test_application_recipe_and_metadata_share_version(self):
        self.assertEqual((ROOT / "VERSION").read_text(), "0.1.0\n")
        self.assertIn('puts("mosdns-c 0.1.0 fixed-splitter")', (ROOT / "c/main.c").read_text())
        self.assertIn("PKG_VERSION:=0.1.0\nPKG_RELEASE:=1\n", (ROOT / "packaging/openwrt/Makefile").read_text())
        self.assertIn("application_version", (ROOT / "scripts/artifacts.py").read_text())

    def test_only_main_push_release_job_gets_write_permission(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        release = workflow.split("  release-010:\n", 1)[1]
        self.assertIn("needs: [native, static, delivery]", release)
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", release)
        self.assertIn("github.repository == 'xfy-see/diversion-dns-c'", release)
        self.assertIn("cancel-in-progress: false", release)
        self.assertIn("persist-credentials: false", release)
        self.assertIn("contents: write", release)
        self.assertNotIn("write-all", workflow)

    def test_tag_release_and_asset_overwrite_flags_absent(self):
        text = (ROOT / "scripts/publish-v0.1.0.py").read_text()
        self.assertNotIn('"--clobber"', text)
        self.assertNotIn('"force": True', text)
        self.assertNotIn('"--prerelease"', text)
        self.assertIn('"draft": True, "prerelease": False', text)
        self.assertIn('"draft": False, "prerelease": False', text)


class GitHubReadContracts(unittest.TestCase):
    def test_absent_accepts_only_verified_404(self):
        for code, stderr, expected in ((0, b"", False), (1, b"gh: Not Found (HTTP 404)", True)):
            with mock.patch.object(pub.subprocess, "run", return_value=subprocess.CompletedProcess([], code, b"{}", stderr)):
                self.assertEqual(pub.absent("releases/tags/v0.1.0"), expected)
        for text in (b"HTTP 403", b"connection timed out", b"HTTP 500"):
            with mock.patch.object(pub.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", text)):
                with self.assertRaisesRegex(ValueError, "absence is unconfirmed"):
                    pub.absent("releases/tags/v0.1.0")

    def test_required_jobs_all_pass_exactly_once(self):
        rows = [{"id": i, "name": name, "status": "completed", "conclusion": "success", "html_url": "https://github.com/"}
                for i, name in enumerate(["A", "B"])]
        with mock.patch.object(pub, "api", return_value={"total_count": 2, "jobs": rows}):
            self.assertEqual(len(pub.checked_jobs(1, ["A", "B"])), 2)
        for changed in (rows[:1], rows + [rows[0]], [dict(rows[0], conclusion="failure"), rows[1]],
                        [dict(rows[0], status="in_progress"), rows[1]]):
            with mock.patch.object(pub, "api", return_value={"total_count": len(changed), "jobs": changed}):
                with self.assertRaisesRegex(ValueError, "not all successful"):
                    pub.checked_jobs(1, ["A", "B"])

    def test_pr_fork_or_other_repo_cannot_publish(self):
        for override in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/feature"},
                         {"GITHUB_REPOSITORY": "someone/fork"}):
            env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
                   "GITHUB_REPOSITORY": pub.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", **override}
            with mock.patch.dict(os.environ, env), mock.patch.object(pub, "api") as api:
                with self.assertRaisesRegex(ValueError, "only this repository"):
                    pub.main()
                api.assert_not_called()

    def test_existing_complete_release_never_calls_mutating_api(self):
        env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": pub.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"}
        with mock.patch.dict(os.environ, env), mock.patch.object(pub, "run", return_value=("a" * 40).encode()) as run, \
                mock.patch.object(pub, "existing_release", return_value={"html_url": "https://github.com/"}), mock.patch.object(pub, "api") as api:
            pub.main()
            api.assert_not_called()
            self.assertEqual(run.call_count, 1)

    def test_partial_release_state_fails_closed(self):
        for rows, tag_missing in (([], False), ([{"tag_name": pub.TAG}], True),
                                  ([{"tag_name": pub.TAG, "draft": True}], False)):
            with mock.patch.object(pub, "api", return_value=rows), mock.patch.object(pub, "absent", return_value=tag_missing):
                with self.assertRaisesRegex(ValueError, "exists; review"):
                    pub.existing_release()


class PublishSequenceContracts(unittest.TestCase):
    def invoke(self, *, corrupt=False, main_moved=False, attempt_changed=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        assets = [Path(tmp.name) / name for name in pub.APK_ASSETS]
        for asset in assets:
            asset.write_bytes(b"synthetic release bytes; never executable")
        commit = pub.ORIGINAL_COMMIT
        calls = []
        def command(argv, **kwargs):
            calls.append(argv)
            if "releases" == argv[2].split("/")[-1] and "POST" in argv:
                return json.dumps({"id": 99}).encode()
            if "PATCH" in argv:
                self.assertEqual(json.loads(kwargs["input"]), {"draft": False, "prerelease": False, "make_latest": "true"})
                return json.dumps({"draft": False, "prerelease": False, "html_url": "https://github.com/release"}).encode()
            return b"{}"
        def api(path):
            if path.endswith("/assets?per_page=100"):
                return [{"name": asset.name, "size": asset.stat().st_size,
                         "digest": "sha256:" + ("0" * 64 if corrupt else pub.a.digest(asset.read_bytes()))} for asset in assets]
            if path.startswith("git/ref/"):
                return {"object": {"sha": "b" * 40 if main_moved and path.endswith("main") else commit}}
            if path.startswith("actions/runs/"):
                return {"head_sha": commit, "run_attempt": 2 if attempt_changed else 1,
                        "status": "completed", "conclusion": "success"}
            raise AssertionError(path)
        with mock.patch.object(pub, "run", side_effect=command), mock.patch.object(pub, "api", side_effect=api), \
                mock.patch.object(pub, "checked_jobs", return_value=[]):
            error = None
            try:
                pub.publish_assets(assets, commit, "release notes", 11, 1, 12, 1)
            except ValueError as exc:
                error = str(exc)
        return calls, error

    def test_tag_then_draft_then_upload_then_publish(self):
        calls, error = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(len(calls), 4)
        self.assertIn("git/refs", calls[0][2])
        self.assertIn("releases", calls[1][2])
        self.assertEqual(calls[2][1:3], ["release", "upload"])
        self.assertIn("PATCH", calls[3])

    def test_bad_upload_or_changed_identity_leaves_draft_unpublished(self):
        for kwargs in ({"corrupt": True}, {"main_moved": True}, {"attempt_changed": True}):
            with self.subTest(kwargs=kwargs):
                calls, error = self.invoke(**kwargs)
                self.assertIsNotNone(error)
                self.assertFalse(any("PATCH" in command for command in calls))


class ArtifactDownloadContracts(unittest.TestCase):
    def test_digest_identity_and_safe_membership_gate_download(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as z:
            z.writestr("bundle.tar.gz", b"fixture bytes, never executable")
        data = raw.getvalue()
        row = {"id": 1, "name": "expected", "expired": False, "size_in_bytes": len(data),
               "digest": "sha256:" + pub.a.digest(data), "workflow_run": {"id": 2, "head_sha": "a" * 40}}
        for change in (None, "sha", "run", "digest", "expired", "bytes"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temporary:
                current = copy.deepcopy(row)
                if change == "sha": current["workflow_run"]["head_sha"] = "b" * 40
                if change == "run": current["workflow_run"]["id"] = 3
                if change == "digest": current["digest"] = "sha256:" + "0" * 64
                if change == "expired": current["expired"] = True
                if change == "bytes": current["size_in_bytes"] += 1
                def download(command, **kwargs):
                    kwargs["stdout"].write(data)
                    return subprocess.CompletedProcess(command, 0)
                with mock.patch.object(pub, "api", return_value={"total_count": 1, "artifacts": [current]}), \
                        mock.patch.object(pub.subprocess, "run", side_effect=download):
                    if change:
                        with self.assertRaises(ValueError):
                            pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
                        self.assertFalse((Path(temporary) / "expected/bundle.tar.gz").exists())
                    else:
                        receipts = pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
                        self.assertEqual(receipts[0]["digest"], row["digest"])
                        self.assertEqual((Path(temporary) / "expected/bundle.tar.gz").read_bytes(), b"fixture bytes, never executable")

    def test_directory_traversal_fails_before_writing_outside(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as z:
            z.writestr("../outside", b"not allowed")
        data = raw.getvalue()
        row = {"id": 1, "name": "expected", "expired": False, "size_in_bytes": len(data),
               "digest": "sha256:" + pub.a.digest(data), "workflow_run": {"id": 2, "head_sha": "a" * 40}}
        def download(command, **kwargs):
            kwargs["stdout"].write(data)
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(pub, "api", return_value={"total_count": 1, "artifacts": [row]}), \
                mock.patch.object(pub.subprocess, "run", side_effect=download):
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
            self.assertFalse((Path(temporary) / "outside").exists())


if __name__ == "__main__":
    unittest.main()
