"""The one-version publishers have no network or executable side effects in tests.

Shared publisher contracts run against both the archived v0.1.0 publisher and
the v0.1.2 publisher, which must keep the same checks.
"""
import importlib.util
from contextlib import contextmanager
import gzip
import tarfile
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


def load_publisher(name, version):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"scripts/publish-v{version}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


pub = load_publisher("publish_010", "0.1.0")
pub012 = load_publisher("publish_012", "0.1.2")
pub013 = load_publisher("publish_013", "0.1.3")
pub014 = load_publisher("publish_014", "0.1.4")


@contextmanager
def publisher_source(publisher):
    """Exercise old publishers against their own archived version, not current HEAD."""
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "VERSION").write_text(publisher.VERSION + "\n")
        notes = getattr(publisher, "NOTES", Path("docs") / f"release-{publisher.TAG}.md")
        (root / notes).parent.mkdir(parents=True)
        (root / notes).write_text("Synthetic release notes\n")
        with mock.patch.object(publisher, "ROOT", root):
            yield root


class VersionContracts(unittest.TestCase):
    def test_application_recipe_and_metadata_share_version(self):
        self.assertEqual((ROOT / "VERSION").read_text(), "0.1.4\n")
        self.assertIn('puts("mosdns-c 0.1.4 fixed-splitter")', (ROOT / "c/main.c").read_text())
        self.assertIn("PKG_VERSION:=0.1.4\nPKG_RELEASE:=1\n", (ROOT / "packaging/openwrt/Makefile").read_text())
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


class GitHubReadContractsMixin:
    pub = None

    def test_absent_accepts_only_verified_404(self):
        for code, stderr, expected in ((0, b"", False), (1, b"gh: Not Found (HTTP 404)", True)):
            with mock.patch.object(self.pub.subprocess, "run", return_value=subprocess.CompletedProcess([], code, b"{}", stderr)):
                self.assertEqual(self.pub.absent(f"releases/tags/{self.pub.TAG}"), expected)
        for text in (b"HTTP 403", b"connection timed out", b"HTTP 500"):
            with mock.patch.object(self.pub.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, b"", text)):
                with self.assertRaisesRegex(ValueError, "absence is unconfirmed"):
                    self.pub.absent(f"releases/tags/{self.pub.TAG}")

    def test_required_jobs_all_pass_exactly_once(self):
        rows = [{"id": i, "name": name, "status": "completed", "conclusion": "success", "html_url": "https://github.com/"}
                for i, name in enumerate(["A", "B"])]
        with mock.patch.object(self.pub, "api", return_value={"total_count": 2, "jobs": rows}):
            self.assertEqual(len(self.pub.checked_jobs(1, ["A", "B"])), 2)
        for changed in (rows[:1], rows + [rows[0]], [dict(rows[0], conclusion="failure"), rows[1]],
                        [dict(rows[0], status="in_progress"), rows[1]]):
            with mock.patch.object(self.pub, "api", return_value={"total_count": len(changed), "jobs": changed}):
                with self.assertRaisesRegex(ValueError, "not all successful"):
                    self.pub.checked_jobs(1, ["A", "B"])

    def test_pr_fork_or_other_repo_cannot_publish(self):
        for override in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/feature"},
                         {"GITHUB_REPOSITORY": "someone/fork"}):
            env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
                   "GITHUB_REPOSITORY": self.pub.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", **override}
            with mock.patch.dict(os.environ, env), mock.patch.object(self.pub, "api") as api:
                with self.assertRaisesRegex(ValueError, "only this repository"):
                    self.pub.main()
                api.assert_not_called()

    def test_existing_complete_release_never_calls_mutating_api(self):
        env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": self.pub.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push"}
        with publisher_source(self.pub), mock.patch.dict(os.environ, env), mock.patch.object(self.pub, "run", return_value=("a" * 40).encode()) as run, \
                mock.patch.object(self.pub, "existing_release", return_value={"html_url": "https://github.com/"}), mock.patch.object(self.pub, "api") as api:
            self.pub.main()
            api.assert_not_called()
            self.assertEqual(run.call_count, 1)

    def test_partial_release_state_fails_closed(self):
        for rows, tag_missing in (([], False), ([{"tag_name": self.pub.TAG}], True),
                                  ([{"tag_name": self.pub.TAG, "draft": True}], False)):
            with mock.patch.object(self.pub, "api", return_value=rows), mock.patch.object(self.pub, "absent", return_value=tag_missing):
                with self.assertRaisesRegex(ValueError, "exists; review"):
                    self.pub.existing_release()


class PublishSequenceContractsMixin:
    pub = None

    def invoke(self, *, corrupt=False, main_moved=False, attempt_changed=False):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        asset = Path(tmp.name) / "fixture.apk"
        asset.write_bytes(b"synthetic release bytes; never executable")
        commit = "a" * 40
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
                         "digest": "sha256:" + ("0" * 64 if corrupt else self.pub.a.digest(asset.read_bytes()))}]
            if path.startswith("git/ref/"):
                return {"object": {"sha": "b" * 40 if main_moved and path.endswith("main") else commit}}
            if path.startswith("actions/runs/"):
                return {"head_sha": commit, "run_attempt": 2 if attempt_changed else 1,
                        "status": "completed", "conclusion": "success", "head_branch": "main", "event": "push",
                        "path": ".github/workflows/" + {"11": "build.yml", "12": "openwrt-apk.yml", "13": "test-suite.yml"}[path.rsplit("/", 1)[1]]}
            raise AssertionError(path)
        with mock.patch.object(self.pub, "run", side_effect=command), mock.patch.object(self.pub, "api", side_effect=api), \
                mock.patch.object(self.pub, "checked_jobs", return_value=[]):
            error = None
            try:
                self.pub.publish_assets([asset], commit, "release notes", 11, 1, 12, 1,
                                        *([13, 1] if self.pub in (pub013, pub014) else []))
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


class ArtifactDownloadContractsMixin:
    pub = None

    def test_digest_identity_and_safe_membership_gate_download(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as z:
            z.writestr("bundle.tar.gz", b"fixture bytes, never executable")
        data = raw.getvalue()
        row = {"id": 1, "name": "expected", "expired": False, "size_in_bytes": len(data),
               "digest": "sha256:" + self.pub.a.digest(data), "workflow_run": {"id": 2, "head_sha": "a" * 40}}
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
                with mock.patch.object(self.pub, "api", return_value={"total_count": 1, "artifacts": [current]}), \
                        mock.patch.object(self.pub.subprocess, "run", side_effect=download):
                    if change:
                        with self.assertRaises(ValueError):
                            self.pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
                        self.assertFalse((Path(temporary) / "expected/bundle.tar.gz").exists())
                    else:
                        receipts = self.pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
                        self.assertEqual(receipts[0]["digest"], row["digest"])
                        self.assertEqual((Path(temporary) / "expected/bundle.tar.gz").read_bytes(), b"fixture bytes, never executable")

    def test_directory_traversal_fails_before_writing_outside(self):
        raw = io.BytesIO()
        with zipfile.ZipFile(raw, "w") as z:
            z.writestr("../outside", b"not allowed")
        data = raw.getvalue()
        row = {"id": 1, "name": "expected", "expired": False, "size_in_bytes": len(data),
               "digest": "sha256:" + self.pub.a.digest(data), "workflow_run": {"id": 2, "head_sha": "a" * 40}}
        def download(command, **kwargs):
            kwargs["stdout"].write(data)
            return subprocess.CompletedProcess(command, 0)
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(self.pub, "api", return_value={"total_count": 1, "artifacts": [row]}), \
                mock.patch.object(self.pub.subprocess, "run", side_effect=download):
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                self.pub.fetch_artifacts(2, 1, "a" * 40, Path(temporary), {"expected"})
            self.assertFalse((Path(temporary) / "outside").exists())



class GitHubReadContracts(GitHubReadContractsMixin, unittest.TestCase):
    pub = pub


class PublishSequenceContracts(PublishSequenceContractsMixin, unittest.TestCase):
    pub = pub


class ArtifactDownloadContracts(ArtifactDownloadContractsMixin, unittest.TestCase):
    pub = pub


class GitHubReadContracts012(GitHubReadContractsMixin, unittest.TestCase):
    pub = pub012


class PublishSequenceContracts012(PublishSequenceContractsMixin, unittest.TestCase):
    pub = pub012


class ArtifactDownloadContracts012(ArtifactDownloadContractsMixin, unittest.TestCase):
    pub = pub012


def main_env(**override):
    return {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_REPOSITORY": "xfy-see/diversion-dns-c", "GITHUB_REF": "refs/heads/main",
            "GITHUB_EVENT_NAME": "push", **override}


class Release012Contracts(unittest.TestCase):
    """v0.1.2-only contracts: names, workflow job, version gate and fail-closed paths."""

    def test_version_derived_names_match_source(self):
        self.assertEqual((pub012.VERSION, pub012.TAG, pub012.PACKAGE_VERSION), ("0.1.2", "v0.1.2", "0.1.2-r1"))
        self.assertEqual(pub012.CLI_VERSION, "mosdns-c 0.1.2 fixed-splitter")
        self.assertEqual(pub012.NOTES.as_posix(), "docs/release-v0.1.2.md")
        self.assertEqual(pub012.WORK.as_posix(), ".build/release-v0.1.2")
        self.assertEqual((pub.TAG, pub.VERSION), ("v0.1.0", "0.1.0"))

    def test_release_notes_exist_and_list_every_asset(self):
        notes = (ROOT / pub012.NOTES).read_text()
        self.assertTrue(notes.startswith("# diversion-dns-c v0.1.2\n"))
        self.assertIn(pub012.CLI_VERSION, notes)
        self.assertNotIn("/workspace/", notes)
        names = pub012.expected_asset_names()
        self.assertEqual(len(names), 17)
        for name in names:
            self.assertIn(name, notes)
        self.assertFalse(any("0.1.0" in name for name in names))
        self.assertIn("diversion-dns-c-lite-0.1.2-r1_mipsel_24kc.apk", names)
        self.assertIn("posix-lite-static-linux-arm64-v0.1.2.tar.gz", names)
        self.assertIn("verification-aarch64_cortex-a53-v0.1.2.tar.gz", names)

    def test_publisher_mirrors_every_archived_check(self):
        old = (ROOT / "scripts/publish-v0.1.0.py").read_text().splitlines()
        new = (ROOT / "scripts/publish-v0.1.2.py").read_text()
        lines = set(new.splitlines())
        allowed = {  # rewritten only to derive names from VERSION
            '"""One-version, main-only release. Verify exact CI bytes; never overwrite a tag.',
            '    a.require(metadata["info"]["version"] == VERSION + "-r1", "downloaded APK version differs")',
            '    # This publisher is an immutable historical release tool, not the current',
        }
        missing = [line for line in old if "0.1.0" not in line and line not in lines and line not in allowed]
        self.assertEqual(missing, [])
        self.assertNotIn("0.1.0", new.replace("archived v0.1.0 publisher", ""))
        self.assertEqual(new.count("a.require("), "\n".join(old).count("a.require(") + 2)
        for text in ('"--clobber"', '"force": True', '"--prerelease"'):
            self.assertNotIn(text, new)
        self.assertIn('"draft": True, "prerelease": False', new)
        self.assertIn('"draft": False, "prerelease": False, "make_latest": "true"', new)

    def test_release_jobs_preserve_archived_checks(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        blocks = [workflow.split("  release-" + label + ":\n", 1)[1].split("  release-", 1)[0].strip()
                  for label in ("010", "011", "012")]
        self.assertEqual(blocks[0].replace("0.1.0", "0.1.1"), blocks[1])
        self.assertEqual(blocks[1].replace("0.1.1", "0.1.2"), blocks[2])
        self.assertIn("run: python3 scripts/publish-v0.1.2.py", blocks[2])
        self.assertEqual(workflow.count("contents: write"), 6)

    def test_other_source_version_skips_before_any_github_read(self):
        for version in ("0.1.0", "0.1.1", "0.2.0"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "VERSION").write_text(version + "\n")
                with mock.patch.dict(os.environ, main_env()), mock.patch.object(pub012, "ROOT", root), \
                        mock.patch.object(pub012, "run", return_value=("a" * 40).encode()) as run, \
                        mock.patch.object(pub012, "api") as api, mock.patch.object(pub012, "absent") as absent, \
                        mock.patch("builtins.print") as printed:
                    pub012.main()
                api.assert_not_called()
                absent.assert_not_called()
                self.assertEqual(run.call_count, 1)
                printed.assert_called_once_with("v0.1.2 publisher skipped for a different source version")

    def test_missing_release_notes_fail_before_any_github_read(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "VERSION").write_text("0.1.2\n")
            with mock.patch.dict(os.environ, main_env()), mock.patch.object(pub012, "ROOT", root), \
                    mock.patch.object(pub012, "run", return_value=("a" * 40).encode()), \
                    mock.patch.object(pub012, "api") as api, mock.patch.object(pub012, "absent") as absent:
                with self.assertRaisesRegex(ValueError, "release notes"):
                    pub012.main()
            api.assert_not_called()
            absent.assert_not_called()

    def test_existing_tag_without_release_is_refused(self):
        def api(path):
            if path.startswith("releases?"):
                return []
            raise AssertionError(path)
        with mock.patch.object(pub012, "api", side_effect=api), mock.patch.object(pub012, "absent", return_value=False):
            with self.assertRaisesRegex(ValueError, "partial/conflicting v0.1.2 tag/release exists"):
                pub012.existing_release()
        env = main_env()
        with publisher_source(pub012), mock.patch.dict(os.environ, env), mock.patch.object(pub012, "run", return_value=("a" * 40).encode()) as run, \
                mock.patch.object(pub012, "api", side_effect=api), mock.patch.object(pub012, "absent", return_value=False):
            with self.assertRaisesRegex(ValueError, "review without overwriting"):
                pub012.main()
            self.assertEqual(run.call_count, 1)  # only `git rev-parse HEAD`; no tag/release POST

    def existing(self, names, published=True):
        commit = "c" * 40
        release = {"id": 7, "tag_name": "v0.1.2", "draft": not published, "prerelease": False,
                   "published_at": "2026-10-11T00:00:00Z" if published else None, "target_commitish": commit,
                   "html_url": "https://github.com/release"}
        assets = [{"id": i, "name": name, "state": "uploaded", "size": 1, "digest": "sha256:" + "1" * 64}
                  for i, name in enumerate(sorted(names))]
        def api(path):
            if path.startswith("releases?"):
                return [release, dict(release, id=8, tag_name="v0.1.0")]
            if path == "git/ref/tags/v0.1.2":
                return {"object": {"type": "commit", "sha": commit}}
            if path == "releases/7/assets?per_page=100":
                return assets
            raise AssertionError(path)
        return api

    def test_existing_release_with_wrong_asset_names_is_refused(self):
        names = pub012.expected_asset_names()
        for changed in ({n.replace("0.1.2", "0.1.0") for n in names},
                        names - {"SHA256SUMS"}, names | {"extra.bin"}):
            with self.subTest(size=len(changed)), mock.patch.object(pub012, "api", side_effect=self.existing(changed)), \
                    mock.patch.object(pub012, "absent", return_value=False), mock.patch.object(pub012, "run") as run:
                with self.assertRaisesRegex(ValueError, "assets incomplete"):
                    pub012.existing_release()
                run.assert_not_called()
        with mock.patch.object(pub012, "api", side_effect=self.existing(names, published=False)), \
                mock.patch.object(pub012, "absent", return_value=False):
            with self.assertRaisesRegex(ValueError, "draft or prerelease exists"):
                pub012.existing_release()

    def test_main_moved_before_any_download_fails_closed(self):
        def api(path):
            if path == "git/ref/heads/main":
                return {"object": {"sha": "b" * 40}}
            raise AssertionError(path)
        with publisher_source(pub012), mock.patch.dict(os.environ, main_env()), mock.patch.object(pub012, "run", return_value=("a" * 40).encode()) as run, \
                mock.patch.object(pub012, "existing_release", return_value=None), mock.patch.object(pub012, "api", side_effect=api):
            with self.assertRaisesRegex(ValueError, "main moved"):
                pub012.main()
            self.assertEqual(run.call_count, 1)



# Archived v0.1.1 runtime contracts still run against its unchanged publisher.
pub011 = load_publisher("publish_011", "0.1.1")
class GitHubReadContracts011(GitHubReadContractsMixin, unittest.TestCase):
    pub = pub011
class ArtifactDownloadContracts011(ArtifactDownloadContractsMixin, unittest.TestCase):
    pub = pub011

class PublishSequenceContracts011(PublishSequenceContractsMixin, unittest.TestCase):
    pub = pub011



class GitHubReadContracts013(GitHubReadContractsMixin, unittest.TestCase):
    pub = pub013


class ArtifactDownloadContracts013(ArtifactDownloadContractsMixin, unittest.TestCase):
    pub = pub013


class PublishSequenceContracts013(PublishSequenceContractsMixin, unittest.TestCase):
    pub = pub013


class Release013Contracts(unittest.TestCase):
    def test_current_version_assets_notes_and_job(self):
        self.assertEqual(pub013.VERSION, "0.1.3")
        self.assertEqual(pub013.PACKAGE_VERSION, "0.1.3-r1")
        names = pub013.expected_asset_names()
        self.assertEqual(len(names), 18)
        self.assertIn("openwrt-recovery-v0.1.3.tar.gz", names)
        notes = (ROOT / pub013.NOTES).read_text()
        self.assertTrue(notes.startswith("# diversion-dns-c v0.1.3\n"))
        for name in names:
            self.assertIn(name, notes)
        self.assertEqual(len(pub013.BUILD_JOBS + pub013.APK_JOBS + pub013.SUITE_JOBS), 10)
        self.assertEqual(set(pub013.BUILD_JOBS[-2:]), {"Real kernel / GCC 14", "delivery"})
        workflow = (ROOT / ".github/workflows/build.yml").read_text().split("  release-013:\n", 1)[1]
        for token in ("needs: [native, static, delivery]", "refs/heads/main", "cancel-in-progress: false",
                      "persist-credentials: false", "contents: write", "python3 scripts/publish-v0.1.3.py"):
            self.assertIn(token, workflow)
        source = (ROOT / "scripts/publish-v0.1.3.py").read_text()
        for token in ('"--clobber"', '"force": True', '"--prerelease"'):
            self.assertNotIn(token, source)

    def state(self, workflow="test-suite.yml", **changes):
        return {"id": 13, "head_sha": "a" * 40, "head_branch": "main", "event": "push", "run_attempt": 1,
                "path": ".github/workflows/" + workflow, "status": "completed", "conclusion": "success", **changes}

    def test_wait_requires_unique_successful_exact_main_push(self):
        row = self.state()
        with mock.patch.object(pub013, "api", return_value={"total_count": 1, "workflow_runs": [row]}):
            self.assertEqual(pub013.wait_workflow("test-suite.yml", "a" * 40, 1), row)
        for rows, total in (([row, row], 2), ([self.state(conclusion="failure")], 1),
                            ([self.state(path="wrong")], 1), ([self.state(head_sha="b" * 40)], 1),
                            ([self.state(event="pull_request")], 1), ([self.state(head_branch="feature")], 1),
                            ([self.state(status="in_progress")], 1), ([], 101)):
            with self.subTest(rows=rows, total=total), mock.patch.object(pub013, "api", return_value={"total_count": total, "workflow_runs": rows}), \
                    mock.patch.object(pub013.time, "monotonic", return_value=2), mock.patch.object(pub013.time, "sleep") as sleep:
                with self.assertRaises(ValueError):
                    pub013.wait_workflow("test-suite.yml", "a" * 40, 1)
                sleep.assert_not_called()

    def test_final_recheck_rejects_suite_attempt_failure_or_identity_change(self):
        def states(change):
            def api(path):
                key = int(path.rsplit("/", 1)[1])
                workflow = {11: "build.yml", 12: "openwrt-apk.yml", 13: "test-suite.yml"}[key]
                return self.state(workflow, **(change if key == 13 else {}))
            return api
        for change in ({}, {"head_sha": "b" * 40}, {"run_attempt": 2}, {"conclusion": "failure"},
                       {"status": "in_progress"}, {"event": "pull_request"}, {"path": "wrong"}, {"head_branch": "feature"}):
            with self.subTest(change=change), mock.patch.object(pub013, "api", side_effect=states(change)), \
                    mock.patch.object(pub013, "checked_jobs", return_value=[]) as checked:
                if change:
                    with self.assertRaisesRegex(ValueError, "CI run or attempt changed"):
                        pub013.recheck_ci("a" * 40, 11, 1, 12, 1, 13, 1)
                else:
                    pub013.recheck_ci("a" * 40, 11, 1, 12, 1, 13, 1)
                    self.assertEqual(checked.call_args_list, [mock.call(11, pub013.BUILD_JOBS),
                        mock.call(12, pub013.APK_JOBS), mock.call(13, pub013.SUITE_JOBS)])

    def test_other_version_never_reads_github(self):
        with publisher_source(pub012) as root, mock.patch.object(pub013, "ROOT", root), \
                mock.patch.dict(os.environ, main_env()), mock.patch.object(pub013, "run", return_value=("a" * 40).encode()), \
                mock.patch.object(pub013, "api") as api, mock.patch("builtins.print"):
            pub013.main()
            api.assert_not_called()


class RecoveryOverlayContracts(unittest.TestCase):
    commit, tree = "a" * 40, "b" * 40

    def files(self):
        return {name: ("immutable synthetic source: " + name).encode() for name in pub013.OVERLAY_FILES}

    def tar(self, entries):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w") as archive:
            for name, data, mode, kind in entries:
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.type = len(data), mode, kind
                if kind == tarfile.SYMTYPE:
                    member.linkname = "../not-allowed"
                archive.addfile(member, io.BytesIO(data))
        return raw.getvalue()

    def entries(self, files=None):
        return [(name, data, pub013.OVERLAY_FILES.get(name, 0o644), tarfile.REGTYPE)
                for name, data in (self.files() if files is None else files).items()]

    def test_source_is_exact_commit_git_archive_with_fixed_modes(self):
        raw = self.tar(self.entries())
        with mock.patch.object(pub013, "run", side_effect=[(self.tree + "\n").encode(), raw]) as run:
            self.assertEqual(pub013.recovery_source(self.commit), (self.tree, self.files()))
        self.assertEqual(run.call_args_list[1].args[0], ["git", "-C", pub013.ROOT, "-c", "tar.umask=0022",
                         "archive", "--format=tar", self.commit, "LICENSE", "deployment/openwrt-recovery"])

    def test_source_rejects_extra_missing_duplicate_symlink_and_changed_mode(self):
        original = self.entries()
        changes = [original + [("extra.sh", b"bad", 0o755, tarfile.REGTYPE)], original[:-1],
                   original + original[:1], [(original[0][0], b"bad", 0o644, tarfile.SYMTYPE)] + original[1:],
                   [(original[0][0], original[0][1], 0o777, tarfile.REGTYPE)] + original[1:]]
        for entries in changes:
            with self.subTest(entries=len(entries)), mock.patch.object(pub013, "run", side_effect=[self.tree.encode(), self.tar(entries)]):
                with self.assertRaises(ValueError):
                    pub013.recovery_source(self.commit)

    def test_archive_roundtrip_has_only_source_license_and_manifest(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(pub013, "recovery_source", side_effect=lambda commit: (self.tree, self.files())) as source:
            report = pub013.prepare_recovery_overlay(Path(temporary), self.commit)
            self.assertEqual(source.call_count, 2)  # writer plus independent read-back verifier
            path = Path(temporary) / pub013.OVERLAY_NAME
            self.assertEqual(report, pub013.verify_recovery_overlay(path, self.commit))
            self.assertEqual(report["manifest"]["commit"], self.commit)
            self.assertEqual(report["manifest"]["source_tree"], self.tree)
            self.assertEqual(set(report["manifest"]["files"]), set(pub013.OVERLAY_FILES))
            self.assertEqual(report["sha256"], pub013.a.digest(path.read_bytes()))
            with tarfile.open(path, "r:gz") as archive:
                self.assertEqual(set(archive.getnames()), set(pub013.OVERLAY_FILES) | {"manifest.json"})
                self.assertEqual(len(archive.getmembers()), 9)
                for member in archive:
                    self.assertTrue(member.isfile())
                    self.assertEqual(member.mode, pub013.OVERLAY_FILES.get(member.name, 0o644))
            with self.assertRaises(FileExistsError):
                pub013.prepare_recovery_overlay(Path(temporary), self.commit)

    def test_archive_rejects_payload_manifest_modes_and_membership_tampering(self):
        files = self.files()
        manifest = pub013.recovery_manifest(self.commit, self.tree, files)
        files["manifest.json"] = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
        entries = self.entries(files)
        cases = [entries[:-1], entries + [entries[0]], entries + [("../escape", b"bad", 0o644, tarfile.REGTYPE)],
                 [(entries[0][0], b"modified", 0o644, tarfile.REGTYPE)] + entries[1:],
                 [(entries[0][0], entries[0][1], 0o777, tarfile.REGTYPE)] + entries[1:],
                 [(entries[0][0], b"", 0o644, tarfile.SYMTYPE)] + entries[1:],
                 entries[:-1] + [("manifest.json", b"{}", 0o644, tarfile.REGTYPE)]]
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(pub013, "recovery_source", side_effect=lambda commit: (self.tree, self.files())):
            path = Path(temporary) / pub013.OVERLAY_NAME
            for i, changed in enumerate(cases):
                with self.subTest(case=i):
                    path.write_bytes(gzip.compress(self.tar(changed)))
                    with self.assertRaises(ValueError):
                        pub013.verify_recovery_overlay(path, self.commit)


class Release014Common(GitHubReadContractsMixin, PublishSequenceContractsMixin, ArtifactDownloadContractsMixin, unittest.TestCase):
    pub = pub014


class Release014Contracts(unittest.TestCase):
    def test_current_version_assets_and_job(self):
        self.assertEqual((ROOT / "VERSION").read_text().strip(), pub014.VERSION)
        self.assertEqual(pub014.PACKAGE_VERSION, "0.1.4-r1")
        self.assertIn(f'puts("{pub014.CLI_VERSION}")', (ROOT / "c/main.c").read_text())
        self.assertEqual(len(pub014.expected_asset_names()), 24)
        notes = (ROOT / pub014.NOTES).read_text()
        for name in pub014.expected_asset_names():
            self.assertIn(name, notes)
        workflow = (ROOT / ".github/workflows/build.yml").read_text().split("  release-014:\n", 1)[1]
        for token in ("needs: [native, static, delivery]", "refs/heads/main", "cancel-in-progress: false",
                      "persist-credentials: false", "contents: write", "python3 scripts/publish-v0.1.4.py"):
            self.assertIn(token, workflow)
        self.assertEqual(pub014.BUILD_JOBS + pub014.APK_JOBS + pub014.SUITE_JOBS,
                         pub013.BUILD_JOBS + pub013.APK_JOBS + pub013.SUITE_JOBS)


if __name__ == "__main__":
    unittest.main()
