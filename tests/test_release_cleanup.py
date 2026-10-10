"""Offline cleanup safety tests; no network, binaries, builds or mutations."""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
spec = importlib.util.spec_from_file_location("cleanup_010", ROOT / "scripts/simplify-v0.1.0.py")
cleanup = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cleanup)
pub = cleanup.pub


def release():
    return {"id": cleanup.RELEASE_ID, "tag_name": pub.TAG, "target_commitish": pub.ORIGINAL_COMMIT,
            "draft": False, "prerelease": False, "published_at": "2026-10-10T09:49:54Z", "body": "original notes"}


def asset_rows(ids=None):
    return [dict(cleanup.PINNED[i], state="uploaded") for i in (ids if ids is not None else cleanup.PINNED)]


class CleanupPolicyTests(unittest.TestCase):
    def test_exact_fixed_scope(self):
        self.assertEqual(cleanup.RELEASE_ID, 408852981)
        self.assertEqual(pub.ORIGINAL_COMMIT, "96f7d7dd11ce4f4eb937d29b7371c10c138825f6")
        self.assertEqual(cleanup.KEEP, {627587452, 627587466})
        self.assertEqual(len(cleanup.REMOVE), 15)
        self.assertTrue(all(cleanup.PINNED[i]["name"].endswith(".apk") for i in cleanup.KEEP))
        self.assertFalse(any(cleanup.PINNED[i]["name"].endswith(".apk") for i in cleanup.REMOVE))

    def test_full_partial_and_complete_states(self):
        for ids in (set(cleanup.PINNED), cleanup.KEEP | {min(cleanup.REMOVE)}, cleanup.KEEP):
            with mock.patch.object(pub, "api", side_effect=[release(), asset_rows(ids)]):
                self.assertEqual(cleanup.state()[1], ids)

    def test_unknown_duplicate_replaced_or_missing_assets_fail(self):
        cases = []
        rows = asset_rows(); cases.append(rows + [dict(rows[0], id=1)])
        rows = asset_rows(); cases.append(rows + [rows[0]])
        cases.append(asset_rows(set(cleanup.PINNED) - {min(cleanup.KEEP)}))
        for key, value in (("id", 1), ("name", "other.apk"), ("size", 1), ("digest", "sha256:" + "0" * 64), ("state", "starter")):
            rows = asset_rows(); rows[0][key] = value; cases.append(rows)
        for rows in cases:
            with self.subTest(rows=rows[0]), mock.patch.object(pub, "api", side_effect=[release(), rows]):
                with self.assertRaises(ValueError):
                    cleanup.state()

    def test_wrong_release_tag_commit_or_visibility_fail(self):
        for key, value in (("id", 1), ("tag_name", "v0.2.0"), ("target_commitish", "a" * 40),
                           ("draft", True), ("prerelease", True), ("published_at", None)):
            changed = release(); changed[key] = value
            with mock.patch.object(pub, "api", return_value=changed):
                with self.assertRaisesRegex(ValueError, "identity differs"):
                    cleanup.state()

    def test_publisher_accepts_only_original_apk_metadata(self):
        pub.validate_original_apks(asset_rows(cleanup.KEEP))
        for rows in (asset_rows(), asset_rows({min(cleanup.KEEP)}),
                     [dict(row, digest="sha256:" + "0" * 64) for row in asset_rows(cleanup.KEEP)]):
            with self.assertRaisesRegex(ValueError, "exactly the two original APKs"):
                pub.validate_original_apks(rows)

    def test_upload_selection_keeps_evidence_local(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            for name in list(pub.APK_ASSETS) + ["SHA256SUMS", "release-verification.json", "bundle.tar.gz"]:
                (directory / name).write_bytes(b"not executable")
            self.assertEqual({p.name for p in pub.upload_selection(directory)}, set(pub.APK_ASSETS))
            (directory / next(iter(pub.APK_ASSETS))).unlink()
            with self.assertRaisesRegex(ValueError, "both release APKs"):
                pub.upload_selection(directory)

    def test_noop_verifies_bytes_but_never_mutates(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.dict(os.environ, {"GITHUB_OUTPUT": temporary + "/output"}), \
                mock.patch.object(cleanup, "identity", return_value=("a" * 40, 1, 1)), \
                mock.patch.object(cleanup, "state", return_value=(release(), cleanup.KEEP)), \
                mock.patch.object(cleanup, "download", return_value=b"verified") as download, \
                mock.patch.object(cleanup, "required_builds") as builds, \
                mock.patch.object(pub, "run") as command:
            cleanup.prepare()
            self.assertEqual({c.args[0] for c in download.call_args_list}, cleanup.KEEP)
            builds.assert_not_called(); command.assert_not_called()
            self.assertEqual(Path(temporary, "output").read_text(), "needed=false\n")

    def test_workflow_archives_before_deletion_and_gates_to_main(self):
        workflow = (ROOT / ".github/workflows/build.yml").read_text().split("  release-010:\n", 1)[1]
        self.assertLess(workflow.index("simplify-v0.1.0.py prepare"), workflow.index("id: cleanup-backup"))
        self.assertLess(workflow.index("id: cleanup-backup"), workflow.index("simplify-v0.1.0.py apply"))
        self.assertLess(workflow.index("simplify-v0.1.0.py apply"), workflow.index("publish-v0.1.0.py"))
        self.assertIn("steps.cleanup-backup.outputs.artifact-id", workflow)
        self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'", workflow)
        self.assertIn("github.repository == 'xfy-see/diversion-dns-c'", workflow)
        self.assertIn("needs: [native, static, delivery]", workflow)
        self.assertNotIn("pull-requests: write", workflow)

    def test_pr_and_wrong_repo_fail_before_network(self):
        for override in ({"GITHUB_EVENT_NAME": "pull_request"}, {"GITHUB_REF": "refs/heads/feature"},
                         {"GITHUB_REPOSITORY": "other/repo"}):
            env = {"GITHUB_REPOSITORY": pub.REPO, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "push", **override}
            with mock.patch.dict(os.environ, env), mock.patch.object(pub, "api") as api, mock.patch.object(pub, "run") as command:
                with self.assertRaisesRegex(ValueError, "main push"):
                    cleanup.identity()
                api.assert_not_called(); command.assert_not_called()


class ApplyTests(unittest.TestCase):
    def invoke(self, *, initial=None, bad_backup=False, changed_body=False, fail_delete=False, edit_during_download=False):
        ids = set(cleanup.PINNED) if initial is None else set(initial)
        current = set(ids)
        notes = (ROOT / "docs/release-v0.1.0.md").read_text()
        live = release()
        receipt = {"prior_body": live["body"]}
        if changed_body:
            live["body"] = "intervening edit"
        commands = []
        def state():
            return copy.deepcopy(live), set(current)
        def run(argv, **kwargs):
            commands.append(argv)
            if "DELETE" in argv:
                asset_id = int(argv[2].rsplit("/", 1)[1])
                self.assertIn(asset_id, cleanup.REMOVE)
                self.assertNotIn(asset_id, cleanup.KEEP)
                if not fail_delete:
                    current.remove(asset_id)
            elif "PATCH" in argv:
                self.assertEqual(argv[2], f"repos/{pub.REPO}/releases/{cleanup.RELEASE_ID}")
                self.assertEqual(json.loads(kwargs["input"]), {"body": notes})
                live["body"] = notes
            else:
                raise AssertionError(argv)
            return b""
        downloads = []
        def download(asset_id):
            downloads.append(asset_id)
            if edit_during_download and len(downloads) == 4:
                live["body"] = "concurrent external edit"
            return b"verified"
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(cleanup, "BACKUP", Path(temporary) / "backup"), \
                mock.patch.dict(os.environ, {"CLEANUP_BACKUP_ARTIFACT_ID": "1"}), \
                mock.patch.object(cleanup, "identity", return_value=("a" * 40, 1, 1)), \
                mock.patch.object(cleanup, "required_builds"), \
                mock.patch.object(cleanup, "verify_backup", side_effect=ValueError("bad backup") if bad_backup else None,
                                  return_value=(receipt, ids)), \
                mock.patch.object(cleanup, "state", side_effect=state), \
                mock.patch.object(cleanup, "download", side_effect=download), \
                mock.patch.object(pub, "run", side_effect=run):
            error = None
            try:
                cleanup.apply()
            except ValueError as exc:
                error = str(exc)
        return commands, current, error

    def test_exact_15_deletes_then_body_update(self):
        commands, current, error = self.invoke()
        self.assertIsNone(error)
        self.assertEqual(current, cleanup.KEEP)
        self.assertEqual({int(c[2].rsplit("/", 1)[1]) for c in commands if "DELETE" in c}, cleanup.REMOVE)
        self.assertEqual(len(commands), 16)
        self.assertIn("PATCH", commands[-1])

    def test_partial_retry_deletes_only_remaining_pinned_extras(self):
        remaining = {min(cleanup.REMOVE)}
        commands, current, error = self.invoke(initial=cleanup.KEEP | remaining)
        self.assertIsNone(error)
        self.assertEqual(current, cleanup.KEEP)
        self.assertEqual(len(commands), 2)

    def test_backup_or_intervening_notes_failure_prevents_mutations(self):
        for kwargs in ({"bad_backup": True}, {"changed_body": True}):
            commands, current, error = self.invoke(**kwargs)
            self.assertIsNotNone(error)
            self.assertEqual(commands, [])
            self.assertEqual(current, set(cleanup.PINNED))

    def test_notes_edit_during_final_download_is_not_overwritten(self):
        commands, current, error = self.invoke(edit_during_download=True)
        self.assertIn("release notes changed", error)
        self.assertFalse(any("PATCH" in command for command in commands))
        self.assertEqual(current, cleanup.KEEP)

    def test_last_delete_then_interruption_can_repair_notes(self):
        commands, current, error = self.invoke(initial=cleanup.KEEP)
        self.assertIsNone(error)
        self.assertEqual(current, cleanup.KEEP)
        self.assertEqual(len(commands), 1)
        self.assertIn("PATCH", commands[0])

    def test_unconfirmed_deletion_fails_without_patching_notes(self):
        commands, current, error = self.invoke(fail_delete=True)
        self.assertIn("deletion not confirmed", error)
        self.assertEqual(len(commands), 1)
        self.assertEqual(current, set(cleanup.PINNED))


class BackupArchiveTests(unittest.TestCase):
    def test_uploaded_archive_must_match_identity_members_receipt_and_bytes(self):
        for fault in (None, "digest", "run", "head", "name", "expired", "size", "missing", "extra", "duplicate", "receipt", "payload"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory() as temporary:
                commit, run_id, attempt = "a" * 40, 1, 1
                content = b"synthetic backup fixture, never executable"
                pins = {i: dict(cleanup.PINNED[i], size=len(content), digest="sha256:" + pub.a.digest(content))
                        for i in cleanup.KEEP | {min(cleanup.REMOVE)}}
                rows = list(pins.values())
                receipt = {"release_id": cleanup.RELEASE_ID, "tag_commit": pub.ORIGINAL_COMMIT,
                           "workflow_commit": commit, "run_id": run_id, "attempt": attempt, "assets": rows}
                receipt_path = Path(temporary) / "cleanup-receipt.json"
                receipt_path.write_text(json.dumps(receipt))
                stream = io.BytesIO()
                with zipfile.ZipFile(stream, "w") as archive:
                    archive.writestr(receipt_path.name, b"changed" if fault == "receipt" else receipt_path.read_bytes())
                    for index, row in enumerate(rows):
                        if fault == "missing" and index == 0:
                            continue
                        archive.writestr(row["name"], b"x" * len(content) if fault == "payload" else content)
                    if fault == "extra":
                        archive.writestr("extra", b"not expected")
                    if fault == "duplicate":
                        import warnings
                        with warnings.catch_warnings():
                            warnings.simplefilter("ignore", UserWarning)
                            archive.writestr(rows[0]["name"], content)
                data = stream.getvalue()
                artifact = {"name": f"release-v0.1.0-cleanup-backup-{commit}-attempt-{attempt}",
                            "workflow_run": {"id": 2 if fault == "run" else run_id, "head_sha": "b" * 40 if fault == "head" else commit},
                            "expired": fault == "expired", "size_in_bytes": len(data) + (1 if fault == "size" else 0),
                            "digest": "sha256:" + ("0" * 64 if fault == "digest" else pub.a.digest(data))}
                if fault == "name":
                    artifact["name"] = "other-backup"
                with mock.patch.object(cleanup, "PINNED", pins), mock.patch.object(cleanup, "RECEIPT", receipt_path), \
                        mock.patch.dict(os.environ, {"CLEANUP_BACKUP_ARTIFACT_ID": "12"}), \
                        mock.patch.object(pub, "api", return_value=artifact), mock.patch.object(pub, "run", return_value=data):
                    if fault:
                        with self.assertRaises(ValueError):
                            cleanup.verify_backup(commit, run_id, attempt)
                    else:
                        actual, ids = cleanup.verify_backup(commit, run_id, attempt)
                        self.assertEqual(actual, receipt)
                        self.assertEqual(ids, set(pins))

    def test_prepare_repairs_original_notes_after_all_deletes(self):
        live = release()
        with tempfile.TemporaryDirectory() as temporary:
            backup = Path(temporary) / "backup"
            output = Path(temporary) / "output"
            with mock.patch.object(cleanup, "BACKUP", backup), \
                    mock.patch.object(cleanup, "RECEIPT", backup / "cleanup-receipt.json"), \
                    mock.patch.object(cleanup, "identity", return_value=("a" * 40, 1, 1)), \
                    mock.patch.object(cleanup, "state", return_value=(live, cleanup.KEEP)), \
                    mock.patch.object(cleanup, "required_builds") as builds, \
                    mock.patch.object(cleanup, "download", return_value=b"already verified"), \
                    mock.patch.dict(pub.PINNED, {"original_body_sha256": pub.a.digest(live["body"].encode())}), \
                    mock.patch.dict(os.environ, {"GITHUB_OUTPUT": str(output)}):
                cleanup.prepare()
                self.assertEqual(output.read_text(), "needed=true\n")
                self.assertTrue((backup / "cleanup-receipt.json").exists())
                builds.assert_called_once()


if __name__ == "__main__":
    unittest.main()
