import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
import testsuite as t

class SuiteTests(unittest.TestCase):
    def test_catalog_valid_and_plan_is_not_pass(self):
        d=t.catalog()
        self.assertGreater(len(d['cases']),30)
        self.assertFalse(t.plan('release',d)['completed'])
        self.assertEqual(t.plan('portable',d)['status'],'planned')
    def test_report_modified_after_success_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp); t.dump(p/'result.json',dict(schema_version=1,status='pass',completed=True))
            t.dump(p/'evidence.json',t.inventory(p)); self.assertEqual(t.verify_report(p)['status'],'pass')
            t.dump(p/'result.json',dict(schema_version=1,status='pass',completed=False))
            with self.assertRaises(ValueError):t.verify_report(p)
    def test_report_traversal_and_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);(p/'result.json').symlink_to('/dev/null')
            t.dump(p/'evidence.json',{'result.json':{'bytes':0,'sha256':hashlib.sha256(b'').hexdigest()}})
            with self.assertRaises(ValueError):t.verify_report(p)
            t.dump(p/'evidence.json',{'result.json':{},'../escape':{}})
            with self.assertRaises((ValueError,KeyError)):t.verify_report(p)
    def test_missing_release_reports_not_green(self):
        rows=t.release_audit(dict(release=dict(expected_commit='a'*40)))
        self.assertTrue(rows);self.assertTrue(all(r['status']=='skip' for r in rows))
    def test_wrong_release_commit_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);t.dump(p/'result.json',dict(schema_version=1,status='pass',completed=True,profile='portable',identity={'commit':'b'*40}))
            t.dump(p/'evidence.json',t.inventory(p))
            with self.assertRaises(ValueError):t.release_audit(dict(release=dict(expected_commit='a'*40,required=['portable'],reports={'portable':tmp})))
    def test_wrong_artifact_run_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg=dict(artifact=dict(bundle=tmp,expected_commit='a'*40,expected_run_id=1,expected_run_attempt=1))
            with patch.object(t.artifacts,'verify_bundle',return_value=dict(commit='b'*40,run_id=1,run_attempt=1)):
                with self.assertRaisesRegex(ValueError,'wrong artifact commit'):t.verify_input(cfg)
    def test_wrong_report_type_cannot_pass_release(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);t.dump(p/'result.json',dict(schema_version=1,status='pass',completed=True,profile='portable',identity={'commit':'a'*40}))
            t.dump(p/'evidence.json',t.inventory(p))
            with self.assertRaisesRegex(ValueError,'profile mismatch'):
                t.release_audit(dict(release=dict(expected_commit='a'*40,required=['kernel'],reports={'kernel':tmp})))
    def test_one_report_cannot_satisfy_two_devices(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);t.dump(p/'result.json',dict(schema_version=1,status='pass',completed=True,profile='device-smoke',identity={'commit':'a'*40,'target_address':'192.168.50.122'}))
            t.dump(p/'evidence.json',t.inventory(p))
            with self.assertRaisesRegex(ValueError,'multiple release'):
                t.release_audit(dict(release=dict(expected_commit='a'*40,required=['device-smoke-122','device-smoke-131'],reports={'device-smoke-122':tmp,'device-smoke-131':tmp},expected_devices={'device-smoke-122':'192.168.50.122','device-smoke-131':'192.168.50.131'})))
    def test_invalid_config_retains_failure_record(self):
        import argparse
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);cfg=root/'bad.json';cfg.write_text('{')
            args=argparse.Namespace(config=cfg,output=root/'result',profile='network',execute_device=False)
            self.assertEqual(t.run(args),1)
            self.assertEqual(t.verify_report(root/'result')['status'],'fail')
    def test_duplicate_config_keys_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)/'input.json';p.write_text('{"a":1,"a":2}')
            with self.assertRaises(ValueError):t.load(p)

if __name__=='__main__':unittest.main()
