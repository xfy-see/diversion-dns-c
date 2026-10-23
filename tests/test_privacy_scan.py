import importlib.util,json,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('privacy',ROOT/'scripts/privacy_scan.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class PrivacyScanTests(unittest.TestCase):
 def test_sensitive_values_are_detected_and_never_echoed(self):
  values=[b'-----BEGIN '+b'OPENSSH PRIVATE KEY-----',b'ghp_'+b'x'*36,b'PrivateKey='+b'A'*43+b'=',b'/Users/'+b'person/private',b'person@'+b'privaterelay.appleid.com',b'host.'+b'synology.me']
  for value in values:
   hits=M.scan('sample.txt',value);self.assertTrue(hits)
   self.assertNotIn(value.decode(),json.dumps(hits))
 def test_local_global_and_mac_not_silently_allowed(self):
  for value in [bytes([55,55,46,56,56,46,57,57,46,49]),bytes([49,57,50,46,49,54,56,46,56,56,46,49]),bytes.fromhex('323030313a343836303a3a3838'),b'aa:bb:'+b'cc:dd:ee:ff']:
   self.assertTrue(M.scan('sample',value))
 def test_documentation_and_service_addresses(self):
  for value in [b'192.0.2.1',b'2001:db8::1',b'::ffff:192.0.2.128',b'1.1.1.1',b'3fff::9',b'02:00:00:00:00:19']:
   self.assertEqual(M.scan('sample',value),[])
 def test_private_paths_detected_even_without_secret_contents(self):
  for name in ['.env','private/config.json','validation/result.json','id_rsa','capture.pcap','expected-egress.json']:
   self.assertTrue(M.scan(name,b'{}'))
 def test_staged_content_cannot_be_hidden_by_working_copy(self):
  with tempfile.TemporaryDirectory() as td:
   r=Path(td);subprocess.run(['git','init','-q',td],check=True)
   p=r/'sample';p.write_bytes(b'ghp_'+b'x'*36);subprocess.run(['git','-C',td,'add','sample'],check=True);p.write_text('clean')
   self.assertEqual(M.scan(*next(M.inputs(r))),[])
   self.assertTrue(M.scan(*next(M.inputs(r,staged=True))))
 def test_policy_matches_exact_path_and_address(self):
  value='77'+'.88.99.1';policy={'fixture':{value:'controlled synthetic parser input'}}
  self.assertEqual(M.scan('fixture',value.encode(),policy),[])
  self.assertTrue(M.scan('runtime',value.encode(),policy))
