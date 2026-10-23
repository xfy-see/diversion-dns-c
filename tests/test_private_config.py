import importlib.util,json,os,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('migration',ROOT/'scripts/migrate-private-config.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
OLD="local function expected_ip(id,af)\n if id=='usss' then return '198.51.100.13' end\nend\nlocal function public_probe() end\nlocal route='ip -4 route get 203.0.113.13 mark 512'"
QUERY="if source=='192.0.2.19' then\n downloader=rules:find('ether saddr 02:00:00:00:00:19',1,true)~=nil and rules:find('fixture bypass',1,true)~=nil and neighbor:find('lladdr 02:00:00:00:00:19',1,true)~=nil\nend"
class PrivateConfigTests(unittest.TestCase):
 def test_endpoint_is_not_egress(self):
  d=M.migrate(OLD,QUERY);self.assertEqual(d['usss']['ipv4'],'198.51.100.13');self.assertEqual(d['usss']['endpoint_ipv4'],'203.0.113.13');self.assertEqual(d['query_source']['ipv4'],'192.0.2.19')
 def test_existing_overrides_preserved(self):
  old={'usss':{'ipv4':'192.0.2.1','endpoint_ipv4':'192.0.2.2'},'aws':{'ipv6':'2001:db8::1'}}
  d=M.migrate(OLD,QUERY,old);self.assertEqual(d['usss'],old['usss']);self.assertEqual(d['aws'],old['aws']);self.assertNotIn('query_source',old)
 def test_ambiguous_missing_and_invalid_refused(self):
  for s in ['',OLD.replace('198.51.100.13','999.1.1.1'),OLD+"\nip -4 route get 203.0.113.14 mark 512"]:
   with self.assertRaises(ValueError):M.migrate(s)
  with self.assertRaises(ValueError):M.migrate(OLD,existing={'usss':{'endpoint_ipv4':'x;id'}})
 def test_private_mode_and_no_overwrite_or_symlink(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'expected-egress.json';d=M.migrate(OLD);M.write_new(p,d)
   self.assertEqual(p.stat().st_mode&0o777,0o600)
   with self.assertRaises(FileExistsError):M.write_new(p,{})
   self.assertEqual(json.loads(p.read_text()),d)
   link=Path(td)/'link';link.symlink_to(p)
   with self.assertRaises(FileExistsError):M.write_new(link,{})
   self.assertEqual(json.loads(p.read_text()),d)
