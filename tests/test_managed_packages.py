"""Managed APK payload and lifecycle checks; no compiler or device access."""
import importlib.util,json,re,subprocess,tempfile,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('managed',ROOT/'scripts/managed-packages.py');M=importlib.util.module_from_spec(spec);spec.loader.exec_module(M)
class ManagedPackage(unittest.TestCase):
 def test_stage_owns_only_its_paths_and_never_ships_network_controller(self):
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);binary=base/'elf';binary.write_bytes(b'not executable')
   roots=M.stage(ROOT,binary,base/'roots','a'*40)
   core=M.contents(roots[M.CORE]);ui=M.contents(roots[M.UI])
   self.assertEqual(core['usr/libexec/diversion-dns-c']['mode'],0o755)
   self.assertEqual(core['etc/config/diversion-dns']['mode'],0o600)
   self.assertFalse(set(core)&set(ui))
   self.assertNotIn('usr/share/diversion-dns-ui/control.lua',ui)
   self.assertNotIn('etc/config/network',core|ui);self.assertNotIn('etc/config/dhcp',core|ui)
   self.assertIn("option enabled '0'",(roots[M.CORE]/'etc/config/diversion-dns').read_text())
   self.assertIn("option enabled '0'",(roots[M.UI]/'etc/config/diversion-dns-ui').read_text())
   profile=json.loads((roots[M.UI]/'etc/diversion-dns-ui/profile.json').read_text());self.assertEqual(profile['device'],'generic')
   menu=json.loads((roots[M.UI]/'usr/share/luci/menu.d/luci-app-diversion-dns.json').read_text())
   for entry in menu.values():self.assertTrue((roots[M.UI]/('www/luci-static/resources/view/'+entry['action']['path']+'.js')).exists())
   with self.assertRaises(ValueError):M.stage(ROOT,binary,base/'roots','a'*40)
 def test_metadata_rejects_added_file_or_wrong_dep(self):
  expected={'usr/a':{'bytes':1,'sha256':'a'*64,'mode':0o755}}
  meta={'info':{'name':M.CORE,'arch':'mipsel_24kc','version':'1-r1','depends':['libc'],'installed-size':1},'paths':[{'name':'usr','acl':{'user':'root','group':'root'},'files':[{'name':'a','size':1,'hash':'a'*64,'acl':{'mode':0o755,'user':'root','group':'root'}}]}]}
  M.verify_metadata(meta,expected,M.CORE,'mipsel_24kc','1-r1',['libc'])
  meta['info']['depends'].append('unexpected')
  with self.assertRaisesRegex(ValueError,'dependency'):M.verify_metadata(meta,expected,M.CORE,'mipsel_24kc','1-r1',['libc'])
  meta['info']['depends']=['libc'];meta['paths'][0]['files'][0]['name']='other'
  with self.assertRaisesRegex(ValueError,'whitelist'):M.verify_metadata(meta,expected,M.CORE,'mipsel_24kc','1-r1',['libc'])
 def test_upgrade_only_restarts_previously_running_service(self):
  for name in ['core','ui']:
   for running in [False,True]:
    with self.subTest(name=name,running=running), tempfile.TemporaryDirectory() as td:
     root=Path(td);(root/'etc/init.d').mkdir(parents=True);(root/'var/run').mkdir(parents=True);(root/'tmp').mkdir()
     service='diversion-dns' if name=='core' else 'diversion-dns-ui'
     daemon=root/'etc/init.d'/service
     daemon.write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "'+str(root/'calls')+'"\nif [ "$1" = running ]; then '+('exit 0' if running else 'exit 1')+'; fi\n');daemon.chmod(0o755)
     rpc=root/'etc/init.d/rpcd';rpc.write_text('#!/bin/sh\nexit 0\n');rpc.chmod(0o755)
     for phase in ['pre-upgrade','post-upgrade']:
      script=(ROOT/f'packaging/managed/hooks/{name}.{phase}').read_text()
      script=re.sub(r'/(?:etc|var|tmp)/',lambda m:str(root)+m.group(),script)
      subprocess.run(['sh','-c',script],check=True,capture_output=True)
     calls=(root/'calls').read_text().splitlines();self.assertEqual(calls,['running','stop','start'] if running else ['running'])
     self.assertFalse((root/f'var/run/{service}-package-upgrade').exists())
 def test_hooks_syntax_and_initial_install_do_not_enable_dns(self):
  for p in (ROOT/'packaging/managed/hooks').iterdir():subprocess.run(['sh','-n',p],check=True)
  self.assertFalse((ROOT/'packaging/managed/hooks/core.post-install').exists())
  self.assertNotIn(' enable',(ROOT/'packaging/managed/hooks/ui.post-install').read_text())
if __name__=='__main__':unittest.main()
