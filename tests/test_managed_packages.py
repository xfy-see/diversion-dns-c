"""Managed APK payload and lifecycle checks; no compiler or device access."""
import importlib.util,json,re,subprocess,tempfile,unittest,os,signal,time
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
   self.assertEqual((roots[M.UI]/'usr/share/diversion-dns-ui/device.lua').stat().st_mtime,0)
   self.assertIn('nftables',M.CORE_DEPS)
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
 def test_frozen_payload_evidence_and_tamper_rejection(self):
  with tempfile.TemporaryDirectory() as td:
   base=Path(td);binary=base/'elf';binary.write_bytes(b'ELF fixture');commit='a'*40
   roots=M.stage(ROOT,binary,base/'roots',commit);version='0.1.3_pre20261019~'+commit[:12]+'-r1'
   managed={'source_commit':commit,'version':version,'packages':{}}
   files={'apk-metadata.json':json.dumps({'paths':[{'name':'usr/sbin','files':[{'name':'diversion-dns-c-lite','hash':M.sha(binary.read_bytes()),'size':binary.stat().st_size}]}]}).encode()};commands={};logs={}
   source={str(p.relative_to(ROOT)):p.read_bytes() for p in (ROOT/'packaging/managed').rglob('*') if p.is_file()}
   for name,root in roots.items():
    arch='mipsel_24kc' if name==M.CORE else 'noarch';deps=M.CORE_DEPS if name==M.CORE else [M.CORE+'='+version]+M.UI_DEPS
    expected=M.contents(root);filename=name+'-'+version+'_'+arch+'.apk';files[filename]=b'container fixture'
    managed['packages'][name]={'filename':filename,'sha256':M.sha(files[filename]),'bytes':len(files[filename]),'arch':arch,'depends':deps,'files':expected}
    prefix='core' if name==M.CORE else 'ui'
    meta={'info':{'name':name,'arch':arch,'version':version,'depends':deps,'installed-size':sum(x['bytes'] for x in expected.values())},'paths':[],'scripts':{p.name.split('.',1)[1]:p.read_text() for p in (ROOT/'packaging/managed/hooks').glob(prefix+'.*')}}
    for path,row in expected.items():
     meta['paths'].append({'name':str(Path(path).parent),'acl':{'user':'root','group':'root'},'files':[{'name':Path(path).name,'size':row['bytes'],'hash':row['sha256'],'acl':{'mode':row['mode'],'user':'root','group':'root'}}]})
    files[name+'-metadata.json']=json.dumps(meta).encode();logs['managed-metadata-'+name]=json.dumps(meta)
    commands['managed-pack-'+name]=['sudo','sh','-ec',M.ROOT_OWNER_SCRIPT]
    for step in ('metadata','integrity','extract'):commands['managed-'+step+'-'+name]=['apk',step,filename]
   files['managed-packages.json']=json.dumps(managed).encode();state={'managed':managed,'source_commit':commit,'application_version':'0.1.3','architecture':'mipsel_24kc'}
   M.verify_evidence(files,state,source,commands,logs)
   managed['packages'][M.UI]['files']['usr/share/diversion-dns-ui/device.lua']['sha256']='0'*64
   files['managed-packages.json']=json.dumps(managed).encode()
   with self.assertRaisesRegex(ValueError,'source payload'):M.verify_evidence(files,state,source,commands,logs)
 def test_init_nft_is_opt_in_and_failure_prevents_listener(self):
  for enabled,nft_ok,cpu in [(False,True,4),(True,True,4),(True,False,4),(True,True,65)]:
   with self.subTest(enabled=enabled,nft_ok=nft_ok),tempfile.TemporaryDirectory() as td:
    root=Path(td);(root/'etc/diversion-dns').mkdir(parents=True);(root/'usr/libexec').mkdir(parents=True);(root/'bin').mkdir()
    (root/'etc/diversion-dns/config.conf').write_text('fixture')
    (root/'etc/diversion-dns/nft-init.nft').write_text('fixture')
    fake=root/'usr/libexec/diversion-dns-c';fake.write_text('#!/bin/sh\nexit 0\n');fake.chmod(0o755)
    nft=root/'bin/nft';nft.write_text('#!/bin/sh\necho nft >> "'+str(root/'calls')+'"\nexit '+('0' if nft_ok else '1')+'\n');nft.chmod(0o755)
    source=(ROOT/'packaging/managed/core.init').read_text().replace('/usr/libexec/',str(root)+'/usr/libexec/').replace('/etc/diversion-dns/',str(root)+'/etc/diversion-dns/')
    setup='config_load() { :; }\nconfig_get_bool() { if [ "$1" = enabled ]; then enabled=1; else nft_init=NSTEP; fi; }\nconfig_get() { case "$1" in config_file) config_file="$4";; cpu) cpu=4;; memory_limit) memory_limit=67108864;; cache_stats) cache_stats=60;; esac; }\nprocd_open_instance() { echo open >> "TRACE"; }\nprocd_close_instance() { echo close >> "TRACE"; }\nprocd_set_param() { echo "set $*" >> "TRACE"; }\nprocd_append_param() { echo "append $*" >> "TRACE"; }\n'.replace('NSTEP','1' if enabled else '0').replace('TRACE',str(root/'calls')).replace('cpu=4','cpu='+str(cpu))
    import os
    env=dict(os.environ,PATH=str(root/'bin')+':'+os.environ['PATH'])
    proc=subprocess.run(['sh','-c',setup+source+'\nstart_service\n'],capture_output=True,text=True,env=env)
    calls=(root/'calls').read_text() if (root/'calls').exists() else ''
    if (enabled and not nft_ok) or cpu>64:self.assertNotEqual(proc.returncode,0);self.assertNotIn('open',calls)
    else:
     self.assertEqual(proc.returncode,0,proc.stderr);self.assertIn('append command --cpu 4',calls);self.assertIn('append limits as=67108864',calls)
     if enabled:self.assertLess(calls.index('nft'),calls.index('open'))
     else:self.assertNotIn('nft',calls)
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
 def test_killed_preupgrade_does_not_leave_a_lock_blocking_the_next_upgrade(self):
  for name in ['core','ui']:
   with self.subTest(name=name),tempfile.TemporaryDirectory() as td:
    root=Path(td);(root/'etc/init.d').mkdir(parents=True);(root/'var/run').mkdir(parents=True);(root/'tmp').mkdir()
    service='diversion-dns'if name=='core'else'diversion-dns-ui';hold=root/'hold';hold.touch();entered=root/'entered'
    daemon=root/'etc/init.d'/service
    daemon.write_text('#!/bin/sh\nif [ "$1" = stop ]; then touch "'+str(entered)+'"; while [ -e "'+str(hold)+'" ]; do sleep 0.05; done; fi\nexit 0\n');daemon.chmod(0o755)
    rpc=root/'etc/init.d/rpcd';rpc.write_text('#!/bin/sh\nexit 0\n');rpc.chmod(0o755)
    def hook(phase):return re.sub(r'/(?:etc|var|tmp)/',lambda m:str(root)+m.group(),(ROOT/f'packaging/managed/hooks/{name}.{phase}').read_text())
    proc=subprocess.Popen(['sh','-c',hook('pre-upgrade')],start_new_session=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    try:
     deadline=time.monotonic()+3
     while not entered.exists()and time.monotonic()<deadline:time.sleep(.01)
     self.assertTrue(entered.exists());os.killpg(proc.pid,signal.SIGKILL);proc.communicate(timeout=3)
     self.assertFalse((root/f'var/run/{service}-package-upgrade.lock').exists())
     hold.unlink()
     for phase in ['pre-upgrade','post-upgrade']:subprocess.run(['sh','-c',hook(phase)],check=True,capture_output=True,timeout=3)
     self.assertFalse((root/f'var/run/{service}-package-upgrade').exists())
    finally:
     if proc.poll()is None:os.killpg(proc.pid,signal.SIGKILL);proc.communicate(timeout=3)
 def test_hooks_syntax_and_initial_install_do_not_enable_dns(self):
  for p in (ROOT/'packaging/managed/hooks').iterdir():subprocess.run(['sh','-n',p],check=True)
  self.assertFalse((ROOT/'packaging/managed/hooks/core.post-install').exists())
  self.assertNotIn(' enable',(ROOT/'packaging/managed/hooks/ui.post-install').read_text())
if __name__=='__main__':unittest.main()
