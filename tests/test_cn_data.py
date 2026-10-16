"""Run the actual dependency-free Lua CN data engine against isolated nft doubles.

CI installs Lua 5.1. Local hosts without Lua skip this executable suite; device
kernel validation is separate and must run against a verified CI source artifact.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / 'deployment/openwrt-recovery/cn-data.lua'
LUA = os.environ.get('LUA_TEST_BIN') or shutil.which('lua5.1') or shutil.which('lua')
IP = ('119.29.0.0/16\n223.5.5.0/24\n' + ''.join(f'180.0.{i}.0/24\n' for i in range(8))
      + '2400:3200::/48\n' + ''.join(f'2401:db8:{i}::/48\n' for i in range(4)))
SITE = 'qq.com\nbaidu.com\n' + ''.join(f'domain{i}.cn\n' for i in range(8))
TEMPLATE = ('add table inet cn_test\n'
            'add set inet cn_test cn4 { type ipv4_addr; flags interval; auto-merge; }\n'
            'add set inet cn_test cn6 { type ipv6_addr; flags interval; auto-merge; }\n'
            'add set inet cn_test unrelated { type ipv4_addr; }\n'
            'add element inet cn_test unrelated { 198.51.100.1 }\n'
            'add element inet cn_test cn4 { 119.29.0.0/16 }\n'
            'add element inet cn_test cn6 { 2400:3200::/48 }\n')
NFT_DOUBLE = r'''
import ipaddress,json,os,pathlib,re,sys
root=pathlib.Path(os.environ['CN_TEST_ROOT']);statepath=root/'nft.json'
state=json.loads(statepath.read_text());args=sys.argv[1:]
with (root/'nft.calls').open('a') as f:f.write(json.dumps(args)+'\n')
if args[:1]==['-nn']:args=args[1:]
if args[:2]==['list','table']:
 sys.exit(0 if state.get('table',True) else 1)
if args[:2]==['list','set']:
 name=args[-1]
 if not state.get('table',True) or name not in state:sys.exit(1)
 fam=int(name[-1]);typ=state.get('badtype',f'ipv{fam}_addr')
 vals=list(ipaddress.collapse_addresses(ipaddress.ip_network(x) for x in state[name]))
 if state.get('as_ranges'):
  values=', '.join(str(v.network_address)+'-'+str(v.broadcast_address) for v in vals)
 else: values=', '.join(str(v) for v in vals)
 print(f'table inet cn_test {{\n set {name} {{\n type {typ};\n flags interval;\n auto-merge;\n elements = {{ {values} }}\n }}\n}}')
 sys.exit(0)
if '-f' in args:
 content=pathlib.Path(args[args.index('-f')+1]).read_text()
 if state.get('fail_check') and '-c' in args:sys.exit(1)
 if state.get('fail_apply') and '-c' not in args:sys.exit(1)
 if '-c' in args:sys.exit(0)
 for name in ('cn4','cn6'):
  if f'flush set inet cn_test {name}' in content:
   state[name]=[]
  for match in re.finditer(r'add element inet cn_test '+name+r' \{ ([^}]+) \}',content):
   state[name]+=match[1].split(', ')
 statepath.write_text(json.dumps(state));sys.exit(0)
sys.exit(90)
'''


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


@unittest.skipUnless(LUA, 'Lua runtime absent; CI and router runs execute these tests')
class CNDataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cn data '")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / 'bin'; self.bin.mkdir()
        nft = self.bin / 'nft'
        nft.write_text('#!' + sys.executable + '\n' + NFT_DOUBLE); nft.chmod(0o755)
        # macOS has shasum instead of sha256sum; this double computes real SHA256.
        sha = self.bin / 'sha256sum'
        sha.write_text('#!' + sys.executable + '\nimport hashlib,sys\n'
                       'print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()+"  "+sys.argv[1])\n')
        sha.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.bin)+os.pathsep+os.environ['PATH'],
                        CN_TEST_ROOT=str(self.root), DIVERSION_CN_TABLE='cn_test',
                        DIVERSION_CN_MIN4='2', DIVERSION_CN_MIN6='1', DIVERSION_CN_MINSITE='2')
        self.ip = self.root/'ip'; self.ip.write_text(IP)
        self.site = self.root/'site'; self.site.write_text(SITE)
        self.template = self.root/'sets'; self.template.write_text(TEMPLATE)
        self.state = {'cn4': [s for s in IP.splitlines() if ':' not in s],
                      'cn6': [s for s in IP.splitlines() if ':' in s], 'unrelated': ['198.51.100.1']}
        self.save_state()

    def save_state(self):
        (self.root/'nft.json').write_text(json.dumps(self.state))

    def invoke(self, *args, rc=0, env=None):
        p = subprocess.run([LUA, str(ENGINE), *map(str,args)], env=env or self.env,
                           text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(p.returncode, rc, p.stdout+p.stderr)
        return p

    def prepare(self, name='generation', baseline='-', rc=0, iphash=None, sitehash=None):
        out = self.root/name; out.mkdir()
        self.invoke('prepare', self.ip, self.site, self.template, baseline, out,
                    iphash or digest(self.ip), sitehash or digest(self.site), rc=rc)
        return out

    def test_prepare_verify_and_merged_kernel_equivalence(self):
        out=self.prepare()
        self.invoke('verify',out)
        self.invoke('audit',out)
        self.state['as_ranges']=True;self.save_state()
        self.invoke('audit',out)
        self.assertIn('unrelated { 198.51.100.1 }',(out/'sets.nft').read_text())
        self.assertNotIn('unrelated',(out/'replace.nft').read_text())

    def test_reordered_and_overlapping_intervals_compare_by_coverage(self):
        old=self.prepare()
        self.ip.write_text('\n'.join(reversed(IP.splitlines()))+'\n180.0.0.0/25\n')
        new=self.prepare('overlap',old)
        self.assertEqual((old/'ranges4.txt').read_bytes(),(new/'ranges4.txt').read_bytes())
        self.invoke('audit',new)
        self.ip.write_text(IP+'119.29.0.0/16\n')
        self.prepare('duplicate',old,rc=1)

    def test_valid_update_and_idempotent_template(self):
        old=self.prepare()
        self.template=old/'sets.nft'
        self.site.write_text(SITE+'new.cn\n')
        new=self.prepare('next',old)
        self.invoke('verify',new)
        self.assertEqual((new/'sets.nft').read_text(),(old/'sets.nft').read_text())

    def install_sort_double(self, body):
        sort=self.bin/'sort'
        sort.write_text('#!'+sys.executable+'\nimport os,pathlib,sys\n'+body)
        sort.chmod(0o755)

    def test_minimal_busybox_sort_without_output_option(self):
        # Reproduce the routers' reduced BusyBox: -o is ignored with exit 0,
        # and sorted data goes to stdout instead of creating the named output.
        self.install_sort_double(
            "args=sys.argv[1:]\n"
            "with (pathlib.Path(os.environ['CN_TEST_ROOT'])/'sort.calls').open('a') as f:f.write(repr(args)+'\\n')\n"
            "sys.stdout.write(''.join(sorted(pathlib.Path(args[-1]).read_text().splitlines(True))))\n")
        old=self.prepare()
        self.site.write_text(SITE+'new.cn\n')
        new=self.prepare('next',old)
        self.invoke('verify',new)
        calls=(self.root/'sort.calls').read_text()
        self.assertNotIn("'-o'",calls)

    def test_sort_failure_not_masked_by_status_marker(self):
        self.install_sort_double("sys.stdout.write(pathlib.Path(sys.argv[-1]).read_text())\nsys.exit(1)\n")
        out=self.prepare('failed-sort',rc=1)
        self.assertFalse((out/'manifest.tsv').exists())

    def test_successful_sort_with_empty_output_rejected(self):
        self.install_sort_double('sys.exit(0)\n')
        out=self.prepare('empty-sort',rc=1)
        self.assertFalse((out/'manifest.tsv').exists())

    def test_failed_download_and_empty_files(self):
        for target in (self.ip,self.site):
            before=target.read_bytes();target.write_bytes(b'')
            self.prepare('empty-'+target.name,rc=1);target.write_bytes(before)
        self.prepare('wrong-digest',rc=1,iphash='0'*64)

    def test_syntactic_truncation_and_missing_family(self):
        self.site.write_text(SITE.rstrip('\n'));self.prepare('unterminated',rc=1)
        self.site.write_text(SITE)
        self.ip.write_text('\n'.join(s for s in IP.splitlines() if ':' not in s)+'\n')
        self.prepare('no-ipv6',rc=1)

    def test_large_loss_and_same_size_replacement_rejected(self):
        old=self.prepare()
        self.site.write_text('qq.com\nbaidu.com\n');self.prepare('truncated',old,rc=1)
        self.site.write_text('qq.com\nbaidu.com\n'+''.join(f'replaced{i}.cn\n' for i in range(8)))
        self.prepare('replaced',old,rc=1)

    def test_unrelated_template_change_rejected(self):
        old=self.prepare()
        self.template.write_text(TEMPLATE.replace('198.51.100.1','198.51.100.2'))
        self.prepare('bad-template',old,rc=1)

    def test_malformed_injected_overbroad_and_foreign_prefixes(self):
        bad=['180.0.0.1/24','1.1.1.0/24','8.8.8.0/24','0.0.0.0/0',
             '2400:::3200/32','2400::1::/32','2400:3200::1/48',
             '180.0.1.0/24;flush ruleset','256.0.0.0/24','180.0.01.0/24']
        for i,s in enumerate(bad):
            self.ip.write_text(IP+s+'\n');self.prepare('badip'+str(i),rc=1)

    def test_domain_canaries_and_unsupported_regex(self):
        for i,extra in enumerate(['com','google.com','regexp:.*','keyword:google','evil..cn','-evil.cn']):
            self.site.write_text(SITE+extra+'\n');self.prepare('badsite'+str(i),rc=1)
        self.site.write_text(SITE.replace('qq.com\n',''));self.prepare('no-qq',rc=1)
        self.site.write_text(SITE.replace('qq.com\n','full:qq.com\n'));self.prepare('qq-without-suffix',rc=1)

    def test_new_wide_suffix_and_coverage_jump_rejected(self):
        old=self.prepare()
        self.site.write_text(SITE+'newtld\n');self.prepare('new-tld',old,rc=1)
        self.site.write_text(SITE)
        self.ip.write_text(IP.replace('180.0.0.0/24','180.0.0.0/8'))
        self.prepare('coverage',old,rc=1)

    def test_payload_corruption_and_wrong_table_rejected(self):
        out=self.prepare()
        wrong=dict(self.env,DIVERSION_CN_TABLE='other')
        self.invoke('verify',out,rc=1,env=wrong)
        (out/'cn-site.txt').write_text('')
        self.invoke('verify',out,rc=1);self.invoke('repair',out,rc=1)
        self.assertFalse((self.root/'nft.calls').exists())

    def test_partial_flush_extra_address_and_missing_set_repaired(self):
        out=self.prepare()
        for mode in ('partial','flush','extra','missing'):
            if mode=='partial':self.state['cn4']=self.state['cn4'][1:]
            if mode=='flush':self.state['cn6']=[]
            if mode=='extra':self.state['cn4']+=['8.8.8.8/32']
            if mode=='missing':self.state.pop('cn6',None)
            self.save_state();self.invoke('audit',out,rc=2);self.invoke('repair',out)
            self.state=json.loads((self.root/'nft.json').read_text())
            self.assertEqual(self.state['unrelated'],['198.51.100.1'])

    def test_failed_nft_transaction_preserves_previous_elements(self):
        out=self.prepare();self.state['cn4']=self.state['cn4'][1:];self.state['fail_apply']=True
        self.save_state();before=(self.root/'nft.json').read_bytes()
        self.invoke('repair',out,rc=1)
        self.assertEqual(before,(self.root/'nft.json').read_bytes())

    def test_missing_table_or_wrong_type_is_unsafe(self):
        out=self.prepare();self.state['table']=False;self.save_state()
        self.invoke('repair',out,rc=1)
        self.state['table']=True;self.state['badtype']='integer';self.save_state()
        self.invoke('repair',out,rc=1)


if __name__ == '__main__':
    unittest.main()
