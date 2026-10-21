#!/usr/bin/env python3
"""Scan published inputs; diagnostics never echo matched values.

Default scans tracked working files. --staged scans Git index bytes, --ref scans
an exact commit tree, and --text-file checks prepared PR/release prose. Historical
secrets require separate remediation: a clean current tree cannot erase history.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess

ROOT=Path(__file__).resolve().parents[1]
RULES={
 'private-key':re.compile(rb'-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----'),
 'provider-token':re.compile(rb'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{20,}|sk-[A-Za-z0-9_-]{30,})\b'),
 'literal-secret':re.compile(rb'(?im)\b(?:PrivateKey|PresharedKey|private_key|preshared_key|api_key|access_token|client_secret)\b["\x27]?\s*[:=]\s*["\x27]?[A-Za-z0-9+/=_-]{24,}'),
 'personal-path':re.compile(rb'/(?:Users|home)/(?!runner(?:/|\b)|user(?:/|\b)|example(?:/|\b))[A-Za-z0-9_.-]+'),
 'private-email':re.compile(rb'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]*privaterelay\.[A-Za-z.]+'),
 'ddns-host':re.compile(rb'\b[A-Za-z0-9.-]+\.(?:synology\.me|duckdns\.org|ddns\.net)\b'),
}
IP4=re.compile(rb'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])')
IP6=re.compile(rb'(?<![\w:])(?:[A-Fa-f0-9]{0,4}:){2,}[A-Fa-f0-9:.]*(?![\w:])')
MAC=re.compile(rb'(?<![\w:])(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}(?![\w:])')
SAFE_NETS=[ipaddress.ip_network(x) for x in ('0.0.0.0/8','127.0.0.0/8','192.0.2.0/24','198.51.100.0/24','203.0.113.0/24','198.18.0.0/15','224.0.0.0/4','255.255.255.255/32','::/128','::1/128','2001:db8::/32','3fff::/20','fe80::/10','fc00::/7','ff00::/8')]
# Public DNS services and generic lab networks are deliberate, reviewed literals.
SERVICE_IPS={'1.1.1.1','1.0.0.1','8.8.8.8','9.9.9.9','223.5.5.5','119.29.29.29','2606:4700:4700::1111','2606:4700:4700::1001'}
LAB_NETS=[ipaddress.ip_network(x) for x in ('10.0.0.0/24','192.168.50.0/24')]
SENSITIVE_PATH=re.compile(r'(?i)(?:^|/)(?:\.env(?:\..*)?|id_rsa(?:\..*)?|id_ed25519(?:\..*)?|known_hosts(?:\..*)?|expected-egress\.json|credentials(?:\..*)?)$|\.(?:pcap(?:ng)?|pem|p12|pfx|key)$|^(?:validation|private|private-artifacts)/')


def git(root,*args):return subprocess.check_output(['git','-C',str(root),*args])


def allowed_ip(address,path,policy):
 if address.version==6 and address.ipv4_mapped is not None:return allowed_ip(address.ipv4_mapped,path,policy)
 if str(address) in SERVICE_IPS:return True
 if any(address.version==net.version and address in net for net in SAFE_NETS+LAB_NETS):return True
 return str(address) in policy.get(path,{})


def scan(path,data,policy=None):
 policy=policy or {};hits=[]
 def hit(rule,start):hits.append({'path':path,'line':data.count(b'\n',0,start)+1,'rule':rule})
 if SENSITIVE_PATH.search(path) and not path.endswith('.example'):hit('private-file',0)
 for name,rx in RULES.items():
  for m in rx.finditer(data):hit(name,m.start())
 for rx in (IP4,IP6):
  for m in rx.finditer(data):
   try:a=ipaddress.ip_address(m[0].decode())
   except ValueError:continue
   if not allowed_ip(a,path,policy):hit('unreviewed-address',m.start())
 for m in MAC.finditer(data):
  if not m[0].lower().startswith(b'02:00:00:') and m[0].lower() not in (b'00:00:00:00:00:00',b'ff:ff:ff:ff:ff:ff'):hit('device-mac',m.start())
 return [dict(t) for t in dict.fromkeys(tuple(h.items()) for h in hits)]


def inputs(root,ref=None,staged=False):
 if ref:
  for row in git(root,'ls-tree','-rz','--full-tree',ref).split(b'\0'):
   if not row:continue
   meta,path=row.split(b'\t',1);mode,kind,oid=meta.split()
   if kind!=b'blob':continue
   yield path.decode(),git(root,'cat-file','blob',oid.decode())
 elif staged:
  for row in git(root,'ls-files','--stage','-z').split(b'\0'):
   if not row:continue
   meta,path=row.split(b'\t',1);mode,oid,stage=meta.split()
   if stage!=b'0':raise ValueError('unmerged index')
   yield path.decode(),git(root,'cat-file','blob',oid.decode())
 else:
  for name in git(root,'ls-files','-z').split(b'\0'):
   if not name:continue
   p=root/name.decode()
   if p.is_symlink():yield name.decode(),str(p.readlink()).encode()
   elif p.is_file():yield name.decode(),p.read_bytes()


def main():
 p=argparse.ArgumentParser(description=__doc__);g=p.add_mutually_exclusive_group()
 g.add_argument('--ref');g.add_argument('--staged',action='store_true');g.add_argument('--text-file',type=Path)
 p.add_argument('--root',type=Path,default=ROOT);p.add_argument('--json',action='store_true');a=p.parse_args()
 try:
  files=[(a.text_file.name,a.text_file.read_bytes())] if a.text_file else list(inputs(a.root,a.ref,a.staged))
  policy_data=next((data for name,data in files if name=='tests/fixtures/privacy-allowlist.json'),b'{}')
  policy=json.loads(policy_data);hits=[]
  for name,data in files:hits.extend(scan(name,data,policy))
 except (OSError,ValueError,subprocess.CalledProcessError):p.exit(2,'Privacy scan could not read all requested inputs.\n')
 print(json.dumps({'files':len(files),'findings':hits},indent=2) if a.json else '\n'.join([f'{x["path"]}:{x["line"]}: {x["rule"]}' for x in hits]+[f'Privacy scan: {len(files)} files, {len(hits)} findings.']))
 return bool(hits)
if __name__=='__main__':raise SystemExit(main())
