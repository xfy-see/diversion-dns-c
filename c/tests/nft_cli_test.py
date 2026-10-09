#!/usr/bin/env python3
"""Exercise actual add_target with a grammar child and test-only netlink transport.

Plain sets perform two real CLI inspections plus fake GETGEN/batch ACK; interval
sets retain the exact real subprocess argv/stdin path and never open a socket.

This catches the observed nft 1.1.6 quoted-identifier failure. It is not kernel
or device evidence: the root task separately verifies real nft acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CHILD = r'''#!/usr/bin/env python3
import ipaddress,json,os,re,sys
args=sys.argv[1:]; body=sys.stdin.read() if args==['-f','-'] else ''
with open(os.environ['NFT_TEST_LOG'],'a') as log:
 log.write(json.dumps({'argv':args,'stdin':body})+'\n')
def tokens(text):
 return re.findall(r'"[^"\n]*"|[{};,]|[^\s{};,]+',text)
def identifier(token):
 # Ordinary identifiers are distinct from quoted-string tokens here.
 return re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]{0,126}',token) is not None
def fail():
 print('Error: syntax error, unexpected quoted string or invalid identifier',file=sys.stderr)
 sys.exit(1)
table=os.environ['NFT_TEST_TABLE']; name=os.environ['NFT_TEST_SET']
family='inet'; kind=os.environ['NFT_TEST_TYPE']; interval=os.environ['NFT_TEST_INTERVAL']=='1'
if args[:4]==['-t','-nn','list','set']:
 t=tokens(' '.join(args[4:]))
 if len(t)!=3 or t[0]!=family or not identifier(t[1]) or not identifier(t[2]) or t[1:]!=[table,name]:fail()
 flags='flags interval;' if interval else 'flags timeout; timeout 30s;'
 print(f'table {family} {table} {{\n set {name} {{\n type {kind};\n {flags}\n }}\n}}')
elif args==['-f','-']:
 t=tokens(body)
 if len(t)<8 or t[:3]!=['add','element',family] or not identifier(t[3]) or not identifier(t[4]) or t[3:5]!=[table,name] or t[5]!='{' or t[-1]!='}':fail()
 expect_address=True
 for token in t[6:-1]:
  if not expect_address:
   if token!=',':fail()
  else:
   try:address=ipaddress.ip_network(token,strict=True) if interval else ipaddress.ip_address(token)
   except ValueError:fail()
   if address.version != (4 if kind=='ipv4_addr' else 6):fail()
  expect_address=not expect_address
 if expect_address:fail()
else:fail()
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--old-source', type=Path)
    parser.add_argument('--sanitize', action='store_true')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--driver', type=Path, help='Use an already compiled CI driver; never invoke cc')
    mode.add_argument('--compile-only', action='store_true')
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    if args.driver and args.old_source:
        parser.error('--driver and --old-source cannot be combined')
    compiler = None if args.driver else Path(shutil.which(os.environ.get('CC', 'cc'))).resolve()
    child = out / 'grammar-nft'
    child.write_text(CHILD); child.chmod(0o700)
    flags = ['-std=c11','-Wall','-Wextra','-Wpedantic','-Werror','-pthread','-D_POSIX_C_SOURCE=200809L','-D_DEFAULT_SOURCE','-I'+str(ROOT/'c/include')]
    if os.uname().sysname=='Darwin': flags += ['-I'+str(ROOT/'c/tests/nft_uapi')]
    if args.sanitize: flags += ['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    else: flags += ['-O2']
    env = os.environ.copy()
    if args.sanitize:
        env['ASAN_OPTIONS'] = 'detect_leaks=0:halt_on_error=1'
        env['UBSAN_OPTIONS'] = 'halt_on_error=1'
    commands = []
    def compile(binary, source=None):
        command = [str(compiler),*flags]
        if source: command += ['-DNFT_SOURCE="'+str(source.resolve())+'"']
        command += [str(ROOT/'c/tests/nft_cli_driver.c'),str(ROOT/'c/pkg/dns.c'),'-o',str(binary)]
        result = subprocess.run(command,capture_output=True,text=True,env=env)
        (out/(binary.name+'-build.stdout')).write_text(result.stdout)
        (out/(binary.name+'-build.stderr')).write_text(result.stderr)
        commands.append({'command':command,'exit':result.returncode})
        assert result.returncode==0,result.stderr
    driver = args.driver.resolve() if args.driver else out/'nft-cli-driver'
    if args.driver:
        assert driver.is_file() and not driver.is_symlink()
    else:
        compile(driver)
    if args.compile_only:
        (out/'compile.json').write_text(json.dumps({'compiled':True,'commands':commands,'driver':str(driver)},indent=2)+'\n')
        return
    checks = []
    def case(label, mode='ipv4', interval=False, table='c131_cplan', name='cn_site4', expected_rc=0, binary=driver):
        log=out/(label+'.calls.jsonl')
        local_env=env|{'NFT_TEST_LOG':str(log),'NFT_TEST_TABLE':table,'NFT_TEST_SET':name,'NFT_TEST_TYPE':'ipv6_addr' if mode=='ipv6' else 'ipv4_addr','NFT_TEST_INTERVAL':'1' if interval else '0'}
        result=subprocess.run([str(binary),str(child),mode,table,name],capture_output=True,text=True,timeout=8,env=local_env)
        (out/(label+'.stdout')).write_text(result.stdout);(out/(label+'.stderr')).write_text(result.stderr)
        assert result.returncode==expected_rc,(label,result.returncode,result.stderr)
        calls=[json.loads(row) for row in log.read_text().splitlines()] if log.exists() else []
        if expected_rc==0 and mode!='nodata' and interval:
            assert len(calls)==2 and calls[0]['argv'][4:]==['inet',table,name] and calls[1]['argv']==['-f','-'],calls
            wanted=('2001:db8:abcd::/48' if interval else '2001:db8:abcd:1234::9') if mode=='ipv6' else ('192.0.2.0/24' if interval else '192.0.2.9')
            assert calls[1]['stdin']==f'add element inet {table} {name} {{ {wanted} }}\n',calls
        if expected_rc==0 and mode!='nodata' and not interval:
            assert len(calls)==2 and all(x['argv'][4:]==['inet',table,name] and x['stdin']=='' for x in calls),calls
            stats=json.loads(result.stdout.splitlines()[0]);assert stats=={'opens':1,'closes':1,'sends':3,'generations':2,'batches':1,'keys':1,'rc':0},stats
        if expected_rc==0 and interval:
            stats=json.loads(result.stdout.splitlines()[0]);assert stats['opens']==stats['sends']==0,stats
        if expected_rc==3 or mode=='nodata':assert calls==[],calls
        checks.append({'label':label,'exit':expected_rc,'calls':len(calls),'passed':True})
    case('ipv4-plain')
    case('ipv4-interval',interval=True,name='cn-site4')
    case('ipv6-plain',mode='ipv6',name='cn_site6')
    case('ipv6-interval',mode='ipv6',interval=True,name='cn_site6')
    case('no-answer-does-not-spawn',mode='nodata')
    case('underscore-name',table='_table',name='_set')
    case('maximum-name',table='t'+'a'*126)
    for label,table,name in [('table-digit-first','9table','cn_site4'),('set-digit-first','table','9set'),('hyphen-first','-table','cn_site4'),('quote','table','"set"'),('semicolon','table','set;flush'),('slash','table','set/path'),('backslash','table','set\\path'),('too-long','t'+'a'*127,'cn_site4')]:
        case('reject-'+label,table=table,name=name,expected_rc=3)
    if args.old_source:
        old = out/'nft-cli-driver-before-fix';compile(old,args.old_source)
        case('observed-quoted-argv-regression',binary=old,expected_rc=4)
        assert 'unexpected quoted string' in (out/'observed-quoted-argv-regression.stderr').read_text()
    record={'ok':True,'checks':checks,'count':len(checks),'commands':commands,'sanitized':args.sanitize,'device_or_kernel_evidence':False,'source_sha256':hashlib.sha256((ROOT/'c/plugin/nftset.c').read_bytes()).hexdigest()}
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'ok':True,'checks':len(checks),'sanitized':args.sanitize,'device_or_kernel_evidence':False}))


if __name__=='__main__':main()
