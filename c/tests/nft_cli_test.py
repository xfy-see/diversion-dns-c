#!/usr/bin/env python3
"""Exercise actual add_target with a grammar child and test-only netlink transport.

Set metadata (type and INTERVAL flag) always comes from fake netlink GETSET; no
`nft list set` is spawned. Plain sets then use fake GETGEN/GETSET/batch ACK
(0 CLI calls); interval sets stop after GETGEN/GETSET and use the exact real
`nft -f -` subprocess argv/stdin path (1 CLI call, plus one per skipped overlap).

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
import time

ROOT = Path(__file__).resolve().parents[2]
# 子进程按标识符/地址语法检查真实 argv 和 stdin；它不替代 Linux 内核的接受结果。
CHILD = r'''#!/usr/bin/env python3
import ipaddress,json,os,re,sys,time
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
failure=os.environ.get('NFT_TEST_FAILURE','')
if args[:4]==['-t','-nn','list','set']:
 t=tokens(' '.join(args[4:]))
 if len(t)!=3 or t[0]!=family or not identifier(t[1]) or not identifier(t[2]) or t[1:]!=[table,name]:fail()
 if failure=='malformed-metadata':
  print(f'table {family} {table} {{ set {name} {{ flags interval; }} }}')
  sys.exit(0)
 flags='flags interval;' if interval else 'flags timeout; timeout 30s;'
 print(f'table {family} {table} {{\n set {name} {{\n type {kind};\n {flags}\n }}\n}}')
elif args==['-f','-']:
 if failure=='overlap':
  # M1: nft rejects a batch whose element overlaps an existing interval and
  # points at that element (nft 1.1 wording and column range).
  bad='198.51.100.0/24' if kind=='ipv4_addr' else '2001:db8:beef::/48'
  if bad in body:
   start=body.index(bad)+1
   print(f'/dev/stdin:1:{start}-{start+len(bad)-1}: Error: interval overlaps with an existing one',file=sys.stderr)
   print(body.rstrip('\n'),file=sys.stderr)
   sys.exit(1)
 if failure=='nonzero-exit':
  print('injected nft update rejection',file=sys.stderr)
  sys.exit(7)
 if failure=='timeout':time.sleep(6)
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
    # 传 --driver 使用 CI 已编译程序；本地下载验证只能走该分支。
    compiler = None if args.driver else Path(shutil.which(os.environ.get('CC', 'cc'))).resolve()
    child = out / 'grammar-nft'
    child.write_text(CHILD); child.chmod(0o700)
    flags = ['-flto','-UNDEBUG','-std=c11','-Wall','-Wextra','-Wpedantic','-Werror','-pthread','-D_POSIX_C_SOURCE=200809L','-D_DEFAULT_SOURCE','-I'+str(ROOT/'c/include')]
    if os.uname().sysname=='Darwin': flags += ['-I'+str(ROOT/'c/tests/nft_uapi')]
    if args.sanitize: flags += ['-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer']
    else: flags += ['-Os']
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
    # 每例同时核对退出码、子进程调用记录和 fake netlink 计数，覆盖两条更新路径。
    checks = []
    def case(label, mode='ipv4', interval=False, table='c131_cplan', name='cn_site4', expected_rc=0, binary=driver, failure=''):
        log=out/(label+'.calls.jsonl')
        local_env=env|{'NFT_TEST_LOG':str(log),'NFT_TEST_TABLE':table,'NFT_TEST_SET':name,'NFT_TEST_TYPE':'ipv6_addr' if mode=='ipv6' else 'ipv4_addr','NFT_TEST_INTERVAL':'1' if interval else '0','NFT_TEST_FAILURE':failure}
        started=time.monotonic()
        result=subprocess.run([str(binary),str(child),mode,table,name],capture_output=True,text=True,timeout=8,env=local_env)
        elapsed=time.monotonic()-started
        (out/(label+'.stdout')).write_text(result.stdout);(out/(label+'.stderr')).write_text(result.stderr)
        assert result.returncode==expected_rc,(label,result.returncode,result.stderr)
        calls=[json.loads(row) for row in log.read_text().splitlines()] if log.exists() else []
        wanted=('2001:db8:abcd::/48' if interval else '2001:db8:abcd:1234::9') if mode=='ipv6' else ('192.0.2.0/24' if interval else '192.0.2.9')
        # R3: metadata is one netlink GETGEN+GETSET on a private socket; an interval
        # set stops there and spawns only `nft -f -`.
        interval_stats={'opens':1,'closes':1,'sends':2,'generations':1,'batches':0,'keys':0,'rc':0 if expected_rc==0 else -1}
        if expected_rc==0 and mode!='nodata' and interval and failure!='overlap':
            assert len(calls)==1 and calls[0]['argv']==['-f','-'],calls
            assert calls[0]['stdin']==f'add element inet {table} {name} {{ {wanted} }}\n',calls
        if expected_rc==0 and mode!='nodata' and not interval:
            assert calls==[],calls
            stats=json.loads(result.stdout.splitlines()[0]);assert stats=={'opens':1,'closes':1,'sends':3,'generations':1,'batches':1,'keys':1,'rc':0},stats
        if mode!='nodata' and interval and expected_rc in (0,4):
            stats=json.loads(result.stdout.splitlines()[0]);assert stats==interval_stats,stats
        if expected_rc==3 or mode=='nodata':assert calls==[],calls
        if failure=='overlap':
            # M1: the overlapping prefix is skipped (1 retry), the other prefix is
            # written, and the DNS answer succeeds with a rate-limited warning.
            other='2001:db8:beef::/48' if mode=='ipv6' else '198.51.100.0/24'
            assert expected_rc==0 and len(calls)==2 and all(x['argv']==['-f','-'] for x in calls),calls
            assert calls[0]['stdin']==f'add element inet {table} {name} {{ {wanted}, {other} }}\n',calls
            assert calls[1]['stdin']==f'add element inet {table} {name} {{ {wanted} }}\n',calls
            assert f'nftset warning: skip {other} ' in result.stderr,result.stderr
        elif failure:
            assert expected_rc==4
            stats=json.loads(result.stdout.splitlines()[0])
            assert stats==interval_stats,stats
            if failure=='malformed-metadata':
                assert calls==[] and 'is not a supported ipv4_addr set' in result.stderr,(calls,result.stderr)
            else:
                assert len(calls)==1 and calls[0]['argv']==['-f','-'],calls
                assert calls[0]['stdin']==f'add element inet {table} {name} {{ 192.0.2.0/24 }}\n',calls
                if failure=='nonzero-exit':
                    assert 'nft command failed: injected nft update rejection' in result.stderr,result.stderr
                else:
                    assert failure=='timeout' and '5 second deadline' in result.stderr,result.stderr
                    assert 4<=elapsed<8,elapsed
        checks.append({'label':label,'exit':expected_rc,'calls':len(calls),'passed':True,'elapsed_seconds':round(elapsed,3)})
    case('ipv4-plain')
    case('ipv4-interval',interval=True,name='cn-site4')
    case('ipv6-plain',mode='ipv6',name='cn_site6')
    case('ipv6-interval',mode='ipv6',interval=True,name='cn_site6')
    case('no-answer-does-not-spawn',mode='nodata')
    case('underscore-name',table='_table',name='_set')
    case('maximum-name',table='t'+'a'*126)
    for label,table,name in [('table-digit-first','9table','cn_site4'),('set-digit-first','table','9set'),('hyphen-first','-table','cn_site4'),('quote','table','"set"'),('semicolon','table','set;flush'),('slash','table','set/path'),('backslash','table','set\\path'),('too-long','t'+'a'*127,'cn_site4')]:
        case('reject-'+label,table=table,name=name,expected_rc=3)
    # Actual CLI error paths, using the grammar child only: no nft executable,
    # netlink socket, production table, or kernel ruleset is accessed.
    case('update-nonzero-exit',interval=True,expected_rc=4,failure='nonzero-exit')
    case('reject-malformed-metadata',interval=True,expected_rc=4,failure='malformed-metadata')
    case('update-bounded-timeout',interval=True,expected_rc=4,failure='timeout')
    case('ipv4-interval-overlap-skipped',interval=True,name='cn-site4',failure='overlap')
    case('ipv6-interval-overlap-skipped',mode='ipv6',interval=True,name='cn_site6',failure='overlap')
    # Fast mode uses only fake netlink. Repeated requests verify successful ACK
    # dedup, expiration renewal, reset recovery and strict metadata/error handling.
    for mode, expected_batches, expected_rc in [('fast-dedup', 1, 0), ('fast-reset', 2, 0), ('fast-renew', 2, 0), ('fast-existing', 0, 0), ('fast-interval', 0, 4), ('fast-error', 1, 4), ('fast-permanent', 0, 0), ('fast-permanent-reset', 0, 0), ('fast-old-kernel', 0, 4), ('fast-ttl-highbit', 1, 0), ('fast-ttl-cap', 1, 0), ('fast-race-before', 1, 0), ('fast-race-after', 1, 0), ('fast-race-flush', 2, 0), ('fast-race-forever', 0, 4), ('fast-restart', 2, 0), ('fast-sequence', 2, 0), ('fast-small-buffer', 5, 0), ('fast-large-answer', 1, 0), ('fast-cohort', None, 0), ('fast-cohort-poison', 3, 0), ('fast-window', 2, 0), ('fast-window-renew', 2, 0), ('fast-window-error', 2, 0), ('fast-both', 1, 0), ('fast-pipeline', 1, 0), ('fast-pipeline-race', 1, 0)]:
        for kind in ('ipv4','ipv6'):
            local_env=env|{'FAKE_MODE':mode,'NFT_TEST_LOG':str(out/(mode+'-'+kind+'.unexpected-cli'))}
            result=subprocess.run([str(driver),str(child),kind,'diag','learn'],capture_output=True,text=True,timeout=8,env=local_env)
            (out/(mode+'-'+kind+'.stdout')).write_text(result.stdout);(out/(mode+'-'+kind+'.stderr')).write_text(result.stderr)
            assert result.returncode==expected_rc,(mode,kind,result.stdout,result.stderr)
            stats=json.loads(result.stdout.splitlines()[0]);assert expected_batches is None or stats['batches']==expected_batches,(mode,kind,stats)
            assert stats['opens']==stats['closes'],(mode,kind,stats)
            assert stats['opens'] <= 5,(mode,kind,stats)  # NFT_FAST_ATTEMPTS
            assert not Path(local_env['NFT_TEST_LOG']).exists(),'fast path invoked CLI'
            checks.append({'label':mode+'-'+kind,'exit':expected_rc,'calls':0,'passed':True,'device_or_kernel_evidence':False})
    # Compatible plain path driven directly over fake netlink: sequence wrap
    # (H4) and bounded generation/ERESTART retries (H3). No CLI child runs.
    for mode, expected_rc, expected in [('plain-sequence-wrap', 0, {'opens':5,'generations':5,'batches':5}),
                                        ('plain-race-retry', 0, {'opens':2,'generations':2,'batches':2}),
                                        ('plain-race-forever', 4, {'opens':8,'generations':8,'batches':8}),
                                        ('plain-restart', 0, {'opens':2,'generations':2,'batches':2}),
                                        ('plain-interval-metadata', 4, {'opens':1,'generations':1,'batches':0}),
                                        ('window-plain', 0, {'opens':2,'batches':2})]:
        for kind in ('ipv4','ipv6'):
            local_env=env|{'FAKE_MODE':mode,'NFT_TEST_LOG':str(out/(mode+'-'+kind+'.unexpected-cli'))}
            result=subprocess.run([str(driver),str(child),kind,'diag','learn'],capture_output=True,text=True,timeout=8,env=local_env)
            (out/(mode+'-'+kind+'.stdout')).write_text(result.stdout);(out/(mode+'-'+kind+'.stderr')).write_text(result.stderr)
            assert result.returncode==expected_rc,(mode,kind,result.stdout,result.stderr)
            stats=json.loads(result.stdout.splitlines()[0])
            assert {k:stats[k] for k in expected}==expected and stats['opens']==stats['closes'],(mode,kind,stats)
            assert not Path(local_env['NFT_TEST_LOG']).exists(),'plain netlink path invoked CLI'
            if mode=='plain-race-forever':
                assert 'attempts=8' in result.stderr and 'errno=85' in result.stderr and 'ERESTART' in result.stderr,result.stderr
            checks.append({'label':mode+'-'+kind,'exit':expected_rc,'calls':0,'passed':True,'device_or_kernel_evidence':False})
    if args.old_source:
        old = out/'nft-cli-driver-before-fix';compile(old,args.old_source)
        case('observed-quoted-argv-regression',binary=old,expected_rc=4)
        assert 'unexpected quoted string' in (out/'observed-quoted-argv-regression.stderr').read_text()
    record={'ok':True,'checks':checks,'count':len(checks),'commands':commands,'sanitized':args.sanitize,'device_or_kernel_evidence':False,'source_sha256':hashlib.sha256((ROOT/'c/plugin/nftset.c').read_bytes()).hexdigest()}
    (out/'result.json').write_text(json.dumps(record,indent=2)+'\n')
    print(json.dumps({'ok':True,'checks':len(checks),'sanitized':args.sanitize,'device_or_kernel_evidence':False}))


if __name__=='__main__':main()
