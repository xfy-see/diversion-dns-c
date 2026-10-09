#!/usr/bin/env python3
"""Execute the complete portable suite from a verified CI bundle; no compilation."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import subprocess
import sys

import artifacts


# 此入口只运行已验证的同架构产物；编译由 GitHub 工作流完成。
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--bundle',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p.add_argument('--checkout',type=Path); p.add_argument('--ci',action='store_true')
    args=p.parse_args(); bundle=args.bundle.resolve(); out=args.output.resolve()
    m=artifacts.verify_bundle(bundle,args.checkout)
    # 先确认主机/产物架构一致，再创建本轮结果目录；不尝试执行跨架构程序。
    expected={'Darwin':'macos','Linux':'linux'}[platform.system()]+'-'+{'arm64':'arm64','aarch64':'arm64','x86_64':'amd64'}[platform.machine()]
    artifacts.require(m['target']==expected, 'artifact cannot run on this host')
    artifacts.require(not out.exists(), 'fresh result directory required'); out.mkdir(parents=True)
    source=bundle/'source'; commands=[]
    suites={label:artifacts.test_suite(profile) for label,profile in m['profiles'].items()}
    result=dict(completed=False,commit=m['commit'],run_id=m['run_id'],target=m['target'],profiles=list(m['profiles']),
                suites=suites,
                started_utc=datetime.now(timezone.utc).isoformat(),compilers_invoked=False,commands=commands,
                scope='Five C suites, shared domain fixture, service integration suite, 18 nft CLI grammar/failure checks and CLI smoke per current profile. Archived legacy bundles retain their 15 nft CLI checks and plan integrations. No real kernel NFT writes or performance/stability proof.')

    def run(label, argv, env, timeout=90):
        r=subprocess.run([str(v) for v in argv],cwd=source,env=env,capture_output=True,text=True,timeout=timeout)
        (out/(label+'.stdout')).write_text(r.stdout); (out/(label+'.stderr')).write_text(r.stderr)
        commands.append(dict(label=label,argv=[str(v) for v in argv],exit_code=r.returncode))
        if r.returncode:
            print(r.stdout, end='', flush=True)
            print(r.stderr, end='', file=sys.stderr, flush=True)
        artifacts.require(r.returncode==0,'test failed: '+label)

    try:
        # 每个 profile 独立设置环境并运行完整套件，避免普通通过掩盖 sanitizer 失败。
        for label, profile in m['profiles'].items():
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1')
            if platform.system()=='Darwin': env['DYLD_LIBRARY_PATH']=str(bundle/'runtime')
            if label=='asan':
                env['ASAN_OPTIONS']='detect_leaks='+('0' if platform.system()=='Darwin' else '1')+':halt_on_error=1'
                env['UBSAN_OPTIONS']='halt_on_error=1'
            tests={t:bundle/n for t,n in profile['tests'].items()}; app=bundle/profile['application']
            fixed=suites[label]=='fixed-splitter'
            unit_tests=('dns_test','cache_domain_test','fixed_config_test','fixed_engine_test','nft_netlink_test') if fixed else ('dns_test','cache_domain_test','engine_test','plan_regression_test','nft_netlink_test')
            for t in unit_tests:
                run(label+'-'+t,[tests[t]],env)
            run(label+'-domain',[sys.executable,source/'c/tests/domain_fixture.py',tests['domain_driver']],env)
            integration='fixed_integration.py' if fixed else 'integration.py'
            run(label+'-integration',[sys.executable,source/'c/tests'/integration,app],env)
            if not fixed:
                run(label+'-plan-integration',[sys.executable,source/'c/tests/plan_integration.py',app],env)
            argv=[sys.executable,source/'c/tests/nft_cli_test.py','--driver',tests['nft_cli_driver'],'--output',out/(label+'-nft')]
            if label=='asan': argv.append('--sanitize')
            run(label+'-nft-cli',argv,env)
            nft=json.loads((out/(label+'-nft/result.json')).read_text())
            artifacts.require(nft['ok'] and nft['count']==(18 if fixed else 15) and not nft['commands'],
                              'nft test count differs or unexpectedly compiled')
            run(label+'-version',[app,'version'],env)
            example='minimal.conf' if fixed else 'minimal.yaml'
            run(label+'-check',[app,'check','-c',source/'c/examples'/example],env)
        # 全部命令完成后再次核验，记录期间产物是否保持完整。
        artifacts.verify_bundle(bundle,args.checkout)
        result['completed']=True
    except BaseException as e:
        result['error']=repr(e); raise
    # 测试阶段失败也保存已完成命令与错误；completed 只有完整成功时才为 true。
    finally:
        result['finished_utc']=datetime.now(timezone.utc).isoformat()
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(completed=True,commit=m['commit'],profiles=list(m['profiles']),commands=len(commands),compilers_invoked=False)))


if __name__=='__main__': main()
