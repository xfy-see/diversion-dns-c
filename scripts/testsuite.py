#!/usr/bin/env python3
"""Run verified C test artifacts, safe device adapters and explicit network probes.

No compiler, production install, firewall takeover, or implicit public target.
Exit: 0 complete pass; 1 failure; 2 incomplete/unavailable/planned.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time

import artifacts

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / 'tests/scenarios/catalog.json'
PROFILES = ('portable', 'kernel', 'network', 'device-smoke', 'device-performance', 'ablation', 'stability', 'release')
DEVICE = {'device-smoke', 'device-performance', 'ablation', 'stability'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def dump(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False) + '\n')


def now():
    return datetime.now(timezone.utc).isoformat()


def load(path):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'duplicate JSON key: ' + key)
            result[key] = value
        return result
    return json.loads(path.read_text(), object_pairs_hook=pairs,
                      parse_constant=lambda v: (_ for _ in ()).throw(ValueError('non-finite JSON: ' + v)))


def catalog(path=CATALOG):
    data = load(path)
    require(data['schema_version'] == 1 and isinstance(data['cases'], list), 'unsupported catalog')
    seen = set()
    for case in data['cases']:
        require(all(key in case for key in ('id', 'category', 'title', 'runner', 'profiles', 'assertions')), 'incomplete case')
        require(re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', case['id']) is not None, 'invalid case id')
        require(case['id'] not in seen, 'duplicate case id')
        require(case['runner'] in {'portable', 'kernel', 'probe', 'device', 'audit', 'manual'}, 'unknown runner')
        require(case.get('status') in {'automated', 'manual', 'planned'}, 'unknown coverage status')
        require(case['profiles'] and set(case['profiles']) <= set(PROFILES), 'unknown profile')
        require(case['assertions'], 'empty assertions')
        seen.add(case['id'])
    return data


def plan(profile, data):
    selected = [c for c in data['cases'] if profile in c['profiles']]
    return dict(schema_version=1, profile=profile, status='planned', completed=False,
                cases=selected, counts={s: sum(c['status'] == s for c in selected) for s in ('automated', 'planned', 'manual')},
                note='Catalog assertions are coverage definitions, not executed results. Device execution requires --execute-device.')


def command(argv, out, label, timeout=600, env=None):
    """Bound runtime; keep failed output and kill only this owned process group."""
    with (out / (label + '.stdout')).open('wb') as stdout, (out / (label + '.stderr')).open('wb') as stderr:
        p = subprocess.Popen([str(a) for a in argv], stdout=stdout, stderr=stderr,
                             env=env, start_new_session=True)
        timed_out = False
        try:
            rc = p.wait(timeout=timeout)
        except BaseException:
            if p.poll() is None:
                os.killpg(p.pid, signal.SIGTERM)
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(p.pid, signal.SIGKILL)
                    p.wait(timeout=5)
            raise
    return dict(argv=[str(a) for a in argv], exit_code=rc, timed_out=timed_out)


def verify_input(config):
    p = config['artifact']
    bundle = Path(p['bundle']).resolve()
    checkout = Path(p.get('checkout', ROOT)).resolve()
    m = artifacts.verify_bundle(bundle, checkout)
    require(re.fullmatch('[0-9a-f]{40}', p['expected_commit']) is not None, 'exact commit required')
    require(m['commit'] == p['expected_commit'], 'wrong artifact commit')
    require(m['run_id'] == p['expected_run_id'] and m['run_attempt'] == p['expected_run_attempt'], 'wrong artifact run/attempt')
    receipt = load(bundle / 'verification.json')
    expected_digest = p['expected_archive_sha256']
    require(re.fullmatch('[0-9a-f]{64}', expected_digest) is not None and receipt['archive_sha256'] == expected_digest, 'archive digest differs from pinned evidence')
    workflow = p['workflow']
    require(workflow['head_sha'] == m['commit'] and workflow['id'] == m['run_id'] and workflow['run_attempt'] == m['run_attempt'], 'workflow identity mismatch')
    require(workflow['status'] == 'completed' and workflow['conclusion'] == 'success', 'workflow has not passed')
    jobs = p['jobs']
    required_jobs = {'Native / macos-arm64', 'Native / linux-amd64', 'Static / linux-amd64', 'Static / linux-arm64'}
    require(len(jobs) >= 4 and len({j.get('id') for j in jobs}) == len(jobs) and all(j.get('id') for j in jobs), 'unique job IDs required')
    require(required_jobs <= {j.get('name') for j in jobs}, 'missing required build job')
    require(all(j.get('conclusion') == 'success' and j.get('status') == 'completed' and j.get('run_id') == m['run_id'] and j.get('run_attempt') == m['run_attempt'] for j in jobs), 'four successful exact-run/attempt build jobs required')
    # Caller supplies metadata obtained from authenticated GitHub API and the
    # pinned ZIP digest; this does not claim a new live GitHub authentication.
    return bundle, checkout, m


def inventory(out):
    return {p.relative_to(out).as_posix(): dict(bytes=p.stat().st_size, sha256=sha(p))
            for p in sorted(out.rglob('*')) if p.is_file() and p.name != 'evidence.json'}


def verify_report(folder):
    folder = Path(folder).resolve()
    entries = load(folder / 'evidence.json')
    require(entries and 'result.json' in entries, 'report evidence manifest missing')
    for name, record in entries.items():
        safe = artifacts.safe_path(name)
        path = folder / safe
        require(path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(folder), 'unsafe/missing evidence')
        require(path.stat().st_size == record['bytes'] and sha(path) == record['sha256'], 'changed report evidence: ' + name)
    result = load(folder / 'result.json')
    require(result.get('schema_version') == 1, 'unsupported report')
    return result


def release_audit(config):
    spec = config['release']
    required = spec.get('required', ['portable', 'kernel', 'device-smoke-122', 'device-smoke-131', 'device-performance-122', 'device-performance-131', 'network', 'stability'])
    require(required and len(set(required)) == len(required), 'empty/duplicate release requirements')
    commit = spec['expected_commit']
    require(re.fullmatch('[0-9a-f]{40}', commit) is not None, 'exact release commit required')
    cases = []
    used = set()
    for label in required:
        path = spec.get('reports', {}).get(label)
        row = dict(id=label, status='skip', reason='required report not supplied')
        if path:
            resolved = str(Path(path).resolve())
            require(resolved not in used, 'one report cannot satisfy multiple release requirements')
            used.add(resolved)
            r = verify_report(path)
            require(label == r.get('profile') or label.startswith(str(r.get('profile')) + '-'), 'release report profile mismatch: ' + label)
            expected_device = spec.get('expected_devices', {}).get(label)
            if r.get('profile', '').startswith('device-') or r.get('profile') in DEVICE:
                require(expected_device is not None, 'release device address must be pinned: ' + label)
            if expected_device:
                require(r.get('identity', {}).get('target_address') == expected_device, 'release device mismatch: ' + label)
            commits = r.get('identity', {}).get('commits', [r.get('identity', {}).get('commit')])
            require(commit in commits, 'release source mismatch: ' + label)
            row.update(status='pass' if r.get('completed') and r.get('status') == 'pass' else 'fail', reason='referenced report status', path=str(path))
        cases.append(row)
    return cases


def write_human(out, result):
    lines = ['测试结果', '', '状态: ' + result['status'], '配置: ' + result['profile'],
             '开始: ' + result['started_utc'], '结束: ' + result['finished_utc'], '',
             '只有实际执行且断言通过的组会记 pass；计划、缺少端点、缺少权限和未执行项目不会记 pass。', '',
             '| 测试组 | 状态 | 说明 |', '| --- | --- | --- |']
    for c in result['cases']:
        note = str(c.get('reason', c.get('error', c.get('raw_path', '')))).replace('|', '\\|').replace('\n', ' ')
        lines.append('| ' + str(c['id']) + ' | ' + c['status'] + ' | ' + note + ' |')
    device_result = out/'device/result.json'
    if device_result.exists():
        device = load(device_result)
        lines.extend(['', '| 版本 / 场景 | P99 中位数 ms | 最坏 max ms | 漏发 | 平衡正反序 |', '| --- | ---: | ---: | ---: | --- |'])
        for row in device.get('aggregate', []):
            lines.append('| {version} / {scenario} | {p99_median_ms} | {worst_max_ms} | {unsent} | {balanced} |'.format(**row))
    lines.extend(['', '原始日志、配置、执行计划和结果的 SHA256 记录在 evidence.json。',
                  '功能、严格固定到达率、延迟阈值是独立指标；漏发不能被较低 P99 掩盖。',
                  'CI/模拟端点结果不等于真机、真实公网路由或连续业务连接的证明。'])
    (out / 'REPORT.md').write_text('\n'.join(lines) + '\n')


def runner_identity():
    files = ('testsuite.py', 'suite_device.py', 'suite_metrics.py', 'suite_network.py')
    result = dict(python=sys.version, platform=platform.platform(),
                  files_sha256={name: sha(ROOT/'scripts'/name) for name in files})
    try:
        result['commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True, stderr=subprocess.DEVNULL).strip()
        result['dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=ROOT, text=True))
    except (OSError, subprocess.SubprocessError):
        result['commit'] = None
        result['dirty'] = None
    return result


def run(args):
    out = args.output.resolve()
    require(not out.exists(), 'fresh result directory required')
    out.mkdir(parents=True)
    config = {}
    result = dict(schema_version=1, profile=args.profile, started_utc=now(), completed=False,
                  scope='Only explicitly configured and executed groups; catalog is a coverage map, not proof of all subcases',
                  status='incomplete', cases=[], identity={}, runner=runner_identity(), commands=[], compilers_invoked=False)
    status = 2
    try:
        config = load(args.config) if args.config else {}
        execution_plan = plan(args.profile, catalog())
        dump(out / 'plan.json', execution_plan)
        result['unautomated_coverage'] = [dict(id=c['id'], status=c['status'], title=c['title']) for c in execution_plan['cases'] if c['status'] != 'automated']
        result['full_catalog_coverage'] = False
        dump(out / 'config.json', config)
        if args.profile in ('portable', 'kernel'):
            bundle, checkout, manifest = verify_input(config)
            result['identity'] = {k: manifest[k] for k in ('commit', 'run_id', 'run_attempt', 'target')}
            dump(out / 'artifact-manifest.json', manifest)
            if args.profile == 'portable':
                c = command([sys.executable, ROOT/'scripts/validate.py', '--bundle', bundle, '--checkout', checkout, '--output', out/'portable'], out, 'portable', 1200)
                result['commands'].append(c)
                report = load(out/'portable/result.json') if (out/'portable/result.json').exists() else {}
                result['cases'].append(dict(id='portable', status='pass' if c['exit_code'] == 0 and report.get('completed') else 'fail', raw_path='portable/result.json', commands=report.get('commands', [])))
            else:
                require(platform.system() == 'Linux' and os.geteuid() == 0, 'kernel profile requires Linux root in dedicated test host; no sudo is invoked')
                require(all(shutil.which(tool) for tool in ('unshare', 'ip', 'nft')), 'kernel profile requires unshare/ip/nft')
                host = 'linux-' + {'aarch64': 'arm64', 'x86_64': 'amd64'}.get(platform.machine(), platform.machine())
                require(manifest['target'] == host, 'kernel artifact architecture mismatch')
                variant = config.get('kernel', {}).get('variant', 'static')
                app = bundle / manifest['profiles'][variant]['application']
                for script in ('nft_kernel_test.py', 'nft_kernel_cli_test.py'):
                    label = script[:-3]
                    child = [sys.executable, bundle/'source/c/tests'/script, '--application', app, '--output', out/label]
                    shell = 'set -eu; ip link set lo up; exec env DIVERSION_OWNED_NETNS=1 ' + shlex.join([str(v) for v in child])
                    c = command(['unshare', '--net', '--pid', '--fork', '--mount-proc', '--kill-child', 'sh', '-c', shell], out, label, 900)
                    result['commands'].append(c)
                    report = load(out/label/'result.json') if (out/label/'result.json').exists() else {}
                    result['cases'].append(dict(id=label, status='pass' if c['exit_code'] == 0 and report.get('passed') and report.get('count', 0) > 0 else 'fail', checks=report.get('checks', []), raw_path=label+'/result.json'))
            artifacts.verify_bundle(bundle, checkout)
        elif args.profile == 'network':
            network_config = config.get('network', config)
            dump(out/'network-input.json', network_config)
            c = command([sys.executable, ROOT/'scripts/suite_network.py', '--config', out/'network-input.json', '--output', out/'network.json'], out, 'network', config.get('timeout_seconds', 7500))
            result['commands'].append(c)
            network = load(out/'network.json') if (out/'network.json').exists() else {}
            result['cases'] = network.get('results', [])
            if not result['cases']:
                result['cases'] = [dict(id='network', status='skip', reason='no explicit endpoints/results')]
            if c['exit_code'] not in (0, 2) and not any(x['status'] == 'fail' for x in result['cases']):
                result['cases'].append(dict(id='network-runner', status='fail', reason='runner failed'))
            result['identity'] = config.get('identity', {})
        elif args.profile in DEVICE:
            require(args.config is not None, 'device config required')
            argv = [sys.executable, ROOT/'scripts/suite_device.py', '--config', args.config.resolve(), '--output', out/'device', '--profile', args.profile]
            if args.execute_device:
                argv.append('--execute')
            c = command(argv, out, 'device', config.get('timeout_seconds', 14400))
            result['commands'].append(c)
            paths = [out/'device/result.json', out/'device/results.json']
            report = next((load(p) for p in paths if p.exists()), {})
            result['cases'] = report.get('cases', [])
            result['identity'] = report.get('identity', {})
            if args.execute_device and report.get('status') != 'pass':
                result['cases'].append(dict(id='device-completion-and-cleanup', status='fail' if report.get('status') == 'fail' else 'incomplete', reason=report.get('error') or 'adapter did not complete with verified cleanup'))
            if not result['cases']:
                result['cases'] = [dict(id='device', status='planned' if not args.execute_device else 'fail', reason=report.get('error', 'adapter did not execute any cases'))]
            if c['exit_code'] not in (0, 2) and not any(x['status'] == 'fail' for x in result['cases']):
                result['cases'].append(dict(id='device-runner', status='fail', reason='adapter failed'))
        else:
            result['cases'] = release_audit(config)
            result['cases'].extend(dict(id=c['id'], status='skip', reason=c['status'] + ': requires separate acceptance evidence') for c in catalog()['cases'] if 'release' in c['profiles'] and c['status'] != 'automated')
            result['identity'] = dict(commit=config['release']['expected_commit'])
        statuses = [c['status'] for c in result['cases']]
        if any(s == 'fail' for s in statuses):
            result['status'] = 'fail'; status = 1
        elif statuses and all(s == 'pass' for s in statuses):
            result['status'] = 'pass'; result['completed'] = True; status = 0
        else:
            result['status'] = 'incomplete'; status = 2
    except (Exception, KeyboardInterrupt) as error:
        result['cases'].append(dict(id='runner', status='fail', error=str(error)))
        result['status'] = 'fail'; result['error'] = str(error); status = 1
    finally:
        result['finished_utc'] = now()
        dump(out/'result.json', result)
        write_human(out, result)
        dump(out/'evidence.json', inventory(out))
    print(json.dumps(dict(status=result['status'], output=str(out), cases=len(result['cases'])), ensure_ascii=False))
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('list', 'plan'):
        p = sub.add_parser(action); p.add_argument('--profile', choices=PROFILES, default='release'); p.add_argument('--output', type=Path)
    p = sub.add_parser('run'); p.add_argument('--profile', choices=PROFILES, required=True)
    p.add_argument('--config', type=Path); p.add_argument('--output', type=Path, required=True)
    p.add_argument('--execute-device', action='store_true', help='explicitly permit isolated test resources on configured devices')
    p = sub.add_parser('summarize'); p.add_argument('--input', type=Path, action='append', required=True); p.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'run':
        return run(args)
    if args.action == 'summarize':
        require(not args.output.exists(), 'fresh output required')
        result = [dict(path=str(p), result=verify_report(p)) for p in args.input]
        dump(args.output, result)
        return 0 if all(r['result']['status'] == 'pass' for r in result) else 2
    data = plan(args.profile, catalog())
    if args.action == 'list':
        data['catalog_profiles'] = catalog()['profiles']
    if args.output:
        require(not args.output.exists(), 'fresh output required'); dump(args.output, data)
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
