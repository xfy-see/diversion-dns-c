#!/usr/bin/env python3
"""Package CI builds and verify downloaded artifacts; never invokes a compiler."""
import argparse
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TESTS = ('dns_test', 'cache_domain_test', 'engine_test', 'plan_regression_test',
         'nft_netlink_test', 'domain_driver', 'nft_cli_driver')
REPO = 'xfy-see/diversion-dns-c'
LIMIT = 400 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def blob(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()


def safe_path(name):
    p = PurePosixPath(name)
    require(bool(name) and not p.is_absolute() and '..' not in p.parts
            and str(p) == name and '\\' not in name, 'unsafe path: ' + name)
    return p


def git_tree(root, commit):
    out = subprocess.check_output(['git', 'ls-tree', '-rz', '--full-tree', commit], cwd=root)
    entries = {}
    for row in out.split(b'\0'):
        if not row:
            continue
        meta, name = row.split(b'\t', 1)
        mode, kind, sha = meta.decode().split()
        require(kind == 'blob' and mode in ('100644', '100755'), 'unsupported Git entry')
        path = name.decode('utf-8'); safe_path(path)
        entries[path] = dict(git_blob=sha, mode=int(mode, 8) & 0o777)
    return entries


def source_matches(root, manifest):
    require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root).decode().strip()
            == manifest['commit'], 'checkout commit differs')
    tree = git_tree(root, manifest['commit'])
    require(tree == manifest['git_tree'], 'Git tree differs')
    for name, item in tree.items():
        p = root / name
        require(p.is_file() and not p.is_symlink() and blob(p.read_bytes()) == item['git_blob'],
                'checkout input differs: ' + name)


def pack(args):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT).decode().strip()
    require(os.environ.get('GITHUB_SHA') == commit and os.environ.get('GITHUB_REPOSITORY') == REPO,
            'pack must run on GitHub for this exact repository/commit')
    tree = git_tree(ROOT, commit)
    payload = {}

    def add(name, path, mode=None):
        safe_path(name)
        p = Path(path)
        require(name not in payload and p.is_file() and not p.is_symlink(), 'invalid payload: ' + name)
        payload[name] = (p.read_bytes(), mode if mode is not None else (0o755 if os.access(p, os.X_OK) else 0o644))

    for name, item in tree.items():
        p = ROOT / name
        require(blob(p.read_bytes()) == item['git_blob'], 'dirty build input: ' + name)
        add('source/' + name, p, item['mode'])
    profiles = {}
    for value in args.profile:
        label, folder = value.split('=', 1)
        require(label in ('native', 'asan', 'static') and label not in profiles, 'invalid profile')
        folder = Path(folder).resolve()
        profiles[label] = {'application': f'builds/{label}/mosdns-c',
                           'tests': {t: f'builds/{label}/tests/{t}' for t in TESTS}}
        add(profiles[label]['application'], folder / 'mosdns-c', 0o755)
        for t, name in profiles[label]['tests'].items():
            add(name, folder / 'tests' / t, 0o755)
        original = folder / 'manifest.json'
        if original.exists():
            m = json.loads(original.read_text())
            require(m['status'] == 'complete' and m['source_unchanged']
                    and all(c['exit_code'] == 0 for c in m['commands']), 'static build incomplete')
            require(digest((folder / 'mosdns-c').read_bytes()) == m['binary']['sha256'], 'linked app differs')
            for t in TESTS:
                require(digest((folder / 'tests' / t).read_bytes()) == m['test_binaries'][t]['sha256'], 'linked test differs')
            for name, item in m['inputs'].items():
                require(digest((ROOT / name).read_bytes()) == item['sha256'], 'frozen source differs')
            if label == 'static':
                size_files = {'diagnostic': 'mosdns-c.unstripped', 'map': 'mosdns-c.map',
                              'report': 'attribution.json'}
                profiles[label]['size'] = {key: f'builds/{label}/size/{name}'
                                           for key, name in size_files.items()}
                for key, name in size_files.items():
                    path = folder / 'size' / name
                    require(path.is_file() and not path.is_symlink()
                            and digest(path.read_bytes()) == m['size_attribution'][key]['sha256'],
                            'size attribution changed: ' + key)
                    add(profiles[label]['size'][key], path, 0o644)
                size_report = json.loads((folder / 'size' / 'attribution.json').read_text())
                require(size_report['release']['sha256'] == m['binary']['sha256']
                        and sum(size_report['disk_bytes'].values()) == m['binary']['bytes']
                        and size_report['diagnostic']['alloc_sections_equal'],
                        'size attribution does not match published ELF')
            add(f'builds/{label}/manifest.ci.json', original, 0o644)
            for p in sorted((folder / 'logs').glob('*')):
                add(f'builds/{label}/logs/{p.name}', p, 0o644)
    for folder in args.logs:
        folder = Path(folder).resolve()
        for p in sorted(folder.rglob('*')):
            if p.is_file():
                add('ci-logs/' + folder.name + '/' + p.relative_to(folder).as_posix(), p, 0o644)
    for p in args.runtime_file:
        add('runtime/' + p.name, p, 0o755)
    manifest = dict(schema=1, repository=REPO, commit=commit, run_id=int(os.environ['GITHUB_RUN_ID']),
                    run_attempt=int(os.environ['GITHUB_RUN_ATTEMPT']), target=args.target, kind=args.kind,
                    created_utc=datetime.now(timezone.utc).isoformat(), git_tree=tree, profiles=profiles,
                    files={n:dict(bytes=len(b),sha256=digest(b),mode=m) for n,(b,m) in sorted(payload.items())})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    require(not args.output.exists(), 'archive already exists')
    with args.output.open('xb') as f, gzip.GzipFile(filename='', mode='wb', fileobj=f, mtime=0) as gz, tarfile.open(fileobj=gz, mode='w') as tar:
        for name, (data, mode) in [('manifest.json', (json.dumps(manifest, sort_keys=True, indent=2).encode()+b'\n', 0o644))] + sorted(payload.items()):
            item = tarfile.TarInfo(name); item.size=len(data); item.mode=mode; item.mtime=0
            tar.addfile(item, io.BytesIO(data))
    print(json.dumps(dict(completed=True,archive=str(args.output),sha256=digest(args.output.read_bytes()),commit=commit)))


def read_archive(path, commit, run_id, archive_sha=None):
    data = path.read_bytes()
    require(len(data) <= LIMIT, 'archive exceeds bound')
    if archive_sha:
        require(digest(data) == archive_sha.removeprefix('sha256:'), 'download archive digest differs')
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            files = z.infolist()
            require(len(files) == 1 and files[0].filename == 'bundle.tar.gz'
                    and files[0].file_size <= LIMIT, 'unexpected Actions ZIP entries')
            data = z.read(files[0])
    contents = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as tar:
        total = 0
        for entry in tar:
            safe_path(entry.name)
            require(entry.isfile() and entry.name not in contents and 0 <= entry.size <= 64*1024*1024,
                    'invalid/duplicate archive entry')
            total += entry.size
            require(total <= LIMIT and len(contents) < 2000, 'expanded archive exceeds bound')
            contents[entry.name] = tar.extractfile(entry).read()
    require('manifest.json' in contents and len(contents['manifest.json']) <= 2*1024*1024, 'missing/oversized manifest')
    m = json.loads(contents.pop('manifest.json'))
    require(m['schema'] == 1 and m['repository'] == REPO and m['commit'] == commit
            and m['run_id'] == run_id and m['run_attempt'] >= 1, 'artifact identity differs')
    require(m['target'] in ('macos-arm64','linux-amd64','linux-arm64')
            and m['kind'] in ('native','static'), 'unexpected platform')
    require(set(contents) == set(m['files']), 'payload membership differs')
    for name, info in m['files'].items():
        b=contents[name]
        require(info['bytes'] == len(b) and info['sha256'] == digest(b)
                and info['mode'] in (0o644,0o755), 'payload digest/mode differs: ' + name)
    for name, entry in m['git_tree'].items():
        b=contents['source/'+name]
        require(blob(b) == entry['git_blob'] and m['files']['source/'+name]['mode'] == entry['mode'], 'source Git blob differs')
    require(set(n[7:] for n in contents if n.startswith('source/')) == set(m['git_tree']), 'source membership differs')
    for label, profile in m['profiles'].items():
        require(label in ('native','asan','static') and set(profile['tests']) == set(TESTS), 'incomplete profile')
        for name in [profile['application'],*profile['tests'].values()]:
            require(name.startswith('builds/'+label+'/') and name in contents and m['files'][name]['mode']==0o755, 'missing executable')
        if label == 'static' and 'size' in profile:
            expected = {key: f'builds/static/size/{name}' for key, name in
                        (('diagnostic', 'mosdns-c.unstripped'), ('map', 'mosdns-c.map'),
                         ('report', 'attribution.json'))}
            require(profile.get('size') == expected and all(name in contents for name in expected.values()),
                    'static size attribution missing')
            size_report = json.loads(contents[expected['report']])
            require(size_report['release']['sha256'] == digest(contents[profile['application']])
                    and sum(size_report['disk_bytes'].values()) == len(contents[profile['application']])
                    and size_report['diagnostic']['alloc_sections_equal'],
                    'static size attribution mismatches application')
    require(bool(m['profiles']), 'no executable profile')
    return m, contents


def verify_bundle(bundle, checkout=None):
    m=json.loads((bundle/'manifest.json').read_text())
    expected={'manifest.json','verification.json',*m['files']}
    actual=set()
    for p in bundle.rglob('*'):
        require(not p.is_symlink(), 'bundle symlink')
        if p.is_file(): actual.add(p.relative_to(bundle).as_posix())
    require(actual == expected, 'verified bundle membership changed')
    for name, info in m['files'].items():
        p=bundle/name
        require(p.stat().st_size==info['bytes'] and digest(p.read_bytes())==info['sha256'], 'verified bundle changed: '+name)
    receipt=json.loads((bundle/'verification.json').read_text())
    require(receipt['completed'] and receipt['commit']==m['commit'] and receipt['run_id']==m['run_id']
            and receipt['manifest_sha256']==digest((bundle/'manifest.json').read_bytes()), 'verification receipt changed')
    if checkout: source_matches(checkout,m)
    return m


def extract(args):
    require(re.fullmatch('[0-9a-f]{40}',args.expected_commit) is not None, 'exact commit required')
    m, contents=read_archive(args.archive,args.expected_commit,args.expected_run_id,args.archive_sha256)
    if args.checkout: source_matches(args.checkout,m)
    require(not args.output.exists(), 'fresh extraction directory required')
    args.output.mkdir(parents=True)
    for name, data in contents.items():
        p=args.output/name; p.parent.mkdir(parents=True,exist_ok=True); p.write_bytes(data); p.chmod(m['files'][name]['mode'])
    raw=json.dumps(m,sort_keys=True,indent=2).encode()+b'\n'
    (args.output/'manifest.json').write_bytes(raw)
    receipt=dict(completed=True,commit=m['commit'],run_id=m['run_id'],run_attempt=m['run_attempt'],target=m['target'],kind=m['kind'],
                 archive_sha256=digest(args.archive.read_bytes()),manifest_sha256=digest(raw),files=len(contents),
                 checkout_verified=bool(args.checkout),archive_digest_verified=bool(args.archive_sha256))
    (args.output/'verification.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt))


def main():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest='command',required=True)
    a=sub.add_parser('pack'); a.add_argument('--profile',action='append',required=True); a.add_argument('--target',required=True)
    a.add_argument('--kind',choices=('native','static'),required=True); a.add_argument('--logs',type=Path,action='append',default=[])
    a.add_argument('--runtime-file',type=Path,action='append',default=[]); a.add_argument('--output',type=Path,required=True); a.set_defaults(func=pack)
    a=sub.add_parser('extract'); a.add_argument('--archive',type=Path,required=True); a.add_argument('--expected-commit',required=True)
    a.add_argument('--expected-run-id',type=int,required=True); a.add_argument('--archive-sha256'); a.add_argument('--checkout',type=Path)
    a.add_argument('--output',type=Path,required=True); a.set_defaults(func=extract)
    args=p.parse_args(); args.func(args)


if __name__=='__main__': main()
