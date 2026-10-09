#!/usr/bin/env python3
"""Verify all four current CI bundles before exposing direct download assets."""
import argparse
import json
import os
from pathlib import Path
import shutil
import artifacts as a


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(); commit=os.environ['GITHUB_SHA']; run=int(os.environ['GITHUB_RUN_ID'])
    attempt=int(os.environ['GITHUB_RUN_ATTEMPT'])
    expected={('native','macos-arm64'),('native','linux-amd64'),('static','linux-amd64'),('static','linux-arm64')}
    files=sorted(args.input.glob('*/bundle.tar.gz')); seen=set(); rows=[]
    a.require(len(files)==4 and not args.output.exists(),'exact four bundles and fresh output required')
    for archive in files:
        m,contents=a.read_archive(archive,commit,run)
        a.source_matches(a.ROOT,m)
        key=(m['kind'],m['target'])
        a.require(key in expected and key not in seen and m['run_attempt']==attempt,'delivery identity differs')
        seen.add(key)
        result=json.loads(contents['ci-logs/ci-validation/result.json'])
        a.require(result['completed'] and result['commit']==commit and result['run_id']==run
                  and result['target']==m['target'] and not result['compilers_invoked']
                  and all(c['exit_code']==0 for c in result['commands']),'CI test result incomplete')
        rows.append((f"{m['kind']}-{m['target']}.tar.gz",archive,a.digest(archive.read_bytes())))
    a.require(seen==expected,'delivery platform missing')
    args.output.mkdir(parents=True)
    for name,archive,_ in rows: shutil.copyfile(archive,args.output/name)
    (args.output/'SHA256SUMS').write_text(''.join(f'{sha}  {name}\n' for name,_,sha in rows))
    print(json.dumps(dict(completed=True,commit=commit,run_id=run,run_attempt=attempt,assets=len(rows))))


if __name__=='__main__': main()
