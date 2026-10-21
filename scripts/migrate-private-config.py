#!/usr/bin/env python3
"""Extract legacy inline identities from a private backup without executing it.

Run offline before replacing a manually installed controller. Output contains
private addresses: never commit it. No network, device writes or service actions.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import tempfile


def one(pattern, text):
    values=set(re.findall(pattern,text))
    if len(values)!=1:raise ValueError('legacy layout is ambiguous or unsupported')
    return values.pop()


def ipv4(value):
    if not isinstance(value,str) or str(ipaddress.IPv4Address(value))!=value:
        raise ValueError('invalid IPv4 configuration')
    return value


def migrate(controller, query=None, existing=None):
    start=controller.index('local function expected_ip(')
    end=controller.index('local function public_probe',start)
    expected=ipv4(one(r"then return '([0-9.]+)' end",controller[start:end]))
    endpoint=ipv4(one(r"ip -4 route get ([0-9.]+) mark 512",controller))
    data=json.loads(json.dumps(existing if existing is not None else {}))
    if not isinstance(data,dict):raise ValueError('configuration must be an object')
    for key in ('usss','usvless'):
        item=data.setdefault(key,{})
        if not isinstance(item,dict):raise ValueError('invalid identity entry')
        item.setdefault('ipv4',expected);item.setdefault('endpoint_ipv4',endpoint)
        ipv4(item['ipv4']);ipv4(item['endpoint_ipv4'])
    if query is not None:
        address=ipv4(one(r"if source=='([0-9.]+)' then",query))
        mac=one(r"ether saddr ([0-9a-fA-F:]{17})",query).lower()
        if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',mac):raise ValueError('invalid MAC')
        comment=one(r"rules:find\('([^']+)',1,true\)~=nil and neighbor",query)
        data.setdefault('query_source',{'ipv4':address,'mac':mac,'rule_comment':comment})
    if 'query_source' in data:
        q=data['query_source']
        if not isinstance(q,dict):raise ValueError('invalid query source')
        ipv4(q.get('ipv4'))
        if not isinstance(q.get('mac'),str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}',q['mac']):raise ValueError('invalid MAC')
        if not isinstance(q.get('rule_comment'),str) or not 1<=len(q['rule_comment'])<=128 or any(ord(c)<32 for c in q['rule_comment']):raise ValueError('invalid rule comment')
    return data


def write_new(path,data):
    path=Path(path)
    # Publish fully written mode-0600 content without replacing a file or symlink.
    fd,name=tempfile.mkstemp(prefix='.private-config-',dir=path.parent)
    try:
        with os.fdopen(fd,'w') as f:
            json.dump(data,f,indent=2);f.write('\n');f.flush();os.fsync(f.fileno())
        os.link(name,path)
    finally:
        os.unlink(name)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--legacy-controller',type=Path,required=True)
    p.add_argument('--legacy-query',type=Path)
    p.add_argument('--existing',type=Path,help='existing device expected-egress.json; preserved values take priority')
    p.add_argument('--output',type=Path,required=True,help='new private output file; never overwritten')
    a=p.parse_args()
    try:
        data=migrate(a.legacy_controller.read_text(),a.legacy_query.read_text() if a.legacy_query else None,json.loads(a.existing.read_text()) if a.existing else None)
        write_new(a.output,data)
    except (OSError,ValueError,TypeError,KeyError):
        p.exit(1,'Migration refused; check private input layout and destination. No input was changed.\n')
    print('Private configuration written with mode 0600; review locally before installation. Addresses are not printed.')

if __name__=='__main__':main()
