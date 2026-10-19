#!/usr/bin/env python3
"""Package a previously tested exact-commit ELF and the observation UI with SDK apk.

Called only by GitHub APK build after QEMU and differential verification. No
compiler, device installation, key generation or repository changes here.
"""
import hashlib
import json
from pathlib import Path
import re
import shutil

CORE='diversion-dns-c'
UI='luci-app-diversion-dns'
MODULES=('device/device.lua','device/window.lua','telemetry.lua','metrics.lua','public-status.lua','dns-status.lua','query.lua')
CORE_DEPS=['libc','libpthread','procd','uci']
UI_DEPS=['luci-base','luci-lib-jsonc','luci-lib-nixio','rpcd-mod-file','uclient-fetch','ca-bundle','libustream-mbedtls20201210','procd','uci','ip-full','nftables','wireguard-tools']


def sha(data):return hashlib.sha256(data).hexdigest()

def put(root,path,data,mode=0o644):
    dest=root/path
    dest.parent.mkdir(parents=True,exist_ok=True)
    dest.write_bytes(data if isinstance(data,bytes) else data.encode())
    dest.chmod(mode)

def contents(root):
    result={}
    for p in sorted(root.rglob('*')):
        if p.is_symlink():raise ValueError('symlink in package root')
        if p.is_file():result[str(p.relative_to(root))]={'sha256':sha(p.read_bytes()),'bytes':p.stat().st_size,'mode':p.stat().st_mode&0o7777}
    return result

def stage(source,binary,destination,commit):
    source,binary,destination=map(Path,(source,binary,destination))
    if destination.exists():raise ValueError('managed staging requires fresh destination')
    if not re.fullmatch('[0-9a-f]{40}',commit):raise ValueError('invalid source commit')
    base=source/'packaging/managed';ui=base/'ui';destination.mkdir()
    roots={CORE:destination/CORE,UI:destination/UI}
    for root in roots.values():root.mkdir()
    put(roots[CORE],'usr/libexec/diversion-dns-c',binary.read_bytes(),0o755)
    for local,remote,mode in [('core.init','etc/init.d/diversion-dns',0o755),('core.uci','etc/config/diversion-dns',0o600),('config.conf','etc/diversion-dns/config.conf',0o600),('cn-domains.txt','etc/diversion-dns/cn-domains.txt',0o600)]:put(roots[CORE],remote,(base/local).read_bytes(),mode)
    for name in MODULES:put(roots[UI],'usr/share/diversion-dns-ui/'+Path(name).name,(ui/name).read_bytes())
    for name in ['control','status']:put(roots[UI],'usr/libexec/diversion-dns-ui-'+name,(ui/'device'/name).read_bytes(),0o755)
    put(roots[UI],'usr/share/diversion-dns-ui/monitor',(ui/'device/monitor').read_bytes(),0o755)
    for local,remote,mode in [('ui.init','etc/init.d/diversion-dns-ui',0o755),('ui.uci','etc/config/diversion-dns-ui',0o600),('profile.json','etc/diversion-dns-ui/profile.json',0o600)]:put(roots[UI],remote,(base/local).read_bytes(),mode)
    view=(ui/'view.js').read_text();assert view.count(' deviceMode: false,')==1
    view=view.replace(' deviceMode: false,',' deviceMode: true,',1)
    asset='diversion-dns/device-'+sha(view.encode())[:12]
    put(roots[UI],'www/luci-static/resources/view/'+asset+'.js',view)
    redirect=(ui/'device/legacy-redirect.js').read_text()
    redirect_asset='diversion-dns/stats-'+sha(redirect.encode())[:12]
    put(roots[UI],'www/luci-static/resources/view/'+redirect_asset+'.js',redirect)
    menu={'admin/network/pnw-control':{'title':'分流与恢复','order':95,'action':{'type':'view','path':asset},'depends':{'acl':[UI]}},'admin/status/diversion-dns-stats':{'action':{'type':'view','path':redirect_asset},'depends':{'acl':[UI]}}}
    put(roots[UI],'usr/share/luci/menu.d/luci-app-diversion-dns.json',json.dumps(menu,ensure_ascii=False,indent=2))
    acl={UI:{'description':'DNS statistics and bounded device diagnostics','read':{'ubus':{'file':['exec']},'file':{'/usr/libexec/diversion-dns-ui-status':['exec']}},'write':{'ubus':{'file':['exec']},'file':{'/usr/libexec/diversion-dns-ui-control':['exec']}}}}
    put(roots[UI],'usr/share/rpcd/acl.d/luci-app-diversion-dns.json',json.dumps(acl,indent=2))
    configs={CORE:['/etc/config/diversion-dns','/etc/diversion-dns/config.conf','/etc/diversion-dns/cn-domains.txt'],UI:['/etc/config/diversion-dns-ui','/etc/diversion-dns-ui/profile.json']}
    for name,root in roots.items():
        put(root,'usr/share/'+name+'/source.json',json.dumps({'source_commit':commit,'package':name,**({'binary_sha256':sha(binary.read_bytes())} if name==CORE else {})},indent=2))
        put(root,'lib/apk/packages/'+name+'.conffiles','\n'.join(configs[name])+'\n')
        # OpenWrt sysupgrade bookkeeping in addition to APK's native installed database.
        paths=sorted('/'+p for p in contents(root))+['/lib/apk/packages/'+name+'.list']
        put(root,'lib/apk/packages/'+name+'.list','\n'.join(paths)+'\n')
        for p in root.rglob('*'):
            if p.is_dir():p.chmod(0o755)
    return roots

def verify_metadata(meta,expected,name,arch,version,deps):
    info=meta['info']
    if (info['name'],info['arch'],info['version'])!=(name,arch,version):raise ValueError('package identity mismatch')
    if set(info['depends'])!=set(deps):raise ValueError('dependency mismatch')
    files={}
    for directory in meta['paths']:
        prefix=directory.get('name','')
        acl=directory.get('acl',{})
        if str(acl.get('user')) not in ('root','0') or str(acl.get('group')) not in ('root','0'):raise ValueError('non-root package directory owner')
        if prefix.startswith('/') or '..' in Path(prefix).parts:raise ValueError('unsafe directory')
        for item in directory.get('files',[]):
            leaf=item['name'];path=str(Path(prefix)/leaf)
            if '/' in leaf or leaf in ('','.','..') or path in files or item.get('target'):raise ValueError('unsafe payload')
            acl=item['acl']
            if str(acl.get('user')) not in ('root','0') or str(acl.get('group')) not in ('root','0'):raise ValueError('non-root package owner')
            files[path]={'sha256':item['hash'],'bytes':item['size'],'mode':acl['mode']}
    if files!=expected:raise ValueError('managed APK whitelist/hash/mode mismatch')
    if sum(v['bytes'] for v in expected.values())!=info['installed-size']:raise ValueError('installed size mismatch')
    return files

def build(source,binary,work,out,apktool,commit,arch,version,run):
    source,binary,work,out,apktool=map(Path,(source,binary,work,out,apktool))
    package_version=version+'_pre20261019~'+commit[:12]+'-r1'
    roots=stage(source,binary,work/'managed-roots',commit)
    result={'source_commit':commit,'version':package_version,'packages':{}}
    empty=work/'managed-empty-keys';empty.mkdir()
    for name,root in roots.items():
        pkgarch=arch if name==CORE else 'noarch'
        deps=CORE_DEPS if name==CORE else [CORE+'='+package_version]+UI_DEPS
        path=out/(name+'-'+package_version+'_'+pkgarch+'.apk')
        cmd=['fakeroot','sh','-ec','chown -R 0:0 "$1"; shift; exec "$@"','managed-root-owner',root,apktool,'mkpkg','--info','name:'+name,'--info','version:'+package_version,'--info','arch:'+pkgarch,'--info','license:GPL-3.0-or-later','--info','description:Managed DNS '+('core service' if name==CORE else 'statistics and diagnostics'),'--info','origin:diversion-dns-c','--info','url:https://github.com/xfy-see/diversion-dns-c','--info','repo-commit:'+commit,'--info','depends:'+' '.join(deps),'--files',root,'--output',path]
        prefix='core' if name==CORE else 'ui'
        hooks={}
        for hook in sorted((source/'packaging/managed/hooks').glob(prefix+'.*')):
            typ=hook.name.split('.',1)[1];hooks[typ]=hook.read_text();cmd+=['--script',typ+':'+str(hook)]
        run('managed-pack-'+name,cmd)
        raw,_=run('managed-metadata-'+name,[apktool,'adbdump','--format','json',path]);meta=json.loads(raw)
        if meta.get('scripts',{})!=hooks:raise ValueError('APK hook mismatch')
        expected=contents(root);verify_metadata(meta,expected,name,pkgarch,package_version,deps)
        (out/(name+'-metadata.json')).write_text(json.dumps(meta,indent=2)+'\n')
        run('managed-integrity-'+name,[apktool,'verify','--allow-untrusted','--no-network','--keys-dir',empty,path])
        extracted=work/('managed-extracted-'+name);extracted.mkdir()
        run('managed-extract-'+name,[apktool,'extract','--allow-untrusted','--no-network','--keys-dir',empty,'--no-chown','--destination',extracted,path])
        if contents(extracted)!=expected:raise ValueError('extracted managed APK mismatch')
        result['packages'][name]={'filename':path.name,'sha256':sha(path.read_bytes()),'bytes':path.stat().st_size,'arch':pkgarch,'depends':deps,'files':expected}
    (out/'managed-packages.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
