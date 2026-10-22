#!/usr/bin/lua
-- Root-only guarded installation of a verified local managed APK pair.
-- Invoke: diversion-dns-upgrade /root/diversion-upgrade/<id> start|status|rollback
local J=require('luci.jsonc');local F=require('nixio.fs');local N=require('nixio')
assert(N.getuid()==0,'root required')
local root=assert(arg[1]);assert(root:match('^/root/diversion%-upgrade/[%w_%-]+$'),'invalid transaction directory')
local mode=arg[2];assert(not arg[3]and(mode=='start'or mode=='status'or mode=='rollback'or mode=='recover'),'invalid operation')
local function q(s)return "'"..tostring(s):gsub("'","'\\''").."'"end
local function read(p)local f=io.open(p);if not f then return nil end;local s=f:read(2097153);f:close();assert(#s<=2097152,'file too large');return s end
local function load(p)return J.parse(assert(read(p),'missing '..p))end
local function save(p,v)local f=assert(io.open(p..'.new','w'));f:write(J.stringify(v));assert(f:close());assert(F.chmod(p..'.new','600'));assert(os.rename(p..'.new',p))end
local function run(cmd)local f=assert(io.popen('('..cmd..") 2>&1; printf '\nRC=%s\n' \"$?\""));local s=f:read(2097153)or'';f:close();assert(#s<=2097152,'command output too large');local b,rc=s:match('^(.*)\nRC=(%d+)\n$');return b or'',tonumber(rc)or 255 end
local function must(cmd)local b,rc=run(cmd);assert(rc==0,'command failed: '..cmd..'\n'..b:sub(-2000));return b end
local function hash(path)return must('sha256sum '..q(path)):match('^([a-f0-9]+)')end
local function now()return tonumber(assert(read('/proc/uptime')):match('^[%d.]+'))end
local function boot()return read('/proc/sys/kernel/random/boot_id')end
local names={'diversion-dns-c','luci-app-diversion-dns'};local services={'diversion-dns','diversion-dns-ui'}
local statefile=root..'/state.json';local plan=load(root..'/plan.json')
local function secure(path)local s=assert(F.lstat(path),'missing protected path');assert(s.type=='dir'and s.uid==0 and s.modestr=='rwx------','transaction path must be root-only directory')end
secure('/root/diversion-upgrade');secure(root)
local function packages(side)
 local p=assert(plan[side]);assert(type(p.version)=='string'and p.version:match('^[%w._~+%-]+$'),'invalid package version');assert(type(p.source_commit)=='string'and #p.source_commit==40 and p.source_commit:match('^[a-f0-9]+$'),'invalid commit')
 secure(root..'/'..side)
 local files={};for _,name in ipairs(names)do
  local row=assert(p.packages[name]);assert(row.filename:match('^[%w._~+%-]+%.apk$'),'invalid APK filename')
  local file=root..'/'..side..'/'..row.filename;assert(F.lstat(file).type=='reg','APK must be regular file');assert(hash(file)==row.sha256,'APK digest mismatch')
  local meta=assert(J.parse(must('apk adbdump --format json '..q(file))))
  assert(meta.info.name==name and meta.info.version==p.version and meta.info['repo-commit']==p.source_commit,'APK identity mismatch')
  files[#files+1]=q(file)
 end;return table.concat(files,' ')
end
local function installed(side)
 local p=plan[side]
 for _,name in ipairs(names)do
  local s=load('/usr/share/'..name..'/source.json');assert(s.source_commit==p.source_commit,'installed source mismatch')
  assert(must('apk list -I '..name):find(name..'-'..p.version..' ',1,true),'installed version mismatch')
  for path,row in pairs(p.packages[name].files)do
   assert(not path:find('..',1,true)and path:sub(1,1)~='/','unsafe manifest path')
   if path:sub(1,4)~='etc/'then assert(hash('/'..path)==row.sha256,'installed payload mismatch: '..path)end
  end
 end
 assert(hash('/usr/libexec/diversion-dns-c')==p.packages['diversion-dns-c'].files['usr/libexec/diversion-dns-c'].sha256,'installed ELF mismatch')
end
local function simulate(side)
 local args=packages(side);local text=must('apk add --simulate --allow-untrusted --no-network '..args)
 for line in text:gmatch('[^\n]+')do
  local action,name=line:match('^%(%d+/%d+%) (%w+) ([%w._+%-]+)')
  if action then assert((name=='diversion-dns-c'or name=='luci-app-diversion-dns')and(action=='Installing'or action=='Upgrading'or action=='Downgrading'or action=='Reinstalling'),'unexpected APK plan: '..line)end
 end;return args
end
-- Warm names are runtime output, not immutable configuration. Keep them in
-- the archive, but do not treat a normal shutdown/save as configuration drift.
local function runtime_files(cfg)
 local values={};for line in (assert(read(cfg),'missing live config')..'\n'):gmatch('([^\n]*)\n')do
  local key,value=line:match('^%s*([%w_]+)%s*=%s*(.-)%s*$')
  if key then values[key]=values[key]or{};values[key][#values[key]+1]=value end
 end
 local warm=values.cache_warm_file;if not warm or #warm==0 or warm[1]==''then return {}end
 assert(#warm==1,'ambiguous warm-file path');warm=warm[1]
 -- Refuse aliases rather than accidentally exempt another configuration file.
 assert(warm:sub(1,1)=='/'and not warm:find('//',1,true)and not warm:find('/%./')and not warm:find('/%.%./')and not warm:match('/%.%.?$'),'warm-file path must be absolute and normalized')
 assert(warm~=cfg and warm:sub(1,12)~='/etc/config/','warm-file overlaps protected configuration')
 for key,entries in pairs(values)do
  if key=='cn_domain_file'or key=='cache_keep_file'or key=='cache_stale_override'then
   for _,value in ipairs(entries)do
    if key=='cache_stale_override'then value=value:match('^%d+:(.+)$')or value end
    assert(value~=warm,'warm-file overlaps a static input')
   end
  end
 end
 return {[warm]=true}
end
local protected={'/etc/config/network','/etc/config/firewall','/etc/config/dhcp'}
local function check_protected(s)for _,p in ipairs(protected)do assert(hash(p)==s.protected[p],'protected network/DHCP configuration changed')end end
local function health(s)
 for _,name in ipairs(services)do local _,rc=run('/etc/init.d/'..name..' running');assert((rc==0)==s.running[name],'service running state mismatch')end
 if s.running['diversion-dns']then
  local p=load('/etc/diversion-dns-ui/profile.json');local Q=dofile('/usr/share/diversion-dns-ui/query.lua')
  for _,typ in ipairs({1,28})do local r=Q.dns_query('www.baidu.com',typ,p.dns_host,p.dns_port);assert(r.ok and #(r.answers or{})>0,'DNS health failed')end
 end
 local ui=J.parse(must('/usr/libexec/diversion-dns-ui-status'));assert(ui and ui.selected,'UI status failed');check_protected(s)
end
local function starttime(pid)local text=read('/proc/'..pid..'/stat');if not text then return nil end;local i=0;for word in text:match('^%d+ %b() (.*)$'):gmatch('%S+')do i=i+1;if i==20 then return word end end end
local function recover(s)
 local lock=root..'/recovery-lock';local st=F.stat(lock)
 if st then
  local owner=read(lock..'/owner.json')and load(lock..'/owner.json')
  if owner then assert(owner.boot~=boot()or starttime(owner.pid)~=owner.start,'recovery already running')
  else assert(st.mtime and os.time()-st.mtime>5,'recovery lock is being reserved')end
  os.remove(lock..'/owner.json');assert(F.rmdir(lock),'cannot release stale recovery lock')
 end
 assert(F.mkdir(lock,'700'),'recovery already running')
 save(lock..'/owner.json',{pid=N.getpid(),start=starttime(N.getpid()),boot=boot()})
 s.state='rolling_back';save(statefile,s)
 local ok,err=pcall(function()
  local args=simulate('old');must('apk add --wait 10 --allow-untrusted --no-network '..args)
  -- Only application configs are restored; network and DHCP are never overwritten.
  must('tar -xzpf '..q(root..'/configs.tar.gz')..' -C /')
  for _,name in ipairs(services)do must('/etc/init.d/'..name..(s.running[name]and' restart'or' stop'))end
  installed('old');for p,digest in pairs(s.configs)do assert(hash(p)==digest,'restored config mismatch')end;health(s)
 end)
 s.state=ok and'rolled_back'or'rollback_failed';s.error=not ok and tostring(err)or nil;s.finished=os.time();save(statefile,s);os.remove(lock..'/owner.json');F.rmdir(lock);return ok
end
local function detach(fn)local pid=assert(N.fork());if pid~=0 then return pid end;N.setsid();local f=assert(N.open('/dev/null','r+'));N.dup(f,N.stdin);N.dup(f,N.stdout);N.dup(f,N.stderr);f:close();local ok,err=pcall(fn);if not ok then save(root..'/worker-error.json',{error=tostring(err)})end;os.exit(ok and 0 or 1)end

if mode=='status'then print(J.stringify(load(statefile)));os.exit(0)end
local active='/root/diversion-upgrade/active.json'
local function unlock()local a=read(active)and load(active);if a and a.root==root then local st=load(statefile);if st.state=='committed'or st.state=='rolled_back'then os.remove(active)end end end
if mode=='recover'then
 local s=load(statefile);if s.state=='committed'or s.state=='rolled_back'or s.state=='rollback_failed'then unlock();os.exit(0)end
 if s.boot==boot()and now()<s.deadline then os.exit(0)end
 if s.boot==boot()and s.pid and s.start==starttime(s.pid)then N.kill(-s.pid,9);N.nanosleep(1)end
 assert(recover(s),'rollback failed');unlock();os.exit(0)
end
if mode=='rollback'then local a=read(active)and load(active);assert(not a or a.root==root,'another upgrade/recovery is pending');local s=load(statefile);assert(s.state~='installing'and s.state~='prepared','active transaction');assert(recover(s),'rollback failed');unlock();print(J.stringify(load(statefile)));os.exit(0)end
assert(not F.stat(statefile),'transaction already exists')
assert(not F.stat(active),'another upgrade or recovery is pending')
local route=read('/etc/diversion-dns-ui/transaction.json')and load('/etc/diversion-dns-ui/transaction.json')
assert(not route or route.state=='committed'or route.state=='rolled_back','routing transaction pending')
-- Preparation must succeed in full before any package/service mutation.
assert(F.mkdir('/var/lock/diversion-upgrade','700'),'another upgrade is preparing; inspect preparation lock before retry')
local prepared,s,args=pcall(function()
installed('old');local args=simulate('new');packages('old')
local s={state='prepared',running={},protected={},configs={},boot=boot(),deadline=now()+120,started=os.time()}
for _,p in ipairs(protected)do s.protected[p]=hash(p)end
for _,name in ipairs(services)do local _,rc=run('/etc/init.d/'..name..' running');s.running[name]=rc==0 end
local paths={'etc/config/diversion-dns','etc/config/diversion-dns-ui','etc/diversion-dns','etc/diversion-dns-ui'}
local cfg=must('uci -q get diversion-dns.main.config_file'):match('^%s*(.-)%s*$')
assert(cfg:match('^/etc/[%w_%-]+/config%.conf$'),'unsupported live config path');local dir=cfg:match('^/(.*)/config%.conf$');if dir~='etc/diversion-dns'then paths[#paths+1]=dir end
local list={};for _,p in ipairs(paths)do if F.stat('/'..p)then list[#list+1]=q(p)end end
must('tar -czpf '..q(root..'/configs.tar.gz')..' -C / '..table.concat(list,' '))
local hashes=must('find '..table.concat(list,' '):gsub("'etc/","'/etc/")..' -type f -exec sha256sum {} \\;')
s.runtime_files=runtime_files(cfg)
for digest,path in hashes:gmatch('([a-f0-9]+)%s+([^\n]+)')do if not s.runtime_files[path]then s.configs[path]=digest end end
assert(type(arg[0])=='string'and arg[0]:sub(1,1)=='/','invoke guard by absolute path');must('cp '..q(arg[0])..' '..q(root..'/guard.lua'));save(statefile,s);save(active,{root=root})
return s,args
end)
F.rmdir('/var/lock/diversion-upgrade');assert(prepared,s)
local guardian=detach(function()
 local f=assert(io.open(root..'/ready','w'));f:write(N.getpid());f:close()
 while now()<s.deadline do N.nanosleep(1);local t=load(statefile);if t.state=='committed'or t.state=='rolled_back'or t.state=='rollback_failed'then return end end
 local t=load(statefile);if t.pid and t.start==starttime(t.pid)then N.kill(-t.pid,9);N.nanosleep(1)end
 recover(t);unlock()
end)
local ready=false;for _=1,50 do if tonumber(read(root..'/ready')or'')==guardian and F.stat('/proc/'..guardian)then ready=true;break end;N.nanosleep(0,20000000)end
assert(ready,'guardian startup failed: no packages changed')
local pid=detach(function()
 s.pid=N.getpid();s.start=starttime(s.pid);s.state='installing';save(statefile,s)
 local ok,err=pcall(function()
  must('apk add --wait 10 --allow-untrusted --no-network '..args)
  installed('new');for p,digest in pairs(s.configs)do assert(hash(p)==digest,'configuration changed during upgrade')end
  for _=1,10 do local good=pcall(health,s);if good then assert(now()<s.deadline,'deadline expired');s.state='committed';s.finished=os.time();save(statefile,s);unlock();return end;N.nanosleep(1)end
  error('post-upgrade health failed')
 end)
 if not ok then s.failure=tostring(err);recover(s);unlock()end
end)
print(J.stringify({accepted=true,pid=pid,guardian=guardian,transaction=root}))
