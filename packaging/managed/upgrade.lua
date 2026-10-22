#!/usr/bin/lua
-- Root-only guarded installation of a verified local managed APK pair.
-- Invoke: diversion-dns-upgrade /root/diversion-upgrade/<id> start|status|rollback
local J=require('luci.jsonc');local F=require('nixio.fs');local N=require('nixio')
assert(N.getuid()==0,'root required')
local root=assert(arg[1]);assert(root:match('^/root/diversion%-upgrade/[%w_%-]+$'),'invalid transaction directory');assert(root~='/root/diversion-upgrade/recovery','reserved transaction directory')
local mode=arg[2];assert(not arg[3]and(mode=='start'or mode=='status'or mode=='rollback'or mode=='recover'or mode=='recover-worker'),'invalid operation')
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
local function hook_locks_clear()
 for _,name in ipairs(services)do assert(not F.stat('/var/run/'..name..'-package-upgrade.lock'),'legacy package hook lock requires inspection')end
end
local function package_status(allow_owned_broken)
 local rows=assert(J.parse(must("apk query --from installed --installed --format json --fields name,status '*'")))
 local broken={};for _,row in ipairs(rows)do
  assert(type(row.name)=='string'and type(row.status)=='table','invalid APK status')
  for _,flag in ipairs(row.status)do
   if flag~='installed'then
    assert(flag=='broken-files'or flag=='broken-scripts'or flag=='broken-xattr','unknown APK status')
    assert(allow_owned_broken and(row.name==names[1]or row.name==names[2]),'broken package requires inspection: '..row.name)
    broken[row.name]=true
   end
  end
 end;return broken
end
local function installed(side)
 hook_locks_clear();package_status(false)
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
local function simulate(side,recovery)
 local args=packages(side);local force=recovery and' --force-reinstall'or''
 local text,rc=run('apk add --simulate'..force..' --allow-untrusted --no-network '..args)
 local planned={};for line in text:gmatch('[^\n]+')do
  if line:match('^%(%d+/%d+%)')then
   local action,name=line:match('^%(%d+/%d+%) (%w+) ([%w._+%-]+)')
   assert((name==names[1]or name==names[2])and(action=='Installing'or action=='Upgrading'or action=='Downgrading'or action=='Reinstalling'),'unexpected APK plan: '..line)
   planned[name]=true
  end
 end
 if rc~=0 then
  -- APK reports existing broken-script flags even for a valid repair plan.
  -- Accept only our two flagged packages, each explicitly scheduled for repair.
  assert(recovery and rc==1 and not text:find('ERROR:',1,true)and text:match('%d+ errors?;'),'APK simulation failed: '..text:sub(-2000))
  local broken=package_status(true);assert(next(broken),'APK simulation failed without owned broken state')
  for name in pairs(broken)do assert(planned[name],'broken package is not scheduled for repair')end
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
  local p=load('/etc/diversion-dns-ui/profile.json')
  assert(dofile(root..'/upgrade-health.lua').check(p),'local DNS listener health failed')
 end
 local ui=J.parse(must('/usr/libexec/diversion-dns-ui-status'));assert(ui and ui.selected,'UI status failed');check_protected(s)
end
local function starttime(pid)local text=read('/proc/'..pid..'/stat');if not text then return nil end;local i=0;for word in text:match('^%d+ %b() (.*)$'):gmatch('%S+')do i=i+1;if i==20 then return word end end end
-- A dead or job-control-stopped worker cannot make progress. Do not leave
-- service recovery waiting for the overall installation deadline in that case.
local function worker_failed(s)
 if not s.pid or not s.start then return false end
 local text=read('/proc/'..s.pid..'/stat')
 if not text or starttime(s.pid)~=s.start then return true end
 local status=text:match('^%d+ %b() (%S+)')
 return status=='T'or status=='t'or status=='Z'or status=='X'
end
-- A stopped recovery owner is still alive: never kill it or its APK children.
local function process_live(identity)
 if not identity or identity.boot~=boot()or not identity.pid or not identity.start or starttime(identity.pid)~=identity.start then return false end
 local text=read('/proc/'..identity.pid..'/stat');local status=text and text:match('^%d+ %b() (%S+)')
 return status and status~='Z'and status~='X'
end
local function group_live(pgid)
 for pid in assert(F.dir('/proc'),'cannot inspect process groups')do
  if pid:match('^%d+$')then
   local text=read('/proc/'..pid..'/stat')
   local status,group;if text then status,group=text:match('^%d+ %b() (%S+) %S+ (%S+)')end
   if tonumber(group)==pgid and status~='Z'and status~='X'then return true end
  end
 end
 return false
end
local function process_group(pid)
 local text=read('/proc/'..pid..'/stat')
 return text and tonumber(text:match('^%d+ %b() %S+ %S+ (%S+)'))
end
local function isolate_recovery()
 local pid=N.getpid()
 if process_group(pid)~=pid then assert(N.setsid(),'cannot isolate recovery session')end
 assert(process_group(pid)==pid,'recovery session is not isolated')
end
local function stop_installer(s)
 if s.boot~=boot()or not s.pid or s.pid==N.getpid()then return end
 local started=starttime(s.pid)
 -- A recycled PID must never be signalled. A surviving process group keeps
 -- its old group ID allocated, so a different leader identity is unrelated.
 if started and started~=s.start then return end
 if process_live(s)then assert(N.kill(-s.pid,9),'cannot stop original installer')end
 -- A dead leader may leave a shell/APK child. Do not blindly signal an
 -- ownerless group; wait for it to drain before touching configs or APK.
 for _=1,40 do
  if not process_live(s)and not group_live(s.pid)then return end
  N.nanosleep(0,50000000)
 end
 error('original installer process group has not stopped')
end
-- One kernel-owned lock covers preparation, state transitions, commit and
-- the entire rollback. Never unlink it: unlinking permits two lock inodes.
-- lockf locks are released by the kernel on process exit, including SIGKILL.
local active='/root/diversion-upgrade/active.json'
local function with_lock(fn)
 local f=assert(N.open('/var/lock/diversion-upgrade.lock','w','600'),'cannot open upgrade lock')
 if not f:lock('tlock')then f:close();return nil,'busy'end
 local ok,a,b=pcall(fn);f:close();if not ok then error(a)end;return a,b
end
-- A healthy worker waits out a monitor's brief read/decision critical section.
-- Recovery observers remain nonblocking; they must never kill a lock holder.
local function with_worker_lock(fn)
 for _=1,200 do
  local value,why=with_lock(fn);if why~='busy'then return value,why end
  N.nanosleep(0,50000000)
 end
 error('upgrade state lock remained busy')
end
local function terminal(s)return s.state=='committed'or s.state=='rolled_back'or s.state=='rollback_failed'end
local function owns(s)return s.boot==boot()and s.pid==N.getpid()and s.start==starttime(N.getpid())end
-- Call only while holding the global lock, so a later transaction cannot
-- publish active.json between this read and remove.
local function unlock(s)
 local a=read(active)and load(active)
 if a and a.root==root and(s.state=='committed'or s.state=='rolled_back')then os.remove(active)end
end
local function set_phase(phase)
 return with_worker_lock(function()
  local s=load(statefile);assert(s.state=='installing'and owns(s),'worker no longer owns upgrade')
  s.phase=phase;save(statefile,s);return s
 end)
end
local function commit()
 return with_worker_lock(function()
  local s=load(statefile);assert(s.state=='installing'and owns(s),'worker no longer owns upgrade')
  assert(now()<s.deadline,'deadline expired')
  s.state='committed';s.finished=os.time();save(statefile,s);unlock(s);return true
 end)
end
local function check_configs(s)
 for p,digest in pairs(s.configs)do assert(hash(p)==digest,'configuration changed during upgrade')end
 check_protected(s)
end
local function install_new(args)
 -- APK sanitizes script environments unless explicitly requested. Pass only
 -- PATH and our marker, never the caller's credentials or unrelated variables.
 local path=os.getenv('PATH')or'/usr/sbin:/usr/bin:/sbin:/bin'
 must('env -i PATH='..q(path)..' DIVERSION_DNS_GUARDED_UPGRADE=1 apk add --preserve-env --wait 10 --allow-untrusted --no-network '..args)
end
local function activate(s)
 check_configs(s)
 -- Hash equality protects the saved configuration; check it with the new
 -- executable as well, before any running service is stopped.
 if s.running['diversion-dns']then
  local cfg=must('uci -q get diversion-dns.main.config_file'):match('^%s*(.-)%s*$')
  assert(cfg:match('^/etc/[%w_%-]+/config%.conf$'),'unsupported live config path')
  must('/usr/libexec/diversion-dns-c check -c '..q(cfg))
 end
 assert(set_phase('activating'),'recovery in progress')
 for _,name in ipairs(services)do must('/etc/init.d/'..name..(s.running[name]and' restart'or' stop'))end
 must('rm -f /tmp/luci-indexcache.*');must('/etc/init.d/rpcd reload')
end
local function recover(reason,failure)
 local result,why=with_lock(function()
  -- All callers, including the guardian, reread AFTER acquiring the lock.
  -- No process may be signalled based on an earlier snapshot.
  local s=load(statefile)
  if reason~='manual'and terminal(s)then unlock(s);return true,'terminal'end
  if reason=='manual'and s.state=='rolled_back'then unlock(s);return true,'terminal'end
  local a=read(active)and load(active);assert(not a or a.root==root,'another upgrade/recovery is pending')
  if reason=='manual'then assert(s.state=='committed'or s.state=='rollback_failed','active transaction')
  elseif reason=='auto'then
   if s.state~='rolling_back'and s.boot==boot()and now()<s.deadline and not worker_failed(s)then return true,'waiting'end
  elseif reason=='failure'then assert(s.state=='installing'and owns(s),'failure from stale worker')
  else error('invalid recovery reason')end
  local previous=s.state;local old_recovery=s.recovery
  if previous=='rolling_back'and old_recovery and old_recovery.pid~=N.getpid()then
   if process_live(old_recovery)then return true,'waiting'end
   -- A killed recovery leader can leave its shell/APK running. Its dedicated
   -- session lets us wait without signalling the procd loop or descendants.
   if old_recovery.boot==boot()and old_recovery.pgid and old_recovery.pgid==old_recovery.pid and group_live(old_recovery.pgid)then return true,'waiting'end
  end
  -- Publish recovery ownership before considering the previous installer.
  -- Holding the lock through APK means other recovery requests only wait.
  s.state='rolling_back';s.recovery={pid=N.getpid(),start=starttime(N.getpid()),boot=boot(),pgid=process_group(N.getpid())==N.getpid()and N.getpid()or nil}
  s.failure=failure or s.failure;save(statefile,s);save(active,{root=root})
  -- Claim publication can survive a crash BEFORE the original installer is
  -- stopped. Every takeover must re-establish quiescence, even rolling_back.
  local quiet,quiet_error=pcall(stop_installer,s)
  if not quiet then s.recovery_error=tostring(quiet_error);save(statefile,s);return false,'installer-busy'end
  s.installer_quiesced=true;s.recovery_error=nil;save(statefile,s)
  local ok,err=pcall(function()
   hook_locks_clear();local args=simulate('old',true)
   -- Restore valid application config before invoking old installation hooks.
   must('tar -xzpf '..q(root..'/configs.tar.gz')..' -C /')
   must('apk add --force-reinstall --wait 10 --allow-untrusted --no-network '..args)
   must('tar -xzpf '..q(root..'/configs.tar.gz')..' -C /')
   for _,name in ipairs(services)do must('/etc/init.d/'..name..(s.running[name]and' restart'or' stop'))end
   installed('old');for p,digest in pairs(s.configs)do assert(hash(p)==digest,'restored config mismatch')end;health(s)
  end)
  s.state=ok and'rolled_back'or'rollback_failed';s.error=not ok and tostring(err)or nil;s.finished=os.time();save(statefile,s);unlock(s);return ok
 end)
 if why=='busy'then return true,'busy'end
 return result,why
end
local function detach(fn)local pid=assert(N.fork());if pid~=0 then return pid end;N.setsid();local f=assert(N.open('/dev/null','r+'));N.dup(f,N.stdin);N.dup(f,N.stdout);N.dup(f,N.stderr);f:close();local ok,err=pcall(fn);if not ok then save(root..'/worker-error.json',{error=tostring(err)})end;os.exit(ok and 0 or 1)end

if mode=='status'then print(J.stringify(load(statefile)));os.exit(0)end
if mode=='recover'then
 -- A UI monitor must not own a rollback which stops/restarts that UI service.
 if read(active)then must('/root/diversion-upgrade/recovery/diversion-dns-upgrade-recovery start')end
 os.exit(0)
end
if mode=='recover-worker'then isolate_recovery();assert(recover('auto'),'rollback failed');os.exit(0)end
if mode=='rollback'then isolate_recovery();assert(recover('manual'),'rollback failed');print(J.stringify(load(statefile)));os.exit(0)end
-- Preparation must succeed in full before any package/service mutation.
local s,args=with_lock(function()
assert(not F.stat(statefile),'transaction already exists')
assert(not F.stat(active),'another upgrade or recovery is pending')
local route=read('/etc/diversion-dns-ui/transaction.json')and load('/etc/diversion-dns-ui/transaction.json')
assert(not route or route.state=='committed'or route.state=='rolled_back','routing transaction pending')
installed('old');local args=simulate('new');packages('old')
local s={state='prepared',running={},protected={},configs={},boot=boot(),deadline=now()+300,started=os.time()}
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
assert(type(arg[0])=='string'and arg[0]:sub(1,1)=='/','invoke guard by absolute path')
local siblings=assert(arg[0]:match('^(.+)/[^/]+$'))
must('cp '..q(arg[0])..' '..q(root..'/guard.lua'))
must('cp '..q(siblings..'/diversion-dns-upgrade-health.lua')..' '..q(root..'/upgrade-health.lua'))
must(q(siblings..'/diversion-dns-upgrade-arm')..' prepare')
s.deadline=now()+300;save(statefile,s);save(active,{root=root})
must(q(siblings..'/diversion-dns-upgrade-arm')..' start')
return s,args
end)
assert(s,'another upgrade operation is running')
local guardian=detach(function()
 local f=assert(io.open(root..'/ready','w'));f:write(N.getpid());f:close()
 while true do
  local t=load(statefile);if terminal(t)then return end
  recover('auto') -- deadline and owner checks are inside the shared lock
  N.nanosleep(1)
 end
end)
local ready=false;for _=1,50 do if tonumber(read(root..'/ready')or'')==guardian and F.stat('/proc/'..guardian)then ready=true;break end;N.nanosleep(0,20000000)end
assert(ready,'guardian startup failed: no packages changed')
local pid=detach(function()
 s=assert(with_worker_lock(function()
  local t=load(statefile);assert(t.state=='prepared','transaction no longer prepared');assert(now()<t.deadline,'deadline expired before installation')
  t.pid=N.getpid();t.start=starttime(t.pid);t.state='installing';save(statefile,t);return t
 end),'recovery in progress')
 local ok,err=pcall(function()
  install_new(args)
  installed('new');activate(s)
  for _=1,10 do local good=pcall(health,s);if good then assert(commit(),'recovery in progress');return end;N.nanosleep(1)end
  error('post-upgrade health failed')
 end)
 if not ok then recover('failure',tostring(err))end
end)
print(J.stringify({accepted=true,pid=pid,guardian=guardian,transaction=root}))
