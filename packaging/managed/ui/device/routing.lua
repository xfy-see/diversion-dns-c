-- Opt-in WireGuard default-peer transaction. Addresses and keys are local data.
local J=require('luci.jsonc');local N=require('nixio');local F=require('nixio.fs')
local M={};local B='/usr/share/diversion-dns-ui';local D='/etc/diversion-dns-ui';local R='/var/run/diversion-dns-ui'
local C=D..'/routing.json';local S=D..'/selection.json';local T=D..'/transaction.json'
local P=dofile(B..'/public-status.lua')
local function quote(s)return "'"..tostring(s):gsub("'","'\\''").."'"end
local function read(p)local f=io.open(p);if not f then return nil end;local s=f:read(131073);f:close();assert(#s<=131072,'oversized state');return s end
local function load(p)local s=read(p);return s and assert(J.parse(s),'invalid state JSON') or nil end
local function save(p,v)local f=assert(io.open(p..'.new','w'));f:write(assert(J.stringify(v)));assert(f:close());assert(F.chmod(p..'.new',384));assert(os.rename(p..'.new',p))end
local function run(c)local f=assert(io.popen('('..c..") 2>&1; printf '\nRC=%s\n' \"$?\""));local s=f:read(131073)or'';f:close();assert(#s<=131072,'oversized command response');local b,r=s:match('^(.*)\nRC=(%d+)\n$');return b or'',tonumber(r)or 255 end
local function uptime()return assert(tonumber((read('/proc/uptime')or''):match('^[%d.]+')),'no monotonic clock')end
local function boot()return read('/proc/sys/kernel/random/boot_id')end
local function same(a,b)if type(a)~=type(b)then return false end;if type(a)~='table'then return a==b end;for k,v in pairs(a)do if not same(v,b[k])then return false end end;for k in pairs(b)do if a[k]==nil then return false end end;return true end
local function copy(v)if type(v)~='table'then return v end;local r={};for k,x in pairs(v)do r[k]=copy(x)end;return r end
local function ident(s)return type(s)=='string'and #s>0 and #s<=15 and s:match('^[%w_%-]+$')end
local function key(s)return type(s)=='string'and #s==44 and s:match('^[%w+/]+=+$')end
local function config()
 local c=load(C);if not c or c.enabled~=true then return nil end
 assert(ident(c.interface),'invalid interface');assert(not c.namespace or ident(c.namespace),'invalid namespace')
 assert(c.table and c.table>=1 and c.table<=4294967295 and c.table==math.floor(c.table),'invalid table')
 -- Namespace profiles exercise real isolated flows; host profiles require the
 -- configured probe destinations to route through this same policy table.
 assert(type(c.exits)=='table'and c.exits.aws and c.exits.nobrand,'two exits required')
 assert(type(c.families)=='table'and #c.families>0 and #c.families<=2,'families required')
 local seen={};for _,af in ipairs(c.families)do assert((af==4 or af==6)and not seen[af],'invalid family');seen[af]=true end
 for id,e in pairs(c.exits)do
  assert((id=='aws'or id=='nobrand')and key(e.peer),'invalid exit')
  for _,af in ipairs(c.families)do assert(P.canonical_ip(e['ipv'..af],af),'expected public address required')end
 end
 assert(c.exits.aws.peer~=c.exits.nobrand.peer,'duplicate peer')
 assert(c.initial=='aws'or c.initial=='nobrand','initial selection required');return c
end
local function prefix(c)return c.namespace and 'ip netns exec '..quote(c.namespace)..' 'or''end
local function peers(c)
 local s,rc=run(prefix(c)..'wg show '..quote(c.interface)..' allowed-ips');assert(rc==0,'cannot read peers');local out={}
 for line in s:gmatch('[^\n]+')do local k,rest=line:match('^(%S+)%s+(.*)$');assert(key(k),'invalid peer response');local a={};for ip in rest:gmatch('%S+')do if ip~='(none)'then a[#a+1]=ip end end;table.sort(a);out[k]=a end
 for _,e in pairs(c.exits)do assert(out[e.peer],'configured peer missing')end;return out
end
local function selected(c)local s=load(S);return s and s.selected or c.initial end
local function target(c,before,id)
 local managed={};for _,af in ipairs(c.families)do managed[af==4 and '0.0.0.0/0' or '::/0']=true end
 local out=copy(before);for _,e in pairs(c.exits)do
  local a={};for _,ip in ipairs(out[e.peer])do if not managed[ip]then a[#a+1]=ip end end;out[e.peer]=a
 end
 for _,af in ipairs(c.families)do out[c.exits[id].peer][#out[c.exits[id].peer]+1]=af==4 and'0.0.0.0/0'or'::/0'end
 for _,a in pairs(out)do table.sort(a)end;return out
end
local function apply(c,state)
 local cmd=prefix(c)..'wg set '..quote(c.interface)
 -- Touch only the managed pair; every other peer is checked but never written.
 for _,id in ipairs({'aws','nobrand'})do local k=c.exits[id].peer;cmd=cmd..' peer '..quote(k)..' allowed-ips '..quote(table.concat(state[k],','))end
 local _,rc=run(cmd);assert(rc==0,'WireGuard update failed');assert(same(peers(c),state),'peer state did not converge')
end
local function runtime(c)
 local p=peers(c);local r={families={},ok=true};local chosen
 for _,af in ipairs(c.families)do
  local matches={};local default=af==4 and'0.0.0.0/0'or'::/0'
  for k,a in pairs(p)do for _,ip in ipairs(a)do if ip==default then local id='unmanaged';for n,e in pairs(c.exits)do if k==e.peer then id=n end end;matches[#matches+1]=id end end end
  local route,rc=run(prefix(c)..'ip -'..af..' route show table '..c.table..' default')
  local id=#matches==1 and matches[1]or'unknown';local lines=0;for _ in route:gmatch('[^\n]+')do lines=lines+1 end
  local good=rc==0 and lines==1 and route:match('^default%s')~=nil and route:match('%f[%w]dev%s+(%S+)')==c.interface and c.exits[id]~=nil
  r.families['ipv'..af]={selected=id,route_ok=good};r.ok=r.ok and good
  chosen=chosen==nil and id or chosen==id and id or'mixed'
 end
 r.selected=chosen or'unknown';r.configured_selected=selected(c);r.ok=r.ok and r.selected==r.configured_selected;return r
end
local function probe(c,id)
 local result={selected=id,time=os.time(),ok=true}
 for _,af in ipairs(c.families)do
  local address=af==4 and'1.1.1.1'or'2606:4700:4700::1111';local url='https://'..(af==4 and address or'['..address..']')..'/cdn-cgi/trace'
  local route,rr=run(prefix(c)..'ip -'..af..' route get '..quote(address))
  local routed=rr==0 and route:find(' dev '..c.interface..' ',1,true)~=nil
  local text,rc=run(prefix(c)..'uclient-fetch -'..af..' --no-proxy -T 5 -q -O - '..quote(url))
  local ip=P.canonical_ip(('\n'..text..'\n'):match('\nip=([^\r\n]+)'),af);local expected=P.canonical_ip(c.exits[id]['ipv'..af],af)
  local ok=routed and rc==0 and ip~=nil and ip==expected
  result['ipv'..af]={ip=ip,expected=expected,reachability=rc==0 and ip~=nil,identity_status=ok and'verified'or'mismatch',probe_scope=c.namespace and'isolated_namespace'or'router_policy',checked_at=os.time(),route_ok=routed};result.ok=result.ok and ok
 end
 return result
end
local function pending(t)return t and(t.state=='prepared'or t.state=='applying'or t.state=='verifying'or t.state=='rolling_back'or t.state=='rollback_failed')end
local function finished(t,state,message)t.state=state;t.message=message;t.finished=os.time();save(T,t)end
local function rollback(t)
 t.state='rolling_back';save(T,t)
 local ok,err=pcall(function()
  assert(same(config(),t.config),'routing configuration changed; manual recovery required')
  local current=peers(t.config)
  -- Refuse to overwrite a third party's peer edits. A single managed operation
  -- may have stopped after one peer: accept each managed row from either state.
  for k,v in pairs(current)do assert(same(v,t.before[k])or((k==t.config.exits.aws.peer or k==t.config.exits.nobrand.peer)and same(v,t.after[k])),'concurrent peer edit; manual recovery required')end
  for k in pairs(t.before)do assert(current[k],'peer removed; manual recovery required')end
  apply(t.config,t.before);save(S,t.selection_before)
 end)
 finished(t,ok and'rolled_back'or'rollback_failed',ok and'切换未提交，已恢复原 peer 与选择' or tostring(err):sub(1,300));return ok
end
local function detached(fn)
 local pid=N.fork();assert(pid,'cannot fork guardian');if pid~=0 then return pid end
 N.setsid();local null=N.open('/dev/null','r+');assert(null);N.dup(null,N.stdin);N.dup(null,N.stdout);N.dup(null,N.stderr);null:close()
 local ok=pcall(fn);os.exit(ok and 0 or 1)
end
local function identity(pid)local s=read('/proc/'..pid..'/stat');return s and s:match('^%d+ %b() (.+)$'):match('^(.*)$') end
local function process_start(pid)local s=identity(pid);if not s then return nil end;local i=0;for value in s:gmatch('%S+')do i=i+1;if i==20 then return value end end end
local function release()os.remove(R..'/route-lock/identity');os.remove(R..'/route-lock/pid');F.rmdir(R..'/route-lock')end
local function mutex()
 F.mkdir(R,448);if not F.mkdir(R..'/route-lock',448)then error('routing operation already running')end
 local f=assert(io.open(R..'/route-lock/pid','w'));f:write(N.getpid());f:close();save(R..'/route-lock/identity',{pid=N.getpid(),start=process_start(N.getpid())})
end
function M.recover()
 local t=load(T);if not pending(t)then return false end
 if t.boot==boot()and uptime()<t.deadline then return false end
 if F.stat(R..'/route-lock')then
  local owner=load(R..'/route-lock/identity');if owner and owner.start and process_start(owner.pid)==owner.start then
   -- The worker has its own session; stop its descendants as well before undo.
   assert(N.kill(-owner.pid,9),'cannot stop expired worker');N.nanosleep(0,100000000)
   assert(process_start(owner.pid)~=owner.start or (identity(owner.pid)or''):match('^Z '),'worker still active')
  end;release()
 end
 mutex();local ok,result=pcall(rollback,t);release();if not ok then error(result)end;return result
end
function M.status()
 local ok,c=pcall(config);if not ok then return {enabled=false,error=tostring(c)}end;if not c then return {enabled=false}end
 local good,r=pcall(runtime,c);if not good then r={ok=false,selected='unknown',configured_selected=selected(c),error=tostring(r)}end
 local t=load(T);return {enabled=true,runtime=r,scope=c.namespace and'隔离测试命名空间；不代表 LAN 出口'or'本机已配置的策略路径',pending=pending(t)or false,transaction=t and{state=t.state,message=t.message,finished=t.finished,target=t.target}or nil,public_exit=t and t.public_exit,previous_exit=(load(S)or{}).previous}
end
function M.start(action)
 assert(not F.stat('/root/diversion-upgrade/active.json')and not F.stat('/var/lock/diversion-upgrade'),'upgrade in progress')
 local c=assert(config(),'routing control disabled');assert(not pending(load(T)),'pending transaction requires recovery')
 local id=action=='rollback'and(load(S)or{}).previous or action:match('^switch%-(%w+)$');assert(c.exits[id],'exit not deployed')
 mutex();local ok,t=pcall(function()
  local before=peers(c);local r=runtime(c);assert(r.selected~='unknown'and r.selected~='mixed','ambiguous runtime selection')
  local after=target(c,before,id)
  local t={id=read('/proc/sys/kernel/random/uuid'),config=copy(c),before=copy(before),after=copy(after),selection_before=load(S)or{selected=c.initial},target=id,state='prepared',boot=boot(),deadline=uptime()+35,started=os.time()}
  -- Reject any default owned by an unmanaged peer before changing anything.
  for k,a in pairs(before)do if k~=c.exits.aws.peer and k~=c.exits.nobrand.peer then for _,ip in ipairs(a)do assert(ip~='0.0.0.0/0'and ip~='::/0','unmanaged default peer')end end end
  save(T,t);return t
 end);release();if not ok then error(t)end
 local ready=R..'/guardian-ready';os.remove(ready)
 local guardian=detached(function()
  local f=assert(io.open(ready,'w'));f:write(N.getpid());f:close()
  while uptime()<t.deadline do N.nanosleep(1);local now=load(T);if not pending(now)or now.id~=t.id then return end end
  M.recover()
 end)
 -- Prove the detached guardian has executed before accepting any mutation.
 local available=false;for _=1,50 do if tonumber(read(ready)or'')==guardian and F.stat('/proc/'..guardian)then available=true;break end;N.nanosleep(0,20000000)end
 if not available then mutex();rollback(t);release();error('guardian did not start; switch refused')end
 detached(function()
  mutex();local f=assert(io.open(R..'/route-lock/pid','w'));f:write(N.getpid());f:close()
  local worked,err=pcall(function()
   t.state='applying';save(T,t);assert(same(config(),c)and same(peers(c),t.before),'state changed before switch');apply(c,t.after)
   t.state='verifying';save(T,t);t.public_exit=probe(c,id);assert(t.public_exit.ok,'public egress identity or route mismatch')
   assert(uptime()<t.deadline and same(config(),c)and same(peers(c),t.after),'transaction expired or state changed')
   save(S,{selected=id,previous=t.selection_before.selected});local r=runtime(c);assert(r.ok,'runtime routes disagree')
   finished(t,'committed','运行 peer、路由及新建 HTTPS 公网出口均通过')
  end)
  if not worked then t.failure=tostring(err):sub(1,300);rollback(t)end;release()
 end)
 return {accepted=true}
end
M._test={same=same,copy=copy,target=target,pending=pending,runtime=runtime,probe=probe,config=config,rollback=rollback}
return M
