-- Device-scoped observation adapter. Never writes network/DNS/firewall configuration.
local J=require('luci.jsonc');local N=require('nixio');local F=require('nixio.fs')
local B='/usr/share/diversion-dns-ui';local R='/var/run/diversion-dns-ui'
local M={};local Q=dofile(B..'/query.lua');local T=dofile(B..'/telemetry.lua')
local function quote(s)return "'"..tostring(s):gsub("'","'\\''").."'" end
local function read(p,limit)local f=io.open(p);if not f then return nil end;local s=f:read((limit or 65536)+1);f:close();if #s>(limit or 65536) then return nil end;return s end
local function load(p)return J.parse(read(p,1048576) or '{}') or {} end
local function save(p,v)local f=assert(io.open(p..'.new','w'));f:write(J.stringify(v));f:close();assert(os.rename(p..'.new',p)) end
local function run(c)
 local f=assert(io.popen('('..c..") 2>&1; printf '\nPNW_DEVICE_RC=%s\n' \"$?\""));local text=f:read(262145) or '';f:close()
 if #text>262144 then return '',255 end
 local body,rc=text:match('^(.*)\nPNW_DEVICE_RC=(%d+)\n$');return body or '',tonumber(rc) or 255
end
local function ms()local a,b=N.gettimeofday();return a*1000+b/1000 end
local function trim(s)return (s or ''):match('^%s*(.-)%s*$')end
local function hash(p)return (run('sha256sum '..quote(p))):match('^([%da-f]+)')end
local function profile()
 local p=load('/etc/diversion-dns-ui/profile.json')
 local kinds={['122']='local',['131']='listener',['lab-local']='local',['lab-listener']='listener',generic='generic'}
 p.kind=assert(kinds[p.device],'unrecognized device profile')
 local cfg=p.kind=='local' and '/etc/diversion-dns-c-lite/config.conf' or p.kind=='listener' and '/etc/diversion-dns-c-test/config.conf' or '/etc/diversion-dns/config.conf'
 assert(p.config==cfg,'invalid config path')
 assert(p.service=='diversion-dns','invalid service')
 local _,host_kind=Q.validate_input(p.dns_host)
 assert((p.kind=='listener' and host_kind=='ipv4') or (p.kind~='listener' and p.dns_host=='127.0.0.1'),'invalid DNS host')
 assert(p.dns_port==(p.kind=='listener' and 15453 or 15353),'invalid DNS port')
 assert(p.selected==(p.kind=='local' and 'wg0' or p.kind=='listener' and 'upstream' or 'unmanaged'),'invalid selected mode')
 return p
end
local function action_map()
 local a={};for _,k in ipairs({'switch-aws','switch-nobrand','switch-usss','switch-usvless'})do a[k]={allowed=false,reason='本设备未部署该受管出口；保留现有网络配置'}end
 for _,k in ipairs({'rollback','rescue','recover','retry-recovery'})do a[k]={allowed=false,reason='本设备未部署 PNW 事务回退与应急恢复机制；不套用主路由规则'}end
 a.check={allowed=true};a.diagnose={allowed=true};return a
end
local function busy()
 local pid=trim(read(R..'/lock/pid',32));return pid:match('^%d+$')~=nil and F.stat('/proc/'..pid)~=nil
end
local function policy_fingerprint()
 return trim(run("(nft -s list chain inet mark_routing classify; nft -s list chain inet mark_routing output; nft -s list chain inet mark_routing prerouting; ip -4 rule show; ip -6 rule show) | sha256sum")):match('^([%da-f]+)')
end
function M.status()
 local p=profile();local current={version='2026.10.19-managed',server_time=os.time(),selected=p.selected,exit_names={wg0='现有 WireGuard wg0',upstream='本机配置的上级网关',unmanaged='尚未验证设备出口'},running=busy(),pending=false,previous_exit=J.null,actions=action_map(),device_profile=p.device,
 mode_text=p.kind=='local' and '现有 mark-routing：国内优先；普通未分类流量按 wg0 策略路由' or p.kind=='listener' and '独立 DNS 测试服务；本机未部署隧道分流' or '管理包已安装；DNS 服务和网络策略需按本机配置启用',
 control_note='保留本设备现有网络。检测与诊断已启用；缺少配套出口或事务机制的操作禁用。检测失败不会修改路由或自动切换。',
 load=trim(read('/proc/loadavg')),memory=tonumber((read('/proc/meminfo') or ''):match('MemAvailable:%s*(%d+)')),
 last=load(R..'/last.json'),health=load(R..'/health.json'),diagnostic=load(R..'/diagnostic.json'),public_exit=load(R..'/public.json'),telemetry=dofile(B..'/window.lua').status(),peers={}}
 current.dns_upstreams=dofile(B..'/dns-status.lua').get({config=p.config,service=p.service,direct_listener=p.direct_listener,binary='/usr/libexec/diversion-dns-c',degraded='/usr/share/diversion-dns-ui/not-managed-degraded'})
 if hash(p.config)~=p.expected_config_sha then
  for _,v in pairs({current.dns_upstreams.cn,current.dns_upstreams.foreign})do v.available=false;v.reason='配置已变化，未确认与已验证运行版本一致'end
 end
 if p.direct_listener then for _,v in pairs({current.dns_upstreams.cn,current.dns_upstreams.foreign})do if v.available then v.reason='独立端口 '..p.dns_port..'；本组件不接管 LAN DNS'end end end
 if p.kind=='local' then
  local hand=run('wg show wg0 latest-handshakes');local latest=0
  for stamp in hand:gmatch('\t(%d+)')do latest=math.max(latest,tonumber(stamp))end
  current.peers={{id='wg0',handshake_age=latest>0 and os.time()-latest or nil,handshake=latest}}
  current.topology_verified=type(p.policy_fingerprint)=='string' and #p.policy_fingerprint==64 and policy_fingerprint()==p.policy_fingerprint
  if not current.topology_verified then current.mode_text='现有策略与已验证快照不同；分流规则需要重新核对'end
 end
 return current
end
local function classify(p,name)
 local result={group='foreign',complete=true,matches={}};local config=read(p.config);local found=false
 for line in (config or ''):gmatch('[^\n]+')do
  local path=line:match('^%s*cn_domain_file%s*=%s*(.-)%s*$')
  if path then
   found=true;local root=p.config:match('^(.*)/[^/]+$')..'/'
   if path:sub(1,1)~='/' then path=root..path end
   if path:sub(1,#root)~=root or path:find('..',1,true) then result.complete=false
   else
    local f=io.open(path);if not f then result.complete=false else
     local size=0;for rule in f:lines()do size=size+#rule+1;if size>16777216 then result.complete=false;break end
      local hit,supported=Q.match_rule(name,rule);if not supported then result.complete=false end
      if hit then result.group='cn';if #result.matches<8 then result.matches[#result.matches+1]={file=path,rule=rule:sub(1,256)}end end
     end;f:close()
    end
   end
  end
 end
 if not found then result.complete=false end
 if result.group~='cn' and not result.complete then result.group='unknown'end
 return result
end
function M.query(input,source)
 local p=profile();local name,kind=Q.validate_input(input)
 if not name then return {ok=false,error=kind}end
 if source~='router' and source~='lan' then return {ok=false,error='本设备仅支持本机和普通 LAN 新连接推断'}end
 local out={ok=true,input=name,kind=kind,source=source,time=os.time(),inference_only=true,answers={},dns={},notes={'基于当前集合及新连接规则推断，不是网站连接或实际出网证明。显式 mark、旧 conntrack、MAC 和端口例外可能改变结果。','DNS 查询使用本设备受管解析器，可能刷新缓存和动态地址集合。'}}
 if kind=='domain' then
  out.classification=classify(p,name)
  for _,typ in ipairs({1,28})do local r=Q.dns_query(name,typ,p.dns_host,p.dns_port);out.dns[#out.dns+1]=r
   for _,a in ipairs(r.answers or {})do if #out.answers<16 then out.answers[#out.answers+1]={family=a.family,address=a.address} end end
  end
 else out.answers={{family=kind=='ipv4' and 4 or 6,address=name}}end
 local known=p.kind=='local' and type(p.policy_fingerprint)=='string' and #p.policy_fingerprint==64 and policy_fingerprint()==p.policy_fingerprint
 for _,a in ipairs(out.answers)do
  local mark=0;a.sets={};a.expected_path='unknown'
  if p.kind=='generic' then
   a.reason='未验证本机策略，不能推断直连或隧道'
  elseif p.kind=='listener' then
   a.reason='本机没有流量分流链；流量交给上级网关，上级策略未在此页推断'
  elseif not known then a.reason='策略与已验证快照不同，拒绝按旧顺序推断'
  else
   local membership=true;local hit
   for _,set in ipairs({'direct_v','geoip_direct_v','dns_direct_v','reserved_v'})do
    local setname=set..a.family;local text,rc=run('nft get element inet mark_routing '..setname..' '..quote('{ '..a.address..' }'))
    if rc==0 and text:find('elements',1,true)then a.sets[#a.sets+1]=setname;hit=hit or set
    elseif rc~=1 or (not text:find('No such file or directory',1,true) and not text:find('does not exist',1,true))then membership=false end
   end
   local route=run('ip -'..a.family..' route get '..quote(a.address)..' mark 0')
   if route:match('^local ') or route:find(' broadcast ',1,true)then a.expected_path='local';a.reason='内核本地或广播路由'
   elseif not membership then a.reason='集合读取不完整'
   elseif hit then mark=hit=='reserved_v' and 0 or 512;a.expected_path=hit=='reserved_v' and 'local' or 'WAN';a.reason=hit=='reserved_v' and '保留地址集合按主路由表处理' or '国内/显式直连集合优先；主路由表经上级网关'
   else mark=256;a.expected_path='tunnel';a.reason='普通新连接未命中直连或保留集合，按 0x100 / table 20220 推断；25565 端口例外未模拟'end
  end
  local route,rc=run('ip -'..a.family..' route get '..quote(a.address)..' mark '..mark)
  a.route={mark=mark,device=route:match('%f[%w]dev%s+(%S+)'),table=route:match('%f[%w]table%s+(%S+)'),available=rc==0,inference_only=true}
  if rc~=0 then a.reason=a.reason..'；对应路由不可用'end
 end
 return out
end
local function foreign_probe(af)
 local started=ms();local text,rc=run('uclient-fetch -'..af..' --no-proxy -T 6 -q -O - https://www.cloudflare.com/cdn-cgi/trace')
 local ip=('\n'..text..'\n'):match('\nip=([^\r\n]+)');ip=dofile(B..'/public-status.lua').canonical_ip(ip,af)
 return {checked_at=os.time(),ip=ip,reachability=rc==0 and ip~=nil,identity_status=rc==0 and ip and 'unconfigured' or 'unavailable',probe_scope='router_https',duration_ms=ms()-started,error=(rc~=0 or not ip) and '国外 HTTPS 目标访问失败或未返回有效地址；保持现有网络' or nil}
end
function M.check()
 local p=profile();local started=ms();local h={selected=p.selected,checks={},details={},ok=true}
 for _,spec in ipairs({{'domestic_dns','www.baidu.com'},{'foreign_dns','www.google.com'}})do
  local results={};local ok=true;local begin=ms()
  for _,typ in ipairs({1,28})do local r=Q.dns_query(spec[2],typ,p.dns_host,p.dns_port);results[#results+1]=r;ok=ok and r.ok and #(r.answers or {})>0 end
  h.checks[spec[1]]=ok;h.details[spec[1]]={ok=ok,duration_ms=ms()-begin,reason=ok and 'A 和 AAAA 均得到地址' or nil,error=not ok and '至少一种地址族未得到正常地址回答' or nil,dns=results};h.ok=h.ok and ok
 end
 local public={selected=p.selected,time=os.time(),domestic=dofile(B..'/public-status.lua').probe()}
 for _,af in ipairs({4,6})do
  local r=foreign_probe(af);public['ipv'..af]=r;h.checks['https_ipv'..af]=r.reachability;h.details['https_ipv'..af]={ok=r.reachability,duration_ms=r.duration_ms,error=r.error};h.ok=h.ok and r.reachability
  local domestic=public.domestic['ipv'..af];h.checks['domestic_https_ipv'..af]=domestic.reachability;h.details['domestic_https_ipv'..af]={ok=domestic.reachability,error=domestic.error};h.ok=h.ok and domestic.reachability
 end
 if p.kind=='local' then
  local latest=0;for n in run('wg show wg0 latest-handshakes'):gmatch('\t(%d+)')do latest=math.max(latest,tonumber(n))end
  local ok=latest>0 and os.time()-latest<180;h.checks.wireguard_handshake=ok;h.details.wireguard_handshake={ok=ok,error=not ok and 'wg0 最近握手超过 180 秒；接口存在不代表隧道可用' or nil};h.ok=h.ok and ok
 end
 h.public_exit=public;h.finished=os.time();h.duration_ms=ms()-started;save(R..'/health.json',h);save(R..'/public.json',public);return h
end
function M.diagnose()
 local p=profile();local metrics=dofile(B..'/metrics.lua');local a=metrics.sample();N.nanosleep(3);local b=metrics.sample()
 local diag={time=os.time(),device=p.device,performance=metrics.delta(a,b),routes4=run('ip -4 route show table all'),routes6=run('ip -6 route show table all'),rules4=run('ip -4 rule show'),rules6=run('ip -6 rule show'),resolver_pid=(T.stats_status()).pid}
 save(R..'/diagnostic.json',diag);return diag
end
function M.main(args)
 local mode=args[1];if mode=='status'then return M.status()end
 if mode=='collect'then return {ok=dofile(B..'/window.lua').collect()}end
 if mode=='query'then assert(not args[4],'unexpected arguments');return M.query(args[2],args[3] or 'router')end
 if mode=='start'then
  local action=args[2];assert((action=='check' or action=='diagnose') and not args[3],'本设备未部署该控制能力，操作已拒绝')
  F.mkdir(R,'700');local lock=R..'/lock'
  if F.stat(lock) and not busy()then os.remove(lock..'/pid');F.rmdir(lock)end
  assert(F.mkdir(lock,'700'),'已有检测或诊断任务正在运行')
  -- Reserve the lock with the live parent PID before fork; never clear a live task.
  local f=assert(io.open(lock..'/pid','w'));f:write(N.getpid());f:close()
  local pid=N.fork();if not pid then os.remove(lock..'/pid');F.rmdir(lock);error('cannot start worker')end
  if pid==0 then
   N.setsid();local null=N.open('/dev/null','r+');if null then N.dup(null,N.stdout);N.dup(null,N.stderr);N.dup(null,N.stdin);null:close()end
   local f=assert(io.open(lock..'/pid','w'));f:write(N.getpid());f:close();local started=ms()
   save(R..'/last.json',{action=action,state='running',time=os.time()})
   local ok,result=pcall(action=='check' and M.check or M.diagnose)
   save(R..'/last.json',{action=action,state=ok and 'success' or 'failed',time=os.time(),duration_ms=ms()-started,message=ok and (action=='check' and (result.ok and '检测完成，全部项目通过' or '检测完成，有失败项；未更改网络') or '诊断已保存') or tostring(result):sub(1,300)})
   os.remove(lock..'/pid');F.rmdir(lock);os.exit(ok and 0 or 1)
  end
  return {accepted=true}
 end
 error('unsupported operation')
end
return M
