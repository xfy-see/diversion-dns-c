-- Optional main-router profile. All mutations inherit the controller deployment
-- lock. No credentials or deployment-specific peers/addresses are embedded.
local M={}
local J=require('luci.jsonc')
local F=require('nixio.fs')
local B='/etc/pnw-control/game-tunnel'
local C='/etc/diversion-dns-c/config.conf'
local Q=dofile('/etc/pnw-control/query.lua')
local function quote(x)return "'"..tostring(x):gsub("'","'\\''").."'"end
local function read(p,n)local f=io.open(p);if not f then return nil end;local s=f:read((n or 1048576)+1);f:close();assert(#s<=(n or 1048576),'file too large');return s end
local function write(p,s)local f=assert(io.open(p..'.new','w'));assert(f:write(s));assert(f:close());assert(os.rename(p..'.new',p))end
local function load(p)return J.parse(read(p) or '{}') or {}end
local function save(p,v)write(p,J.stringify(v))end
local function run(c)local f=assert(io.popen('('..c..") 2>&1; printf '\nGAME_RC=%s\n' \"$?\""));local s=f:read(1048577) or '';f:close();assert(#s<=1048576,'command output too large');local b,r=s:match('^(.*)\nGAME_RC=(%d+)\n$');return b or '',tonumber(r) or 255 end
local function must(c)local s,r=run(c);assert(r==0,'game tunnel operation failed: '..s:sub(1,240));return s end
local function locked()assert(os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')=='1','game tunnel requires deployment lock')end
local function egress()
 if not read(B..'/egress.json')then
  if (read('/etc/diversion-dns-c/policy.nft')or ''):find('Dedicated game fail closed',1,true)then
   return {label='独立 AWS',consistent=false,ready=false,error='独立 AWS 配置缺失；不会使用全局出口代替'}
  end
  return nil
 end
 return assert(dofile('/etc/pnw-control/game-egress.lua').status(),'dedicated egress unavailable')
end
local function integer(n,low,high)return type(n)=='number'and n==math.floor(n)and n>=low and n<=high end
local function public4(ip)
 local v,k=Q.validate_input(ip);if k~='ipv4' then return false end
 local a,b=ip:match('^(%d+)%.(%d+)%.');a,b=tonumber(a),tonumber(b)
 return a>0 and a<224 and a~=10 and a~=127 and not(a==192 and b==0) and not(a==198 and b==51) and not(a==203 and b==0) and not(a==100 and b>=64 and b<=127)and not(a==169 and b==254)and not(a==172 and b>=16 and b<=31)and not(a==192 and b==168)and not(a==198 and (b==18 or b==19))
end
-- The two official feeds are consumed as data only. Reject the entire update
-- on malformed/empty/oversized data; never replace last-good with a partial list.
function M.parse_feeds(sdr,cm)
 assert(type(sdr)=='table'and sdr.success==true and type(sdr.pops)=='table'and integer(sdr.revision,1,4294967295),'invalid SDR response')
 assert(type(cm)=='table'and type(cm.response)=='table'and cm.response.success==true and type(cm.response.serverlist)=='table','invalid CM response')
 local out={revision=sdr.revision,updated=os.time(),relay={},cm={}};local seen={};local pops=0
 for _,pop in pairs(sdr.pops)do
  pops=pops+1;assert(pops<=256 and type(pop)=='table','invalid SDR pop')
  for _,relay in ipairs(pop.relays or {})do
   assert(type(relay)=='table'and type(relay.ipv4)=='string'and public4(relay.ipv4),'invalid SDR address')
   local p=relay.port_range;assert(type(p)=='table'and #p==2 and integer(p[1],1024,65535)and integer(p[2],p[1],65535)and p[2]-p[1]<1024,'invalid SDR ports')
   local key=relay.ipv4..':'..p[1]..'-'..p[2];if not seen[key]then out.relay[#out.relay+1]={ip=relay.ipv4,first=p[1],last=p[2]};seen[key]=true end
  end
 end
 seen={}
 for _,server in ipairs(cm.response.serverlist)do
  assert(type(server)=='table'and server.type=='netfilter'and type(server.endpoint)=='string','invalid CM server')
  local ip,port=server.endpoint:match('^(%d+%.%d+%.%d+%.%d+):(%d+)$');port=tonumber(port)
  assert(ip and public4(ip)and integer(port,1024,65535),'invalid CM endpoint')
  if not seen[server.endpoint]then out.cm[#out.cm+1]={ip=ip,port=port};seen[server.endpoint]=true end
 end
 assert(#out.relay>=10 and #out.relay<=2048 and #out.cm>=2 and #out.cm<=1024,'empty or unreasonable game list')
 return out
end
local function verified_data(d)
 assert(type(d)=='table'and integer(d.updated,1,4294967295)and type(d.relay)=='table'and #d.relay>=10 and #d.relay<=2048 and type(d.cm)=='table'and #d.cm>=2 and #d.cm<=1024,'no valid last-good game data')
 for _,r in ipairs(d.relay)do assert(public4(r.ip)and integer(r.first,1024,65535)and integer(r.last,r.first,65535)and r.last-r.first<1024,'invalid stored SDR entry')end
 for _,r in ipairs(d.cm)do assert(public4(r.ip)and integer(r.port,1024,65535),'invalid stored CM entry')end
 return d
end
local function fetch()
 local a=B..'/sdr.download';local b=B..'/cm.download'
 local function download(url,path)
  -- timeout + output limit; no shell data from the downloaded document is run.
  must('(ulimit -f 2048; uclient-fetch --no-proxy -T 10 -q -O '..quote(path)..' '..quote(url)..')')
  return assert(J.parse(assert(read(path))),'invalid JSON')
 end
 local ok,value=pcall(function()return M.parse_feeds(download('https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=570',a),download('https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&cmtype=netfilter',b))end)
 os.remove(a);os.remove(b);assert(ok,value)
 local old=load(B..'/data.json')
 if type(old.relay)=='table'and #old.relay>0 then assert(#value.relay>=#old.relay*0.7,'SDR list shrank unexpectedly; last-good retained')end
 if type(old.cm)=='table'and #old.cm>0 then assert(#value.cm>=#old.cm*0.5,'CM list shrank unexpectedly; last-good retained')end
 if type(old.revision)=='number'then assert(value.revision>=old.revision,'SDR revision went backwards')end
 return value
end
function M.config(original,on)
 assert(type(original)=='string'and not original:find('\r',1,true),'unsupported DNS configuration')
 local begin='# BEGIN PNW GAME TUNNEL\n';local finish='# END PNW GAME TUNNEL\n'
 local a=original:find(begin,1,true);local b=original:find(finish,1,true)
 if a or b then assert(a and b and b>a and not original:find(begin,a+#begin,true)and not original:find(finish,b+#finish,true),'invalid managed game block');original=original:sub(1,a-1)..original:sub(b+#finish)end
 assert(not original:match('tunnel_domain_file%s*=')and not original:match('tunnel_nftset_ipv[46]%s*='),'unmanaged tunnel configuration exists')
 if on then
  if original:sub(-1)~='\n' then original=original..'\n'end
  original=original..begin..'tunnel_domain_file='..B..'/domains.txt\ntunnel_nftset_ipv4=inet,diversion_dns,game_site4,ipv4_addr,32\ntunnel_nftset_ipv6=inet,diversion_dns,game_site6,ipv6_addr,128\n'..finish
 end
 return original
end
-- This is called by the approved apply-policy helper before its single nft
-- transaction. Gate stays empty when disabled; existing WAN/local exemptions
-- remain ahead of the profile's rules in both classifier chains.
function M.bootstrap()
 local lines={}
 local specs={game_enabled='inet_proto',game_site4='ipv4_addr; flags timeout; timeout 1h',game_site6='ipv6_addr; flags timeout; timeout 1h',game_relay4='ipv4_addr . inet_service; flags interval; auto-merge',game_cm4='ipv4_addr . inet_service'}
 for _,name in ipairs({'game_enabled','game_site4','game_site6','game_relay4','game_cm4'})do
  local _,rc=run('nft -t list set inet diversion_dns '..name)
  if rc~=0 then lines[#lines+1]='add set inet diversion_dns '..name..' { type '..specs[name]..'; }'end
 end
 local state=load(B..'/state.json');local pending=read(B..'/pending.json')~=nil
 local data=state.enabled==true and not pending and verified_data(load(B..'/data.json'))or nil
 return table.concat(lines,'\n')..'\n'..M.runtime(data~=nil,data)
end
function M.runtime(on,data)
 local lines={'flush set inet diversion_dns game_enabled','flush set inet diversion_dns game_relay4','flush set inet diversion_dns game_cm4'}
 if on then
  data=verified_data(data)
  local rows={};for _,r in ipairs(data.relay)do rows[#rows+1]=r.ip..' . '..r.first..'-'..r.last end
  lines[#lines+1]='add element inet diversion_dns game_relay4 { '..table.concat(rows,', ')..' }'
  rows={};for _,r in ipairs(data.cm)do rows[#rows+1]=r.ip..' . '..r.port end
  lines[#lines+1]='add element inet diversion_dns game_cm4 { '..table.concat(rows,', ')..' }'
  lines[#lines+1]='add element inet diversion_dns game_enabled { tcp, udp }'
 end
 return table.concat(lines,'\n')..'\n'
end
local function apply_runtime(on,data)
 write(B..'/runtime.nft',M.runtime(on,data));must('nft -c -f '..B..'/runtime.nft');must('nft -f '..B..'/runtime.nft')
end
local function dns_restart()
 must('/usr/sbin/diversion-dns-c check -c '..C)
 must('/etc/init.d/diversion-dns-c restart');must('/etc/init.d/diversion-dns-c running')
 -- procd running means the process exists, not that rule loading/listeners
 -- are ready. A connected UDP socket can receive ECONNREFUSED immediately.
 local last
 for attempt=1,5 do
  local output,rc=run('lua /etc/diversion-dns-c/dns-probe.lua 127.0.0.1 15363 example.com A positive udp')
  if rc==0 then return end
  last=output;if attempt<5 then must('sleep 1')end
 end
 error('DNS did not become ready after bounded retries: '..tostring(last):sub(1,240))
end
function M.recover()
 locked();if not read(B..'/pending.json')then return false end;local p=load(B..'/pending.json');assert(p.state=='applying','invalid game recovery journal')
 assert(type(p.before)=='string'and type(p.after)=='string'and type(p.old)=='table','invalid game recovery journal')
 local now=read(C);assert(now==p.before or now==p.after,'DNS configuration changed externally; game rollback refused')
 write(C,p.before);dns_restart();apply_runtime(p.old.enabled==true,p.old.enabled and load(B..'/data.json')or nil)
 save(B..'/state.json',p.old);must('sync');assert(os.remove(B..'/pending.json'));return true
end
function M.set(on)
 locked();assert(type(on)=='boolean','invalid switch value');assert(not read(B..'/pending.json'),'unfinished game transaction')
 must('/etc/diversion-dns-c/cn-policy.sh audit-runtime')
 assert(not read('/etc/pnw-control/emergency')and not read('/etc/diversion-dns-c/degraded'),'game switch unavailable in emergency/degraded mode')
 local old=load(B..'/state.json');local data
 if on then
  local e=egress();assert(not e or e.ready,e and e.error or 'dedicated egress unavailable')
  -- Downloads happen before any mutation. Failure leaves the current mode.
  data=fetch();save(B..'/data.json',data)
 end
 local before=assert(read(C));local after=M.config(before,on)
 write(B..'/check.conf',after);must('/usr/sbin/diversion-dns-c check -c '..B..'/check.conf')
 save(B..'/pending.json',{state='applying',before=before,after=after,old=old});must('sync')
 local ok,err=pcall(function()
  write(C,after);dns_restart();apply_runtime(on,data)
  if not on then must('nft flush set inet diversion_dns game_site4');must('nft flush set inet diversion_dns game_site6')end
  save(B..'/state.json',{enabled=on,changed=os.time()});must('sync');assert(os.remove(B..'/pending.json'))
 end)
 if not ok then local restored,reason=pcall(M.recover);error(tostring(err)..(restored and '; previous mode restored' or '; rollback failed: '..tostring(reason)))end
 return on and 'Steam login/community and Dota 2 relay exception enabled; downloads keep normal policy; reconnect game clients' or 'Game exception disabled; normal CN policy restored; reconnect game clients'
end
function M.refresh()
 locked();assert(not read(B..'/pending.json'),'unfinished game transaction');local data=fetch();local state=load(B..'/state.json')
 if state.enabled then apply_runtime(true,data)end
 save(B..'/data.json',data);return 'Official game server lists refreshed; current switch preserved'
end
function M.reconcile()
 locked();M.recover()
 local state=load(B..'/state.json');if not state.enabled then return end
 local data=load(B..'/data.json');local attempt=load(B..'/refresh.json')
 if os.time()-(data.updated or 0)<3600 or os.time()-(attempt.time or 0)<1800 then return end
 save(B..'/refresh.json',{time=os.time(),state='running'})
 local ok,err=pcall(M.refresh)
 save(B..'/refresh.json',{time=os.time(),state=ok and 'success' or 'failed',error=not ok and tostring(err):sub(1,240)or nil})
end
function M.status()
 local state=load(B..'/state.json');local data=load(B..'/data.json')
 local gate,rc=run('nft list set inet diversion_dns game_enabled')
 local actual=rc==0 and gate:find('tcp',1,true)~=nil and gate:find('udp',1,true)~=nil
 local cfg=read(C)or '';local configured=cfg:find('# BEGIN PNW GAME TUNNEL\n',1,true)~=nil
 local pending=read(B..'/pending.json')~=nil
 local refresh=load(B..'/refresh.json');local e=egress()
 return {available=true,egress=e,enabled=state.enabled==true,runtime_enabled=actual,consistent=(not e or e.consistent)and rc==0 and actual==(state.enabled==true)and configured==(state.enabled==true)and not pending,pending=pending,refresh_error=refresh.error,updated=data.updated,relay_count=type(data.relay)=='table'and #data.relay or 0,cm_count=type(data.cm)=='table'and #data.cm or 0,downloads='normal',scope='Steam 登录/社区及 Dota 2 SDR；下载沿用原分流；现有设备豁免保留',note='切换后请重连 Steam/游戏。域名分流基于 IP，共享地址可能连带；不覆盖第三方游戏服务器、客户端私有 DNS 或本地缓存未重新解析的连接。'}
end
return M
