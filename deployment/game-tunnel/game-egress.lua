local M={}
local J=require('luci.jsonc')
local B='/etc/pnw-control/game-tunnel'
local function read(p)local f=io.open(p);if not f then return nil end;local s=f:read(8193);f:close();assert(#s<=8192,'egress file too large');return s end
local function run(c)local f=assert(io.popen(c..' 2>/dev/null'));local s=f:read(16385)or '';f:close();assert(#s<=16384,'egress output too large');return s end
function M.status()
 local raw=read(B..'/egress.json');if not raw then return nil end
 local c=assert(J.parse(raw),'invalid dedicated egress config')
 assert(c.interface=='wg_game'and c.mark==2 and c.table==20234 and type(c.peer)=='string'and #c.peer==44 and c.peer:match('^[A-Za-z0-9+/]+=+$'),'invalid dedicated egress identity')
 local d={label='独立 AWS',interface=c.interface,mark=c.mark,table=c.table,consistent=true,ready=false,ipv4=false,ipv6=false}
 for _,af in ipairs({4,6})do
  local r=run('ip -'..af..' route get '..(af==4 and '1.1.1.1' or '2606:4700:4700::1111')..' mark 2')
  d['ipv'..af]=r:match('%sdev%s+wg_game%s')~=nil and r:match('%stable%s+20234%s')~=nil
  d.consistent=d.consistent and d['ipv'..af]
 end
 local peers=run('wg show wg_game allowed-ips');local n=0;local matched=false
 for key,ips in peers:gmatch('([^%s]+)%s+([^\n]+)')do n=n+1;if key==c.peer and ips:find('0.0.0.0/0',1,true)and ips:find('::/0',1,true)then matched=true end end
 d.consistent=d.consistent and n==1 and matched
 for _,chain in ipairs({'router_output','split'})do
  local rules=run('nft list chain inet diversion_dns '..chain)
  for _,set in ipairs({'game_site4','game_site6','game_relay4','game_cm4'})do
   local found=false
   for line in rules:gmatch('[^\n]+')do
    if line:find('@'..set,1,true)then
     found=true;d.consistent=d.consistent and line:find('meta mark set 0x00000002',1,true)~=nil
    end
   end
   d.consistent=d.consistent and found
  end
 end
 for _,name in ipairs({'guard','router_guard'})do
  local rules=run('nft list chain inet diversion_dns '..name)
  local snapshot=J.parse(run('nft -j list chain inet diversion_dns '..name))
  local first
  for _,item in ipairs(type(snapshot)=='table'and type(snapshot.nftables)=='table'and snapshot.nftables or {})do if item.rule then first=item.rule;break end end
  d.consistent=d.consistent and first~=nil and first.comment=='Dedicated game fail closed'
  local line=rules:match('[^\n]*Dedicated game fail closed[^\n]*')or ''
  d.consistent=d.consistent and line:find('oifname != "wg_game"',1,true)~=nil and line:find('meta mark 0x00000002',1,true)~=nil
 end
 local hs=run('wg show wg_game latest-handshakes')
 for key,t in hs:gmatch('([^%s]+)%s+(%d+)')do if key==c.peer then d.handshake_age=math.max(0,os.time()-tonumber(t))end end
 d.ready=d.consistent and d.handshake_age~=nil and d.handshake_age<=180
 if not d.consistent then d.error='独立 AWS 的路由、peer 或防泄漏规则不一致；游戏流量保持隔离'
 elseif not d.ready then d.error='独立 AWS 暂无近期握手；不会回退到其他出口'end
 return d
end
return M
