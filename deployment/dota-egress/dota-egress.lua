-- Dota IPv4 SDR only. All writers hold the controller's deployment lock.
local M={}
local J=require('luci.jsonc')
local B='/etc/pnw-control/dota-egress';local R='/var/run/pnw-dota-egress'
local choices={aws={label='AWS 游戏隧道',dev='wg_game',mark=16,table=24016},hk={label='香港 SS',dev='pnwhks0',mark=17,table=24017},game={label='当前游戏 SS',dev='pnwgfec0',mark=18,table=24018}}
local ids={'aws','hk','game'}
local function read(p)local f=io.open(p);if not f then return nil end;local s=f:read(262145);f:close();assert(#s<=262144,'Dota file too large');return s end
local function load(p)local s=read(p);if not s then return nil end;local x=J.parse(s);assert(type(x)=='table','invalid Dota JSON');return x end
local function save(p,x)local f=assert(io.open(p..'.new','w'));assert(f:write(J.stringify(x)));assert(f:close());assert(os.rename(p..'.new',p))end
local function run(c)
 local f=assert(io.popen('('..c..") 2>/dev/null; printf '\nDOTA_RC=%s\n' \"$?\""));local s=f:read(262145)or'';f:close();assert(#s<=262144,'Dota command output too large')
 local body,rc=s:match('^(.*)\nDOTA_RC=(%d+)\n$');return body or'',tonumber(rc)or 255
end
local function must(c)local s,rc=run(c);assert(rc==0,'Dota command failed');return s end
local function locked()assert(os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')=='1','Dota write requires deployment lock')end
local function config()local c=load(B..'/config.json');if not c then return nil end;assert(c.version==1 and choices[c.selected],'invalid Dota exit configuration');return c end
local function uptime()return tonumber((read('/proc/uptime')or''):match('^[%d.]+'))or 0 end
function M.delta(previous,current,same_generation)
 assert(type(current)=='number' and current>=0,'invalid Dota counter')
 if not same_generation or type(previous)~='number' or current<previous then return current end
 return current-previous
end
local function public4(ip)
 if type(ip)~='string'then return false end
 local a,b,c,d=ip:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$');a,b,c,d=tonumber(a),tonumber(b),tonumber(c),tonumber(d)
 if not a or not b or not c or not d or a<1 or a>=224 or b>255 or c>255 or d>255 then return false end
 return a~=10 and a~=127 and not(a==100 and b>=64 and b<=127)and not(a==169 and b==254)and not(a==172 and b>=16 and b<=31)and not(a==192 and b==168)and not(a==198 and(b==18 or b==19))
end
function M.relays(data)
 assert(type(data)=='table' and type(data.relay)=='table' and #data.relay>=10 and #data.relay<=2048,'invalid Dota relay list')
 local out={};for _,r in ipairs(data.relay)do
  assert(public4(r.ip)and type(r.first)=='number'and type(r.last)=='number'and r.first==math.floor(r.first)and r.last==math.floor(r.last)and r.first>=1024 and r.last>=r.first and r.last<=65535 and r.last-r.first<1024,'invalid Dota relay tuple')
  out[#out+1]=r.ip..' . '..r.first..'-'..r.last
 end;return table.concat(out,', ')
end
local function nft(s)local f=assert(io.open(R..'/apply.nft','w'));assert(f:write(s));f:close();must('nft -f '..R..'/apply.nft')end
function M.schema()
 local s='table inet pnw_dota_egress {\nset relay4 { type ipv4_addr . inet_service; flags interval; auto-merge; }\nset enabled { type inet_proto; }\n'
 for _,id in ipairs(ids)do for _,d in ipairs({'up','down'})do s=s..'counter '..id..'_'..d..' {}\n'end end
 s=s..'counter rejected {}\nchain choose {}\nchain select { type filter hook prerouting priority -124; policy accept;\nct direction reply return\niifname "br-lan" meta mark { 2, 6, 7, 16, 17, 18 } ip daddr . udp dport @relay4 meta l4proto @enabled jump choose\n}\nchain guard { type filter hook forward priority -23; policy accept;\n'
 for _,id in ipairs(ids)do local c=choices[id];s=s..'ct direction original meta mark '..c.mark..' oifname != "'..c.dev..'" counter name rejected reject\n'end
 s=s..'}\nchain account { type filter hook forward priority 10; policy accept;\n'
 for _,id in ipairs(ids)do local c=choices[id];s=s..'ct direction original ct mark '..c.mark..' oifname "'..c.dev..'" counter name '..id..'_up\nct direction reply ct mark '..c.mark..' iifname "'..c.dev..'" counter name '..id..'_down\n'end
 return s..'}\n}\n'
end
local function routes()
 local rules=must('ip -4 rule show')
 for _,id in ipairs(ids)do local c=choices[id];local pref=12000+c.mark
  local expected='from all fwmark 0x'..string.format('%x',c.mark)..' lookup '..c.table
  local found;for line in rules:gmatch('[^\n]+')do if line:match('^'..pref..':')then assert(not found and line:match('^%d+:%s*(.*)$')==expected,'Dota rule ownership conflict');found=true end end
  local r=run('ip -N -4 route show table '..c.table)
  for line in r:gmatch('[^\n]+')do assert(line:match('proto 187')and(line:match('^unreachable default')or line:match('^default dev '..c.dev..' ')),'Dota route ownership conflict')end
  if not r:find('unreachable default',1,true)then must('ip -4 route add unreachable default proto 187 metric 32767 table '..c.table)end
  if not found then must('ip -4 rule add pref '..pref..' fwmark '..c.mark..' lookup '..c.table)end
  local _,up=run('ip -o link show dev '..c.dev..' | grep -q "<[^>]*UP"')
  local has=r:find('default dev '..c.dev..' ',1,true)
  if up==0 and not has then must('ip -4 route add default dev '..c.dev..' proto 187 metric 10 table '..c.table)
  elseif up~=0 and has then must('ip -4 route del default dev '..c.dev..' proto 187 metric 10 table '..c.table)end
 end
end
local function active()
 local g=load('/etc/pnw-control/game-tunnel/state.json');local _,rc=run("nft get element inet diversion_dns game_enabled '{ udp }'")
 return not not(g and g.enabled==true and rc==0 and not read('/etc/pnw-control/game-tunnel/pending.json'))
end
function M.apply(c)
 locked();assert(c and choices[c.selected],'unknown Dota exit');routes()
 local _,rc=run('nft list table inet pnw_dota_egress');local created=rc~=0
 if created then nft(M.schema())end
 local data=assert(load('/etc/pnw-control/game-tunnel/data.json'),'missing last-good Dota data');local list=M.relays(data);local enabled=active()
 local fingerprint=c.selected..'\n'..tostring(enabled)..'\n'..list
 if created or read(R..'/applied')~=fingerprint then
  local x=choices[c.selected];nft('flush chain inet pnw_dota_egress choose\nadd rule inet pnw_dota_egress choose meta mark set '..x.mark..' ct mark set '..x.mark..'\nflush set inet pnw_dota_egress relay4\nadd element inet pnw_dota_egress relay4 { '..list..' }\nflush set inet pnw_dota_egress enabled\n'..(enabled and'add element inet pnw_dota_egress enabled { udp }\n'or''))
  local f=assert(io.open(R..'/applied','w'));f:write(fingerprint);f:close()
 end
 save(R..'/route.json',{selected=c.selected,enabled=enabled,time=os.time(),interface=choices[c.selected].dev})
end
local function kernel()
 local raw=must('nft -a -j list table inet pnw_dota_egress');local data=assert(J.parse(raw),'invalid Dota kernel reply');local counters={};local handle
 for _,o in ipairs(data.nftables or{})do if o.table then handle=o.table.handle end;if o.counter and o.counter.name then counters[o.counter.name]={bytes=o.counter.bytes,packets=o.counter.packets}end end
 assert(handle,'Dota counter generation unavailable');return counters,(read('/proc/sys/kernel/random/boot_id')or'')..':'..handle
end
function M.collect(force)
 locked();local current,generation=kernel();local now=uptime();local s=load(R..'/traffic.json')or load(B..'/traffic.json')or{totals={},started=os.time(),resets=0}
 local same=s.generation==generation;local dt=same and s.monotonic and now-s.monotonic or 0;local totals=s.totals or{};local rates={}
 for _,id in ipairs(ids)do totals[id]=totals[id]or{};rates[id]={};for _,d in ipairs({'up','down'})do
  local key=id..'_'..d;local cur=assert(current[key],'missing Dota counter');local prev=s.raw and s.raw[key]or{};local delta=M.delta(prev.bytes,cur.bytes,same)
  totals[id][d]=(totals[id][d]or 0)+delta;totals[id][d..'_packets']=(totals[id][d..'_packets']or 0)+M.delta(prev.packets,cur.packets,same)
  if dt>0 and dt<=30 then rates[id][d]=delta/dt end
 end end
 local out={totals=totals,rates=rates,started=s.started or os.time(),updated=os.time(),monotonic=now,generation=generation,raw=current,resets=(s.resets or 0)+(s.generation and not same and 1 or 0),checkpoint=s.checkpoint or 0,rejected=current.rejected and current.rejected.packets or 0}
 save(R..'/traffic.json',out)
 if force or os.time()-out.checkpoint>=300 then out.checkpoint=os.time();save(B..'/traffic.json',out);save(R..'/traffic.json',out)end
 return out
end
function M.switch(id)
 locked();assert(choices[id],'unknown Dota exit');local old=assert(config(),'Dota switching not provisioned');assert(not read(B..'/pending.json'),'Dota recovery required')
 assert(not read('/etc/pnw-control/emergency')and not read('/etc/diversion-dns-c/degraded'),'emergency/degraded mode prevents Dota switching')
 assert(not read('/etc/pnw-control/pending.json')and not read('/etc/pnw-control/game-tunnel/pending.json'),'unfinished transaction')
 must('ip -o link show dev '..choices[id].dev..' | grep -q "<[^>]*UP"')
 M.collect(true);local new={version=1,selected=id};save(B..'/pending.json',{old=old,new=new})
 local ok=pcall(function()M.apply(new);save(B..'/config.json',new)end)
 if not ok then local restored=pcall(function()M.apply(old);save(B..'/config.json',old)end);if restored then os.remove(B..'/pending.json')end;error('Dota switch failed'..(restored and'; restored previous exit'or'; recovery required'))end
 os.remove(B..'/pending.json');return 'Dota 2 出口已切换至 '..choices[id].label..'；请重新连接游戏'
end
function M.tick(force)
 locked();local c=config();if not c then return end
 local pending=load(B..'/pending.json');if pending then assert(pending.old and choices[pending.old.selected],'invalid Dota recovery journal');M.apply(pending.old);save(B..'/config.json',pending.old);os.remove(B..'/pending.json');c=pending.old end
 M.apply(c);M.collect(force)
end
function M.status()
 local c=config();if not c then return{available=false,reason='未部署 Dota 独立出口'}end
 local r=load(R..'/route.json')or{};local stats=load(R..'/traffic.json')or load(B..'/traffic.json')or{};local out={available=true,selected=c.selected,label=choices[c.selected].label,interface=choices[c.selected].dev,enabled=r.enabled==true,updated=r.time,pending=read(B..'/pending.json')~=nil,choices={},traffic=stats,scope='LAN IPv4 Dota SDR; IP packet bytes; excludes Steam, downloads and proxy overhead',checkpoint_seconds=300}
 local selected=choices[c.selected];local route,route_rc=run('ip -4 route get 1.1.1.1 mark '..selected.mark)
 local choose,choose_rc=run('nft list chain inet pnw_dota_egress choose')
 local mark_ok=choose:match('meta mark set 0x0*'..string.format('%x',selected.mark)..'%f[%W]')~=nil or choose:find('meta mark set '..selected.mark..' ',1,true)~=nil
 out.consistent=r.selected==c.selected and type(r.time)=='number'and os.time()-r.time<20 and route_rc==0 and route:find('dev '..selected.dev..' ',1,true)~=nil and route:find('table '..selected.table,1,true)~=nil and choose_rc==0 and mark_ok
 out.readiness_scope='local interface and policy checks; remote connectivity not continuously tested'
 for _,id in ipairs(ids)do local v=choices[id];local _,rc=run('ip -o link show dev '..v.dev..' | grep -q "<[^>]*UP"');out.choices[id]={label=v.label,available=rc==0,interface=v.dev}end
 if not out.consistent then out.error='Dota 独立出口状态过期或不一致'end
 if not stats.updated or os.time()-stats.updated>20 then stats.rates={};out.stats_stale=true end
 return out
end
return M
