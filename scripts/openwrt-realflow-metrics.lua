#!/usr/bin/lua
-- Read-only metrics/guard for a privately owned 24h DNS experiment.
-- lua openwrt-realflow-metrics.lua RUN BASE [--guard]
-- lua openwrt-realflow-metrics.lua --check-final RUN/runner/final.json
-- No credentials, DNS names, WireGuard public/private keys or full conntrack dump.
local fs = require('nixio.fs')
local NULL = {}
local function read(path, limit)
 local f=io.open(path,'rb'); if not f then return nil end
 local s=f:read(limit or 1048576); f:close(); return s
end
local function trim(s) return s and s:match('^%s*(.-)%s*$') or nil end
local function quote(s)
 return '"'..s:gsub('[%z\1-\31\\"]',function(c)
  local r={['"']='\\"',['\\']='\\\\',['\b']='\\b',['\f']='\\f',['\n']='\\n',['\r']='\\r',['\t']='\\t'}
  return r[c] or string.format('\\u%04x',c:byte())
 end)..'"'
end
local function encode(v)
 if v==NULL or v==nil then return 'null' end
 if type(v)=='string' then return quote(v) end
 if type(v)=='number' then if v~=v or v==math.huge or v==-math.huge then return 'null' end return string.format('%.17g',v) end
 if type(v)=='boolean' then return v and 'true' or 'false' end
 if type(v)~='table' then error('unsupported JSON value') end
 local isarray=v._array==true; local out={}
 if isarray then for i=1,#v do out[#out+1]=encode(v[i]) end return '['..table.concat(out,',')..']' end
 local keys={}; for k in pairs(v) do if k~='_array' then keys[#keys+1]=k end end; table.sort(keys)
 for _,k in ipairs(keys) do out[#out+1]=quote(k)..':'..encode(v[k]) end
 return '{'..table.concat(out,',')..'}'
end
-- Strict bounded JSON parser. Only --check-final uses it; strings and objects
-- are consumed completely so a nested/malicious "complete" cannot pass a grep.
local function decode(text)
 local p,n=1,#text; local parse
 local function ws() while p<=n and text:sub(p,p):match('%s') do p=p+1 end end
 local function stringval()
  assert(text:sub(p,p)=='"','expected string');p=p+1;local out={}
  while p<=n do
   local c=text:sub(p,p);p=p+1
   if c=='"' then return table.concat(out) end
   if c=='\\' then
    local e=text:sub(p,p);p=p+1;local simple={['"']='"',['\\']='\\',['/']='/',b='\b',f='\f',n='\n',r='\r',t='\t'}
    if simple[e] then out[#out+1]=simple[e]
    elseif e=='u' then local h=text:sub(p,p+3);assert(h:match('^%x%x%x%x$'),'bad unicode');p=p+4
     -- Keep non-ASCII escape representations; no metadata key requires Unicode.
     local code=tonumber(h,16);out[#out+1]=code<128 and string.char(code) or ('\\u'..h)
    else error('bad escape') end
   else assert(c:byte()>=32,'control in string');out[#out+1]=c end
  end
  error('unterminated string')
 end
 parse=function(depth)
  assert(depth<64,'JSON too deep');ws();local c=text:sub(p,p)
  if c=='"' then return stringval() end
  if c=='{' then
   p=p+1;ws();local o={};if text:sub(p,p)=='}' then p=p+1;return o end
   while true do ws();local k=stringval();assert(o[k]==nil,'duplicate key');ws();assert(text:sub(p,p)==':','expected colon');p=p+1;o[k]=parse(depth+1);ws()
    c=text:sub(p,p);p=p+1;if c=='}' then return o end;assert(c==',','expected comma')
   end
  elseif c=='[' then
   p=p+1;ws();local a={_array=true};if text:sub(p,p)==']' then p=p+1;return a end
   while true do a[#a+1]=parse(depth+1);ws();c=text:sub(p,p);p=p+1;if c==']' then return a end;assert(c==',','expected comma') end
  elseif text:sub(p,p+3)=='true' then p=p+4;return true
  elseif text:sub(p,p+4)=='false' then p=p+5;return false
  elseif text:sub(p,p+3)=='null' then p=p+4;return NULL
  else
   local tail=text:sub(p);local number=tail:match('^-?%d+%.%d+[eE][+-]?%d+') or tail:match('^-?%d+[eE][+-]?%d+') or tail:match('^-?%d+%.%d+') or tail:match('^-?%d+')
   assert(number and not number:match('^-?0%d'),'invalid number');p=p+#number;local value=tonumber(number);assert(value and value==value and value~=math.huge and value~=-math.huge,'nonfinite number');return value
  end
 end
 local result=parse(0);ws();assert(p==n+1,'trailing JSON');return result
end
if arg[1]=='--check-final' then
 local path=arg[2] or '';if not path:match('^/data/dns%-ab24%-20261015%-[%w_-]+/runs/[%w_-]+/runner/final%.json$') then io.write('invalid\n');os.exit(2) end
 local text=read(path,4194305);if not text or #text>4194304 then io.write('invalid\n');os.exit(2) end
 local ok,result=pcall(decode,text)
 if not ok or type(result)~='table' or type(result.complete)~='boolean' or result.finished~=true then io.write('invalid\n');os.exit(2) end
 io.write(result.complete and 'complete\n' or 'incomplete\n');os.exit(result.complete and 0 or 1)
end
local run,base=arg[1] or '',arg[2] or ''
local id=base:match('^/data/dns%-ab24%-20261015%-([%w_-]+)$')
local phase=id and run:match('^'..base:gsub('([^%w])','%%%1')..'/runs/([%w_-]+)$')
if not id or #id>64 or not phase or #phase>64 or trim(read(base..'/OWNERSHIP',256))~=id then io.stderr:write('invalid metrics ownership/path\n');os.exit(2) end
local function number(path) return tonumber(trim(read(path,4096))) or NULL end
local function array(t) t._array=true;return t end
local reasons={};local function reason(s) reasons[#reasons+1]=s end
local function proc(pid)
 local status=read('/proc/'..pid..'/status',65536);local stat=read('/proc/'..pid..'/stat',65536)
 if not status or not stat then return nil end
 local rest=stat:match('^%d+ .*%) (.*)$');if not rest then return nil end
 local fields={};for s in rest:gmatch('%S+') do fields[#fields+1]=s end
 local function field(k) return tonumber(status:match('\n'..k..':%s*(%d+)')) or NULL end
 local fd=0;local iter=fs.dir('/proc/'..pid..'/fd');if iter then for _ in iter do fd=fd+1 end else fd=NULL end
 return {pid=pid,rss_kib=field('VmRSS'),vmsize_kib=field('VmSize'),threads=field('Threads'),
  fd_count=fd,starttime=tonumber(fields[20]) or NULL,state=fields[1] or NULL,
  stat_ticks={utime=tonumber(fields[12]) or NULL,stime=tonumber(fields[13]) or NULL},exe=fs.readlink('/proc/'..pid..'/exe') or NULL}
end
local processes={};local totalrss=0
local binaries={a='dns-a',b='dns-b',capture='realflow-capture',runner='realflow-runner'}
for _,name in ipairs({'a','b','capture','runner'}) do
 local identity=read(run..'/'..name..'.identity',1024) or ''
 local pid,start,exe=identity:match('^(%d+) (%d+) ([^\n]+)\n?$');pid=tonumber(pid);start=tonumber(start)
 local data=pid and proc(pid) or nil
 local expectedExit=name=='capture' and fs.stat(run..'/allow_capture_exit')~=nil and (not data or data.state=='Z')
 if expectedExit then processes[name]=NULL
 elseif not data or data.starttime~=start or data.exe~=exe or exe~=base..'/bin/'..binaries[name] or data.state=='Z' then
  processes[name]=data or NULL;reason(name..'_identity_or_liveness')
 else
  processes[name]=data
  if type(data.rss_kib)~='number' then reason(name..'_rss_unavailable')
  else totalrss=totalrss+data.rss_kib;if data.rss_kib>98304 then reason(name..'_rss_limit') end end
 end
end
if totalrss>262144 then reason('owned_total_rss_limit') end
local mem=read('/proc/meminfo',65536) or ''
local available=tonumber(mem:match('MemAvailable:%s*(%d+)')) or NULL
if type(available)~='number' then reason('mem_available_unavailable') elseif available<786432 then reason('mem_available_limit') end
local ct=number('/proc/sys/net/netfilter/nf_conntrack_count');local ctmax=number('/proc/sys/net/netfilter/nf_conntrack_max')
if type(ct)~='number' then reason('conntrack_unavailable') elseif ct>=52428 then reason('conntrack_limit') end
local boot=trim(read('/proc/sys/kernel/random/boot_id',256)) or NULL
if boot~=trim(read(run..'/boot-id',256)) then reason('boot_id_changed') end
local function commandline(command)
 local p=io.popen(command,'r');if not p then return nil end;local s=p:read('*a');p:close();return s
end
-- The caller bounds this entire Lua process group. Keep these subprocesses in
-- that same group; nested independent groups would escape its timeout cleanup.
local diskused=tonumber((commandline('du -sk '..base..' 2>/dev/null') or ''):match('^(%d+)')) or NULL
local diskfree=NULL
for line in (commandline('df -Pk /data 2>/dev/null') or ''):gmatch('[^\n]+') do
 local total,used,free=line:match('^%S+%s+(%d+)%s+(%d+)%s+(%d+)%s+');if free then diskfree=tonumber(free) end
end
if type(diskused)~='number' then reason('disk_usage_unavailable') elseif diskused>524288 then reason('disk_usage_limit') end
if type(diskfree)~='number' then reason('disk_free_unavailable') elseif diskfree<262144 then reason('disk_free_limit') end
local handshake,peers=0,0
for line in (commandline('wg show wg_vpn latest-handshakes 2>/dev/null') or ''):gmatch('[^\n]+') do
 local value=tonumber(line:match('%s(%d+)%s*$'));if value then peers=peers+1;if value>handshake then handshake=value end end
end
local production={pid=NULL,degraded=fs.stat('/etc/diversion-dns-c/degraded')~=nil,recovering=fs.stat('/etc/diversion-dns-c/recovering')~=nil}
local pids=fs.dir('/proc');if pids then for pid in pids do if pid:match('^%d+$') then
 local cmd=read('/proc/'..pid..'/cmdline',4096);if cmd and cmd:match('^/usr/sbin/diversion%-dns%-c%z') then production.pid=tonumber(pid);break end
end end end
-- The observed source disappears if production DNS exits or its guard switches
-- dnsmasq to fallback. A healthy shadow pair alone cannot establish coverage.
if production.pid==NULL then reason('production_dns_missing')
else
 local live=proc(production.pid)
 local identity=trim(read(run..'/production.identity',1024)) or ''
 local pid,start,exe=identity:match('^(%d+) (%d+) ([^\n]+)$')
 if not live or live.state=='Z' or live.pid~=tonumber(pid) or live.starttime~=tonumber(start) or live.exe~=exe then reason('production_dns_identity_changed') end
end
if production.degraded then reason('production_dns_degraded') end
if production.recovering then reason('production_dns_recovering') end
local cpuline=(read('/proc/stat',65536) or ''):match('^(cpu [^\n]+)') or ''
local cpu={};for value in cpuline:gmatch('%d+') do cpu[#cpu+1]=tonumber(value) end
local cachelines={};local f=io.open(run..'/b.stderr.log','rb')
if f then local size=f:seek('end') or 0;f:seek('set',math.max(0,size-16384));local tail=f:read(16384) or '';f:close()
 if size>16384 then tail=tail:gsub('^[^\n]*\n','',1) end
 for line in tail:gmatch('[^\n]+') do local lower=line:lower();if lower:find('cache',1,true) and (lower:find('cn',1,true) or lower:find('foreign',1,true)) then cachelines[#cachelines+1]=line end end
 while #cachelines>32 do table.remove(cachelines,1) end
end
local up=tonumber((read('/proc/uptime',4096) or ''):match('^(%S+)')) or NULL
local result={schema='diversion-realflow-resources-v1',ts_unix_s=os.time(),uptime_s=up,boot_id=boot,processes=processes,
 owned_total_rss_kib=totalrss,rss_scope='sum of a,b,capture,runner; transient supervisor/metrics/bounded overhead is protected by MemAvailable threshold',mem_available_kib=available,conntrack_count=ct,conntrack_max=ctmax,
 wg_vpn={rx_bytes=number('/sys/class/net/wg_vpn/statistics/rx_bytes'),tx_bytes=number('/sys/class/net/wg_vpn/statistics/tx_bytes'),latest_handshake=peers>0 and handshake or NULL,peer_count=peers,scope='interface counters and maximum handshake across peers'},
 production=production,cpu_ticks=array(cpu),disk_usage_kib=diskused,disk_free_kib=diskfree,
 cache_stats_lines=array(cachelines),cache_stats_scope='last 16 KiB, at most 32 matching lines; cumulative snapshots may repeat',
 guard_ok=#reasons==0,guard_reasons=array(reasons)}
io.write(encode(result),'\n')
if arg[3]=='--guard' and #reasons>0 then os.exit(1) end
