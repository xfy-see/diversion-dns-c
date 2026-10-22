-- Local upgrade readiness only. Public DNS availability is not an install gate.
local M={}
local J=require('luci.jsonc');local F=require('nixio.fs')
local EXE='/usr/libexec/diversion-dns-c'
local function read(path,limit)
 local f=assert(io.open(path),'cannot read '..path);local s=f:read((limit or 2097152)+1);f:close()
 assert(type(s)=='string'and #s<=(limit or 2097152),'invalid or oversized '..path);return s
end
local function instance_list()
 local f=assert(io.popen("ubus -t 3 call service list '{\"name\":\"diversion-dns\"}' 2>/dev/null; printf '\\nUPGRADE_HEALTH_RC=%s\\n' \"$?\""),'cannot query local services')
 local s=f:read(262145)or'';f:close();assert(#s<=262144,'service response too large')
 local body,rc=s:match('^(.*)\nUPGRADE_HEALTH_RC=(%d+)\n$');assert(rc=='0','local service query failed')
 local v=J.parse(body);assert(type(v)=='table'and type(v['diversion-dns'])=='table','resolver service not registered')
 local instances=v['diversion-dns'].instances;assert(type(instances)=='table','resolver instances missing');return instances
end
local function address_hex(host)
 assert(type(host)=='string'and host:match('^%d+%.%d+%.%d+%.%d+$'),'upgrade health requires an IPv4 listener profile')
 local octets={};for s in host:gmatch('%d+')do assert(#s<=3 and tonumber(s)<=255 and(#s==1 or s:sub(1,1)~='0'),'invalid listener address');octets[#octets+1]=tonumber(s)end
 assert(#octets==4,'invalid listener address')
 -- /proc/net IPv4 words use native byte order. The Lua 5.1 chunk header
 -- describes that same ABI; avoid assuming MIPS byte order from its name.
 local header=string.dump(function()end)
 assert(header:sub(1,6)=='\27Lua\81\0'and(header:byte(7)==0 or header:byte(7)==1),'unsupported Lua ABI')
 local out={};if header:byte(7)==1 then for i=4,1,-1 do out[#out+1]=string.format('%02X',octets[i])end
 else for i=1,4 do out[#out+1]=string.format('%02X',octets[i])end end
 return table.concat(out)
end
local function identity(pid)
 local text=read('/proc/'..pid..'/stat',4096);local rest=text:match('^'..pid..' %b() (.*)$');assert(rest,'invalid resolver identity')
 local fields={};for word in rest:gmatch('%S+')do fields[#fields+1]=word end
 assert(fields[1]=='R'or fields[1]=='S'or fields[1]=='D','resolver is not running')
 assert(fields[20]and fields[20]:match('^%d+$'),'resolver start time missing')
 assert(F.readlink('/proc/'..pid..'/exe')==EXE,'resolver executable mismatch')
 return fields[20]
end
local function sockets(pid)
 local found={};local it=assert(F.dir('/proc/'..pid..'/fd'),'resolver descriptors unavailable');local count=0
 for fd in it do
  count=count+1;assert(count<=16384,'too many resolver descriptors')
  if fd:match('^%d+$')then local link=F.readlink('/proc/'..pid..'/fd/'..fd);local inode=link and link:match('^socket:%[(%d+)%]$');if inode then found[inode]=true end end
 end;return found
end
local function bound(protocol,address,port,owned)
 for line in read('/proc/net/'..protocol):gmatch('[^\n]+')do
  local a={};for word in line:gmatch('%S+')do a[#a+1]=word end
  local host,p;if a[2]then host,p=a[2]:match('^(%x+):(%x+)$')end
  if host and(host==address or host=='00000000')and tonumber(p,16)==port and a[3]=='00000000:0000'and a[4]==(protocol=='tcp'and'0A'or'07')and owned[a[10]]then return true end
 end;return false
end
function M.check(profile)
 local ok,err=pcall(function()
  assert(type(profile)=='table','listener profile missing');local address=address_hex(profile.dns_host);local port=profile.dns_port
  assert(type(port)=='number'and port%1==0 and port>=1 and port<=65535,'invalid listener port')
  local candidates=instance_list();local examined=0;local errors={}
  for _,instance in pairs(candidates)do
   examined=examined+1;assert(examined<=16,'too many resolver instances')
   if type(instance)=='table'and instance.running==true and type(instance.pid)=='number'and instance.pid>=1 and instance.pid%1==0 and type(instance.command)=='table'and instance.command[1]==EXE then
    local valid,why=pcall(function()
     local pid=string.format('%.0f',instance.pid);local before=identity(pid);local owned=sockets(pid)
     assert(bound('udp',address,port,owned),'resolver UDP listener missing')
     assert(bound('tcp',address,port,owned),'resolver TCP listener missing')
     assert(identity(pid)==before,'resolver changed during readiness check')
    end)
    if valid then return end;errors[#errors+1]=tostring(why)
   end
  end
  error(#errors>0 and table.concat(errors,'; ')or'no running resolver instance')
 end)
 return ok,not ok and tostring(err)or nil
end
return M
