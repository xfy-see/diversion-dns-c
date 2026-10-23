-- Local upgrade readiness only. Public DNS availability is not an install gate.
local M={}
local J=require('luci.jsonc');local F=require('nixio.fs');local N=require('nixio')
local EXE='/usr/libexec/diversion-dns-c'
local function read(path,limit)
 local f=assert(io.open(path),'cannot read '..path);local ok,s=pcall(f.read,f,(limit or 2097152)+1);f:close()
 assert(ok and type(s)=='string'and #s<=(limit or 2097152),'invalid or oversized '..path);return s
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
local function bound(protocol,address,port,owned,host)
 for line in read('/proc/net/'..protocol):gmatch('[^\n]+')do
  local a={};for word in line:gmatch('%S+')do a[#a+1]=word end
  local local_address,p;if a[2]then local_address,p=a[2]:match('^(%x+):(%x+)$')end
  if local_address and(local_address==address or local_address=='00000000')and tonumber(p,16)==port and a[3]=='00000000:0000'and a[4]==(protocol=='tcp'and'0A'or'07')and owned[a[10]]then
   -- A wildcard owned listener does not prove that an arbitrary profile IP is
   -- local. Probe loopback instead; exact binds prove their own local address.
   return local_address=='00000000'and'127.0.0.1'or host
  end
 end;return nil
end
local function uptime()
 local now=tonumber(read('/proc/uptime',128):match('^(%d+%.%d+)'))
 assert(now and now>=0,'monotonic clock unavailable');return now
end
local function u16(n)return string.char(math.floor(n/256),n%256)end
local function r16(s,p)
 local a,b=s:byte(p,p+1);assert(b,'short DNS response');return a*256+b
end
local function probe_packet()
 local f=assert(io.open('/dev/urandom','rb'),'health nonce unavailable')
 local ok,bytes=pcall(f.read,f,16);f:close()
 assert(ok and type(bytes)=='string'and #bytes==16,'health nonce unavailable')
 local token={};for i=1,#bytes do token[i]=string.format('%02x',bytes:byte(i))end
 local label='upgrade-health-'..table.concat(token)
 local question=string.char(#label)..label..'\7invalid\0'..u16(1)..u16(1)
 local id=r16(bytes,1)
 return u16(id)..u16(256)..u16(1)..string.rep('\0',6)..question,id,question
end
local function name_end(s,pos)
 local resume,expanded,seen=nil,0,{}
 for _=1,128 do
  assert(not seen[pos],'DNS name pointer loop');seen[pos]=true
  local n=assert(s:byte(pos),'short DNS name')
  if n==0 then assert(expanded+1<=255,'DNS name too long');return resume or pos+1 end
  if n>=192 then
   local low=assert(s:byte(pos+1),'short DNS pointer');local target=(n-192)*256+low+1
   assert(target>=13 and target<pos,'invalid DNS pointer')
   resume=resume or pos+2;pos=target
  else
   assert(n<64 and pos+n<=#s,'invalid DNS label');expanded=expanded+n+1
   assert(expanded<255,'DNS name too long');pos=pos+n+1
  end
 end
 error('DNS name too complex')
end
local function response_ok(s,id,question)
 assert(type(s)=='string'and #s>=12+#question and #s<=512,'DNS timeout, short or oversized response')
 local flags=r16(s,3)
 assert(r16(s,1)==id and r16(s,5)==1 and s:sub(13,12+#question):lower()==question,'DNS response does not match question')
 assert(flags>=32768 and math.floor(flags/2048)%16==0,'not a standard DNS response')
 assert(math.floor(flags/512)%2==0,'truncated DNS response')
 local count=r16(s,7)+r16(s,9)+r16(s,11);assert(count<=64,'too many health DNS records')
 local pos=13+#question
 for _=1,count do
  pos=name_end(s,pos);local size=r16(s,pos+8);pos=pos+10
  assert(pos+size<=#s+1,'short DNS record');pos=pos+size
 end
 assert(pos==#s+1,'trailing DNS response data')
 -- Any RCODE, including NXDOMAIN/SERVFAIL, proves local packet processing.
 -- The ordinary .invalid query may contact an upstream; success is not needed.
 return true
end
local function retryable(code,connecting)
 local c=N.const or{}
 return code~=nil and(code==c.EAGAIN or code==c.EWOULDBLOCK or code==c.EINTR or(connecting and(code==c.EINPROGRESS or code==c.EALREADY)))
end
local function roundtrip(kind,host,port)
 local sock;local ok,err=pcall(function()
  local packet,id,question=probe_packet();local deadline=uptime()+8;local operations=0
  sock=assert(N.socket('inet',kind),'cannot create health DNS socket')
  assert(sock:setblocking(false),'cannot make health DNS socket nonblocking')
  local function ready(direction)
   while true do
    operations=operations+1;assert(operations<=2048,'too many health DNS I/O operations')
    local left=deadline-uptime();assert(left>0,'health DNS deadline expired')
    local fds={{fd=sock,events=N.poll_flags(direction)}}
    local count,code=N.poll(fds,math.max(1,math.ceil(left*1000)))
    assert(uptime()<deadline,'health DNS deadline expired')
    if count then
     assert(type(count)=='number'and count>0,'health DNS poll failed or timed out')
     local flags=N.poll_flags(fds[1].revents or 0)
     assert(not flags.err and not flags.nval and flags[direction],'health DNS socket not ready')
     return
    end
    assert(code~=nil and code==(N.const or{}).EINTR,'health DNS poll failed or timed out')
   end
  end
  local connected,code=sock:connect(host,tostring(port))
  assert(connected or retryable(code,true),'local health DNS connect failed')
  ready('out');assert(sock:getsockopt('socket','error')==0,'local health DNS connect failed')
  local wire=kind=='stream'and u16(#packet)..packet or packet;local sent=0
  while sent<#wire do
   ready('out');local n,e=sock:send(wire:sub(sent+1))
   if n then
    assert(type(n)=='number'and n%1==0 and n>0 and n<=#wire-sent,'health DNS send failed')
    assert(kind=='stream'or n==#wire,'partial health DNS datagram');sent=sent+n
   else assert(retryable(e,false),'health DNS send failed')end
  end
  local function receive(size)
   while true do
    ready('in');local data,e=sock:recv(size)
    if data then assert(type(data)=='string'and #data>0 and #data<=size,'health DNS EOF or oversized chunk');return data end
    assert(retryable(e,false),'health DNS receive failed')
   end
  end
  local response
  if kind=='stream'then
   local function exact(size)
    local out='';while #out<size do out=out..receive(size-#out)end;return out
   end
   local size=r16(exact(2),1);assert(size>=12+#question and size<=512,'invalid health DNS TCP frame length')
   response=exact(size)
  else response=receive(513)end
  response_ok(response,id,question);assert(uptime()<deadline,'health DNS deadline expired')
 end)
 if sock then local closed,result=pcall(sock.close,sock);if ok then ok=closed and result;err='cannot close health DNS socket'end end
 assert(ok,tostring(err))
end
function M.check(profile)
 local ok,err=pcall(function()
  assert(type(profile)=='table','listener profile missing');local address=address_hex(profile.dns_host);local port=profile.dns_port
  assert(type(port)=='number'and port%1==0 and port>=1 and port<=65535,'invalid listener port')
  local candidates=instance_list();local examined=0;local errors={}
  for _,instance in pairs(candidates)do
   examined=examined+1;assert(examined<=16,'too many resolver instances')
   if type(instance)=='table'and instance.running==true and type(instance.pid)=='number'and instance.pid>=1 and instance.pid%1==0 and type(instance.command)=='table'and instance.command[1]==EXE then
    local valid,why,start,udp_host,tcp_host=pcall(function()
     local pid=string.format('%.0f',instance.pid);local before=identity(pid);local owned=sockets(pid)
     local udp=assert(bound('udp',address,port,owned,profile.dns_host),'resolver UDP listener missing')
     local tcp=assert(bound('tcp',address,port,owned,profile.dns_host),'resolver TCP listener missing')
     assert(identity(pid)==before,'resolver changed during readiness check')
     return pid,before,udp,tcp
    end)
    if valid then
     -- Only one verified owner is probed. Do not multiply the 16s I/O budget
     -- by the number of procd instances when one listener is unresponsive.
     roundtrip('dgram',udp_host,port);roundtrip('stream',tcp_host,port)
     assert(identity(why)==start,'resolver changed during DNS health probe')
     local after=sockets(why)
     assert(bound('udp',address,port,after,profile.dns_host)==udp_host and bound('tcp',address,port,after,profile.dns_host)==tcp_host,'resolver listeners changed during DNS health probe')
     return
    end;errors[#errors+1]=tostring(why)
   end
  end
  error(#errors>0 and table.concat(errors,'; ')or'no running resolver instance')
 end)
 return ok,not ok and tostring(err)or nil
end
return M
