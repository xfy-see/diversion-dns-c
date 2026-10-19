-- Manual domestic HTTPS observation. No routing, firewall or configuration changes.
-- Matching an active WAN address proves address identity, not a forced WAN route.
local M={}
local SOURCE='https://myip.ipip.net'
local BODY_LIMIT=4096
local FETCH_TIMEOUT=6
local function trim(s) return s:match('^%s*(.-)%s*$') end
local function ipv4(s)
 if type(s)~='string' or not s:match('^%d+%.%d+%.%d+%.%d+$') then return nil end
 local octets={}
 for v in s:gmatch('%d+') do
  if #v>3 or (#v>1 and v:sub(1,1)=='0') or tonumber(v)>255 then return nil end
  octets[#octets+1]=tonumber(v)
 end
 return table.concat(octets,'.'),octets
end
local function ipv6(s)
 if type(s)~='string' or #s>45 or not s:find(':',1,true) then return nil end
 if s:find('.',1,true) then
  local left,tail=s:match('^(.*:)([^:]+)$');local _,v=ipv4(tail)
  if not v then return nil end
  s=left..string.format('%x:%x',v[1]*256+v[2],v[3]*256+v[4])
 end
 if s:find('[^%da-fA-F:]') or s:find(':::',1,true) then return nil end
 local split=s:find('::',1,true)
 if split and s:find('::',split+2,true) then return nil end
 if not split and (s:sub(1,1)==':' or s:sub(-1)==':') then return nil end
 local left,right={},{}
 local function parse(part,out)
  if part=='' then return true end
  if part:sub(1,1)==':' or part:sub(-1)==':' then return false end
  for v in part:gmatch('[^:]+') do if #v>4 then return false end;out[#out+1]=tonumber(v,16) end
  return true
 end
 if split then
  if not parse(s:sub(1,split-1),left) or not parse(s:sub(split+2),right) or #left+#right>=8 then return nil end
 else if not parse(s,left) or #left~=8 then return nil end end
 local words={};for _,n in ipairs(left) do words[#words+1]=n end
 if split then for _=1,8-#left-#right do words[#words+1]=0 end end
 for _,n in ipairs(right) do words[#words+1]=n end
 local best,start,count=0,nil,0;local best_start
 for i=1,9 do
  if i<=8 and words[i]==0 then start=start or i;count=count+1
  else if count>best then best=count;best_start=start end;start=nil;count=0 end
 end
 local result={};for i=1,8 do result[i]=string.format('%x',words[i]) end
 if best>=2 then
  local a,b={},{};for i=1,best_start-1 do a[#a+1]=result[i] end
  for i=best_start+best,8 do b[#b+1]=result[i] end
  return table.concat(a,':')..'::'..table.concat(b,':'),words
 end
 return table.concat(result,':'),words
end
function M.canonical_ip(s,family)
 if family==4 then return ipv4(s) end
 if family==6 then return ipv6(s) end
 return nil
end
local function alive(entry)
 return type(entry)=='table' and (entry.valid==nil or (type(entry.valid)=='number' and entry.valid>0))
end
local function global6(s)
 local canonical,words=ipv6(s)
 if not words or words[1]<0x2000 or words[1]>=0x4000 then return nil end
 return canonical,words
end
function M.in_prefix(address,prefix,bits)
 local _,a=ipv6(address);local _,p=ipv6(prefix)
 if not a or not p or type(bits)~='number' or bits<0 or bits>128 or bits~=math.floor(bits) then return false end
 for i=1,8 do
  local n=math.min(16,bits);if n==0 then return true end
  local divisor=2^(16-n)
  if math.floor(a[i]/divisor)~=math.floor(p[i]/divisor) then return false end
  bits=bits-n
 end
 return true
end
function M.parse_response(body,family)
 if type(body)~='string' or #body>BODY_LIMIT then return nil end
 body=trim(body)
 if body:find('[%z\1-\31\127]') then return nil end
 local address=body:match('^当前 IP：%s*(%S+)%s+来自于：.*$')
  or body:match('^当前 IP:%s*(%S+)%s+来自于:.*$')
  or body:match('^(%S+)$')
 return M.canonical_ip(address,family)
end
-- The external command and output are both bounded. A non-zero fetch status is
-- never rescued by a plausible IP in an error page or partial response.
local function bounded_run(command,limit)
 local p=io.popen('('..command..'; printf "\\nPNW_PUBLIC_RC=%s\\n" "$?") 2>/dev/null | head -c '..(limit+64))
 if not p then return nil,255,'cannot start observation command' end
 local s=p:read(limit+65) or '';p:close()
 if #s>limit+32 then return nil,255,'observation response exceeded size limit' end
 local body,rc=s:match('^(.*)\nPNW_PUBLIC_RC=(%d+)\n$')
 if not body or #body>limit then return nil,255,'observation response was incomplete or too large' end
 return body,tonumber(rc)
end
local function fetch(family)
 return bounded_run('uclient-fetch -'..family..' --no-proxy -T '..FETCH_TIMEOUT..' -q -O - '..SOURCE,BODY_LIMIT)
end
local function interface_status(name)
 -- Names are selected only from the constants below.
 local body,rc,err=bounded_run('ubus -t 3 call network.interface.'..name..' status',65536)
 if rc~=0 then return nil,err or ('interface status failed ('..rc..')') end
 local ok,result=pcall(function() return require('luci.jsonc').parse(body) end)
 if not ok or type(result)~='table' then return nil,'invalid interface status' end
 return result
end
local function safe_interface(fn,name)
 local ok,value,err=pcall(fn,name)
 if not ok then return nil,'interface status unavailable' end
 if type(value)~='table' then return nil,err or 'interface status unavailable' end
 return value
end
local function device(status)
 local name=status and status.l3_device
 return type(name)=='string' and #name<=64 and name:match('^[%w_.:%-]+$') and name or nil
end
local function active(status) return type(status)=='table' and status.up==true end
local function items(value) return type(value)=='table' and value or {} end
local function identify(row,family,statuses)
 local candidates=family==4 and {'wan'} or {'wan_6','wan6','wan'}
 local active_wan=false
 for _,name in ipairs(candidates) do
  local status=statuses[name]
  if active(status) then
   active_wan=true;row.route_device=row.route_device or device(status)
   for _,entry in ipairs(items(status['ipv'..family..'-address'])) do
    local candidate=alive(entry) and (family==6 and global6(entry.address) or ipv4(entry.address)) or nil
    if candidate and candidate==row.ip then
     row.identity_status='wan_matched';row.identity_basis='wan_interface_address';row.wan_interface=name
     row.route_device=device(status);return
    end
   end
  end
 end
 if family==6 and active(statuses.lan) then
  for _,assignment in ipairs(items(statuses.lan['ipv6-prefix-assignment'])) do
   local address=type(assignment)=='table' and assignment['local-address']
   if alive(assignment) and alive(address) and global6(address.address)==row.ip then
    for _,name in ipairs(candidates) do
     local status=statuses[name]
     if active(status) then
      for _,prefix in ipairs(items(status['ipv6-prefix'])) do
       if alive(prefix) and global6(prefix.address) and M.in_prefix(row.ip,prefix.address,prefix.mask) then
        row.identity_status='wan_prefix_matched';row.identity_basis='wan_delegated_local_address';row.wan_interface=name
        row.route_device=device(status);return
       end
      end
     end
    end
   end
  end
 end
 row.identity_status='unverified'
 row.reason=active_wan and 'observed IP does not match an active WAN address; upstream NAT or another policy path may be in use'
  or 'active WAN interface status is unavailable; observed IP cannot be attributed to WAN'
end
function M.probe(deps)
 deps=deps or {};local now=deps.now or os.time;local get_status=deps.interface_status or interface_status
 local statuses={}
 for _,name in ipairs({'wan','wan_6','wan6','lan'}) do statuses[name]=safe_interface(get_status,name) end
 local result={time=now()}
 for _,family in ipairs({4,6}) do
  local row={source=SOURCE,probe_scope='router_domestic_https',identity_status='unavailable',reachability=false,available=false}
  local ok,body,rc,err=pcall(deps.fetch or fetch,family,SOURCE,BODY_LIMIT,FETCH_TIMEOUT)
  row.checked_at=now()
  local ip=ok and rc==0 and M.parse_response(body,family) or nil
  if ip then
   row.ip=ip;row.observed_ip=ip;row.reachability=true;row.available=true;identify(row,family,statuses)
  else
   row.error=not ok and 'domestic HTTPS observation failed' or err or
    (rc~=0 and ('domestic HTTPS observation failed (exit '..tostring(rc or 'unknown')..')') or 'domestic HTTPS response did not contain a valid IPv'..family..' address')
   row.error=tostring(row.error):sub(1,180)
   row.reason=row.error
  end
  result['ipv'..family]=row
 end
 return result
end
M.get=M.probe
M.source=SOURCE
return M
