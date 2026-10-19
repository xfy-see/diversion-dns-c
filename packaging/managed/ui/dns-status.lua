-- Read-only DNS topology. Only whitelisted addresses, interfaces and marks leave
-- this module; no complete service/configuration objects are returned.
local json=require('luci.jsonc')
local M={}
local CONFIG='/etc/diversion-dns-c/config.conf'
local FILTER='/etc/pnw-control/foreign-v4-dns.conf'
local function trim(s) return (s or ''):match('^%s*(.-)%s*$') end
local function q(s) return "'"..tostring(s):gsub("'","'\\''").."'" end
local function read(path,limit)
 local f=io.open(path);if not f then return nil end
 local s=f:read((limit or 65536)+1);f:close()
 if s and #s>(limit or 65536) then return nil end;return s
end
local function run(command)
 local p=io.popen('('..command..") 2>/dev/null; printf '\nPNW_DNS_STATUS_RC=%s\n' \"$?\"")
 if not p then return '',255 end
 local s=p:read(65537) or '';p:close();if #s>65536 then return '',255 end
 local body,rc=s:match('^(.*)\nPNW_DNS_STATUS_RC=(%d+)\n$');return body or '',tonumber(rc) or 255
end
local function family(s)
 if s:match('^%d+%.%d+%.%d+%.%d+$') then
  for n in s:gmatch('%d+') do if #n>3 or tonumber(n)>255 or (#n>1 and n:sub(1,1)=='0') then return nil end end
  return 4
 end
 if not s:find(':',1,true) or s:find('[^%da-fA-F:]') or s:find(':::',1,true) then return nil end
 local first=s:find('::',1,true);if first and s:find('::',first+2,true) then return nil end
 local count=0;for part in s:gmatch('[^:]+') do if #part>4 then return nil end;count=count+1 end
 if (first and count<8) or (not first and count==8 and s:sub(1,1)~=':' and s:sub(-1)~=':') then return 6 end
end
local function endpoint(s,dnsmasq)
 if type(s)~='string' or #s>128 or s:find('[%z\1-\32\127]') then return nil end
 local transport=s:match('^(%a+)://');if transport then
  if dnsmasq or (transport~='tcp' and transport~='udp') then return nil end
  s=s:sub(#transport+4)
 end
 if dnsmasq and s:find('#',1,true) then
  local host,port=s:match('^([^#]+)#(%d+)$');if not host then return nil end
  if family(host)==6 then s='['..host..']:'..port else s=host..':'..port end
 end
 local host,port=s:match('^%[([%da-fA-F:]+)%]:(%d+)$')
 if not host then host,port=s:match('^(%d+%.%d+%.%d+%.%d+):(%d+)$') end
 if not host then host=s;port='53' end
 local af=family(host);port=tonumber(port)
 if not af or not port or port<1 or port>65535 then return nil end
 host=host:lower();local address=(af==6 and '['..host..']' or host)..':'..port
 return {host=host,port=port,family=af,address=(transport and transport..'://' or '')..address,key=host..'#'..port}
end
local function append(list,seen,value)
 if #list>=32 then return false end
 if not seen[value] then list[#list+1]=value;seen[value]=true end;return true
end
local function number(s)
 if not s then return 0 end
 if not s:match('^%d+$') and not s:match('^0[xX][%da-fA-F]+$') then return nil end
 local value=tonumber(s);if not value or value>4294967295 then return nil end;return value
end
local function config(text)
 local out={cn={available=false,upstreams={},mode='unknown'},foreign={available=false,upstreams={},mode='unknown'},listeners={}}
 if type(text)~='string' then return out,'DNS configuration is unavailable' end
 local values={cn_upstream={},foreign_upstream={},listen_udp={},listen_tcp={}}
 for line in (text..'\n'):gmatch('(.-)\n') do
  local key,value=line:match('^%s*([%w_]+)%s*=%s*(.-)%s*$')
  if type(values[key])=='table' then if #values[key]>=32 then return out,'too many DNS upstreams or listeners' end;values[key][#values[key]+1]=value
  elseif key=='cn_interface' or key=='foreign_interface' or key=='cn_mark' or key=='foreign_mark' then
   if values[key]~=nil then return out,'duplicate DNS routing option' end;values[key]=value
  end
 end
 for _,group in ipairs({'cn','foreign'}) do
  local row=out[group];local seen={}
  for _,value in ipairs(values[group..'_upstream']) do
   local parsed=endpoint(value);if not parsed then return out,'invalid numeric DNS upstream' end
   append(row.upstreams,seen,parsed.address)
  end
  if #row.upstreams==0 then return out,'DNS upstream is missing' end
  local iface=values[group..'_interface'] or ''
  if #iface>63 or iface:find('[^%w_.:%-]') then return out,'invalid DNS interface' end
  row.interface=iface~='' and iface or nil;row.mark=number(values[group..'_mark'])
  if not row.mark then return out,'invalid DNS packet mark' end
 end
 for _,key in ipairs({'listen_udp','listen_tcp'}) do for _,value in ipairs(values[key]) do
  local parsed=endpoint(value);if not parsed then return out,'invalid DNS listener' end
  out.listeners[parsed.key]=true
 end end
 return out
end
local function running(exec,parse,name,check)
 local raw,rc=exec("ubus call service list '{\"name\":\""..name.."\"}'")
 if rc~=0 then return false end
 local ok,services=pcall(parse,raw);local instances=ok and type(services)=='table' and services[name] and services[name].instances
 if type(instances)~='table' then return false end
 for _,instance in pairs(instances) do
  if type(instance)=='table' and instance.running==true and type(instance.command)=='table' and check(instance.command) then return true end
 end
 return false
end
local function has_arg(command,flag,value)
 for i,arg in ipairs(command) do if arg==flag and command[i+1]==value then return true end end
 return false
end
local function dnsmasq_sources(exec,reader)
 local raw,rc=exec("uci -q get 'dhcp.@dnsmasq[0].server'");local entries,seen={},{};local valid=rc==0 or trim(raw)==''
 for entry in (raw or ''):gmatch('%S+') do
  local parsed=endpoint(entry,true)
  if not parsed or not append(entries,seen,parsed.address) then valid=false end
 end
 local noresolv,norc=exec("uci -q get 'dhcp.@dnsmasq[0].noresolv'")
 local from='dnsmasq server';noresolv=trim(noresolv)
 if noresolv~='1' then
  if noresolv~='' and noresolv~='0' then valid=false end
  local path,prc=exec("uci -q get 'dhcp.@dnsmasq[0].resolvfile'");path=trim(path)
  if prc~=0 or path=='' then path='/tmp/resolv.conf.d/resolv.conf.auto' end
  -- Do not follow arbitrary UCI paths into secrets; only resolver files under
  -- the usual OpenWrt locations are read, and only nameserver values emitted.
  if #path>192 or path:find('..',1,true) or path:find('[^%w_./%-]') or not (path:match('^/tmp/resolv') or path:match('^/etc/resolv')) then valid=false
  else
   local resolv=reader(path,16384);from=from..' + '..path
   if not resolv then valid=false else for line in (resolv..'\n'):gmatch('(.-)\n') do
    local ip=line:match('^%s*nameserver%s+([^%s]+)')
    if ip then local parsed=endpoint(ip,true);if not parsed or not append(entries,seen,parsed.address) then valid=false end end
   end end
  end
 end
 if norc~=0 and noresolv~='' then valid=false end
 return entries,valid,from,noresolv=='1'
end
local function route(exec,row)
 for _,value in ipairs(row.upstreams) do
  local target=endpoint(value);if not target then return false end
  local command='ip -'..target.family..' route get '..q(target.host)..' mark '..tostring(row.mark or 0)
  if row.interface then command=command..' oif '..q(row.interface) end
  local body,rc=exec(command);local dev=body and body:match('%f[%w]dev%s+([%w_.:%-]+)')
  if rc~=0 or not dev or (row.interface and dev~=row.interface) or body:match('^%s*unreachable') or body:match('^%s*blackhole') or body:match('^%s*prohibit') then return false end
 end
 return true
end
local function filtered(reader,exec,parse,row)
 if #row.upstreams~=1 or endpoint(row.upstreams[1]).key~='127.0.0.1#15364' then return true end
 row.mode='foreign-v4-filter';row.downstream={};local seen={};local body=reader(FILTER,16384)
 if not body then return false,'foreign IPv4-only DNS filter configuration is unavailable' end
 local port,listen,noresolv,filter
 for line in (body..'\n'):gmatch('(.-)\n') do
  line=trim(line)
  if line=='no-resolv' then noresolv=true elseif line=='filter-AAAA' then filter=true
  else local key,value=line:match('^([%w%-]+)=(.*)$')
   if key=='port' then port=value elseif key=='listen-address' then listen=value
   elseif key=='server' then local parsed=endpoint(value,true);if not parsed or not append(row.downstream,seen,parsed.address) then return false,'foreign DNS filter has unsupported forwarding options' end end
  end
 end
 if port~='15364' or listen~='127.0.0.1' or not noresolv or not filter or #row.downstream==0 then return false,'foreign DNS filter forwarding topology is not recognized' end
 local active=running(exec,parse,'pnw-foreign-v4-dns',function(cmd)
  if cmd[1]~='/usr/sbin/dnsmasq' then return false end
  for _,arg in ipairs(cmd) do if arg=='--conf-file='..FILTER then return true end end
  return false
 end)
 if not active then return false,'foreign IPv4-only DNS filter is not running' end
 return true
end
function M.get(deps)
 deps=deps or {};local reader=deps.read or read;local exec=deps.run or run;local parse=deps.parse or json.parse
 local topology,why=config(reader(deps.config or CONFIG,65536))
 local out={cn=topology.cn,foreign=topology.foreign,source=deps.config or CONFIG,observed_at=(deps.now or os.time)(),scope='configured DNS forwarding and route snapshot; not a per-request trace'}
 local upstreams,valid,source,exclusive=dnsmasq_sources(exec,reader)
 if reader(deps.degraded or '/etc/diversion-dns-c/degraded',1024)~=nil then
  for _,key in ipairs({'cn','foreign'}) do out[key]={available=false,upstreams=upstreams,mode='degraded-dnsmasq',reason=valid and #upstreams>0 and 'DNS uses common dnsmasq fallback; domestic/foreign split is inactive' or 'DNS fallback is active but its forwarding targets are unavailable'} end
  out.source=source;return out
 end
 local active=running(exec,parse,deps.service or 'diversion-dns-c',function(cmd) return cmd[1]==(deps.binary or '/usr/sbin/diversion-dns-c') and cmd[2]=='start' and has_arg(cmd,'-c',deps.config or CONFIG) end)
 if not why and not active then why='managed DNS service is not running with the expected configuration' end
 if not why and not deps.direct_listener then
  if not valid or not exclusive or #upstreams==0 then why='dnsmasq forwarding is not exclusively using the managed DNS service'
  else for _,value in ipairs(upstreams) do if not topology.listeners[endpoint(value).key] then why='dnsmasq forwarding does not match the managed DNS listeners';break end end end
 end
 for _,key in ipairs({'cn','foreign'}) do
  local row=out[key];row.mode='diversion';row.reason=why
  if not why then
   local ok,filter_why=true,nil
   if key=='foreign' then ok,filter_why=filtered(reader,exec,parse,row) end
   if not ok then row.reason=filter_why elseif not route(exec,row) then row.reason='DNS upstream route is unavailable or does not match its configured interface'
   else row.available=true end
  end
 end
 return out
end
return M
