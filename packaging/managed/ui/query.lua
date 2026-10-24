-- Bounded rule explanation. Does not change routes, nft rules or configuration.
local M={}
local function q(s) return "'"..tostring(s):gsub("'","'\\''").."'" end
local function read(path,limit)
 local f=io.open(path);if not f then return nil end
 local s=f:read((limit or 262144)+1);f:close();if s and #s>(limit or 262144) then return nil end;return s
end
local function run(command)
 local p=io.popen('('..command..") 2>&1; printf '\nPNW_QUERY_RC=%s\n' \"$?\"")
 if not p then return '',255 end
 local s=p:read(131073) or '';p:close()
 if #s>131072 then return '',255 end
 local body,rc=s:match('^(.*)\nPNW_QUERY_RC=(%d+)\n$');return body or '',tonumber(rc) or 255
end
local function ipv4(s)
 local out={};if not s:match('^%d+%.%d+%.%d+%.%d+$') then return nil end
 for v in s:gmatch('%d+') do if #v>3 or tonumber(v)>255 or (#v>1 and v:sub(1,1)=='0') then return nil end;out[#out+1]=tonumber(v) end
 return out
end
local function ipv6(s)
 if not s:find(':',1,true) or s:find('[^%da-fA-F:]') or s:find(':::',1,true) then return nil end
 local first=s:find('::',1,true);if first and s:find('::',first+2,true) then return nil end
 local count=0;for v in s:gmatch('[^:]+') do if #v>4 then return nil end;count=count+1 end
 if first then return count<8 and count>=0 or nil end
 return count==8 and s:sub(1,1)~=':' and s:sub(-1)~=':' or nil
end
function M.validate_input(s)
 if type(s)~='string' or #s>254 or s=='' or s:find('[%z\1-\32\127]') then return nil,'enter one domain or IPv4/IPv6 address' end
 if ipv4(s) then return s,'ipv4' end
 if ipv6(s) then return s:lower(),'ipv6' end
 if s:match('^[%d.]+$') or s:find(':',1,true) then return nil,'invalid IP address' end
 s=s:lower():gsub('%.$','')
 if #s>253 or #s==0 or s:find('[^a-z0-9.%-]') or s:find('..',1,true) then return nil,'invalid domain; use an ASCII or punycode hostname' end
 for label in s:gmatch('[^.]+') do if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then return nil,'invalid domain label' end end
 if s:sub(1,1)=='.' or s:sub(-1)=='.' then return nil,'invalid domain' end
 return s,'domain'
end
local function u16(x) return string.char(math.floor(x/256),x%256) end
local function r16(s,p) local a,b=s:byte(p,p+1);assert(b,'short DNS response');return a*256+b end
local function name_end(s,p)
 for _=1,128 do
  local n=assert(s:byte(p),'short DNS name')
  if n==0 then return p+1 end
  if n>=192 then local b=assert(s:byte(p+1),'short DNS pointer');assert((n-192)*256+b<#s,'invalid DNS pointer');return p+2 end
  assert(n<64 and p+n<=#s,'invalid DNS label');p=p+n+1
 end
 error('DNS name too long')
end
function M.parse_dns(response,id,question)
 assert(type(response)=='string' and #response>=12,'DNS timeout or short response')
 assert(r16(response,1)==id and r16(response,5)==1 and response:sub(13,12+#question)==question,'DNS response does not match question')
 local flags=r16(response,3);assert(flags>=32768 and math.floor(flags/2048)%16==0,'not a standard DNS response');assert(math.floor(flags/512)%2==0,'truncated DNS response')
 local rcode=flags%16;local count=r16(response,7)+r16(response,9)+r16(response,11);assert(count<=128,'too many DNS records')
 local pos=13+#question;local addresses={};local seen={}
 for i=1,count do
  pos=name_end(response,pos);local typ,class,size=r16(response,pos),r16(response,pos+2),r16(response,pos+8);pos=pos+10
  assert(pos+size<=#response+1,'short DNS record')
  if i<=r16(response,7) and class==1 and ((typ==1 and size==4) or (typ==28 and size==16)) then
   local parts={};local address
   if typ==1 then for x=pos,pos+3 do parts[#parts+1]=tostring(response:byte(x)) end;address=table.concat(parts,'.')
   else for x=pos,pos+15,2 do parts[#parts+1]=string.format('%x',r16(response,x)) end;address=table.concat(parts,':') end
   if not seen[address] and #addresses<16 then addresses[#addresses+1]={family=typ==1 and 4 or 6,address=address};seen[address]=true end
  end
  pos=pos+size
 end
 return {ok=rcode==0,rcode=rcode,answers=addresses,error=rcode~=0 and ('DNS rcode '..rcode) or nil}
end
function M.dns_query(name,typ,server,port)
 local n=require('nixio');local sec,usec=n.gettimeofday();local started=sec+usec/1000000
 local id=(sec+usec+typ)%65536;local encoded='';for label in name:gmatch('[^.]+') do encoded=encoded..string.char(#label)..label end
 local question=encoded..'\0'..u16(typ)..u16(1);local packet=u16(id)..u16(256)..u16(1)..u16(0)..u16(0)..u16(0)..question
 local sock;local ok,result=pcall(function()
  sock=assert(n.socket('inet','dgram'),'cannot create DNS socket');assert(sock:setsockopt('socket','rcvtimeo',2,0),'cannot set DNS timeout')
  assert(sock:connect(server or '127.0.0.1',tostring(port or 53)),'local DNS connect failed');assert(sock:send(packet)==#packet,'DNS send failed')
  return M.parse_dns(sock:recv(8192),id,question)
 end)
 if sock then sock:close() end
 local ending,micro=n.gettimeofday();local out=ok and result or {ok=false,error=tostring(result):sub(1,180),answers={}}
 out.qtype=typ==1 and 'A' or 'AAAA';out.duration_ms=math.max(0,(ending+micro/1000000-started)*1000)
 return out
end
function M.match_rule(name,line)
 line=line:gsub('#.*$',''):match('^%s*(.-)%s*$');if line=='' then return false,true end
 local kind,value=line:match('^(%a+):(.*)$');if not kind then kind='domain';value=line end
 value=value:lower():gsub('%.$','')
 if kind=='full' then return name==value,true end
 if kind=='domain' then value=value:gsub('%.$',''):gsub('^%.','');return value=='' or name==value or name:sub(-#value-1)=='.'..value,true end
 if kind=='keyword' then return name:find(value,1,true)~=nil,true end
 return false,false -- Never treat Lua patterns as the resolver's PCRE rules.
end
local function classify(name,config)
 local out={group='foreign',matches={},complete=true,files=0,unsupported_rules=0};local total=0
 for line in (config or ''):gmatch('[^\r\n]+') do
  local path=line:match('^%s*cn_domain_file%s*=%s*(.-)%s*$')
  if path then
  if out.files>=64 then out.complete=false;break end
  if path:sub(1,1)~='/' then path='/etc/diversion-dns-c/'..path end
  if path:sub(1,21)~='/etc/diversion-dns-c/' or path:find('..',1,true) then out.complete=false
  else
   local f=io.open(path);out.files=out.files+1
   if not f then out.complete=false else
    for line in f:lines() do
     total=total+#line+1;if total>16777216 then out.complete=false;break end
     local hit,supported=M.match_rule(name,line)
     if not supported then out.unsupported_rules=out.unsupported_rules+1;out.complete=false end
     if hit then out.group='cn';if #out.matches<8 then out.matches[#out.matches+1]={file=path,rule=line:sub(1,256)} end end
    end
    f:close()
   end
  end
  end
 end
 if out.files==0 then out.complete=false end
 if out.group~='cn' and not out.complete then out.group='unknown' end
 return out
end
local function reserved(address,family)
 if family==6 then local first=tonumber(address:match('^([%da-fA-F]+)'),16) or 0;return first<8192 or first>=16384 end
 local a=ipv4(address);return a[1]==0 or a[1]==10 or a[1]==127 or a[1]>=224 or (a[1]==100 and a[2]>=64 and a[2]<=127) or (a[1]==169 and a[2]==254) or (a[1]==172 and a[2]>=16 and a[2]<=31) or (a[1]==192 and a[2]==168) or (a[1]==198 and (a[2]==18 or a[2]==19))
end
function M.lookup(input,ctx)
 ctx=ctx or {};local name,kind=M.validate_input(input)
 if not name then return {ok=false,error=kind,input=tostring(input or ''):sub(1,254)} end
 local source=ctx.source or 'router'
 local bypass
 if source~='router' and source~='lan' then
  local ok,config=pcall(function() return require('luci.jsonc').parse(read('/etc/pnw-control/expected-egress.json',65536) or '{}') end)
  local item=ok and type(config)=='table' and config.query_source or nil
  if type(item)~='table' or type(item.ipv4)~='string' or not ipv4(item.ipv4) or type(item.mac)~='string' or not item.mac:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$') or type(item.rule_comment)~='string' or #item.rule_comment<1 or #item.rule_comment>128 or item.rule_comment:find('[%z\1-\31]') or (source~='bypass' and source~=item.ipv4) then
   return {ok=false,error='source selector is not configured locally'}
  end
  bypass=item
 end
 local out={ok=true,input=name,kind=kind,source=source,time=os.time(),inference_only=true,answers={},dns={},notes={
  '根据当前分类集合推断普通新连接；不代表实际连接或公网出口证据。',
  '显式标记、协议端口、源 MAC、其他策略路由、旧连接和客户端自用 DNS 可能改变结果。',
  '域名查询使用路由器本地 DNS；正常解析可能更新 DNS 缓存和动态地址集合。'}}
 if kind=='domain' then
  out.classification=classify(name,read('/etc/diversion-dns-c/config.conf'))
  local seen={};for _,typ in ipairs({1,28}) do local r=M.dns_query(name,typ);out.dns[#out.dns+1]={qtype=r.qtype,ok=r.ok,rcode=r.rcode,error=r.error,duration_ms=r.duration_ms}
   for _,a in ipairs(r.answers or {}) do if not seen[a.address] and #out.answers<16 then out.answers[#out.answers+1]=a;seen[a.address]=true end end
  end
  if #out.answers==0 then out.notes[#out.notes+1]='未取得 A/AAAA 地址；无法根据目标地址推断路径。' end
 else out.answers[1]={family=kind=='ipv4' and 4 or 6,address=name} end
 local chain=source=='router' and 'router_output' or 'split';local rules,rc=run('nft list chain inet diversion_dns '..chain)
 local policy_known=rc==0 and rules:find('@cn4',1,true) and rules:find('@cnsite4',1,true) and rules:find('@cn6',1,true) and rules:find('@cnsite6',1,true) and rules:find('meta mark set 0x00000001',1,true)
 local game_known=true;local game_enabled=false
 if rules:find('@game_site4',1,true) then
  local gate,grc=run('nft list set inet diversion_dns game_enabled')
  game_known=grc==0;game_enabled=game_known and gate:find('tcp',1,true)~=nil
  out.notes[#out.notes+1]='游戏例外优先于国内集合；SDR/登录服务器 IP 还取决于连接协议与端口，此查询不推断这些端口条件。'
 end
 local downloader=false
 if bypass then
  local neighbor=select(1,run('ip -4 neigh show to '..q(bypass.ipv4)..' dev br-lan'))
  downloader=rules:lower():find('ether saddr '..bypass.mac:lower(),1,true)~=nil and rules:find(bypass.rule_comment,1,true)~=nil and neighbor:lower():find('lladdr '..bypass.mac:lower(),1,true)~=nil
  out.notes[#out.notes+1]='下载器按现场 MAC 豁免与当前 IPv4 邻居映射核验；本机 DNS 结果不代表下载器自己的 WAN DNS 结果。'
 end
 local set_available={}
 for _,set in ipairs({'cn4','cnsite4','cn6','cnsite6'}) do local _,exists=run('nft -t list set inet diversion_dns '..set);set_available[set]=exists==0 end
 for _,a in ipairs(out.answers) do
  a.sets={};a.inference_only=true;a.expected_path='unknown'
  local membership_known=true
  for _,set in ipairs(a.family==4 and {'cn4','cnsite4'} or {'cn6','cnsite6'}) do
   -- get element succeeds only for a present key, including interval prefixes.
   local found,code=run('nft get element inet diversion_dns '..set..' '..q('{ '..a.address..' }'))
   if code==0 and found:find('elements',1,true) then a.sets[#a.sets+1]=set
   elseif not set_available[set] or code~=1 or (not found:find('No such file or directory',1,true) and not found:find('does not exist',1,true)) then membership_known=false end
  end
  local gamehit=false
  if game_enabled then
   local gs='game_site'..a.family
   local found,code=run('nft get element inet diversion_dns '..gs..' '..q('{ '..a.address..' }'))
   if code==0 and found:find('elements',1,true)then gamehit=true;a.sets[#a.sets+1]=gs
   elseif code~=1 or (not found:find('No such file or directory',1,true)and not found:find('does not exist',1,true))then game_known=false end
  end
  local base=select(1,run('ip -'..a.family..' route get '..q(a.address)..' mark 0'))
  local localpath=reserved(a.address,a.family) or base:match('^local ') or base:find('dev br-lan',1,true)
  if bypass and not downloader then a.reason='下载器 MAC 豁免或邻居映射未确认'
  elseif not policy_known or not membership_known or not game_known then a.reason='当前策略或集合无法完整读取'
  elseif localpath then a.expected_path='local';a.reason='本地／保留地址或 LAN 路由'
  elseif downloader then a.expected_path='WAN';a.reason='下载器源 MAC 的 WAN 豁免已匹配'
  elseif gamehit then a.expected_path='tunnel';a.reason='Steam/游戏登录社区地址例外优先于国内集合；TCP/UDP 新连接'
  elseif #a.sets>0 then a.expected_path='WAN';a.reason='命中当前国内地址集合 '..table.concat(a.sets,', ')
  else a.expected_path='tunnel';a.reason='未命中国内地址集合，普通流量按 mark=1 推断' end
  if a.expected_path=='tunnel' and (ctx.emergency or (a.family==6 and (ctx.selected=='usss' or ctx.selected=='usvless'))) then a.expected_path='blocked';a.reason=ctx.emergency and '应急隔离阻断隧道标记流量' or '当前美国出口阻断境外 IPv6' end
  local mark=(a.expected_path=='tunnel' or a.expected_path=='blocked') and 1 or 0
  local route,route_rc=run('ip -'..a.family..' route get '..q(a.address)..' mark '..mark)
  a.route={mark=mark,device=route:match('%sdev%s+(%S+)'),table=route:match('%stable%s+(%S+)'),available=route_rc==0,inference_only=true}
 end
 return out
end
return M
