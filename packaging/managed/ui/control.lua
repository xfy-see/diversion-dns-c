#!/usr/bin/lua
local json=require('luci.jsonc')
local nixio=require('nixio')
local fs=require('nixio.fs')
local B='/etc/pnw-control';local R='/var/run/pnw-control';local SELF='/usr/libexec/pnw-control'
local VERSION='2026.10.18.2';local PROBE_UID=65533
local function milliseconds() local a,b=nixio.gettimeofday();return a*1000+(b or 0)/1000 end
local function clean_error(e) return tostring(e):gsub('^[^\n]-:%d+: ',''):sub(1,500) end
local function q(s) return "'"..tostring(s):gsub("'","'\\''").."'" end
local function read(p) local f=io.open(p);if not f then return nil end;local s=f:read('*a');f:close();return s end
local function write(p,s) local f=assert(io.open(p..'.new','w'));f:write(s);f:close();assert(os.rename(p..'.new',p)) end
local function load(p) return json.parse(read(p) or '{}') or {} end
local function save(p,v) write(p,json.stringify(v)) end
local function run(s)
 local p=assert(io.popen('('..s..") 2>&1; printf '\nPNW_RC=%s\n' \"$?\""));local out=p:read('*a');p:close()
 local body,rc=out:match('^(.*)\nPNW_RC=(%d+)\n$');return body or '',tonumber(rc) or 255
end
local function must(s,msg) local out,rc=run(s);assert(rc==0,(msg or 'operation failed')..(out~='' and (': '..out:sub(1,240)) or ''));return out end
local function trim(s) return s:match('^%s*(.-)%s*$') end
local function uci(k) return trim(must('uci -q get '..q(k),'missing managed option')) end
local function words(s) local a={};for w in s:gmatch('%S+') do a[#a+1]=w end;return a end
local function equal(a,b) local x,y={},{};for _,v in ipairs(a) do x[#x+1]=v end;for _,v in ipairs(b) do y[#y+1]=v end;table.sort(x);table.sort(y);return table.concat(x,',')==table.concat(y,',') end
local exits={aws={dev='wg_vpn',iface='wg_vpn'},nobrand={dev='wg_vpn',iface='wg_vpn'},usss={dev='pnwuss0',iface='pnw_uss'},usvless={dev='pnwuvl0',iface='pnw_uvl'}}
local function selected()
 local intf=trim(select(1,run('uci -q get network.route_gfw_v4.interface')))
 for _,id in ipairs({'usss','usvless'}) do if intf==exits[id].iface then return id end end
 for _,id in ipairs({'aws','nobrand'}) do if (' '..uci('network.pnw_'..id..'.allowed_ips')..' '):find(' 0.0.0.0/0 ',1,true) then return id end end
 return 'unknown'
end
local function hashes(skip_dns)
 return must('sha256sum '..(skip_dns and '' or '/etc/config/dhcp ')..'/etc/config/firewall /etc/diversion-dns-c/policy.nft /etc/diversion-dns-c/config.conf /etc/nftables.d/97-pnw-egress-bind.nft')
end
local function peer(id)
 local prefix='network.pnw_'..id..'.'
 return {key=uci(prefix..'public_key'),allowed=words(uci(prefix..'allowed_ips')),endpoint=uci(prefix..'endpoint_host'),port=uci(prefix..'endpoint_port')}
end
local function ensure_topology(allow_missing_routes)
 assert(trim(must('uci changes network'))=='','uncommitted network edits; refused')
 local dev=assert(exits[selected()],'unknown exit').dev
 assert((read('/etc/diversion-dns-c/config.conf') or ''):find('foreign_interface='..((selected()=='usss' or selected()=='usvless') and 'lo' or dev)..'\n',1,true),'unsupported active tunnel')
 for _,af in ipairs({'4','6'}) do
  local routes=trim(must('ip -'..af..' route show table 100 default'))
  if routes=='' then assert(allow_missing_routes,'IPv'..af..' policy default is missing')
  else
   local count=0
   for line in routes:gmatch('[^\n]+') do count=count+1;assert(line=='default dev '..dev or line:match('^default dev '..dev..'%s'),'IPv'..af..' policy route mismatch') end
   assert(count==1,'multiple policy defaults; refused')
  end
 end
 assert((read('/etc/nftables.d/97-pnw-egress-bind.nft') or ''):find('oifname != "'..dev..'"',1,true),'egress guard mismatch')
 must('/etc/diversion-dns-c/cn-policy.sh audit-runtime','managed policy failed verification')
end
local function cn_health()
 must('lua /etc/diversion-dns-c/dns-probe.lua 127.0.0.1 53 www.baidu.com A positive','domestic DNS failed')
end
local function dns_action(action,message)
 assert(action=='recover' or action=='rollback','invalid DNS action')
 assert(os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')=='1','DNS action requires deployment lock')
 assert(trim(must('uci changes dhcp'))=='','uncommitted DHCP edits; refused')
 -- The child replaces fd9 for its private lock. Keep the authoritative lock on
 -- fd8 too, including if its parent worker dies while the DNS script is running.
 must('DIVERSION_DNS_LOCK=/var/lock/pnw-control-nested.lock /etc/diversion-dns-c/'..action..'.sh manual 8>&9',message)
end
-- Telemetry is optional: observation must never undo an otherwise safe operation.
local function telemetry(method,value)
 local ok,m=pcall(dofile,B..'/telemetry.lua');if not ok or type(m)~='table' or type(m[method])~='function' then return {available=false,reason='telemetry unavailable'} end
 local good,result=pcall(m[method],value);return good and result or {available=false,reason=clean_error(result)}
end
-- Read-only display modules are optional and cannot change routing decisions.
local function observation(name,method)
 local ok,m=pcall(dofile,B..'/'..name..'.lua')
 if not ok or type(m)~='table' or type(m[method])~='function' then return nil,name..' unavailable' end
 local good,result=pcall(m[method])
 if good and type(result)=='table' then return result end
 return nil,clean_error(result)
end
local function dns_upstreams()
 local d,err=observation('dns-status','get')
 return d or {source='DNS configuration',observed_at=os.time(),cn={available=false,reason=err},foreign={available=false,reason=err}}
end
local function containment_state()
 local out,rc=run('nft list tables')
 local active=rc==0 and ('\n'..out..'\n'):find('\ntable inet pnw_emergency\n',1,true)~=nil
 return {marker=read(B..'/emergency')~=nil,active=active,known=rc==0,error=rc~=0 and clean_error(out) or nil}
end
local function reset_containment(reason)
 -- Persist intent before applying a block; never leave active containment unrecorded.
 if not read(B..'/emergency') then write(B..'/emergency',(reason or 'operator')..'\n');must('sync') end
 local st=containment_state();assert(st.known,'cannot inspect emergency containment')
 local rules=assert(read(B..'/emergency.nft'),'missing containment rules')
 write(R..'/emergency-apply.nft',(st.active and 'delete table inet pnw_emergency\n' or '')..rules)
 must('nft -f '..R..'/emergency-apply.nft','emergency containment failed')
 assert(containment_state().active,'emergency table missing after apply');os.remove(R..'/probe-active')
end
local function release_containment()
 local st=containment_state();assert(st.known,'cannot inspect emergency containment')
 if st.active then must('nft delete table inet pnw_emergency','cannot release emergency containment') end
 local after=containment_state();assert(after.known and not after.active,'cannot verify emergency release')
 if read(B..'/emergency') then assert(os.remove(B..'/emergency'),'cannot clear emergency marker') end
 must('sync')
end
local function probe_uid_available()
 for line in (read('/etc/passwd') or ''):gmatch('[^\n]+') do assert(tonumber(line:match('^[^:]*:[^:]*:(%d+):'))~=PROBE_UID,'isolated probe UID already assigned') end
 local iter=assert(fs.dir('/proc'),'cannot enumerate process ownership')
 for pid in iter do if pid:match('^%d+$') then
  local uids=(read('/proc/'..pid..'/status') or ''):match('\nUid:%s*([^\n]+)')
  if uids then for uid in uids:gmatch('%d+') do assert(tonumber(uid)~=PROBE_UID,'isolated probe UID in use') end end
 end end
 assert(type(nixio.setuid)=='function' and type(nixio.setgid)=='function' and type(nixio.exec)=='function','isolated probe unavailable')
end
local function with_isolated_probe(fn)
 probe_uid_available();reset_containment('candidate validation')
 -- The only exception belongs to a temporary unprivileged child and fixed probe
 -- destinations. The route hook forces table 100 after ordinary classification;
 -- forwarding stays blocked. The only root-owned exception is DNS to the two
 -- existing foreign upstreams, needed by the resolver during this short check.
 local rules='add chain inet pnw_emergency probe_mark { type route hook output priority -128; policy accept; }\n'
 for _,spec in ipairs({{'ip','1.1.1.1'},{'ip','1.0.0.1'},{'ip6','2606:4700:4700::1111'},{'ip6','2606:4700:4700::1001'}}) do
  local match='meta skuid '..PROBE_UID..' '..spec[1]..' daddr '..spec[2]..' tcp dport 443 '
  rules=rules..'insert rule inet pnw_emergency local '..match..'accept\n'..'add rule inet pnw_emergency probe_mark '..match..'meta mark set 1\n'
 end
 -- Permit only the existing resolver upstreams for the root-owned DNS daemon.
 -- Forced mark 1 plus the normal egress guard keeps these requests on the candidate.
 for _,destination in ipairs({'1.1.1.1','8.8.8.8'}) do for _,protocol in ipairs({'udp','tcp'}) do
  local dns='meta skuid 0 ip daddr '..destination..' '..protocol..' dport 53 '
  rules=rules..'insert rule inet pnw_emergency local '..dns..'accept\n'..'add rule inet pnw_emergency probe_mark '..dns..'meta mark set 1\n'
 end end
 write(R..'/probe-active',tostring(nixio.getpid()));write(R..'/probe.nft',rules);must('nft -f '..R..'/probe.nft','cannot install isolated probe rules')
 local ok,result=pcall(fn)
 local cleaned,err=pcall(reset_containment,'candidate validation')
 assert(cleaned,'probe cleanup failed; emergency retained: '..clean_error(err))
 if not ok then error(result) end
 return result
end
-- Device identities are local configuration, never source-code defaults. The
-- expected public egress and the route endpoint are intentionally independent.
local function identity(id)
 local raw=read(B..'/expected-egress.json')
 if not raw then return {} end
 assert(#raw<=65536,'exit identity configuration is too large')
 local ok,configured=pcall(json.parse,raw)
 assert(ok and type(configured)=='table','invalid exit identity configuration')
 local item=configured[id]
 assert(item==nil or type(item)=='table','invalid exit identity entry')
 return item or {}
end
local function ipv4_literal(value)
 if type(value)~='string' or not value:match('^%d+%.%d+%.%d+%.%d+$') then return nil end
 for part in value:gmatch('%d+') do
  if #part>3 or (#part>1 and part:sub(1,1)=='0') or tonumber(part)>255 then return nil end
 end
 return value
end
local function expected_ip(id,af)
 local value=identity(id)['ipv'..af]
 if value~=nil then
  assert(type(value)=='string' and (af=='4' and ipv4_literal(value) or af=='6' and value:find(':',1,true) and value:match('^[%x:]+$')),'invalid expected egress address')
 end
 -- These exits formerly had a fixed expected identity. Missing configuration
 -- must not silently downgrade that check to reachability-only.
 if (id=='usss' or id=='usvless') and af=='4' then assert(value,'proxy egress identity is not configured; migrate local configuration first') end
 return value
end
local function proxy_endpoint(id)
 local value=identity(id).endpoint_ipv4
 assert(ipv4_literal(value),'proxy endpoint is not configured; migrate local configuration first')
 return value
end
local function public_probe(af,isolated)
 local out,rc=run(isolated and (SELF..' probe-fetch '..af) or ('uclient-fetch -'..af..' --no-proxy -T 10 -q -O - https://www.cloudflare.com/cdn-cgi/trace'))
 local observed=('\n'..out..'\n'):match('\nip=([^\r\n]+)')
 local valid=observed and (af=='4' and observed:match('^%d+%.%d+%.%d+%.%d+$') or af=='6' and observed:find(':',1,true) and observed:match('^[%xa-fA-F:.]+$'))
 local expected=expected_ip(selected(),af)
 local r={checked_at=os.time(),ip=valid and observed or nil,expected=expected,reachability=rc==0 and valid~=nil or false,identity_status='unavailable',probe_scope=isolated and 'isolated_candidate' or 'router_https'}
 if not r.reachability then r.error='IPv'..af..' HTTPS failed: '..(rc==0 and 'invalid trace response' or clean_error(out))
 elseif expected then r.matches_expected=observed==expected;r.identity_status=r.matches_expected and 'verified' or 'mismatch';if not r.matches_expected then r.error='observed public IP does not match configured expected IP' end
 else r.identity_status='unconfigured' end
 return r
end
local function foreign_health(isolated)
 local identities={time=os.time(),selected=selected()}
 for _,af in ipairs((selected()=='usss' or selected()=='usvless') and {'4'} or {'4','6'}) do
  local r=public_probe(af,isolated);identities['ipv'..af]=r;save(R..'/public-exit.json',identities)
  assert(r.reachability and r.identity_status~='mismatch',r.error or 'foreign probe failed')
 end
 if selected()=='usss' or selected()=='usvless' then identities.ipv6={identity_status='disabled',reason='selected exit is IPv4 only',checked_at=os.time()} end
 save(R..'/public-exit.json',identities);return identities
end
local function set_allowed(id,list)
 local k='network.pnw_'..id..'.allowed_ips'
 fs.mkdir(R..'/uci','700')
 must('uci -t '..R..'/uci -q delete '..q(k),'cannot stage peer update')
 for _,ip in ipairs(list) do assert(ip:match('^[%da-fA-F:./]+$'));must('uci -t '..R..'/uci add_list '..q(k..'='..ip),'cannot stage peer prefix') end
end
local function runtime(id,list,key)
 must('wg set wg_vpn peer '..q(key)..' allowed-ips '..q(table.concat(list,',')),'WireGuard peer update failed')
end
local managed_files={'/etc/diversion-dns-c/config.conf','/etc/diversion-dns-c/policy.nft','/etc/nftables.d/97-pnw-egress-bind.nft'}
local function stable_hashes(skip_dns)
 return must('sha256sum '..(skip_dns and '' or '/etc/config/dhcp ')..'/etc/config/firewall /etc/pnw-control/us-exits.json /etc/pnw-control/foreign-v4-dns.conf')
end
local function dns_protected()
 -- Recovery legitimately changes only the first dnsmasq section's server and cache.
 -- Protect every other DHCP option and named section across that transition.
 local out=must('uci -q show dhcp','cannot inspect DNS configuration');local section=out:match('([^\n=]+)=dnsmasq')
 assert(section,'dnsmasq section is missing');local kept={}
 for line in out:gmatch('[^\n]+') do
  local key=line:match('^([^=]+)=')
  if key~=section..'.server' and key~=section..'.cachesize' then kept[#kept+1]=line end
 end
 return table.concat(kept,'\n')
end
local function bind_rules(dev)
 assert(dev=='wg_vpn' or dev=='pnwuss0' or dev=='pnwuvl0')
 local v4only=dev~='wg_vpn'
 local extra=v4only and ('add rule inet fw4 pnw_egress_bind_postrouting ct direction original meta mark 0x1 meta nfproto ipv6 counter drop comment "PNW US IPv4 only"\nadd rule inet fw4 pnw_egress_bind_forward ct direction original meta mark 0x1 meta nfproto ipv6 counter reject with icmpx type admin-prohibited comment "PNW US IPv4 only"\n') or ''
 return 'flush chain inet fw4 pnw_egress_bind_postrouting\nflush chain inet fw4 pnw_egress_bind_forward\n'..extra..
 'add rule inet fw4 pnw_egress_bind_postrouting ct direction original meta mark 0x1 oifname != "'..dev..'" counter drop\n'..
 'add rule inet fw4 pnw_egress_bind_forward ct direction original meta mark 0x1 oifname != "'..dev..'" counter reject with icmpx type admin-prohibited\n'
end
local function apply_plan(p,side)
 local id=side=='old' and p.from or p.to;local profile=assert(exits[id])
 for _,name in ipairs({'aws','nobrand'}) do set_allowed(name,p[side][name]) end
 if p.files then
  for _,af in ipairs({'4','6'}) do
   must('uci -t '..R..'/uci set network.route_gfw_v'..af..'.interface='..q(profile.iface),'cannot stage exit route')
  end
 end
 must('uci -t '..R..'/uci commit network','persist exit failed')
 for _,name in ipairs({'aws','nobrand'}) do assert(equal(peer(name).allowed,p[side][name]),'persistent peer verification failed') end
 if p.files then for _,af in ipairs({'4','6'}) do assert(uci('network.route_gfw_v'..af..'.interface')==profile.iface,'persistent route verification failed') end end
 -- Remove the old default owner before assigning the new one.
 local first=id=='aws' and 'nobrand' or 'aws';local second=first=='aws' and 'nobrand' or 'aws'
 runtime(first,p[side][first],p.keys[first]);runtime(second,p[side][second],p.keys[second])
 if p.files then
  for _,path in ipairs(managed_files) do write(path,p.files[path][side]) end
  write(R..'/bind.nft',bind_rules(profile.dev));must('nft -f '..R..'/bind.nft','cannot apply exit containment')
  must('/etc/diversion-dns-c/apply-policy.sh','cannot apply classifier guards')
  must('/etc/diversion-dns-c/cn-policy.sh seed --replace','cannot record approved guard baseline')
  must('ip -4 route replace default dev '..profile.dev..' table 100','cannot set IPv4 exit')
  must('ip -6 route replace default dev '..profile.dev..' table 100 metric 1024','cannot set IPv6 exit')
  must('ubus call network reload','cannot reload route configuration')
  must('/etc/init.d/diversion-dns-c restart','cannot reload foreign DNS interface')
  nixio.nanosleep(2)
 end
end
local function restore()
 local path=B..'/pending.json';if not read(path) then return end
 local p=load(path)
 assert(p.old and p.new and p.keys and exits[p.from],'invalid saved transaction')
 if p.isolated then reset_containment('failed candidate; restoring previous exit') end
 if p.dns_protected then
  assert(dns_protected()==p.dns_protected and stable_hashes(true)==p.immutable_guard,'unrelated configuration changed; rollback refused')
  if not p.files then assert(hashes(true)==p.managed_guard,'managed configuration changed; rollback refused') end
 end
 assert(trim(must('uci changes network'))=='','uncommitted network edits block rollback')
 for _,id in ipairs({'aws','nobrand'}) do
  local now=peer(id);assert(now.key==p.keys[id],'peer identity changed; rollback refused')
  assert(equal(now.allowed,p.old[id]) or equal(now.allowed,p.new[id]),'peer prefixes changed by another writer; rollback refused')
 end
 if p.files then
  assert(stable_hashes(p.dns_protected~=nil)==p.protected,'protected configuration changed; automatic rollback refused')
  if p.dns_protected then assert(dns_protected()==p.dns_protected,'unrelated DHCP configuration changed; rollback refused') end
  for _,af in ipairs({'4','6'}) do
   local iface=uci('network.route_gfw_v'..af..'.interface')
   assert(iface==exits[p.from].iface or iface==exits[p.to].iface,'route changed by another writer; rollback refused')
  end
  for _,file in ipairs(managed_files) do
   local current=read(file);assert(current==p.files[file].old or current==p.files[file].new,'managed file changed by another writer; rollback refused')
  end
 end
 apply_plan(p,'old')
 assert(selected()==p.from,'rollback selection mismatch')
 if p.files then must('/etc/diversion-dns-c/cn-policy.sh audit-runtime','rollback guard audit failed');cn_health() end
 if p.was_degraded then dns_action('rollback','cannot restore prior DNS rescue state') end
 assert(os.remove(path),'cannot retire completed rollback transaction');save(R..'/recovery.json',{time=os.time(),restored=p.from})
end
local function switch(to)
 assert(exits[to],'unknown target')
 assert(not read(B..'/pending.json'),'unfinished transaction; recovery required')
 local containment=containment_state();assert(containment.known,'cannot inspect containment')
 local isolated=containment.marker or containment.active or read('/etc/diversion-dns-c/degraded')~=nil
 if isolated then reset_containment('switching candidate while isolated') end
 ensure_topology(isolated)
 local from=selected();assert(exits[from],'unknown current peer')
 if from==to then assert(not isolated,'choose an alternate exit or use recover for the current exit');cn_health();foreign_health();return 'already selected and healthy' end
 local peers={aws=peer('aws'),nobrand=peer('nobrand')}
 if to=='aws' or to=='nobrand' then
  local target=peers[to]
  local route=must('ip '..(target.endpoint:find(':',1,true) and '-6' or '-4')..' route get '..q(target.endpoint)..' mark 0','endpoint has no route')
  assert(route:find('dev pppoe-wan',1,true),'candidate endpoint is not WAN reachable')
  local hs=must('wg show wg_vpn latest-handshakes');local timestamp
  for key,t in hs:gmatch('(%S+)%s+(%d+)') do if key==target.key then timestamp=tonumber(t) end end
  assert(timestamp and os.time()-timestamp<180 and timestamp>0,'candidate has no recent handshake')
 else
  assert(fs.stat('/sys/class/net/'..exits[to].dev),'US proxy TUN is not running')
  must('/etc/init.d/pnw-foreign-v4-dns status','foreign-only IPv4 DNS filter is not running')
  expected_ip(to,'4') -- Validate identity before any route changes.
  local route=must('ip -4 route get '..q(proxy_endpoint(to))..' mark 512','proxy endpoint has no route')
  assert(route:find('dev pppoe-wan',1,true),'US endpoint is not WAN reachable')
 end
 cn_health();local protected=hashes(isolated)
 local dns_guard=isolated and dns_protected() or nil;local immutable_guard=isolated and stable_hashes(true) or nil
 local p={from=from,to=to,old={},new={},keys={},time=os.time(),isolated=isolated,was_degraded=read('/etc/diversion-dns-c/degraded')~=nil,dns_protected=dns_guard,immutable_guard=immutable_guard,managed_guard=isolated and protected or nil}
 for _,id in ipairs({'aws','nobrand'}) do
  p.old[id]=peers[id].allowed;p.new[id]={};p.keys[id]=peers[id].key
  for _,ip in ipairs(p.old[id]) do
   if (to=='usss' or to=='usvless') or (ip~='0.0.0.0/0' and ip~='::/0') then p.new[id][#p.new[id]+1]=ip end
  end
 end
 if to=='aws' or to=='nobrand' then p.new[to][#p.new[to]+1]='0.0.0.0/0';p.new[to][#p.new[to]+1]='::/0' end
 if exits[from].dev~=exits[to].dev then
  assert(not fs.stat('/etc/diversion-dns-c/recovering'),'DNS recovery transaction active')
  p.files={};p.protected=stable_hashes(isolated);if isolated then p.dns_protected=dns_protected() end
  for i,path in ipairs(managed_files) do
   local old=assert(read(path));local new,count
   if i==1 then
    local oldUS=from=='usss' or from=='usvless';local newUS=to=='usss' or to=='usvless'
    new,count=old:gsub('foreign_interface='..(oldUS and 'lo' or 'wg_vpn')..'\n','foreign_interface='..(newUS and 'lo' or 'wg_vpn')..'\n');assert(count==1,'foreign DNS field mismatch')
    new,count=new:gsub('foreign_mark='..(oldUS and '0' or '1')..'\n','foreign_mark='..(newUS and '0' or '1')..'\n');assert(count==1,'foreign DNS mark mismatch')
    if oldUS~=newUS then
     if newUS then
      new,count=new:gsub('foreign_upstream=1%.1%.1%.1:53\nforeign_upstream=8%.8%.8%.8:53\n','foreign_upstream=127.0.0.1:15364\n')
     else new,count=new:gsub('foreign_upstream=127%.0%.0%.1:15364\n','foreign_upstream=1.1.1.1:53\nforeign_upstream=8.8.8.8:53\n') end
     assert(count==1,'foreign DNS upstream mismatch')
    end
   else
    new,count=old:gsub('oifname != "'..exits[from].dev..'"','oifname != "'..exits[to].dev..'"');assert(count==(i==2 and 4 or 2),'guard rule count mismatch')
    if i==3 then
     new=new:gsub('[^\n]*comment "PNW US IPv4 only"[^\n]*\n','')
     if to=='usss' or to=='usvless' then
      new=new:gsub('(type filter hook postrouting[^\n]*\n)','%1    ct direction original meta mark 0x1 meta nfproto ipv6 counter drop comment "PNW US IPv4 only"\n')
      new=new:gsub('(type filter hook forward[^\n]*\n)','%1    ct direction original meta mark 0x1 meta nfproto ipv6 counter reject with icmpx type admin-prohibited comment "PNW US IPv4 only"\n')
     end
    end
   end
   p.files[path]={old=old,new=new}
  end
 end
 save(B..'/pending.json',p);must('sync')
 apply_plan(p,'new')
 save(R..'/switch-applied.json',{target=to,selected=selected(),interface4=uci('network.route_gfw_v4.interface'),interface6=uci('network.route_gfw_v6.interface'),routes=must('ip -4 route show table 100; ip -6 route show table 100'),time=os.time()})
 if isolated then
  dns_action('recover','DNS recovery failed; emergency retained')
  assert(dns_protected()==p.dns_protected,'unrelated DHCP configuration changed during recovery')
  cn_health();with_isolated_probe(function()
   foreign_health(true);must('lua /etc/diversion-dns-c/dns-probe.lua 1.1.1.1 53 example.com A positive','candidate UDP DNS failed');must('lua /etc/diversion-dns-c/dns-probe.lua 127.0.0.1 53 www.cloudflare.com A positive','candidate foreign DNS failed')
  end)
 else cn_health();foreign_health() end
 if to=='usss' or to=='usvless' then
  if not isolated then must('lua /etc/diversion-dns-c/dns-probe.lua 1.1.1.1 53 example.com A positive','US UDP DNS failed') end
  must('lua '..B..'/dns-v4-check.lua 127.0.0.1 53','foreign AAAA/HTTPS filtering failed')
 end
 if p.files then
  assert(stable_hashes(p.dns_protected~=nil)==p.protected,'protected configuration changed concurrently')
  if p.dns_protected then assert(dns_protected()==p.dns_protected,'unrelated DHCP configuration changed concurrently') end
  for _,path in ipairs(managed_files) do assert(read(path)==p.files[path].new,'managed configuration changed concurrently') end
  must('/etc/diversion-dns-c/cn-policy.sh audit-runtime','guard audit failed')
 else
  if isolated then assert(hashes(true)==protected and stable_hashes(true)==immutable_guard and dns_protected()==dns_guard,'protected configuration changed concurrently')
  else assert(hashes()==protected,'protected configuration changed concurrently') end
 end
 assert(selected()==to,'selected exit mismatch')
 if isolated then release_containment() end
 save(B..'/previous.json',{selected=from,time=os.time()});assert(os.remove(B..'/pending.json'),'cannot retire completed switch transaction');must('sync')
 return 'selected '..to..((to=='usss' or to=='usvless') and '; IPv4 HTTPS/UDP passed; foreign IPv6 blocked; domestic IPv6 retained' or '; dual-stack HTTPS and domestic DNS passed')
end
local function repair_routes()
 -- Reconcile only missing managed defaults after the interface has returned.
 -- A different default belongs to another writer and must never be replaced.
 local profile=assert(exits[selected()],'unknown current exit')
 local dev=profile.dev
 must('ip link show dev '..dev,'selected tunnel interface is absent; restore its service first')
 local missing={}
 for _,af in ipairs({'4','6'}) do
  local routes=trim(must('ip -'..af..' route show table 100 default','cannot read policy routes'))
  if routes=='' then missing[#missing+1]=af
  else
   local count=0
   for line in routes:gmatch('[^\n]+') do count=count+1;assert(line:match('^default dev '..dev..'%s') or line=='default dev '..dev,'conflicting policy default; refused') end
   assert(count==1,'multiple policy defaults; refused')
  end
 end
 for _,af in ipairs(missing) do must('ip -'..af..' route add default dev '..dev..' table 100','cannot restore managed default') end
end
local function emergency(on)
 if on then
  reset_containment('operator')
  dns_action('rollback','DNS rescue failed; tunnel containment retained')
  cn_health();return 'domestic DNS rescue; foreign marked traffic blocked'
 end
 -- Keep both durable intent and the actual block until candidate probes succeed.
 reset_containment('recovering current exit');repair_routes()
 dns_action('recover','DNS recovery failed; containment retained')
 cn_health();with_isolated_probe(function()foreign_health(true);must('lua /etc/diversion-dns-c/dns-probe.lua 1.1.1.1 53 example.com A positive','candidate UDP DNS failed');must('lua /etc/diversion-dns-c/dns-probe.lua 127.0.0.1 53 www.cloudflare.com A positive','candidate foreign DNS failed')end)
 if selected()=='usss' or selected()=='usvless' then must('lua '..B..'/dns-v4-check.lua 127.0.0.1 53','foreign AAAA/HTTPS filtering failed') end
 release_containment();return 'split routing recovered; configured address families passed isolated HTTPS and UDP DNS checks'
end
local function health()
 local started=milliseconds();local h={time=os.time(),selected=selected(),peers={},checks={},details={},public_exit={selected=selected(),time=os.time()}}
 local hs,rc=run('wg show wg_vpn latest-handshakes')
 for _,id in ipairs({'aws','nobrand'}) do
  local p=peer(id);local age
  if rc==0 then for key,t in hs:gmatch('(%S+)%s+(%d+)') do if key==p.key and tonumber(t)>0 then age=math.max(0,os.time()-tonumber(t)) end end end
  h.peers[id]={handshake_age_seconds=age,recent=age~=nil and age<180}
 end
 local function check(name,fn)
  local began=milliseconds();local ok,err=pcall(fn);h.checks[name]=ok
  h.details[name]={ok=ok,duration_ms=math.max(0,milliseconds()-began),error=not ok and clean_error(err) or nil}
 end
 check('domestic_dns',cn_health)
 check('foreign_dns',function()must('lua /etc/diversion-dns-c/dns-probe.lua 127.0.0.1 53 www.cloudflare.com A positive','foreign DNS failed')end)
 local us=selected()=='usss' or selected()=='usvless'
 if us then
  h.checks.https_ipv6='disabled';h.details.https_ipv6={reason='selected exit is IPv4 only'}
  h.public_exit.ipv6={identity_status='disabled',checked_at=os.time()}
  check('foreign_ipv4_only',function()must('lua '..B..'/dns-v4-check.lua 127.0.0.1 53','foreign AAAA/HTTPS filtering failed')end)
 end
 for _,af in ipairs(us and {'4'} or {'4','6'}) do check('https_ipv'..af,function()
  local r=public_probe(af,false);h.public_exit['ipv'..af]=r
  assert(r.reachability and r.identity_status~='mismatch',r.error or 'HTTPS probe failed')
 end) end
 -- Domestic echo is a display observation, not a new switch/recovery gate.
 -- Persist it independently so foreign-only candidate checks cannot erase it.
 local domestic,err=observation('public-status','probe')
 if not domestic then
  domestic={time=os.time()}
  for _,af in ipairs({'ipv4','ipv6'}) do domestic[af]={checked_at=os.time(),reachability=false,identity_status='unavailable',probe_scope='router_domestic_https',error=err} end
 end
 h.public_exit.domestic=domestic;save(R..'/public-domestic.json',domestic)
 h.finished=os.time();h.duration_ms=math.max(0,milliseconds()-started);h.ok=true
 for _,ok in pairs(h.checks) do if ok==false then h.ok=false end end
 save(R..'/health.json',h);save(R..'/public-exit.json',h.public_exit);telemetry('record_health',h)
 return h.ok and 'DNS and configured HTTPS checks passed' or 'health check completed with failures; see individual checks'
end
local allowed={['switch-aws']=true,['switch-nobrand']=true,['switch-usss']=true,['switch-usvless']=true,rollback=true,rescue=true,recover=true,diagnose=true,check=true,['retry-recovery']=true,['game-on']=true,['game-off']=true,['game-refresh']=true}
local function diagnose()
 local metrics=dofile(B..'/metrics.lua');local a=metrics.sample();nixio.nanosleep(3);local b=metrics.sample()
 local report={time=os.time(),boot=trim(read('/proc/sys/kernel/random/boot_id') or ''),load=trim(read('/proc/loadavg') or ''),memory=read('/proc/meminfo'),cpu=read('/proc/stat'),softirqs=read('/proc/softirqs'),conntrack=trim(read('/proc/sys/net/netfilter/nf_conntrack_count') or '')}
 report.interval=metrics.delta(a,b)
 report.routes=must('ip -4 route show table 100; ip -6 route show table 100; ip rule; ip -6 rule')
 report.processes=must("ps w | awk 'NR==1 {print;next} {print $1,$2,$3,$4,$5}'")
 report.services=must("ubus call service list '{\"name\":\"diversion-dns-c\"}'")
 report.protected=hashes();save(R..'/diagnostic.json',report)
 return 'diagnostic saved locally (latest only)'
end
local function status()
 local now=os.time();local ok,current=pcall(selected);local containment=containment_state()
 local pending=read(B..'/pending.json')~=nil;local running=fs.stat(R..'/job')~=nil
 local previous=load(B..'/previous.json').selected
 local st={dns_upstreams=dns_upstreams(),version=VERSION,server_time=now,updated_at=now,selected=ok and current or 'unavailable',running=running,
 emergency=containment.marker or containment.active,containment=containment,dns_degraded=read('/etc/diversion-dns-c/degraded')~=nil,pending=pending,
 previous_exit=previous,last=load(R..'/result.json'),load=trim(read('/proc/loadavg') or ''),memory=trim((read('/proc/meminfo') or ''):match('MemAvailable:%s*(%d+)') or ''),
 endpoint_health=load(B..'/endpoint-health.json'),health=load(R..'/health.json'),public_exit=load(R..'/public-exit.json'),cpu_monitor=load(R..'/cpu-monitor.json'),diagnostic=load(R..'/diagnostic.json'),
 vless_available=fs.stat('/sys/class/net/pnwuvl0')~=nil,usss_available=fs.stat('/sys/class/net/pnwuss0')~=nil,recovery=load(R..'/reconcile.json'),telemetry=telemetry('status',{selected=ok and current or 'unavailable'})}
 st.services={wireguard={available=fs.stat('/sys/class/net/wg_vpn')~=nil},usss={available=st.usss_available},usvless={available=st.vless_available}}
 st.game_tunnel=select(1,observation('game-tunnel','status')) or {available=false,reason='本机未部署游戏隧道模块'}
 st.pending=st.pending or st.game_tunnel.pending==true
 st.actions={}
 st.public_exit.domestic=load(R..'/public-domestic.json')
 for action in pairs(allowed) do
  local reason
  local target=action:match('^switch%-(.+)$');if action=='rollback' then target=previous;if not exits[target] then reason='no previous exit' end end
  if running then reason='another action is running'
  elseif pending and action~='diagnose' and action~='retry-recovery' then reason='unfinished transaction; recovery required'
  elseif action=='retry-recovery' and not pending and not st.recovery.paused then reason='no paused or unfinished recovery'
  elseif not containment.known and action~='diagnose' then reason='cannot inspect emergency containment'
  elseif target and (target=='usss' or target=='usvless') and not st.services[target].available then reason='target proxy TUN is not running'
  elseif target and st.emergency and target==current then reason='choose an alternate exit or recover the current exit' end
  if action:match('^game%-') then
   if action=='game-off' and not pending then reason=nil end
   if not st.game_tunnel.available then reason='本设备未部署游戏隧道模块'
   elseif st.game_tunnel.pending then reason='游戏切换未完成，请重试恢复'
   elseif action~='game-off' and (st.emergency or st.dns_degraded) then reason='应急或 DNS 降级期间不可切换游戏策略'
   elseif action=='game-on' and st.game_tunnel.enabled and st.game_tunnel.consistent then reason='已经开启'
   elseif action=='game-off' and not st.game_tunnel.enabled and st.game_tunnel.consistent then reason='已经关闭' end
  end
  st.actions[action]={allowed=reason==nil,reason=reason}
 end
 return st
end
local function complete_result(result)
 save(R..'/result.json',result);telemetry('record_operation',result)
end
local function reconcile_containment()
 local st=containment_state();assert(st.known,'cannot inspect emergency containment')
 if (st.marker and not st.active) or (st.active and not st.marker) or read(R..'/probe-active') then reset_containment('reconciled emergency') end
end
local function reconcile_locked(ignore_job)
 if not ignore_job and fs.stat(R..'/job') then
  local pid=read(R..'/job/pid')
  if pid and pid:match('^%d+$') and (read('/proc/'..pid..'/cmdline') or ''):find(SELF,1,true) then return false end
  if os.time()-(load(R..'/result.json').time or 0)<10 then return false end
  os.remove(R..'/job/game-data');os.remove(R..'/job/token');os.remove(R..'/job/pid');fs.rmdir(R..'/job')
 end
 reconcile_containment()
 if read(B..'/pending.json') then restore() end
 if read(B..'/game-tunnel.lua') then pcall(function()dofile(B..'/game-tunnel.lua').reconcile()end) end
 return true
end
fs.mkdir(R,'700')
local mode=arg[1] or 'status'
if mode=='status' then print(json.stringify(status()))
elseif mode=='telemetry' then print(json.stringify(telemetry('collect',{selected=selected()})))
elseif mode=='query' then
 local query=dofile(B..'/query.lua');print(json.stringify(query.lookup(arg[2],{source=arg[3] or 'router',selected=selected(),emergency=read(B..'/emergency')~=nil or containment_state().active,dns_degraded=read('/etc/diversion-dns-c/degraded')~=nil})))
elseif mode=='probe-fetch' then
 assert(os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')=='1','probe requires controller lock')
 local st=containment_state();assert(st.marker and st.active,'probe requires emergency containment')
 assert(nixio.setgid(PROBE_UID) and nixio.setuid(PROBE_UID),'cannot isolate probe identity')
 local af=arg[2];assert(af=='4' or af=='6','invalid probe family')
 -- Use the certificate hostname; this uclient version rejects HTTPS IP literals.
 nixio.exec('/bin/uclient-fetch','-'..af,'--no-proxy','-T','10','-q','-O','-','https://one.one.one.one/cdn-cgi/trace')
 error('probe exec failed')
elseif mode=='game-prepare' then
 write(R..'/job/pid',tostring(nixio.getpid()))
 local game=dofile(B..'/game-tunnel.lua');game.prepare(R..'/job/game-data')
elseif mode=='start' then
 local action=arg[2];assert(allowed[action],'invalid action')
 assert(not read(B..'/game-tunnel/pending.json') or action=='diagnose' or action=='retry-recovery','unfinished game transaction')
 assert(not read(B..'/pending.json') or action=='diagnose' or action=='retry-recovery','unfinished transaction; automatic rollback pending')
 assert(fs.mkdir(R..'/job','700'),'another action is running')
 local token=tostring(os.time())..'-'..nixio.getpid();write(R..'/job/token',token)
 save(R..'/result.json',{action=action,state='running',time=os.time(),started_at=os.time()})
 local _,rc=run('(trap "" HUP; if [ '..q(action)..' = game-on ] || [ '..q(action)..' = game-refresh ]; then '..SELF..' game-prepare; fi; (flock -n 9 || { '..SELF..' busy '..q(token)..'; exit 1; }; export DIVERSION_CN_DEPLOY_LOCK_HELD=1 PNW_GAME_PREPARED=/var/run/pnw-control/job/game-data; '..SELF..' worker '..q(action)..' '..q(token)..') 9>/var/lock/diversion-dns-deploy.lock >'..R..'/job.log 2>&1 </dev/null &)')
 assert(rc==0,'cannot start worker');print(json.stringify({accepted=true}))
elseif mode=='busy' then
 local token=arg[2];assert(read(R..'/job/token')==token,'invalid busy worker ownership')
 local r=load(R..'/result.json');r.state='failed';r.message='another policy or DNS transaction holds the lock; retry later';r.time=os.time();r.rollback={attempted=false,state='not_needed'};complete_result(r)
 os.remove(R..'/job/game-data');os.remove(R..'/job/token');fs.rmdir(R..'/job')
elseif mode=='worker' then
 local action,token=arg[2],arg[3];assert(allowed[action] and read(R..'/job/token')==token,'invalid worker ownership')
 write(R..'/job/pid',tostring(nixio.getpid()))
 local started=milliseconds();local started_at=os.time()
 local ok,result=pcall(function()
  if action:match('^game%-') then
   if action~='game-off' then ensure_topology() end
   if action~='game-off' and runtime_snapshot then assert(runtime_snapshot(selected()).consistent,'runtime exit mismatch') end
   local game=dofile(B..'/game-tunnel.lua')
   if action=='game-refresh' then return game.refresh() end
   return game.set(action=='game-on')
  elseif action=='switch-aws' then return switch('aws') elseif action=='switch-nobrand' then return switch('nobrand')
  elseif action=='switch-usss' then return switch('usss') elseif action=='switch-usvless' then return switch('usvless')
  elseif action=='rollback' then local old=load(B..'/previous.json').selected;assert(exits[old],'no previous exit');return switch(old)
  elseif action=='retry-recovery' then restore();reconcile_locked(true);return 'unfinished transaction recovery retried; emergency state retained when present'
  elseif action=='rescue' then return emergency(true) elseif action=='recover' then return emergency(false) elseif action=='check' then return health() else return diagnose() end
 end)
 local rollback={attempted=false,state='not_needed'}
 if not ok and read(B..'/pending.json') then
  rollback.attempted=true;local restored,err=pcall(restore);rollback.state=restored and 'success' or 'failed'
  if not restored then
   rollback.error=clean_error(err);local blocked,blockerr=pcall(reset_containment,'rollback failed')
   if not blocked then rollback.containment_error=clean_error(blockerr) end
  end
 end
 complete_result({action=action,state=ok and 'success' or 'failed',message=clean_error(result),rollback=rollback,rollback_ok=rollback.state~='failed',time=os.time(),started_at=started_at,duration_ms=math.max(0,milliseconds()-started)})
 if ok and action~='diagnose' and action~='check' then save(R..'/reconcile.json',{failures=0,paused=false,last_attempt=os.time()}) end
 os.remove(R..'/job/game-data');os.remove(R..'/job/token');os.remove(R..'/job/pid');fs.rmdir(R..'/job')
elseif mode=='reconcile' then
 if os.getenv('DIVERSION_CN_DEPLOY_LOCK_HELD')~='1' then
  -- Exit 75 is a busy lock, not a failed recovery attempt.
  local _,rc=run('(flock -n 9 || exit 75; export DIVERSION_CN_DEPLOY_LOCK_HELD=1; '..SELF..' reconcile) 9>/var/lock/diversion-dns-deploy.lock')
  if rc==0 and read(B..'/game-tunnel.lua') then pcall(function()if dofile(B..'/game-tunnel.lua').refresh_due() then run(SELF..' start game-refresh')end end)end
  os.exit(rc)
 end
 local state=load(R..'/reconcile.json')
 if (state.failures or 0)>=3 then
  -- Pausing transaction retries must not leave an orphaned probe exception active.
  local safe,err=pcall(reconcile_containment)
  if not safe then state.containment_error=clean_error(err);save(R..'/reconcile.json',state) end
  os.exit(76)
 end
 local ok,result=pcall(reconcile_locked)
 if ok and result==false then os.exit(75) end
 state.last_attempt=os.time()
 if ok then state.failures=0;state.paused=false;state.last_error=nil
 else
  state.failures=(state.failures or 0)+1;state.paused=state.failures>=3;state.last_error=clean_error(result)
  if read(B..'/pending.json') then
   local safe,err=pcall(reset_containment,'automatic rollback failed')
   if not safe then state.containment_error=clean_error(err) end
  end
 end
 save(R..'/reconcile.json',state);os.exit(ok and 0 or 1)
else error('invalid command') end
