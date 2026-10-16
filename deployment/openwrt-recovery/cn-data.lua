#!/usr/bin/lua
-- CN data engine. Shell wrapper owns serialization, generation selection and DNS
-- reload. No network downloader, C compiler, Python, LuCI or nixio is required.
local M = {}
assert(os.setlocale('C','collate')) -- same ordering as LC_ALL=C sort
local function fail(s) error(s, 0) end
local function quote(s) return "'" .. tostring(s):gsub("'", "'\\''") .. "'" end
local function read(path, limit)
 local f = io.open(path, 'rb'); if not f then fail('cannot read ' .. path) end
 local s = f:read((limit or 16777216) + 1); f:close()
 if not s or #s > (limit or 16777216) then fail('file exceeds size limit: ' .. path) end
 return s
end
local function write(path, s)
 local f = assert(io.open(path, 'wb')); assert(f:write(s)); assert(f:close())
end
local function command(s)
 local p = assert(io.popen(s .. " 2>&1; printf '\\n__cn_status:%s\\n' \"$?\"", 'r'))
 local out = p:read('*a'); p:close()
 local body, rc = out:match('^(.*)\n__cn_status:(%d+)\n$')
 if not rc then fail('command status unavailable') end
 return tonumber(rc) == 0, body
end
local function sha(path)
 local ok, s = command('sha256sum ' .. quote(path))
 local h = s:match('^([0-9a-f]+)%s')
 if not ok or not h or #h ~= 64 then fail('sha256sum failed: ' .. path) end
 return h
end
local function envint(name, def)
 local s = os.getenv(name); if not s then return def end
 if not s:match('^%d+$') then fail('invalid ' .. name) end
 return tonumber(s)
end
local tab = os.getenv('DIVERSION_CN_TABLE') or 'diversion_dns'
if not tab:match('^[a-zA-Z_][a-zA-Z0-9_]*$') or #tab > 64 then fail('invalid table name') end
local function textfile(s)
 if s == '' or s:sub(-1) ~= '\n' or s:find('\0', 1, true) or s:find('\r', 1, true) then
  fail('empty, unterminated or non-text file')
 end
end
local function lines(s)
 textfile(s)
 local out = {}; for l in s:gmatch('([^\n]*)\n') do
  if l == '' or l:find('%s') or #l > 1024 then fail('blank, whitespace or oversized input line') end
  out[#out+1] = l
 end; return out
end
local function ipv4(s)
 local a,b,c,d = s:match('^(%d+)%.(%d+)%.(%d+)%.(%d+)$')
 if not a then fail('invalid IPv4: ' .. s) end
 local out = ''; for _,v in ipairs({a,b,c,d}) do
  if tonumber(v)>255 or (#v>1 and v:sub(1,1)=='0') then fail('invalid IPv4: ' .. s) end
  out = out .. string.format('%02x', tonumber(v))
 end; return out
end
local function ip(s)
 if s:find('.',1,true) then return ipv4(s),4 end
 if not s:match('^[0-9a-fA-F:]+$') then fail('invalid IPv6: ' .. s) end
 local i,j=s:find('::',1,true); local parts={}
 local function split(x)
  local r={}; if x=='' then return r end
  if x:sub(1,1)==':' or x:sub(-1)==':' then fail('invalid IPv6 colon') end
  for v in x:gmatch('[^:]+') do
   if #v>4 then fail('invalid IPv6 group') end; r[#r+1]=tonumber(v,16)
  end
  if table.concat((function() local z={} for _,v in ipairs(r) do z[#z+1]=string.format('%x',v) end return z end)(),':')=='' then fail('invalid IPv6') end
  return r
 end
 if i then
  if s:find('::',j+1,true) then fail('multiple IPv6 compression') end
  local left,right=split(s:sub(1,i-1)),split(s:sub(j+1))
  if #left+#right>=8 then fail('invalid IPv6 compression') end
  for _,v in ipairs(left) do parts[#parts+1]=v end
  for _=1,8-#left-#right do parts[#parts+1]=0 end
  for _,v in ipairs(right) do parts[#parts+1]=v end
 else
  if s:sub(1,1)==':' or s:sub(-1)==':' then fail('invalid IPv6 colon') end
  parts=split(s); if #parts~=8 then fail('invalid IPv6 length') end
 end
 local out='';for _,v in ipairs(parts) do out=out..string.format('%04x',v) end
 return out,6
end
local function bounds(hex, prefix)
 local low,high='',''
 for pos=1,#hex do
  local bits=math.max(0,math.min(4,prefix-(pos-1)*4));local unit=2^(4-bits)
  local n=tonumber(hex:sub(pos,pos),16); local v=math.floor(n/unit)*unit
  low=low..string.format('%x',v);high=high..string.format('%x',v+unit-1)
 end
 return low,high
end
local function network(s, strict)
 local a,p=s:match('^([^/]+)/(%d+)$');if not a then a=s end
 local hex,fam=ip(a);p=p and tonumber(p) or #hex*4
 if p>#hex*4 or p<0 then fail('invalid prefix') end
 local lo,hi=bounds(hex,p)
 if strict and (not s:find('/',1,true) or hex~=lo or p<(fam==4 and 8 or 16)) then fail('noncanonical or overbroad prefix: '..s) end
 return {lo,hi},fam,p
end
local function plusone(s)
 local t={};local carry=1
 for i=#s,1,-1 do local n=tonumber(s:sub(i,i),16)+carry;t[i]=string.format('%x',n%16);carry=math.floor(n/16) end
 return carry==0 and table.concat(t) or nil
end
local function canonical(ranges)
 table.sort(ranges,function(a,b) return a[1]<b[1] or (a[1]==b[1] and a[2]<b[2]) end)
 local out={};for _,r in ipairs(ranges) do
  local last=out[#out]
  if last and (r[1]<=last[2] or r[1]==plusone(last[2])) then if r[2]>last[2] then last[2]=r[2] end
  else out[#out+1]={r[1],r[2]} end
 end
 local t={};for _,r in ipairs(out) do t[#t+1]=r[1]..' '..r[2]..'\n' end
 return table.concat(t),out
end
local function includes(rs, addr)
 local hex=ip(addr);for _,r in ipairs(rs) do if r[1]<=hex and hex<=r[2] then return true end end;return false
end
local known_regex={
 ['.+\\.awsdns-cn-[0-9][0-9]\\.(biz|com|net|top)$']=true,
 ['.+\\.awsdns-cn-[0-9][a-e0-9]\\.cn$']=true,
 ['^(.+\\.)*zh\\.okaapps\\.com$']=true,
 ['^.+-mihayo\\.akamaized\\.net$']=true,
 ['^cdn\\d-epicgames-\\d+\\.file\\.myqcloud\\.com$']=true,
 ['^epicgames-download\\d-\\d+\\.file\\.myqcloud\\.com$']=true,
 ['^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.googlevideo\\.com$']=true,
 ['^r+[0-9]+(---|\\.)sn-(2x3|ni5|j5o)\\w{5}\\.xn--ngstr-lra8j\\.com$']=true
}
local forbidden_tld={com=true,net=true,org=true,edu=true,gov=true,io=true,dev=true,app=true,uk=true,us=true,jp=true,de=true,fr=true,au=true,ru=true}
local function sortfile(input, output)
 -- Minimal OpenWrt BusyBox sort may silently ignore -o and still exit zero.
 -- Shell redirection works with its [-nru] implementation as well as full sort.
 if input==output then fail('CN-site sort input and output must differ') end
 local ok=command('LC_ALL=C sort '..quote(input)..' > '..quote(output))
 if not ok then fail('cannot sort CN-site for bounded-memory validation') end
 local f=io.open(output,'rb')
 if not f then fail('CN-site sorted output unavailable') end
 f:close()
end
local function domains(path, sorted)
 sortfile(path, sorted)
 local positive={'qq.com','baidu.com','cn-data-health.qq.com','www.baidu.com'}
 local negative={'example.com','google.com','cloudflare.com','wikipedia.org'}
 local exact,suffix={},{}
 local function index(q, required)
  local entry={name=q,required=required,found=false}
  exact[q]=entry
  while true do
   suffix[q]=suffix[q] or {};suffix[q][#suffix[q]+1]=entry
   local p=q:find('.',1,true);if not p then break end;q=q:sub(p+1)
  end
 end
 for _,q in ipairs(positive) do index(q,true) end
 for _,q in ipairs(negative) do index(q,false) end
 local count,last,wide=0,nil,{}
 for l in io.lines(sorted) do
  if l=='' or l:find('%s') or #l>1024 then fail('blank, whitespace or oversized domain line') end
  if l==last then fail('duplicate domain rule: '..l) end;last=l;count=count+1
  local kind,name=l:match('^([a-z]+):(.*)$');if not kind then kind='domain';name=l end
  if kind=='regexp' then
   if not known_regex[name] then fail('new/changed regex requires explicit review') end
  elseif kind=='domain' or kind=='full' then
   if #name>253 or name~=name:lower() or not name:match('^[a-z0-9][a-z0-9%.%-]*[a-z0-9]$') or name:find('..',1,true) then fail('invalid domain rule: '..l) end
   for label in name:gmatch('[^.]+') do if #label>63 or label:sub(1,1)=='-' or label:sub(-1)=='-' then fail('invalid domain label') end end
   if kind=='full' then if exact[name] then exact[name].found=true end
   else
    for _,entry in ipairs(suffix[name] or {}) do entry.found=true end
    if not name:find('.',1,true) then if forbidden_tld[name] then fail('overbroad public suffix') end;wide[name]=true end
   end
  else fail('unsupported domain rule: '..l) end
 end
 for q,entry in pairs(exact) do
  if entry.required and not entry.found then fail('missing domestic domain canary: '..q) end
  if not entry.required and entry.found then fail('foreign domain canary classified CN: '..q) end
 end
 return count,wide
end
local function parsedata(iptext,sitefile,sortedfile)
 local ls=lines(iptext);local ips,rs,cov,seen={[4]={},[6]={}},{[4]={},[6]={}},{[4]=0,[6]=0},{}
 for _,s in ipairs(ls) do
  local r,f,p=network(s,true);local key=r[1]..'/'..p
  if seen[key] then fail('duplicate CN-IP prefix') end;seen[key]=true
  ips[f][#ips[f]+1]=s;rs[f][#rs[f]+1]=r;cov[f]=cov[f]+2^(f==4 and 32-p or 128-p)
 end
 if #ips[4]<envint('DIVERSION_CN_MIN4',1000) or #ips[6]<envint('DIVERSION_CN_MIN6',100) then fail('missing or undersized IP family') end
 for _,s in ipairs({'223.5.5.5','119.29.29.29','2400:3200::1'}) do local _,f=ip(s);if not includes(rs[f],s) then fail('missing domestic IP canary: '..s) end end
 for _,s in ipairs({'0.0.0.1','10.0.0.1','127.0.0.1','192.168.1.1','1.1.1.1','8.8.8.8','fc00::1','::1','2606:4700:4700::1111','2001:4860:4860::8888'}) do local _,f=ip(s);if includes(rs[f],s) then fail('foreign IP canary classified CN: '..s) end end
 local count,wide=domains(sitefile,sortedfile)
 if count<envint('DIVERSION_CN_MINSITE',10000) then fail('undersized CN-site') end
 return {ips=ips,rs=rs,cov=cov,ipseen=seen,domaincount=count,wide=wide,sorted=sortedfile}
end
local files={'cn-ip.txt','cn-site.txt','sets.nft','replace.nft','ranges4.txt','ranges6.txt'}
local function manifest(dir)
 local s=read(dir..'/manifest.tsv',8192);local m={}
 for line in s:gmatch('[^\n]+') do
  local name,h=line:match('^([a-z0-9%.%-]+)\t([0-9a-f]+)$')
  if not name or #h~=64 or m[name] then fail('invalid manifest') end;m[name]=h
 end
 local count=0;for _ in pairs(m) do count=count+1 end;if count~=#files then fail('manifest member count') end
 for _,f in ipairs(files) do if not m[f] or sha(dir..'/'..f)~=m[f] then fail('generation checksum mismatch: '..f) end end
 local replacement=read(dir..'/replace.nft',2097152)
 local header='flush set inet '..tab..' cn4\nflush set inet '..tab..' cn6\n'
 if replacement:sub(1,#header)~=header then fail('generation table binding mismatch') end
 return m
end
function M.verify(dir) manifest(dir);return 0 end
local function bounded(n,old,label)
 if n<old*0.8 or n>old*1.2 then fail('change exceeds 20 percent: '..label) end
end
local function additions(ips)
 local out={}
 for _,f in ipairs({4,6}) do for i=1,#ips[f],200 do
  local chunk={};for j=i,math.min(i+199,#ips[f]) do chunk[#chunk+1]=ips[f][j] end
  out[#out+1]='add element inet '..tab..' cn'..f..' { '..table.concat(chunk,', ')..' }\n'
 end end;return table.concat(out)
end
local function stripped(template)
 local out={};local owned=0
 for l in (template..'\n'):gmatch('([^\n]*)\n') do
  local n=l:match('^add element inet '..tab..' (cn[46])%s+{.*}%s*$')
  if n then owned=owned+1 else
   if l:match('^add element inet '..tab..' cn[46]%s') then fail('unsupported multiline owned set definition') end
   if l~='' then out[#out+1]=l end
  end
 end
 if owned==0 then fail('sets template contains no owned elements') end
 return table.concat(out,'\n')..'\n'
end
function M.prepare(ipfile,sitefile,template,baseline,outdir,iph,siteh)
 -- Staging is infrequent; cap Lua's growth between collections on small routers.
 collectgarbage('setpause',110);collectgarbage('setstepmul',400)
 if not iph or not siteh or not iph:match('^[0-9a-f]+$') or not siteh:match('^[0-9a-f]+$') or #iph~=64 or #siteh~=64 then fail('two expected SHA256 values required') end
 if sha(ipfile)~=iph or sha(sitefile)~=siteh then fail('candidate download checksum mismatch') end
 local it,st,tt=read(ipfile,524288),read(sitefile,4194304),read(template,2097152)
 textfile(st)
 write(outdir..'/cn-ip.txt',it);write(outdir..'/cn-site.txt',st)
 if sha(outdir..'/cn-ip.txt')~=iph or sha(outdir..'/cn-site.txt')~=siteh then fail('candidate changed during staging') end
 local d=parsedata(it,outdir..'/cn-site.txt',outdir..'/.site.sorted');local skeleton=stripped(tt)
 collectgarbage('collect')
 if baseline~='-' then
  manifest(baseline)
  -- The immutable baseline was validated when created and its hashes were just
  -- verified. Stream comparison avoids retaining two 111k-rule tables on MIPS.
  local oldcounts={[4]=0,[6]=0};local oldcov={[4]=0,[6]=0}
  local oldips,keptips,oldsites,keptsites=0,0,0,0;local oldwide={}
  for line in io.lines(baseline..'/cn-ip.txt') do
   local r,f,p=network(line,true);oldcounts[f]=oldcounts[f]+1
   oldcov[f]=oldcov[f]+2^(f==4 and 32-p or 128-p)
   oldips=oldips+1;if d.ipseen[r[1]..'/'..p] then keptips=keptips+1 end
  end
  sortfile(baseline..'/cn-site.txt',outdir..'/.baseline.sorted')
  local candidate=assert(io.open(d.sorted,'r'));local current=candidate:read('*l')
  for line in io.lines(outdir..'/.baseline.sorted') do
   oldsites=oldsites+1
   while current and current<line do current=candidate:read('*l') end
   if current==line then keptsites=keptsites+1 end
   local name=line:match('^domain:(.*)$') or (not line:find(':',1,true) and line)
   if name and not name:find('.',1,true) then oldwide[name]=true end
  end
  candidate:close();os.remove(outdir..'/.baseline.sorted')
  for _,f in ipairs({4,6}) do bounded(#d.ips[f],oldcounts[f],'IPv'..f..' count');bounded(d.cov[f],oldcov[f],'IPv'..f..' coverage') end
  bounded(d.domaincount,oldsites,'domain count')
  if keptips<oldips*0.8 or keptsites<oldsites*0.8 then fail('more than 20 percent of baseline entries replaced') end
  for tld in pairs(d.wide) do if not oldwide[tld] then fail('new single-label suffix requires explicit review') end end
  if stripped(read(baseline..'/sets.nft',2097152))~=skeleton then fail('unrelated sets template changed') end
 end
 local add=additions(d.ips)
 os.remove(d.sorted)
 write(outdir..'/sets.nft',skeleton..add)
 write(outdir..'/replace.nft','flush set inet '..tab..' cn4\nflush set inet '..tab..' cn6\n'..add)
 write(outdir..'/ranges4.txt',canonical(d.rs[4]));write(outdir..'/ranges6.txt',canonical(d.rs[6]))
 local sums={};for _,f in ipairs(files) do sums[#sums+1]=f..'\t'..sha(outdir..'/'..f)..'\n' end
 write(outdir..'/manifest.tsv',table.concat(sums));manifest(outdir)
 print('prepared ipv4='..#d.ips[4]..' ipv6='..#d.ips[6]..' domains='..d.domaincount);return 0
end
local function live(f)
 local name='cn'..f
 local ok,s=command('nft -nn list set inet '..tab..' '..name)
 if not ok then
  local exists=command('nft list table inet '..tab)
  if not exists then fail('owned table unavailable; policy restoration required') end
  return nil,'missing'
 end
 -- nft's pretty printer separates set attributes with newlines, while saved
 -- command syntax may use semicolons. Parse complete attributes, not a loose
 -- substring: timeout/dynamic/concatenated sets are not safe static CN sets.
 local body=s:match('^%s*table%s+inet%s+'..tab..'%s*{%s*set%s+'..name..'%s*{(.*)}%s*}%s*$')
 if not body then fail('unexpected owned set listing: '..name) end
 local contents,count
 body,count=body:gsub('elements%s*=%s*{([^{}]*)}',function(value) contents=value;return '' end)
 if count>1 then fail('duplicate owned set elements: '..name) end
 local attrs={}
 for line in body:gmatch('[^;\n]+') do
  line=line:match('^%s*(.-)%s*$')
  if line~='' then
   local key,value=line:match('^(%S+)%s+(.+)$')
   if line=='auto-merge' then key='auto-merge';value=true end
   local valid=(key=='type' and value=='ipv'..f..'_addr') or (key=='flags' and value=='interval')
    or (key=='auto-merge' and value==true) or (key=='size' and value:match('^%d+$'))
    or (key=='policy' and (value=='performance' or value=='memory'))
   if not valid or attrs[key] then fail('unsafe owned set type or flags: '..name) end
   attrs[key]=value
  end
 end
 if not attrs.type or not attrs.flags or not attrs['auto-merge'] then fail('unsafe owned set type or flags: '..name) end
 if not contents then return '',s end
 local ranges={}
 for token in (contents..','):gmatch('(.-),') do
  token=token:match('^%s*(.-)%s*$')
  if token~='' then
   local a,b=token:match('^([0-9a-fA-F:%.]+)%s*%-%s*([0-9a-fA-F:%.]+)$')
   local r,fam
   if a then local lo,f1=ip(a);local hi,f2=ip(b);if f1~=f2 or lo>hi then fail('invalid nft range') end;r={lo,hi};fam=f1
   else r,fam=network(token,false) end
   if fam~=f then fail('wrong nft address family') end;ranges[#ranges+1]=r
  end
 end
 return canonical(ranges),s
end
function M.audit(dir)
 manifest(dir)
 for _,f in ipairs({4,6}) do if live(f)~=read(dir..'/ranges'..f..'.txt',2097152) then print('repair_needed cn'..f);return 2 end end
 print('intact');return 0
end
function M.repair(dir)
 manifest(dir);local prefix=''
 for _,f in ipairs({4,6}) do
  local _,why=live(f)
  if why=='missing' then prefix=prefix..'add set inet '..tab..' cn'..f..' { type ipv'..f..'_addr; flags interval; auto-merge; }\n' end
 end
 local path=os.tmpname();write(path,prefix..read(dir..'/replace.nft',2097152))
 local ok,err=command('nft -c -f '..quote(path))
 if ok then ok,err=command('nft -f '..quote(path)) end
 os.remove(path);if not ok then fail('atomic owned-set repair failed: '..err) end
 return M.audit(dir)
end
local ok,rc=pcall(function()
 local action=arg[1];if not M[action] then fail('usage: cn-data.lua prepare|verify|audit|repair ...') end
 return M[action](unpack(arg,2))
end)
if not ok then io.stderr:write('cn-data: '..tostring(rc)..'\n');os.exit(1) end
os.exit(rc or 0)
