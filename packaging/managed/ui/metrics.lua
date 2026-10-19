-- Read-only, bounded /proc samples. Never collect command arguments or payloads.
local fs=require('nixio.fs')
local M={}
local function read(p) local f=io.open(p);if not f then return '' end;local s=f:read('*a');f:close();return s end
local function numbers(s) local a={};for v in s:gmatch('%d+') do a[#a+1]=tonumber(v) end;return a end
function M.cpu()
 local r={}
 for name,rest in read('/proc/stat'):gmatch('(cpu%d*)%s+([^\n]+)') do
  local a=numbers(rest);local total=0;for i=1,8 do total=total+(a[i] or 0) end
  r[name]={total=total,idle=(a[4] or 0)+(a[5] or 0),softirq=a[7] or 0,irq=a[6] or 0}
 end
 return r
end
function M.cpu_delta(a,b)
 local out={cores={},max_core_pct=0}
 for name,v in pairs(b) do
  local old=a[name];local dt=old and v.total-old.total or 0
  if dt>0 then
   local x={busy_pct=math.max(0,math.min(100,100*(1-(v.idle-old.idle)/dt))),softirq_pct=100*(v.softirq-old.softirq)/dt,irq_pct=100*(v.irq-old.irq)/dt}
   if name=='cpu' then out.aggregate=x else out.cores[name]=x;out.max_core_pct=math.max(out.max_core_pct,x.busy_pct) end
  end
 end
 return out
end
function M.sample()
 local out={cpu=M.cpu(),threads={},thread_limit=1024,thread_count=0,uptime=tonumber(read('/proc/uptime'):match('^[%d.]+')),net={},softirqs={}}
 local pids=fs.dir('/proc')
 for pid in pids do
  if pid:match('^%d+$') then
   local tids=fs.dir('/proc/'..pid..'/task')
   if tids then for tid in tids do
    if tid:match('^%d+$') then
     if out.thread_count>=out.thread_limit then out.truncated=true;break end
     local comm,rest=read('/proc/'..pid..'/task/'..tid..'/stat'):match('^%d+ %((.*)%) (.*)$')
     if rest then
      local f={};for s in rest:gmatch('%S+') do f[#f+1]=s end
      if f[20] and tonumber(f[12]) and tonumber(f[13]) then
       out.threads[pid..':'..tid]={pid=tonumber(pid),tid=tonumber(tid),name=comm,start=f[20],ticks=tonumber(f[12])+tonumber(f[13])};out.thread_count=out.thread_count+1
      end
     end
    end
   end end
  end
  if out.truncated then break end
 end
 for name,rest in read('/proc/net/dev'):gmatch('([%w_.%-]+):%s*([^\n]+)') do local a=numbers(rest);out.net[name]={rx_bytes=a[1],rx_packets=a[2],rx_drop=a[4],tx_bytes=a[9],tx_packets=a[10],tx_drop=a[12]} end
 for name,rest in read('/proc/softirqs'):gmatch('([A-Z_]+):%s*([^\n]+)') do local sum=0;for _,v in ipairs(numbers(rest)) do sum=sum+v end;out.softirqs[name]=sum end
 return out
end
function M.delta(a,b)
 local out=M.cpu_delta(a.cpu,b.cpu);out.seconds=b.uptime-a.uptime;out.thread_scan_truncated=a.truncated or b.truncated or false;out.top_threads={};out.interfaces={};out.softirq_events={}
 local cores=0;for k in pairs(b.cpu) do if k~='cpu' then cores=cores+1 end end
 local dt=b.cpu.cpu.total-a.cpu.cpu.total
 if dt>0 then for key,v in pairs(b.threads) do
  local old=a.threads[key]
  if old and old.start==v.start and v.ticks>=old.ticks then
   out.top_threads[#out.top_threads+1]={pid=v.pid,tid=v.tid,name=v.name,cpu_one_core_pct=100*cores*(v.ticks-old.ticks)/dt}
  end
 end end
 table.sort(out.top_threads,function(x,y)return x.cpu_one_core_pct>y.cpu_one_core_pct end)
 while #out.top_threads>20 do table.remove(out.top_threads) end
 if out.seconds>0 then for name,v in pairs(b.net) do if a.net[name] then local d={};for k,n in pairs(v) do if n>=a.net[name][k] then d[k..'_per_second']=(n-a.net[name][k])/out.seconds end end;out.interfaces[name]=d end end end
 for k,n in pairs(b.softirqs) do if a.softirqs[k] then out.softirq_events[k]=math.max(0,n-a.softirqs[k]) end end
 return out
end
return M
