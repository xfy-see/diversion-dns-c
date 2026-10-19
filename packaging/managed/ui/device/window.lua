-- Recent-window adapter for the existing stats producer. No fabricated legacy file.
local J=require('luci.jsonc');local F=require('nixio.fs');local N=require('nixio')
local T=dofile('/usr/share/diversion-dns-ui/telemetry.lua');local M={};local R='/var/run/diversion-dns-ui';local SOURCE='/tmp/diversion-dns-stats.json'
local function read(p,max)local f=io.open(p);if not f then return nil end;local s=f:read((max or 1048576)+1);f:close();return #s<=(max or 1048576) and s or nil end
local function load(p)return J.parse(read(p) or '{}') or {}end
local function save(v)local f=assert(io.open(R..'/window.json.new','w'));f:write(J.stringify(v));f:close();assert(os.rename(R..'/window.json.new',R..'/window.json'))end
function M.convert(raw,boot)
 local safe,why=T.validate_stats(raw,os.time());if not safe then return nil,why end
 local ticks,err=T.process_identity(raw);if not ticks then return nil,err end
 local bins={};for i,v in ipairs(raw.histogram_upper_ms)do bins[i]=type(v)=='number' and math.floor(v*1000+.5) or J.null end
 local point,reason=T.validate({version=1,pid=raw.pid,started_unix=raw.started_unix,sequence=math.floor(raw.uptime_seconds*1000),uptime_ms=math.floor(raw.uptime_seconds*1000),sampled_unix=raw.snapshot_unix,
 totals={requests=raw.received_valid,completed=raw.total.completed,success=raw.total.success,failed=raw.total.completed-raw.total.success,latency_count=raw.total.rt.samples,latency_sum_us=math.floor((tonumber(raw.total.rt.avg_ms) or 0)*raw.total.rt.samples*1000+.5),latency_buckets=raw.total.rt.histogram},cache=raw.cache_engine,latency_bucket_upper_us=bins},boot)
 if point then point.identity=point.identity..':'..ticks;point.process_start=ticks end
 return point,reason
end
function M.collect()
 F.mkdir(R,'700');local lock=R..'/window-lock';local st=F.stat(lock)
 if st and st.mtime and os.time()-st.mtime>30 then local owner=read(lock..'/pid',32);if not owner or not owner:match('^%d+$') or not F.stat('/proc/'..owner)then os.remove(lock..'/pid');F.rmdir(lock)end end
 if not F.mkdir(lock,'700')then return false end
 local owner=assert(io.open(lock..'/pid','w'));owner:write(N.getpid());owner:close()
 local ok,result=pcall(function()
  local raw=load(SOURCE);local point,reason=M.convert(raw,read('/proc/sys/kernel/random/boot_id',128));local state=load(R..'/window.json');state.points=state.points or {}
  if not point then state.error=reason or 'stats unavailable'
  else state.error=nil;local old=state.points[#state.points]
   if old and (point.identity~=old.identity or point.sequence<old.sequence or (point.sequence>old.sequence and not T.delta(old,point)))then state.points={};old=nil end
   if not old or point.sequence>old.sequence then state.points[#state.points+1]=point end
   while #state.points>32 or (#state.points>2 and state.points[2].uptime_ms<point.uptime_ms-300000)do table.remove(state.points,1)end
  end
  state.collected_at=os.time();save(state)
 end)
 os.remove(lock..'/pid');F.rmdir(lock);return ok,result
end
function M.status()
 local raw=load(SOURCE);local safe,why=T.validate_stats(raw,os.time());local ticks=safe and T.process_identity(raw)
 local state=load(R..'/window.json');local last=state.points and state.points[#state.points]
 local result
 if not safe or not ticks or not last or raw.pid~=last.pid or raw.started_unix~=last.started_unix or ticks~=last.process_start or state.error or not state.collected_at or os.time()-state.collected_at>90 then
  local reason=why or state.error or '等待当前进程的两次有效 stats 快照';result={dns={available=false,reason=reason},cache={available=false,reason=reason}}
 else result=T.reduce(state.points,os.time())end
 for _,v in pairs(result)do v.source=SOURCE..'（同进程累计差值）'end
 if result.dns.available and safe then
  for i=#safe.intervals,1,-1 do local it=safe.intervals[i]
   if it.metrics and it.metrics.completed>0 and it.finish and raw.snapshot_unix-it.finish<=90 then
    result.dns.recent_ms=it.metrics.rt.avg_ms;result.dns.recent_kind='interval_average';result.dns.recent_at=it.finish;break
   end
  end
 end
 result.dns.recent_kind='interval_average';result.stats=safe or {available=false,reason=why}
 return result
end
return M
