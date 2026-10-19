-- Real resolver counters only. This module never infers cache hits from DNS probes.
local json=require('luci.jsonc')
local fs=require('nixio.fs')
local M={}
local R='/var/run/pnw-control'
local SOURCE='/var/run/diversion-dns-c/metrics.json'
local WINDOW=300
local MAX_AGE=90
local cache_keys={'fresh_hit','stale_hit','miss_cold','miss_evicted','miss_expired','bypass'}
local cache_aliases={fresh_hit='fresh',stale_hit='stale',miss_cold='cold',miss_evicted='evicted',miss_expired='expired',bypass='bypass'}
local total_keys={'requests','completed','success','failed','latency_count','latency_sum_us'}
local function read(path,limit)
 local f=io.open(path);if not f then return nil end
 local s=f:read((limit or 262144)+1);f:close()
 if s and #s>(limit or 262144) then return nil end;return s
end
local function load(path) local s=read(path);return s and json.parse(s) or nil end
local function save(path,value)
 local tmp=path..'.new';local f=assert(io.open(tmp,'w'));f:write(json.stringify(value));f:close();assert(os.rename(tmp,path))
end
local function integer(n) return type(n)=='number' and n>=0 and n<=9007199254740991 and n==math.floor(n) end
local function unavailable(reason) return {available=false,reason=reason,source=SOURCE,window_seconds=0} end
local function group_values(raw)
 if type(raw)~='table' then return nil end
 local out={}
 for _,key in ipairs(cache_keys) do local value=raw[key] or raw[cache_aliases[key]];if not integer(value) then return nil end;out[key]=value end
 return out
end
function M.validate(raw,boot)
 if type(raw)=='table' and raw.final==true then return nil,'resolver has stopped (final snapshot)' end
 if type(raw)~='table' or raw.version~=1 or not integer(raw.pid) or raw.pid<1 or not integer(raw.started_unix) or not integer(raw.sequence) or not integer(raw.uptime_ms) then return nil,'invalid resolver snapshot identity' end
 local t=raw.totals;if type(t)~='table' then return nil,'missing resolver totals' end
 for _,key in ipairs(total_keys) do if not integer(t[key]) then return nil,'invalid resolver counter '..key end end
 if t.success+t.failed~=t.completed or t.latency_count~=t.completed then return nil,'inconsistent resolver counters' end
 local cn=group_values(raw.cache and raw.cache.cn);local foreign=group_values(raw.cache and raw.cache.foreign)
 if not cn or not foreign then return nil,'invalid cache counters' end
 local time=integer(raw.updated_unix_ms) and raw.updated_unix_ms/1000 or raw.sampled_unix or raw.time_unix or (raw.started_unix+raw.uptime_ms/1000)
 if type(time)~='number' or time<raw.started_unix then return nil,'invalid sample time' end
 local out={version=1,pid=raw.pid,started_unix=raw.started_unix,sequence=raw.sequence,uptime_ms=raw.uptime_ms,
  time=time,identity=tostring(boot or '')..':'..raw.pid..':'..raw.started_unix,totals={},cache={cn=cn,foreign=foreign}}
 for _,key in ipairs(total_keys) do out.totals[key]=t[key] end
 if integer(t.latest_latency_us) then out.totals.latest_latency_us=t.latest_latency_us end
 if integer(t.latest_completion_unix_ms) then out.totals.latest_completion_unix_ms=t.latest_completion_unix_ms end
 local bounds=raw.latency_bucket_upper_us or t.latency_bucket_upper_us
 if type(t.latency_buckets)=='table' and type(bounds)=='table' and #t.latency_buckets<=64 and #t.latency_buckets>0 then
  out.totals.latency_buckets={};out.latency_bucket_upper_us={};local sum,last=0,-1
  for i,count in ipairs(t.latency_buckets) do
   local bound=bounds[i]
   local overflow=i==#t.latency_buckets and (bound==nil or type(bound)=='userdata' or (json.null~=nil and bound==json.null))
   if not integer(count) or (not overflow and (not integer(bound) or bound<=last)) then return nil,'invalid latency histogram' end
   sum=sum+count;last=overflow and last or bound;out.totals.latency_buckets[i]=count;out.latency_bucket_upper_us[i]=overflow and 'inf' or bound
  end
  if sum~=t.latency_count then return nil,'inconsistent latency histogram' end
 end
 return out
end
function M.process_identity(raw,reader,readlink)
 reader=reader or read;readlink=readlink or fs.readlink
 local path='/proc/'..raw.pid
 local stat=reader(path..'/stat',4096) or '';local rest=stat:match('^%d+ %(.+%) (.*)$')
 if not rest then return nil,'resolver process is no longer running' end
 local fields={};for v in rest:gmatch('%S+') do fields[#fields+1]=v end
 if fields[1]=='Z' or fields[1]=='X' or not fields[20] or not fields[20]:match('^%d+$') then return nil,'resolver process has exited' end
 local exe=readlink and readlink(path..'/exe')
 if exe~='/usr/libexec/diversion-dns-c' and exe~='/usr/libexec/diversion-dns-c (deleted)' and exe~='/usr/sbin/diversion-dns-c' and exe~='/usr/sbin/diversion-dns-c (deleted)' and exe~='/usr/sbin/diversion-dns-c-lite' and exe~='/usr/sbin/diversion-dns-c-lite (deleted)' then return nil,'snapshot PID does not identify the managed resolver' end
 return fields[20]
end
local function delta_keys(a,b,keys)
 local out={};for _,k in ipairs(keys) do if b[k]<a[k] then return nil end;out[k]=b[k]-a[k] end;return out
end
local function cache_summary(d)
 local hits=d.fresh_hit+d.stale_hit;local requests=hits+d.miss_cold+d.miss_evicted+d.miss_expired+d.bypass
 return {queries=requests,cache_hits=hits,fresh_hits=d.fresh_hit,stale_hits=d.stale_hit,
  misses=d.miss_cold+d.miss_evicted+d.miss_expired,bypass=d.bypass,cache_hit_rate_pct=requests>0 and 100*hits/requests or nil,
  reason=requests==0 and 'no queries in observation window' or nil}
end
function M.delta(a,b)
 if not a or not b then return nil,'waiting for two resolver snapshots' end
 if a.identity~=b.identity or b.sequence<=a.sequence or b.uptime_ms<=a.uptime_ms then return nil,'resolver restarted or snapshot sequence reset; collecting a new window' end
 local d=delta_keys(a.totals,b.totals,total_keys)
 local cn=delta_keys(a.cache.cn,b.cache.cn,cache_keys);local foreign=delta_keys(a.cache.foreign,b.cache.foreign,cache_keys)
 if not d or not cn or not foreign then return nil,'resolver counter reset; collecting a new window' end
 if d.success+d.failed>d.completed or d.latency_count>d.completed then return nil,'inconsistent counter delta; collecting a new window' end
 local common={window_start=a.time,window_end=b.time,window_seconds=(b.uptime_ms-a.uptime_ms)/1000}
 local dns={available=true,source=SOURCE,scope='resolver completed DNS requests; success = NOERROR or NXDOMAIN and response send accepted',
  requests=d.requests,completed=d.completed,successes=d.success,failures=d.failed,
  success_rate_pct=d.completed>0 and 100*d.success/d.completed or nil,
  avg_ms=d.latency_count>0 and d.latency_sum_us/d.latency_count/1000 or nil,
  latency_count=d.latency_count,reason=d.completed==0 and 'no completed DNS requests in observation window' or nil}
 if d.completed>0 and b.totals.latest_completion_unix_ms and b.totals.latest_completion_unix_ms>=a.time*1000 then dns.recent_ms=(b.totals.latest_latency_us or 0)/1000;dns.recent_at=b.totals.latest_completion_unix_ms/1000 end
 if a.totals.latency_buckets and b.totals.latency_buckets and #a.totals.latency_buckets==#b.totals.latency_buckets then
  local cumulative,valid=0,true
  for i,n in ipairs(b.totals.latency_buckets) do
   if n<a.totals.latency_buckets[i] or b.latency_bucket_upper_us[i]~=a.latency_bucket_upper_us[i] then valid=false;break end
   cumulative=cumulative+n-a.totals.latency_buckets[i]
   if not dns.p95_ms and not dns.p95_overflow and d.latency_count>0 and cumulative>=math.ceil(d.latency_count*0.95) then
    if b.latency_bucket_upper_us[i]=='inf' then dns.p95_overflow=true;dns.p95_lower_bound_ms=(b.latency_bucket_upper_us[i-1] or 0)/1000
    else dns.p95_ms=b.latency_bucket_upper_us[i]/1000;dns.p95_is_upper_bound=true end
   end
  end
  if not valid then return nil,'latency histogram reset; collecting a new window' end
 end
 local all={};for _,k in ipairs(cache_keys) do all[k]=cn[k]+foreign[k] end
 local cache={available=true,source=SOURCE,scope='resolver cache lookups, fresh and stale hits / all counted lookups including bypass',groups={all=cache_summary(all),cn=cache_summary(cn),foreign=cache_summary(foreign)}}
 for k,v in pairs(common) do dns[k]=v;cache[k]=v end
 return {dns=dns,cache=cache}
end
function M.reduce(points,now)
 local b=points and points[#points]
 if not b then return {dns=unavailable('resolver metrics are not available'),cache=unavailable('resolver metrics are not available')} end
 local age=now-b.time
 if age< -5 or age>MAX_AGE then local why=age<0 and 'sample clock is ahead; awaiting current data' or 'resolver metrics are stale';return {dns=unavailable(why),cache=unavailable(why)} end
 local a
 for _,p in ipairs(points) do if p.identity==b.identity and p.uptime_ms>=b.uptime_ms-WINDOW*1000 and p.uptime_ms<b.uptime_ms then a=p;break end end
 local result,reason=M.delta(a,b)
 if not result then result={dns=unavailable(reason),cache=unavailable(reason)} end
 for _,v in pairs(result) do v.sample_age_seconds=age;v.sampled_at=b.time;v.process_started=b.started_unix;v.maximum_window_seconds=WINDOW end
 return result
end
function M.collect()
 fs.mkdir(R,'700')
 local lock=R..'/telemetry-lock';local st=fs.stat(lock)
 if st and st.mtime and os.time()-st.mtime>30 then
  local pid=read(lock..'/pid',32)
  if not pid or not pid:match('^%d+$') or not fs.stat('/proc/'..pid) then os.remove(lock..'/pid');fs.rmdir(lock) end
 end
 if not fs.mkdir(lock,'700') then return false end
 local ok,err=pcall(function()
  local f=assert(io.open(lock..'/pid','w'));f:write(tostring(require('nixio').getpid()));f:close()
  local raw=load(SOURCE);local boot=(read('/proc/sys/kernel/random/boot_id',128) or ''):gsub('%s+$','')
  local p,why=M.validate(raw,boot)
  if p then local process_start,reason=M.process_identity(p);if not process_start then p=nil;why=reason else p.process_start=process_start;p.identity=p.identity..':'..process_start end end
  local state=load(R..'/telemetry-state.json') or {points={}}
  state.points=state.points or {}
  if not p then state.error=why or 'resolver metrics are not available'
  else
   state.error=nil;local last=state.points[#state.points]
   if last and (p.identity~=last.identity or p.sequence<last.sequence or p.uptime_ms<last.uptime_ms) then state.points={} end
   if not last or p.identity~=last.identity or p.sequence~=last.sequence then
    if last and last.identity==p.identity and not M.delta(last,p) then state.points={} end
    state.points[#state.points+1]=p
    while #state.points>64 or (#state.points>2 and state.points[2].uptime_ms<p.uptime_ms-WINDOW*1000) do table.remove(state.points,1) end
   end
  end
  state.collected_at=os.time();save(R..'/telemetry-state.json',state)
 end)
 os.remove(lock..'/pid');fs.rmdir(lock)
 return ok,err
end
local function legacy_status()
 local state=load(R..'/telemetry-state.json') or {};local now=os.time()
 if state.error or not state.collected_at or now-state.collected_at>MAX_AGE then
  local why=state.error or 'waiting for telemetry collector';return {dns=unavailable(why),cache=unavailable(why)}
 end
 local latest=state.points and state.points[#state.points]
 if latest then
  local process_start,why=M.process_identity(latest)
  if not process_start or process_start~=latest.process_start then local reason=why or 'resolver process changed; awaiting a new window';return {dns=unavailable(reason),cache=unavailable(reason)} end
  -- The producer can stop after collection; a final file must invalidate the UI
  -- immediately, even while the collector still has a fresh cached snapshot.
  local raw=load(SOURCE)
  if not raw or raw.final==true or raw.pid~=latest.pid or raw.started_unix~=latest.started_unix then
   local reason='resolver stopped or restarted; awaiting a current snapshot';return {dns=unavailable(reason),cache=unavailable(reason)}
  end
 end
 return M.reduce(state.points,now)
end

-- Optional PR #27 stats. Keep it separate: completed-request cache attribution
-- is not the legacy cache-lookup denominator. Never synthesize one from another.
local STATS_SOURCE='/tmp/diversion-dns-stats.json'
local error_keys={'queue_full','queue_timeout','upstream_failure','upstream_timeout','nft_failure','execution_deadline','invalid_response','memory','send_failure','client_disconnected','shutdown'}
local event_keys={'invalid_udp','invalid_tcp','tcp_read_timeout','tcp_write_timeout','tcp_limit_rejected','tcp_evicted','allocation_failure'}
local function finite(n) return type(n)=='number' and n==n and n>=0 and n<math.huge end
local function counters(raw,keys)
 if type(raw)~='table' then return nil end
 local out={};for _,k in ipairs(keys) do if not integer(raw[k]) then return nil end;out[k]=raw[k] end;return out
end
local function histogram(raw,bounds,expected)
 if type(raw)~='table' or raw.samples~=expected or type(raw.histogram)~='table' or #raw.histogram~=#bounds then return nil end
 local out={samples=expected};local sum=0
 for i,n in ipairs(raw.histogram) do
  if not integer(n) then return nil end;sum=sum+n
  for _,q in ipairs({50,95,99}) do
   local key='p'..q
   if expected>0 and not out[key..'_set'] and sum>=math.ceil(expected*q/100) then
    out[key..'_set']=true
    if bounds[i]=='inf' then out[key..'_overflow']=true;out[key..'_lower_ms']=bounds[i-1] or 0
    else out[key..'_ms']=bounds[i] end
   end
  end
 end
 if sum~=expected then return nil end
 if expected>0 then
  if not finite(raw.avg_ms) or not finite(raw.max_ms) or raw.avg_ms>raw.max_ms+0.001 then return nil end
  out.avg_ms=raw.avg_ms;out.max_ms=raw.max_ms
 end
 return out
end
local function metric(raw,bounds)
 if type(raw)~='table' then return nil end
 local out=counters(raw,{'completed','success','noerror','nxdomain'})
 if not out or out.success>out.completed or out.noerror+out.nxdomain>out.completed then return nil end
 out.cache=counters(raw.cache,{'fresh','stale','miss','disabled_or_unchecked'})
 out.errors=counters(raw.errors,error_keys)
 if not out.cache or not out.errors then return nil end
 local total=0;for _,n in pairs(out.cache) do total=total+n end
 if total~=out.completed then return nil end
 for _,key in ipairs({'rt','queue','service'}) do
  -- Queue/service samples may differ from completed (immediate rejections).
  local h=raw[key];if type(h)~='table' or not integer(h.samples) or h.samples>out.completed then return nil end
  if key=='rt' and h.samples~=out.completed then return nil end
  out[key]=histogram(h,bounds,h.samples);if not out[key] then return nil end
 end
 local errors=0;for _,n in pairs(out.errors) do errors=errors+n end
 if errors>out.completed-out.success then return nil end
 out.failures=out.completed-out.success
 out.success_rate_pct=out.completed>0 and 100*out.success/out.completed or nil
 out.cache_hit_rate_pct=out.completed>0 and 100*(out.cache.fresh+out.cache.stale)/out.completed or nil
 if type(raw.rcode)=='table' then
  out.rcode={};local counted=0
  for i=0,16 do local key=i==16 and "extended" or tostring(i);local n=raw.rcode[key]
   if not integer(n) then return nil end;out.rcode[key]=n;counted=counted+n
  end
  if counted>out.completed then return nil end
 end
 return out
end
function M.validate_stats(raw,now)
 local function bad(reason) return nil,'stats '..reason end
 if type(raw)~='table' or raw.schema~='diversion-dns-stats-v1' then return bad('未启用或格式不支持') end
 if raw.final==true then return bad('进程已停止，文件为最终快照') end
 if not integer(raw.pid) or raw.pid<1 or not integer(raw.started_unix) or not integer(raw.snapshot_unix)
  or not finite(raw.uptime_seconds) or not integer(raw.interval_seconds) or raw.interval_seconds<5 or raw.interval_seconds>3600 then return bad('身份或时间字段无效') end
 local age=now-raw.snapshot_unix
 if age< -5 or age>math.max(90,raw.interval_seconds*2+20) or raw.snapshot_unix<raw.started_unix
  or math.abs(raw.started_unix+raw.uptime_seconds-raw.snapshot_unix)>5 then return bad('快照过期或时钟异常') end
 local bounds={};local bins=raw.total and type(raw.total)=='table' and raw.total.rt
 bins=type(bins)=='table' and type(bins.histogram)=='table' and #bins.histogram or 0
 if type(raw.histogram_upper_ms)~='table' or bins<2 or bins>64 or #raw.histogram_upper_ms>bins then return bad('直方图边界无效') end
 for i=1,bins do
  local n=raw.histogram_upper_ms[i]
  if i==bins and (n==nil or type(n)=='userdata' or (json.null~=nil and n==json.null)) then bounds[i]='inf'
  elseif not finite(n) or (i>1 and n<=bounds[i-1]) then return bad('直方图边界无效') else bounds[i]=n end
 end
 if bounds[bins]~='inf' then return bad('缺少溢出桶') end
 local out={available=true,source=STATS_SOURCE,pid=raw.pid,started_unix=raw.started_unix,sampled_at=raw.snapshot_unix,
  sample_age_seconds=age,uptime_seconds=raw.uptime_seconds,interval_seconds=raw.interval_seconds,
  total=metric(raw.total,bounds),intervals={},breakdown={}}
 if not out.total then return bad('累计计数不一致') end
 if not integer(raw.received_valid) or not integer(raw.inflight) or raw.received_valid~=out.total.completed+raw.inflight then return bad('在途计数不一致') end
 out.inflight=raw.inflight;out.received_valid=raw.received_valid
 out.events=counters(raw.events,event_keys);if not out.events then return bad('事件计数无效') end
 if type(raw.recent_intervals)~='table' or #raw.recent_intervals>60 then return bad('区间数量无效') end
 local last_end=-1
 for _,v in ipairs(raw.recent_intervals) do
  if type(v)~='table' or not finite(v.start_uptime_seconds) or not finite(v.duration_seconds) or v.duration_seconds<=0
   or v.start_uptime_seconds<last_end-0.002 or v.start_uptime_seconds+v.duration_seconds>raw.uptime_seconds+0.002 then return bad('区间时间无效') end
  local m=metric(v.metrics,bounds);if not m then return bad('区间计数无效') end
  last_end=v.start_uptime_seconds+v.duration_seconds
  out.intervals[#out.intervals+1]={start=raw.started_unix+v.start_uptime_seconds,finish=raw.started_unix+last_end,seconds=v.duration_seconds,qps=m.completed/v.duration_seconds,metrics=m}
 end
 if type(raw.breakdown)~='table' or #raw.breakdown~=12 then return bad('分组数量无效') end
 local seen,completed={},0
 for _,v in ipairs(raw.breakdown) do
  if type(v)~='table' or (v.group~='cn' and v.group~='foreign') or (v.qtype~='A' and v.qtype~='AAAA' and v.qtype~='other') or (v.transport~='udp' and v.transport~='tcp') then return bad('分组标签无效') end
  local key=v.group..v.qtype..v.transport;local m=metric(v.metrics,bounds)
  if seen[key] or not m then return bad('分组重复或计数无效') end
  seen[key]=true;completed=completed+m.completed
  out.breakdown[#out.breakdown+1]={group=v.group,qtype=v.qtype,transport=v.transport,metrics=m}
 end
 if completed~=out.total.completed then return bad('分组总量不一致') end
 local top=raw.top50
 if type(top)~='table' or top.algorithm~='space-saving' or top.capacity~=1024 or not integer(top.replacements)
  or type(top.exact)~='boolean' or top.exact~=(top.replacements==0) or type(top.domains)~='table' or #top.domains>50 then return bad('排行格式无效') end
 out.top50={exact=top.exact,domains={}};local names={}
 for _,d in ipairs(top.domains) do
  if type(d)~='table' or type(d.domain)~='string' or #d.domain<1 or #d.domain>253 or d.domain:find('[%z\1-\31\127]')
   or names[d.domain] or not integer(d.count_estimate) or not integer(d.count_lower_bound) or not integer(d.error_bound)
   or d.count_lower_bound+d.error_bound~=d.count_estimate or d.count_estimate>out.total.completed or (top.exact and d.error_bound~=0) then return bad('排行计数无效') end
  names[d.domain]=true;out.top50.domains[#out.top50.domains+1]={domain=d.domain,count_estimate=d.count_estimate,count_lower_bound=d.count_lower_bound,error_bound=d.error_bound}
 end
 table.sort(out.top50.domains,function(a,b) return a.count_estimate>b.count_estimate or (a.count_estimate==b.count_estimate and a.domain<b.domain) end)
 return out
end
function M.stats_status()
 local s=read(STATS_SOURCE,1048576);local raw=s and json.parse(s)
 local safe,result,why=pcall(M.validate_stats,raw,os.time())
 if not safe then result=nil;why="stats 快照结构无效" end
 if result then
  local start,reason=M.process_identity(result)
  if not start then result=nil;why=reason end
 end
 return result or {available=false,source=STATS_SOURCE,reason=why}
end
function M.status()
 local result=legacy_status()
 result.stats=M.stats_status()
 return result
end

-- Keep operation/check durations separate from actual DNS traffic statistics.
function M.record_health(h) save(R..'/telemetry-last-health.json',h) end
function M.record_operation(r) save(R..'/telemetry-last-operation.json',r) end
M.source=SOURCE
return M
