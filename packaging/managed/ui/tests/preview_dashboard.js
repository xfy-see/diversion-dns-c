'use strict';
// Offline preview of the real LuCI renderer. Fixtures only; no router calls.
const fs=require('node:fs'),path=require('node:path');
const test=fs.readFileSync(path.join(__dirname,'frontend.test.js'),'utf8').split('(async () => {')[0];
const {fixture,statsFixture}=new Function('require','__dirname',test+'\nreturn {fixture,statsFixture};')(require,__dirname);
const data=fixture(),stats=statsFixture();
stats.started_unix=data.server_time-3600;stats.uptime_seconds=3600;
stats.intervals=Array.from({length:60},(_,i)=>{
 const m=structuredClone(stats.total);m.completed=100+i*2;m.success=m.completed-(i%13===0?2:0);m.cache={fresh:Math.floor(m.completed*.85),stale:4};
 m.success_rate_pct=100*m.success/m.completed;m.cache_hit_rate_pct=100*(m.cache.fresh+m.cache.stale)/m.completed;
 m.rt={samples:m.completed,avg_ms:2+i%5,p95_ms:8+i%4*4,p99_ms:16+(i%17===0?80:i%5*4)};
 return {start:stats.started_unix+i*60,finish:stats.started_unix+(i+1)*60,seconds:60,qps:m.completed/60,metrics:m};
});
stats.total=structuredClone(stats.total);stats.total.completed=stats.intervals.reduce((n,v)=>n+v.metrics.completed,0);stats.total.success=stats.intervals.reduce((n,v)=>n+v.metrics.success,0);stats.total.failures=stats.total.completed-stats.total.success;stats.total.errors={upstream_timeout:stats.total.failures};stats.breakdown[0].metrics=stats.total;
stats.top50.domains=Array.from({length:50},(_,i)=>({domain:(['chatgpt','claude','google','example'][i%4])+i+'.example',count_estimate:100-i,count_lower_bound:98-i,error_bound:2}));
data.telemetry={stats};
const source=fs.readFileSync(path.join(__dirname,'../view.js'),'utf8');
const encode=x=>JSON.stringify(x).replace(/</g,'\\u003c');
const html=`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DNS stats 离线预览 · 模拟数据</title><style>body{font:15px/1.5 system-ui,sans-serif;background:#f5f7fa;color:#1e293b;margin:0 auto;padding:24px;max-width:1200px}button,select,input{font:inherit;padding:9px;border:1px solid #aab6c6;border-radius:6px;background:#fff;color:inherit}button:disabled{opacity:.5}th{background:#f1f5f9}h3{font-size:17px}#banner{background:#fff1cd;padding:15px;border-radius:8px;position:sticky;top:0;z-index:5}#topDomains{max-height:400px}</style><div id="banner"><strong>离线交互预览 · 全部为模拟数据 · 无路由器连接</strong><p>可切换趋势、筛选域名、展开明细；设备控制已停用。</p><label>预览状态 <select id="mode"><option value="stats">扩展统计</option><option value="legacy">仅旧版 metrics</option><option value="missing">统计过期</option></select></label></div><main id="app"></main><script>
const original=${encode(data)}, source=${encode(source)};
function E(tag,attrs,children){const el=document.createElement(tag);Object.entries(attrs||{}).forEach(([k,v])=>{if(typeof v==='function')el.addEventListener(k,v);else el.setAttribute(k,v)});(Array.isArray(children)?children:[children]).forEach(c=>{if(c!==undefined&&c!==null)el.appendChild(typeof c==='object'?c:document.createTextNode(c))});return el;}
function draw(){const d=structuredClone(original);d.server_time=Date.now()/1000;d.running=true;d.health.finished=d.server_time;
const mode=document.querySelector('#mode').value;if(mode!=='stats')d.telemetry={stats:{available:false,reason:mode==='missing'?'模拟：快照过期':'模拟：未启用 stats'},dns:{available:true,completed:100,successes:98,failures:2,requests:100,latency_count:100,avg_ms:4,p95_ms:16,p95_is_upper_bound:true,recent_ms:2.5,source:'模拟旧版 metrics',window_seconds:60},cache:{available:true,groups:{cn:{queries:60,cache_hits:54},foreign:{queries:40,cache_hits:28},all:{queries:100,cache_hits:82}}}};
const page=new Function('view','fs','poll','ui','E',source)({extend:x=>x},{exec:()=>Promise.reject(Error('离线预览禁用操作'))},{add(){}},{addNotification(){}},E);const root=page.render(d);document.querySelector('#app').replaceChildren(root);root.querySelectorAll('[data-pnw-action]').forEach(b=>{b.disabled=true});}
document.querySelector('#mode').addEventListener('change',draw);draw();
</script></html>`;
fs.writeFileSync(process.argv[2]||'/tmp/pnw-stats-preview.html',html);
