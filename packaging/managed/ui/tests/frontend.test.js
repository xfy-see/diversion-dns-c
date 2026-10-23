'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../view.js'), 'utf8');

class Element {
 constructor(tag, attrs = {}, children = []) {
  this.tag = tag; this.attrs = attrs || {}; this.children = []; this.events = {};
  this.disabled = !!this.attrs.disabled; this.value = this.attrs.value || ''; this.hidden = false;
  this.className = this.attrs.class || ''; this._text = '';
  Object.keys(this.attrs).forEach(k => { if (typeof this.attrs[k] === 'function') this.events[k] = this.attrs[k]; });
  (Array.isArray(children) ? children : [children]).forEach(c => { if (c !== undefined && c !== null) this.appendChild(typeof c === 'string' ? new TextNode(c) : c); });
 }
 appendChild(child) { child.parentNode = this; this.children.push(child); return child; }
 removeChild(child) { this.children.splice(this.children.indexOf(child), 1); child.parentNode = null; return child; }
 addEventListener(type, fn) { this.events[type] = fn; }
 get firstChild() { return this.children[0] || null; }
 get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
 set textContent(v) { this._text = String(v); this.children = []; }
 click() { if (!this.disabled && this.events.click) return this.events.click(); }
}
class TextNode { constructor(s) { this.textContent = s; } }
function all(node, predicate) { return [node, ...(node.children || []).flatMap(c => all(c, predicate))].filter(predicate); }
function fixture(extra = {}) {
 const now = 1792300000;
 return Object.assign({ selected: 'aws', running: false, emergency: false, pending: false, dns_degraded: false,
  server_time: now, version: '2026.10.18.1', previous_exit: 'nobrand', usss_available: true, vless_available: true,
  endpoint_health: { dns_failures: [] }, last: { action: 'check', state: 'success', time: now, duration_ms: 280 },
  health: { selected: 'aws', finished: now, duration_ms: 275, ok: true,
   checks: { domestic_dns: true, foreign_dns: true, https_ipv4: true, https_ipv6: true },
   details: { domestic_dns: { ok: true, duration_ms: 2.4 } },
   public_exit: { selected: 'aws', time: now, ipv4: { ip: '203.0.113.5', expected: '203.0.113.5', matches_expected: true, identity_status: 'verified', checked_at: now, probe_scope: 'router_https' } }
  }, diagnostic: { fixture: true } }, extra);
}
function create(data, handler, statsOnly = false, deviceMode = false) {
 let now = 1792300000000;
 const polls = [], calls = [], notifications = [];
 class TestDate extends Date { static now() { return now; } }
 const factory = new Function('view', 'fs', 'poll', 'ui', 'E', 'document', 'Date', 'URL', 'Blob', 'setTimeout', source);
 const instance = factory({ extend: x => x }, { exec: async () => ({ code: 0, stdout: '{}' }) }, { add: (fn, interval) => polls.push({ fn, interval }) },
  { addNotification: (a, b, c) => notifications.push([a, b, c]) }, (tag, attrs, children) => new Element(tag, attrs, children),
  { createTextNode: s => new TextNode(s), createElement: tag => new Element(tag) }, TestDate, { createObjectURL: () => 'blob:fixture', revokeObjectURL() {} }, Blob, setTimeout);
 instance.call = args => { calls.push(args); return handler ? handler(args) : Promise.resolve(fixture()); };
 instance.statsOnly=statsOnly;instance.deviceMode=deviceMode;
 const root = instance.render(data);
 const part = id => all(root, n => n.attrs && n.attrs['data-pnw-part'] === id)[0];
 const action = id => all(root, n => n.attrs && n.attrs['data-pnw-action'] === id)[0];
 return { root, part, action, calls, notifications, instance, polls, poll: interval => polls.find(p => p.interval === interval).fn(), advance: ms => { now += ms; } };
}
const flush = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const tests = [];
function test(name, fn) { tests.push([name, fn]); }

test('fresh check details, public IP and honest identity are visible', () => {
 const ui = create(fixture());
 assert.match(ui.part('healthSummary').textContent, /最近检测通过/);
 assert.match(ui.part('checks').textContent, /2\.4 ms/);
 assert.match(ui.part('publicExit').textContent, /203\.0\.113\.5/);
 assert.match(ui.part('publicExit').textContent, /与预期一致/);
 assert.match(ui.part('publicExit').textContent, /尚未验证出口身份/);
 assert.equal(ui.action('retry-recovery').parentNode.hidden, true);
});

test('DNS cards show separate configured upstream chains, routing and timestamps as text', () => {
 const d = fixture();
 d.dns_upstreams = { source: 'resolver configuration', observed_at: d.server_time,
  cn: { available: true, upstreams: ['udp://223.5.5.5:53', 'udp://119.29.29.29:53'], interface: 'eth1', mark: 0, mode: 'direct' },
  foreign: { available: true, upstreams: ['udp://127.0.0.1:5335'], downstream: ['https://dns.example/dns-query', '<script>untrusted</script>'], interface: 'wg_vpn', mark: 1, mode: 'local forwarder' } };
 const ui = create(d);
 assert.match(ui.part('dnsCn').textContent, /223\.5\.5\.5:53/);
 assert.match(ui.part('dnsCn').textContent, /119\.29\.29\.29:53/);
 assert.match(ui.part('dnsCn').textContent, /路由标记：0/);
 assert.doesNotMatch(ui.part('dnsCn').textContent, /127\.0\.0\.1/);
 assert.match(ui.part('dnsForeign').textContent, /本地转发器后续上游/);
 assert.match(ui.part('dnsForeign').textContent, /dns\.example\/dns-query/);
 assert.match(ui.part('dnsForeign').textContent, /wg_vpn/);
 assert.match(ui.part('dnsForeign').textContent, /配置读取时间/);
 assert.match(ui.root.textContent, /不代表某次请求实际命中的服务器/);
 assert.equal(all(ui.root, n => n.tag === 'script').length, 0);
});

test('missing or stale DNS configuration never appears current or invents upstreams', () => {
 const d = fixture();
 d.dns_upstreams = { observed_at: d.server_time - 600, cn: { available: false, reason: '配置缺失' }, foreign: { available: true, upstreams: ['udp://127.0.0.1:5335'] } };
 const ui = create(d);
 assert.match(ui.part('dnsCn').textContent, /暂无 DNS 上游数据/);
 assert.match(ui.part('dnsCn').textContent, /配置缺失/);
 assert.match(ui.part('dnsForeign').textContent, /当前未知/);
 assert.doesNotMatch(ui.part('dnsCn').textContent, /223\.5\.5\.5/);
 assert.match(create(fixture()).part('dnsForeign').textContent, /当前未知/);
});

function domesticFixture(d = fixture()) {
 d.public_exit = { selected: 'nobrand', time: d.server_time - 600,
  ipv4: { ip: '203.0.113.9', identity_status: 'verified', checked_at: d.server_time - 600, probe_scope: 'router_https' },
  domestic: { time: d.server_time,
   ipv4: { ip: '198.51.100.7', reachability: true, identity_status: 'wan_matched', checked_at: d.server_time, probe_scope: 'router_domestic_https', route_device: 'eth1', source: 'fixture HTTPS' },
   ipv6: { ip: '2001:db8::7', reachability: true, identity_status: 'unverified', checked_at: d.server_time, probe_scope: 'router_domestic_https', route_device: 'eth1', source: 'fixture HTTPS' } } };
 return d;
}

test('domestic and foreign egress retain separate IPs, provenance and exit-independent freshness', () => {
 const d = domesticFixture();
 const ui = create(d), domestic = ui.part('domesticPublicExit'), foreign = ui.part('publicExit');
 assert.match(domestic.textContent, /198\.51\.100\.7/);
 assert.match(domestic.textContent, /2001:db8::7/);
 assert.match(domestic.textContent, /eth1/);
 assert.match(domestic.textContent, /fixture HTTPS/);
 assert.match(domestic.textContent, /与 WAN 接口地址一致/);
 assert.match(domestic.textContent, /WAN 路径未确认（可能经过上级 NAT）/);
 assert.doesNotMatch(domestic.textContent, /当前未知/);
 assert.equal(all(domestic, n => n.className === 'pnw-text-ok').length, 1);
 assert.match(foreign.textContent, /203\.0\.113\.5/);
 assert.doesNotMatch(foreign.textContent, /198\.51\.100\.7/);
});

test('domestic delegated IPv6 match uses its own fresh provenance and never borrows foreign status', () => {
 const d = domesticFixture(), v6 = d.public_exit.domestic.ipv6;
 v6.identity_status = 'wan_prefix_matched';
 v6.identity_basis = 'wan_delegated_local_address';
 const view = create(d).part('domesticPublicExit');
 assert.match(view.textContent, /与本机 WAN 委派 IPv6 地址一致/);
 assert.equal(all(view, n => n.className === 'pnw-text-ok').length, 2);
 for (const change of ['stale', 'unknown-scope', 'unreachable']) {
  const altered = structuredClone(d), row = altered.public_exit.domestic.ipv6;
  if (change === 'stale') row.checked_at -= 600;
  if (change === 'unknown-scope') row.probe_scope = 'router_https';
  if (change === 'unreachable') row.reachability = false;
  assert.equal(all(create(altered).part('domesticPublicExit'), n => n.className === 'pnw-text-ok').length, 1, change);
 }
});

test('unavailable DNS chain retains configured endpoints explicitly as references', () => {
 const d = fixture();
 d.dns_upstreams = { source: 'resolver configuration', observed_at: d.server_time,
  foreign: { available: false, upstreams: ['udp://127.0.0.1:5335'], downstream: ['https://dns.example/dns-query'], reason: '本地转发器未运行' } };
 const view = create(d).part('dnsForeign');
 assert.match(view.textContent, /配置参考（未确认当前生效）/);
 assert.match(view.textContent, /127\.0\.0\.1:5335/);
 assert.match(view.textContent, /后续上游配置参考/);
 assert.match(view.textContent, /dns\.example\/dns-query/);
 assert.match(view.textContent, /本地转发器未运行/);
});

test('domestic egress fails closed on missing or stale metadata independently for each protocol', () => {
 for (const change of ['missing-time', 'stale-time', 'missing-checked-at', 'stale-row', 'missing-scope', 'foreign-scope']) {
  const d = domesticFixture(), domestic = d.public_exit.domestic;
  if (change === 'missing-time') delete domestic.time;
  if (change === 'stale-time') domestic.time -= 600;
  if (change === 'missing-checked-at') delete domestic.ipv4.checked_at;
  if (change === 'stale-row') domestic.ipv4.checked_at -= 600;
  if (change === 'missing-scope') delete domestic.ipv4.probe_scope;
  if (change === 'foreign-scope') domestic.ipv4.probe_scope = 'router_https';
  const ui = create(d), view = ui.part('domesticPublicExit');
  assert.equal(all(view, n => n.className === 'pnw-text-ok').length, 0, change);
  assert.match(view.textContent, /当前未知/, change);
  assert.equal(all(ui.part('publicExit'), n => n.className === 'pnw-text-ok').length, 1, change);
 }
});

test('newest domestic observation wins and failed IPv6 stays explicit', () => {
 const d = domesticFixture();
 d.health.public_exit.domestic = { time: d.server_time + 1,
  ipv4: { ip: '198.51.100.8', reachability: true, identity_status: 'unverified', checked_at: d.server_time + 1, probe_scope: 'router_domestic_https' },
  ipv6: { reachability: false, identity_status: 'unavailable', checked_at: d.server_time + 1, probe_scope: 'router_domestic_https', error: 'no domestic IPv6 route' } };
 const view = create(d).part('domesticPublicExit');
 assert.match(view.textContent, /198\.51\.100\.8/);
 assert.doesNotMatch(view.textContent, /198\.51\.100\.7/);
 assert.match(view.textContent, /探测失败/);
 assert.match(view.textContent, /no domestic IPv6 route/);
 assert.equal(all(view, n => n.className === 'pnw-text-bad').length, 1);
});

test('lost polling marks both public egress groups and configured DNS as historical', async () => {
 const d = domesticFixture();
 d.dns_upstreams = { observed_at: d.server_time, cn: { available: true, upstreams: ['udp://223.5.5.5:53'] } };
 const ui = create(d, () => Promise.reject(new Error('offline')));
 await ui.poll(5);
 assert.match(ui.part('domesticPublicExit').textContent, /当前未知/);
 assert.match(ui.part('publicExit').textContent, /当前未知/);
 assert.match(ui.part('dnsCn').textContent, /当前未知/);
 assert.equal(all(ui.root, n => n.className === 'pnw-text-ok').length, 0);
});

test('domestic and foreign cache cards use their own denominators and preserve missing samples', () => {
 const d = fixture({ telemetry: { cache: { available: true, source: 'resolver snapshot', window_seconds: 60,
  groups: { all: { queries: 30, cache_hits: 12 }, cn: { queries: 10, cache_hits: 8, fresh_hits: 7, stale_hits: 1 }, foreign: { queries: 20, cache_hits: 4, fresh_hits: 3, stale_hits: 1 } } } } });
 const ui = create(d);
 assert.equal(ui.part('cacheCnRate').textContent, '80.0%');
 assert.equal(ui.part('cacheForeignRate').textContent, '20.0%');
 assert.equal(ui.part('cacheRate').textContent, '40.0%');
 assert.match(ui.part('cacheCnNote').textContent, /缓存命中 8 \/ 查找 10/);
 assert.match(ui.part('cacheForeignNote').textContent, /新鲜 3，过期 1/);
 d.telemetry.cache.groups.cn = { queries: 0, cache_hits: 0 };
 delete d.telemetry.cache.groups.foreign;
 const missing = create(d);
 assert.equal(missing.part('cacheCnRate').textContent, '暂无数据');
 assert.equal(missing.part('cacheForeignRate').textContent, '暂无数据');
 d.telemetry.cache.available = false;
 d.telemetry.cache.reason = 'resolver restarted';
 const reset = create(d);
 assert.match(reset.part('cacheCnNote').textContent, /resolver restarted/);
 assert.equal(reset.part('cacheForeignRate').textContent, '暂无数据');
});

test('filter failures and unknown future checks cannot hide behind successful summary', () => {
 const d = fixture();
 d.health.checks.foreign_ipv4_only = false;
 d.health.checks.future_check = false;
 d.health.details.foreign_ipv4_only = { ok: false, error: 'AAAA filter failed', duration_ms: 1900 };
 d.health.checks.https_ipv6 = 'disabled';
 const ui = create(d);
 assert.match(ui.part('healthSummary').textContent, /失败项/);
 assert.match(ui.part('checks').textContent, /国外 AAAA \/ HTTPS 过滤/);
 assert.match(ui.part('checks').textContent, /AAAA filter failed/);
 assert.match(ui.part('checks').textContent, /1\.90 秒/);
 assert.match(ui.part('checks').textContent, /future_check/);
 assert.match(ui.part('checks').textContent, /按配置停用/);
});

test('new current-exit probe replaces older health IP and uses its own freshness/scope', () => {
 const d = fixture();
 d.health.finished = d.server_time - 600;
 d.health.public_exit.time = d.server_time - 600;
 d.health.public_exit.ipv4.checked_at = d.server_time - 600;
 d.public_exit = { selected: 'aws', time: d.server_time, ipv4: { ip: '203.0.113.9', identity_status: 'verified', checked_at: d.server_time, probe_scope: 'isolated_candidate' } };
 const ui = create(d), view = ui.part('publicExit');
 assert.match(view.textContent, /203\.0\.113\.9/);
 assert.doesNotMatch(view.textContent, /203\.0\.113\.5/);
 assert.match(view.textContent, /隔离候选出口探测（仅探测流量）/);
 assert.match(view.textContent, /不代表正常分流已恢复/);
 assert.equal(all(view, n => n.className === 'pnw-text-ok').length, 1);
 assert.match(ui.part('healthSummary').textContent, /过期/);
});

test('public IP freshness cannot borrow a fresh health check or missing identity metadata', () => {
 for (const change of ['stale', 'different-exit', 'missing-time', 'stale-row']) {
  const d = fixture();
  d.health.public_exit = {};
  d.public_exit = { selected: 'aws', time: d.server_time, ipv4: { ip: '203.0.113.9', identity_status: 'verified', checked_at: d.server_time, probe_scope: 'router_https' } };
  if (change === 'stale') d.public_exit.time -= 600;
  if (change === 'different-exit') d.public_exit.selected = 'nobrand';
  if (change === 'missing-time') delete d.public_exit.time;
  if (change === 'stale-row') d.public_exit.ipv4.checked_at -= 600;
  const ui = create(d), view = ui.part('publicExit');
  assert.match(ui.part('healthSummary').textContent, /最近检测通过/);
  assert.equal(all(view, n => n.className === 'pnw-text-ok').length, 0, change);
  assert.match(view.textContent, /当前未知/);
 }
});

test('current exit is preferred and newest own timestamp wins between probe sources', () => {
 const d = fixture();
 d.public_exit = { selected: 'nobrand', time: d.server_time + 1, ipv4: { ip: '203.0.113.9', identity_status: 'verified', checked_at: d.server_time } };
 assert.match(create(d).part('publicExit').textContent, /203\.0\.113\.5/);
 d.public_exit.selected = 'aws';
 assert.match(create(d).part('publicExit').textContent, /203\.0\.113\.9/);
 d.public_exit.time = d.server_time - 1;
 assert.match(create(d).part('publicExit').textContent, /203\.0\.113\.5/);
});

test('poll failure invalidates all green health and operation states; reconnect restores them', async () => {
 let fail = true;
 const ui = create(fixture(), () => fail ? Promise.reject(new Error('session expired')) : Promise.resolve(fixture()));
 await ui.poll(5);
 assert.match(ui.part('connection').textContent, /当前状态未知/);
 assert.match(ui.part('connection').textContent, /session expired/);
 assert.match(ui.part('task').textContent, /任务状态未知/);
 assert.equal(all(ui.root, n => n.className === 'pnw-text-ok').length, 0);
 assert(all(ui.root, n => n.attrs && n.attrs['data-pnw-action']).every(n => n.disabled));
 fail = false; await ui.poll(5);
 assert.match(ui.part('connection').textContent, /已连接/);
 assert.equal(ui.action('check').disabled, false);
});

test('independent freshness watchdog expires a hanging poll', async () => {
 let resolve;
 const ui = create(fixture(), () => new Promise(r => { resolve = r; }));
 const pending = ui.poll(5);
 ui.advance(16000); ui.poll(1);
 assert.match(ui.part('connection').textContent, /超过 15 秒/);
 assert.equal(ui.action('check').disabled, true);
 resolve(fixture()); await pending;
 assert.equal(ui.action('check').disabled, false);
});

test('initial error and missing nested data render safe unknown states', () => {
 const missing = create({ selected: 'aws', running: false });
 assert.match(missing.part('cacheRate').textContent, /暂无数据/);
 assert.match(missing.part('latency').textContent, /暂无数据/);
 assert.match(missing.part('checks').textContent, /当前未知/);
 const failed = create({ _load_error: 'login required' });
 assert.match(failed.part('connection').textContent, /login required/);
 assert.match(failed.part('mode').textContent, /尚未取得/);
 assert.equal(failed.action('check').disabled, true);
});

test('click locks every operation immediately and preserves server busy state', async () => {
 let finishStart;
 const ui = create(fixture(), args => args[0] === 'start' ? new Promise(resolve => { finishStart = resolve; }) : Promise.resolve(fixture({ running: true })));
 ui.action('check').click();
 assert(all(ui.root, n => n.attrs && n.attrs['data-pnw-action']).every(n => n.disabled));
 ui.action('rescue').click();
 assert.equal(ui.calls.length, 1);
 finishStart({ accepted: true }); await flush();
 assert.equal(ui.action('rescue').disabled, true);
 assert.match(ui.action('rescue').title, /执行/);
});

test('action rejection refreshes status and never leaves an unconditional enabled button', async () => {
 const ui = create(fixture(), args => args[0] === 'start' ? Promise.reject(new Error('lock held')) : Promise.reject(new Error('network lost')));
 ui.action('check').click(); await flush();
 assert.equal(ui.action('check').disabled, true);
 assert.equal(ui.notifications.length, 1);
 assert.match(ui.part('attention').textContent, /lock held/);
 assert.match(ui.part('connection').textContent, /network lost/);
});

test('backend blockers, TUN absence and missing rollback target have precise reasons', () => {
 const ui = create(fixture({ actions: { recover: { allowed: false, reason: 'route conflict fixture' } }, usss_available: false, previous_exit: null }));
 assert.equal(ui.action('recover').disabled, true);
 assert.equal(ui.action('recover').title, 'route conflict fixture');
 assert.match(ui.action('switch-usss').title, /TUN/);
 assert.match(ui.action('rollback').title, /没有可回滚/);
});

test('pending recovery permits only diagnostic/retry and exposes rollback failure', () => {
 const ui = create(fixture({ pending: true, emergency: true, recovery: { paused: true, failures: 3, last_error: 'restore conflict' }, last: { rollback: { attempted: true, state: 'failed', error: 'protected file changed' } } }));
 assert.equal(ui.action('switch-nobrand').disabled, true);
 assert.equal(ui.action('diagnose').disabled, false);
 assert.equal(ui.action('retry-recovery').disabled, false);
 assert.equal(ui.action('retry-recovery').parentNode.hidden, false);
 assert.match(ui.part('attention').textContent, /protected file changed/);
 assert.match(ui.part('attention').textContent, /暂停重试/);
 assert.match(ui.part('switchHelp').textContent, /应急状态下可直接切换备用出口/);
});

test('emergency alone does not block selecting an alternate exit', () => {
 const ui = create(fixture({ emergency: true, actions: { 'switch-nobrand': { allowed: true, reason: '' } } }));
 assert.equal(ui.action('switch-nobrand').disabled, false);
});

test('zero samples and unavailable sources never become zero latency or 100% success', () => {
 const ui = create(fixture({ telemetry: { cache: { available: true, groups: { all: { queries: 0, cache_hits: 0 } } }, dns: { available: true, requests: 0, completed: 0, latency_count: 0, successes: 0, failures: 0, recent_ms: 0, avg_ms: 0, p95_ms: 0 } } }));
 assert.equal(ui.part('cacheRate').textContent, '暂无数据');
 assert.equal(ui.part('successRate').textContent, '暂无数据');
 assert.equal(ui.part('latency').textContent, '暂无数据');
 assert.doesNotMatch(ui.part('latencyNote').textContent, /0\.0 ms/);
 const absent = create(fixture({ telemetry: { dns: { available: false, reason: 'resolver counters unsupported' } } }));
 assert.match(absent.part('successNote').textContent, /resolver counters unsupported/);
});

test('real metrics use explicit denominators and histogram bound', () => {
 const ui = create(fixture({ telemetry: { cache: { available: true, source: 'resolver snapshot', window_seconds: 60, groups: { all: { queries: 20, cache_hits: 15 }, cn: { queries: 10, cache_hits: 8, fresh_hits: 7, stale_hits: 1 } } }, dns: { available: true, requests: 12, completed: 10, latency_count: 10, successes: 9, failures: 1, success_rate_pct: 100, recent_ms: 4.2, avg_ms: 8, p95_ms: 50, p95_is_upper_bound: true, window_seconds: 60, source: 'resolver snapshot' } } }));
 assert.equal(ui.part('cacheRate').textContent, '75.0%');
 assert.equal(ui.part('successRate').textContent, '90.0%');
 assert.equal(ui.part('latency').textContent, '4.2 ms');
 assert.match(ui.part('successNote').textContent, /已完成请求 10/);
 assert.match(ui.part('successNote').textContent, /接收 12/);
 assert.match(ui.part('latencyNote').textContent, /P95 ≤ 50 ms/);
 assert.match(ui.part('cacheNote').textContent, /实际窗口 60 秒/);
});

test('query transmits separate argv/source and renders failures/inference as text', async () => {
 const response = { ok: true, input: '<script>x</script>', source: 'lan', kind: 'domain', time: 1792300000, classification: { group: 'foreign', complete: false, matches: [{ file: 'fixture.conf', rule: '/example.com/' }] }, dns: [{ qtype: 'AAAA', ok: false, error: 'timeout', duration_ms: 1000 }], answers: [{ family: 'IPv4', address: '203.0.113.2', expected_path: 'tunnel', reason: 'gfw set', route: { device: 'wg_vpn' } }], notes: ['device MAC override not inspected'], inference_only: true };
 const ui = create(fixture(), () => Promise.resolve(response));
 const input = all(ui.root, n => n.tag === 'input' && n.attrs['aria-label'] === '待查询的域名或 IP')[0], select = all(ui.root, n => n.tag === 'select' && n.attrs['aria-label'] === '查询流量来源')[0];
 const button = all(ui.root, n => n.tag === 'button' && n.textContent === '查询分流')[0];
 input.value = 'example.com'; select.value = 'lan'; button.click(); await flush();
 assert.deepEqual(ui.calls[0], ['query', 'example.com', 'lan']);
 assert.match(ui.part('queryResult').textContent, /规则推断不等于真实连接验证/);
 assert.match(ui.part('queryResult').textContent, /timeout/);
 assert.match(ui.part('queryResult').textContent, /wg_vpn/);
 assert.equal(all(ui.root, n => n.tag === 'script').length, 0);
});

test('query result remains explicitly a query-time snapshot after exit changes', async () => {
 const response = { ok: true, input: 'example.com', source: 'router', time: 1792300000, classification: { group: 'foreign' }, answers: [{ family: 'IPv4', address: '203.0.113.2', expected_path: 'tunnel', route: { device: 'wg_vpn' }, reason: 'fixture' }] };
 const ui = create(fixture(), args => Promise.resolve(args[0] === 'query' ? response : fixture({ selected: 'usss' })));
 all(ui.root, n => n.tag === 'input' && n.attrs['aria-label'] === '待查询的域名或 IP')[0].value = 'example.com';
 all(ui.root, n => n.tag === 'button' && n.textContent === '查询分流')[0].click();
 await flush();
 const before = ui.part('queryResult').textContent;
 await ui.poll(5);
 assert.match(ui.part('exit').textContent, /美国 SS/);
 assert.equal(ui.part('queryResult').textContent, before);
 assert.match(before, /查询时预计路径/);
 assert.match(before, /查询时隧道/);
 assert.match(before, /出口或配置变化后，结果不会自动刷新，请重新查询/);
 assert.doesNotMatch(before, /当前隧道/);
});

test('overflow P95 reports a lower bound instead of an invented percentile', () => {
 const ui = create(fixture({ telemetry: { dns: { available: true, completed: 1, latency_count: 1, successes: 0, failures: 1, recent_ms: 6000, avg_ms: 6000, p95_overflow: true, p95_lower_bound_ms: 5000 } } }));
 assert.match(ui.part('latencyNote').textContent, /P95 > 5\.00 秒/);
});

test('late older status cannot replace a newer status response', async () => {
 const resolves = [];
 const ui = create(fixture(), () => new Promise(resolve => resolves.push(resolve)));
 const first = ui.poll(5), second = ui.poll(5);
 resolves[1](fixture({ selected: 'nobrand' })); await second;
 resolves[0](fixture({ selected: 'aws' })); await first;
 assert.match(ui.part('exit').textContent, /nobrand/);
});


function statsFixture() {
 const h={samples:10,avg_ms:3,max_ms:8,p95_ms:8,p99_ms:8};
 const m={completed:10,success:9,failures:1,cache:{fresh:6,stale:2},rt:h,queue:h,service:h,errors:{upstream_timeout:1},success_rate_pct:90,cache_hit_rate_pct:80};
 return {available:true,source:'/tmp/diversion-dns-stats.json',started_unix:1792299900,sampled_at:1792300000,sample_age_seconds:0,uptime_seconds:100,inflight:2,total:m,
  intervals:[{start:1792299900,finish:1792299960,seconds:60,qps:10/60,metrics:m}],breakdown:[{group:'foreign',qtype:'AAAA',transport:'tcp',metrics:m}],events:{tcp_read_timeout:2},
  top50:{exact:false,domains:[{domain:'chatgpt.example',count_estimate:10,count_lower_bound:8,error_bound:2},{domain:'<script>bad</script>',count_estimate:4,count_lower_bound:2,error_bound:2}]}};
}
test('stats dashboard preserves scopes, percentile bounds and top estimate errors',()=>{
 const ui=create(fixture({telemetry:{stats:statsFixture()}}));
 assert.match(ui.part('statsTotals').textContent,/90.0%/);assert.match(ui.part('statsRT').textContent,/P99 ≤ 8.0 ms/);
 assert.match(ui.part('statsErrors').textContent,/上游超时1/);assert.match(ui.part('statsEvents').textContent,/TCP 读超时2/);
 assert.match(ui.part('statsGroups').textContent,/国外 · AAAA · TCP/);assert.match(ui.part('topInfo').textContent,/近似排行/);
 assert.match(ui.part('topDomains').textContent,/可信下界/);assert.match(ui.part('topDomains').textContent,/<script>bad<\/script>/);
 assert.equal(all(ui.root,n=>n.tag==='script').length,0);assert.equal(ui.part('trendChart').children.length,1);
 assert.equal(ui.part('cacheRate').textContent,'暂无数据'); // never substitute completed denominator into legacy card
});
test('top filter keeps rank and never executes a network operation',()=>{
 const ui=create(fixture({telemetry:{stats:statsFixture()}}));
 const search=all(ui.root,n=>n.attrs&&n.attrs['aria-label']==='筛选 Top 50 域名')[0];
 search.events.input({target:{value:' CHATGPT '}});assert.match(ui.part('topDomains').textContent,/1. chatgpt.example/);
 assert.doesNotMatch(ui.part('topDomains').textContent,/bad/);assert.equal(ui.calls.length,0);
});
test('metric selector switches chart without network requests',()=>{
 const ui=create(fixture({telemetry:{stats:statsFixture()}}));
 const select=all(ui.root,n=>n.attrs&&n.attrs['aria-label']==='趋势指标')[0];
 select.events.change({target:{value:'success'}});assert.match(ui.part('trendInfo').textContent,/纵轴 0–100.00/);
 assert.equal(ui.calls.length,0);
});
test('empty intervals and unavailable stats never fabricate history or errors',()=>{
 const d=statsFixture();d.intervals=[];const ui=create(fixture({telemetry:{stats:d}}));
 assert.match(ui.part('trendInfo').textContent,/等待第一个完整统计区间/);
 const missing=create(fixture());assert.match(missing.part('topInfo').textContent,/不能.*推算/);
 assert.doesNotMatch(missing.part('statsErrors').textContent,/没有此类记录/);
 assert.equal(all(missing.root,n=>n.tag==='button'&&n.textContent==='导出当前统计（含域名）')[0].disabled,true);
});
test('no samples and histogram overflow remain distinct in chart and table',()=>{
 const d=statsFixture();d.intervals[0].metrics.rt={samples:10,p99_overflow:true,p99_lower_ms:32000};
 const ui=create(fixture({telemetry:{stats:d}}));
 assert.equal(all(ui.part('trendChart'),n=>n.className==='pnw-bar pnw-bar-overflow').length,1);
 assert.match(ui.part('trendTable').textContent,/> 32.00 秒/);
 d.intervals[0].metrics.rt={samples:0};const empty=create(fixture({telemetry:{stats:d}}));
 assert.equal(all(empty.part('trendChart'),n=>n.className==='pnw-bar pnw-bar-missing').length,1);
 assert.doesNotMatch(empty.part('trendTable').textContent,/0.0 ms/);
});
test('disconnect marks dashboard history and disables control actions',async()=>{
 const ui=create(fixture({telemetry:{stats:statsFixture()}}),()=>Promise.reject(new Error('lost')));
 try{await ui.poll(5);}catch(_){}
 assert.match(ui.part('statsInfo').textContent,/历史快照，当前未知/);assert.match(ui.part('topInfo').textContent,/历史快照，当前未知/);
 assert.equal(ui.action('switch-aws').disabled,true);
});
test('new process snapshot replaces rather than appends history',async()=>{
 const d=statsFixture(),next=statsFixture();next.intervals=[];next.top50.domains=[];next.started_unix=1792300000;
 const ui=create(fixture({telemetry:{stats:d}}),()=>Promise.resolve(fixture({telemetry:{stats:next}})));
 await ui.poll(5);assert.equal(ui.part('trendChart').children.length,0);assert.doesNotMatch(ui.part('topDomains').textContent,/chatgpt/);
});

test('read-only stats page has no route actions or unrelated fake statuses',()=>{const ui=create({stats_only:true,server_time:1792300000,version:'test',telemetry:{stats:statsFixture()}},null,true);assert.equal(all(ui.root,n=>n.attrs&&n.attrs['data-pnw-action']).length,0);assert.doesNotMatch(ui.root.textContent,/当前出口|分流已启用|最近检测通过|qBittorrent/);assert.match(ui.root.textContent,/DNS 统计/);assert.match(ui.part('statsTotals').textContent,/90.0%/);});
test('device page uses actual mode and fails closed for missing actions',()=>{const ui=create(fixture({selected:'upstream',mode_text:'独立 DNS 测试，未部署分流',exit_names:{upstream:'上级网关'},actions:{check:{allowed:true},diagnose:{allowed:true}},control_note:'保留现有网络'}),null,false,true);assert.match(ui.part('mode').textContent,/未部署分流/);assert.equal(ui.part('exit').textContent,'上级网关');assert.equal(ui.action('switch-aws').disabled,true);assert.equal(ui.action('rescue').disabled,true);assert.equal(ui.action('check').disabled,false);assert.match(ui.part('switchHelp').textContent,/保留现有网络/);});

test('device layout has three sections and scopes switch without querying or losing stats',async()=>{
 const d=fixture({actions:{check:{allowed:true},diagnose:{allowed:true}},telemetry:{stats:statsFixture()}});
 const ui=create(d,()=>Promise.resolve(d),false,true);
 assert.deepEqual(all(ui.root,n=>n.attrs&&n.attrs.class==='pnw-section').map(n=>n.attrs.id),['pnw-overview','pnw-dns','pnw-diagnostics']);
 const select=all(ui.root,n=>n.attrs&&n.attrs['aria-label']==='统计时间范围')[0];
 const recent=ui.part('telemetryInfo').parentNode,lifetime=ui.part('statsInfo').parentNode;
 assert.equal(recent.hidden,false);assert.equal(lifetime.hidden,true);
 select.events.change({target:{value:'lifetime'}});
 assert.equal(recent.hidden,true);assert.equal(lifetime.hidden,false);assert.equal(ui.calls.length,0);
 await ui.poll(30);assert.equal(lifetime.hidden,false);assert.match(ui.part('statsTotals').textContent,/90.0%/);
 assert.match(ui.root.textContent,/不能直接比较/);
 assert.equal(all(ui.root,n=>n.attrs&&n.attrs['data-pnw-part']==='statsTotals').length,1);
 assert.equal(all(ui.root,n=>n.attrs&&n.attrs['data-pnw-part']==='groupMetrics').length,0);
});
test('device capability grouping keeps actions blocked and failure alerts outside collapsed controls',async()=>{
 let d=fixture({actions:{check:{allowed:true},diagnose:{allowed:true}},pending:true,recovery:{paused:true,last_error:'fixture failure'}});
 const ui=create(d,()=>Promise.resolve(d),false,true);
 assert.equal(ui.part('availableActions').children.length,2);assert.equal(ui.part('unavailableActions').children.length,8);
 assert.equal(ui.action('switch-aws').disabled,true);ui.action('switch-aws').click();assert.equal(ui.calls.length,0);
 assert.match(ui.part('attention').textContent,/fixture failure/);
 assert.equal(ui.part('attention').parentNode.attrs.id,'pnw-overview');
 assert.equal(ui.part('unavailableActions').parentNode.attrs.open,undefined);
 assert.match(ui.part('last').textContent,/耗时 280 ms/);
 d=fixture({actions:{diagnose:{allowed:true}}});await ui.poll(30);
 assert.equal(ui.part('availableActions').children.length,1);assert.equal(ui.action('check').disabled,true);
 assert.equal(ui.action('check').parentNode.parentNode,ui.part('unavailableActions'));
});
test('device shares identical windows but retains differing timestamps and unavailable data',()=>{
 const w={source:'same',window_start:1792299700,window_end:1792300000,window_seconds:300,available:true};
 const d=fixture({telemetry:{cache:{...w,groups:{cn:{cache_hits:2,queries:3},foreign:{cache_hits:1,queries:4}}},dns:{...w,completed:4,successes:3,failures:1}}});
 let ui=create(d,null,false,true);
 assert.equal((ui.part('telemetryInfo').textContent.match(/来源：same/g)||[]).length,1);
 assert.doesNotMatch(ui.part('cacheCnNote').textContent,/来源/);assert.match(ui.part('cacheCnRate').textContent,/66.7%/);assert.match(ui.part('successRate').textContent,/75.0%/);
 d.telemetry.dns.window_end--;d.telemetry.dns.available=false;d.telemetry.dns.reason='expired';
 ui=create(d,null,false,true);assert.equal((ui.part('telemetryInfo').textContent.match(/来源：same/g)||[]).length,2);
 assert.match(ui.part('successRate').textContent,/暂无数据/);assert.match(ui.part('successNote').textContent,/expired/);
});

(async () => {
 let failed = 0;
 for (const [name, fn] of tests) {
  try { await fn(); process.stdout.write('PASS ' + name + '\n'); }
  catch (error) { failed++; process.stderr.write('FAIL ' + name + '\n' + error.stack + '\n'); }
 }
 process.stdout.write(tests.length + ' tests, ' + failed + ' failures\n');
 process.exitCode = failed ? 1 : 0;
})();
