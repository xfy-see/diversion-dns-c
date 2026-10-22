'use strict';
'require view';
'require fs';
'require poll';
'require ui';

var PNW_VIEW_VERSION = '2026.10.19.1-compact';

return view.extend({
 statsOnly: false,
 deviceMode: false,
 handleSave: null, handleSaveApply: null, handleReset: null,
 call: function(args) {
  if (this.statsOnly && args[0] !== 'status') return Promise.reject(new Error('只读统计页面不支持控制操作'));
  var statusPath = this.statsOnly ? '/usr/libexec/pnw-stats-status' : this.deviceMode ? '/usr/libexec/diversion-dns-ui-status' : '/usr/libexec/pnw-status';
  return fs.exec(args[0] === 'status' ? statusPath : this.deviceMode ? '/usr/libexec/diversion-dns-ui-control' : '/usr/libexec/pnw-control', args[0] === 'status' ? [] : args).then(function(r) {
   if (r.code !== 0) throw new Error(r.stderr || r.stdout || '操作失败');
   var d = JSON.parse(r.stdout);
   if (!d || typeof d !== 'object' || Array.isArray(d)) throw new Error('服务返回了无效数据');
   return d;
  });
 },
 load: function() { return this.call(['status']).catch(function(e) { return { _load_error: e.message }; }); },
 render: function(data) {
  if (this.deviceMode && ui.menu && ui.menu.flushCache) ui.menu.flushCache();
  var self = this, current = {}, connected = false, receivedAt = 0, lastSuccess = 0;
  var requestSequence = 0, appliedSequence = 0, submitting = false, querying = false;
  var transportError = '', actionError = '', queryResult = null, queryError = '';
  var buttons = [], parts = {}, trendMetric = 'p99', domainFilter = '';
  var errorNames = {queue_full:'队列满',queue_timeout:'排队超时',upstream_failure:'上游失败',upstream_timeout:'上游超时',nft_failure:'地址集合写入失败',execution_deadline:'处理期限',invalid_response:'无效响应',memory:'内存分配',send_failure:'发送失败',client_disconnected:'客户端断开',shutdown:'服务停止'};
  var eventNames = {invalid_udp:'非法 UDP',invalid_tcp:'非法 TCP',tcp_read_timeout:'TCP 读超时',tcp_write_timeout:'TCP 写超时',tcp_limit_rejected:'TCP 限流',tcp_evicted:'TCP 连接淘汰',allocation_failure:'内存分配失败'};
  var exitNames = { aws: 'AWS 新加坡（IPv6 入口）', nobrand: 'nobrand（IPv4 入口）', usss: '美国 SS（HTTP 混淆）', usvless: '美国 VLESS（Reality / Vision）' };
  var checkNames = { domestic_dns: '国内 DNS', foreign_dns: '国外 DNS', https_ipv4: 'HTTPS IPv4', https_ipv6: 'HTTPS IPv6', foreign_ipv4_only: '国外 AAAA / HTTPS 过滤' };

  function object(v) { return v && typeof v === 'object' && !Array.isArray(v) ? v : {}; }
  function number(v) { return typeof v === 'number' && isFinite(v); }
  function value(v) { return v === undefined || v === null || v === '' ? '暂无数据' : String(v); }
  function time(v) { return number(v) && v > 0 ? new Date(v * 1000).toLocaleString() : '暂无时间'; }
  function duration(v) { return number(v) && v >= 0 ? (v < 1000 ? v.toFixed(v < 10 ? 1 : 0) + ' ms' : (v / 1000).toFixed(2) + ' 秒') : '暂无数据'; }
  function count(v) { return number(v) && v >= 0 ? v.toLocaleString() : '暂无数据'; }
  function rate(n, total) { return number(n) && number(total) && total > 0 && n >= 0 && n <= total ? (n / total * 100).toFixed(1) + '%' : '暂无数据'; }
  function name(id) { return object(current.exit_names)[id] || exitNames[id] || value(id); }
  function replace(node, children) {
   while (node.firstChild) node.removeChild(node.firstChild);
   children.forEach(function(child) { node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child); });
  }
  function part(id, tag, attrs) { attrs = attrs || {}; attrs['data-pnw-part'] = id; parts[id] = E(tag || 'div', attrs); return parts[id]; }
  function message(text, kind) { return E('p', { 'class': 'pnw-message pnw-' + (kind || 'neutral') }, text); }
  function card(title, id) { return E('section', { 'class': 'pnw-card' }, [E('h3', {}, title), part(id)]); }
  function metric(title, id, noteId) { return E('div', {}, [E('h3', {}, title), part(id, 'div', { 'class': 'pnw-value' }), part(noteId, 'p', { 'class': 'pnw-muted' })]); }
  function row(cells, header) { return E('tr', {}, cells.map(function(c) { return E(header ? 'th' : 'td', {}, c); })); }
  function table(headers, rows) { return E('div', { 'class': 'pnw-table-scroll' }, [E('table', { 'class': 'table pnw-table' }, [E('thead', {}, row(headers, true)), E('tbody', {}, rows)])]); }
  function serverNow() { return number(current.server_time) ? current.server_time + Math.max(0, Date.now() - receivedAt) / 1000 : Date.now() / 1000; }
  function isFresh() {
   var h = object(current.health), age = serverNow() - h.finished;
   return connected && number(h.finished) && age >= -5 && age < 300 && h.selected === current.selected;
  }
  function unavailableReason(action) {
   if (!connected) return '当前状态未知，请等待连接恢复';
   if (submitting) return '操作正在提交，请稍候';
   if (current.running === true) return '后台任务正在执行';
   if (current.running !== false) return '任务状态缺失，暂不可操作';
   var entry = object(object(current.actions)[action]);
   if (self.deviceMode && entry.allowed !== true) return entry.reason || '本设备未部署该受管能力';
   if (entry.allowed === false) return entry.reason || '当前状态不允许此操作';
   if (current.pending && action !== 'diagnose' && action !== 'retry-recovery') return '存在待回退事务，请先查看回退结果';
   if (action === 'switch-usss' && current.usss_available === false) return '美国 SS 的 TUN 接口未运行';
   if (action === 'switch-usvless' && current.vless_available === false) return '美国 VLESS 的 TUN 接口未运行';
   if (action === 'rollback' && current.previous_exit === null) return '没有可回滚的上次出口';
   return '';
  }
  function renderActions() {
   buttons.forEach(function(item) {
    var reason = unavailableReason(item.action);
    item.node.disabled = !!reason; item.node.title = reason || '执行 ' + item.label; item.reason.textContent = reason;
    if (self.deviceMode) {
     var enabled = object(object(current.actions)[item.action]).allowed === true;
     var target = enabled ? parts.availableActions : parts.unavailableActions;
     var wrapper = item.node.parentNode;
     if (wrapper.parentNode !== target) { wrapper.parentNode.removeChild(wrapper); target.appendChild(wrapper); }
     item.reason.hidden = !enabled;
     wrapper.hidden = false;
    } else if (item.action === 'retry-recovery') item.node.parentNode.hidden = !(current.pending || object(current.recovery).paused);
   });
   if (self.deviceMode) parts.unavailableActions.parentNode.hidden = !parts.unavailableActions.children.length;
   queryButton.disabled = !connected || querying || submitting || current.running !== false;
   queryButton.title = !connected ? '当前状态未知，请等待连接恢复' : querying ? '查询进行中' : submitting || current.running ? '后台操作正在执行' : '';
   refreshButton.disabled = submitting;
  }
  function renderConnection() {
   parts.connection.className = 'pnw-message pnw-' + (connected ? 'ok' : 'bad');
   parts.connection.textContent = connected ? '已连接 · 页面最后刷新：' + new Date(lastSuccess).toLocaleString() + ' · 每 ' + ((self.statsOnly || self.deviceMode) ? '30' : '5') + ' 秒刷新' : '连接中断或状态已过期 · 当前状态未知。' + (lastSuccess ? ' 最后成功刷新：' + new Date(lastSuccess).toLocaleString() + '。' : ' 尚未取得状态。') + (transportError ? ' ' + transportError : '');
   parts.version.textContent = '页面版本 ' + PNW_VIEW_VERSION + ' · 服务版本 ' + value(current.version);
  }
  function renderOverview() {
   var h = object(current.health), last = object(current.last), failures = object(current.endpoint_health).dns_failures, containment = object(current.containment);
   var known = connected ? '' : '上次记录：';
   parts.exit.textContent = known + name(current.selected) + (current.configured_selected && current.configured_selected !== current.selected ? '（配置：' + name(current.configured_selected) + '）' : '');
   var mode = current.emergency ? containment.known && containment.active ? '国内应急；海外标记流量已阻断' : '国内应急；海外阻断规则未确认生效' : current.dns_degraded ? 'DNS 已降级' : '分流已启用（不代表出口可用）';
   if (self.deviceMode) mode = current.mode_text || '设备策略状态未知';
   parts.mode.textContent = connected ? mode : current.selected ? '当前模式未知；上次记录：' + mode : '当前模式未知，尚未取得配置状态';
   parts.task.textContent = connected && current.running === false ? '任务空闲' : connected && current.running === true ? '后台任务执行中' : '任务状态未知';
   var failed = h.ok === false || Object.keys(object(h.checks)).some(function(k) { return h.checks[k] === false; });
   var verdict = !connected ? '当前可用性未知' : !isFresh() ? '未测、已过期或出口已变化' : failed ? '最近检测存在失败项' : h.ok === true ? '最近检测通过' : '检测结果缺失';
   parts.healthSummary.className = 'pnw-message pnw-' + (!isFresh() ? 'neutral' : !failed && h.ok === true ? 'ok' : 'bad');
   parts.healthSummary.textContent = verdict + (h.finished ? ' · ' + time(h.finished) : '');
   parts.system.textContent = known + '系统负载 ' + value(current.load) + ' · 可用内存 ' + value(current.memory) + ' KiB';
   parts.last.textContent = (last.action || '暂无操作') + (last.state ? ' / ' + ({ running: '执行中', success: '成功', failed: '失败' }[last.state] || last.state) : '') + (last.time ? ' · ' + time(last.time) : '') + (last.message ? '\n' + last.message : '');
   if (self.deviceMode && number(last.duration_ms)) parts.last.textContent += ' · 耗时 ' + duration(last.duration_ms);
   parts.operationTime.textContent = duration(last.duration_ms);
   parts.operationTimeNote.textContent = last.action ? '最近操作 ' + last.action + '；包含失败操作。' : '尚未记录操作耗时。';
   parts.checkTime.textContent = duration(h.duration_ms);
   parts.checkTimeNote.textContent = h.finished ? '最近完整检测 · ' + time(h.finished) + '；' + (isFresh() ? '对应当前出口' : '历史记录，当前可用性需重新检测') : '点击“检测出口可用性”生成检测样本。';
   if (self.deviceMode) parts.checkTimeNote.textContent += ' · 耗时 ' + duration(h.duration_ms);
   parts.endpoint.textContent = Array.isArray(failures) ? '入口域名解析异常：' + (failures.join('、') || '无（最近记录）') : '入口域名解析：暂无数据';
   var alerts = [], rollback = object(last.rollback), recovery = object(current.recovery);
   if (actionError) alerts.push(message('操作请求失败：' + actionError, 'bad'));
   if (current.pending) alerts.push(message('存在待回退事务：普通操作已停用，请查看回退原因；可采集诊断或重试未完成回退。', 'bad'));
   if (rollback.attempted === true || rollback.state === 'success' || rollback.state === 'failed') {
    alerts.push(message('最近操作自动回退：' + (rollback.state === 'success' ? '成功' : rollback.state === 'failed' ? '失败' : '结果未知') + (rollback.error ? '；' + rollback.error : ''), rollback.state === 'success' ? 'neutral' : 'bad'));
   } else if (last.rollback_ok === false) alerts.push(message('最近操作自动回退失败；服务未提供详细原因。', 'bad'));
   else if (rollback.state === 'not_needed' || rollback.attempted === false) alerts.push(message('最近操作自动回退：无需回退。'));
   if (containment.known === false) alerts.push(message('无法确认应急阻断规则：' + (containment.error || '状态读取失败'), 'bad'));
   if (containment.known === true && containment.marker !== containment.active) alerts.push(message('应急持久标记与实际阻断规则不一致，请先查看诊断或执行恢复。', 'bad'));
   if (recovery.last_error || recovery.paused || recovery.failures > 0) alerts.push(message('后台恢复：' + (recovery.paused ? '已达到失败限制，暂停重试' : '最近失败 ' + count(recovery.failures) + ' 次') + (recovery.last_attempt ? ' · ' + time(recovery.last_attempt) : '') + (recovery.last_error ? '\n' + recovery.last_error : ''), 'bad'));
   replace(parts.attention, alerts);
   parts.switchHelp.textContent = self.deviceMode ? (current.control_note || '仅启用本设备已验证的能力。') : current.emergency ? '应急状态下可直接切换备用出口。验证期间保留隔离，验证通过后才恢复正常分流；失败会尝试回退并保留应急保护。' : '切换会同步出口路由、国外 DNS 和防泄漏规则；验证失败会尝试自动回退。';
   parts.rollbackTarget.textContent = current.previous_exit ? '回滚目标：' + name(current.previous_exit) : '回滚目标：暂无记录';
  }
  function renderDNSUpstreams() {
   var dns = object(current.dns_upstreams);
   ['cn', 'foreign'].forEach(function(id) {
    var group = object(dns[id]), endpoints = Array.isArray(group.upstreams) ? group.upstreams.filter(function(v) { return typeof v === 'string' && v; }) : [];
    var downstream = Array.isArray(group.downstream) ? group.downstream.filter(function(v) { return typeof v === 'string' && v; }) : [];
    var observedAge = serverNow() - dns.observed_at;
    var fresh = connected && number(dns.observed_at) && observedAge >= -5 && observedAge < 300;
    var nodes = [E('p', { 'class': 'pnw-preserve' }, endpoints.length ? (group.available === true ? '' : '配置参考（未确认当前生效）：\n') + endpoints.join('\n') : '暂无 DNS 上游数据')];
    if (group.available !== true) nodes.push(message(group.reason || '无法确认当前 DNS 配置。', 'bad'));
    else if (group.reason) nodes.push(E('p', { 'class': 'pnw-muted' }, group.reason));
    if (downstream.length) nodes.push(E('p', { 'class': 'pnw-preserve' }, (group.available === true ? '本地转发器后续上游：\n' : '本地转发器后续上游配置参考（未确认当前生效）：\n') + downstream.join('\n')));
    nodes.push(E('p', { 'class': 'pnw-muted' }, '配置模式：' + value(group.mode) + ' · 绑定接口：' + value(group.interface) + ' · 路由标记：' + value(group.mark)));
    nodes.push(E('p', { 'class': 'pnw-muted' }, (fresh ? '配置读取时间：' : '历史记录或时间信息不完整（当前未知）：') + time(dns.observed_at) + ' · 来源：' + value(dns.source)));
    replace(parts[id === 'cn' ? 'dnsCn' : 'dnsForeign'], nodes);
   });
  }
  function renderDomesticExit() {
   var candidates = [object(object(current.public_exit).domestic), object(object(object(current.health).public_exit).domestic)], ips = {};
   candidates.forEach(function(candidate) {
    if (!candidate.ipv4 && !candidate.ipv6) return;
    if ((!ips.ipv4 && !ips.ipv6) || (number(candidate.time) ? candidate.time : 0) > (number(ips.time) ? ips.time : 0)) ips = candidate;
   });
   var exitAge = serverNow() - ips.time;
   var exitFresh = connected && number(ips.time) && exitAge >= -5 && exitAge < 300;
   replace(parts.domesticPublicExit, [E('p', { 'class': 'pnw-muted' }, '国内目标 HTTPS 探测 · ' + time(ips.time) + '。WAN 地址匹配结果单独标注；仅反映本机探测。'), table(['协议', '检测到的公网 IP', '检测结果 / 身份验证', '路径 / 来源', '检测时间'], ['ipv4', 'ipv6'].map(function(af) {
    var p = object(ips[af]), probeAge = serverNow() - p.checked_at;
    var scoped = p.probe_scope === 'router_domestic_https';
    var probeFresh = exitFresh && number(p.checked_at) && probeAge >= -5 && probeAge < 300 && scoped;
    var identity = { wan_matched: '与 WAN 接口地址一致', wan_prefix_matched: '与本机 WAN 委派 IPv6 地址一致', unverified: '公网回显已取得，WAN 路径未确认（可能经过上级 NAT）', unavailable: '未取得公网 IP', disabled: '按配置停用' }[p.identity_status] || '尚未验证 WAN 路径';
    if (p.reachability === true) identity = '探测成功；' + identity;
    else if (p.reachability === false) identity = '探测失败；' + identity;
    if (p.error) identity += '；' + p.error;
    if (p.expected) identity = '预期 ' + (Array.isArray(p.expected) ? p.expected.join(' / ') : p.expected) + '；' + identity;
    if (!probeFresh) identity = '历史记录或信息不完整（当前未知）：' + identity;
    var provenance = (scoped ? '国内目标 HTTPS 探测' : '未确认探测路径') + (p.route_device ? ' · ' + p.route_device : '') + (p.source ? ' · 来源 ' + p.source : '');
    return row([af.toUpperCase(), p.ip || '暂无数据', E('span', { 'class': probeFresh && p.reachability === false ? 'pnw-text-bad' : probeFresh && p.reachability === true && (p.identity_status === 'wan_matched' || p.identity_status === 'wan_prefix_matched') && p.ip ? 'pnw-text-ok' : 'pnw-muted' }, identity), provenance, time(p.checked_at)]);
   }))]);
  }
  function renderHealth() {
   var h = object(current.health), checks = object(h.checks), details = object(h.details), fresh = isFresh();
   var keys = ['domestic_dns', 'foreign_dns', 'https_ipv4', 'https_ipv6'];
   Object.keys(checks).concat(Object.keys(details)).forEach(function(k) { if (keys.indexOf(k) < 0) keys.push(k); });
   var rows = keys.map(function(k) {
    var detail = object(details[k]), result = checks[k];
    if (result === undefined) result = detail.ok;
    var label = result === true ? '通过' : result === false ? '失败' : result === 'disabled' ? '按配置停用' : '未测';
    if (!fresh) label = result === undefined ? '当前未知 / 未测' : '历史记录：' + label + '（当前未知）';
    return row([checkNames[k] || k, E('span', { 'class': fresh && result === true ? 'pnw-text-ok' : fresh && result === false ? 'pnw-text-bad' : 'pnw-muted' }, label), duration(detail.duration_ms), detail.error || detail.reason || '—']);
   });
   replace(parts.checks, [table(['检查项', '结果', '耗时', '详情'], rows)]);
   // A switch/recovery probe can be newer than the last full health check.
   // Public-exit records carry their own exit/time and never inherit health
   // freshness; prefer the newest record for the currently selected exit.
   var candidates = [object(current.public_exit), object(h.public_exit)], ips = {};
   candidates.forEach(function(candidate) {
    if (!candidate.ipv4 && !candidate.ipv6) return;
    var match = candidate.selected === current.selected, chosenMatch = ips.selected === current.selected;
    if ((!ips.ipv4 && !ips.ipv6) || (match && !chosenMatch) || (match === chosenMatch && (number(candidate.time) ? candidate.time : 0) > (number(ips.time) ? ips.time : 0))) ips = candidate;
   });
   var exitAge = serverNow() - ips.time;
   var exitFresh = connected && ips.selected === current.selected && number(ips.time) && exitAge >= -5 && exitAge < 300;
   replace(parts.publicExit, [E('p', { 'class': 'pnw-muted' }, '探测时出口：' + name(ips.selected) + ' · ' + time(ips.time) + '。隔离候选探测仅验证该探测路径，不代表正常分流已恢复。'), table(['协议', '检测到的公网 IP', '预期 IP / 身份验证', '探测范围', '检测时间'], ['ipv4', 'ipv6'].map(function(af) {
    var p = object(ips[af]);
    var probeAge = serverNow() - p.checked_at;
    var probeFresh = exitFresh && number(p.checked_at) && probeAge >= -5 && probeAge < 300;
    var identity = { verified: '与预期一致', unconfigured: '未配置预期 IP，尚未验证出口身份', mismatch: '与预期不符', unavailable: '未取得公网 IP', disabled: '按配置停用' }[p.identity_status] || '尚未验证出口身份';
    if (p.error) identity += '；' + p.error;
    if (p.expected) identity = '预期 ' + (Array.isArray(p.expected) ? p.expected.join(' / ') : p.expected) + '；' + identity;
    if (!probeFresh) identity = '历史记录或信息不完整（当前未知）：' + identity;
    var scope = { router_https: '路由器 HTTPS 探测', isolated_candidate: '隔离候选出口探测（仅探测流量）', isolated_namespace: '独立命名空间测试流量', router_policy: '本机策略路由探测' }[p.probe_scope] || (p.probe_scope ? '其他探测范围：' + p.probe_scope : '未标明探测范围');
    return row([af.toUpperCase(), p.ip || '暂无数据', E('span', { 'class': probeFresh && p.identity_status === 'mismatch' ? 'pnw-text-bad' : probeFresh && p.identity_status === 'verified' ? 'pnw-text-ok' : 'pnw-muted' }, identity), scope, time(p.checked_at)]);
   }))]);
   var peers = object(h.peers);
   parts.peers.textContent = ['aws', 'nobrand'].map(function(id) { var p = object(peers[id]); return name(id) + '：' + (number(p.handshake_age_seconds) ? p.handshake_age_seconds + ' 秒前握手（检测时）' : '未取得握手'); }).join('；');
   if (self.deviceMode) parts.peers.textContent = (Array.isArray(current.peers) && current.peers.length) ? current.peers.map(function(p){return p.id + '：' + (number(p.handshake_age) ? p.handshake_age + ' 秒前握手（状态读取时）' : '未取得握手');}).join('；') : '本机未部署活动 WireGuard 隧道';
  }
  function metricWindow(t) {
   return '来源：' + (t.source || '未提供') + ' · 采样：' + time(t.window_end || t.sampled_at) + (number(t.window_seconds) ? ' · 实际窗口 ' + Number(t.window_seconds.toFixed(1)) + ' 秒' : ' · 窗口尚未形成') + (t.window_start ? '（' + time(t.window_start) + ' 至 ' + time(t.window_end) + '）' : '') + (number(t.sample_age_seconds) ? ' · 样本距今 ' + Number(t.sample_age_seconds.toFixed(1)) + ' 秒' : '');
  }
  function renderTelemetry() {
   var t = object(current.telemetry), cache = object(t.cache), dns = object(t.dns), groups = object(cache.groups), all = object(groups.all);
   var cacheOK = cache.available === true, dnsOK = dns.available === true, suffix = connected ? '' : '（历史记录）';
   parts.telemetryInfo.textContent = '成功率与耗时统计解析器实际接受的完整合法 DNS 请求；缓存命中率单独按缓存查找计数。' + (connected ? '' : '页面已失联，以下仅为历史快照。');
   ['cn', 'foreign'].forEach(function(id) {
    var group = cacheOK ? object(groups[id]) : {}, partId = id === 'cn' ? 'cacheCn' : 'cacheForeign';
    parts[partId + 'Rate'].textContent = (cacheOK ? rate(group.cache_hits, group.queries) : '暂无数据') + suffix;
    parts[partId + 'Note'].textContent = (cacheOK ? '缓存命中 ' + count(group.cache_hits) + ' / 查找 ' + count(group.queries) + '；新鲜 ' + count(group.fresh_hits) + '，过期 ' + count(group.stale_hits) + '。' : cache.reason || '尚未取得缓存统计。') + (self.deviceMode ? '' : '\n' + metricWindow(cache));
   });
   parts.cacheRate.textContent = (cacheOK ? rate(all.cache_hits, all.queries) : '暂无数据') + suffix;
   parts.cacheNote.textContent = (cacheOK ? '缓存命中 ' + count(all.cache_hits) + ' / 缓存查找 ' + count(all.queries) + '；无查找时不计算比率。' : cache.reason || '尚未取得缓存统计。') + (self.deviceMode ? '' : '\n' + metricWindow(cache));
   parts.successRate.textContent = (dnsOK ? rate(dns.successes, dns.completed) : '暂无数据') + suffix;
   parts.successNote.textContent = (dnsOK ? '成功 ' + count(dns.successes) + ' / 已完成请求 ' + count(dns.completed) + '；失败 ' + count(dns.failures) + '，接收 ' + count(dns.requests) + '。' : dns.reason || '尚未取得实际请求统计。') + (self.deviceMode ? '' : '\n' + metricWindow(dns));
   if (self.deviceMode) {
    var cacheWindow = metricWindow(cache), dnsWindow = metricWindow(dns);
    parts.telemetryInfo.textContent += '\n' + (cacheWindow === dnsWindow ? cacheWindow : '缓存：' + cacheWindow + '\n请求：' + dnsWindow);
   }
   var hasLatency = dns.latency_count > 0;
   parts.latency.textContent = (dnsOK && hasLatency ? duration(dns.recent_ms) : '暂无数据') + suffix;
   var p95 = hasLatency && dns.p95_overflow && number(dns.p95_lower_bound_ms) ? '> ' + duration(dns.p95_lower_bound_ms) : (dns.p95_is_upper_bound && hasLatency ? '≤ ' : '') + duration(hasLatency ? dns.p95_ms : null);
   parts.latencyNote.textContent = dnsOK ? (dns.recent_kind === 'interval_average' ? '最近有请求区间的平均耗时（非最后单条请求）' : '最近完成请求') + (dns.recent_at ? ' · ' + time(dns.recent_at) : '') + '；窗口平均 ' + duration(hasLatency ? dns.avg_ms : null) + '，P95 ' + p95 + '；耗时样本 ' + count(dns.latency_count) + '。' : dns.reason || '尚未取得实际请求耗时。';
   replace(parts.groupMetrics, [table(['分组', '缓存命中 / 查找', '命中率', '新鲜 / 过期缓存命中'], ['cn', 'foreign'].map(function(id) {
    var g = cacheOK ? object(groups[id]) : {};
    return row([id === 'cn' ? '国内' : '国外', count(g.cache_hits) + ' / ' + count(g.queries), rate(g.cache_hits, g.queries), count(g.fresh_hits) + ' / ' + count(g.stale_hits)]);
   }))]);
  }

  function percentile(h, q) {
   h = object(h);
   return h[q + '_overflow'] ? '> ' + duration(h[q + '_lower_ms']) : number(h[q + '_ms']) ? '≤ ' + duration(h[q + '_ms']) : '暂无数据';
  }
  function renderStats() {
   var s = object(object(current.telemetry).stats), ok = s.available === true, m = object(s.total);
   var rt = object(m.rt), intervals = ok && Array.isArray(s.intervals) ? s.intervals : [];
   var suffix = connected ? '' : '（历史快照，当前未知）';
   parts.statsInfo.textContent = ok ? '累计周期：' + time(s.started_unix) + ' 起 · 已运行 ' + count(Math.floor(s.uptime_seconds)) + ' 秒 · 采样 ' + time(s.sampled_at) + ' · 样本年龄 ' + count(s.sample_age_seconds) + ' 秒。' + suffix : '扩展 stats 暂不可用：' + (s.reason || '当前版本未提供 stats，启用支持的解析器后显示。') + suffix;
   parts.statsTotals.textContent = ok ? '已完成 ' + count(m.completed) + ' · 成功 ' + rate(m.success, m.completed) + ' · 失败 ' + count(m.failures) + ' · 在途 ' + count(s.inflight) : '暂无扩展统计';
   parts.statsRT.textContent = ok ? '平均 ' + duration(rt.avg_ms) + ' · P95 ' + percentile(rt, 'p95') + ' · P99 ' + percentile(rt, 'p99') + ' · 最大 ' + duration(rt.max_ms) : '等待有效样本';
   parts.statsStages.textContent = ok ? '平均排队 ' + duration(object(m.queue).avg_ms) + ' · 平均执行 ' + duration(object(m.service).avg_ms) + '。包含失败请求；分段可能重叠，不能相加当作 RT。' : '';
   var descriptions = {qps:'完成 QPS',avg:'平均 RT (ms)',p95:'P95 桶上界 (ms)',p99:'P99 桶上界 (ms)',success:'请求成功率 (%)',cache:'前台缓存命中 / 已完成请求 (%)'};
   var values = intervals.map(function(v) {
    var x = object(v.metrics), h = object(x.rt);
    return trendMetric === 'qps' ? v.qps : trendMetric === 'success' ? x.success_rate_pct : trendMetric === 'cache' ? x.cache_hit_rate_pct : trendMetric === 'avg' ? h.avg_ms : h[trendMetric + '_ms'];
   });
   var maximum = trendMetric === 'success' || trendMetric === 'cache' ? 100 : Math.max.apply(null, [1].concat(values.filter(number)));
   var bars = intervals.map(function(v, i) {
    var n = values[i], valid = number(n) && n >= 0, h = object(object(v.metrics).rt);
    var overflow = (trendMetric === 'p95' || trendMetric === 'p99') && h[trendMetric + '_overflow'];
    var label = time(v.start) + ' — ' + time(v.finish) + ' · ' + descriptions[trendMetric] + '：' + (overflow ? '> ' + h[trendMetric + '_lower_ms'] : valid ? n.toFixed(2) : '无样本');
    return E('div', { 'class':'pnw-bar-slot', 'title':label, 'tabindex':'0', 'aria-label':label }, [E('div', { 'class': 'pnw-bar ' + (overflow ? 'pnw-bar-overflow' : valid ? '' : 'pnw-bar-missing'), 'style':'height:' + (overflow ? 100 : valid ? Math.max(n > 0 ? 1 : 0, Math.min(100, n / maximum * 100)) : 2) + '%' })]);
   });
   parts.trendInfo.textContent = intervals.length ? descriptions[trendMetric] + ' · 每柱一个实际区间（等宽，时长见明细） · ' + time(intervals[0].start) + ' 至 ' + time(intervals[intervals.length-1].finish) + ' · ' + intervals.length + ' 段 · 纵轴 0–' + maximum.toFixed(2) + '。灰色为无样本，橙色为超出直方图上限。' + suffix : '等待第一个完整统计区间；不会把缺失数据补成 0。';
   parts.trendChart.hidden = intervals.length === 0;
   replace(parts.trendChart, bars);
   replace(parts.trendTable, [table(['区间结束 / 秒数', '完成 / QPS', '成功率', '前台命中率', '平均 RT', 'P95', 'P99'], intervals.map(function(v) {
    var x = object(v.metrics), h = object(x.rt);
    return row([time(v.finish) + ' / ' + Number(v.seconds.toFixed(2)), count(x.completed) + ' / ' + v.qps.toFixed(2), rate(x.success,x.completed), rate(object(x.cache).fresh + object(x.cache).stale,x.completed), duration(h.avg_ms), percentile(h,'p95'), percentile(h,'p99')]);
   }))]);
   function countsPanel(raw, names, unavailable) {
    var keys = Object.keys(names), found = keys.filter(function(k) { return number(raw[k]) && raw[k] > 0; });
    if (!ok) return [message(unavailable)];
    return found.length ? [table(['原因', '累计次数'], found.map(function(k) { return row([names[k], count(raw[k])]); }))] : [message('当前累计没有此类记录。')];
   }
   replace(parts.statsErrors, countsPanel(object(m.errors),errorNames,'扩展统计启用后显示错误原因。'));
   var codes = object(m.rcode), codeNames={'0':'NOERROR','1':'FORMERR','2':'SERVFAIL','3':'NXDOMAIN','4':'NOTIMP','5':'REFUSED',extended:'扩展 RCODE'};
   replace(parts.statsRcodes, ok && Object.keys(codes).length ? [table(['DNS 响应码','累计次数'],Object.keys(codes).filter(function(k){return codes[k]>0;}).map(function(k){return row([codeNames[k]||'RCODE '+k,count(codes[k])]);}))] : [message('当前快照未提供响应码明细。')]);
   replace(parts.statsEvents, countsPanel(object(s.events),eventNames,'扩展统计启用后显示连接事件。'));
   if (ok) parts.statsErrors.appendChild(E('p', {'class':'pnw-muted'}, '失败总计 ' + count(m.failures) + '；终态原因不覆盖全部 DNS 错误 RCODE。连接事件可能与请求错误重叠，两表不能相加。'));
   replace(parts.statsGroups, [table(['累计分组', '完成', '成功率', '前台命中率', '平均 RT', 'P99'], (ok && Array.isArray(s.breakdown) ? s.breakdown : []).map(function(v) {
    var x=object(v.metrics), c=object(x.cache);
    return row([(v.group==='cn'?'国内':'国外')+' · '+v.qtype+' · '+v.transport.toUpperCase(),count(x.completed),rate(x.success,x.completed),rate(c.fresh+c.stale,x.completed),duration(object(x.rt).avg_ms),percentile(x.rt,'p99')]);
   }))]);
   var top=object(s.top50), domains=ok && Array.isArray(top.domains)?top.domains:[];
   parts.topInfo.textContent = ok ? '本进程累计 DNS 请求域名 Top 50 · ' + (top.exact ? '候选未发生替换，计数精确。' : 'Space-Saving 近似排行；实际次数介于下界与估计之间，名次可能有误差。') + '含失败请求，不含后台预热；不是网站访问量。' + suffix : '旧 metrics 不记录域名排行，不能从缓存命中率推算 Top 50。';
   var filtered=domains.map(function(d,i){return {d:d,rank:i+1};}).filter(function(v){return v.d.domain.toLowerCase().indexOf(domainFilter)>=0;});
   replace(parts.topDomains, filtered.length ? [table(['排名 / 域名','次数估计','可信下界','最大计数误差'],filtered.map(function(v){return row([v.rank+'. '+v.d.domain,count(v.d.count_estimate),count(v.d.count_lower_bound),count(v.d.error_bound)]);}))] : [message(ok ? '没有匹配的域名。' : '等待 stats 数据。')]);
   exportStats.disabled=!ok;
  }
  function renderQuery() {
   if (querying) { replace(parts.queryResult, [message('正在解析并检查当前规则…')]); return; }
   if (queryError) { replace(parts.queryResult, [message(queryError, 'bad')]); return; }
   if (!queryResult) { replace(parts.queryResult, [E('p', { 'class': 'pnw-muted' }, '输入域名或 IP，查看当前规则推断。查询会产生 DNS 请求；不会主动连接目标网站。')]); return; }
   var r = queryResult, c = object(r.classification), result = [];
   result.push(message((r.ok === false ? '查询未完成：' + (r.error || r.reason || '请查看详情') : '查询目标：' + value(r.input)) + ' · ' + time(r.time), r.ok === false ? 'bad' : 'neutral'));
   if (!connected) result.push(message('页面已失联，以下查询结果为历史记录。', 'bad'));
   result.push(E('p', { 'class': 'pnw-muted' }, '以下为查询时快照；出口或配置变化后，结果不会自动刷新，请重新查询。'));
   result.push(E('p', {}, '查询时来源：' + ({ router: '路由器本机', lan: '普通 LAN 客户端', bypass: '本地配置的豁免客户端' }[r.source] || value(r.source)) + ' · 查询时域名分类：' + ({ cn: '国内', foreign: '国外', unknown: '未确定' }[c.group] || '未确定') + (c.complete === false ? '（规则依据不完整）' : '')));
   if (Array.isArray(c.matches) && c.matches.length) result.push(table(['命中规则文件', '规则'], c.matches.map(function(m) { return row([value(m.file), value(m.rule)]); })));
   if (Array.isArray(r.dns) && r.dns.length) result.push(table(['DNS 类型', '解析结果', '耗时'], r.dns.map(function(d) { return row([value(d.qtype), (d.ok === true ? '完成' : '失败') + ' · ' + value(d.rcode) + (d.error ? ' · ' + d.error : ''), duration(d.duration_ms)]); })));
   if (Array.isArray(r.answers)) result.push(table(['地址族', '地址', '查询时预计路径', '查询时规则依据'], r.answers.map(function(a) {
    var route = object(a.route), path = { WAN: '查询时 WAN 直连', tunnel: '查询时隧道', blocked: '查询时阻断', local: '查询时本地地址', unknown: '查询时未确定' }[a.expected_path] || value(a.expected_path);
    if (route.device) path += ' · ' + route.device;
    return row([value(a.family), value(a.address), path, value(a.reason) + (Array.isArray(a.sets) && a.sets.length ? '；集合 ' + a.sets.join('、') : '')]);
   })));
   (Array.isArray(r.notes) && !self.deviceMode ? r.notes : []).forEach(function(n) { result.push(E('p', { 'class': 'pnw-muted' }, String(n))); });
   result.push(E('p', { 'class': 'pnw-muted' }, (self.deviceMode ? 'DNS 查询可能刷新缓存和地址集合。' : '') + '规则推断不等于真实连接验证。已有连接、设备例外、外部 DNS / DoH 可能改变实际路径；实际连接需结合 conntrack、路由标记和出口验证。'));
   result.push(E('details', {}, [E('summary', {}, '查询依据'), E('pre', { 'class': 'pnw-json' }, JSON.stringify(r, null, 2))]));
   replace(parts.queryResult, result);
  }
  function paint() { if (self.statsOnly) { renderConnection(); renderStats(); return; } renderConnection(); renderOverview(); renderDNSUpstreams(); renderHealth(); renderDomesticExit(); renderTelemetry(); renderStats(); renderQuery(); renderActions(); }
  function offline(e) { connected = false; transportError = e && e.message ? e.message : String(e || '超过 15 秒未取得状态'); paint(); }
  function update(d, sequence) {
   if (sequence !== undefined && sequence < appliedSequence) return;
   if (!d || typeof d !== 'object' || Array.isArray(d) || (self.statsOnly ? d.stats_only !== true : !d.selected || typeof d.running !== 'boolean')) throw new Error('状态响应不完整，当前状态未知');
   appliedSequence = sequence === undefined ? appliedSequence : sequence;
   current = d; connected = true; transportError = ''; lastSuccess = receivedAt = Date.now();
   parts.diagnostic.textContent = JSON.stringify(d.diagnostic || {}, null, 2); paint();
  }
  function refresh() {
   var sequence = ++requestSequence;
   return self.call(['status']).then(function(d) { update(d, sequence); return d; }).catch(function(e) { if (sequence >= appliedSequence) offline(e); throw e; });
  }
  function button(label, action) {
   var reason = E('small', { 'class': 'pnw-action-reason', 'id': 'pnw-reason-' + action });
   var b = E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-action', 'data-pnw-action': action, 'aria-describedby': 'pnw-reason-' + action, 'click': function() {
    if (unavailableReason(action)) return;
    submitting = true; actionError = ''; paint();
    self.call(['start', action]).then(function(r) { if (r.accepted !== true) throw new Error(r.error || '服务没有接受操作'); return refresh(); }).catch(function(e) {
     actionError = e.message; ui.addNotification(null, E('p', {}, e.message), 'error'); return refresh().catch(function() {});
    }).then(function() { submitting = false; paint(); });
   } }, label);
   buttons.push({ node: b, action: action, reason: reason, label: label }); return E('div', { 'class': 'pnw-action' }, [b, reason]);
  }
  var refreshButton = E('button', { 'type': 'button', 'class': 'cbi-button', 'click': function() { refresh().catch(function() {}); } }, '刷新状态');
  var queryInput = E('input', { 'type': 'text', 'class': 'cbi-input-text', 'placeholder': '例如 example.com 或 1.1.1.1', 'aria-label': '待查询的域名或 IP', 'maxlength': '253', 'autocomplete': 'off', 'spellcheck': 'false' });
  var querySource = E('select', { 'class': 'cbi-input-select', 'aria-label': '查询流量来源' }, [E('option', { 'value': 'router' }, '路由器本机'), E('option', { 'value': 'lan' }, '普通 LAN 客户端'), E('option', { 'value': 'bypass' }, '本地配置的豁免客户端')]);
  function query() {
   if (queryButton.disabled) return;
   var input = queryInput.value.trim();
   if (!input) { queryError = '请输入域名或 IP。'; renderQuery(); return; }
   querying = true; queryError = ''; renderQuery(); renderActions();
   self.call(['query', input, querySource.value || 'router']).then(function(r) { queryResult = r; }).catch(function(e) { queryError = e.message; }).then(function() { querying = false; renderQuery(); renderActions(); });
  }
  var queryButton = E('button', { 'type': 'button', 'class': 'cbi-button cbi-button-action', 'click': query }, '查询分流');
  queryInput.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); query(); } });

  var trendSelect = E('select', {'aria-label':'趋势指标','change':function(ev){trendMetric=ev.target.value;renderStats();}}, ['p99','p95','avg','qps','success','cache'].map(function(k){return E('option',{value:k},{p99:'P99 耗时',p95:'P95 耗时',avg:'平均耗时',qps:'完成 QPS',success:'成功率',cache:'前台缓存命中率'}[k]);}));
  var topSearch = E('input', {'type':'search','placeholder':'筛选 Top 50 域名','aria-label':'筛选 Top 50 域名','input':function(ev){domainFilter=ev.target.value.toLowerCase().trim();renderStats();}});
  var exportStats=E('button',{'type':'button','class':'cbi-button','click':function(){
   var snapshot=object(object(current.telemetry).stats);
   var url=URL.createObjectURL(new Blob([JSON.stringify({exported_at:new Date().toISOString(),page_connected:connected,stats:snapshot},null,2)],{type:'application/json'}));
   var a=document.createElement('a');a.href=url;a.download='pnw-dns-stats.json';a.click();setTimeout(function(){URL.revokeObjectURL(url);},1000);
  }},'导出当前统计（含域名）');
  var root = E('div', { 'class': 'pnw-control' }, [
   E('style', {}, '.pnw-control{max-width:1200px}.pnw-control [hidden]{display:none!important}.pnw-control h3{margin:0 0 .7em;font-size:1.05em}.pnw-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px;margin:14px 0}.pnw-egress-grid{grid-template-columns:1fr}.pnw-egress-grid td:first-child,.pnw-egress-grid th:first-child{white-space:nowrap}.pnw-card{padding:16px;border:1px solid var(--border-color-low,#d9dde3);border-radius:8px;min-width:0;margin:12px 0}.pnw-card p{margin:.5em 0}.pnw-value{font-size:1.7em;font-weight:600;line-height:1.3;overflow-wrap:anywhere}.pnw-muted,.pnw-action-reason{color:var(--text-color-medium,#626971);font-size:.9em;white-space:pre-wrap}.pnw-message{padding:10px 12px;border-left:4px solid #7b8794;background:var(--background-color-high,#f4f5f7);white-space:pre-wrap;overflow-wrap:anywhere}.pnw-ok{border-color:#23834d}.pnw-bad{border-color:#c43f3f}.pnw-text-ok{color:#23834d}.pnw-text-bad{color:#bf3333;font-weight:600}.pnw-actions{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:14px 0}.pnw-action button{width:100%;white-space:normal;min-height:36px}.pnw-action-reason{display:block;min-height:1.3em;margin-top:4px}.pnw-table-scroll{overflow-x:auto}.pnw-table{width:100%;margin:10px 0}.pnw-table td,.pnw-table th{text-align:left;padding:8px;vertical-align:top;overflow-wrap:anywhere}.pnw-json{white-space:pre-wrap;max-height:24em;overflow:auto;overflow-wrap:anywhere}.pnw-query{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}.pnw-query input{flex:1;min-width:200px}.pnw-top-domains{max-height:25em;overflow:auto}.pnw-bars{display:flex;align-items:flex-end;height:160px;gap:3px;border-bottom:1px solid #94a3b8;margin:12px 0;padding-top:8px}.pnw-bar-slot{position:relative;flex:1;height:100%;min-width:2px;display:flex;align-items:flex-end}.pnw-bar{width:100%;background:#26866f;border-radius:3px 3px 0 0}.pnw-bar-missing{background:#94a3b8}.pnw-bar-overflow{background:#d97706}.pnw-bar-slot:focus{outline:2px solid #2563eb}.pnw-control details{margin:12px 0}.pnw-control summary{cursor:pointer}.pnw-preserve{white-space:pre-wrap;overflow-wrap:anywhere}@media(max-width:600px){.pnw-card{padding:12px}.pnw-grid{grid-template-columns:1fr}.pnw-actions{grid-template-columns:1fr 1fr}.pnw-value{font-size:1.45em}.pnw-table{font-size:.9em}}'),
   E('h2', {}, '分流与恢复'), part('connection', 'p', { 'role': 'status', 'aria-live': 'polite' }), refreshButton,
   E('div', { 'class': 'pnw-grid' }, [card('当前出口', 'exit'), card('配置模式', 'mode'), card('任务状态', 'task')]),
   part('healthSummary', 'p'), part('attention'), part('system', 'p', { 'class': 'pnw-muted' }),
   E('section', { 'class': 'pnw-card' }, [E('h3', {}, '出口与恢复操作'), part('switchHelp', 'p'),
    E('div', { 'class': 'pnw-actions' }, [button('切换 AWS 新加坡', 'switch-aws'), button('切换 nobrand', 'switch-nobrand'), button('切换美国 SS', 'switch-usss'), button('切换美国 VLESS', 'switch-usvless'), button('回滚上次出口', 'rollback')]), part('rollbackTarget', 'p', { 'class': 'pnw-muted' }),
    E('div', { 'class': 'pnw-actions' }, [button('恢复国内联网（应急）', 'rescue'), button('恢复正常分流', 'recover'), button('检测出口可用性', 'check'), button('采集诊断（3 秒）', 'diagnose'), button('重试未完成回退', 'retry-recovery')]),
    E('p', { 'class': 'pnw-muted', 'data-device-hide': '1' }, '国内应急保留 LAN、静态租约和管理入口，停止海外标记流量；AI 服务不会自动改走 WAN。美国出口仅使用 IPv4，境外 IPv6 阻断，国内 IPv6 保留。出口身份以设备本地配置和实际检测为准；两个出口是否独立需由部署配置确认。'), part('last', 'p', { 'class': 'pnw-preserve' })]),
   E('div', { 'class': 'pnw-grid' }, [E('section', { 'class': 'pnw-card' }, metric('最近操作耗时', 'operationTime', 'operationTimeNote')), E('section', { 'class': 'pnw-card' }, metric('最近检测耗时', 'checkTime', 'checkTimeNote'))]),
   E('section', { 'class': 'pnw-card' }, [E('h3', {}, '国内 / 国外 DNS'), E('p', { 'class': 'pnw-muted' }, '当前配置的 DNS 上游与转发链。并发、故障切换和缓存会影响每次请求，以下不代表某次请求实际命中的服务器。'), E('div', { 'class': 'pnw-grid' }, [card('国内 DNS', 'dnsCn'), card('国外 DNS', 'dnsForeign')])]),
   E('section', { 'class': 'pnw-card' }, [E('h3', {}, 'DNS 实际请求指标'), part('telemetryInfo', 'p', { 'class': 'pnw-muted' }), E('div', { 'class': 'pnw-grid' }, [metric('国内缓存命中率', 'cacheCnRate', 'cacheCnNote'), metric('国外缓存命中率', 'cacheForeignRate', 'cacheForeignNote')]), E('div', { 'class': 'pnw-grid' }, [metric('请求成功率', 'successRate', 'successNote'), metric(self.deviceMode ? '近期 DNS 耗时' : '最近 DNS 耗时', 'latency', 'latencyNote')]), E('details', {}, [E('summary', {}, '全部缓存与分组明细'), metric('全部缓存命中率', 'cacheRate', 'cacheNote'), part('groupMetrics')]),
    E('details', {}, [E('summary', {}, '统计口径'),
     E('p', { 'class': 'pnw-muted' }, '成功：NOERROR 或 NXDOMAIN 响应已成功交给本机 socket。NXDOMAIN 是有效的否定回答；本机发送成功不保证客户端收到。SERVFAIL、REFUSED、其他错误响应及发送失败计入失败。分母为本窗口已完成请求，接收数与完成数可因在途请求不同。'),
     E('p', { 'class': 'pnw-muted' }, '耗时：从接受完整合法查询到响应提交或最终失败，包含排队、TCP 写入等待与失败请求，不包含客户端网络往返。P95 来自直方图，显示范围上界或溢出下界。后台刷新、预热、非法报文和进入解析器前的丢包不属于请求统计。'),
     E('p', { 'class': 'pnw-muted' }, '缓存：命中包含新鲜与过期缓存；分母包含未命中和绕过缓存的查找。共享在途查询与过载拒绝等情况会使缓存查找数不同于完整请求数。')])]),

   E('section', {'class':'pnw-card'}, [E('h3',{},'DNS 趋势与排障'),part('statsInfo','p',{'class':'pnw-muted'}),part('statsTotals','p',{'class':'pnw-value'}),part('statsRT','p'),part('statsStages','p',{'class':'pnw-muted'}),
    E('p',{'class':'pnw-muted'},self.statsOnly ? '总览、错误、分组和排行是本进程累计；趋势是最近最多 60 个区间。命中率按前台已完成请求计算。此页只读，不提供出口切换或 DNS 配置修改。' : self.deviceMode ? '上方卡片由 stats 的实际请求与缓存引擎累计计数计算最近最多 5 分钟差值；这里展示本进程累计。趋势缓存命中率以前台完成请求为分母，与上方缓存查找分母不同。' : '上方卡片是最近最多 5 分钟的 metrics；这里的总览、错误、分组和排行是 stats 自进程启动累计。两者独立采样，不拼接、不互相补零。趋势命中率按前台已完成请求计算，与上方缓存查找口径不同。'),
    trendSelect,part('trendInfo','p',{'class':'pnw-muted'}),part('trendChart','div',{'class':'pnw-bars','role':'group','aria-label':'DNS 区间趋势'}),
    E('details',{},[E('summary',{},'查看每个区间的数值'),part('trendTable')]),
    E('div',{'class':'pnw-grid'},[card('请求终态错误（累计）','statsErrors'),card('连接与报文事件（累计）','statsEvents')]),
    E('details',{},[E('summary',{},'DNS 响应码（累计）'),part('statsRcodes')]),
    E('details',{},[E('summary',{},'国内 / 国外 · A / AAAA · UDP / TCP 累计性能'),part('statsGroups')]),
    E('h3',{},'Top 50 DNS 域名'),part('topInfo','p',{'class':'pnw-muted'}),topSearch,part('topDomains','div',{'class':'pnw-top-domains'}),exportStats,
    E('p',{'class':'pnw-muted'},'统计包含访问域名，仅在现有管理登录下查看。导出文件分享前请检查隐私。重启开启新累计周期；这些观察不能证明网站访问成功或代替版本间同流量对照。')]),
   E('section', { 'class': 'pnw-card' }, [E('h3', {}, '最近出口检测'), part('checks'), E('h3', {}, '实际公网出口'), E('div', { 'class': 'pnw-grid pnw-egress-grid' }, [card('国内公网出口', 'domesticPublicExit'), card('国外公网出口', 'publicExit')]), part('peers', 'p', { 'class': 'pnw-muted' }), part('endpoint', 'p', { 'class': 'pnw-muted' })]),
   E('section', { 'class': 'pnw-card' }, [E('h3', {}, '域名 / IP 分流查询'), E('div', { 'class': 'pnw-query' }, [queryInput, querySource, queryButton]), part('queryResult')]),
   E('p', { 'class': 'pnw-muted', 'data-device-hide': '1' }, '客户端豁免由设备本地配置和当前规则决定；本页不会新增或修改豁免。'),
   E('button', { 'type': 'button', 'class': 'cbi-button', 'click': function() {
    var url = URL.createObjectURL(new Blob([parts.diagnostic.textContent], { type: 'application/json' }));
    var a = document.createElement('a'); a.href = url; a.download = 'pnw-diagnostic.json'; a.click(); setTimeout(function() { URL.revokeObjectURL(url); }, 1000);
   } }, '导出最近诊断'),
   E('details', {}, [E('summary', {}, '最近一次脱敏诊断（本机保留）'), part('diagnostic', 'pre', { 'class': 'pnw-json' })]), part('version', 'p', { 'class': 'pnw-muted' })
  ]);
  if (self.deviceMode) {
   // Move existing components so polling, permissions and export handlers keep one owner.
   function take(n) { if (n.parentNode) n.parentNode.removeChild(n); return n; }
   function section(id, title, children) { return E('section', {id:id, 'class':'pnw-section'}, [E('h2', {}, title)].concat(children)); }
   var style = take(root.firstChild), title = take(root.firstChild);
   var overviewCards = take(parts.exit.parentNode.parentNode);
   var upstreams = take(parts.dnsCn.parentNode.parentNode.parentNode);
   var recent = take(parts.telemetryInfo.parentNode);
   var stats = take(parts.statsInfo.parentNode);
   var health = take(parts.checks.parentNode);
   var lookup = take(parts.queryResult.parentNode);
   var diagnostics = take(parts.diagnostic.parentNode);
   var diagnosticExport = Array.prototype.filter.call(root.children, function(n) { return n.tagName === 'BUTTON' || n.tag === 'button'; }).filter(function(n) { return n !== refreshButton; })[0];
   var definitions = take(recent.children[recent.children.length - 1]);
   var allCache = take(parts.cacheRate.parentNode);
   // Group rows repeat the two main cache cards; the aggregate remains available.
   var aggregate = recent.children[recent.children.length - 1];
   replace(aggregate, [E('summary', {}, '全部缓存合计'), allCache]);
   recent.firstChild.textContent = '近期请求（最多 5 分钟）';
   var cumulative = E('section', {'class':'pnw-card'}, [E('h3', {}, '本次运行累计'), take(parts.statsInfo), take(parts.statsTotals), take(parts.statsRT), take(parts.statsStages)]);
   cumulative.hidden = true;
   var scopeSelect = E('select', {'aria-label':'统计时间范围', 'change':function(ev) {
    recent.hidden = ev.target.value === 'lifetime'; cumulative.hidden = !recent.hidden;
   }}, [E('option', {value:'recent'}, '近 5 分钟（按实际窗口）'), E('option', {value:'lifetime'}, '本次运行累计')]);
   stats.firstChild.textContent = '趋势、错误与域名排行';
   // Keep one common explanation for scope and denominator; trend/errors retain their labels.
   stats.removeChild(stats.children[1]);
   definitions.appendChild(E('p', {'class':'pnw-muted'}, '近期缓存命中率以缓存查找为分母；趋势缓存占比以前台已完成请求为分母，不能直接比较。错误、响应码、分组和 Top 50 为本次运行累计，重启后重新开始。'));
   var unavailable = E('details', {}, [E('summary', {}, '本设备未部署的能力'), take(parts.switchHelp), part('unavailableActions', 'div', {'class':'pnw-actions'})]);
   var available = part('availableActions', 'div', {'class':'pnw-actions'});
   health.appendChild(take(parts.checkTimeNote));
   var overview = section('pnw-overview', '概览', [overviewCards, take(parts.healthSummary), take(parts.attention), take(parts.system), E('section', {'class':'pnw-card'}, [E('h3', {}, '最近操作'), take(parts.last)]), unavailable]);
   var dnsSection = section('pnw-dns', 'DNS 统计', [E('label', {}, ['统计范围 ', scopeSelect]), recent, cumulative, stats, definitions, E('details', {}, [E('summary', {}, 'DNS 上游配置'), upstreams])]);
   var diagnosticSection = section('pnw-diagnostics', '检测与诊断', [available, health, lookup, take(diagnosticExport), diagnostics]);
   replace(root, [style, title, take(parts.connection), take(refreshButton), E('nav', {'class':'pnw-query','aria-label':'页面分区'}, [E('a', {href:'#pnw-overview'}, '概览'), E('a', {href:'#pnw-dns'}, 'DNS 统计'), E('a', {href:'#pnw-diagnostics'}, '检测与诊断')]), overview, dnsSection, diagnosticSection, take(parts.version)]);
  }
  if (self.deviceMode) {
   function hideDeviceHints(n) { if (n.attrs && n.attrs['data-device-hide']) n.hidden = true; if (n.getAttribute && n.getAttribute('data-device-hide')) n.hidden = true; Array.prototype.forEach.call(n.children || [], hideDeviceHints); }
   hideDeviceHints(root);
   while (querySource.children.length > 2) querySource.removeChild(querySource.children[2]);
  }
  if (self.statsOnly) replace(root, [root.firstChild, E('h2', {}, 'DNS 统计'), parts.connection, refreshButton, parts.statsInfo.parentNode, parts.version]);
  try { if (data._load_error) offline(data._load_error); else update(data); } catch (e) { offline(e); }
  poll.add(function() { return refresh().catch(function() {}); }, (self.statsOnly || self.deviceMode) ? 30 : 5);
  poll.add(function() { if (connected && Date.now() - lastSuccess > ((self.statsOnly || self.deviceMode) ? 90000 : 15000)) offline('超过 ' + ((self.statsOnly || self.deviceMode) ? '90' : '15') + ' 秒未取得新状态，当前状态未知'); }, 1);
  return root;
 }
});
