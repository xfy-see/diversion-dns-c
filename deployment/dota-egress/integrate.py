"""Exact-anchor transforms for the static router owner; never connects to devices."""

def once(s,a,b):
    if s.count(a)!=1:raise ValueError('unsupported Dota integration anchor: '+a[:60])
    return s.replace(a,b,1)

def controller(s):
    s=once(s,"['game-refresh']=true}","['game-refresh']=true,['dota-aws']=true,['dota-hk']=true,['dota-game']=true}")
    anchor=' st.pending=st.pending or st.game_tunnel.pending==true'
    s=once(s,anchor," st.dota_egress=select(1,observation('dota-egress','status')) or {available=read(B..'/dota-egress/config.json')~=nil,consistent=false,error='Dota 状态读取失败'}\n"+anchor)
    s=once(s,'  st.actions[action]={allowed=reason==nil,reason=reason}',"""  if action:match('^dota%-') then
   local id=action:sub(6);local d=st.dota_egress
   if not reason then
    if not d.available or not d.choices then reason='本设备未部署 Dota 独立出口'
    elseif d.pending or not d.consistent then reason='Dota 状态未完成同步，请稍后重试'
    elseif st.emergency or st.dns_degraded then reason='应急或降级期间不可切换 Dota'
    elseif not d.choices[id] or not d.choices[id].available then reason='目标接口未就绪'
    elseif d.selected==id then reason='已选择该出口' end
   end
  end
  st.actions[action]={allowed=reason==nil,reason=reason}""")
    s=once(s," local ok,result=pcall(function()\n  if action:match('^game%-') then\n", " local ok,result=pcall(function()\n  if action:match('^dota%-') then return dofile(B..'/dota-egress.lua').switch(action:sub(6))\n  elseif action:match('^game%-') then\n")
    return s

def emergency(s):
    import re
    count=0
    def patch(m):
        nonlocal count
        count+=1
        values=m.group(1).strip('{} ').replace(',',' ').split()
        return 'meta mark { '+', '.join(dict.fromkeys(values+['16','17','18']))+' }'
    lines=[]
    for line in s.splitlines(True):
        if 'drop' in line:line=re.sub(r'meta mark\s+(\{[^}]+\}|\d+)',patch,line)
        lines.append(line)
    if count<2:raise ValueError('unsupported emergency guards')
    s=''.join(lines)
    pos=s.rfind('}')
    if pos<0:raise ValueError('emergency table end missing')
    return s[:pos]+' chain dota_forward { type filter hook forward priority -129; policy accept; meta mark { 16, 17, 18 } counter drop }\n'+s[pos:]

def view(s):
    s=once(s,"  function renderOverview() {",'''  function renderDota() {
   var d = object(current.dota_egress), t = object(d.traffic), totals = object(t.totals), rates = object(t.rates);
   parts.dotaCard.hidden = d.available !== true;
   parts.dotaStatus.textContent = !connected ? 'Dota 出口状态未知' : d.consistent !== true ? (d.error || 'Dota 配置与运行状态不一致') : (d.enabled ? '当前出口：' : '游戏总开关关闭；已选择：') + (d.label || '未知');
   function bytes(n) { if (!number(n) || n < 0) return '暂无数据'; if (n < 1024) return n.toFixed(0) + ' B'; if (n < 1048576) return (n/1024).toFixed(1) + ' KiB'; if (n < 1073741824) return (n/1048576).toFixed(2) + ' MiB'; return (n/1073741824).toFixed(2) + ' GiB'; }
   var rows = ['aws','hk','game'].map(function(id) {
    var a = object(totals[id]), r = object(rates[id]), c = object(object(d.choices)[id]);
    return row([c.label || id, bytes(a.up), bytes(a.down), number(a.up) && number(a.down) ? bytes(a.up+a.down) : '暂无数据', !connected || d.stats_stale ? '未知' : bytes(r.up) + '/s ↑ · ' + bytes(r.down) + '/s ↓']);
   });
   replace(parts.dotaTraffic, [table(['出口','上传','下载','合计','当前速率'], rows)]);
   parts.dotaNote.textContent = '仅统计普通 LAN 的 Dota IPv4 SDR 游戏报文，不含 Steam 登录、下载和代理封装。采样约 5 秒，累计始于 ' + time(t.started) + '；数据时间 ' + time(t.updated) + '。累计每 5 分钟保存，突然断电最多丢失约 5 分钟增量。出口选择只检查本地接口，不代表公网实测；切换后请重新连接游戏。';
  }
  function renderOverview() {
   renderDota();''')
    anchor="   var entry = object(object(current.actions)[action]);"
    s=once(s,anchor,anchor+"\n   if (action.indexOf('dota-') === 0 && entry.allowed !== true) return entry.reason || 'Dota 独立出口不可操作';")
    s=once(s,"    if (item.action.indexOf('game-') === 0) {", "    if (item.action.indexOf('dota-') === 0) { item.node.parentNode.hidden = object(current.dota_egress).available !== true;\n    } else if (item.action.indexOf('game-') === 0) {")
    s=once(s,"'已开启：登录、社区和 Dota 2 走'", "(object(current.dota_egress).available ? '已开启：Steam 登录和社区走' : '已开启：登录、社区和 Dota 2 走')")
    lines=s.splitlines(True);idx=[i for i,line in enumerate(lines)if "part('gameCard', 'div')" in line]
    if len(idx)!=1:raise ValueError('unknown game card')
    lines.insert(idx[0]+1,"   E('section', {'class':'pnw-card'}, [part('dotaCard','div'), E('h3', {}, 'Dota 2 独立出口与流量'), part('dotaStatus'), E('div', {'class':'pnw-actions'}, [button('Dota → AWS', 'dota-aws'), button('Dota → 香港 SS', 'dota-hk'), button('Dota → 当前游戏 SS', 'dota-game')]), part('dotaTraffic'), part('dotaNote','p',{'class':'pnw-muted'})]),\n")
    s=''.join(lines)
    s=once(s,'  parts.gameCard = parts.gameCard.parentNode;', '  parts.dotaCard = parts.dotaCard.parentNode;\n  parts.gameCard = parts.gameCard.parentNode;')
    return s
