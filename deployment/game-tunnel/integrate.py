"""Pure transformations for the existing main-router owner. Never SSH or deploy.
Fail on unknown anchors; callers back up, validate, apply and adopt the changed
policy under the shared deployment lock. Private input/output must stay local.
"""
from pathlib import Path

def once(text,old,new):
    if text.count(old)!=1: raise ValueError('unsupported or already patched source: '+old[:65])
    return text.replace(old,new,1)

def policy(text):
    for chain in ('split','router_output'):
        prefix='add rule inet diversion_dns '+chain+' '
        anchor=prefix+'ip daddr @cn4 '
        if text.count(anchor)!=1: raise ValueError('CN priority anchor missing')
        rules=[
            'meta l4proto @game_enabled ip daddr @game_site4 meta mark set 1 ct mark set 1 counter return comment "Game login/community IPv4 tunnel"',
            'meta l4proto @game_enabled ip6 daddr @game_site6 meta mark set 1 ct mark set 1 counter return comment "Game login/community IPv6 tunnel"',
            'ip daddr . udp dport @game_relay4 meta l4proto @game_enabled meta mark set 1 ct mark set 1 counter return comment "Dota 2 SDR tunnel"',
            'ip daddr . tcp dport @game_cm4 meta l4proto @game_enabled meta mark set 1 ct mark set 1 counter return comment "Steam CM TCP tunnel"',
            'ip daddr . udp dport @game_cm4 meta l4proto @game_enabled meta mark set 1 ct mark set 1 counter return comment "Steam CM UDP tunnel"',
        ]
        text=text.replace(anchor,''.join(prefix+x+'\n'for x in rules)+anchor)
    return text

def dedicated_policy(text):
    """Upgrade an already integrated profile. Dedicated mark never becomes global."""
    lines=text.splitlines(True);count=0
    for i,line in enumerate(lines):
        if any(x in line for x in ('@game_site4','@game_site6','@game_relay4','@game_cm4')):
            if 'meta mark set 1 ct mark set 1' not in line:
                raise ValueError('unsupported game mark')
            lines[i]=line.replace('meta mark set 1 ct mark set 1','meta mark set 2 ct mark set 2');count+=1
    if count!=10:raise ValueError('expected ten existing game rules')
    text=''.join(lines)
    anchor='add rule inet diversion_dns router_output ct direction reply return\n'
    text=once(text,anchor,anchor+
        'add rule inet diversion_dns router_output udp sport 51824 meta mark set 0 ct mark set 0 return comment "Dedicated game WireGuard transport WAN"\n'+
        'add rule inet diversion_dns router_output oifname "wg_game" meta mark set 2 ct mark set 2 return comment "Explicit dedicated game interface"\n')
    text+='insert rule inet diversion_dns guard ct direction original meta mark 2 oifname != "wg_game" counter reject comment "Dedicated game fail closed"\n'
    text+='insert rule inet diversion_dns router_guard ct direction original meta mark 2 oifname != "wg_game" counter drop comment "Dedicated game fail closed"\n'
    return text

def dedicated_emergency(text):
    if text.count('meta mark 1 counter drop')!=2:raise ValueError('unknown emergency rules')
    return text.replace('meta mark 1 counter drop','meta mark { 1, 2 } counter drop')

def dedicated_query(text):
    text=once(text,' local game_known=true;local game_enabled=false',
        " local game_known=true;local game_enabled=false\n local dedicated=read('/etc/pnw-control/game-tunnel/egress.json')~=nil")
    text=once(text,"elseif gamehit then a.expected_path='tunnel';a.reason='Steam/游戏登录社区地址例外优先于国内集合；TCP/UDP 新连接'",
        "elseif gamehit then a.expected_path='tunnel';a.reason=dedicated and 'Steam/游戏例外：独立 AWS 隧道；TCP/UDP 新连接' or 'Steam/游戏登录社区地址例外优先于国内集合；TCP/UDP 新连接'")
    text=once(text,"a.family==6 and (ctx.selected=='usss' or ctx.selected=='usvless')",
        "a.family==6 and not (gamehit and dedicated) and (ctx.selected=='usss' or ctx.selected=='usvless')")
    text=once(text,"local mark=(a.expected_path=='tunnel' or a.expected_path=='blocked') and 1 or 0",
        "local mark=(a.expected_path=='tunnel' or a.expected_path=='blocked') and ((gamehit and dedicated) and 2 or 1) or 0")
    return text

def helper(text):
    # The sets must exist before nft sees references from the policy. Generated
    # bootstrap operations and all classifier updates use the same transaction.
    return once(text,'cat "$base/policy.nft" >> "$file"','lua /etc/pnw-control/game-tunnel-render.lua >> "$file"\ncat "$base/policy.nft" >> "$file"')

def controller(text):
    text=once(text,"['retry-recovery']=true}","['retry-recovery']=true,['game-on']=true,['game-off']=true,['game-refresh']=true}")
    text=once(text,' st.actions={}',''' st.game_tunnel=select(1,observation('game-tunnel','status')) or {available=false,reason='本机未部署游戏隧道模块'}
 st.pending=st.pending or st.game_tunnel.pending==true
 st.actions={}''')
    text=once(text,'  st.actions[action]={allowed=reason==nil,reason=reason}', '''  if action:match('^game%-') then
   if action=='game-off' and not pending then reason=nil end
   if not st.game_tunnel.available then reason='本设备未部署游戏隧道模块'
   elseif st.game_tunnel.pending then reason='游戏切换未完成，请重试恢复'
   elseif action~='game-off' and (st.emergency or st.dns_degraded) then reason='应急或 DNS 降级期间不可切换游戏策略'
   elseif action=='game-on' and st.game_tunnel.enabled and st.game_tunnel.consistent then reason='已经开启'
   elseif action=='game-off' and not st.game_tunnel.enabled and st.game_tunnel.consistent then reason='已经关闭' end
  end
  st.actions[action]={allowed=reason==nil,reason=reason}''')
    text=once(text," reconcile_containment()\n if read(B..'/pending.json') then restore() end", " reconcile_containment()\n if read(B..'/pending.json') then restore() end\n if read(B..'/game-tunnel.lua') then pcall(function()dofile(B..'/game-tunnel.lua').reconcile()end) end")
    text=once(text," local action=arg[2];assert(allowed[action],'invalid action')", " local action=arg[2];assert(allowed[action],'invalid action')\n assert(not read(B..'/game-tunnel/pending.json') or action=='diagnose' or action=='retry-recovery','unfinished game transaction')")
    text=once(text,"  if action=='switch-aws' then", """  if action:match('^game%-') then
   if action~='game-off' then ensure_topology() end
   if action~='game-off' and runtime_snapshot then assert(runtime_snapshot(selected()).consistent,'runtime exit mismatch') end
   local game=dofile(B..'/game-tunnel.lua')
   if action=='game-refresh' then return game.refresh() end
   return game.set(action=='game-on')
  elseif action=='switch-aws' then""")
    text=once(text,"(trap \"\" HUP; (flock -n 9", "(trap \"\" HUP; if [ '..q(action)..' = game-on ] || [ '..q(action)..' = game-refresh ]; then '..SELF..' game-prepare; fi; (flock -n 9")
    text=once(text,"export DIVERSION_CN_DEPLOY_LOCK_HELD=1; '..SELF..' worker", "export DIVERSION_CN_DEPLOY_LOCK_HELD=1 PNW_GAME_PREPARED=/var/run/pnw-control/job/game-data; '..SELF..' worker")
    text=once(text,"elseif mode=='start' then", "elseif mode=='game-prepare' then\n write(R..'/job/pid',tostring(nixio.getpid()))\n local game=dofile(B..'/game-tunnel.lua');game.prepare(R..'/job/game-data')\nelseif mode=='start' then")
    text=once(text,"  os.exit(rc)", "  if rc==0 and read(B..'/game-tunnel.lua') then pcall(function()if dofile(B..'/game-tunnel.lua').refresh_due() then run(SELF..' start game-refresh')end end)end\n  os.exit(rc)")
    text=text.replace("os.remove(R..'/job/token');", "os.remove(R..'/job/game-data');os.remove(R..'/job/token');")
    return text

def view(text):
    text=once(text,"var PNW_VIEW_VERSION = '","var PNW_VIEW_VERSION = 'game-20261024-")
    text=once(text,'   var entry = object(object(current.actions)[action]);','''   var entry = object(object(current.actions)[action]);
   if (action.indexOf('game-') === 0 && (object(current.game_tunnel).available !== true || entry.allowed !== true)) return entry.reason || '本设备未部署游戏隧道开关';''')
    text=once(text,'    if (self.deviceMode) {\n     var enabled',"    if (item.action.indexOf('game-') === 0) {\n     var g = object(current.game_tunnel);\n     item.node.parentNode.hidden = g.available !== true || (item.action === 'game-on' && g.enabled === true && g.consistent === true) || (item.action === 'game-off' && g.enabled !== true && g.consistent === true);\n    } else if (self.deviceMode) {\n     var enabled")
    text=once(text,'  function renderOverview() {','''  function renderOverview() {
   var game = object(current.game_tunnel);
   parts.gameCard.hidden = game.available !== true;
   parts.gameStatus.textContent = !connected ? '游戏隧道状态未知' : !game.consistent ? '配置与运行状态尚未一致，请等待完成或重试恢复' : game.enabled ? '已开启：登录、社区和 Dota 2 走' + (object(game.egress).label || '当前隧道') : '已关闭：按原 CN-site / CN-IP 分流';
   parts.gameNote.textContent = '游戏下载沿用原分流；现有设备豁免保留。切换后请重新连接 Steam / 游戏。' + (game.updated ? ' 游戏地址更新：' + time(game.updated) + '；SDR ' + count(game.relay_count) + '，登录服务器 ' + count(game.cm_count) + '。' : '') + (object(game.egress).error ? ' ' + object(game.egress).error + '。' : '') + (game.note || '');''')
    anchor="   E('div', { 'class': 'pnw-grid' }, [E('section', { 'class': 'pnw-card' }, metric('最近操作耗时'"
    text=once(text,anchor,"   E('section', { 'class': 'pnw-card' }, [part('gameCard', 'div'), E('h3', {}, 'Steam / Dota 2 游戏隧道'), part('gameStatus'), part('gameNote', 'p', {'class':'pnw-muted'}), E('div', {'class':'pnw-actions'}, [button('开启游戏隧道', 'game-on'), button('关闭游戏隧道', 'game-off'), button('更新游戏地址', 'game-refresh')])]),\n"+anchor)
    # Make the actual section the part rather than hiding an empty marker.
    text=once(text,"  if (self.deviceMode) {\n   function take", "  parts.gameCard = parts.gameCard.parentNode;\n  if (self.deviceMode) {\n   function take") if "  if (self.deviceMode) {\n   function take" in text else once(text,"  if (self.deviceMode) {\n   function hideDeviceHints", "  parts.gameCard = parts.gameCard.parentNode;\n  if (self.deviceMode) {\n   function hideDeviceHints")
    return text

def query(text):
    text=once(text," local downloader=false",''' local game_known=true;local game_enabled=false
 if rules:find('@game_site4',1,true) then
  local gate,grc=run('nft list set inet diversion_dns game_enabled')
  game_known=grc==0;game_enabled=game_known and gate:find('tcp',1,true)~=nil
  out.notes[#out.notes+1]='游戏例外优先于国内集合；SDR/登录服务器 IP 还取决于连接协议与端口，此查询不推断这些端口条件。'
 end
 local downloader=false''')
    text=once(text,"  local base=select(1,run('ip -'..a.family",'''  local gamehit=false
  if game_enabled then
   local gs='game_site'..a.family
   local found,code=run('nft get element inet diversion_dns '..gs..' '..q('{ '..a.address..' }'))
   if code==0 and found:find('elements',1,true)then gamehit=true;a.sets[#a.sets+1]=gs
   elseif code~=1 or (not found:find('No such file or directory',1,true)and not found:find('does not exist',1,true))then game_known=false end
  end
  local base=select(1,run('ip -'..a.family''')
    text=once(text,"elseif not policy_known or not membership_known then", "elseif not policy_known or not membership_known or not game_known then")
    text=once(text,"  elseif #a.sets>0 then", "  elseif gamehit then a.expected_path='tunnel';a.reason='Steam/游戏登录社区地址例外优先于国内集合；TCP/UDP 新连接'\n  elseif #a.sets>0 then")
    return text

if __name__=='__main__':
    import argparse
    p=argparse.ArgumentParser();p.add_argument('kind',choices=['policy','helper','controller','view','query']);p.add_argument('input',type=Path);p.add_argument('output',type=Path);a=p.parse_args()
    if a.output.exists():p.error('output must be fresh')
    a.output.write_text(globals()[a.kind](a.input.read_text()))
