#!/usr/bin/env python3
"""Real bidirectional packet accounting in a fresh, owned network namespace."""
import json,os,pathlib,secrets,subprocess,sys,time
from lupa.lua51 import LuaRuntime
ROOT=pathlib.Path(__file__).resolve().parents[2]
def run(*args,input=None):return subprocess.check_output(list(args),input=input,text=True,stderr=subprocess.PIPE)
if '--owned' not in sys.argv:
 if os.geteuid()!=0:raise SystemExit('root required')
 raise SystemExit(subprocess.call(['unshare','--net',sys.executable,__file__,'--owned']))
client='dota_c_'+secrets.token_hex(4);server='dota_s_'+secrets.token_hex(4);proc=None
try:
 lua=LuaRuntime();lua.execute("package.preload['luci.jsonc']=function()return{}end")
 module=lua.execute((ROOT/'deployment/dota-egress/dota-egress.lua').read_text())
 run('ip','link','set','lo','up');run('sysctl','-qw','net.ipv4.ip_forward=1','net.ipv4.conf.all.rp_filter=0','net.ipv4.conf.default.rp_filter=0')
 for ns in(client,server):run('ip','netns','add',ns);run('ip','netns','exec',ns,'ip','link','set','lo','up')
 run('ip','link','add','br-lan','type','veth','peer','name','client0');run('ip','link','set','client0','netns',client)
 run('ip','addr','add','198.18.0.1/24','dev','br-lan');run('ip','link','set','br-lan','up')
 run('ip','netns','exec',client,'ip','addr','add','198.18.0.2/24','dev','client0');run('ip','netns','exec',client,'ip','link','set','client0','up');run('ip','netns','exec',client,'ip','route','add','default','via','198.18.0.1')
 run('ip','netns','exec',server,'ip','addr','add','198.51.100.1/32','dev','lo')
 for index,dev in enumerate(('wg_game','pnwhks0','pnwgfec0'),1):
  peer='peer'+str(index);run('ip','link','add',dev,'type','veth','peer','name',peer);run('ip','link','set',peer,'netns',server)
  run('ip','addr','add',f'198.18.{index}.1/24','dev',dev);run('ip','link','set',dev,'up');run('ip','netns','exec',server,'ip','addr','add',f'198.18.{index}.2/24','dev',peer);run('ip','netns','exec',server,'ip','link','set',peer,'up')
  run('ip','rule','add','fwmark',str(15+index),'table',str(24015+index));run('ip','route','add','198.51.100.1/32','via',f'198.18.{index}.2','dev',dev,'table',str(24015+index))
 run('nft','-f','-',input=module.schema())
 run('nft','-f','-',input='''table inet test_original {
 chain pre { type filter hook prerouting priority -128; policy accept;
 iifname "br-lan" ct direction original udp dport 27015 meta mark set 2 ct mark set 2
 }
}
add element inet pnw_dota_egress relay4 { 198.51.100.1 . 27015 }
add element inet pnw_dota_egress enabled { udp }
''')
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('198.51.100.1',27015));\nwhile True:\n d,a=s.recvfrom(4096);s.sendto(d,a)"
 proc=subprocess.Popen(['ip','netns','exec',server,sys.executable,'-u','-c',code],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE);time.sleep(.2)
 def snapshot():
  x=json.loads(run('nft','-a','-j','list','table','inet','pnw_dota_egress'));return {o['counter']['name']:o['counter']for o in x['nftables']if 'counter'in o}
 for index,id in enumerate(('aws','hk','game'),1):
  run('ip','netns','exec',server,'ip','route','replace','198.18.0.0/24','via',f'198.18.{index}.1')
  run('nft','-f','-',input=f'flush chain inet pnw_dota_egress choose\nadd rule inet pnw_dota_egress choose meta mark set {15+index} ct mark set {15+index}\n')
  code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(2);\nfor i in range(3):\n d=bytes([i])*100;s.sendto(d,('198.51.100.1',27015));assert s.recv(4096)==d"
  run('ip','netns','exec',client,sys.executable,'-c',code)
  counts=snapshot();assert counts[id+'_up']['packets']==3,counts;assert counts[id+'_down']['packets']==3,counts
  assert counts[id+'_up']['bytes']==384 and counts[id+'_down']['bytes']==384,counts
  print('PASS',id,'3 UDP replies; exactly 384 IP bytes each direction')
 # Verify generated emergency syntax and its post-classification block.
 import importlib.util
 spec=importlib.util.spec_from_file_location('dota_integrate',ROOT/'deployment/dota-egress/integrate.py');transform=importlib.util.module_from_spec(spec);spec.loader.exec_module(transform)
 emergency='table inet pnw_emergency {\nchain ingress { type filter hook prerouting priority -129; policy accept;\nmeta mark { 1, 2 } counter drop\n}\nchain local { type filter hook output priority -129; policy accept;\nmeta mark { 1, 2 } counter drop\n}\n}\n'
 run('nft','-f','-',input=transform.emergency(emergency))
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5);s.sendto(b'contained',('198.51.100.1',27015));\ntry:\n s.recv(4096);raise AssertionError('emergency escape')\nexcept (socket.timeout,ConnectionRefusedError):pass"
 run('ip','netns','exec',client,sys.executable,'-c',code)
 assert snapshot()['game_up']['packets']==3
 block=json.loads(run('nft','-j','list','chain','inet','pnw_emergency','dota_forward'))
 assert sum(e.get('counter',{}).get('packets',0)for r in block['nftables']for e in r.get('rule',{}).get('expr',[]))==1
 run('nft','delete','table','inet','pnw_emergency');print('PASS emergency drops classified Dota before forwarding/accounting')
 # Force an AWS-marked flow down the HK interface; guard must reject it.
 run('nft','-f','-',input='flush chain inet pnw_dota_egress choose\nadd rule inet pnw_dota_egress choose meta mark set 16 ct mark set 16\n')
 run('ip','route','replace','198.51.100.1/32','via','198.18.2.2','dev','pnwhks0','table','24016')
 code="import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.settimeout(.5);s.sendto(b'blocked',('198.51.100.1',27015));\ntry:\n s.recv(4096);raise AssertionError('escape reply')\nexcept (socket.timeout,ConnectionRefusedError):pass"
 run('ip','netns','exec',client,sys.executable,'-c',code);counts=snapshot();assert counts['rejected']['packets']==1,counts
 print('PASS wrong-interface escape rejected before accounting')
 print(json.dumps({'passed':5,'counters':counts},sort_keys=True))
finally:
 if proc:
  proc.terminate()
  try:proc.wait(timeout=3)
  except subprocess.TimeoutExpired:proc.kill();proc.wait()
 for ns in(client,server):subprocess.run(['ip','netns','del',ns],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
