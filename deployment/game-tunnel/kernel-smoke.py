#!/usr/bin/env python3
"""Real nft parser/kernel regression. Only run inside an explicitly owned netns."""
import argparse,json,os,subprocess
from pathlib import Path
import integrate

def run(args,**kw):return subprocess.run(args,check=True,capture_output=True,text=True,**kw)
def main():
 p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 assert os.geteuid()==0 and os.environ.get('DIVERSION_OWNED_NETNS')=='1','owned root network namespace required'
 assert not a.output.exists(),'preserve previous evidence'
 assert subprocess.run(['nft','list','table','inet','diversion_dns'],capture_output=True).returncode!=0,'table already exists'
 header='add table inet diversion_dns\n'
 for name,spec in [('cn4','ipv4_addr'),('game_enabled','inet_proto'),('game_site4','ipv4_addr'),('game_site6','ipv6_addr'),('game_relay4','ipv4_addr . inet_service; flags interval; auto-merge'),('game_cm4','ipv4_addr . inet_service')]:
  header+=f'add set inet diversion_dns {name} {{ type {spec}; }}\n'
 policy=''.join(f'add chain inet diversion_dns {c}\nadd rule inet diversion_dns {c} ip daddr @cn4 return\n'for c in ('split','router_output'))
 data=header+integrate.policy(policy);result={'passed':False,'scope':'complete two-chain nft parser and kernel installation; no production routes'}
 try:
  run(['nft','-c','-f','-'],input=data)
  run(['nft','-f','-'],input=data)
  for enabled in (True,False):
   batch='flush set inet diversion_dns game_enabled\n'
   if enabled:batch+='add element inet diversion_dns game_enabled { tcp, udp }\n'
   run(['nft','-f','-'],input=batch)
  saved=json.loads(run(['nft','-j','list','table','inet','diversion_dns']).stdout)
  rules=[r['rule']for r in saved['nftables']if 'rule'in r]
  assert len(rules)==12 and sum('comment'in r for r in rules)==10
  result.update(passed=True,rules=len(rules),game_rules=10)
 finally:
  subprocess.run(['nft','delete','table','inet','diversion_dns'],capture_output=True)
  a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(result,indent=2)+'\n')
 print(json.dumps(result))
if __name__=='__main__':main()
