#!/bin/sh
# OpenWrt preflight only. No network requests, service changes, rule application,
# or route changes. nft -c validates a transaction without applying it.
set -eu
controller=${1:-/usr/libexec/pnw-control}
case "$controller" in /*) ;; *) exit 2;; esac
lua - "$controller" <<'LUA'
local path=arg[1]
assert(loadfile(path),'controller syntax failed')
local n=require('nixio')
for _,name in ipairs({'gettimeofday','setgid','setuid','exec'}) do assert(type(n[name])=='function','missing nixio '..name) end
print('Lua syntax and required nixio APIs passed')
LUA
command -v lua
command -v uclient-fetch
sha256sum "$controller" /etc/pnw-control/emergency.nft
nft list chain inet diversion_dns router_output | sed -n '1,5p'
ip -4 route show table 100 default
ip -6 route show table 100 default
if [ -n "$(uci changes network)" ] || [ -n "$(uci changes dhcp)" ]; then
 printf '%s\n' 'FAIL: uncommitted network/DHCP edits present (contents omitted)'
 exit 1
fi
if awk -F: '$3==65533 {found=1} END {exit !found}' /etc/passwd; then
 printf '%s\n' 'FAIL: probe UID 65533 is assigned'
 exit 1
fi
for p in /proc/[0-9]*/status; do
 if awk '$1=="Uid:" {for(i=2;i<=NF;i++) if($i==65533) found=1} END {exit !found}' "$p" 2>/dev/null; then
  printf '%s\n' 'FAIL: probe UID 65533 is in use'
  exit 1
 fi
done
if nft list table inet pnw_control_preflight >/dev/null 2>&1; then
 printf '%s\n' 'FAIL: preflight table name is already owned; refusing check'
 exit 1
fi
nft -c -f - <<'NFT'
table inet pnw_control_preflight {
 chain local {
  type filter hook output priority -129; policy accept;
  meta skuid 65533 ip daddr { 1.1.1.1, 1.0.0.1 } tcp dport 443 accept
  meta skuid 65533 ip6 daddr { 2606:4700:4700::1111, 2606:4700:4700::1001 } tcp dport 443 accept
  meta skuid 0 ip daddr { 1.1.1.1, 8.8.8.8 } udp dport 53 accept
  meta skuid 0 ip daddr { 1.1.1.1, 8.8.8.8 } tcp dport 53 accept
  meta mark 1 drop
 }
 chain probe_mark {
  type route hook output priority -128; policy accept;
  meta skuid 65533 ip daddr { 1.1.1.1, 1.0.0.1 } tcp dport 443 meta mark set 1
  meta skuid 65533 ip6 daddr { 2606:4700:4700::1111, 2606:4700:4700::1001 } tcp dport 443 meta mark set 1
  meta skuid 0 ip daddr { 1.1.1.1, 8.8.8.8 } udp dport 53 meta mark set 1
  meta skuid 0 ip daddr { 1.1.1.1, 8.8.8.8 } tcp dport 53 meta mark set 1
 }
}
delete table inet pnw_control_preflight
table inet pnw_control_preflight {
 chain local { type filter hook output priority -129; policy accept; meta mark 1 drop; }
}
NFT
if nft list table inet pnw_control_preflight >/dev/null 2>&1; then
 printf '%s\n' 'FAIL: nft check unexpectedly left a table'
 exit 1
fi
printf '%s\n' 'PASS: read-only preflight; active emergency switching remains untested by this script'
