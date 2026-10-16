#!/bin/sh
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
. "$base/common.sh"
exec 9>"$lock"
flock -n 9 || exit 75
mode=${1:-manual}
case "$mode" in manual|--automatic|--reconcile) ;; *) exit 2;; esac
[ -f "$base/active" ] || exit 1

if [ -d "$base/recovering" ]; then
 restore_transaction
 exit $?
fi
[ "$mode" != --reconcile ] || exit 0
[ -f "$base/degraded" ] || exit 0
if [ "$mode" = --automatic ]; then
 [ -f "$base/recovery-auto" ] || exit 1
 [ "$(cat "$base/recovery-auto")" = service-health ] || exit 1
fi

# Snapshot before starting C; the switching marker precedes the first mutation.
mkdir "$base/recovering" || exit 1
committed=0
cleanup() {
 rc=$?
 trap - EXIT HUP INT TERM
 if [ "$committed" -eq 0 ]; then restore_transaction || rc=1; fi
 exit "$rc"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
uci -q get 'dhcp.@dnsmasq[0].server' > "$base/recovering/servers" || exit 1
uci -q get 'dhcp.@dnsmasq[0].cachesize' > "$base/recovering/cachesize" || exit 1
[ -s "$base/recovering/servers" ] || exit 1
printf '%s\n' "$mode" > "$base/recovering/mode" || exit 1
sync || exit 1
# The durable transaction permits C after reboot too. Client DNS stays on ISP.
"$initdir/diversion-dns-c" start || exit 1
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 if probe 127.0.0.1 "$c_port" health.diversion-dns-c.qq.com A allow-response; then ready=1; break; fi
 sleep 1
done
[ "$ready" -eq 1 ] || exit 1
for round in 1 2 3; do
 upstream_health "$c_port" nonce "$round" cn || exit 1
 [ "$round" -eq 3 ] || sleep 10
done

: > "$base/recovering/switching" || exit 1
sync || exit 1
set_dns "127.0.0.1#$c_port" 0 || exit 1
upstream_health "$dns_port" nonce final cn || exit 1
upstream_health "$dns_port" fixed final cn || exit 1
rm -f "$base/degraded" || exit 1
sync || exit 1
retire_transaction || exit 1
rm -f "$base/recovery-auto"
committed=1
sync
date > "$base/recovered"
log "C DNS recovered after three healthy CN A/AAAA rounds; CN-site learning active"
foreign_health_tick force
