#!/bin/sh
# Overlay for the existing diversion-dns-c OpenWrt deployment, not an APK init.
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
run=${DIVERSION_DNS_RUN:-/var/run/diversion-dns-recovery}
initdir=${DIVERSION_DNS_INITDIR:-/etc/init.d}
lock=${DIVERSION_DNS_LOCK:-/var/lock/diversion-dns-deploy.lock}
umask 077
mkdir -p "$run" || exit 1
set -f

now_seconds() { read -r seconds rest < /proc/uptime; printf '%s\n' "${seconds%%.*}"; }
boot_id() { cat /proc/sys/kernel/random/boot_id; }
valid_uint() {
 case "$1" in ''|*[!0-9]*) return 1;; esac
 [ "${#1}" -le 10 ] || return 1
 case "$1" in 0|[1-9]*) return 0;; *) return 1;; esac
}
log() { logger -t diversion-dns-c "$*"; }
probe() { lua "$base/dns-probe.lua" "$@" >/dev/null 2>&1; }

read_state() {
 recovery_failures=0; recovery_next=0; recovery_stable=0
 recovery_boot=$(boot_id)
 if [ -f "$run/state" ]; then
  read -r b f n s < "$run/state" || return 0
  valid_uint "$f" && valid_uint "$n" && valid_uint "$s" || return 0
  current=$(now_seconds)
  if [ "$b" = "$recovery_boot" ] && [ "$f" -le 5 ] && [ "$n" -le $((current+900)) ] && [ "$s" -le "$current" ]; then
   recovery_failures=$f; recovery_next=$n; recovery_stable=$s
  fi
 fi
}
save_state() {
 printf '%s %s %s %s\n' "$recovery_boot" "$recovery_failures" "$recovery_next" "$recovery_stable" > "$run/state.$$" && mv "$run/state.$$" "$run/state"
}
recovery_delay() {
 case "$recovery_failures" in 0|1) echo 60;; 2) echo 120;; 3) echo 240;; 4) echo 480;; *) echo 900;; esac
}
schedule_recovery() {
 tick=$1
 recovery_stable=0
 if [ "$recovery_next" -eq 0 ]; then
  delay=$(recovery_delay); [ "$delay" -ge 120 ] || delay=120
  recovery_next=$((tick+delay)); save_state; return 1
 fi
 [ "$tick" -ge "$recovery_next" ] || return 1
 [ "$recovery_failures" -ge 5 ] || recovery_failures=$((recovery_failures+1))
 recovery_next=$((tick+$(recovery_delay)))
 save_state
}
record_recovery_result() {
 if [ "$1" -eq 0 ]; then recovery_next=0; recovery_stable=$2
 else recovery_next=$(($2+$(recovery_delay))); recovery_stable=0; fi
 save_state
}
normal_tick() {
 [ "$recovery_stable" -ne 0 ] || recovery_stable=$1
 if [ $(($1-recovery_stable)) -ge 600 ]; then recovery_failures=0; fi
 recovery_next=0; save_state
}

# Fresh questions avoid a healthy cache masking a failed upstream. These suffixes
# must be classified CN/foreign respectively by the installed domain files.
upstream_health() {
 health_port=$1
 health_mode=${2:-nonce}
 health_nonce="r-$(now_seconds)-$$-${3:-0}"
 for health_domain in qq.com example.com; do
  for health_type in A AAAA; do
   if [ "$health_mode" = nonce ]; then
    health_name="$health_nonce-$(printf '%s' "$health_type" | tr A-Z a-z).$health_domain"
    probe 127.0.0.1 "$health_port" "$health_name" "$health_type" health || return 1
   else
    if [ "$health_domain" = qq.com ]; then health_name=www.baidu.com; else health_name=$health_domain; fi
    probe 127.0.0.1 "$health_port" "$health_name" "$health_type" positive || return 1
   fi
  done
 done
}

set_dns() {
 dns_servers=$1; dns_cache=$2
 uci -q delete 'dhcp.@dnsmasq[0].server' || true
 for dns_server in $dns_servers; do
  uci add_list "dhcp.@dnsmasq[0].server=$dns_server" || return 1
 done
 uci set "dhcp.@dnsmasq[0].cachesize=$dns_cache" || return 1
 uci commit dhcp || return 1
 "$initdir/dnsmasq" restart || return 1
 # procd starts dnsmasq asynchronously. Never treat its startup gap as failure.
 sleep 1
 for dns_attempt in 1 2 3 4 5 6 7 8 9 10; do
  if probe 127.0.0.1 53 localhost A; then return 0; fi
  sleep 1
 done
 return 1
}

# A durable transaction makes interrupted switchovers recoverable after reboot.
# Only these two owned dnsmasq settings are restored; no entire UCI file import.
retire_transaction() {
 retired=$(mktemp -d "$base/.recovery-retired.XXXXXX") || return 1
 rmdir "$retired" || return 1
 mv "$base/recovering" "$retired" || return 1
 sync || return 1
 # Once renamed, a signal or a partial cleanup must never roll back DNS again.
 rm -rf "$retired" || log "retired recovery evidence could not be removed: $retired"
}
restore_transaction() {
 [ -d "$base/recovering" ] || return 0
 if [ -f "$base/recovering/switching" ]; then
  old_servers=$(cat "$base/recovering/servers") || return 1
  old_cache=$(cat "$base/recovering/cachesize") || return 1
  [ -n "$old_servers" ] || return 1
  case "$old_cache" in ''|*[!0-9]*) return 1;; esac
  if ! set_dns "$old_servers" "$old_cache"; then
   log "CRITICAL: fallback restoration incomplete; keeping C running and recovery transaction for retry"
   return 1
  fi
 fi
 date > "$base/degraded" || return 1
 sync
 "$initdir/diversion-dns-c" stop || return 1
 retire_transaction || return 1
 log "recovery aborted; previous DNS configuration retained/restored"
}
