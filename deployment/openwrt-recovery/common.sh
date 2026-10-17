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
# Isolated validation instances can use alternate ports without touching the
# production listeners. Production deliberately ignores these test overrides.
c_port=15363; dns_port=53; policy_table=diversion_dns
if [ "$base" != /etc/diversion-dns-c ]; then
 c_port=${DIVERSION_DNS_C_PORT:-15363}; dns_port=${DIVERSION_DNS_FRONTEND_PORT:-53}
 policy_table=${DIVERSION_DNS_POLICY_TABLE:-diversion_dns}
 case "$policy_table" in ''|*[!A-Za-z0-9_]*|[0-9]*) exit 2;; esac
 [ "${#policy_table}" -le 64 ] || exit 2
 valid_uint "$c_port" && valid_uint "$dns_port" &&
  [ "$c_port" -gt 0 ] && [ "$c_port" -le 65535 ] &&
  [ "$dns_port" -gt 0 ] && [ "$dns_port" -le 65535 ] || exit 2
fi
log() { logger -t diversion-dns-c "$*"; }
probe() { lua "$base/dns-probe.lua" "$@" >/dev/null 2>&1; }

# Missing marker(s) must not turn an existing managed generation into an
# unmanaged policy. This also fails closed on partial/failed policy adoption.
managed_cn_data_enabled() {
 [ -e "$base/cn-data/enabled" ] || [ -L "$base/cn-data/enabled" ] ||
 [ -e "$base/cn-data/current" ] || [ -L "$base/cn-data/current" ] ||
 [ -d "$base/cn-data/generations" ] ||
 [ -e "$base/cn-data/pending" ] || [ -L "$base/cn-data/pending" ] ||
 [ -e "$base/cn-data/repair-pending" ] || [ -L "$base/cn-data/repair-pending" ]
}
managed_policy_enabled() {
 [ -e "$base/cn-policy/enabled" ] || [ -L "$base/cn-policy/enabled" ] ||
 [ -e "$base/cn-policy/current" ] || [ -L "$base/cn-policy/current" ] ||
 [ -d "$base/cn-policy/generations" ]
}
verify_managed_data() {
 managed_cn_data_enabled || return 0
 if [ ! -x "$base/cn-data.sh" ] ||
    ! DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-data.sh" check-start; then
  log "CRITICAL: managed CN data unverified; refusing policy application"
  return 1
 fi
}
verify_managed_policy() {
 managed_policy_enabled || return 0
 if [ ! -x "$base/cn-policy.sh" ]; then
  log "CRITICAL: managed policy verifier missing; refusing resolver activation"
  return 1
 fi
 DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-policy.sh" audit-runtime || {
  log "CRITICAL: managed policy unverified; refusing resolver activation"
  return 1
 }
}

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
# CN and foreign health are deliberately separate: a tunnel outage must never
# stop the C resolver or the CN-site learning it provides.
upstream_health() {
 health_port=$1
 health_mode=${2:-nonce}
 health_nonce="r-$(now_seconds)-$$-${3:-0}"
 case "${4:-all}" in
  cn) health_domains=qq.com;;
  foreign) health_domains=example.com;;
  all) health_domains='qq.com example.com';;
  *) return 2;;
 esac
 for health_domain in $health_domains; do
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

# Volatile, independent foreign health/backoff. This function never changes DNS,
# stops C, or arms whole-service recovery. A cold foreign probe may time out, so
# run it only AFTER the CN/client checks. Failed probes back off to five minutes;
# CN/client checks remain active throughout the outage.
foreign_health_tick() {
 foreign_now=$(now_seconds)
 foreign_boot=$(boot_id)
 foreign_failures=0; foreign_next=0
 if [ -f "$run/foreign-state" ]; then
  if read -r foreign_b foreign_f foreign_n < "$run/foreign-state" &&
     valid_uint "$foreign_f" && valid_uint "$foreign_n" &&
     [ "$foreign_b" = "$foreign_boot" ] && [ "$foreign_f" -le 5 ] &&
     [ "$foreign_n" -le $((foreign_now+300)) ]; then
   foreign_failures=$foreign_f; foreign_next=$foreign_n
  fi
 fi
 if [ "${1:-}" != force ] && [ "$foreign_now" -lt "$foreign_next" ]; then return 0; fi
 if upstream_health "$c_port" nonce foreign-c foreign && upstream_health "$dns_port" nonce foreign-client foreign; then
  foreign_failures=0; foreign_delay=20
  if [ -f "$run/foreign-degraded" ]; then
   rm -f "$run/foreign-degraded" || log "could not clear foreign degradation status"
   log "foreign DNS recovered; CN service and dnsmasq unchanged"
  fi
 else
  [ "$foreign_failures" -ge 5 ] || foreign_failures=$((foreign_failures+1))
  case "$foreign_failures" in 1) foreign_delay=20;; 2) foreign_delay=40;; 3) foreign_delay=80;; 4) foreign_delay=160;; *) foreign_delay=300;; esac
  if [ ! -f "$run/foreign-degraded" ]; then
   printf '%s %s\n' "$foreign_boot" "$foreign_now" > "$run/foreign-degraded.$$" &&
    mv "$run/foreign-degraded.$$" "$run/foreign-degraded" || log "could not persist foreign degradation status"
   log "foreign DNS unavailable; preserving CN DNS, CN-site learning and dnsmasq"
  fi
 fi
 # Use completion time: a timeout must not consume its own retry backoff.
 foreign_next=$(($(now_seconds)+foreign_delay))
 printf '%s %s %s\n' "$foreign_boot" "$foreign_failures" "$foreign_next" > "$run/foreign-state.$$" &&
  mv "$run/foreign-state.$$" "$run/foreign-state" || log "could not persist foreign health backoff"
 return 0
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
  if probe 127.0.0.1 "$dns_port" localhost A; then return 0; fi
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
