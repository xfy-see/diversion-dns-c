#!/bin/sh
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
. "$base/common.sh"
startup=120; interval=20
if [ "$base" != /etc/diversion-dns-c ]; then
 startup=${DIVERSION_DNS_GUARD_STARTUP:-120}; interval=${DIVERSION_DNS_GUARD_INTERVAL:-20}
 valid_uint "$startup" && valid_uint "$interval" && [ "$startup" -le 3600 ] &&
  [ "$interval" -gt 0 ] && [ "$interval" -le 300 ] || exit 2
fi
once=0
if [ "${1:-}" = --once ] && [ "$base" != /etc/diversion-dns-c ]; then once=1; startup=0; fi
# Interrupted switchovers are reconciled promptly, including after reboot.
[ ! -d "$base/recovering" ] || startup=0
[ ! -f "$base/cn-data/pending" ] || startup=0
[ ! -f "$base/cn-data/repair-pending" ] || startup=0
[ "$startup" -eq 0 ] || sleep "$startup"
owned_policy_present() {
 for chain in classify split guard router_output router_guard dns_redirect; do
  nft list chain inet "$policy_table" "$chain" >/dev/null 2>&1 || return 1
 done
 for set in vpn_clients4 vpn_clients6; do
  nft list set inet "$policy_table" "$set" >/dev/null 2>&1 || return 1
 done
}
bad=0
exec 9>"$lock"
while [ -f "$base/active" ]; do
 if ! flock -n 9; then
  [ "$once" -eq 0 ] || exit 75
  sleep "$interval"; continue
 fi
 read_state
 tick=$(now_seconds)
 action=
 # The data wrapper takes its own lock second. Never overlap a durable DNS
 # switchover, including an interrupted one which must be reconciled first.
 # A data repair failure is an alert, not a reason to stop CN-site learning.
 if [ ! -d "$base/recovering" ] && managed_cn_data_enabled; then
  if [ ! -x "$base/cn-data.sh" ] ||
     ! DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-data.sh" audit-runtime; then
   log "CRITICAL: CN data verifier missing or repair failed; keeping DNS service available"
  fi
 fi
 healthy=1
 if [ ! -d "$base/recovering" ]; then
  policy_managed=0
  if managed_policy_enabled; then
   policy_managed=1
   if [ ! -x "$base/cn-policy.sh" ] ||
      ! DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-policy.sh" audit-runtime; then healthy=0; fi
  fi
  if [ "$healthy" = 1 ] && ! owned_policy_present; then
   log "owned policy missing: repairing"
   if [ "$policy_managed" = 1 ]; then
    DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-policy.sh" audit-runtime --repair && owned_policy_present || healthy=0
   else
    verify_managed_data && "$base/apply-policy.sh" && owned_policy_present || healthy=0
   fi
  fi
  if [ "$healthy" = 0 ]; then
   log "CRITICAL: policy repair unverified; preserving C and enabling emergency containment"
   "$base/enable-rescue.sh" || log "CRITICAL: emergency protection failed"
  fi
 fi
 "$base/refresh-monitor.sh" || log "monitor exception refresh failed; previous sets retained"
 if [ -d "$base/recovering" ]; then
  # A running recover owns this lock, so any transaction visible here is stale.
  action=reconcile
 elif [ -f "$base/degraded" ]; then
  bad=0
  probe 127.0.0.1 "$dns_port" localhost A || log "degraded local DNS not responding"
  if [ "$healthy" = 1 ] && [ -f "$base/recovery-auto" ] && [ "$(cat "$base/recovery-auto")" = service-health ]; then
   if schedule_recovery "$tick"; then action=recover; fi
  fi
 else
  if probe 127.0.0.1 "$dns_port" localhost A &&
     upstream_health "$c_port" nonce guard cn && upstream_health "$dns_port" nonce client cn; then
   bad=0; normal_tick "$tick"
   foreign_health_tick
  else
   bad=$((bad+1)); recovery_stable=0; save_state
  fi
  if [ "$bad" -ge 3 ]; then
   # The legacy fallback helper reapplies policy. Never let it bypass a failed
   # managed policy verification, even when CN DNS is also unhealthy.
   if [ "$healthy" = 1 ]; then action=fallback
   else log "CRITICAL: CN DNS unhealthy but policy unsafe; withholding legacy fallback"; fi
   bad=0
  fi
 fi
 flock -u 9
 case "$action" in
  recover|reconcile)
   if [ "$action" = recover ]; then arg=--automatic; else arg=--reconcile; fi
   log "DNS auto-recovery action=$action attempt=$recovery_failures"
   "$base/recover.sh" "$arg"; result=$?
   if [ "$result" -ne 75 ]; then
    flock 9
    read_state
    record_recovery_result "$result" "$(now_seconds)"
    flock -u 9
    # Repairing an interrupted transaction is urgent, with a bounded retry
    # pause if local DNS/config restoration itself fails.
    if [ "$action" = reconcile ] && [ "$result" -ne 0 ] && [ "$once" -eq 0 ]; then sleep 60; fi
   fi;;
  fallback) "$base/rollback.sh" service-health || log "CRITICAL: DNS fallback failed";;
 esac
 [ "$once" -eq 0 ] || break
 sleep "$interval"
done
