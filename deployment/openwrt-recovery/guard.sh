#!/bin/sh
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
. "$base/common.sh"
startup=120; interval=20
once=0
if [ "${1:-}" = --once ] && [ "$base" != /etc/diversion-dns-c ]; then once=1; startup=0; fi
# Interrupted switchovers are reconciled promptly, including after reboot.
[ ! -d "$base/recovering" ] || startup=0
[ "$startup" -eq 0 ] || sleep "$startup"
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
 healthy=1
 for chain in classify split guard router_output router_guard dns_redirect; do
  if ! nft list chain inet diversion_dns "$chain" >/dev/null 2>&1; then healthy=0; break; fi
 done
 for set in vpn_clients4 vpn_clients6; do
  if ! nft list set inet diversion_dns "$set" >/dev/null 2>&1; then healthy=0; break; fi
 done
 if [ "$healthy" = 0 ]; then
  log "owned policy missing: repairing"
  if "$base/apply-policy.sh"; then healthy=1
  else "$base/enable-rescue.sh" || log "CRITICAL: emergency protection failed"; fi
 fi
 "$base/refresh-monitor.sh" || log "monitor exception refresh failed; previous sets retained"
 if [ -d "$base/recovering" ]; then
  # A running recover owns this lock, so any transaction visible here is stale.
  action=reconcile
 elif [ -f "$base/degraded" ]; then
  bad=0
  probe 127.0.0.1 53 localhost A || log "degraded local DNS not responding"
  if [ "$healthy" = 1 ] && [ -f "$base/recovery-auto" ] && [ "$(cat "$base/recovery-auto")" = service-health ]; then
   if schedule_recovery "$tick"; then action=recover; fi
  fi
 else
  if [ "$healthy" = 1 ] && upstream_health 15363 nonce guard && upstream_health 53 nonce client; then
   bad=0; normal_tick "$tick"
  else
   bad=$((bad+1)); recovery_stable=0; save_state
  fi
  if [ "$bad" -ge 3 ]; then action=fallback; bad=0; fi
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
