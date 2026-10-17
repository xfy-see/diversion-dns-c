#!/bin/sh
# Independent procd watchdog; never respawns/restarts the experiment.
# Usage: openwrt-realflow-lease.sh BASE PHASE SECONDS
umask 077
rf_script_dir=$(dirname "$(readlink -f "$0")")
REALFLOW_LIB_ONLY=1
. "$rf_script_dir/openwrt-realflow-run.sh"
unset REALFLOW_LIB_ONLY
[ "$#" -eq 3 ] || exit 2
rf_validate "$1" "$2" || exit 2
[ -x "$rf_base/bin/realflow-bounded" ] && [ ! -L "$rf_base/bin/realflow-bounded" ] || exit 2
rf_duration=$3
case "$rf_duration" in ''|*[!0-9]*|0*) exit 2;; esac
[ "${#rf_duration}" -le 6 ] && [ "$rf_duration" -ge 10 ] && [ "$rf_duration" -le 86400 ] || exit 2
rf_table || exit 2
rf_wait_start=$(rf_uptime)
while [ ! -f "$rf_run/main.identity" ] || [ ! -f "$rf_run/started.monotonic" ]; do
 if [ "$(rf_uptime)" -ge "$((rf_wait_start+120))" ]; then
  mkdir -p "$rf_run" || exit 1
  rf_log 'watchdog main_did_not_start'
  printf '%s\n' 'main_did_not_start' > "$rf_run/watchdog-aborted"
  rf_stop_owned;rf_delete_table
  exit 1
 fi
 sleep 2
done
rf_start=$(cat "$rf_run/started.monotonic")
case "$rf_start" in ''|*[!0-9]*) exit 2;; esac
rf_deadline=$((rf_start+rf_duration+120))
rf_log "watchdog_started deadline_monotonic=$rf_deadline"
while :; do
 if [ -f "$rf_run/finished" ]; then
  rf_left=0
  for rf_name in a b capture runner; do if rf_recorded_alive "$rf_name"; then rf_left=1;fi;done
  if [ "$rf_left" -eq 0 ]; then
   rf_table_exists;rf_exists=$?
   case "$rf_exists" in 0) rf_watch_reason=owned_table_after_completion;break;; 2) rf_watch_reason=nft_query_failed_after_completion;break;; esac
   rf_log 'watchdog_normal_completion';exit 0
  fi
  rf_watch_reason=owned_process_after_completion;break
 fi
 if ! rf_match main; then rf_watch_reason=main_exited_without_completion;break;fi
 if [ "$(rf_uptime)" -ge "$rf_deadline" ]; then rf_watch_reason=watchdog_hard_deadline;break;fi
 sleep 10
done
rf_log "watchdog_abort $rf_watch_reason"
printf '%s\n' "$rf_watch_reason" > "$rf_run/watchdog-aborted"
# TERM main first so its EXIT trap can collect state; every signal is guarded
# by the immutable executable path plus recorded /proc starttime.
rf_signal main TERM
rf_stop_owned
rf_main_until=$(($(rf_uptime)+20))
while rf_match main && [ "$(rf_uptime)" -lt "$rf_main_until" ]; do sleep 1;done
if rf_match main; then printf 'main %s\n' "$(cat "$rf_run/main.identity")" >> "$rf_run/forced_kill";rf_signal main KILL;fi
rf_delete_table
rf_timeout sha256sum -c "$rf_base/protected.sha256" > "$rf_run/protected-watchdog.txt" 2>&1 || true
exit 1
