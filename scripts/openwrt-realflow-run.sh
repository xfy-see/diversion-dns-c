#!/bin/sh
# OpenWrt ash supervisor. It owns only BASE/runs/PHASE processes and BASE/table-name.
# Usage: openwrt-realflow-run.sh BASE PHASE SECONDS off|tuned
# Pair with an independent procd instance running openwrt-realflow-lease.sh.
# No package installation, production DNS/routing changes or cgroup mutations.

rf_uptime() { awk '{ split($1,a,"."); print a[1] }' /proc/uptime; }
rf_proc_start() { awk '{ sub(/^.*\) /, ""); print $20 }' "/proc/$1/stat" 2>/dev/null; }
rf_exe() { readlink -f "/proc/$1/exe" 2>/dev/null; }
rf_valid_token() { case "$1" in ''|*[!A-Za-z0-9_-]*) return 1;; esac; [ "${#1}" -le 64 ]; }
rf_validate() {
 rf_base=$1
 case "$rf_base" in /data/dns-ab24-20261015-*) ;; *) return 1;; esac
 rf_id=${rf_base#/data/dns-ab24-20261015-}
 rf_valid_token "$rf_id" || return 1
 [ ! -L "$rf_base" ] && [ -d "$rf_base" ] || return 1
 [ "$(readlink -f "$rf_base")" = "$rf_base" ] || return 1
 [ -f "$rf_base/OWNERSHIP" ] && [ ! -L "$rf_base/OWNERSHIP" ] || return 1
 [ "$(cat "$rf_base/OWNERSHIP")" = "$rf_id" ] || return 1
 RF_OWNER_FILE="$rf_base/OWNERSHIP" lua -e 'local s=require("nixio.fs").stat(os.getenv("RF_OWNER_FILE")); if not s or s.uid~=0 then os.exit(1) end' || return 1
 rf_phase=$2;rf_valid_token "$rf_phase" || return 1
 rf_run=$rf_base/runs/$rf_phase
 [ ! -L "$rf_base/runs" ] && [ ! -L "$rf_run" ] || return 1
 return 0
}
rf_timeout() { env GOMAXPROCS=1 GOMEMLIMIT=32MiB "$rf_base/bin/realflow-bounded" -seconds 5 -- "$@"; }
rf_lua() { env GOMAXPROCS=1 GOMEMLIMIT=32MiB "$rf_base/bin/realflow-bounded" -seconds 10 -- lua "$@"; }
rf_table() {
 [ -f "$rf_base/table-name" ] && [ ! -L "$rf_base/table-name" ] || return 1
 rf_table_name=$(cat "$rf_base/table-name")
 case "$rf_table_name" in dns_ab24_*) ;; *) return 1;; esac
 case "$rf_table_name" in *[!A-Za-z0-9_]*|'') return 1;; esac
 [ "${#rf_table_name}" -le 63 ] || return 1
 return 0
}
rf_expected_exe() {
 case "$1" in a) printf '%s/bin/dns-a\n' "$rf_base";; b) printf '%s/bin/dns-b\n' "$rf_base";; capture) printf '%s/bin/realflow-capture\n' "$rf_base";; runner) printf '%s/bin/realflow-runner\n' "$rf_base";; *) return 1;; esac
}
rf_match() {
 local rf_name=$1 rf_pid rf_start rf_savedexe rf_extra rf_nowexe
 [ -f "$rf_run/$rf_name.identity" ] && [ ! -L "$rf_run/$rf_name.identity" ] || return 1
 read -r rf_pid rf_start rf_savedexe rf_extra < "$rf_run/$rf_name.identity" || return 1
 case "$rf_pid:$rf_start" in *[!0-9:]*|:*|*:) return 1;; esac
 [ "$rf_pid" -gt 1 ] && [ -z "$rf_extra" ] || return 1
 [ "$(cat "$rf_run/$rf_name.pid" 2>/dev/null)" = "$rf_pid" ] || return 1
 [ "$(rf_proc_start "$rf_pid")" = "$rf_start" ] || return 1
 rf_nowexe=$(rf_exe "$rf_pid");[ -n "$rf_nowexe" ] && [ "$rf_nowexe" = "$rf_savedexe" ] || return 1
 if [ "$rf_name" = main ]; then
  tr '\000' '\n' < "/proc/$rf_pid/cmdline" | grep -F -x "$rf_script_dir/openwrt-realflow-run.sh" >/dev/null || return 1
 else [ "$rf_nowexe" = "$(rf_expected_exe "$rf_name")" ] || return 1
 fi
 # Zombies cannot receive a signal and are not running owned work.
 [ "$(awk '{ sub(/^.*\) /, ""); print $1 }' "/proc/$rf_pid/stat" 2>/dev/null)" != Z ] || return 1
 return 0
}
rf_record() {
 local rf_name=$1 rf_pid=$2 rf_expected=$3 rf_n=0 rf_actual rf_start
 case "$rf_pid" in ''|*[!0-9]*) return 1;; esac
 printf '%s\n' "$rf_pid" > "$rf_run/$rf_name.pid"
 while [ "$rf_n" -lt 10 ]; do
  rf_actual=$(rf_exe "$rf_pid");rf_start=$(rf_proc_start "$rf_pid")
  if [ "$rf_actual" = "$rf_expected" ] && [ -n "$rf_start" ]; then
   printf '%s %s %s\n' "$rf_pid" "$rf_start" "$rf_actual" > "$rf_run/$rf_name.identity.tmp"
   mv "$rf_run/$rf_name.identity.tmp" "$rf_run/$rf_name.identity"
   return 0
  fi
  kill -0 "$rf_pid" 2>/dev/null || return 1
  sleep 1;rf_n=$((rf_n+1))
 done
 return 1
}
rf_signal() {
 local rf_name=$1 rf_sig=$2 rf_pid
 rf_match "$rf_name" || return 0
 rf_pid=$(cat "$rf_run/$rf_name.pid")
 kill "-$rf_sig" "$rf_pid" 2>/dev/null || true
}
rf_recorded_alive() {
 local rf_name=$1 rf_pid rf_start rf_savedexe rf_extra
 [ -f "$rf_run/$rf_name.identity" ] || return 1
 read -r rf_pid rf_start rf_savedexe rf_extra < "$rf_run/$rf_name.identity" || return 1
 case "$rf_pid:$rf_start" in *[!0-9:]*|:*|*:) return 1;; esac
 [ "$rf_pid" -gt 1 ] && [ "$(rf_proc_start "$rf_pid")" = "$rf_start" ] || return 1
 [ "$(awk '{ sub(/^.*\) /, ""); print $1 }' "/proc/$rf_pid/stat" 2>/dev/null)" != Z ]
}
rf_stop_owned() {
 local rf_n rf_left rf_until
 for rf_n in capture runner a b; do rf_signal "$rf_n" TERM; done
 rf_until=$(($(rf_uptime)+20))
 while :; do
  rf_left=0
  for rf_n in capture runner a b; do if rf_recorded_alive "$rf_n"; then rf_left=1;fi;done
  [ "$rf_left" -eq 0 ] && return 0
  [ "$(rf_uptime)" -lt "$rf_until" ] || break
  sleep 1
 done
 # A hard kill means trace/evidence buffers might not have been flushed. Record
 # it explicitly and report failed cleanup even when the process then vanishes.
 for rf_n in capture runner a b; do
  if rf_match "$rf_n"; then
   printf '%s %s\n' "$rf_n" "$(cat "$rf_run/$rf_n.identity")" >> "$rf_run/forced_kill"
   rf_signal "$rf_n" KILL
  fi
 done
 sleep 1
 return 1
}
rf_table_exists() {
 local rf_tables
 rf_tables=$(rf_timeout nft list tables 2> "$rf_run/nft-enumeration.stderr.log") || return 2
 printf '%s\n' "$rf_tables" | grep -F -x "table inet $rf_table_name" >/dev/null
}
rf_delete_table() {
 local rf_saved_table=$rf_table_name rf_exists
 rf_table || return 1
 [ -z "$rf_saved_table" ] || [ "$rf_saved_table" = "$rf_table_name" ] || return 1
 rf_table_exists;rf_exists=$?
 case "$rf_exists" in
  0) rf_timeout nft delete table inet "$rf_table_name" >> "$rf_run/nft-cleanup.log" 2>&1 || return 1;;
  1) return 0;;
  *) return 1;;
 esac
 rf_table_exists;[ "$?" -eq 1 ]
}
rf_log() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*" >> "$rf_run/supervisor.log"; }

# Lease sources only the functions above; it cannot accidentally start a phase.
if [ "${REALFLOW_LIB_ONLY:-}" = 1 ]; then return 0; fi

umask 077
rf_script_dir=$(dirname "$(readlink -f "$0")")
[ "$#" -eq 4 ] || { echo 'usage: openwrt-realflow-run.sh BASE PHASE SECONDS off|tuned' >&2;exit 2; }
rf_validate "$1" "$2" || { echo 'invalid task ownership/path' >&2;exit 2; }
rf_duration=$3;rf_mode=$4
case "$rf_duration" in ''|*[!0-9]*|0*) echo 'invalid duration' >&2;exit 2;; esac
[ "${#rf_duration}" -le 6 ] && [ "$rf_duration" -ge 10 ] && [ "$rf_duration" -le 86400 ] || exit 2
case "$rf_mode" in off) rf_bconf=$rf_base/configs/b-off.conf;; tuned) rf_bconf=$rf_base/configs/b.conf;; *) exit 2;; esac
rf_table || { echo 'invalid owned nft table marker' >&2;exit 2; }
[ -s "$rf_base/protected.sha256" ] && [ ! -L "$rf_base/protected.sha256" ] || exit 2
for rf_input in "$rf_base/bin/dns-a" "$rf_base/bin/dns-b" "$rf_base/bin/realflow-capture" "$rf_base/bin/realflow-runner" "$rf_base/bin/realflow-bounded" "$rf_base/configs/a.conf" "$rf_bconf" "$rf_base/sites.json" "$rf_script_dir/openwrt-realflow-metrics.lua"; do
 [ -f "$rf_input" ] && [ ! -L "$rf_input" ] || { echo 'missing/symlink input' >&2;exit 2; }
done
for rf_binary in dns-a dns-b realflow-capture realflow-runner realflow-bounded; do [ -x "$rf_base/bin/$rf_binary" ] || exit 2; done
mkdir -p "$rf_base/runs" || exit 2
mkdir "$rf_run" || { echo 'phase output must be new' >&2;exit 2; }
chmod 700 "$rf_base" "$rf_base/runs" "$rf_run"
rf_state=aborted;rf_reason=setup_failed;rf_cleaned=0;rf_exit_code=1
rf_cleanup() {
 [ "$rf_cleaned" -eq 0 ] || return 0
 rf_cleaned=1
 trap - EXIT HUP INT TERM
 rf_log "cleanup state=$rf_state reason=$rf_reason"
 exec 9>&-
 rf_cleanup_ok=true
 rf_stop_owned || { rf_cleanup_ok=false;rf_state=aborted;rf_reason=owned_cleanup_incomplete; }
 rf_delete_table || { rf_cleanup_ok=false;rf_state=aborted;rf_reason=nft_cleanup_failed; }
 if ! rf_timeout sha256sum -c "$rf_base/protected.sha256" > "$rf_run/protected-after.txt" 2>&1; then rf_state=aborted;rf_reason=production_hash_changed;rf_cleanup_ok=false;fi
 if [ "$(cat /proc/sys/kernel/random/boot_id)" != "$(cat "$rf_run/boot-id")" ]; then rf_state=aborted;rf_reason=boot_id_changed;rf_cleanup_ok=false;fi
 [ "$rf_cleanup_ok" = true ] || rf_exit_code=1
 printf '{"state":"%s","reason":"%s","cleanup_ok":%s,"finished_unix_s":%s}\n' "$rf_state" "$rf_reason" "$rf_cleanup_ok" "$(date +%s)" > "$rf_run/outcome.json.tmp"
 mv "$rf_run/outcome.json.tmp" "$rf_run/outcome.json"
 printf '%s\n' "$rf_state" > "$rf_run/finished.tmp";mv "$rf_run/finished.tmp" "$rf_run/finished"
 rf_log "finished cleanup_ok=$rf_cleanup_ok"
}
rf_abort() { rf_reason=$1;rf_state=aborted;rf_exit_code=1;rf_log "abort $rf_reason";exit 1; }
trap 'rf_cleanup' EXIT
trap 'rf_reason=interrupted;rf_state=aborted;exit 1' HUP INT TERM
cat /proc/sys/kernel/random/boot_id > "$rf_run/boot-id"
[ ! -f "$rf_base/boot-id" ] || [ "$(cat "$rf_base/boot-id")" = "$(cat "$rf_run/boot-id")" ] || rf_abort preflight_boot_id_changed
printf '%s\n' "$(rf_uptime)" > "$rf_run/started.monotonic"
printf '%s\n' "$(date +%s)" > "$rf_run/started.unix"
printf '%s\n' "$rf_duration" > "$rf_run/duration"
printf '%s\n' "$rf_mode" > "$rf_run/mode"
rf_record main "$$" "$(rf_exe "$$")" || rf_abort main_identity_failed
rf_prod_pid=$(pidof diversion-dns-c)
case "$rf_prod_pid" in ''|*[!0-9]*) rf_abort production_dns_identity_unavailable;; esac
[ "$(rf_exe "$rf_prod_pid")" = /usr/sbin/diversion-dns-c ] || rf_abort production_dns_exe_changed
printf '%s %s %s\n' "$rf_prod_pid" "$(rf_proc_start "$rf_prod_pid")" /usr/sbin/diversion-dns-c > "$rf_run/production.identity"
rf_timeout sha256sum -c "$rf_base/protected.sha256" > "$rf_run/protected-before.txt" 2>&1 || rf_abort production_hash_preflight
rf_timeout nft list table inet "$rf_table_name" > "$rf_run/nft-before.txt" 2>&1 || rf_abort owned_table_missing
rf_timeout sha256sum "$rf_base/bin/dns-a" "$rf_base/bin/dns-b" "$rf_base/bin/realflow-capture" "$rf_base/bin/realflow-runner" "$rf_base/bin/realflow-bounded" "$rf_base/configs/a.conf" "$rf_bconf" "$rf_base/sites.json" "$rf_base/OWNERSHIP" "$rf_base/table-name" "$rf_base/protected.sha256" "$rf_script_dir/openwrt-realflow-run.sh" "$rf_script_dir/openwrt-realflow-lease.sh" "$rf_script_dir/openwrt-realflow-metrics.lua" > "$rf_run/inputs.sha256" || rf_abort input_hash_failed
rf_timeout sha256sum "$rf_base"/rules/*.txt "$rf_run/production.identity" >> "$rf_run/inputs.sha256" || rf_abort rule_hash_failed
rf_interval=900
if [ -f "$rf_base/https-interval" ]; then rf_interval=$(cat "$rf_base/https-interval");case "$rf_interval" in ''|*[!0-9]*|0*) rf_abort invalid_https_interval;; esac;[ "${#rf_interval}" -le 5 ] && [ "$rf_interval" -ge 1 ] && [ "$rf_interval" -le 86400 ] || rf_abort invalid_https_interval;fi
rf_log "starting duration=$rf_duration mode=$rf_mode"
(
 ulimit -c 0 || exit 1;ulimit -v 131072 || exit 1
 exec env DIVERSION_TRACE="$rf_run/a.trace.tsv" nice -n 10 "$rf_base/bin/dns-a" start -c "$rf_base/configs/a.conf" --cpu 2
) > "$rf_run/a.stdout.log" 2> "$rf_run/a.stderr.log" &
rf_apid=$!;rf_record a "$rf_apid" "$rf_base/bin/dns-a" || rf_abort a_start_failed
(
 ulimit -c 0 || exit 1;ulimit -v 131072 || exit 1
 exec env DIVERSION_TRACE="$rf_run/b.trace.tsv" DIVERSION_CACHE_STATS=60 nice -n 10 "$rf_base/bin/dns-b" start -c "$rf_bconf" --cpu 2
) > "$rf_run/b.stdout.log" 2> "$rf_run/b.stderr.log" &
rf_bpid=$!;rf_record b "$rf_bpid" "$rf_base/bin/dns-b" || rf_abort b_start_failed
rf_ready=0;rf_try=0
while [ "$rf_try" -lt 30 ]; do
 rf_match a && rf_match b || rf_abort resolver_exited_before_listen
 if awk '$2=="0100007F:3C65" {a=1} $2=="0100007F:3C66" {b=1} END {exit !(a&&b)}' /proc/net/udp && awk '$2=="0100007F:3C65"&&$4=="0A" {a=1} $2=="0100007F:3C66"&&$4=="0A" {b=1} END {exit !(a&&b)}' /proc/net/tcp; then rf_ready=1;break;fi
 sleep 1;rf_try=$((rf_try+1))
done
[ "$rf_ready" -eq 1 ] || rf_abort listen_readiness_timeout
rf_log 'both resolvers have UDP sockets and TCP listeners; no warmup query sent'
mkfifo "$rf_run/capture.fifo" || rf_abort fifo_failed
# Open read/write in the parent so neither child can be stranded in FIFO open
# before exec/PID identity capture. Both children close this inherited fd first.
exec 9<> "$rf_run/capture.fifo" || rf_abort fifo_anchor_failed
printf '%s\n' "$(rf_uptime)" > "$rf_run/runner-launch.monotonic"
(
 exec 9>&-
 ulimit -c 0 || exit 1
 exec env GOMAXPROCS=1 GOMEMLIMIT=32MiB nice -n 10 "$rf_base/bin/realflow-runner" -a 127.0.0.1:15461 -b 127.0.0.1:15462 -duration "$rf_duration" -output "$rf_run/runner" -sites "$rf_base/sites.json" -https-interval "$rf_interval" -https-interface wg_vpn -https-mark 1 -dns-timeout 8 -max-inflight 32 -queue 256 < "$rf_run/capture.fifo"
) > "$rf_run/runner.stdout.log" 2> "$rf_run/runner.stderr.log" &
rf_rpid=$!
printf '%s\n' "$(rf_uptime)" > "$rf_run/capture-launch.monotonic"
(
 exec 9>&-
 ulimit -c 0 || exit 1
 exec env GOMAXPROCS=1 GOMEMLIMIT=32MiB nice -n 10 "$rf_base/bin/realflow-capture" -iface lo -dst-port 15363 -seconds "$((rf_duration+2))" -stats-seconds 30 > "$rf_run/capture.fifo"
) 2> "$rf_run/capture.stderr.log" &
rf_cpid=$!
rf_record capture "$rf_cpid" "$rf_base/bin/realflow-capture" || rf_abort capture_start_failed
rf_record runner "$rf_rpid" "$rf_base/bin/realflow-runner" || rf_abort runner_start_failed
exec 9>&-
printf '%s\n' "$(rf_uptime)" > "$rf_run/observation.monotonic"
printf '%s\n' "$(date +%s)" > "$rf_run/observation.unix"
rf_log 'observation_started'
rf_last_full=0
while :; do
 rf_now=$(rf_uptime)
 rf_started=$(cat "$rf_run/started.monotonic")
 [ "$rf_now" -lt "$((rf_started+rf_duration+120))" ] || rf_abort main_hard_deadline
 rf_match a && rf_match b || rf_abort resolver_exited
 [ "$(cat /proc/sys/kernel/random/boot_id)" = "$(cat "$rf_run/boot-id")" ] || rf_abort boot_id_changed
 rf_timeout sha256sum -c "$rf_base/protected.sha256" > "$rf_run/protected-current.txt" 2>&1 || rf_abort production_hash_changed
 rf_timeout sha256sum -c "$rf_run/inputs.sha256" > "$rf_run/inputs-current.txt" 2>&1 || rf_abort input_hash_changed
 read -r rf_prod_pid rf_prod_start rf_prod_exe < "$rf_run/production.identity" || rf_abort production_identity_unreadable
 [ "$(rf_proc_start "$rf_prod_pid")" = "$rf_prod_start" ] && [ "$(rf_exe "$rf_prod_pid")" = "$rf_prod_exe" ] || rf_abort production_dns_identity_changed
 [ ! -e /etc/diversion-dns-c/degraded ] && [ ! -e /etc/diversion-dns-c/recovering ] || rf_abort production_dns_degraded_or_recovering
 if ! rf_match runner; then
  rf_launch=$(cat "$rf_run/runner-launch.monotonic")
  [ "$rf_now" -ge "$((rf_launch+rf_duration))" ] || rf_abort runner_exited_early
  wait "$rf_rpid";rf_rc=$?
  [ "$rf_rc" -eq 0 ] || rf_abort runner_exit_nonzero
  rf_final=$(rf_lua "$rf_script_dir/openwrt-realflow-metrics.lua" --check-final "$rf_run/runner/final.json");rf_final_rc=$?
  case "$rf_final:$rf_final_rc" in complete:0) rf_state=completed;rf_reason=observation_finished;rf_exit_code=0;; incomplete:1) rf_state=incomplete;rf_reason=runner_incomplete;rf_exit_code=0;; *) rf_abort runner_final_invalid;; esac
  break
 fi
 if ! rf_match capture; then
  rf_launch=$(cat "$rf_run/capture-launch.monotonic")
  [ "$rf_now" -ge "$((rf_launch+rf_duration+2))" ] || rf_abort capture_exited_early
  wait "$rf_cpid";rf_rc=$?;[ "$rf_rc" -eq 0 ] || rf_abort capture_exit_nonzero
  : > "$rf_run/allow_capture_exit"
 fi
 if ! rf_lua "$rf_script_dir/openwrt-realflow-metrics.lua" "$rf_run" "$rf_base" --guard > "$rf_run/resources-current.json.tmp" 2> "$rf_run/metrics.stderr.log"; then
  mv "$rf_run/resources-current.json.tmp" "$rf_run/resources-current.json"
  cat "$rf_run/resources-current.json" >> "$rf_run/resources.jsonl"
  rf_abort resource_guard_failed
 fi
 mv "$rf_run/resources-current.json.tmp" "$rf_run/resources-current.json"
 if [ "$rf_last_full" -eq 0 ] || [ "$((rf_now-rf_last_full))" -ge 60 ]; then cat "$rf_run/resources-current.json" >> "$rf_run/resources.jsonl";rf_last_full=$rf_now;fi
 sleep 10
done
rf_log "observation_finished state=$rf_state"
rf_cleanup
exit "$rf_exit_code"
