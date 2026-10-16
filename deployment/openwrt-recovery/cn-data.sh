#!/bin/sh
# Owns only the CN generations, cn4/cn6 contents and the C resolver restart.
# Download, validation and staging never change live data. Caller may already
# hold the DNS deployment lock; the data lock must always be acquired second.
set -eu
umask 077
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
initdir=${DIVERSION_DNS_INITDIR:-/etc/init.d}
binary=${DIVERSION_CN_BINARY:-/usr/sbin/diversion-dns-c}
store="$base/cn-data"
engine="$base/cn-data.lua"
if [ "${DIVERSION_CN_DEPLOY_LOCK_HELD:-0}" != 1 ]; then
 lock=${DIVERSION_DNS_LOCK:-/var/lock/diversion-dns-deploy.lock}
 exec 9>"$lock"
 flock 9
fi
# Startup verification can run recursively from reload_cn -> init while this
# process owns data lock 7. It is read-only and serialized by deployment lock 9.
if [ "${1:-}" != check-start ]; then
 mkdir -p "$store/generations"
 exec 7>"$store/lock"
 flock 7
fi
say() { printf '%s\n' "$*"; }
log() { logger -t diversion-cn-data "$*"; }
valid_id() { case "$1" in ''|*[!0-9a-f]*) return 1;; esac; [ "${#1}" -eq 64 ]; }
current_id() {
 target=$(readlink "$store/${1:-current}" 2>/dev/null || true)
 case "$target" in generations/*) id=${target#generations/};; *) return 1;; esac
 valid_id "$id" || return 1
 printf '%s\n' "$id"
}
point() {
 valid_id "$2" || return 1
 rm -f "$store/.$1.$$" || return 1
 ln -s "generations/$2" "$store/.$1.$$" || return 1
 mv -fT "$store/.$1.$$" "$store/$1" || return 1
 sync || return 1
}
links() {
 for file in cn-ip.txt cn-site.txt sets.nft; do
  wanted="cn-data/current/$file"
  [ "$(readlink "$base/$file" 2>/dev/null || true)" = "$wanted" ] && continue
  rm -f "$base/.$file.$$" || return 1
  ln -s "$wanted" "$base/.$file.$$" || return 1
  mv -fT "$base/.$file.$$" "$base/$file" || return 1
 done
 sync || return 1
}
regular_generation() {
 [ -d "$1" ] && [ ! -L "$1" ] || return 1
 for regular_file in manifest.tsv cn-ip.txt cn-site.txt sets.nft replace.nft ranges4.txt ranges6.txt; do
  [ -f "$1/$regular_file" ] && [ ! -L "$1/$regular_file" ] || return 1
 done
}
verified() {
 regular_generation "$store/generations/$1" || return 1
 manifest_hash=$(sha256sum "$store/generations/$1/manifest.tsv" | cut -d ' ' -f 1)
 valid_id "$manifest_hash" || return 1
 rescue_hash=$(printf '%s bootstrap\n' "$manifest_hash" | sha256sum | cut -d ' ' -f 1)
 [ "$1" = "$manifest_hash" ] || [ "$1" = "$rescue_hash" ] || return 1
 lua "$engine" verify "$store/generations/$1" >/dev/null
}
ensure_previous() {
 # A restored previous can become current. Replenish its independent standby
 # before reporting recovery complete; otherwise the next corruption has no
 # usable backup. Only the verified active content can authorize a new copy.
 sp_active=$1
 valid_id "$sp_active" && verified "$sp_active" || return 1
 sp_previous=$(current_id previous 2>/dev/null || true)
 if [ -n "$sp_previous" ] && [ "$sp_previous" != "$sp_active" ] && verified "$sp_previous"; then return 0; fi
 sp_manifest=$(sha256sum "$store/generations/$sp_active/manifest.tsv" | cut -d ' ' -f 1)
 sp_peer=$sp_manifest
 if [ "$sp_active" = "$sp_manifest" ]; then
  sp_peer=$(printf '%s bootstrap\n' "$sp_manifest" | sha256sum | cut -d ' ' -f 1)
 fi
 valid_id "$sp_peer" && [ "$sp_peer" != "$sp_active" ] || return 1
 if ! verified "$sp_peer"; then
  sp_draft=$(mktemp -d "$store/.standby.XXXXXX") || return 1
  if ! cp -Rp "$store/generations/$sp_active/." "$sp_draft/" ||
     ! regular_generation "$sp_draft" ||
     [ "$(sha256sum "$sp_draft/manifest.tsv" | cut -d ' ' -f 1)" != "$sp_manifest" ] ||
     ! lua "$engine" verify "$sp_draft" >/dev/null || ! verified "$sp_active"; then
   rm -rf "$sp_draft"; return 1
  fi
  sync || { rm -rf "$sp_draft"; return 1; }
  if [ -e "$store/generations/$sp_peer" ] || [ -L "$store/generations/$sp_peer" ]; then
   [ ! -L "$store/quarantine" ] && mkdir -p "$store/quarantine" || { rm -rf "$sp_draft"; return 1; }
   sp_bad=$(mktemp -d "$store/quarantine/damaged.XXXXXX") || { rm -rf "$sp_draft"; return 1; }
   printf '%s\n' "$sp_peer" > "$sp_bad/original-id" || { rm -rf "$sp_draft"; return 1; }
   mv "$store/generations/$sp_peer" "$sp_bad/generation" || { rm -rf "$sp_draft"; return 1; }
   sync || { rm -rf "$sp_draft"; return 1; }
  fi
  # Same-filesystem rename publishes a fully verified copy. A crash before this
  # point leaves active intact; the next audit retries these same two slot IDs.
  mv "$sp_draft" "$store/generations/$sp_peer" || { rm -rf "$sp_draft"; return 1; }
  sync || return 1
  verified "$sp_peer" || return 1
 fi
 point previous "$sp_peer" || return 1
 log "independent CN standby retained for $sp_active as $sp_peer"
}
reload_cn() {
 if [ -f "$base/degraded" ] && [ ! -d "$base/recovering" ]; then
  log "CN files repaired/updated; resolver restart deferred while DNS is held degraded"
  return 0
 fi
 # The legacy init applies policy before starting C. Validate managed policy
 # BEFORE restart stops the current resolver, including standalone activate and
 # journal recovery calls. This process already owns the deployment lock; pass
 # it through rather than recursively acquiring a second lock descriptor.
 policy_store="$base/cn-policy"
 if [ -e "$policy_store/enabled" ] || [ -L "$policy_store/enabled" ] ||
    [ -e "$policy_store/current" ] || [ -L "$policy_store/current" ] ||
    [ -d "$policy_store/generations" ]; then
  if [ ! -x "$base/cn-policy.sh" ]; then
   log "CRITICAL: managed policy verifier missing; refusing C restart"
   return 1
  fi
  if ! DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-policy.sh" audit-runtime; then
   log "CRITICAL: managed policy unverified; keeping C running and CN transaction for retry"
   return 1
  fi
 fi
 # The custom probe is only allowed in an isolated test layout.
 DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$initdir/diversion-dns-c" restart || return 1
 if [ "$base" != /etc/diversion-dns-c ] && [ -n "${DIVERSION_CN_TEST_PROBE:-}" ]; then
  "$DIVERSION_CN_TEST_PROBE"; return $?
 fi
 port=${DIVERSION_DNS_C_PORT:-15363}
 for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if lua "$base/dns-probe.lua" 127.0.0.1 "$port" www.baidu.com A positive >/dev/null 2>&1; then break; fi
  [ "$attempt" -lt 10 ] || return 1
  sleep 1
 done
 for type in A AAAA; do
  lua "$base/dns-probe.lua" 127.0.0.1 "$port" www.baidu.com "$type" positive >/dev/null 2>&1 || return 1
 done
}
check_config() {
 generation=$1
 [ -f "$base/config.conf" ] || return 1
 cfg="$store/.check-config.$$"
 # Match the exact owned path; leave additional operator domain files intact.
 awk -v old="cn_domain_file=$base/cn-site.txt" -v new="cn_domain_file=$generation/cn-site.txt" '
  $0 == old { print new; found=1; next } { print }
  END { if (!found) exit 1 }
 ' "$base/config.conf" > "$cfg" || { rm -f "$cfg"; return 1; }
 if "$binary" check -c "$cfg"; then rm -f "$cfg"; else rm -f "$cfg"; return 1; fi
}
stage() {
 [ "$#" -eq 4 ] || return 2
 baseline=-
 if old=$(current_id); then verified "$old" || return 1; baseline="$store/generations/$old"; fi
 draft=$(mktemp -d "$store/.stage.XXXXXX")
 if ! lua "$engine" prepare "$1" "$2" "$base/sets.nft" "$baseline" "$draft" "$3" "$4" > "$draft/result.json"; then
  rm -rf "$draft"; return 1
 fi
 if ! check_config "$draft" > "$draft/config-check.log" 2>&1; then
  cat "$draft/config-check.log" >&2; rm -rf "$draft"; return 1
 fi
 # The ID binds every payload hash recorded by the engine.
 new=$(sha256sum "$draft/manifest.tsv" | cut -d ' ' -f 1)
 valid_id "$new" || { rm -rf "$draft"; return 1; }
 if [ -d "$store/generations/$new" ]; then
  verified "$new" || { rm -rf "$draft"; return 1; }
  rm -rf "$draft"
 else
  mv "$draft" "$store/generations/$new"
 fi
 sync
 printf '%s\n' "$new"
}
restore_pending() {
 [ -f "$store/pending" ] || return 0
 read -r prior next < "$store/pending" || return 1
 valid_id "$prior" && valid_id "$next" && verified "$prior" || return 1
 point current "$prior" || return 1
 links || return 1
 lua "$engine" repair "$store/generations/$prior" || return 1
 reload_cn || return 1
 ensure_previous "$prior" || return 1
 rm -f "$store/pending" || return 1
 sync || return 1
 log "interrupted/failed CN activation restored generation $prior"
}
finish_repair() {
 [ -f "$store/repair-pending" ] || return 0
 repair_id=$(cat "$store/repair-pending") || return 1
 valid_id "$repair_id" && verified "$repair_id" || return 1
 point current "$repair_id" || return 1
 links || return 1
 lua "$engine" repair "$store/generations/$repair_id" || return 1
 reload_cn || return 1
 ensure_previous "$repair_id" || return 1
 rm -f "$store/repair-pending" || return 1
 sync || return 1
 log "CN file/snapshot repair completed, resolver synchronized"
}
begin_repair() {
 valid_id "$1" && verified "$1" || return 1
 printf '%s\n' "$1" > "$store/.repair-pending.$$" || return 1
 mv "$store/.repair-pending.$$" "$store/repair-pending" || return 1
 sync || return 1
 finish_repair
}
activate() {
 [ "$#" -eq 1 ] && valid_id "$1" || return 2
 [ ! -d "$base/recovering" ] || return 75
 activation_target=$1
 verified "$activation_target" || return 1
 check_config "$store/generations/$activation_target" || return 1
 restore_pending || return 1
 finish_repair || return 1
 next=$activation_target
 prior=$(current_id) || return 1
 verified "$prior" || return 1
 [ "$prior" != "$next" ] || { audit; return $?; }
 printf '%s %s\n' "$prior" "$next" > "$store/.pending.$$" || return 1
 mv "$store/.pending.$$" "$store/pending" || return 1
 sync || return 1
 if lua "$engine" repair "$store/generations/$next" && point current "$next" && links && reload_cn; then
  point previous "$prior" || return 1
  ensure_previous "$next" || return 1
  rm -f "$store/pending" || return 1
  sync || return 1
  log "CN generation activated $next; previous $prior retained"
 else
  log "CN activation failed; restoring previous generation"
  restore_pending || { log "CRITICAL: CN transaction still requires recovery"; return 1; }
  return 1
 fi
}
audit() {
 [ ! -d "$base/recovering" ] || return 75
 restore_pending || return 1
 finish_repair || return 1
 active=$(current_id 2>/dev/null || true)
 if [ -z "$active" ] || ! verified "$active"; then
  old=$(current_id previous) && verified "$old" || { log "CRITICAL: no verified CN generation available"; return 1; }
  log "active CN snapshot or pointer unavailable; restoring previous verified generation"
  begin_repair "$old" || return 1
  active=$old
 fi
 changed=0
 for file in cn-ip.txt cn-site.txt sets.nft; do
  if [ "$(readlink "$base/$file" 2>/dev/null || true)" != "cn-data/current/$file" ]; then changed=1; fi
 done
 if [ "$changed" -eq 1 ]; then begin_repair "$active" || return 1; fi
 result=0
 lua "$engine" audit "$store/generations/$active" || result=$?
 case "$result" in
  0) ;;
  2) lua "$engine" repair "$store/generations/$active" || return 1; log "restored CN-IP kernel contents from verified generation";;
  *) return 1;;
 esac
 ensure_previous "$active" || return 1
}
case "${1:-}" in
 check-start)
  [ "$#" -eq 1 ] || exit 2
  startup_id=$(current_id) || exit 1
  verified "$startup_id" || exit 1
  for file in cn-ip.txt cn-site.txt sets.nft; do
   [ "$(readlink "$base/$file" 2>/dev/null || true)" = "cn-data/current/$file" ] || exit 1
  done
  printf '%s\n' 'CN startup data verified';;
 stage) shift; stage "$@";;
 seed)
  shift; [ "$#" -eq 2 ] || exit 2
  if current_id >/dev/null 2>&1; then audit; exit $?; fi
  new=$(stage "$base/cn-ip.txt" "$base/cn-site.txt" "$1" "$2")
  lua "$engine" audit "$store/generations/$new"
  # Keep original regular files for uninstall, and a separate verified copy
  # for recovery before the first successful update creates a previous version.
  mkdir -p "$store/bootstrap"
  for file in cn-ip.txt cn-site.txt sets.nft; do
   [ -e "$store/bootstrap/$file" ] || cp -p "$base/$file" "$store/bootstrap/$file"
  done
  ensure_previous "$new"
  sync
  : > "$store/enabled"
  sync
  point current "$new"
  links
  lua "$engine" audit "$store/generations/$new"
  log "adopted verified CN generation $new";;
 activate) shift; activate "$@";;
 rollback) [ ! -d "$base/recovering" ] || exit 75; restore_pending; old=$(current_id previous); activate "$old";;
 reconcile) [ ! -d "$base/recovering" ] || exit 75; restore_pending; finish_repair;;
 audit-runtime)
  uptime_file=/proc/uptime
  if [ "$base" != /etc/diversion-dns-c ]; then uptime_file=${DIVERSION_CN_TEST_UPTIME:-$uptime_file}; fi
  read -r uptime rest < "$uptime_file"; tick=${uptime%%.*}
  runtime=${DIVERSION_DNS_RUN:-/var/run/diversion-dns-recovery}; mkdir -p "$runtime"
  last=$(cat "$runtime/cn-audit-time" 2>/dev/null || echo 0)
  case "$last" in ''|*[!0-9]*) last=0;; esac
  interval=${DIVERSION_CN_AUDIT_INTERVAL:-60}
  case "$interval" in ''|*[!0-9]*) exit 2;; esac
  if [ "${2:-}" != --force ] && [ ! -f "$store/pending" ] && [ ! -f "$store/repair-pending" ] && [ "$last" -le "$tick" ] && [ $((tick-last)) -lt "$interval" ]; then exit 0; fi
  audit
  printf '%s\n' "$tick" > "$runtime/cn-audit-time";;
 fetch)
  shift; [ "$#" -eq 4 ] || exit 2
  case "$1" in https://*) ;; *) exit 2;; esac
  case "$2" in https://*) ;; *) exit 2;; esac
  tmp=$(mktemp -d "$store/.download.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT HUP INT TERM
  # No automatic activation: a successfully downloaded candidate must still
  # pass full staging and then an explicit activation with rollback.
  for kind in ip site; do
   if [ "$kind" = ip ]; then url=$1; else url=$2; fi
   if command -v curl >/dev/null 2>&1; then
    curl --fail --location --proto '=https' --proto-redir '=https' --connect-timeout 10 --max-time 60 --max-filesize 8388608 -o "$tmp/$kind" "$url"
   else
    (ulimit -f 8192; timeout 60 wget -T 10 -O "$tmp/$kind" "$url")
   fi
   [ "$(wc -c < "$tmp/$kind")" -le 8388608 ] || exit 1
  done
  stage "$tmp/ip" "$tmp/site" "$3" "$4";;
 *) say 'usage: cn-data.sh check-start | seed IP_SHA SITE_SHA | stage IP SITE IP_SHA SITE_SHA | activate ID | rollback | reconcile | audit-runtime [--force] | fetch HTTPS_IP HTTPS_SITE IP_SHA SITE_SHA' >&2; exit 2;;
esac
