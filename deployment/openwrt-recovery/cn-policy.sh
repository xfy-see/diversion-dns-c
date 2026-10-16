#!/bin/sh
# Adopt an explicitly approved policy, then restore only that policy's chains.
# Runtime audits never adopt drift as a new baseline. The existing apply helper
# owns its own policy lock; acquire deployment lock first, never policy lock here.
set -eu
umask 077
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
store="$base/cn-policy"
table=diversion_dns
if [ "$base" != /etc/diversion-dns-c ]; then table=${DIVERSION_DNS_POLICY_TABLE:-diversion_dns}; fi
case "$table" in ''|*[!A-Za-z0-9_]*|[0-9]*) exit 2;; esac
[ "${#table}" -le 64 ] || exit 2
if [ "${DIVERSION_CN_DEPLOY_LOCK_HELD:-0}" != 1 ]; then
 exec 9>"${DIVERSION_DNS_LOCK:-/var/lock/diversion-dns-deploy.lock}"
 flock 9
fi
chains='split classify guard router_output router_guard dns_redirect'
files='policy.nft helper.sha256 table split.chain classify.chain guard.chain router_output.chain router_guard.chain dns_redirect.chain'
mkdir -p "$store/generations"
temporary=
trap '[ -z "$temporary" ] || rm -rf "$temporary"' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
log() { logger -t diversion-cn-policy "$*"; }
valid_hash() { case "$1" in ''|*[!0-9a-f]*) return 1;; esac; [ "${#1}" -eq 64 ]; }
sha() { line=$(sha256sum "$1") || return 1; printf '%s\n' "${line%% *}"; }
current() {
 target=$(readlink "$store/current") || return 1
 case "$target" in generations/*) id=${target#generations/};; *) return 1;; esac
 valid_hash "$id" || return 1
 snapshot="$store/generations/$id"
}
verify() {
 [ -d "$snapshot" ] && [ ! -L "$snapshot" ] || return 1
 [ "$(sha "$snapshot/SHA256SUMS")" = "$id" ] || return 1
 [ "$(wc -l < "$snapshot/SHA256SUMS" | tr -d ' ')" = 9 ] || return 1
 for item in $files; do
  [ -f "$snapshot/$item" ] && [ ! -L "$snapshot/$item" ] || return 1
  expected=$(awk -v f="$item" '$2 == f && NF == 2 { print $1 }' "$snapshot/SHA256SUMS")
  valid_hash "$expected" && [ "$(sha "$snapshot/$item")" = "$expected" ] || return 1
 done
 [ "$(cat "$snapshot/table")" = "$table" ] || return 1
 valid_hash "$(cat "$snapshot/helper.sha256")" || return 1
}
helper_intact() { [ "$(sha "$base/apply-policy.sh")" = "$(cat "$snapshot/helper.sha256")" ]; }
helper_data_intact() {
 # The approved legacy helper reads sets.nft when recreating a missing table.
 # A prior failed data audit must not authorize that read. This also runs from
 # cn-data -> reload_cn with data lock 7 held: check-start is read-only, takes
 # no data lock, and inherits deployment lock 9 rather than acquiring it again.
 if [ -e "$base/cn-data/enabled" ] || [ -L "$base/cn-data/enabled" ] ||
    [ -e "$base/cn-data/current" ] || [ -L "$base/cn-data/current" ] ||
    [ -d "$base/cn-data/generations" ] ||
    [ -e "$base/cn-data/pending" ] || [ -L "$base/cn-data/pending" ] ||
    [ -e "$base/cn-data/repair-pending" ] || [ -L "$base/cn-data/repair-pending" ]; then
  if [ ! -x "$base/cn-data.sh" ] ||
     ! DIVERSION_CN_DEPLOY_LOCK_HELD=1 "$base/cn-data.sh" check-start; then
   log 'CRITICAL: managed CN data unverified; refusing approved policy helper'
   return 1
  fi
 fi
 return 0
}
capture() { nft -s -nn list chain inet "$table" "$1" > "$2"; }
nonempty_chain() {
 # Stateless output removes packet counters but retains rules. Do not adopt a
 # missing/empty critical chain as a valid recovery baseline.
 awk 'NF && $0 !~ /^[[:space:]]*(table |chain |type |[{}])/ { n++ } END { exit n == 0 }' "$1"
}
source_scope() {
 # This deployment uses one command per line; refuse unknown command/table/chain
 # declarations instead of silently broadening the approved helper's input.
 awk -v t="$table" '
  /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
  $1 != "add" || ($2 != "chain" && $2 != "rule") || $3 != "inet" || $4 != t { exit 1 }
  $5 !~ /^(split|classify|guard|router_output|router_guard|dns_redirect)$/ { exit 1 }
  $2 == "rule" && index($0, ";") { exit 1 }
  $2 == "chain" && index($0, "{") {
   tail=substr($0, index($0, "{"))
   # BusyBox awk rejects bare interval braces even when other awk variants
   # accept them as literals. Bracket expressions are portable ERE literals.
   if (tail !~ /^[{][[:space:]]*type (filter|route|nat) hook (prerouting|input|forward|output|postrouting|ingress) priority -?[0-9]+;[[:space:]]*policy (accept|drop);[[:space:]]*[}][[:space:]]*$/) exit 1
  }
  $2 == "chain" && !index($0, "{") && NF != 5 { exit 1 }
  { n++ } END { if (!n) exit 1 }
 ' "$1"
}
seed() {
 case "${1:-}" in ''|--replace) ;; *) return 2;; esac
 [ ! -e "$store/current" ] && [ ! -L "$store/current" ] || [ "${1:-}" = --replace ] || {
  log 'baseline already exists; explicit seed --replace required for approved policy changes'; return 1;
 }
 source_scope "$base/policy.nft" || return 1
 temporary=$(mktemp -d "$store/.seed.XXXXXX")
 cp "$base/policy.nft" "$temporary/policy.nft"
 sha "$base/apply-policy.sh" > "$temporary/helper.sha256"
 printf '%s\n' "$table" > "$temporary/table"
 for chain in $chains; do capture "$chain" "$temporary/$chain.chain"; nonempty_chain "$temporary/$chain.chain" || return 1; done
 # Fail if the approved input changed while its live signatures were captured.
 [ "$(sha "$base/policy.nft")" = "$(sha "$temporary/policy.nft")" ] || return 1
 [ "$(sha "$base/apply-policy.sh")" = "$(cat "$temporary/helper.sha256")" ] || return 1
 (cd "$temporary"; for item in $files; do sha256sum "$item"; done) > "$temporary/SHA256SUMS"
 id=$(sha "$temporary/SHA256SUMS"); valid_hash "$id" || return 1
 snapshot="$store/generations/$id"
 if [ -d "$snapshot" ]; then verify || return 1; rm -rf "$temporary"; else mv "$temporary" "$snapshot"; fi
 temporary=
 ln -s "generations/$id" "$store/.current.$$"
 mv -fT "$store/.current.$$" "$store/current"
 printf '%s\n' "$id" > "$store/enabled"
 sync
 log "adopted explicitly approved six-chain policy baseline $id"
}
audit() {
 current && verify || { log 'CRITICAL: policy baseline invalid; refusing untrusted repair'; return 1; }
 helper_intact || { log 'CRITICAL: approved apply-policy helper changed; refusing execution'; return 1; }
 temporary=$(mktemp -d "$store/.audit.XXXXXX")
 changed=0
 [ "${1:-}" != --repair ] || changed=1
 for chain in $chains; do
  if ! capture "$chain" "$temporary/$chain.chain" || ! cmp -s "$temporary/$chain.chain" "$snapshot/$chain.chain"; then changed=1; fi
 done
 if ! cmp -s "$base/policy.nft" "$snapshot/policy.nft"; then
  cp "$snapshot/policy.nft" "$base/.policy-restore.$$"
  chmod 600 "$base/.policy-restore.$$"
  mv -fT "$base/.policy-restore.$$" "$base/policy.nft"
  sync
  changed=1
 fi
 [ "$changed" -eq 1 ] || return 0
 # The helper applies a checked nft batch and refreshes its owned monitor/VPN
 # exceptions. It does not reload the global firewall or change DNS settings.
 helper_data_intact && helper_intact && "$base/apply-policy.sh" || return 1
 for chain in $chains; do
  capture "$chain" "$temporary/$chain.chain" && cmp -s "$temporary/$chain.chain" "$snapshot/$chain.chain" || {
   log "CRITICAL: policy repair verification failed for $chain"; return 1;
  }
 done
 cmp -s "$base/policy.nft" "$snapshot/policy.nft" || return 1
 log 'restored and verified six owned policy chains from approved baseline'
}
case "${1:-}" in
 seed) [ ! -d "$base/recovering" ] || exit 75; shift; seed "$@";;
 audit-runtime) shift; case "${1:-}" in ''|--repair) audit "${1:-}";; *) exit 2;; esac;;
 *) echo 'usage: cn-policy.sh seed [--replace] | audit-runtime [--repair]' >&2; exit 2;;
esac
