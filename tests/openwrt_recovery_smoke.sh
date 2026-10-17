#!/bin/sh
# BusyBox ash fixture: fake services only. Keep the output directory as evidence.
set -eu
[ "$#" -eq 1 ] || { echo "usage: $0 /tmp/diversion-recovery-smoke-NAME" >&2; exit 2; }
root=$1
case "$root" in /tmp/diversion-recovery-smoke-*) ;; *) echo "unsafe test root" >&2; exit 2;; esac
case "${root#/tmp/}" in */*|*..*) echo "unsafe test root" >&2; exit 2;; esac
[ ! -e "$root" ] && [ ! -L "$root" ] || { echo "test root already exists" >&2; exit 2; }
command -v flock >/dev/null || { echo "real flock required" >&2; exit 2; }
source_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../deployment/openwrt-recovery" && pwd -P)
[ -f "$source_dir/recover.sh" ] && [ -f "$source_dir/common.sh" ] || exit 2
mkdir -m 700 "$root"
cat > "$root/double" <<'MOCK'
#!/bin/sh
set -eu
r=$RECOVERY_TEST_ROOT
case "$r" in /tmp/diversion-recovery-smoke-*/*) ;; *) exit 98;; esac
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$r/calls"
case "$name" in
 uci)
  [ "${1:-}" != -q ] || shift
  op=$1; arg=${2:-}; key=${arg%%=*}; value=${arg#*=}
  case "$key" in 'dhcp.@dnsmasq[0].server') f=servers;; 'dhcp.@dnsmasq[0].cachesize') f=cache;; dhcp) f=unused;; *) exit 97;; esac
  case "$op" in
   get) cat "$r/$f";;
   delete) : > "$r/$f";;
   add_list) old=$(cat "$r/$f"); printf '%s\n' "${old:+$old }$value" > "$r/$f";;
   set) printf '%s\n' "$value" > "$r/$f";;
   commit) n=$(cat "$r/commits"); n=$((n+1)); echo "$n" > "$r/commits"
    [ ! -f "$r/fail-commit" ] || [ "$(cat "$r/fail-commit")" != "$n" ] || exit 1;;
   *) exit 97;;
  esac;;
 lua)
  # script, host, port, question, qtype, mode
  port=$3; domain=$4; qtype=$5; mode=${6:-}
  if [ "$port" = 15363 ] && [ "$mode" = health ] && [ -d "$r/base/recovering" ]; then
   case "$domain" in *.qq.com)
    [ "$(cat "$r/servers")" = '192.0.2.53 198.51.100.53' ] || exit 96
    echo "$domain $qtype" >> "$r/preflight";;
   esac
  fi
  if [ -f "$r/fail-probe" ]; then
   read -r fp suffix ft fm < "$r/fail-probe"
   if [ "$port" = "$fp" ] && [ "$qtype" = "$ft" ] && [ "$mode" = "$fm" ]; then
    case "$domain" in *"$suffix") exit 1;; esac
   fi
  fi;;
 diversion-dns-c)
  case "$1" in
   start) [ -s "$r/base/recovering/servers" ] && [ -s "$r/base/recovering/cachesize" ] || exit 96
    [ -f "$r/base/degraded" ] || exit 96; echo 1 > "$r/running";;
   stop) echo 0 > "$r/running";;
   *) exit 97;;
  esac;;
 dnsmasq) [ "$1" = restart ] || exit 97
  n=$(cat "$r/restarts"); echo "$((n+1))" > "$r/restarts";;
 logger|sleep|sync|nft) :;;
 *) exit 97;;
esac
MOCK
chmod 700 "$root/double"
original_path=$PATH
fail() { echo "FAIL $case_name: $*" >&2; exit 1; }
eq() { [ "$(cat "$r/$1")" = "$2" ] || fail "$1 expected $2"; }
exists() { [ -e "$r/$1" ] || fail "missing $1"; }
absent() { [ ! -e "$r/$1" ] || fail "unexpected $1"; }
setup() {
 case_name=$1; r=$root/$case_name
 mkdir -p "$r/base" "$r/run" "$r/init" "$r/bin"
 for f in common.sh recover.sh rollback.sh guard.sh dns-probe.lua; do cp "$source_dir/$f" "$r/base/$f"; done
 for f in uci lua logger sleep sync nft; do cp "$root/double" "$r/bin/$f"; done
 for f in diversion-dns-c dnsmasq; do cp "$root/double" "$r/init/$f"; done
 for f in apply-policy.sh refresh-monitor.sh enable-rescue.sh; do printf '#!/bin/sh\nexit 0\n' > "$r/base/$f"; done
 cat > "$r/base/dns-mode.sh" <<'FALLBACK'
fallback_dns() { : > "$DIVERSION_DNS_BASE/degraded"; }
FALLBACK
 chmod 700 "$r/base/"*.sh "$r/bin/"* "$r/init/"*
 printf '%s\n' '192.0.2.53 198.51.100.53' > "$r/servers"
 echo 1500 > "$r/cache"
 for f in running commits restarts; do echo 0 > "$r/$f"; done
 : > "$r/calls"; : > "$r/preflight"; : > "$r/base/active"; : > "$r/base/degraded"
 echo service-health > "$r/base/recovery-auto"
 export RECOVERY_TEST_ROOT=$r DIVERSION_DNS_BASE=$r/base DIVERSION_DNS_RUN=$r/run
 export DIVERSION_DNS_INITDIR=$r/init DIVERSION_DNS_LOCK=$r/lock PATH=$r/bin:$original_path
}
recover_ok() { /bin/sh "$r/base/recover.sh" "${1:---automatic}" > "$r/output" 2>&1 || fail "unexpected recovery failure"; }
recover_fail() { if /bin/sh "$r/base/recover.sh" --automatic > "$r/output" 2>&1; then fail "unexpected recovery success"; fi; }
original_dns() { eq servers '192.0.2.53 198.51.100.53'; eq cache 1500; }
pass() { echo "PASS $case_name"; }
setup success
recover_ok
eq servers '127.0.0.1#15363'; eq cache 0; eq running 1; eq restarts 1
absent base/degraded; absent base/recovering; absent base/recovery-auto; exists base/recovered
[ "$(wc -l < "$r/preflight" | tr -d ' ')" = 6 ] || fail 'three complete preflight rounds required'
for suffix in qq.com; do
 for kind in A AAAA; do
  [ "$(grep -c "$suffix $kind$" "$r/preflight")" = 3 ] || fail "missing rounds for $suffix $kind"
 done
done
pass
for suffix in qq.com; do
 for kind in A AAAA; do
  setup "failed-$suffix-$kind"
  echo "15363 $suffix $kind health" > "$r/fail-probe"
  recover_fail; original_dns; eq running 0; eq restarts 0; eq commits 0
  exists base/degraded; absent base/recovering; pass
 done
done
for kind in A AAAA; do
 setup "foreign-unavailable-$kind"
 echo "15363 example.com $kind health" > "$r/fail-probe"
 recover_ok; eq servers '127.0.0.1#15363'; eq cache 0; eq running 1; eq restarts 1
 absent base/degraded; absent base/recovering; exists run/foreign-degraded; pass
done
setup manual-hold
rm "$r/base/recovery-auto"
/bin/sh "$r/base/guard.sh" --once > "$r/output" 2>&1 || fail 'guard failed'
recover_fail; original_dns; eq running 0; eq restarts 0; absent base/recovering
if grep -q '^diversion-dns-c ' "$r/calls"; then fail 'manual hold started C'; fi
pass
setup unknown-hold
echo unknown > "$r/base/recovery-auto"
recover_fail; original_dns; eq running 0; eq restarts 0; absent base/recovering
if grep -q '^diversion-dns-c ' "$r/calls"; then fail 'unknown hold started C'; fi
pass
setup final-probe-failed
echo '53 qq.com AAAA health' > "$r/fail-probe"
recover_fail; original_dns; eq running 0; eq restarts 2; exists base/degraded; absent base/recovering; pass
setup restoration-failed
echo '53 qq.com AAAA health' > "$r/fail-probe"; echo 2 > "$r/fail-commit"
recover_fail; eq running 1; exists base/recovering/switching; exists base/degraded
rm "$r/fail-probe" "$r/fail-commit"
recover_ok --reconcile; original_dns; eq running 0; absent base/recovering; pass
setup persisted-transaction
mkdir "$r/base/recovering"
cp "$r/servers" "$r/base/recovering/servers"; cp "$r/cache" "$r/base/recovering/cachesize"
: > "$r/base/recovering/switching"
echo '127.0.0.1#15363' > "$r/servers"; echo 0 > "$r/cache"; echo 1 > "$r/running"
/bin/sh "$r/base/guard.sh" --once > "$r/output" 2>&1 || fail 'guard reconciliation failed'
original_dns; eq running 0; eq restarts 1; exists base/degraded; absent base/recovering; pass
setup foreign-guard-outage
rm "$r/base/degraded" "$r/base/recovery-auto"
echo '127.0.0.1#15363' > "$r/servers"; echo 0 > "$r/cache"; echo 1 > "$r/running"
echo '15363 example.com A health' > "$r/fail-probe"
/bin/sh "$r/base/guard.sh" --once > "$r/output" 2>&1 || fail 'guard failed'
eq servers '127.0.0.1#15363'; eq running 1; eq restarts 0; eq commits 0
exists run/foreign-degraded; absent base/degraded; absent base/recovery-auto
if grep -q '^diversion-dns-c ' "$r/calls"; then fail 'foreign outage changed C service'; fi
pass
case_name=foreign-guard-recovery
rm "$r/fail-probe" "$r/run/foreign-state"
/bin/sh "$r/base/guard.sh" --once >> "$r/output" 2>&1 || fail 'guard recovery failed'
eq servers '127.0.0.1#15363'; eq running 1; eq restarts 0; eq commits 0
absent run/foreign-degraded; absent base/degraded; absent base/recovery-auto; pass
printf 'PASS all 12 isolated BusyBox shell scenarios; evidence: %s\n' "$root"
