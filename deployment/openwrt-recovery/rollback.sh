#!/bin/sh
base=${DIVERSION_DNS_BASE:-/etc/diversion-dns-c}
. "$base/common.sh"
exec 9>"$lock"
flock 9
# Manual/unknown fallback is held. Automatic recovery must not undo an operator.
rm -f "$base/recovery-auto"
. "$base/dns-mode.sh"
fallback_dns || exit 1
if [ -d "$base/recovering" ]; then retire_transaction || exit 1; fi
if [ "${1:-manual}" = service-health ]; then
 printf '%s\n' service-health > "$base/recovery-auto"
fi
sync
