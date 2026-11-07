#!/bin/sh
umask 077
mkdir -p /var/run/pnw-dota-egress
while :;do
 (flock -n 9 || exit 0
 export DIVERSION_CN_DEPLOY_LOCK_HELD=1
 lua -e 'dofile("/etc/pnw-control/dota-egress.lua").tick(false)'
 ) 9>/var/lock/diversion-dns-deploy.lock
 sleep 5
done
