# Preserve direct connections across DNS address expiry

The fast DNS writer installs ordinary timeout sets. A routing rule which only
returns for a direct address will reclassify later packets when that address
expires. For a CN-site-only address outside static CN-IP, this can move an
existing TCP/WebSocket connection to the default tunnel and break it.

`scripts/pin-openwrt-direct-connections.py INPUT OUTPUT` transforms a local copy
of the known `mark-routing` generator. It updates exactly the IPv4/IPv6 rules
for `direct`, `geoip_direct` and `dns_direct`: save the configured bypass mark
in both the packet and conntrack mark, preserving unrelated bits. Existing
conntrack restore rules must remain before these classifiers. Already marked
tunnel flows keep their original route. New connections use current policy.

The tool does not deploy, reload, flush conntrack or alter the C executable.
Unknown or partially patched layouts are rejected. Back up the generator and
live rules, check the rendered nft syntax, then atomically replace the six live
rules and install the generated file with an independent rollback timer.

Test existing and new IPv4/IPv6 connections across set expiry, explicit flush
and ruleset recreation. Assert the connection mark and actual packet delivery,
not only rule counters. This does not preserve connections across conntrack
flushes, device reboot, or a physical gateway/tunnel failure. Direct decisions
remain fixed for the connection lifetime even if policy subsequently changes.
