# Dota 2 exit selection and traffic accounting

Static router extension for an already provisioned Steam/Dota policy. The Dota
card independently selects AWS game (`wg_game`), Hong Kong SS (`pnwhks0`), or the
existing game proxy (`pnwgfec0`). Undeployed interfaces are disabled. Selection
checks local interface/policy readiness; it is not a remote health test or an
automatic failover mechanism. Steam, downloads and the global exit keep their
existing owners. Only normal LAN IPv4 SDR UDP tuples are covered. IPv6, VPN,
non-SDR game servers and process-level identification are outside this module.

The classifier runs at prerouting -124, after existing game overrides. It accepts
only traffic already marked by the original game policy and owned Dota marks,
so original device/transport/DNS exclusions still win. Independent marks 16–18,
tables 24016–24018 and preferences 12016–12018 are reserved. Each table has an
unreachable default and a checked, owned interface route. A separate forward
guard rejects escape. Emergency isolation must explicitly include these marks.

Named forward counters at priority 10 count accepted IP packet bytes and packets
in both directions, per exit. They exclude proxy/WireGuard overhead, Steam and
other tunnel traffic. These numbers are not provider billing estimates. Sampling
runs every five seconds. Runtime totals survive daemon restarts; atomic persistent
checkpoints run every five minutes and before switching. Sudden power loss can
lose the last checkpoint interval. Boot/table generations and counter decreases
are handled without subtracting accumulated totals. Missing counters retain the
previous snapshot; stale rates are shown as unknown. Historical use cannot be
reconstructed before installation.

Install source from an exact verified CI commit. Keep config.json version 1 and a
selected exit (`aws`, `hk`, `game`) under root-only `/etc/pnw-control/dota-egress`.
Install the Lua module as `/etc/pnw-control/dota-egress.lua`, daemon.sh in the
config directory and service.init as `/etc/init.d/pnw-dota-egress`. Existing
last-good SDR data and game state remain under their current owner. `integrate.py`
transforms the controller, view and emergency rules with exact anchors and refuses
unknown/already patched inputs. Preserve the existing authenticated execution ACL.

Provision narrowly scoped fw4 forward accepts for original LAN mark 16 via
wg_game, 17 via pnwhks0 and 18 via pnwgfec0. Persist them through the existing fw4
include owner, ahead of zone rejects. Preserve every existing include rule.
Before deployment, capture hashes and backups, check reserved mark/table/rule
ownership, hold the shared deployment lock, arm timed and boot rollback, validate
nft syntax and fw4 generation, then verify routes, accounting and actual replies.
Only exact owned objects may be removed on rollback. This is an optional static
router module, not an automatic generic APK routing migration.
