# Steam / Dota 2 tunnel exception

This opt-in main-router feature adds a Web UI switch for Steam login/community
and Dota 2 game relay traffic. Downloads keep the ordinary CN-site/CN-IP policy.
It does not replace the selected exit, create a new WireGuard peer, or require
dnsmasq-full. It is disabled until explicitly enabled and unsupported managed
APK/device profiles do not expose an actionable switch.

## Classification

- `domains.txt` is a deliberately narrow login/community/game-control list.
  `steamcontent.com`, `steamstatic.com`, `steamusercontent.com`, download hosts,
  and the blanket `steampowered.com` suffix are not forced.
- Original DNS QNAME matches use the foreign upstream and populate
  `game_site4` / `game_site6`, including fresh/stale cache hits and refreshes.
- [Valve's SDR API](https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=570)
  supplies Dota 2 relay IPv4 + UDP port ranges. The
  [Steam CM API](https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&cmtype=netfilter)
  supplies login server IPv4 + TCP/UDP ports. These are not broad port rules.
- Rules go after existing local/private/LAN, device, transport and DNS exemptions
  but before CN-IP/CN-site returns. LAN, existing VPN-client scope and router
  output inherit the existing classifier scope. Existing marked-traffic egress
  guards and emergency isolation apply; no WAN fallback is introduced.
- Disabling removes the opt-in DNS block, restarts DNS, empties the enable gate
  and profile sets, and restores ordinary classification. It does not force WAN:
  an overseas destination can still use the tunnel under the normal policy.

This is IP-based routing, not process identification. Shared hosting addresses
can affect other names at the same IP, including a download when it shares a
learned login address. Client-private DNS, pre-existing client DNS caches,
third-party game servers and non-SDR direct Dota server endpoints are outside
exact identification. Reconnect Steam and the game after switching. Established
NAT/conntrack sessions are not deleted. Actual game login/match quality requires
a client gameplay check; DNS/nft probes are not a substitute.

## Ownership and installation

The static main-router layout is distinct from the managed generic APK profile.
`integrate.py` provides fail-on-unknown-input transforms for the existing
controller, policy, apply helper, query helper and view. It never connects to or
modifies a router. `packaging/managed/ui/control.lua` remains a source-only fixture;
its game action wiring is not a generic APK routing migration.

A deployment must first back up the exact live files and active CN-policy
snapshot, compare pre-change hashes, hold `/var/lock/diversion-dns-deploy.lock`,
and arm an independent rollback guard. Install `game-tunnel.lua` and
`game-tunnel-render.lua` in `/etc/pnw-control/`; create root-only
`/etc/pnw-control/game-tunnel/` containing `domains.txt` and initially
`state.json` (`{"enabled":false}`). Use the matching verified CI C binary with
`tunnel_domain_file` support. Keep device-specific files out of the repository.

The policy apply helper must render the profile's sets into its own atomic nft
transaction before adding classifier references. Apply and explicitly adopt the
new approved policy with `cn-policy.sh seed --replace`; preserve the old
snapshot for rollback. Preserve the controller's existing endpoint bindings,
MAC exemptions and runtime exit validation. Install a content-hashed LuCI view
and retain the existing authenticated control/status ACL (no new anonymous RPC).

The controller holds the global lock across switching and recovery. The module
journals exact before/after DNS configuration before mutations, refuses rollback
if another writer changed it, and leaves failed recovery journals intact.
Its existing monitor reconciliation restores interrupted toggles. DNS readiness
uses up to five real queries with one-second gaps because procd can report a
running process before its listeners are ready; persistent failure still rolls back. Runtime state
is shown separately from saved intent; missing or inconsistent state is not
reported as enabled. File-write and network failures do not silently enable it.

Official lists are fetched before enabling; malformed, empty, private-address,
implausibly shrunken or backwards-revision updates are rejected. While enabled,
monitor reconciliation checks for hourly refresh, with at least 30 minutes
between failed attempts; failures retain last-good lists and are displayed.
Boot/policy recreation uses locally validated last-good data, never an untrusted
network response. The UI also supports manual list refresh.

## Tests

- GitHub compiles the C regression tests: tunnel override wins over CN, foreign
  upstream is selected, A/AAAA cold and cache-hit paths write only the tunnel
  set, nft failures propagate, ordinary CN/foreign paths and disabled config
  retain old behavior. Configuration validation covers orphaned/invalid keys.
- `python3 -m unittest discover -s tests -p test_game_tunnel.py -v` uses prebuilt
  `lupa` for feed validation, config round trips, state mismatch, interrupted
  rollback, external-writer refusal, gate and policy ordering tests.
- `node packaging/managed/ui/tests/frontend.test.js` covers unavailable controls,
  confirmed vs optimistic state, pending submissions and stale connection state.
- `kernel-smoke.py` installs both complete classifier chains in an owned CI
  network namespace. Transport tuples precede the dynamic protocol gate: nft
  otherwise loses transport context and rejects port expressions.
- Device kernel set/tuple syntax, exact binary source provenance, real DNS/route behavior,
  on/off persistence, automatic recovery and normal traffic must be verified on
  the target separately. Mock tests are not device proof.

## Dedicated AWS exit (optional static-router deployment)

A root-private `game-tunnel/egress.json` activates the dedicated status checks:
`interface=wg_game`, `mark=2`, `table=20234`, and `peer` containing the independently
provisioned server public key. No endpoint, client key or real address is shipped
in source. `game-egress.lua` verifies both route families, single default peer,
classifier mark, forward/postrouting guards and recent handshake. The Web view
labels this profile **独立 AWS**; missing routes or stale handshake are visible.
Enabling requires a ready dedicated tunnel. Disabling remains possible when it fails.

Use `dedicated_policy`, `dedicated_query` and `dedicated_emergency` transformations
only against the already integrated profile. They keep all ten game rules ahead
of CN, change only their mark to 2, protect the dedicated transport (UDP source
51824), and reject mark 2 escaping `wg_game`. The global exit still owns mark 1
and table 100; switching it does not migrate the dedicated interface. Emergency
containment blocks both marks. Query inference uses the game's actual mark/table.

Provision a new client key on the router and only its public key on the AWS
server. Add a peer with unused /32 and /128 addresses to the existing service;
never copy the active global client's identity or steal its AllowedIPs. Keep keys
and backup configurations on their devices. Netifd owns the independent interface,
mark rules and table defaults. Install terminal unreachable defaults via loopback
so loss of the interface cannot fall through to main. A dedicated firewall zone
must provide dual-stack source NAT, LAN/VPN forwarding and MTU/MSS handling.
No default route is added to main. Keep the existing WAN endpoint host route.

Deployment must back up current UCI, policy, UI, emergency rules and CN-policy
snapshot, arm a timed/boot rollback, validate the tunnel before changing game
marks, and adopt the new approved policy under the shared lock. Rollback removes
only the new peer/interface and restores pre-change policy. Verify fresh AWS and
ordinary global-exit HTTPS identities, game TCP/UDP counters, IPv6, route-loss
containment, independent down/up recovery and both Web switch states.

DNS for the game names continues using the configured foreign resolver group;
this feature selects the connection egress, not a separate DNS upstream. Clients
must reconnect after enabling. Existing conntrack flows are not forcibly deleted.

### Review hardening

Dedicated-egress inspection failures keep the game card visible with an error.
Disabling remains available during a global exit mismatch or DNS degradation;
authentication, deployment locking and unfinished-transaction checks still apply.
The gate is cleared before restarting DNS on disable. Main-exit recovery runs
before optional game recovery, whose errors cannot abort the main recovery path.

Official-list downloads run in the background job before acquiring the deployment
lock. Only validated data prepared within 60 seconds can be committed under the
lock. The unlocked reconcile parent schedules periodic refresh through this same
job path, with a 30-minute retry backoff. Rollback journals include the exact prior
list bytes (or absence), alongside DNS configuration and switch state.
Dedicated guards are inserted at the head of both guard chains. Status checks
both LAN and router classifiers for all four game address sets.

Remaining acceptance requirements: verify real rule ordering, firewall reload
persistence, IPv6 client traffic, and DNS-learned-address expiry on the target.
The one-hour game address timeout still requires DNS re-resolution; a client
retaining an address beyond that period may lose domain-based classification.
Shared CDN addresses can affect unrelated connections to the same IP. These
limitations are not resolved by the transaction and recovery fixes above.
