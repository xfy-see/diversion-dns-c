# Private deployment configuration and publication checks

The public repository contains code, synthetic fixtures and reproducible test
summaries. Device addresses, delegated prefixes, MAC addresses, DDNS names,
credentials, original packet captures and device reports stay outside Git.
`validation/`, `private/`, `private-artifacts/` and `*.local.json` are ignored.
Ignoring a path does not remove an already tracked file or prevent `git add -f`.

## Local configuration and compatibility

The manually installed PNW controller reads `/etc/pnw-control/expected-egress.json`.
Existing `ipv4`/`ipv6` expectations retain their meaning. Proxy entries additionally
use `endpoint_ipv4` for the WAN reachability preflight. Endpoint and public egress
are different identities; neither is inferred from the other or learned from an
unverified observation. Missing proxy identity/endpoint refuses switching before
route edits. WireGuard peers still come from existing local UCI configuration.
The optional `query_source` entry holds the exempt client's address, MAC and exact
nft comment. Its UI selector is `bypass`; an old selector equal to the configured
address also works. This only explains existing rules, and never creates bypasses.

The JSON sample in `packaging/managed/expected-egress.example.json` uses
non-routable documentation addresses: **do not install it as live configuration**.

Before manually upgrading an old controller, preserve private copies of its
controller, query module and existing identity JSON. On an offline workstation:

```sh
python3 scripts/migrate-private-config.py \
  --legacy-controller private/controller.lua \
  --legacy-query private/query.lua \
  --existing private/expected-egress.json \
  --output private/expected-egress.local.json
```

Omit `--existing` only when the device has no identity JSON. The migration reads
literal values without executing the old code, preserves configured overrides,
requires an unambiguous old layout, writes mode 0600, refuses overwrite/symlinks,
and never prints addresses. It does not SSH, install files or restart services.
Unsupported layouts require local review; do not bypass the refusal.

For a separately authorized deployment, validate the private result, keep the old
controller/config as rollback, and install the JSON on the device as root:root
0600 **before** replacing the controller or query module. Confirm egress identity,
endpoint route and exempt-client inference against existing behavior. Roll back
both code and configuration if checks fail. Do not replace live settings with a
sample, reroute traffic, flush rules or restart DNS merely for this migration.

The managed APK does not install this main-router controller or its private JSON.
It continues installing observation/diagnostic modules only. Existing profile
identifiers and configuration paths remain accepted; the listener address is
validated from the existing root-managed profile. Example names are generic,
and package hooks still preserve configured files and service running state.
No migration or production update is performed by this repository change.

## Before publishing

```sh
python3 scripts/privacy_scan.py --staged
python3 scripts/privacy_scan.py --ref HEAD
python3 scripts/privacy_scan.py --text-file private/pr-body.md
```

CI scans the exact checked-out tree before build/test/artifact creation. The scan
checks common credential patterns, private filenames, personal paths, DDNS,
private relay email, device MACs and unreviewed IP literals. Diagnostics show only
file, line and rule, never matched values. Documentation address ranges, public
resolver constants and a small generic lab network are explicitly allowed.
Rare additional synthetic inputs require an exact-path/address allowlist with a
reason; never allow an entire report directory or a real deployment identity.
The scan is a guardrail, not proof that arbitrary encoded secrets are absent.
Review added domain names, free text, binary attachments and author identity too.
Use the account's GitHub no-reply address for future commits.

## Previously public data

PR/release prose can be redacted without discarding failure/performance results.
A clean new tree does not erase old commits, other branches, tags, release assets,
Actions logs, clones or caches. History rewrites or artifact deletion require a
separate coordinated plan: preserve private evidence and provenance, identify
consumers of hashes/tags, and avoid breaking deployment/rollback references.
If a real credential is ever found, revoke/rotate it independently of text cleanup.
