# UI import provenance

Imported from the owner-managed PNW `router_shell/pnw-control` source after the
2026-10-19 compact layout deployment. GPL-3.0-or-later, same owner.
The runtime whitelist contains only observation modules, bounded check/diagnose,
and the device-mode view. `control.lua` is a source-only test fixture and is never
installed: route switches, emergency writes, firewall and DHCP changes are not
part of this package. Device profiles are local configuration, not published state.
