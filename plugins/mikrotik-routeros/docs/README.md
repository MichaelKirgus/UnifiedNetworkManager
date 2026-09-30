# MikroTik RouterOS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [RouterOS](https://mikrotik.com/)
routers over its REST API (`/rest`, available since 7.1), with an interactive SSH
console on top.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | CPU/memory/disk gauges, uptime, per-interface throughput rates (30 s cadence). |
| Inventory | — | Interfaces + addresses, ARP table, DHCP leases, routes, firewall rules (filter + NAT), wireless clients. TTL-cached snapshot (default 60 s). |
| Configuration actions | — | Single-device actions from the action catalog over REST. |
| Planning / rollouts | — | Multi-device intents: `network.create`, `network.delete` with a `/preflight` resolver for per-device attach-point suggestions. Pure REST writes — no extra credentials needed. |
| Firmware status | — | Live RouterOS version vs the known release catalog (available-without-apply — RouterOS OS updates go through the web UI / package server; there is no safe programmatic update API). |
| SSH console | — | Interactive CLI shell over SSH (port 22). Always effective: when no dedicated `ssh` slot is bound, the primary username/password login is reused (RouterOS shares one account across REST + SSH). Bind a separate user or an ed25519/rsa key via the optional slot. |
| Security checks | — | Service-exposure scan (telnet/ftp/www) + failed-login analysis from `/log/print`, over the REST API at ~15-min cadence. No extra slots. |
| WiFi | **Box has wireless radios** | Detected per device: an interface of type `wfi`/`wireless`, or associated clients in the ROS 7 registration table. Wired-only hardware (most CCRs, CHR) shows this capability as not effective — there is nothing to configure. |

## Credential slots

1. **Primary — username/password** (`usernamePassword` secret type). The RouterOS
   console login used for REST Basic auth. Required for everything above. An empty
   password is legitimate (the default `admin` account has none).
2. **Optional — `ssh` slot.** Accepts a username/password login OR an ssh key pair.
   Unbound = the primary login is reused for the interactive shell. Bind here to use
   a separate user or key.

## Supported firmware lines

REST API available since 7.1beta4; supported release lines:

**7.8 · 7.9 · 7.10 · 7.11 · 7.12 · 7.13 · 7.14** (current)

Point releases are handled by the Updates page comparison; OS upgrades themselves
are performed in RouterOS's web UI or via a package server (no programmatic API).

## Supported hardware

Any device running RouterOS, including:

- CCR rackmounts — CCR1009-7G-1C-2X+D, CCR1016-12S-1G+EMS, CCR2004-1G-12S+2XS+
- hEX / RB desktop units — hEX S (RB750Gr3), hEX (RB750Gr2), RB4011iGS+, RB5009
- CHR virtual routers
- Custom / any other RouterOS device

The model selection in the UNM device form is informational (icon + firmware catalog);
the plugin works identically on all of them. WiFi capability depends on whether the
specific box has radios, not on the model entry.

## License

MIT — see [LICENSE.md](../LICENSE.md).
