# FRITZ!Box Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Monitors [AVM FRITZ!Box](https://avm.de/service/fritzbox/)
class routers through their web-UI session, collecting system, WAN/LAN and WiFi state plus a
device inventory. Read-only monitoring — no configuration actions are exposed.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System (uptime, load, temperature), WAN link + throughput, LAN/WiFi client counts, per-SSID state. |
| Inventory | — | Hostname/firmware, interfaces, connected clients, network topology facts for the Networks/Hosts pages. |

## Credential slots

1. **Primary** — `usernamePassword` secret: a FRITZ!Box web-UI login (System → Administration → Users). The plugin keeps a session cookie; no API key is involved.

## Options

- `apiMode` / `transport` — session transport selection.
- `httpsPort` / `httpPort` / `sshPort` / `tr064Port` — non-standard port overrides (TR-064 discovery uses the TR-069 port).

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
