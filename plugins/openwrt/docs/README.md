# OpenWrt Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [OpenWrt](https://openwrt.org/docs/guide-user)
routers with a dual transport: **LuCI ubus-over-HTTP** as primary, plus an optional SSH slot
that unlocks `uci`-based configuration actions and security checks.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System state + per-interface throughput (ubus). |
| Inventory | — | Interfaces, wireless, tunnels, services for the Networks/Hosts pages. |
| Configuration actions | — | 61 catalog actions: firewall zones/rules, DNS hosts + reconfigure, DHCP static mappings, WireGuard tunnel create, OpenVPN site-to-site create, back-route creation and more. |
| Planning / rollouts | — | Multi-device intents for fleet configuration (firewall, DNS, DHCP, VPN). |
| Updates | — | Firmware + package update status/apply through opkg. |
| Security checks | **SSH slot bound** | Read-only SSH checks at inventory cadence. |

## Credential slots

1. **Primary** — `usernamePassword` secret for the LuCI ubus endpoint (HTTPS).
2. **Optional — `ssh` slot.** Username/password or key pair; required for uci-based write actions and security checks.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
