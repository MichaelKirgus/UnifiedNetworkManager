# LANCOM LCOS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [LANCOM](https://www.lancom-systems.com/en/)
**LCOS routers** via SNMP as the primary transport, with an optional SSH slot that unlocks
configuration actions and security checks.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System state, LAN/WAN throughput, VPN tunnels, firewall counters, temperature sensors. |
| Inventory | — | Networks (LAN/VLAN), tunnels, routes for the Networks/Hosts pages. |
| Configuration actions | — | 22 catalog actions: firewall rules read, routing/DHCP/VLAN/IPv6 network reads, config backup/restore, WLAN radio channel/power, NTP/DNS server sets. |
| Planning / rollouts | — | Multi-device intents for fleet configuration. |
| Updates | — | Firmware status + update through the LCOS update mechanism. |
| Security checks | **SSH slot bound** | Read-only SSH checks at inventory cadence. |

## Credential slots

1. **Primary** — `snmp` secret (community or v3 user) for monitoring/inventory.
2. **Optional — `ssh` slot.** Username/password or key pair; required for configuration actions and security checks.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
