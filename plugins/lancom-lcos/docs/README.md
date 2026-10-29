# LANCOM LCOS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [LANCOM](https://www.lancom-systems.com/en/)
**LCOS routers** via SNMP as the primary transport, with an optional SSH slot that unlocks
configuration actions and security checks.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System state, LAN/WAN throughput, VPN tunnels, firewall counters, temperature sensors. |
| Inventory | — | Networks (LAN/VLAN), tunnels, routes for the Networks/Hosts pages; static DNS entries (`dnsEntries`) from `Setup/DNS/DNS-List` via SNMP walk (`.1.3.6.1.4.1.2356.11.2.17.5`, column-first length-prefixed index — Host-name / IP-Address / IPV6-Address / Rtg-tag). |
| Configuration actions | — | 22 catalog actions: firewall rules read, routing/DHCP/VLAN/IPv6 network reads, config backup/restore, WLAN radio channel/power, NTP/DNS server sets. |
| Planning / rollouts | — | Multi-device intents for fleet configuration (`network.create`, `network.delete`, `dns.set`, `dns.delete`, `dns.rename`). DNS writes go through the CLI over SSH (v4: `add "NAME" 0 <ip>`; v6: `add "NAME" 0 0.0.0.0 <ipv6>`; dual A+AAAA in ONE row: `add "NAME" 0 <ip> <ipv6>` — a second `add` for an existing name REPLACES the whole row, so the intents are merge-aware and always write both families in one command; delete/rename: `del Setup/DNS/DNS-List/<name>` + re-add); reads stay on SNMP. |
| Updates | — | Firmware status + update through the LCOS update mechanism. |
| Security checks | **SSH slot bound** | Read-only SSH checks at inventory cadence. |

## Credential slots

1. **Primary** — `snmp` secret (community or v3 user) for monitoring/inventory.
2. **Optional — `ssh` slot.** Username/password or key pair; required for configuration actions and security checks.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
