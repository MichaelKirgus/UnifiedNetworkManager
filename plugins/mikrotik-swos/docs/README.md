# MikroTik SwOS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [MikroTik](https://help.mikrotik.com/)
**SwOS / SwOS Lite switches** (CRS, CSS) via their `.b-file` HTTP API: system and port
monitoring plus configuration actions for ports, PoE, LAGs and VLANs.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System state + per-port link/throughput via the `.b-file` API. |
| Inventory | — | Ports and VLANs for the Networks/Hosts pages. |
| Configuration actions | — | 20 catalog actions: port config, PoE config, LAG config, VLAN port membership, VLAN table sets, SNMP config, firmware update, backup download / config restore. |
| Planning / rollouts | — | Multi-device intents for fleet switch configuration. |
| Updates | — | Firmware status + update through the `.b-file` API. |

## Credential slots

1. **Primary** — `usernamePassword` secret: a SwOS user (IP → Users) with at least read permission; write actions need the matching privilege level.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
