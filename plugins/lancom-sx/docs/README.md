# LANCOM SX Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [LANCOM](https://www.lancom-systems.com/en/)
**SX-Series switches** via SNMP: system/PSU/fan/temperature health, per-port state and
throughput, PoE consumption, plus port/VLAN/LACP/PoE configuration actions.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System health (PSUs, fans, temperature), per-port link/throughput, PoE power draw. |
| Inventory | — | Ports and routes for the Networks/Hosts pages. |
| Configuration actions | — | 12 catalog actions: port speed/duplex mode, PoE mode/priority, LACP membership, VLAN PVID/mode sets. |
| Planning / rollouts | — | Multi-device intents for fleet switch configuration. |

## Credential slots

1. **Primary** — `snmp` secret (community or v3 user). Write actions use SNMP SET where the MIB supports it; otherwise they are reported as not effective for that device.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
