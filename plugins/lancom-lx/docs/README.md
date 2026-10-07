# LANCOM LX Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [LANCOM](https://www.lancom-systems.com/en/)
**LX-Series access points** via the LCOS-LX-MIB over SNMP: radios, SSIDs, associated stations
and RF environment monitoring, plus a wide action catalog for radio/VLAN/LACP/PoE tuning.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | Radio state, per-SSID client counts, channel/utilization, RF environment (interference, noise floor). |
| Inventory | — | Interfaces, ports, WLC assignment for the Networks/Hosts pages. |
| Configuration actions | — | 52 catalog actions: radio channel/power sets, SSID VLAN mapping, VLAN/LACP/PoE config, WLC address, NTP/SNMP/STP settings. |
| Planning / rollouts | — | Multi-device intents for fleet-wide AP configuration. |
| Updates | — | Firmware status + update through the LCOS-LX update mechanism. |

## Credential slots

1. **Primary** — `snmp` secret (community or v3 user). Write actions use SNMP SET where the MIB supports it; otherwise they are reported as not effective for that device.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
