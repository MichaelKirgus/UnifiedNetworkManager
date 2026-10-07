# Generic SNMP Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A generic **SNMP monitor** for any device that
speaks SNMPv1/v2c/v3: system group (hostname, uptime, load), interface throughput and — when
enabled — WiFi 802.11 MIB data (radios, SSIDs, associated stations) from access points.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| SNMP monitoring | — | System group + per-interface in/out throughput; v3 authPriv supported. |
| WiFi inventory | `collectWifi` option enabled | 802.11 MIB walk: radios, SSIDs, stations, RF environment (APs only). |

## Credential slots

1. **Primary** — `snmp` secret type: community string (v1/v2c) or user + auth/priv keys (v3), plus version and port.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
