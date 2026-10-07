# Zabbix Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Integrates UNM with a [Zabbix](https://www.zabbix.com/documentation)
server: it pulls fleet metrics from Zabbix over JSON-RPC and syncs host inventory into Zabbix,
so both systems stay consistent without manual import/export.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | Fleet metrics pulled from the Zabbix server (JSON-RPC) at poll cadence. |
| Inventory sync | — | Host inventory written into Zabbix host groups, keeping UNM and Zabbix in step. |

## Credential slots

1. **Primary** — `apiKeyNoSecret`: a Zabbix **API token** (preferred), or a `usernamePassword` user login as an alternative. The account needs read access to the relevant host groups; write scope is needed for inventory sync.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
