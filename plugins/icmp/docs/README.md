# ICMP Plugin — Documentation

Plugin for the Unified Network Manager (UNM). A generic **ping monitor**: it sends ICMP echo
requests from its own container to a target host and records latency, loss and jitter. No
credentials are needed at all — useful for monitoring devices that expose no API.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring (ping) | — | Latency/loss/jitter/reachable metrics per poll; health derived from loss threshold. |
| Inventory | — | IP/MAC facts learned for the Hosts page when the target answers. |

## Credential slots

None — the plugin pings from its own container network position. The target must be reachable by ICMP from that vantage point.

## Options

- `pingHost` — override the ping destination (default: the device's own IP).
- `pingCount` / `timeoutMs` — burst size and per-ping timeout.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
