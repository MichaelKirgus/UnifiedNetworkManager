# Docker Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [Docker Engine](https://docs.docker.com/engine/)
hosts over the Engine API (TCP, TLS or local socket), exposing containers as a first-class
inventory and offering lifecycle actions. An optional SSH slot unlocks an interactive console.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | Container states, per-container CPU/memory from the Engine API; self-metrics for poll health. |
| Inventory | — | `containers[]` metric: image, state, ports, labels, restart policy. |
| Configuration actions | — | 17 catalog actions: container start/stop/restart/delete, deploy-compose, run-image, images pull/update/prune/delete, logs read. |
| Planning / rollouts | — | Multi-device intents for fleet-wide container operations. |
| Device state (Config page) | — | Live `GET /state` document with context-aware actions. |
| Probe | — | Pre-flight reachability check used by the device form. |

## Credential slots

1. **Primary** — none required: plain TCP or local-socket transport needs no secret (transport + port configured as options).
2. **Optional — `dockerTls` slot.** Docker TLS client certificates (CA + cert + key) for the tls transport / auto fallback. Unbound = plain TCP only.
3. **Optional — `ssh` slot.** Username/password or key pair; needed by `containers.deploy-compose` (runs `docker compose up -d` on the box — the Engine API has no classic compose endpoint) and unlocks the interactive SSH console.

## Options

- `transport` / `port` / `localSocketPath` — how to reach the daemon.
- `version` — Engine API version pin (default: latest supported).

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
