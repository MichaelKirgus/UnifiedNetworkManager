# Template Plugin — Documentation

Copy of the starting point for new UNM plugins. Copy this folder to
`plugins/<your-plugin>/`, update `package.json` (name, UUID in `src/index.ts`) and
follow [docs/PLUGIN-DEVELOPMENT.md](../../docs/PLUGIN-DEVELOPMENT.md) — it covers the
SDK surface, discovery contract, action catalog, planning intents and the local dev loop.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | One example metric descriptor; replace with your own. |

## Credential slots

None by default — set `requiredSecretType` in discovery when your plugin needs one.

## Options

- `pollIntervalSeconds` — poll cadence (default 30).
- `logToApi` — ship structured log entries to the UNM API for the device Logs view.
- `system.example` — example option showing the descriptor shape.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
