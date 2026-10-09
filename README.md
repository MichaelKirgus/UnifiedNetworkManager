# UnifiedNetworkManager (UNM)

Open-source network management and monitoring platform for mixed-vendor environments. A central control plane that manages devices through **pluggable vendor adapters** — each plugin is a small microservice speaking one common contract, so adding a new device family never means touching the core.

Currently supported vendors: **OPNsense** (routing/firewall), **LANCOM LCOS-LX** (Wi-Fi 6/7 access points), **LANCOM LCOS** (routers), **LANCOM SX-Series** (managed switches, both 4.x and legacy GS-2310 firmware lines), **MikroTik SwOS / SwOS Lite** (switches), **AVM FRITZ!Box-class routers** (FBox plugin — web-UI session monitoring + inventory), plus generic **SNMP** and **ICMP ping** plugins for anything else.

## Features

- **Open API** — vendor-neutral REST contract in [`openapi/unified-network-manager.openapi.yaml`](openapi/unified-network-manager.openapi.yaml); the Express API validates every request against it at runtime (`express-openapi-validator`).
- **Plugin system** — vendor adapters are independent microservices discovered via mDNS/DNS-SD with an HTTP polling fallback. A device can carry **multiple plugins at once** (e.g. generic SNMP + a vendor plugin), each with its own credentials; exactly one is *primary*.
- **Authentication with RBAC + 2FA** — JWT auth, flat permission catalog, DB-backed roles, TOTP two-factor for privileged operations (config jobs and plan execution require an enrolled authenticator). The API itself is a pure auth broker: credential verification is delegated to the pluggable **basic-auth** identity provider.
- **Secrets management** — device credentials are encrypted at rest by the pluggable **secrets-provider** plugin (the crypto holder); the API only ever stores ciphertext. Generatable secret types (WireGuard key pairs, tunnel PSKs, OpenVPN CA/cert/key) can be created and regenerated from the UI or as part of a plan.
- **Configuration workflows** — single-device config jobs plus multi-step **plans**: ordered steps with dependencies, token substitution between step results (`${steps[N].result.details.<key>}`), automatic best-effort config snapshots before writes (undoable plans), and secret provisioning wired into the plan lifecycle.
- **Cross-device inventory pages** — Networks (logical subnets/VLANs merged across devices), Hosts (one row per MAC, ARP/NDP/DHCP/Wi-Fi sources), Routes (static + connected + dynamic, with gateway health enrichment), Tunnels (WireGuard/IPsec/OpenVPN live state: peer addresses, handshake age, transfer rates), and Wi-Fi clients.
- **Plugin log pipeline** — plugins ship structured logs to the API (`POST /plugin/logs`); entries are retained for a configurable number of days and browsable globally or per device in the webapp (gated by its own `logs:read` permission). Emission is on by default and can be switched off globally or per device.
- **Plugin self-metrics** — every plugin auto-serves `GET /metrics` (CPU%, heap/RSS memory, event-loop lag, in-flight polls, last-poll duration + error rate, emitted metric count, log queue depth); the API samples it every 30 s and the webapp shows per-plugin runtime health with history sparklines — for spotting overloaded plugins or growing telemetry payloads.
- **MCP server** — exposes the whole API to AI agents over the [Model Context Protocol](https://modelcontextprotocol.io); new endpoints appear as tools automatically.

## Architecture

```mermaid
flowchart LR
    subgraph Browser
        W[Webapp<br/>React + Vite]
    end
    subgraph Docker
        A[API :3000/v1<br/>Express + Drizzle + Postgres 16]
        P1[OPNsense plugin]
        P2[ICMP / SNMP plugins]
        P3[LANCOM LX / LCOS / SX plugins]
        P4[SwOS plugin]
        P5[FBox plugin<br/>AVM routers]
        BA[basic-auth plugin<br/>identity provider]
        SP[secrets-provider plugin<br/>crypto holder]
        M[MCP server :3901]
    end
    D[(Postgres 16)]
    HW[Real appliances /<br/>mock-appliance]

    W -->|REST + JWT| A
    M -->|OpenAPI tools| A
    A <--> D
    A -->|/monitoring, /config, /plan<br/>+ x-unm-settings header| P1 & P2 & P3 & P4
    P1 & P2 & P3 & P4 -->|telemetry + logs| A
    A -->|credential verification| BA
    A -->|encrypt/decrypt/generate| SP
    P1 & P3 & P4 --> HW
```

- **Control plane API** (`api/`) — auth, RBAC, inventory, monitoring, config jobs, plans, secrets broker. Background workers (telemetry poll every 30 s, config-job executor, plan executor, log retention sweep) start only after the HTTP server has bound successfully.
- **Plugin runtime** — each plugin advertises itself via `/discover` (identity, capabilities, options, actions, device-model catalog). The API caches descriptors and injects effective settings as an `x-unm-settings` JSON header on every call it makes to a plugin.
- **Telemetry pipeline** — normalized metrics + inventory ride in one `telemetry` row per poll; the API fans inventory out into the cross-device `networks`, `hosts`, `routes`, and tunnel tables.

## Repository layout

| Path | What it is |
|------|-----------|
| `api/` | Express API service (Drizzle ORM + Postgres), OpenAPI-validated, JWT/RBAC/TOTP auth, workers for telemetry/config jobs/plans/log retention |
| `webapp/` | React 18 + Vite + Tailwind SPA (login, devices, plans, networks, hosts, routes, tunnels, Wi-Fi, logs, plugins, secrets, sites, users, roles, tokens) |
| `packages/plugin-sdk/` | Shared TypeScript SDK for plugins (`@unm/plugin-sdk`): HTTP server scaffolding (incl. auto-mounted self-metrics `/metrics`), settings reading, API client, structured logger |
| `packages/snmp-client/` | Shared net-snmp CLI wrapper used by the SNMP + LANCOM plugins |
| `plugins/opnsense/` | OPNsense plugin — monitoring, inventory, config actions, multi-device plan intents (WireGuard/IPsec/OpenVPN/routes), tunnel + route enrichment |
| `plugins/icmp/` | ICMP ping plugin — reachability/latency/jitter/loss + IP/MAC inventory; no credentials needed |
| `plugins/generic-snmp/` | Generic SNMP Plugin — SNMPv1/v2c/v3 monitoring (system group, interface throughput) + inventory via net-snmp CLI |
| `plugins/lancom-lx/` | LANCOM LCOS-LX access points — radios, SSIDs, stations, RF environment, WDS/CAPWAP; Wi-Fi client propagation |
| `plugins/lancom-lcos/` | LANCOM LCOS routers — system/LAN/WAN metrics, VPN + firewall counters; config over SNMP SET (`lcsSetup`) with web-UI backup via a second credential slot |
| `plugins/lancom-sx/` | LANCOM SX-Series switches (4.x unified MIB **and** legacy GS-2310 3.x tree, auto-detected) — ports, PoE, LAG/LACP; config over SNMP SET |
| `plugins/mikrotik-swos/` | MikroTik SwOS Plugin — SwOS / SwOS Lite switches via the `.b-file` HTTP API (Digest auth): system, ports, PoE, SFP, VLANs; plan/config actions |
| `plugins/fbox/` | FBox Plugin — AVM FRITZ!Box-class routers over the box's own web-UI session API: system/WAN/LAN/WiFi metrics + LAN-device/WLAN-client/SSID inventory propagation |
| `plugins/basic-auth/` | Identity provider plugin — local users + TOTP verification on behalf of the API |
| `plugins/secrets-provider/` | Secrets provider plugin — encryption at rest (owns `MASTER_KEY`) + key/cert generation |
| `mcp/` | MCP server exposing the OpenAPI operations as tools (+ read-only SQL & plugin probes on a gated debug endpoint) |
| `openapi/` | The OpenAPI contract — single source of truth for the public API surface |
| `scripts/` | Mock OPNsense appliance + TLS material, plan e2e test suite |
| `docs/PLUGIN-DEVELOPMENT.md` | **The plugin developer guide** — contract, SDK usage, settings loop, logging, discovery, deployment |

## Getting started

Prerequisites: Docker (with compose), Node.js ≥ 20. The script detects whether you can reach the Docker daemon without sudo and only escalates when truly needed.

```bash
./setup.sh
```

This installs all dependencies (`make setup`), starts Postgres, syncs the schema (`drizzle-kit push`), builds the shared packages + plugins in parallel (`make build`), starts every plugin container with `--build`, then runs the API and webapp as hot-reloading dev servers. It blocks until you press Enter; teardown (dev servers + containers) happens automatically on exit/Ctrl+C.

| URL | Service |
|-----|---------|
| http://localhost:5173 | Web app |
| http://localhost:3000/v1 | API (health at `/healthz`) |
| http://localhost:3901/mcp | MCP server (`/debug/mcp` gated by `MCP_DEBUG_KEY`, default `dev-mcp-debug-key`) |

### First login

On first boot the API seeds an **admin** user (password `admin`) and prints its generated TOTP secret + `otpauth://` URI to the console — scan it with an authenticator app, then complete 2FA at login. Accounts created without an enrolled TOTP can pass 2FA with any 6-digit code in dev mode but will **not** receive the `amr: totp` claim required by 2FA-gated endpoints (config jobs, plan execution).

### Manual / containerized run

```bash
make setup                                  # install all deps
docker compose up -d --build postgres api \
  opnsense-plugin icmp-plugin generic-snmp-plugin lancom-lx-plugin lancom-sx-plugin \
  lancom-lcos-plugin mikrotik-swos-plugin fbox-plugin basic-auth-plugin secrets-provider-plugin webapp mcp
```

Dev mode with hot reload (API + webapp on the host, plugins in Docker): `make api-dev` / `make web-dev`. Other targets: `make up|down|restart`, `make stop-api|stop-web`, `make clean` (removes containers **and** volumes).

## Security model

- **RBAC** — flat permission catalog (`api/src/auth/permissions.ts` is the single source of truth; `GET /v1/permissions` serves it to the UIs). Users carry their effective permissions in JWT claims; roles are DB-backed bundles unioned into explicit grants at login time. New permissions added to the catalog are **backfilled onto existing admin users and the built-in admin role** on API start, so upgrades never lock admins out.
- **2FA (TOTP)** — required for privileged operations (`configs:apply`); enrollment is per-user via the My Account page or by an admin with `users:manage-credentials`.
- **Secrets** — values are encrypted by the secrets-provider plugin; the API stores only ciphertext and never sees plaintext. The webapp shows metadata only.
- **SNMP transport** — SNMP queries run in-process over native UDP (`@unm/snmp-client` on the `net-snmp` npm package); credentials (community strings, USM passphrases) are never passed as command-line arguments or written to logs. DES privacy is rejected at credential-validation time (Node ≥17 OpenSSL dropped it) — use AES.
- **API tokens** — long-lived bearer tokens (`unm_…`) for agents/scripts, self-service on the Tokens page or `POST /v1/tokens`, with per-token permission narrowing.

Permission catalog (current):

| Permission | Grants |
|------------|--------|
| `devices:read` | View devices, their plugins and telemetry |
| `logs:read` | View plugin log entries (device and global) — separate from `devices:read` because logs can carry critical details |
| `configs:apply` | Submit configuration jobs / execute plans (requires 2FA) |
| `plugins:manage` | Change global plugin settings |
| `secrets:read` / `secrets:write` / `secrets:delete` | Manage secrets (metadata only — values stay encrypted) |
| `sites:write` | Create, update and delete sites |
| `tokens:manage` | Create, view and revoke your own API tokens |
| `users:read` / `users:write` / `users:create` | View users; edit roles/permissions & manage roles; create users with initial password + TOTP enrollment |
| `users:manage-credentials` / `users:self-credentials` | Reset passwords and manage 2FA of other users / own account |

## Device addressing (multi-IP)

Each device has exactly one **primary address** (`managementAddress`) plus any number of **secondary IPs**. All addresses must be a bare IPv4 literal, an IPv6 literal, or a DNS name — no scheme (`https://…`), because choosing the transport is each plugin's own decision.

- The primary is set at creation and edited via `PATCH /devices/{id}`; secondaries are managed with `GET/POST /devices/{id}/ips` and `DELETE /devices/{id}/ips/{ipId}` (mirrors the plugin-assignment pattern).
- Every `/monitoring` and `/config` call to a plugin carries **all** addresses as `ipAddresses: [{ address, isPrimary }]`, so plugins can reach secondary interfaces when they need to.
- Transport handling (TLS vs plaintext, self-signed certificates) lives in the **plugin**, not on the device — e.g. the OPNsense plugin's `transport` option (`auto` = HTTPS with self-signed accepted, `https`, or `http`).

## Plugin model

Each plugin is responsible for one or more `vendor/deviceType` combinations and advertises capabilities:

- `monitoring` (health/metrics/events)
- `inventory` (facts/interfaces/modules — propagated into the cross-device pages)
- `configuration` (read/apply/reconcile actions)
- `planning` (multi-step, multi-device plan intents with a step catalog)
- `secretsProvider` / `identityProvider` (the two broker plugins; swappable via `SECRETS_PLUGIN_ID` / `AUTH_PLUGIN_ID`)

Plugins are discovered automatically: every plugin SELF-REGISTERS with the API on boot (`POST /v1/plugin/register`, SDK `startRegistration`) using its `UNM_API_URL` + `PLUGIN_API_KEY`, and mDNS/DNS-SD is a second path where multicast reaches. UNM keeps no catalog of known plugins — deploying a third-party plugin needs zero changes to the main app (see [`docs/PLUGIN-DEVELOPMENT.md`](docs/PLUGIN-DEVELOPMENT.md) §1). The full developer guide, including the settings loop, credential slots, device-model catalogs, and the logging pipeline, lives in that document.

### Plugin log pipeline

Every plugin ships structured logs to `POST /plugin/logs` (shared `x-plugin-api-key`, self-reported `pluginId`). Entries land in `plugin_logs` with level, message, optional JSON context and device association; a retention worker deletes rows older than `LOG_RETENTION_DAYS` (default 7) hourly. The webapp shows them on the global **Logs** page and per device in Device Detail — both gated by `logs:read`.

Emission is **on by default** via the standard settings loop: each plugin declares a boolean `logToApi` option, so it can be switched off globally (Plugins → Configure) or overridden per device without redeploying anything. The SDK's `createPluginLogger()` batches entries (2 s flush), queues up to 500 with drop-oldest backpressure, and degrades silently when the API is unreachable — logging never blocks a poll cycle.

### Multi-instance plugins (remote sites)

Every plugin supports running **multiple instances of the same type** — e.g. one ICMP or SNMP plugin at each remote site, all reporting into a single UNM instance. Each instance registers as its own plugin row and can be assigned to devices independently.

Two optional environment variables control this:

| Variable | Effect |
|----------|--------|
| `PLUGIN_INSTANCE_ID` (e.g. `site-a`) | Makes the advertised identity unique (`<plugin-uuid>:site-a`). Without it, two instances of the same plugin type would collide into one registration. |
| `PLUGIN_DISPLAY_NAME` (optional) | Overrides the displayed name. If unset, the instance id is appended automatically: `ICMP Plugin (site-a)`. |

With neither set, behavior is exactly as before — single-instance deployments are unaffected. A commented example lives in `docker-compose.yml`. Notes: each instance needs a unique `ADVERTISED_ENDPOINT` (and self-registers independently on boot); settings are per-instance; changing an id/name just restarts it and the old registration goes offline like any stopped plugin.

## Plans & configuration jobs

- **Config jobs** — single-device action submissions (`POST /devices/:deviceId/config-jobs` with an explicit `pluginId`), executed by the config-job worker against that plugin assignment. Require `configs:apply` + 2FA.
- **Plans** — multi-step workflows with per-step dependencies, reordering (cycle-checked while draft/ready), and `${steps[N].result.details.<key>}` token substitution from earlier step results. The executor runs one plan at a time, persists the *resolved* input of each step before dispatch, honors `bestEffort` flags, and marks orphaned executing plans failed on startup. Plan creation can **provision secrets** (e.g. WireGuard key pairs) through the secrets provider with rollback on failure; provisioned material is referenced by id in steps and never stored in plaintext anywhere.
- E2E test suite: `scripts/e2e-plans.ts` against the mock OPNsense appliance (`docker compose --profile test up -d mock-appliance`; the service is hidden behind the `test` profile so productive `up`s never start it).

## MCP server (AI agent access)

The `mcp/` service exposes the UNM API to AI agents via the [Model Context Protocol](https://modelcontextprotocol.io). It reads the OpenAPI spec at startup and turns every operation into a tool — new API endpoints appear automatically. The container serves two Streamable-HTTP endpoints on port **3901**:

| Endpoint | Purpose |
|----------|---------|
| `POST /mcp` | Production-safe: OpenAPI operations only. What an agent can do is controlled entirely by the permissions of its API token — create a scoped token (e.g. read-only) on the **Tokens** page and pass it as `UNM_API_TOKEN`. |
| `POST /debug/mcp` | Extended debug for diagnosing UNM itself: adds `query_database` (single read-only SELECT/WITH statement, max 200 rows) and `plugin_probe` (live `/healthz` + `/discover` of every plugin endpoint). Requires `Authorization: Bearer <MCP_DEBUG_KEY>`. |

**Environment variables:**

| Variable | Effect |
|----------|--------|
| `UNM_API_TOKEN` | Long-lived API token for the OpenAPI tools — **required**. Create it on the Tokens page (or `POST /v1/tokens`). |
| `UNM_API_BASE` | Base URL of the API. Defaults to `http://localhost:3000/v1`; the container uses `http://api:3000/v1`. |
| `MCP_DEBUG_KEY` | Bearer key gating `/debug/mcp` (default in compose: `dev-mcp-debug-key`). |
| `MCP_KEY` | Optional — when set, also gates the plain `/mcp` endpoint. |
| `DATABASE_URL` | Postgres connection used by the debug SQL tool only (same DB as the API). |

**VS Code MCP client config** (remote/HTTP transport):

```jsonc
{
  "mcpServers": {
    "unm": {
      "url": "http://localhost:3901/mcp"
    },
    "unm-debug": {
      "url": "http://localhost:3901/debug/mcp",
      "headers": { "Authorization": "Bearer dev-mcp-debug-key" }
    }
  }
}
```

The same server also runs in **stdio mode** without Docker (client-launched, production-safe tools only): `node mcp/dist/index.js` with `UNM_API_TOKEN` set — no `MCP_PORT` needed.

## Development workflow

- **Build order matters**: `@unm/plugin-sdk` and `@unm/snmp-client` must build first — npm `file:` dependencies are *copied* into each consumer's `node_modules`, so `make build` refreshes those copies before fanning out all plugin builds in parallel. After editing a shared package, always run `make build`.
- **Type-check**: `cd api && npx tsc --noEmit`, same for `webapp/` and each plugin; or just `make build`.
- **OpenAPI is enforced**: every new public route must be added to `openapi/unified-network-manager.openapi.yaml` — the validator 404s undocumented paths. Structural check: `node validate-openapi.cjs`.
- **Schema changes**: idempotent DDL in `initDb()` (`api/src/db.ts`) + `drizzle-kit push`; keep `schema.ts` composite-PK names equal to the live Postgres constraint names.
- **Smoke tests**: `cd plugins/opnsense && ../../node_modules/.bin/tsx smoke-test.ts` (same for `plugins/mikrotik-swos`).
- **Plugin images always rebuild from source** (`docker compose up -d --build <service>`) — reusing stale images silently serves old code.

### Key environment variables (API)

| Variable | Default | Effect |
|----------|---------|--------|
| `JWT_SECRET` | `dev-secret` | JWT signing key — change in production |
| `DATABASE_URL` | `postgresql://unm:unm@postgres:5432/unm` | Postgres connection |
| `PLUGIN_API_KEY` | `dev-plugin-key` | Shared key the API presents to plugins (`x-plugin-api-key`) and that plugins use for log shipping / broker calls |
| `AUTH_PLUGIN_ID` | built-in basic-auth plugin | Active identity provider; falls back to built-in when unset/offline |
| `SECRETS_PLUGIN_ID` | built-in secrets-provider plugin | Active secrets provider; same fallback behavior |
| `LOG_RETENTION_DAYS` | `7` | Plugin log + self-metrics retention window for the hourly sweep |
| `TELEMETRY_RETENTION_DAYS` | `7` | Raw telemetry snapshot retention — older rows are deleted by the hourly retention sweep (the fastest-growing table in the system) |
| `TELEMETRY_POLL_INTERVAL_MS` | `30000` | Telemetry poll beat. Raise for very large fleets, or lower `TELEMETRY_MAX_CONCURRENCY` instead |
| `TELEMETRY_MAX_CONCURRENCY` | `64` | Max in-flight `/monitoring` calls per poll cycle — keeps the per-beat burst flat regardless of fleet size |
| `SECRET_CACHE_TTL_MS` | `60000` | How long decrypted secrets are cached for the poll path (write paths always read fresh). Cuts secrets-provider load by orders of magnitude at scale; set `0` to disable |
| `DATABASE_POOL_MAX` | `20` | Postgres pool size — raise if you see queued writes during poll beats on large fleets |
| `PLUGIN_POLL_ENDPOINTS` | *(empty)* | Optional legacy discovery fallback: comma-separated endpoints to poll when a plugin cannot reach the API at all. Normal deployments leave this unset — plugins self-register instead (see §Plugins) |
| `PLUGIN_HOST_PORT_MAP` | *(unset)* | Dev-mode only (`setup.sh` sets it): `service:port,…` pairs letting the host-running dev API rewrite compose service names to localhost ports |

## Scaling & HA

The API is designed to run as **N replicas** behind a load balancer while exactly **one** of them runs the background workers. Election uses Postgres advisory locks (`api/src/workers/leader.ts`) — no Redis, no external coordinator:

- Each worker (telemetry polling, plan execution, log/telemetry retention, plugin self-metrics, plugin discovery) takes a non-blocking `pg_try_advisory_lock` at startup. The winner runs the loop; the others log *waiting for leadership* and serve HTTP only.
- **Failover is automatic**: if the leader dies (crash, OOM, `docker compose down`), Postgres frees its locks and every standby re-attempts within 15 s. A rolling deploy steps down gracefully on SIGTERM so handover takes seconds.
- All routes are stateless — jobs land in Postgres (`config_jobs`, `plans`), not process memory. The one exception is the **config-job worker**, which drains each instance's own in-process queue, so every replica runs it (it only picks up rows *its* routes enqueued).

**Overhead of HA-by-design on a single-replica deployment:** one extra `pg_try_advisory_lock` per worker at startup plus one verification query per minute — effectively zero. The lock rides on one dedicated pinned pool connection that is never returned to the idle list (node-postgres would destroy it after 5 min and silently drop session-scoped locks).

**Capacity guidance** (2 plugins/device, ~10 KB snapshots):

| Fleet | Notes |
|-------|-------|
| ≤ 50 devices | Defaults are fine. Retention is the only thing that matters long-term. |
| 50–150 devices | Fine as-is; watch plugin self-metrics (`inFlight`, event-loop lag) during poll beats. |
| 150–400+ devices | Raise `TELEMETRY_POLL_INTERVAL_MS` (60 s) and/or keep the concurrency cap; consider a second API replica for HA — polling load stays on one leader, HTTP scales out. |

The normalized inventory tables (`networks`, `hosts`, …) hold only current state and are swept at 24 h independently of telemetry retention.
