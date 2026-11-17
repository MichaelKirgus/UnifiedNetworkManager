# Development — repository layout, build workflow & API environment variables

For people working on UNM itself (or extending it): what lives where, how to run a hot-reload dev stack, the rules that keep builds green, and the key API environment variables.

## Repository layout

| Path | What it is |
|------|-----------|
| `api/` | Express API service (Drizzle ORM + Postgres), OpenAPI-validated, JWT/RBAC/TOTP auth, workers for telemetry/config jobs/plans/log retention |
| `webapp/` | React 18 + Vite + Tailwind SPA (login, devices, plans, networks, hosts, routes, tunnels, Wi-Fi, flows, logs, plugins, secrets, sites, users, roles, tokens) |
| `packages/plugin-sdk/` | Shared TypeScript SDK for plugins (`@unm/plugin-sdk`): HTTP server scaffolding (incl. auto-mounted self-metrics `/metrics`), settings reading, API client, structured logger |
| `packages/snmp-client/` | Shared net-snmp CLI wrapper used by the SNMP + LANCOM plugins |
| `plugins/` | One microservice per vendor adapter — 28 plugins in total. The full list with supported vendors & devices lives in [PLUGINS.md](PLUGINS.md); `_template/` is the scaffold for new plugins |
| `plugins/basic-auth/` | Identity provider plugin — local users + TOTP verification on behalf of the API (swappable via `AUTH_PLUGIN_ID`) |
| `plugins/secrets-provider/` | Secrets provider plugin — encryption at rest (owns `MASTER_KEY`) + key/cert generation (swappable via `SECRETS_PLUGIN_ID`) |
| `mcp/` | MCP server exposing the OpenAPI operations as tools (+ read-only SQL & plugin probes on a gated debug endpoint) — see [MCP.md](MCP.md) |
| `openapi/` | The OpenAPI contract — single source of truth for the public API surface |
| `scripts/` | Mock OPNsense appliance + TLS material, plan e2e test suite |

## Hot-reload dev setup

If you're working on UNM itself, use `setup.sh` instead of plain compose — it needs Node.js ≥ 20 and builds everything from source (it works against `docker-compose.dev.yml`, which carries the `build:` blocks). The script detects whether you can reach the Docker daemon without sudo and only escalates when truly needed.

```bash
./setup.sh
```

This installs all dependencies (`make setup`), starts Postgres, syncs the schema (`drizzle-kit push`), builds the shared packages + plugins in parallel (`make build`), starts every plugin container with `--build`, then runs the API and webapp as hot-reloading dev servers. It blocks until you press Enter; teardown (dev servers + containers) happens automatically on exit/Ctrl+C.

Other targets: `make up|down|restart`, `make stop-api|stop-web`, `make clean` (removes containers **and** volumes).

On first boot the API seeds an **admin** user (password `admin`) — see [First login](../README.md#getting-started): the initial sign-in is password-only and a mandatory setup wizard then forces a new password + second-factor enrollment. Accounts without an enrolled second factor cannot pass 2FA at all, so they are locked out of 2FA-gated endpoints (config jobs, plan execution) until one is enrolled.

## Build & test workflow

- **Build order matters**: `@unm/plugin-sdk` and `@unm/snmp-client` must build first — npm `file:` dependencies are *copied* into each consumer's `node_modules`, so `make build` refreshes those copies before fanning out all plugin builds in parallel. After editing a shared package, always run `make build`.
- **Type-check**: `cd api && npx tsc --noEmit`, same for `webapp/` and each plugin; or just `make build`.
- **OpenAPI is enforced**: every new public route must be added to `openapi/unified-network-manager.openapi.yaml` — the validator 404s undocumented paths. Structural check: `node validate-openapi.cjs`.
- **Schema changes**: edit `src/db/schema.ts`, then `cd api && npx drizzle-kit push`. In dev, `setup.sh` re-runs this on every start; in production images the API does it itself at boot (`api/src/schemaBootstrap.ts`) — fresh databases are bootstrapped automatically, and **additive** changes (new tables/columns) apply on next container start. A **data-loss** change is refused without `--force` so it can never silently destroy data: review it, then run it manually with `docker exec <api> sh -c "cd /app/api && node_modules/.bin/drizzle-kit push --force"`. Keep `schema.ts` composite-PK names equal to the live Postgres constraint names.
- **Smoke tests**: `cd plugins/opnsense && ../../node_modules/.bin/tsx smoke-test.ts` (same for `plugins/mikrotik-swos`).
- **Plugin images always rebuild from source** (`docker compose up -d --build <service>`) — reusing stale images silently serves old code.

## Key environment variables (API)

| Variable | Default | Effect |
|----------|---------|--------|
| `JWT_SECRET` | `dev-secret` | JWT signing key. Set a random value in `.env` for production (compose reads it via `${JWT_SECRET:-dev-secret}`) |
| `DATABASE_URL` | built from `POSTGRES_*` vars | Postgres connection — compose renders `postgresql://${POSTGRES_USER:-unm}:${POSTGRES_PASSWORD:-unm}@postgres:5432/${POSTGRES_DB:-unm}`, so setting the `POSTGRES_*` vars in `.env` is enough; you only override this directly to point at an external database |
| `UNM_CORS_ORIGINS` | *(empty)* | Comma-separated CORS allowlist for the API. The webapp origin from `WEBAUTHN_ORIGIN` is always included, and `http(s)://localhost` / `127.0.0.1` on any port are always allowed (dev works without setting this). Production: set your real origin(s), e.g. `https://unm.example.com`. Not needed for a same-origin reverse-proxy setup |
| `UNM_TRUST_PROXY` | *(off)* | Reverse proxy: trust `X-Forwarded-For` so rate limiting uses the real client IP (`1` = one hop, `N`, or CIDR/named policy). See [DEPLOYMENT.md](DEPLOYMENT.md#reverse-proxy-environment-variables) |
| `UNM_CLIENT_IP_HEADER` | *(off)* | Reverse proxy: explicit client-IP header (e.g. Cloudflare's `CF-Connecting-IP`). Wins over `X-Forwarded-For`; only set if the proxy is the sole ingress |
| `PLUGIN_API_KEY` | `dev-plugin-key` | Shared key the API presents to plugins (`x-plugin-api-key`) and that plugins use for log shipping / broker calls |
| `AUTH_PLUGIN_ID` | built-in basic-auth plugin | Active identity provider; falls back to built-in when unset/offline |
| `SECRETS_PLUGIN_ID` | built-in secrets-provider plugin | Active secrets provider; same fallback behavior |
| `LOG_RETENTION_DAYS` | `7` | Plugin log + self-metrics retention window for the hourly sweep |
| `TELEMETRY_RETENTION_DAYS` | `7` | Raw telemetry snapshot retention — older rows are deleted by the hourly retention sweep (the fastest-growing table in the system) |
| `TELEMETRY_POLL_INTERVAL_MS` | `30000` | Telemetry poll beat. Raise for very large fleets, or lower `TELEMETRY_MAX_CONCURRENCY` instead |
| `TELEMETRY_MAX_CONCURRENCY` | `64` | Max in-flight `/monitoring` calls per poll cycle — keeps the per-beat burst flat regardless of fleet size |
| `SECRET_CACHE_TTL_MS` | `60000` | How long decrypted secrets are cached for the poll path (write paths always read fresh). Cuts secrets-provider load by orders of magnitude at scale; set `0` to disable |
| `DATABASE_POOL_MAX` | `20` | Postgres pool size — raise if you see queued writes during poll beats on large fleets |
| `PLUGIN_POLL_ENDPOINTS` | *(empty)* | Optional legacy discovery fallback: comma-separated endpoints to poll when a plugin cannot reach the API at all. Normal deployments leave this unset — plugins self-register instead (see [PLUGINS.md](PLUGINS.md)) |
| `PLUGIN_HOST_PORT_MAP` | *(unset)* | Dev-mode only (`setup.sh` sets it): `service:port,…` pairs letting the host-running dev API rewrite compose service names to localhost ports |
