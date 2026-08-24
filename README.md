# UnifiedNetworkManager

Open source network management and monitoring platform for mixed-vendor environments.

## Features

This repository now defines a concrete, implementation-ready foundation for a unified manager that can operate across:

- **MikroTik** (switching/routing)
- **OPNsense** (routing/firewall)
- **OpenWrt** (WLAN/edge; including legacy LEDE/OpenWrt deployments)

Core requirements addressed:

- **Open API** (vendor-neutral): see `/openapi/unified-network-manager.openapi.yaml`
- **Authentication with RBAC + 2FA**: role/permission model and TOTP challenge endpoints
- **Plugin system**: vendor adapters are registered as plugins instead of hardcoded integrations
- **Scalability**: stateless API workers, queue-based config execution, and horizontally scalable telemetry ingestion

## Architecture (minimal baseline)

- **Control Plane API**: central REST API for auth, inventory, monitoring, and configuration workflows
- **Plugin Runtime**: loads vendor-specific adapters through a common contract
- **Task Queue**: async execution for configuration jobs and polling tasks
- **Telemetry Pipeline**: normalized metrics/events from heterogeneous devices into a common model

## Plugin model

Each plugin is responsible for one or more `vendor/deviceType` combinations and exposes capabilities:

- `monitoring` (health/metrics/events)
- `configuration` (read/apply/reconcile)
- `inventory` (facts/interfaces/modules)

Plugins are discovered and registered through API endpoints and validated against the plugin schema in the OpenAPI contract.

## Security model

- **RBAC** with explicit permissions (e.g., `devices:read`, `configs:apply`, `tokens:manage`) — the admin role carries every permission automatically; new permissions are backfilled into existing admins on API start
- **2FA (TOTP)** required for privileged operations
- **Audit trail** for login, device changes, and plugin actions

## Device addressing (multi-IP)

Each device has exactly one **primary address** (`managementAddress`) plus any number of **secondary IPs**. All addresses must be a bare IPv4 literal, an IPv6 literal, or a DNS name — no scheme (`https://…`), because choosing the transport is each plugin's own decision.

- The primary is set at creation and edited via `PATCH /devices/{id}`; secondaries are managed with `GET/POST /devices/{id}/ips` and `DELETE /devices/{id}/ips/{ipId}` (mirrors the plugin-assignment pattern).
- Every `/monitoring` and `/config` call to a plugin carries **all** addresses as `ipAddresses: [{ address, isPrimary }]`, so plugins can reach secondary interfaces when they need to.
- Transport handling (TLS vs plaintext, self-signed certificates) lives in the **plugin**, not on the device — e.g. the OPNsense plugin's `transport` option (`auto` = HTTPS with self-signed accepted, `https`, or `http`).

## SNMP plugin (monitoring + inventory)

The `plugins/snmp/` service collects data over **SNMPv1/v2c and SNMPv3 (USM)** using the net-snmp CLI. It provides:

- **Monitoring**: system group (description, object ID, name, location, contact, uptime), per-interface rx/tx throughput in bits/s (computed from counter deltas each poll cycle), and an aggregated total-throughput metric shown as a quick metric in the devices table.
- **Inventory**: per-interface attributes (name, type, speed, MAC address, operational status) + system identity data, exposed both as "Inventory"-group metrics (visible in Device Detail) and via dedicated endpoints: `GET /inventory?managementAddress=…&community=…` for v1/v2c, and `POST /inventory` with a JSON body (`{ managementAddress, credentials: { version, … } }`, same contract as `/monitoring`) — required for SNMPv3 so USM passwords never travel in URLs.

**Setup:**
1. Create an **snmp-type secret** (Secrets page): version + community string for `v1`/`v2c`, or USM username / security level / auth+priv protocols and passwords for `v3`.
2. Assign the SNMP Plugin to a device and attach that secret to the assignment.
3. Optionally drop vendor `.mib` files into `plugins/snmp/mibs/` — they're mounted read-only at `/app/mibs` inside the container and added to snmpwalk's MIB search path.

**Options** (Plugins page → Configure): `timeoutMs`, `retries`, `mibDir` (container-internal path), `inventoryTtlMs` (slow-path refresh cadence, default 15 min). Live throughput counters always refresh every poll cycle regardless of the inventory TTL.

## Multi-instance plugins (remote sites)

Every plugin supports running **multiple instances of the same type** — e.g. one ICMP or SNMP plugin at each remote site, all reporting into a single UnifiedNetworkManager instance. Each instance registers as its own plugin row and can be assigned to devices independently.

Two optional environment variables control this:

| Variable | Effect |
|----------|--------|
| `PLUGIN_INSTANCE_ID` (e.g. `site-a`) | Makes the advertised identity unique (`<plugin-uuid>:site-a`). Without it, two instances of the same plugin type would collide into one registration. |
| `PLUGIN_DISPLAY_NAME` (optional) | Overrides the displayed name. If unset, the instance id is appended automatically: `ICMP Plugin (site-a)`. |

With neither set, behavior is exactly as before — single-instance deployments are unaffected.

**Example** (`docker-compose.yml`) — a second ICMP plugin for site A:

```yaml
  icmp-site-a:
    build:
      context: ./plugins/icmp
    ports:
      - "4010:4004"
    environment:
      - PORT=4004
      - ADVERTISED_ENDPOINT=http://icmp-site-a:4010   # must be unique per instance
      - PLUGIN_INSTANCE_ID=site-a                     # required for multi-instance
      # - PLUGIN_DISPLAY_NAME=HQ ICMP                 # optional display name
    restart: unless-stopped
```

Also append the new endpoint to the API's `PLUGIN_POLL_ENDPOINTS` list (or rely on mDNS discovery). The instance then appears as its own row on the **Plugins** page, with independent online status, settings, and device assignments.

Notes:
- Each instance needs a unique `ADVERTISED_ENDPOINT` (different container name or published port) — that's how the API routes telemetry to the right one.
- Settings are per-instance: configuring "ICMP Plugin (site-a)" does not affect "ICMP Plugin".
- If you change an instance's id/name, restart it; the old registration simply goes offline like any stopped plugin.

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

## Next implementation steps

1. Build the API service from the OpenAPI contract
2. Implement reference plugins for OPNsense, OpenWrt, and MikroTik
3. Add persistent storage and queue workers
4. Add UI/CLI clients using the same open API

## Getting started (reference implementation)

This repository now includes a working reference implementation of the platform described above:

- `api/` — Express API service, dynamically validated against the OpenAPI spec (`express-openapi-validator`), JWT auth + RBAC + TOTP 2FA, SQLite persistence (`better-sqlite3`), and background workers for telemetry polling and config job processing.
- `plugins/opnsense/` — reference plugin microservice implementing the monitoring/configuration/inventory contract against the OPNsense REST API.
- `webapp/` — React 18 + Vite + Tailwind single-page app (Login, Devices, Device Detail, Config Jobs, Plugins).
- `docker-compose.yml` — wires the api, opnsense plugin, and webapp services together for local use.

### Running locally

```bash
# API (http://localhost:3000, mounted under /v1)
cd api && npm install && npm run dev

# Reference OPNsense plugin (http://localhost:4001)
cd plugins/opnsense && npm install && npm run dev

# Web app (http://localhost:5173)
cd webapp && npm install && npm run dev
```

On first run, the API seeds a default `admin` user (password `admin`) and prints that
user's generated TOTP secret and `otpauth://` enrollment URI to the console — scan it
with an authenticator app (or feed the secret into any TOTP generator) to complete the
2FA step at `/auth/2fa/verify`. Accounts created without an enrolled TOTP secret can
complete 2FA with any 6-digit code in dev mode, but will **not** receive the `amr: totp`
claim required by 2FA-gated endpoints such as submitting config jobs.
