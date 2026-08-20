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

- **RBAC** with explicit permissions (e.g., `devices:read`, `configs:apply`, `plugins:manage`)
- **2FA (TOTP)** required for privileged operations
- **Audit trail** for login, device changes, and plugin actions

## Device addressing (multi-IP)

Each device has exactly one **primary address** (`managementAddress`) plus any number of **secondary IPs**. All addresses must be a bare IPv4 literal, an IPv6 literal, or a DNS name — no scheme (`https://…`), because choosing the transport is each plugin's own decision.

- The primary is set at creation and edited via `PATCH /devices/{id}`; secondaries are managed with `GET/POST /devices/{id}/ips` and `DELETE /devices/{id}/ips/{ipId}` (mirrors the plugin-assignment pattern).
- Every `/monitoring` and `/config` call to a plugin carries **all** addresses as `ipAddresses: [{ address, isPrimary }]`, so plugins can reach secondary interfaces when they need to.
- Transport handling (TLS vs plaintext, self-signed certificates) lives in the **plugin**, not on the device — e.g. the OPNsense plugin's `transport` option (`auto` = HTTPS with self-signed accepted, `https`, or `http`).

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
