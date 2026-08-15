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

## Next implementation steps

1. Build the API service from the OpenAPI contract
2. Implement reference plugins for OPNsense, OpenWrt, and MikroTik
3. Add persistent storage and queue workers
4. Add UI/CLI clients using the same open API
