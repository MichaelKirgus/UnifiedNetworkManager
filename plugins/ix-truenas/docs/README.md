# TrueNAS Plugin — Documentation

Plugin for the Unified Network Manager (UNM). Manages [TrueNAS SCALE](https://www.truenas.com/)
appliances over their JSON-RPC API: system health, ZFS pools and datasets, interfaces,
VMs, containers/apps, shares, firmware updates and full configuration backup/restore.

## Capabilities

| Capability | Requirement | Notes |
| --- | --- | --- |
| Monitoring | — | System status, pool/dataset gauges, service health; alert mirroring into UNM notifications (`notifyAlerts`). |
| Inventory | — | Pools, datasets, zvols, snapshots, interfaces, VMs (when `collectVms`), apps/catalog (when `collectApps`). |
| Configuration actions | — | 94 catalog actions across system, pools, interfaces, config backup/restore, firmware, bootenv, alerts, containers (incl. change image `containers.image.set`), VMs, storage, shares, images and catalog. |
| Planning / rollouts | — | Multi-device intents for fleet operations. |
| Updates | — | Firmware status + apply through the appliance's own update pipeline. |
| Device state (Config page) | — | Live `GET /state` document with context-aware actions. |
| Per-container detail + filesystem browser + web console | **SSH slot bound** | Real MACs/live IPs via docker inspect, dataset browsing over SFTP, full shell on the host or inside a container.

## Credential slots

1. **Primary** — `usernamePassword`: a TrueNAS login (user + password). Transport is HTTPS by default with port overrides available.
2. **Optional — `apiKey` slot.** A TrueNAS API key (System → Advanced → API Keys), used *instead of* username/password when bound (recommended); on TrueNAS 26+ also set the "API key owner username" option.
3. **Optional — `ssh` slot.** Username/password or key pair; unlocks per-container detail, the filesystem browser and the interactive web console.

## License

EUPL-1.2 — see [LICENSE.md](../LICENSE.md).
