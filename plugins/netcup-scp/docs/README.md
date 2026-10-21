# netcup SCP Plugin for UnifiedNetworkManager

Manages **netcup Server Control Panel (SCP)** accounts from UNM — VM fleet
monitoring plus plan-gated VM and firewall management over the official SCP REST API.

- **API base:** `https://servercontrolpanel.de/scp-core` (verified live; spec version 2026.1020.x)
- **Auth:** OAuth2 Bearer token from netcup's Keycloak realm `scp` — see [Getting a token](#getting-an-api-token) below
- **Secret type:** *API Key (without secret)* — the single field holds the raw Bearer token

## Getting an API token

The SCP API has no non-interactive login: tokens are issued through the
**Keycloak Device Authorization Grant** (the same flow the `ncctl` CLI uses).

1. Log in to your netcup account and open **Server Control Panel → Settings → API**
   (or use any tool that performs the device-code flow against
   `https://servercontrolpanel.de`, realm `scp`).
2. Approve the device code in the browser; you receive a long-lived access token.
3. Paste it into an UNM secret of type **API Key (without secret)** and bind that
   secret to your SCP device.

Tokens stay valid for roughly **30 days** and are refreshed on use — when one
expires, create a new token in the SCP UI and update the bound secret. The plugin
reports `critical` health with an explicit "token expired" message until then.

## Device setup

| Field | Value |
| --- | --- |
| Plugin | netcup SCP Plugin |
| Management address | `https://servercontrolpanel.de/scp-core` (or a bare host — the plugin adds `https://`) |
| Secret | *API Key (without secret)* containing the Bearer token |

One UNM device = one netcup account. All VMs in that account appear as rows of
the **Servers** metric table; every interface IP alias feeds UNM's Networks page,
and every firewall rule feeds the unified Firewall page (toggle via the
*Collect firewall rules into UNM* option).

## Capabilities

### Monitoring (read)

- `netcup.servers` — one row per VM: name, nickname, state (`RUNNING`, `SHUTOFF`, …), vCPU, RAM, IPs
- `netcup.tasks` — the 10 most recent SCP tasks with their state
- Inventory propagation into UNM: `networks[]` (v4/v6 aliases per interface) and
  unified `firewallRules[]` (policy rules expanded per interface; a failed read
  never wipes previously ingested rows)

### Configuration (plan-gated writes)

| Module | Actions | Risk |
| --- | --- | --- |
| Servers | `server.start`, `server.stop`, `server.reboot` (POWERCYCLE/RESET), `server.hostname.set`, `server.nickname.set` | write / dangerous |
| Snapshots | `snapshot.create` (online or per-disk), `snapshot.delete`, `snapshot.revert` | write / dangerous |
| Rescue | `rescue.activate`, `rescue.deactivate` | write |
| ISO | `iso.attach` (catalog image or user ISO, optional CD-ROM boot switch), `iso.detach` | write |
| Image | `image.setup` — full OS re-install with provisioning (hostname, locale, timezone, additional user, SSH keys, custom script) | **dangerous — wipes the disk** |
| Firewall | `firewall.policy.create/update/delete`, `firewall.interface.apply` (replaces the policy set on one interface MAC) | write / dangerous |
| rDNS | `rdns.set`, `rdns.delete` (v4 + v6, auto-detected) | write |
| Tasks | `task.cancel` | dangerous |

All writes **verify by re-reading state** afterwards (`verified: true` only when
the target state was actually observed); async 202+TaskInfo endpoints are verified
via task polling. Power/stop/reboot, image setup and firewall apply set
`retryOnDispatchFailure: false` (flapping guard).

### Rollback snapshots

When a plan step targets a concrete server (`serverId` in the input), UNM's plan
finalizer prepends a **best-effort `snapshot.create`** for that device — an online
rollback snapshot named `unm-rollback-*`. Account-scoped actions (firewall policy
CRUD) have nothing to snapshot and get no rollback step.

## API quirks this plugin works around

- `PATCH /api/v1/servers/{id}` requires `Content-Type: application/merge-patch+json`
  **and accepts only ONE attribute per request**; `stateOption` is a query param.
- There is no `/users/me` — the user id for policy endpoints is resolved from
  `executingUser.id` on recent tasks (the community-proven approach). If your
  account has never run a task, firewall-policy actions fail with an explicit hint.
- Mutating endpoints answer **202 + TaskInfo** (async) — the plugin polls the task
  to terminal state before reporting success.

## Development

```bash
cd plugins/netcup-scp && npm install --legacy-peer-deps
npx tsc --noEmit          # typecheck
docker compose -f docker-compose.dev.yml up -d --build netcup-scp-plugin   # from repo root (no sudo)
```

Debug port mapping: host `4023` → container `4080`.
