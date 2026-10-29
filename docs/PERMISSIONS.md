# Permission catalog & access control

This document is the reference for UNM's RBAC model: how permissions are
enforced, the complete permission catalog, which API routes and webapp pages
each permission gates, and the special cases that don't follow the obvious
pattern.

The **single source of truth** is [`api/src/auth/permissions.ts`](../api/src/auth/permissions.ts).
`GET /v1/permissions` (auth-only, no permission gate) serves the catalog to the
Users/Roles UIs — this document must stay in sync with that file.

## How RBAC works

- **Flat at enforcement time.** Users carry a `permissions` string array in
  their JWT claims; middleware checks only that claim. There is no role lookup
  per request.
- **Roles are DB-backed bundles** (`roles` table) whose permissions are unioned
  into the user's explicit grants **when the JWT is minted**. Role changes —
  like explicit grant changes — take effect on the next login.
- **Admin backfill.** On every API start, `api/src/db.ts` adds *all* catalog
  permissions to the built-in admin role row and to every user carrying the
  admin role (`backfillAdminRole()` / `backfillAdminPermissions()`). New
  permissions added in an upgrade therefore never lock admins out. Non-admin
  users/roles need explicit grants via the Users/Roles pages.
- **2FA gate.** Privileged operations (currently: everything gated on
  `configs:apply`) require a fresh TOTP revalidation (`amr: ['totp']` in the
  JWT). Which second factors satisfy the privileged-action gate is configurable
  per user via credential policies (`auth:policies:write`).
- **Device scope.** Beyond permissions, users can carry a `deviceScope`
  (site ids / tags / explicit device ids) restricting *which* devices they see.
  Carriers of `devices:all` bypass all scope checks; the permission is granted
  to everyone by default (see below), so removing it from a role/user is what
  activates their restrictions.

## Permission catalog

Descriptions are verbatim from `PERMISSION_DESCRIPTIONS`.

### Devices & device access

| Permission | Grants |
|------------|--------|
| `devices:read` | View devices, their plugins and telemetry |
| `devices:write` | Create, update and delete devices and plugin assignments |
| `devices:all` | Access every device regardless of device-scope rules — **ADDITIVE**: granted to everyone at backfill time; carriers bypass all device-scope checks. Removing it from a role/user is what activates their `deviceScope` restrictions. |

### Cross-device inventory pages

Each webapp page has its own read permission gating its data routes; where an
area supports mutation outside the plan workflow, there is a matching write
permission.

| Permission | Grants |
|------------|--------|
| `networks:read` | View the Networks inventory page (logical networks across devices) |
| `hosts:read` | View the Hosts inventory page (ARP/NDP/DHCP/WLAN clients) |
| `documented-hosts:read` | View documented hosts (the user-maintained host inventory) |
| `documented-hosts:write` | Create, update and delete documented hosts (incl. CSV import) |
| `documented-networks:read` | View documented networks (the user-maintained network inventory) |
| `documented-networks:write` | Create, update and delete documented networks (incl. CSV import) |
| `tunnels:read` | View the Tunnels page (configured + live tunnel state) |
| `services:read` | View the Services page (systemd/rc/middleware services across devices) — managed via the plan/config workflow |
| `mail:read` | View the Mail page (domains, mailboxes and aliases across devices) — managed via the plan/config workflow |
| `routes:read` | View the Routes page (static and dynamic routes across devices) |
| `dns:read` | View the DNS page (static DNS entries across devices) — managed via the plan/config workflow |
| `firewall:read` | View the Firewall page (filter + NAT rules across devices) |
| `certificates:read` | View the Certificates page (TLS certs + SSH host keys across devices) |
| `certificates:write` | Accept changed certificates / SSH host keys (re-pin endpoints) — security-relevant, gated separately from reading |
| `wifi:read` | View the WiFi page (SSIDs, spectrum and neighbors) |
| `storage:read` | View the Storage page (filesystems, pools/datasets and physical disks across devices) |
| `shares:read` | View the Shares page (SMB/NFS/iSCSI/NVMe-oF shares and active client sessions across devices) — managed via the plan/config workflow |
| `time:read` | View the Time page (device clocks, timezones and clock drift across devices) — managed via the plan/config workflow |
| `containers:read` | View the Containers page (Apps/container workloads across devices) |
| `vms:read` | View the VMs page (virtual machines and their NICs across devices) |

### Files, updates & traffic

| Permission | Grants |
|------------|--------|
| `files:read` | View the Files page (the central file repository) |
| `files:write` | Upload, download and delete files in the central file repository |
| `updates:read` | View the Updates page (available firmware/package/image updates across devices) — applying an update is a plan (`configs:apply` + 2FA) |
| `flows:read` | View the Flows page (traffic flows between devices and to the internet); also gates GeoIP status |

### Security, topology & logs

| Permission | Grants |
|------------|--------|
| `security:read` | View the Security page (unsuccessful logins, file-integrity and rate-limit findings across devices) — own permission because findings can carry sensitive detail |
| `topology:read` | View the Topology page (physical + logical network graph) |
| `logs:read` | View plugin log entries (device and global) — separate from `devices:read` because logs can carry critical details |

### Automation, plans & configuration

| Permission | Grants |
|------------|--------|
| `automations:read` | View automation rules (Actions & Schedules) and their run history; also gates the read-only test-pattern endpoint |
| `automations:write` | Create, edit, delete and test-run automation rules |
| `sites:read` | View sites |
| `sites:write` | Create, update and delete sites |
| `plans:read` | View execution plans and their steps |
| `configs:apply` | Submit configuration jobs to devices (**requires 2FA**) — gates *all* plan writes (create/patch/steps/execute/retry/cancel/schedule/delete) and config-job submission |

### Plugins & notifications

| Permission | Grants |
|------------|--------|
| `plugins:read` | View plugins, their options and self-metrics |
| `plugins:manage` | Change global plugin settings (also gates per-device plugin-settings PUT/DELETE) |
| `notifications:read` | View the notification center (bell, panel and Notifications page); acknowledging/closing/resolving is read-level — it only affects the user's own view state |
| `notifications:write` | Change personal notification visibility settings |

### Secrets

| Permission | Grants |
|------------|--------|
| `secrets:read` | View secrets (metadata only — values stay encrypted) |
| `secrets:write` | Create and update secrets (global scope) |
| `secrets:delete` | Delete secrets (global scope) |
| `secrets:self-write` | Create and manage your own personal secrets (for interactive SSH / file access) — see [Inline gates](#inline-gates-not-middleware-permissions) for the visibility rules |

### Topology layers

| Permission | Grants |
|------------|--------|
| `layers:write` | Add, edit or remove network layers used by the topology view — `GET /layers` is open to any authenticated user (the topology page needs it) |

### Users, tokens & authentication

| Permission | Grants |
|------------|--------|
| `tokens:manage` | Create, view and revoke your own API tokens |
| `users:read` | View users and their roles/permissions |
| `users:write` | Edit user roles/permissions, manage roles, and delete users; also required to mint/revoke tokens *for other users* |
| `users:create` | Create new users with an initial password and TOTP enrollment |
| `users:manage-credentials` | Reset passwords and manage 2FA of **other** users |
| `users:self-credentials` | Change own password and manage own 2FA |
| `auth:policies:write` | Edit credential policies (2FA requirements and 2FA-gate satisfaction) — global default and per-user overrides; reads are open to any authenticated user |
| `auth:interactive-login` | Sign in interactively to the web UI — **ADDITIVE**: checked only at `POST /auth/login`; removing it locks a service-only account out of the *web UI* but never affects its API tokens |

### System, CA & instance backup

| Permission | Grants |
|------------|--------|
| `system:read` | View system status — workers, leader election, database health (Workers + Settings pages) |
| `system:write` | Change runtime worker/HA settings (poll cadence, concurrency); also gates GeoIP DB refresh |
| `ca:read` | View the certificate authority status and issued certificates — UNM's *own* PKI (`unm-ca`), distinct from device-facing `certificates:*` |
| `ca:manage` | Manage the certificate authority (revoke/renew leaves) |
| `instance:backup` | Back up, restore and replicate UNM's own configuration; also the gate for accepting inbound replication sync pushes (the presented token must carry it) |

## API route → permission map

Condensed per area. Routes not listed here are either auth-only (no permission
gate) or covered by an [inline gate](#inline-gates-not-middleware-permissions).

### Devices (`api/src/routes/devices.ts`)

| Route(s) | Permission |
|----------|------------|
| `GET /devices`, `GET /devices/:id/{ips,plugins,options,monitoring,state,probe,ports,port-roles,telemetry}` | `devices:read` |
| `POST /devices/refresh`, `POST/PATCH/DELETE /devices…` (device CRUD, clone, IPs, plugin assignments, order) | `devices:write` |
| `PUT/DELETE /devices/:id/plugins/:pluginId/settings` | **`plugins:manage`** — per-device settings are plugin configuration, not device data |
| `POST /devices/:id/quick-action` | `devices:read` — resolving a web-UI URL transmits no credentials to the browser |
| `POST /devices/:id/{filesystem,console}`, `GET/PUT /devices/:id/session-credentials`, `PUT /devices/:id/port-roles` | `devices:write` |

### Cross-device inventory (`api/src/routes/networks.ts`)

Most cross-device GETs live in one router file; each is gated by its page's
read permission: `/networks(+suggestions)` → `networks:read`; `/hosts`,
`/host-states` → `hosts:read`; `/dns` → `dns:read`; `/tunnels` → `tunnels:read`;
`/services` → `services:read`; `/certificates(+history)` → `certificates:read`;
`POST /certificates/accept` → **`certificates:write`**; `/routes` →
`routes:read`; `/firewall-rules`, `/firewall-events`, `/firewall-sessions` →
`firewall:read`; `/wifi` → `wifi:read`; `/storage` → `storage:read`; `/shares` →
`shares:read`; `/device-time`, `/ntp-references` → `time:read`; `/containers` →
`containers:read`; `/vms` → `vms:read`.

### Plans (`api/src/routes/plans.ts`)

| Route(s) | Permission |
|----------|------------|
| `GET /plans(+activity,/:id)` | `plans:read` |
| **All writes** — create/patch/steps/bulk/reorder/execute/retry/cancel/schedule/delete | `configs:apply` (+ 2FA) |
| `POST /plans/:id/secrets/:ref/regenerate` | `secrets:write` |
| `POST /plans/{network-check,preflight}` | `devices:read` — read-only checks, no plan is created |

### Plugins (`api/src/routes/plugins.ts`)

| Route(s) | Permission |
|----------|------------|
| All reads (list, options, actions, metrics, self-metrics, required-secret-type) | `plugins:read` |
| `POST /plugins/:id/actions/execute` | **`containers:read`** — the read-only "peek" path for pages that need live appliance data without a plan; only catalog entries with `riskLevel: 'read'` may run here, enforced against the persisted catalog |
| `PUT/DELETE /plugins/:id/settings` | `plugins:manage` |
| `POST /plugins/:id/tls/renew` | `ca:manage` |
| `GET /plugins/:id/{icon,asset}` | **unauthenticated by design** — plain `<img>` tags cannot send bearer headers; do not gate these |

### Everything else (one line each)

- Documented hosts/networks: GET → `*:read`; all writes (CRUD, bulk, import,
  merge, sync-macs, import-from-inventory) → `*:write`.
- Automations: list/preview-schedule/runs/test-pattern → `automations:read`;
  create/edit/delete/test-run → `automations:write`.
- Sites: GET → `sites:read`; writes → `sites:write`.
- Roles: all routes (GET/POST/PATCH/DELETE) → `users:write`.
- Users: list → `users:read`; create → `users:create`; edit/status/delete →
  `users:write`; credential endpoints → [inline gate](#inline-gates-not-middleware-permissions).
- Secrets & tokens: see [Inline gates](#inline-gates-not-middleware-permissions).
- CA: status/certificates → `ca:read`; revoke/renew → `ca:manage`.
- Security/CVE: vulnerabilities/summary/**refresh** → `security:read`.
- GeoIP: status → `flows:read`; **refresh → `system:write`**.
- Settings & system: GETs → `system:read`; writes → `system:write`.
- Notifications: list/count/prefs-GET + ack/close/resolve/delete →
  `notifications:read`; only `PUT /notifications/prefs` → `notifications:write`.
- Layers: GET open to all authenticated users; writes → `layers:write`.
- Files, updates, topology, flows, mail, logs, counts: their page's read
  permission (`files:read`, `updates:read`, `topology:read`, `flows:read`,
  `mail:read`, `logs:read`; `/counts` is auth-only).
- Backups (all routes) → `instance:backup`.

### Plugin plane (`api/src/routes/internal.ts`)

All `/plugin/*` routes are the **plugin-to-API** plane, authenticated with the
per-plugin API key (`x-plugin-api-key`) — user permissions do not apply. This
includes plugin registration, CA enrollment, log/flow/firewall-event/host-state
ingest, state storage, and the secrets/users broker endpoints plugins use to
resolve credentials server-side.

## Inline gates (not middleware permissions)

A few route families check permissions *inside* the handler because the gate
depends on **which** user/secret is targeted:

### Secrets (`api/src/routes/secrets.ts`)

- `GET /secrets` — needs `secrets:read` **or** `secrets:self-write`. Visibility:
  global readers see everything; a user with only `self-write` sees their own
  secrets plus those created by users holding `secrets:write` (the "shared"
  pool).
- `POST /secrets` — needs `secrets:write` **or** `secrets:self-write` (personal
  area: the secret is owned by the caller and only they can manage it).
- `GET/PATCH/DELETE /secrets/:id` — same read-or-self-write entry gate, then a
  per-secret visibility check; deleting needs `secrets:delete` **or**
  `self-write` on your own secret.
- `POST /secrets/{generate,/:id/regenerate}` → `secrets:write`.

### User credentials (`api/src/routes/users.ts`)

Password reset and TOTP/passkey enrollment/confirm/delete act on a *target*
user: target is **self** → needs `users:self-credentials`; target is **another
user** → needs `users:manage-credentials` (checked by
`checkCredentialAccess()`).

### Tokens (`api/src/routes/tokens.ts`)

- `GET/POST /tokens` → `tokens:manage`.
- `POST /tokens` with a different `userId` additionally needs `users:write` —
  this is how admins mint tokens for service-only accounts that can't sign in.
- `DELETE /tokens/:id` — own token: `tokens:manage`; **any** user's token:
  `users:write`.

### Credential policies (`api/src/routes/credentialPolicies.ts`)

Reads (global + per-user) are open to any authenticated user; the writes
(`PUT /auth/policies/global`, `PUT/DELETE /users/:id/policy`) require
`auth:policies:write`, checked inline.

## Webapp page guards

Route guards live in [`webapp/src/App.tsx`](../webapp/src/App.tsx)
(`PAGE_PERMISSIONS`). The `<Page permission?>` guard redirects to `/` when the
permission is missing; a **permission array means ANY one suffices**. The
sidebar hides menu entries whose read permission is missing, and the home
redirect lands on the first readable page (else My Account).

| Page(s) | Permission |
|---------|------------|
| `/devices` | `devices:read` |
| `/networks`, `/networks/rollout` | `networks:read` |
| `/hosts` | `hosts:read` |
| `/dns`, `/dns/rollout` | `dns:read` |
| `/documented-hosts` (+ `/import-from-inventory`) | `documented-hosts:read` (the import wizard additionally needs `documented-hosts:write`) |
| `/documented-networks` (+ `/import-from-inventory`) | `documented-networks:read` (wizard needs `documented-networks:write`) |
| `/tunnels`, `/services`, `/mail`, `/routes`, `/logs`, `/notifications`, `/wifi`, `/storage`, `/shares`, `/time`, `/files`, `/updates`, `/security`, `/flows`, `/topology`, `/sites` | the matching `*:read` permission |
| `/containers` (+ `/create-app`) | `containers:read` |
| `/vms` (+ `/create-vm`) | `vms:read` |
| `/backups` (+ `/restore`) | `instance:backup` |
| `/plans`, `/automations`, `/plugins` | `plans:read`, `automations:read`, `plugins:read` |
| `/users` | `users:read` |
| `/roles` | **`users:write`** — the Roles page is an admin surface, not a read surface |
| `/tokens` | `tokens:manage` |
| `/workers`, `/settings` | `system:read` |
| `/secrets` | `['secrets:read', 'secrets:self-write']` — **ANY one suffices** (a personal-area-only user still gets the page, scoped to their own secrets) |
| `/layers` | *no permission* — open to all authenticated users |
| `/credential-policies` | *no permission* — reads are open; edits are gated server-side on `auth:policies:write` |

In-page action buttons are additionally gated with `can('…')` from
[`webapp/src/auth/permissions.ts`](../webapp/src/auth/permissions.ts) (e.g. the
Containers page "Change image" bulk action requires the selected app's plugin to
advertise the `containers.image.set` intent, and executing it flows through a
plan — i.e. `configs:apply` + 2FA).

## Keeping this in sync

When adding a permission: add id + description to
`api/src/auth/permissions.ts`, gate the routes (middleware or inline), update
the webapp guard if there is a page, and update **this file**. Admins pick up
new permissions automatically on next API start; everyone else needs an explicit
grant.
