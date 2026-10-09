# Plugin Development Guide

How to build a plugin for UnifiedNetworkManager (UNM). A plugin is a small
Node.js/TypeScript HTTP service that the API discovers, polls for telemetry,
and dispatches config actions and plans to. **All shared machinery lives in
`@unm/plugin-sdk`** (`packages/plugin-sdk`) — contract types plus runtime
helpers. Your plugin only declares *what it is* (identity, options, metrics)
and implements the device-specific logic.

Start from `plugins/_template/` — a complete, minimal monitoring plugin.

---

## 1. The port model (read this first)

Every plugin container listens on **one conventional internal port: `4080`**.
The host mapping in the compose file is optional and exists solely for
curl-from-host debugging + `setup.sh`'s readiness wait — UNM itself never needs
it, because discovery is push-based (below):

```yaml
my-plugin:
  build: { context: ., dockerfile: plugins/my-plugin/Dockerfile }
  ports: ["4030:4080"]          # optional — next free HOST port, debug only
  environment:
    - PORT=4080                 # always the same inside the container
    - ADVERTISED_ENDPOINT=http://my-plugin:4080   # how the API reaches it
    - UNM_API_URL=http://api:3000/v1              # where to self-register + ship logs
    - PLUGIN_API_KEY=${PLUGIN_API_KEY:-dev-plugin-key}  # shared key for both
```

- `PORT` — internal listen port. Leave at `4080`; the SDK's
  `resolvePluginIdentity` reads it (default 4080).
- `ADVERTISED_ENDPOINT` — the URL the API calls back on. Without it the plugin
  advertises `http://localhost:4080`, which is unreachable from the API's own
  container. **Always set it to `http://<compose-service-name>:4080`.**
- `UNM_API_URL` + `PLUGIN_API_KEY` — what make the plugin SELF-REGISTER (see
  below). Every UNM deployment sets both; a plugin without them runs standalone
  (no registration, no log shipping) and is only reachable via mDNS.

### Discovery: plugins announce themselves — there is no catalog to maintain

UNM keeps **no list of known plugins anywhere in the main app**. On boot the
SDK's `createPluginServer().listen()` starts a registration loop that POSTs the
plugin's full `/discover` payload to the API's internal
`POST /v1/plugin/register` route (gated by `x-plugin-api-key`). The API upserts
the row into its plugins table, and its discovery worker polls every endpoint
in that table for liveness + descriptor refresh. So:

- **Deploying a plugin = one container with the env vars above.** No api code,
  no compose env list, no Makefile edit — this is what makes third-party
  plugins (built by anyone, outside this repo) drop-in deployable.
- The loop retries while the API is down and re-registers on a 5-minute
  heartbeat, so identity/descriptors stay fresh and a wiped or freshly-migrated
  database self-heals with zero UNM-side config.
- mDNS/DNS-SD remains a second discovery path (networks where multicast
  reaches), and the API's optional `PLUGIN_POLL_ENDPOINTS` env var is a legacy
  fallback for topologies where a plugin cannot reach the API at all — neither
  is needed in a normal deployment.

Multi-instance: set `PLUGIN_INSTANCE_ID=site-a` (+ optional
`PLUGIN_DISPLAY_NAME`) on a second service using the same Dockerfile. The SDK
then advertises `<uuid>:site-a` as a distinct plugin, and each instance
self-registers independently. See the commented `icmp-site-a` example in
`docker-compose.yml`.

---

## 2. Creating a new plugin

```bash
cp -r plugins/_template plugins/my-plugin
# edit: package.json (name), Dockerfile (folder name ×3), src/index.ts (UUID, name)
cd plugins/my-plugin && npm install --legacy-peer-deps && npx tsc --noEmit
```

Then add a service block to `docker-compose.yml` (the shape above — the three
env vars are all it takes). The Makefile and setup.sh discover every
`plugins/*/package.json` folder automatically, so no build or bootstrap edit is
needed. Start it with:

```bash
docker compose up -d --build my-plugin   # it registers itself within seconds
```

The Dockerfile uses the **repo root as build context** so it can copy + build
the shared SDK first — keep that structure when editing.

### 2a. Canonical module layout (keep every plugin shaped like this)

All plugins follow one file-structure convention so a maintainer can find any
concern in the same place, regardless of vendor:

```
src/
  index.ts            # entry: identity, options, metric descriptors, route wiring — no business logic
  monitoring.ts       # POST /monitoring collection + buildDescriptors/buildMetrics (when non-trivial)
  plan.ts             # POST /plan → buildPlan() (+ PlanningError usage)
  security.ts         # security-check derivation/collection (collectSecurityChecks / deriveSecurityChecks)
  state.ts            # POST /state document builder        ┐ only when the plugin
  stateStore.ts       # persistent per-host store + PLUGIN_UUID ┘ exposes deviceState
  deviceModels.ts     # vendor/model catalog (+ firmware releases where relevant)
  <vendor>Client.ts   # transport client for the appliance API (top-level, or client/<vendor>Client.ts
                      #   when it grows multiple transports/backends — e.g. opnsense/client/*, openwrt/client/*)
  actions/            # action catalog: registry.ts + one module per domain (firewall.ts, routes.ts, …)
                      #   OR a single src/actions.ts for small catalogs — both are fine, pick ONE per plugin
```

Naming rules (enforced by review):

- **Name modules after what they DO**, not how they do it: `ping.ts` (not
  `icmpping.ts`), `inventory.ts` (not `rows.ts`), `swosPlatform.ts` (not a bare
  `platform.ts`), `webuiEndpoints.ts` (not `endpoints.ts`). A reader must be able
  to guess the module's job from its name alone.
- **One concern per file.** If a file mixes an SSH/transport pool with data
  collection, split it: transport in `ssh.ts`, collection in its own module
  (`enrichment.ts` in ix-truenas is the reference).
- **Top-level modules must not share a bare name with `actions/*`.** The layering
  is intentional — top level = READ/collect (e.g. opnsense's `firewall.ts`
  collects rules), `actions/firewall.ts` = WRITE intents — but the two layers are
  distinguished by directory, so keep each file's role unambiguous from its name.
- **Client names must match their transport.** A read-only SNMP collector is not
  a "client" (lancom-lx: `snmpCollector.ts` for the SNMP walk, `webapi.ts` for
  the real ubus web client).

---

## 3. What the SDK gives you (`@unm/plugin-sdk`)

| Export | Purpose |
| --- | --- |
| `resolvePluginIdentity({uuid,name,version,vendors,capabilities,authType?})` | Multi-instance identity from env (`PORT`, `ADVERTISED_ENDPOINT`, `PLUGIN_INSTANCE_ID`, `PLUGIN_DISPLAY_NAME`). Returns `{effectiveUuid, displayName, port, endpoint, …}`. |
| `createPluginServer({identity, logTag?, jsonLimit?, iconsDir?, discovery?, selfMetricsExtra?})` | Pre-wired express app: cors + json + `/healthz` + `/discover` + **auto-mounted `GET /metrics`** (self-metrics — see §11) (+ static `/icons`). `.listen()` binds the port and starts mDNS advertising (service type `_unm-plugin._tcp`). Returns `{app, identity, listen()}`. |
| `quickActionHandler(fn)` | Express handler factory for `POST /quick-action` (kind-`'url'` quick actions). `fn(body: {deviceId, managementAddress, actionId}, req) → Promise<{url}>`; 200 on success, 502 + `{error}` when it throws. |
| `buildWebUiUrl(address, {webUiPort?, scheme?}, path?)` | Builds the browser-openable management web-UI URL: explicit `http(s)://` in the address wins verbatim; bare addresses get the configured port (omitted when equal to the scheme default) + optional path. The single home for web-UI URL knowledge — never assemble appliance URLs by hand. |
| `readSettings(req, options)` | Parses the `x-unm-settings` JSON header the API injects on every call, merged over your declared option defaults. Missing/malformed header → sane defaults. |
| `clampInt(v,min,max,fallback)`, `hostFromAddress(addr)`, `pickString/pickNumber` | Small shared helpers. |
| `MetricDescriptor` + factories `gaugeMetric/textMetric/tableMetric/errorDescriptor/modelFirmwareDescriptors` | The metric contract the webapp renders from, plus convenience builders. |
| `INVENTORY_INTERVAL_MS` (15 min) | Conventional refresh cadence for slow-changing inventory walks. |
| `validateInput(schema, value)` / `isValidInput` | Canonical input validation (superset semantics incl. string minLength/maxLength). The plugin's `/config` is the authority — always re-validate there. |
| `createRegistry(actions)` → `{listActions,getAction,listModules,listCatalog}` | Replaces the byId-map + lister boilerplate for action catalogs. |
| `finalizePlan(intentActionId, devices, provisionRequests, rawSteps, isDirty, {rollbackStep?})` | Assigns step indices, re-indexes `dependsOn`, shifts `${steps[N]…}` tokens, and prepends a best-effort rollback step per dirty device (e.g. a config backup). **CRITICAL:** it captures the snapshot count *before* appending raw steps — don't reimplement this by hand. |
| `PlanningError` | Throw for invalid plan requests → HTTP 400 at `/plan`. |
| `CounterTracker` (`{toBitsPerSec?=true, staleMs?}`) | Counter-delta rate tracking: `.sample(key, value)` → bits/s (or Δ/s), null on first sample or counter reset; `.evictStale()`, `.clear()`. Use for any cumulative byte/packet counters. |
| `TtlCache<V>` (`{isFresh?, maxSize?}`) | TTL cache with a quality gate + oldest-first eviction. Pair it with a plain `Map` "lastKnown" fallback to serve stale data on blips instead of flapping health. |
| `createApiClient()` / `isNotFound(err)` | Axios bootstrap for plugins that call BACK into the API's internal `/plugin/*` routes (basic-auth, secrets-provider). Reads `UNM_API_URL` + `PLUGIN_API_KEY`. |
| `createFileRepoClient()` → `{list,getMeta,get,getStream,upload,remove,recordUse}` | The ONE client for UNM's central file repository (`/plugin/files/*`). Use it to store files you download on a device's behalf (config backups, firmware) or fetch repo files to push onto a device via your native transport. Never touch the repo volume directly — the API brokers everything. |
| `configBackupFileName({device?, host?, ext?})` | The shared naming convention for config backups stored in the file repo: `<device>__config-backup-<YYYYMMDD-HHMMSS>.<ext>` (UTC). Use it so every vendor's backups follow one pattern on the Files page. Pair with `createFileRepoClient().upload(data, {name, category:'config-backup'})` and return `details.repoFileId`; restore actions should accept a `repoFileId` input (fetch via `get()`) in addition to legacy base64. |
| `createPluginLogger(identity)` | Structured log shipping to the API (`POST /plugin/logs`). Fire-and-forget batching with drop-on-failure — see §9 Logging. Its queue depth is automatically exposed in `GET /metrics`. |
| `createNotifier(identity)` | Notification-center pushes to the API (`POST /plugin/notifications`) — appliance-level events like vendor alerts. See §10 Notifications. |
| `createSelfMetrics(opts?)` → `{trackMiddleware, handler, collect}` | The self-metrics collector behind the auto-mounted `GET /metrics` (CPU%, memory, event-loop lag, poll stats). Only needed if you build a server by hand instead of using `createPluginServer` — see §11. |
| `requirePluginKey` | Middleware authenticating the calling API via `x-plugin-api-key` (skipped when unset = dev mode). |
| Contract types | `Health`, `MetricDescriptor`, `PluginOptionDescriptor`, `DeviceModelEntry`, `CredentialSlotDescriptor`, `SecretField/SecretType`, `RiskLevel`, `InputSchema(Property)`, `CatalogEntry`, `ProvisionRequest`, `PlanStep`, `Plan`, `PlanDevice<C>`, `PlanRequest<C>`, `StepCredentials`, `MonitoringRequestBody/ResponseBody`, `ConfigRequestBody/ResponseBody`. |

---

## 4. The `/discover` contract

The API polls `<endpoint>/discover` (and listens for mDNS) to register the
plugin. Build it with `createPluginServer({discovery: …})`; the identity core
(uuid, name, version, vendors, capabilities, endpoint, authType) is filled in
for you from `resolvePluginIdentity`. Optional extras:

| Field | Meaning |
| --- | --- |
| `requiredSecretType` | Secret type expected for device credentials (`'usernamePassword'`, `'snmp'`, `'apiKey'`, …). `null` = no credentials. Re-fetched live by the API, never persisted. |
| `requiredSecretTypes: string[]` | Multiple acceptable PRIMARY secret types (e.g. `['usernamePassword', 'sshKeyPair']`). Wins over `requiredSecretType`; declare BOTH when using it so older consumers keep working. The webapp's credential picker offers every listed type. |
| `metrics: MetricDescriptor[]` | Static descriptors (drives webapp visualization + the settings form's metric list). |
| `options: PluginOptionDescriptor[]` | Settings the user can change; values come back via `x-unm-settings`. Discriminated union on `type`: `string` (`enumOptions`, `pattern`, `minLength`, `maxLength`), `integer` (`min`,`max`), `boolean`. Use `enumOptions: string[]` for closed value sets (modes, transports, methods) — the webapp renders a combobox and the API rejects anything outside the list. Always include a `default`. |
| `actions: CatalogEntry[]` | The action catalog (from `createRegistry().listCatalog()`). Only when implementing `/config`. |
| `modules: string[]` | Optional grouping hint for the webapp. |
| `iconUrl` | Relative path served from your static `/icons` dir, e.g. `/icons/my-plugin.svg`. |
| `deviceModels: DeviceModelEntry[]` | `{vendor, model, iconPath?, firmwareVersions?}` — drives Model/Firmware dropdowns; the selection is forwarded to every `/monitoring` call as `model`/`firmwareVersion`. |
| `credentialSlots: CredentialSlotDescriptor[]` | Extra named credentials beyond the primary secret (e.g. a web-UI login for backup actions). `{name, secretType, required?, description?}`. The API passes decrypted slot fields under `credentials.slots.<name>`. |
| `quickActions: QuickAction[]` | One-click shortcuts for the Devices page "Device Actions" column — see §4a below. Advertise the `'quickActions'` capability when at least one entry has `kind: 'url'`. |
| `identityProvider` / `secretsProvider` | Special capabilities — see basic-auth / secrets-provider plugins. |

### 4a. Quick actions (`/discover quickActions`, `POST /quick-action`)

Plugins propagate a small set of one-click shortcuts for their devices, rendered in the Devices page "Device Actions" column (hidden by default; users enable it via the table's Columns picker). Each entry:

```ts
{ id: 'webui', label: 'Web UI', description?: string,
  iconPath?: string,              // optional icon from your /icons dir (API icon proxy); generic glyph when absent
  kind: 'url' | 'shell' | 'files' | 'action',
  url?: { path?: string },        // kind 'url': path appended to the resolved base
  actionId?: string,              // kind 'action': id of a single-device catalog entry
  prefill?: Record<string, unknown> }
```

- **`kind: 'url'`** — open the device's management web UI. The PLUGIN owns ALL URL knowledge (scheme, path, port): implement `POST /quick-action` with the SDK's `quickActionHandler(fn)` and build the URL with `buildWebUiUrl(managementAddress, { webUiPort, scheme }, path)`. **Never hard-code a port** — declare an integer option for it (default = the vendor-known port, e.g. 443/80) and read it via `readSettings(req, PLUGIN_OPTIONS)`; per-device overrides then work automatically through the settings pipeline. The API brokers the click (`POST /v1/devices/:id/quick-action`) with the device's effective settings in `x-unm-settings` and hands the URL to the browser verbatim — no credentials are transmitted.
- **`kind: 'shell'`** — reuses the webapp's SSH console dialog; requires capability `'sshConsole'`. No plugin endpoint needed.
- **`kind: 'files'`** — reuses the filesystem browser dialog; requires capability `'filesystem'`. No plugin endpoint needed.
- **`kind: 'action'`** — runs a catalog entry through the plan workflow with risk gating: `read` = instant, `write` = confirm dialog, **`dangerous` is never offered as a quick action** (the webapp drops it). Use for safe one-click ops like "Reboot"-adjacent reads or service restarts.
- **Icons** — each entry may carry an `iconPath` (relative path served from your static `/icons` dir, same rules as `iconUrl`). The webapp renders it through the API icon proxy (`/v1/plugins/:id/icon?path=…`) and falls back to a generic per-kind glyph when absent or broken: Globe for `url`, Terminal for `shell`, FolderOpen for `files`, Zap for `action`. Up to 3 actions render as plain icon buttons in the row (like the Management Actions column); extras collapse into a "more" dropdown.

The API persists the list on the plugin row and attaches it to every device assignment view (`pluginQuickActions`).

### 4b. Inventory sync into an external monitoring system (capability `'inventorySync'`)

Some plugins do not just READ a device — they keep an **external subsystem** in step with UNM's host inventory: when a host is collected or created in UNM it should appear in the monitoring system, disabling a host there should disable it over there, and removals can be mirrored too. The first consumer is the **zabbix plugin**, but the contract is deliberately subsystem-agnostic so Nagios/Prometheus/… plugins reuse it unchanged:

1. **The API serves the authoritative snapshot** — `GET /v1/plugin/inventory/hosts` (internal, `x-plugin-api-key`). It merges the user-maintained `documented_hosts` (+ their IPs) with recent live observations from the `hosts` table and returns plain data (`InventorySnapshot`, see `packages/plugin-sdk/src/types.ts`): each host carries `id`, `name`, `dnsNames[]`, `tags[]`, `isActive`, `documented`, `addresses[{address, mac, networkLabel, vlanId}]`, `lastSeenAt`. Query params: `documentedOnly=1`, `activeOnly=1`, `search=<text>`. The API never interprets monitoring-system concepts — it only brokers the read.
2. **The plugin owns ALL mapping logic** through its own options + a plan action (the zabbix plugin's `zabbix.host.sync`): name template, target groups, template link, tag filter, IP-interface mode, inactive→disabled and orphan-deletion policy are plain plugin options (`resolveSyncConfig()` in the zabbix plugin is the reference implementation). Adapting to another monitoring system's logic never requires API changes.
3. **Writes go through the plans system** — a sync action is `riskLevel: 'write'` (confirm dialog) and idempotent; per-host failures are collected into `details.errors`, not thrown, so one bad host never aborts the run. A quick action of `kind: 'action'` pointing at the sync entry gives users a one-click "Sync" button on the Devices page for free.
4. **Ownership must be explicit** — a sync may only ever touch hosts IT created/claimed. The zabbix plugin's reference model: every synced host carries a marker tag whose **value is the UNM host id**, so matching/orphan detection are keyed on that value and survive name-template changes (a stale technical name is renamed back, not duplicated). Hosts without the marker tag are never touched; an optional `adoptExisting` claims an untagged Zabbix host with a colliding technical name instead of failing. Ambiguous ownership (two UNM hosts → one Zabbix host) is reported in `details.conflicts`, never acted on automatically.

Advertise `'inventorySync'` in your identity's `capabilities` when you implement such an action. The SDK exports the contract types (`InventoryHost`, `InventorySnapshot`) and `createApiClient()` (the zabbix plugin uses it to fetch the snapshot — set `UNM_API_URL` + `PLUGIN_API_KEY` on the service, same as for log shipping).

---

## 5. `POST /monitoring` (telemetry)

The API's telemetry worker polls every ~30 s with a **hard 10 s budget**.

**Request body** (`MonitoringRequestBody`, credentials already decrypted):
```ts
{ deviceId, managementAddress, ipAddresses?, model?, firmwareVersion?, credentials }
```

**Response** — always HTTP 200; report problems via `health`:
```ts
{ health: 'ok'|'warning'|'critical'|'unknown', metrics: Record<string, unknown>, metricDescriptors?: MetricDescriptor[] }
```

- `metrics` keys must match your descriptor `key`s. Values are rendered by the
  webapp verbatim (pre-format table cells as strings).
- **Inventory propagation** — arrays inside `metrics` that the API ingests into
  its cross-device pages:
  - `networks[]` (`{name, ip?, prefix?, version?, vlanId?, mac?, status?}`) → Networks page
  - `arp[]` / `ndp[]` / `dhcpLeases[]` / `wlanClients[]` / `macTable[]` → Hosts page
  - `tunnels[]`, `routes[]`, `ports[]` → Tunnels/Routes/Config pages
  - **Firewall page:** `firewallRules[]` — one row per firewall rule (filter + NAT kinds), normalized by YOUR plugin to the unified shape so different vendors share one table: `{ruleType: 'filter'|'dnat'|'snat'|'one-to-one'|'npt', vendorRuleId, position, protocol, sourceIp, destIp, sourcePort?, destPort?, action: 'allow'|'deny'|'other', enabled, description, scope, ipVersion?: 'v4'|'v6'|'both', packets?, bytes?, states?, extra?}`. `vendorRuleId` is the stable vendor-side identity (OPNsense uuid / RouterOS `.id`) and part of the row key — `position` is display data only, so reordering rules never churns rows. Normalize protocol to lowercase names (`tcp`, `udp`, …; `''` = any), map filter verdicts to allow/deny (NAT actions → `other`), treat a missing `disabled` flag as enabled, and put vendor-specific leftovers (uuid/family/log/tag for OPNsense; connection-state/time/address-list/to-addresses for RouterOS) into the free-form `extra` object. Set `ipVersion` from your device's family field (OPNsense `family`/`ipprotocol`: inet→v4, inet6→v6, any/inet46→both) or derive it from the address text when there is no explicit field; emit live per-rule hit counters as `packets`/`bytes` when your API exposes them in the same response (RouterOS does), and `states` for connection-state counts where available. Emit even when EMPTY so removed rules vanish on the next poll; omit the key only if your device class has no firewall at all, or when collection FAILED (a failed cycle must not wipe previously stored rows).
    - **Address resolution (API-side):** keep `sourceIp`/`destIp` as configured — alias names are fine. The API resolves them against the cross-device networks + hosts inventory at read time and attaches `sourceResolved`/`destResolved` to each row (matched subnets, carrying interfaces, discovered hostnames/MACs). If your vendor constrains rules via named address lists instead of inline addresses (RouterOS `src-address-list`/`dst-address-list`), store the list CONTENTS in `extra.srcAddressLists` / `extra.dstAddressLists` as `{listName: [address, …]}` — the API folds those into the resolution too.
  - `wifiNetworks[]`, `wifiAirtime[]`, `wifiRadios[]`, `wifiNeighbors[]`, `wlanClients[]` → WiFi page
  - **Storage page:** `filesystems[]` (`{name, type?, mountpoint?, sizeBytes?, usedBytes?, freeBytes?, status?, parent?, extra?}` — types: `zfs-pool`, `zfs-dataset`, `ext4`, `squashfs`, `usb`, `other`) and `disks[]` (`{name, model?, serial?, capacityBytes?, rotationRate?, health?, poolName?, extra?}` — rotation: `hdd|ssd|flash|unknown`). Emit them even when EMPTY so removed datasets/disks vanish on the next poll; omit the key entirely only if your device class has no storage at all. Datasets set `parent` to their pool name — the webapp nests them under the pool row (expander). The optional `extra` JSON object carries plugin-specific details (ZFS dataset props like quota/compression/mount options, disk temperature) stored verbatim for expandable rows and future config/state endpoints.
  - **Containers page:** `containers[]` (`{name, state?, image?, version?, upgradeAvailable?, extra?}`) — one row per App/container workload on the device (TrueNAS SCALE Apps today; any plugin may emit it). `state` is normalized to UPPERCASE at ingest (`RUNNING`, `STOPPED`, …); put vendor-specific details in `extra`: `networks[] {name, driver?, subnets?}`, `ips[]` (static container IPs), `ports[]` (published host ports), `containerCount`, `containers[]` per-service detail `{service, image, state}`, `volumeMounts[]`. Emit even when EMPTY so uninstalled apps vanish on the next poll; omit the key only if your device class has no containers at all.
  - **Security page:** `securityChecks[]` (`{name, kind, status, detail?, count?, extra?}`) — per-appliance security findings; see §5a below. Only rows with `status !== 'ok'` are persisted (the API drops clean checks); emit the key even when EMPTY so resolved findings clear on the next poll, and omit it only when collection FAILED or your device class has no applicable checks at all.
  A key present-but-empty upserts + deletes-on-absent; a key *absent* means "I don't report this" and never wipes data.

Health conventions: unreachable/bad creds → `critical`; stale snapshot or
degraded state → `warning`; wrong device type → `unknown`.

### 5a. Security checks (capability `'securityChecks'`)

Cross-device **Security page** of actionable findings (failed logins, file-integrity changes, active rate limiting, exposed services, account hygiene). Advertise the capability and emit `metrics['securityChecks']` during your INVENTORY window (the checks are comparatively heavy — never on every 30 s poll):

```ts
type SecurityCheckRow = {
  name: string;      // stable identity WITHIN (device, kind) — e.g. "/etc/passwd", "auth-failures"
  kind: 'auth-failures' | 'file-integrity' | 'rate-limiting' | 'account' | 'service-exposure' /* or a custom string */;
  status: 'ok' | 'info' | 'warning' | 'critical';   // 'ok' rows are dropped at ingest
  detail?: string;   // human-readable explanation (shown in the page)
  count?: number;    // optional numeric magnitude (e.g. failure count, banned IPs)
  extra?: Record<string, unknown>;                  // free-form drill-down data
};
```

Conventions:
- **`info`** is for positive/neutral state worth surfacing ("fail2ban active — 3 IPs banned", "a handful of scanner failures") — it persists but renders as a neutral badge. `warning` = should look at this; `critical` = act now.
- Run every check best-effort and in parallel; one missing tool degrades THAT check to not-applicable, never the poll. Wrap the whole emission so a failure omits the key (no wipe).
- **File-integrity checks must NOT auto-resolve.** A changed file keeps raising `critical` until an operator explicitly re-baselines it — otherwise an attacker who edits `/etc/passwd` clears their own finding by editing it again. Persist baselines in the generic state store (§5b) and ship a `security.rebaseline` write action (reference: `plugins/generic-ssh/src/security.ts` + `actions/security.ts`).
- **Custom kinds are allowed** — use a short kebab-case string for a domain-specific check (`wifi-encryption`, `vpn-crypto`, `email-auth`). The webapp renders unknown kinds with a neutral badge and the raw kind text; add a label/style entry in `webapp/src/pages/Security.tsx` (`KIND_LABELS` / `KIND_STYLES`) when you introduce one.
- **Counter-based checks need deltas, not absolutes.** Cumulative counters (e.g. LANCOM WLAN PSK-failure U32s) must be diffed between re-checks or a single old failure stays "critical" forever. Keep a small in-module baseline map keyed per host+object (reset/wrap-safe: `new < old` → re-baseline). Don't reuse the SDK `CounterTracker` for this — it returns a *rate* and your snapshot may be TTL-cached, so repeated identical samples yield 0.
- Reference implementations: **generic-ssh** (file integrity + journald/syslog auth failures + fail2ban/nftables rate limits + uid-0/empty-password accounts), **openwrt** (busybox `logread`, uci firewall `limit` rules, dropbear), **opnsense** (over the optional `ssh` slot — no REST equivalent; FreeBSD `sha256`, `/etc/master.passwd`, pf rate limits), **mikrotik-routeros** (REST-only: `/ip/service` exposure + `/log/print` failed logins), **lancom-lx / lancom-lcos** (SNMP, pure derivation from the already-collected snapshot — no extra walks; WiFi cipher strength + PSK brute-force deltas on LX, IPsec crypto weakness on LCOS routers), **mailcow** (REST: fail2ban ban state as `rate-limiting` info + per-domain DKIM presence/strength as `email-auth`; SPF/DMARC are NOT reachable via the JSON API).

### 5b. Generic plugin state store (persistent data in the UNM database)

Plugins that must remember something ACROSS polls and container restarts — file-integrity baselines, last-seen counters, TOFU fingerprints — use the SDK's `createPluginStateStore({ effectiveUuid })` instead of a local volume or their own DB. The API owns storage (table `plugin_state`, PK `(pluginId, namespace, key)`) behind internal `/v1/plugin/state/*` routes (`x-plugin-api-key`).

- **Natural key = `(namespace, key)`** — `namespace` groups one feature ("file-integrity"), `key` is your stable identity within it ("<host>|/etc/passwd"). `value` is an opaque JSON blob (≤ 64 KB). Every call is scoped to THIS plugin instance automatically.
- **Multi-instance rule:** the scope is the EFFECTIVE uuid (`<uuid>:<instanceId>` when `PLUGIN_INSTANCE_ID` is set). Build ONE shared module-level store per process bound to the resolved effective uuid and use it from BOTH `/monitoring` and your actions — never build a second one in an action from raw env (an unset/incorrect id silently no-ops or clobbers another instance's state). Reference: `plugins/generic-ssh/src/stateStore.ts`.
- **Best-effort by contract:** every operation resolves on failure (`list → {}`, `put → 0`) — a missing key, unreachable API or malformed response degrades to "no state", so e.g. file-integrity simply re-baselines next poll instead of sinking the check.
- Rows carry an optional `deviceId` so deleting a device cascades its baselines; stale rows age out via the API's retention sweep.

---

## 6. Actions, `/config`, and plans (optional)

**Fleet intents** (`network.create`, `network.delete`, `l2.topology.read`) have a
canonical cross-vendor contract — field names, the superset input schemas,
preflight expectations and per-plugin deviations are documented in
[INTENTS.md](./INTENTS.md). The machine-readable source of truth is
`packages/plugin-sdk/src/intents.ts`. Read it before implementing or changing an
intent.

Declare actions with the SDK registry (`createRegistry`), advertise them via
`listCatalog()` in `/discover`, then:

- **`POST /config`** — accept BOTH body shapes the API uses: plan steps
  `{actionId, input}` and legacy config jobs `{action, payload}`. Re-validate
  with `validateInput(action.inputSchema, input)` (the plugin is the authority),
  execute, respond `{success, result}`. Respond 200 even on failure — the API
  only marks a job failed when `success === false`.
- **`POST /plan`** — body `PlanRequest<Credentials>`:
  `{intent:{actionId, inputs}, devices:[{deviceId, managementAddress, credentials}]}`.
  Build raw steps (fan-out per device and/or multi-device intents), then call
  the SDK's `finalizePlan(...)` to get indices/dependencies/token-shifting/rollback
  right for free. Throw `PlanningError` → HTTP 400.

### Verifying outcomes (`ActionResult.verified`)

The API marks a plan **succeeded** only when every non-best-effort write step
was *confirmed*, not merely acknowledged. Your action's `execute()` should:

1. capture the BEFORE state (store it in `details.before` — users can then see
   old → new, e.g. uptime 42d → 0s after a restart);
2. apply the change;
3. re-read device state and report it via `verified`:

```ts
import { pollUntil } from '@unm/plugin-sdk';

async execute(ctx, input) {
  const before = await readState(ctx, input);          // optional pre-capture
  await applyChange(ctx, input);                        // the actual write
  const wait = await pollUntil(                         // bounded re-read loop
    () => readState(ctx, input),
    (s) => s === TARGET_STATE,                          // e.g. 'STOPPED' / uptime reset
    { timeoutMs: 60_000, intervalMs: 3_000 },
  );
  return {
    success: true, applied: true, verified: wait.ok,
    details: { before, after: wait.value ?? null, ...(wait.ok ? {} : { note: 'state not confirmed within timeout' }) },
  };
}
```

Semantics the executor applies per step (non-best-effort only):

| `verified` in result | step status | plan outcome |
|---|---|---|
| `true` | succeeded | contributes to **succeeded** |
| absent / `false` | succeeded | plan ends **unverified** (applied, not confirmed) + warning notification |
| — with `success: false` | failed | plan ends **failed** |

Read-only actions (`riskLevel: 'read'`) are exempt — a read is its own
confirmation. Use the SDK's `pollUntil(probe, isDone, {timeoutMs, intervalMs})`
helper (probe errors are swallowed; only the bounded timeout decides) and keep
verification INSIDE `execute()` — it must not exceed the action's `timeoutMs`.

### Retrying failed steps (`ActionResult.retryable` / `waitMs`)

A plan step that FAILS is re-dispatched by the executor **only when the failure
is transient**. The retry budget comes from the plan's retry policy (per-plan
override ⊕ global settings `planStepRetryMaxAttempts` / `planStepRetryWaitMs`,
visible on the Settings page and editable per plan in the webapp). You decide
WHICH failures are transient:

| How your action reports | Executor behavior |
|---|---|
| **Dispatch-level failure** (the plugin was unreachable or the round-trip timed out) | **Transient by default** — the device may simply not be ready yet (reboot, update in flight). Re-dispatched per the retry policy unless your action opts out below. |
| `{ success: false, retryable: true }` | **Transient** — the step is dispatched again until `maxAttempts` TOTAL dispatches (initial + retries), waiting `waitMs` (or your per-failure hint) between attempts. Use for "appliance not ready yet", "service still starting", "container not up", "job queue busy". The SDK's `isTransientTransportError(err)` classifies connection/timeout/socket-drop errors for exactly this — wire it into your `/config` catch so transport failures come back as `{ success: false, retryable: true }`. |
| `{ success: false, retryable: true, waitMs: 120_000 }` | Same, but the NEXT attempt waits your suggested `waitMs` (clamped to ≤ 3600 s) instead of the policy default — e.g. minutes for an update to settle. |
| `{ success: false }` or a **thrown error** without classification | **Hard failure** — fails the plan immediately, no retries, regardless of the retry policy. Use for validation errors, missing objects, wrong states that will not fix themselves. |

Rules of thumb:

- A thrown exception is hard UNLESS your `/config` catch classifies it as a
  transient transport error (see `isTransientTransportError`). When you want a
  retry, RETURN `{ success: false, retryable: true, error: '…' }`.
- Retries re-dispatch the SAME step with the SAME input — keep actions
  idempotent (the executor already skips steps whose target state is reached).
- The wait between attempts is interruptible by a user cancel; each attempt gets
  its own `config_jobs` row, so every dispatch stays auditable.

You can also steer the retry policy for an ENTIRE plan from your `/plan`
handler — e.g. disable retries for a critical intent where any failure must
surface immediately:

```ts
return {
  id, createdAt, intentActionId, provisionRequests, steps,
  retryPolicy: { maxAttempts: 0 },   // or { waitMs: 60_000 } to slow the default down
};
```

The user's explicit choice at creation time (or an edit before execution) wins
over your suggestion; omit `retryPolicy` to inherit the global defaults.

#### Flapping guard (`ActionDescriptor.retryOnDispatchFailure`)

Retries re-dispatch the SAME step — which is exactly what you do NOT want for
actions that cause flapping states: a failed `system.reboot` whose dispatch
timed out (the box went down) must not be sent again, or the switch would be
rebooted twice. Declare such actions with `retryOnDispatchFailure: false`:

```ts
const systemRebootAction: ActionDescriptor<MyContext> = {
  id: 'system.reboot',
  // …
  riskLevel: 'dangerous',
  retryOnDispatchFailure: false,   // a failed attempt is ALWAYS final — no re-dispatch
  inputSchema: {},
  execute: async (ctx) => { /* … */ },
};
```

The flag is advertised in `/discover` and honored by the executor for EVERY
failure kind of that action — it overrides both the dispatch-level transient
guess and a plugin-reported `retryable: true`. Set it on power actions
(reboot/halt/shutdown), firmware flashes, config restores/resets, and any other
non-idempotent or device-downing operation. Everything else (config writes,
service restarts, container upgrades) should keep the default so "device not
ready yet" failures self-heal.

---

## 7. Device state — `POST /state` (the Config page)

The webapp's per-device **Config** page renders a *dynamic* device-state
document: sections of items (switch ports with live states + learned MACs,
appliance interfaces, ZFS pools, system info) plus context-aware action
references. **Plugins own the shape; the API is a generic broker.** New device
kinds (file systems, ZFS pools, …) cost zero API or webapp changes — you just
return more sections.

**Advertise it:** add `'deviceState'` to your `capabilities`. The Config page's
plugin selector only lists assignments whose plugin advertises this capability.

**Request body** (`StateRequestBody`, credentials already decrypted — same
model as `/monitoring`):
```ts
{ deviceId, managementAddress, ipAddresses?, model?, firmwareVersion?, credentials }
```

**Response** — `DeviceStateResponse`; the API returns it to the webapp verbatim:
```ts
{
  collectedAt: string, // ISO timestamp
  sections: [
    {
      id: 'ports',            // stable section key
      label: 'Ports',         // rendered as the band title
      description?: string,   // optional one-liner under the title
      kind?: 'table'|'switch',// 'switch' → virtual switch face (see below); default 'table'
      layout?: {              // only for kind:'switch' — bands top→bottom; absent = generic rows
        groups: [
          { id: 'row-rj45', label: 'RJ45', portKeys: ['1','2', …] },  // keys must match item.key
          { id: 'row-sfp',  label: 'SFP+', portKeys: ['9','10'] },
        ],
      },
      items: [
        {
          key: 'P1',                          // stable item key within the section
          title: 'Port 1',                    // bold row header
          subtitle?: 'port 1',                // small text next to the title
          status?: 'up'|'down'|'disabled'|'ok'|'degraded'|'critical'|…, // badge (free string)
          fields: { Speed: '1G', MACs: ['aa:bb:…'], PVID: 5 }, // arrays → chip lists
          actions?: [{ actionId: 'port.config.set', prefill: { port: 1 } }],
        },
      ],
      actions?: [{ actionId: 'system.reboot' }], // section-level, no item context
    },
  ],
}
```

**Virtual switch face (`kind: 'switch'`):** sections with this kind render as a
front-panel view instead of a table — one compact cell per port (LED colored by
status, port number, one info line; full details incl. learned MACs in the
tooltip). Clicking cells selects ports for **bulk actions**: the webapp shows an
action bar with every catalog action at least one selected port supports and
applies it to ALL of them as one plan (one step per port — 2FA + `configs:apply`
+ audit trail apply exactly like single-port actions).

- Propagate a **model-specific layout** via `layout.groups`: bands top→bottom,
  each with an optional label (`'RJ45'`, `'SFP+'`) and the item keys in panel
  order. Items not referenced by any band are appended as a trailing unlabeled
  band, so nothing is ever hidden.
- **No layout?** The webapp falls back to a generic face: numeric port order
  split into balanced rows (a 48-port switch becomes 3×16). Use the SDK helper
  `suggestPortLayout(items, rows?)` if you want to emit that fallback yourself.
- Keep per-item `actions` + `prefill` — bulk execution reuses each port's own
  prefill (e.g. `{port: N}`) and merges in the shared values from the dialog.

**Rules:**
- Every `actionId` must be a **single-device** entry of YOUR persisted catalog —
  the API validates against `/discover` and silently strips unknown refs (a
  stale state document must never surface an unexecutable button).
- `prefill` is merged UNDER your schema defaults in the action dialog, so it's
  how "shutdown THIS port" carries `{port: 5}` into the form.
- **Execution always flows through the plan workflow** — the webapp creates a
  1-step plan and executes it immediately (2FA + `configs:apply` apply). You
  never get a direct write call from the Config page; your `/config` handler is
  the only execution path. Mark destructive actions `riskLevel: 'dangerous'` —
  the dialog then shows a red confirm step.
- Use the SDK's `stateHandler(fn, logTag)` wrapper: it validates the body and
  converts thrown errors into a JSON error envelope (Express 4 does not catch
  async rejections). Your callback receives `(body, req)` so you can call
  `readSettings(req, …)`.

**Inventory shortcut — `metrics['ports']`:** if your `/monitoring` also emits a
`ports[]` array (`PortRow`: `{name, status?, speed?, duplex?, vlanId?, poe?, extra?}`),
the API normalizes it into the cross-device `device_ports` table (upsert on
deviceId+pluginId+name, delete-on-absent). That powers port views across devices
and is a cheap fallback for plugins that don't implement `/state`.

Reference implementations: `plugins/lancom-sx/src/state.ts` (switch ports +
variant-aware actions, single-band layout), `plugins/opnsense/src/state.ts`
(interfaces + system power actions), `plugins/mikrotik-swos/src/state.ts` (ports
with PoE/LAG/VLANs + learned MACs, RJ45/SFP+ band layout from SFP diagnostics),
`plugins/ix-truenas/src/state.ts` (ZFS pools + interfaces). The webapp's
reusable face renderer lives in `webapp/src/components/VirtualSwitch.tsx`.

---

## 8. Settings round-trip

Declare options in `/discover`; read them on every request with
`readSettings(req, PLUGIN_OPTIONS)`. The API persists user overrides and injects
them via the `x-unm-settings` header — **the plugin never stores settings**.
Clamp integers with `clampInt` so a bad override can't break collection.

---

## 9. Logging (ship structured logs to the API)

Every plugin should emit its console-worthy events as structured log entries so
they show up in the webapp — per device (DeviceDetail → Logs section) and
globally (Logs page with level/plugin/device/search/time-range filters).

**Setup (once, at startup):**
```ts
import { createPluginLogger } from '@unm/plugin-sdk';
const logger = createPluginLogger(identity); // identity from resolvePluginIdentity()
```

**Gate emission per call** with the conventional `logToApi` boolean option
(default `true`) — it flows through the settings loop, so users can disable it
globally or per-device in the Settings UI:
```ts
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  // …your options…
  { key: 'logToApi', label: 'Send logs to UNM', type: 'boolean' as const, default: true,
    description: 'Ship structured log entries (poll failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.' },
];

// in each handler, right after readSettings():
const settings = readSettings(req, PLUGIN_OPTIONS);
logger.setEnabled(settings.logToApi === true);
```

**Emit at your existing error sites** (keep the `console.error` too — container
logs stay useful for debugging):
```ts
logger.error(`Monitoring poll for ${host} failed: ${(err as Error).message}`, {
  deviceId,                                   // null/omit for plugin-level events
  context: { host },                          // arbitrary JSON details (capped ~8KB)
});
// levels: logger.debug / .info / .warn / .error — message capped ~2KB at ingest
```

**Semantics:** entries are batched in memory (~2 s flush, max 500 queued,
drop-oldest on overflow) and POSTed to the API's internal `POST /plugin/logs`
with the shared `x-plugin-api-key`. **Drop-on-failure**: if the API is
unreachable or rejects a batch, entries get one retry then are silently
dropped — logging must never break a poll, config job, or plan step. Without
`PLUGIN_API_KEY` set the logger degrades to a no-op (with a startup warning).
Entries are kept `LOG_RETENTION_DAYS` (default 7) on the API side.

**What NOT to log:** per-poll success spam (the telemetry table already shows
health), secrets/credentials, or anything that would make logs grow unbounded.
Log failures and state changes; keep messages short — details go in `context`.

---

## 10. Notifications (push appliance-level events to the notification center)

The UNM webapp has a **notification center** — a bell in the top-right with an
unread badge, plus a full Notifications page with filters. Three sources feed it:

- **system** — the API itself (plan failures, config-job failures);
- **device** — mirrored automatically from telemetry (a device going offline /
critical / degraded notifies; recovery resolves it). You do NOT push these;
- **plugin** — pushed by YOU via `createNotifier()` for events only your plugin
  can see: vendor alert lists, firmware availability, pool scrub failures, …

**Setup (once, at startup):**
```ts
import { createNotifier } from '@unm/plugin-sdk';
const notifier = createNotifier(identity);
```

**Gate emission per call** with a conventional boolean option (default `true`),
same pattern as `logToApi`:
```ts
{ key: 'notifyAlerts', label: 'Mirror alerts to notification center', type: 'boolean' as const, default: true,
  description: 'Push active appliance alerts into the UNM notification center.' },

// in each handler, right after readSettings():
notifier.setEnabled(settings.notifyAlerts === true);
```

**Emit + resolve:** ongoing conditions MUST carry a stable `dedupeKey` — while
the condition persists the API upserts the same row (occurrences bump), and when
it clears you call `resolve()` with the same key so the row auto-resolves:
```ts
notifier.warning(`${hostname}: SMART uncorrected errors on da0`, {
  dedupeKey: 'alert:smart-uncorrected:da0',   // stable per condition!
  deviceId,
  context: { klass: 'SMARTUncorrectedErrorsAlert' },
});
// …later, when the alert disappears from the appliance:
notifier.resolve(['alert:smart-uncorrected:da0']);
```
One-shot events ("backup completed") omit `dedupeKey` — they stay until a user
acknowledges/closes them or retention sweeps them.

**Semantics:** fire-and-forget batching (~2 s flush, max 200 queued,
drop-oldest on overflow) to the internal `POST /plugin/notifications` with the
shared `x-plugin-api-key`; drop-on-failure (a notification must never break a
poll). Severities: `info | warning | critical`. Without `PLUGIN_API_KEY` set the
notifier degrades to a no-op. The API prefixes your dedupe keys with
`plugin:<your-uuid>:` so different plugins can't collide.

**What NOT to push:** per-poll success spam, raw log lines (use the logger),
or device reachability — the API already mirrors offline/degraded/critical from
telemetry. Push appliance-level state that telemetry health alone doesn't tell.

---

## 11. Self-metrics (your plugin's own runtime health)

Every plugin built with `createPluginServer()` automatically serves **`GET /metrics`**
— no code needed. The API polls it every 30 s and stores samples in
`plugin_metrics`; the webapp's Plugins page shows them per plugin (hover a row).
What is collected, and why you'd look at it:

| Field | Meaning |
| --- | --- |
| `cpuPercent` | % of ONE core over the last sample window (>100 possible on multi-core hosts). A plugin that should be idle but burns CPU (e.g. a walk loop that stopped being paced) shows up here. Note: SNMP traffic is native UDP in-process (`@unm/snmp-client`) — its cost shows in poll duration, not CPU. |
| `heapUsedBytes` / `heapTotalBytes` / `rssBytes` | Node heap + resident set size. Monotonic heap growth = leak; in a single-node-process container RSS ≈ the container's memory usage. |
| `eventLoopLagMs` | Moving-average event-loop lag (ms). The classic Node overload indicator — catches blocking work that CPU% misses. 0 is healthy. |
| `inFlight` | `/monitoring` + `/config` + `/plan` requests currently being handled. **>1 means a poll is taking longer than the API's 30 s cycle** → slow device or stuck walk; this directly explains telemetry gaps. |
| `lastPollMs` / `errorRatePercent` | Duration and failure rate of the last 20 work requests. Distinguishes "plugin overloaded" from "device unresponsive". |
| `emittedMetricsCount` | Metric keys in your LAST `/monitoring` payload — the actual per-poll telemetry weight (vs. the declared descriptor count shown next to it). Grows as you add metrics; a proxy for DB write cost. |
| `logQueueDepth` | Pending entries in the plugin logger queue (absent when you have no logger). A full queue means log shipping is falling behind. |
| `uptimeSeconds` | Process age — context after restarts (cold caches, first-sample nulls). |

**Custom gauges:** pass `selfMetricsExtra` to `createPluginServer()` — an object or a function returning an object of finite numbers, merged into the response under its own keys. Nothing needs it on day one; everything above is collected generically in the SDK.

If you build your express app by hand (no `createPluginServer`), mount the same thing yourself:
```ts
import { createSelfMetrics } from '@unm/plugin-sdk';
const selfMetrics = createSelfMetrics(); // optional: { extra, windowSize }
app.use(selfMetrics.trackMiddleware);    // BEFORE your /monitoring, /config, /plan routes
app.get('/metrics', selfMetrics.handler);
```

Samples are kept `LOG_RETENTION_DAYS` (default 7) and swept by the same retention worker as plugin logs.

---

## 11. Verification checklist (per plugin)

```bash
cd plugins/<your-plugin> && npx tsc --noEmit        # type-check
# after ANY @unm/plugin-sdk edit: rebuild + refresh the file:-linked copies
cd ../../packages/plugin-sdk && npm run build       # then re-run `make setup`/build or cp into each node_modules
```

Then, from the repo root: `make build`, and for a live check
`docker compose up -d --build <your-plugin> api` — confirm `/discover` returns
the expected catalog and the API registers the plugin.

### 11a. The standardized contract suite (CI gate)

Every plugin is covered by the **plugin test kit** (`packages/plugin-test-kit`)
— a Docker-free harness that spawns your BUILT plugin standalone against
in-process mock appliances and runs a capability-driven contract suite:
`/healthz`, full `/discover` descriptor validation, settings robustness,
monitoring happy-path (T4) + dead-target handling (T5), and — when you advertise
them — the `/config`, `/plan` and `/probe` contracts. This is what CI runs to
catch fatal flaws before a plugin ships:

```bash
make build                                        # the kit tests dist/ output
node packages/plugin-test-kit/bin/run.mjs <name>  # one plugin
node packages/plugin-test-kit/bin/run-all.mjs     # every plugin (CI entry point)
# or simply: make test / make plugin-tests
```

To give your plugin a real T4 happy-path, add `plugins/<your-plugin>/test/config.mjs`
pointing the suite at a mock appliance (shared mocks for HTTP, SNTP and the Docker
Engine API live in the kit; see its README). Without one, only the
transport-agnostic tests run. New plugins get the baseline automatically — no
registration anywhere is needed.
