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
The host mapping in `docker-compose.yml` is the only per-plugin choice and it
exists solely for curl-from-host debugging + `setup.sh`'s `wait_for_port`:

```yaml
my-plugin:
  build: { context: ., dockerfile: plugins/my-plugin/Dockerfile }
  ports: ["4010:4080"]          # ← next free HOST port (4001–4009 are taken)
  environment:
    - PORT=4080                 # always the same inside the container
    - ADVERTISED_ENDPOINT=http://my-plugin:4080   # how the API reaches it
```

- `PORT` — internal listen port. Leave at `4080`; the SDK's
  `resolvePluginIdentity` reads it (default 4080).
- `ADVERTISED_ENDPOINT` — the URL the plugin advertises in `/discover` + mDNS.
  Without it the plugin advertises `http://localhost:4080`, which is
  unreachable from the API's own container. **Always set it to
  `http://<compose-service-name>:4080`.**
- New plugins pick the next free HOST port (currently **4010**) and append
  their endpoint to the api service's `PLUGIN_POLL_ENDPOINTS` list in
  `docker-compose.yml`.

Multi-instance: set `PLUGIN_INSTANCE_ID=site-a` (+ optional
`PLUGIN_DISPLAY_NAME`) on a second service using the same Dockerfile. The SDK
then advertises `<uuid>:site-a` as a distinct plugin. See the commented
`icmp-site-a` example in `docker-compose.yml`.

---

## 2. Creating a new plugin

```bash
cp -r plugins/_template plugins/my-plugin
# edit: package.json (name), Dockerfile (folder name ×3), src/index.ts (UUID, name)
cd plugins/my-plugin && npm install --legacy-peer-deps && npx tsc --noEmit
```

Then register it in `docker-compose.yml` (service block above) and add its
endpoint to the api's `PLUGIN_POLL_ENDPOINTS`. Add a build line to the
Makefile's `build:` target if you want `make build` to cover it.

The Dockerfile uses the **repo root as build context** so it can copy + build
the shared SDK first — keep that structure when editing.

---

## 3. What the SDK gives you (`@unm/plugin-sdk`)

| Export | Purpose |
| --- | --- |
| `resolvePluginIdentity({uuid,name,version,vendors,capabilities,authType?})` | Multi-instance identity from env (`PORT`, `ADVERTISED_ENDPOINT`, `PLUGIN_INSTANCE_ID`, `PLUGIN_DISPLAY_NAME`). Returns `{effectiveUuid, displayName, port, endpoint, …}`. |
| `createPluginServer({identity, logTag?, jsonLimit?, iconsDir?, discovery?, selfMetricsExtra?})` | Pre-wired express app: cors + json + `/healthz` + `/discover` + **auto-mounted `GET /metrics`** (self-metrics — see §9) (+ static `/icons`). `.listen()` binds the port and starts mDNS advertising (service type `_unm-plugin._tcp`). Returns `{app, identity, listen()}`. |
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
| `createPluginLogger(identity)` | Structured log shipping to the API (`POST /plugin/logs`). Fire-and-forget batching with drop-on-failure — see §8 Logging. Its queue depth is automatically exposed in `GET /metrics`. |
| `createSelfMetrics(opts?)` → `{trackMiddleware, handler, collect}` | The self-metrics collector behind the auto-mounted `GET /metrics` (CPU%, memory, event-loop lag, poll stats). Only needed if you build a server by hand instead of using `createPluginServer` — see §9. |
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
| `metrics: MetricDescriptor[]` | Static descriptors (drives webapp visualization + the settings form's metric list). |
| `options: PluginOptionDescriptor[]` | Settings the user can change; values come back via `x-unm-settings`. Discriminated union on `type`: `string` (`pattern`, `minLength`, `maxLength`), `integer` (`min`,`max`), `boolean`. Always include a `default`. |
| `actions: CatalogEntry[]` | The action catalog (from `createRegistry().listCatalog()`). Only when implementing `/config`. |
| `modules: string[]` | Optional grouping hint for the webapp. |
| `iconUrl` | Relative path served from your static `/icons` dir, e.g. `/icons/my-plugin.svg`. |
| `deviceModels: DeviceModelEntry[]` | `{vendor, model, iconPath?, firmwareVersions?}` — drives Model/Firmware dropdowns; the selection is forwarded to every `/monitoring` call as `model`/`firmwareVersion`. |
| `credentialSlots: CredentialSlotDescriptor[]` | Extra named credentials beyond the primary secret (e.g. a web-UI login for backup actions). `{name, secretType, required?, description?}`. The API passes decrypted slot fields under `credentials.slots.<name>`. |
| `identityProvider` / `secretsProvider` | Special capabilities — see basic-auth / secrets-provider plugins. |

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
  its Networks/Hosts pages: `networks[]` (`{name, ip, vlanId?, status?}`),
  `macTable[]` (`{mac, intf}`). A key present-but-empty upserts + deletes-on-absent; a key *absent* means "I don't report this" and never wipes data.

Health conventions: unreachable/bad creds → `critical`; stale snapshot or
degraded state → `warning`; wrong device type → `unknown`.

---

## 6. Actions, `/config`, and plans (optional)

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

---

## 7. Settings round-trip

Declare options in `/discover`; read them on every request with
`readSettings(req, PLUGIN_OPTIONS)`. The API persists user overrides and injects
them via the `x-unm-settings` header — **the plugin never stores settings**.
Clamp integers with `clampInt` so a bad override can't break collection.

---

## 8. Logging (ship structured logs to the API)

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

## 9. Self-metrics (your plugin's own runtime health)

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

## 10. Verification checklist (per plugin)

```bash
cd plugins/<your-plugin> && npx tsc --noEmit        # type-check
# after ANY @unm/plugin-sdk edit: rebuild + refresh the file:-linked copies
cd ../../packages/plugin-sdk && npm run build       # then re-run `make setup`/build or cp into each node_modules
```

Then, from the repo root: `make build`, and for a live check
`docker compose up -d --build <your-plugin> api` — confirm `/discover` returns
the expected catalog and the API registers the plugin.
