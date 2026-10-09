# @unm/plugin-test-kit

Standardized per-plugin test suite for UnifiedNetworkManager. Spawns each **built**
plugin as a standalone child process (no `UNM_API_URL`/`PLUGIN_API_KEY`, so no
self-registration side effects) against in-process mock appliances and runs a
capability-driven contract suite. **No Docker required** — plain Node 20+.

## Run

```bash
make build   # once — the kit tests dist/src/index.js, not source
node packages/plugin-test-kit/bin/run-all.mjs                 # every plugin
node packages/plugin-test-kit/bin/run.mjs generic-ntp         # one plugin (by name or dir)
node packages/plugin-test-kit/bin/run-all.mjs --only docker,generic-http
```

CI: `make build && node packages/plugin-test-kit/bin/run-all.mjs` — exit 0 only when
every suite passes. Unbuilt plugins are reported, not failed (so partial local runs work).

## What the contract suite checks

| Test | Applies to | Catches |
| --- | --- | --- |
| T1 `GET /healthz → 200 ok` | all | dead-on-arrival builds |
| T2 `/discover` validation | all | broken descriptors: bad uuid/semver, unknown capabilities, duplicate metric keys/options/action ids, options without defaults, enum default outside list, min>max, table metrics without columns, device-model vendor mismatch (warning) |
| T3 settings robustness | `monitoring` | malformed/missing `x-unm-settings` must not crash the poll |
| T4 monitoring happy-path | `monitoring` + config | always-200 contract, known health value, ISO `collectedAt`, expected health against the mock appliance |
| T5 dead-target handling | `monitoring` (opt-out via `skipDeadTarget`) | unreachable device → bounded failure (< 20 s; API budget is 10 s), not a hang or crash |
| T6 configuration contract | `configuration` | unknown actionId → clean 4xx / `success:false`, no crash |
| T7 planning contract | `planning` | invalid plan request → clean 4xx (PlanningError) |
| T8 probe envelope | `probe` | `/probe` answers with JSON, never hangs |

## Per-plugin config — `plugins/<name>/test/config.mjs`

Optional. Without one, only the transport-agnostic tests run (T1–T3 + capability-gated
negatives). With one:

```js
export default {
  // Declarative mocks (first mock's port is substituted into ${mockPort}):
  mocks: { http: {...}, ntp: {...}, dockerDaemon: true },
  monitoringAddress: 'http://127.0.0.1:${mockPort}',   // T4 target
  settings: {},            // x-unm-settings for T4 (e.g. { transport:'tcp', port })
  expectHealth: 'ok',      // or omit → asserts "no system.error metric"
  deadAddress: '...',      // T5 target (default: closed 127.0.0.1 TCP port)
  settingsForDead: {},     // x-unm-settings for the dead-target poll
  expectDeadHealth: 'critical',
  skipDeadTarget: true,    // for self-health plugins (flow-collector, web-fetch)
  assumeCaps: ['monitoring'], // opt in when /discover advertises no capabilities
  env: { SFLOW_PORT: '...' }, // extra child-process env

  // OR full control — start your own mocks and return the suite config. The runner
  // spreads the WHOLE mock barrel (see "Shared mock appliances"), so every starter is
  // available by name: startHttpMock, startNtpMock, startDockerDaemonMock,
  // startOpnsenseMock, startMailcowMock, startZabbixMock, startFboxMock,
  // startOpenwrtMock, startRouterOsMock, startTruenasMock, startSshMock, startSnmpMock.
  async setup({ startHttpMock, getDeadTcpPort, getDeadUdpPort }) {
    const http = await startHttpMock();
    return { mocks: [http], config: { monitoringAddress: `127.0.0.1:${http.port}`, ... } };
  },

  // Plugin-specific assertions (run after T1–T8):
  extraChecks: async ({ url, discover, caps, optionKeys, rec }) => {
    rec.check('X', 'label', condition, detailOnFailure);
  },
};
```

## Shared mock appliances (`src/mocks/`)

All bind ephemeral ports on 127.0.0.1 and expose `{port, url?, requests?, stop()}`.
Re-exported through the barrel `src/mocks/index.js`, which the runner spreads into a
config's `setup({ …mocksApi, getDeadTcpPort, getDeadUdpPort })` — so every starter
below is available by name in any `test/config.mjs`.

**Transport primitives:**
- `startHttpMock({path,status,body})` — plain HTTP server + request capture.
- `startNtpMock({stratum,precision})` — RFC 1305 SNTP responder (current time).
- `startDockerDaemonMock()` — Engine API read endpoints (`/version`, `/containers/json`, `/images/json`).

**Phase 2 — plain-HTTP appliance fixtures** (`applianceHttp.js`; each speaks just
enough of that appliance's REST/session API to make a `/monitoring` poll report
health `ok`. Configs force plain HTTP via an explicit `http://…` address or a
`transport:'http'` setting so no in-process TLS/cert generation is needed):
- `startOpnsenseMock()` — Basic auth; health from `GET /api/core/system/status`.
- `startMailcowMock()` — `X-API-Key`; decisive `GET /api/v1/get/status/version`.
- `startZabbixMock()` — JSON-RPC over POST `/zabbix/api_jsonrpc.php` (answers by method).
- `startFboxMock()` — classic-UI session flow (`/login_sid.lua` → SID cookie) + `/systeminfo64.json`.
- `startOpenwrtMock()` — LuCI session flow; answers the ubus `network.interface dump` + per-interface status (the only live metric in LuCI-only mode).
- `startRouterOsMock()` — RouterOS REST API (`/rest/<table>`, Basic auth); probe gate `/rest/system/resource` + `/rest/interface` rows.

**Phase 2 — TrueNAS:** `truenasMock.js` → `startTruenasMock()`: JSON-RPC 2.0 over
WebSocket (`ws`). Config forces `transport:'http'` for a plain `ws://`.

**Phase 3 — SSH appliance:** `sshMock.js` → `startSshMock()`: an in-process `ssh2`
Server that accepts any password auth and answers exec channels with canned output,
including the marker-batched live-metrics script (`UNM_SECTION:<name>:BEGIN/END`).

**Phase 3 — pure-JS SNMP v2c agent:** `snmpMock.js` → `startSnmpMock({mib, community})`:
a dependency-free RFC 3416 agent over UDP answering GET / GETBULK. Value types in a
MIB profile: `'int'`→Integer32, `'str'`→OCTET STRING, `'c64'`→Counter64 (tag `0x46`).
Two MIB-profile modules ship with it:
- `lancomMibs.js` → `lcosMib()`, `sx4Mib()`, `lxMib()` — LANCOM **column-first** tables (`<table>.1.<col>.<idx>`); text indexes are length-prefixed ASCII sub-ids, MACs raw 6-byte Buffers.
- `standardIfMib.js` → `genericSnmpMib()` — standard IF-MIB/SNMPv2-MIB layout (`<table>.<field>.<ifIndex>`).

The SNMP plugins take a non-default agent port via the plugin option `snmpPort`
(default 161) because UDP/161 is not bindable as a non-root user. Verified against
the real `@unm/snmp-client` by `bin/verify-snmp-mock.mjs` (standalone, no plugin).

## Monitoring coverage matrix

| Plugin | T4/T5 mock | Notes |
| --- | --- | --- |
| generic-http / generic-ntp / docker / icmp / flow-collector / web-fetch | http / ntp / docker-daemon / — | transport primitives (pre-existing) |
| opnsense, mailcow, zabbix, fbox, openwrt, mikrotik-routeros | `applianceHttp.js` fixtures | Phase 2 HTTP appliances |
| ix-truenas | `truenasMock.js` | JSON-RPC over WebSocket |
| generic-ssh | `sshMock.js` | dead-target floor is `warning`, not `critical` (see below) |
| lancom-lcos / lancom-sx / lancom-lx, generic-snmp | `snmpMock.js` + MIB profiles | dead-target health is `unknown` by design |
| mikrotik-swos | — (basic-only) | binary `.b` protocol; T1–T3 + capability negatives only |

Two deliberate "floor" decisions worth knowing:
- **generic-ssh** reports `warning` (not `critical`) on a dead target because its
  collector unconditionally emits the stored `system.privilege` field, so metrics is
  never empty. Only a *missing* credential yields `critical`. The config asserts the
  real contract (`expectDeadHealth: 'warning'`).
- **LANCOM** plugins report `unknown` (not `critical`) on a failed probe by design —
  "may simply be assigned to the wrong device type". Configs use
  `expectDeadHealth: 'unknown'` and a distinct dead host (`127.0.0.2`) because their
  snapshot cache is keyed by bare host, not port.

## Standalone fixtures (`src/fixtures/`)

Full-stack e2e test doubles — plain CJS scripts (no kit imports, no build step),
run as separate processes against the LIVE dev stack. These are the single home
for every mock appliance/exporter in the repo:

- `netflowExporter.cjs` — NetFlow v5 + v9 UDP exporter (v9 sends one template
  datagram at startup, then data-only packets). Exports byte builders for unit tests.
- `sflowExporter.cjs` — sFlow v5 UDP exporter (IPv4/IPv6 flow samples + counter
  samples). Exports record builders for unit tests.
- `geoipWebserver.cjs` — GeoIP MMDB/CSV fixture server with an optional
  `--proxy` mode (CONNECT tunnel) for the webFetch proxy chain.
- `opnsenseAppliance.cjs` — mock OPNsense appliance on host :80/:443 (self-signed
  TLS from `tls/`, request capture at `/__requests`). Mounted by the compose
  service `mock-appliance` (profile `test` — start with
  `docker compose --profile test up -d mock-appliance`; plain `up` never starts it).

Consumers: `scripts/e2e-flows.cjs`, `scripts/e2e-geoip.cjs` (spawn them),
`scripts/verify-netflow-parser.cjs` / `verify-sflow-parser.cjs` (require their
byte builders). The kit's in-process mocks above are what the T1–T8 contract
suite uses; these fixtures exist because those e2e scripts exercise the live
API + DB pipeline, which the standalone suite does not.

## Adding a new plugin's suite

1. `cp -r plugins/_template plugins/my-plugin` → implement it.
2. Add `plugins/my-plugin/test/config.mjs` pointing T4 at the right mock (or skip
   T4 if there is no appliance to fake yet — T1–T3 + capability negatives still run).
3. Done — the runner picks up every `plugins/*/package.json` automatically.
