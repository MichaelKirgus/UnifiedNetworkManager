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

  // OR full control — start your own mocks and return the suite config:
  async setup({ startHttpMock, startNtpMock, startDockerDaemonMock, getDeadTcpPort, getDeadUdpPort }) {
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

- `startHttpMock({path,status,body})` — plain HTTP server + request capture.
- `startNtpMock({stratum,precision})` — RFC 1305 SNTP responder (current time).
- `startDockerDaemonMock()` — Engine API read endpoints (`/version`, `/containers/json`, `/images/json`).

All bind ephemeral ports on 127.0.0.1 and expose `{port, url?, requests?, stop()}`.
Phase 2 will add an in-process SSH server mock (`ssh2` Server) for the appliance
plugins that collect over SSH; Phase 3 a pure-JS SNMP agent (UDP GET/BULKWALK).

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
  service `mock-appliance`.

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
