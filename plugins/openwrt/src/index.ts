/**
 * OpenWRT plugin — main entry point.
 *
 * Mirrors the opnsense plugin's structure: one pre-wired express app from
 * @unm/plugin-sdk (cors + json + /healthz + /discover + static icons + mDNS),
 * plus this file's own routes:
 *
 *   POST /monitoring  two-tier cadence collection (live metrics every poll,
 *                     inventory at the SDK's 15-min interval) — ALWAYS 200.
 *   POST /config      one action step (registry dispatch + schema validation).
 *   POST /plan        multi-device intents (WireGuard tunnel, OpenVPN site-to-
 *                     site, back-route pair) with snapshot rollback steps.
 *   POST /state       dynamic device-state document for the Config page.
 *   POST /probe       short-cycle live telemetry (CPU/memory/traffic/services).
 *   WS   /console     interactive SSH shell (capability 'sshConsole').
 *
 * Transport model (the plugin's defining feature): every request resolves ONE
 * Backend that negotiates HOW to reach the appliance —
 *   auto = LuCI ubus-over-HTTP for structured reads when reachable, SSH fills
 *          everything else; luci = HTTP only (writes rejected); ssh = shell.
 * ALL config writes go through uci-over-SSH in every mode: uci syntax is
 * version-stable while LuCI's CGI save endpoints are not.
 */

import path from 'path';
import {
  PluginOptionDescriptor,
  createPluginLogger,
  createPluginServer,
  createTerminalPool,
  makeConsoleUpgrade,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  probeHandler,
  collectDeviceCertificates,
  parseProbeTarget,
  createPinningGuard,
  dynamicSshHostVerifier,
  hostFromAddress,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  resolveSshCredentials,
  buildDeviceTimeInfo,
  quickActionHandler,
  buildWebUiUrl,
} from '@unm/plugin-sdk';
import type { CertificateRow, ProbeRequestBody, StateRequestBody, QuickAction } from '@unm/plugin-sdk';

import { Backend } from './client/backend';
import { closeSshPools } from './client/sshBackend';
import { collectMonitoring, getInventory } from './monitoring';
import { getAction, listModules } from './actions/registry';
import type { ActionContext } from './actions/types';
import { validateInput } from '@unm/plugin-sdk';
import type { StepCredentials } from '@unm/plugin-sdk';
import { buildPlan, PlanningError, listCatalog } from './plan';
import type { PlanRequest } from './plan';
import { buildOpenWrtState } from './state';

export const PLUGIN_UUID = 'aa9f941c-f63c-432c-adef-19049b320d03';
export const PLUGIN_NAME = 'OpenWRT Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "OpenWRT Plugin (site-a)". Unset = single-instance behavior.
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['openwrt'],
  // monitoring + inventory: two-tier cadence collection (live metrics every poll,
  // ARP/NDP/DHCP/networks/routes/tunnels/wifi/firewall at the 15-min interval).
  // configuration: uci-based actions over SSH (firewall, wireguard, openvpn,
  // routes, interfaces, dns/dhcp, wireless, system, snapshots).
  // planning: multi-device intents (/plan) with snapshot rollback steps.
  // deviceState: POST /state — the dynamic document behind the Config page.
  // ssh: SSH data path (uci reads/writes, /proc stats, console shell).
  // probe: short-cycle live telemetry for on-demand webapp polling.
  // sshConsole: interactive dropbear shell over WebSocket (/console).
  capabilities: ['monitoring', 'inventory', 'configuration', 'planning', 'deviceState', 'ssh', 'probe', 'sshConsole', 'quickActions'],
});

/**
 * The options this plugin exposes for configuration. Declared in /discover so
 * the API can persist + validate user-set values and the webapp can render a
 * generic form — this plugin never stores settings itself; it receives them on
 * every call via the `x-unm-settings` header (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport mode',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'luci', 'ssh'],
    description:
      "How to reach the appliance. auto = use LuCI (ubus-over-HTTP) for structured reads when reachable and SSH for everything else (default). luci = HTTP only — read-only, config writes are rejected. ssh = shell only.",
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's HTTPS management UI (LuCI). Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the appliance's plain-HTTP management UI (LuCI). Most OpenWRT boxes serve LuCI on HTTP only.",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's dropbear SSH daemon. Used for uci config reads/writes, /proc metrics and the interactive web console when the management address carries no explicit port.",
  },
  {
    key: 'pollIntervalSec',
    label: 'Poll interval (seconds)',
    type: 'integer' as const,
    default: 30,
    min: 5,
    max: 600,
    description: 'How often the plugin re-collects live metrics from the appliance. Slower values reduce load on low-end boxes.',
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/** Certificate pinning guard: before ANY credentials are transmitted to an
 * appliance, the management endpoint's TLS certificate is verified against UNM's
 * certificate inventory (strict mode — a mismatch throws and the request stops;
 * unknown endpoints are accepted once via TOFU). Plain-HTTP boxes have nothing
 * to pin — the guard resolves silently. */
const assertPinned = createPinningGuard();

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// OpenWRT exposes a full POSIX shell over dropbear (port 22) — the same login
// that feeds the uci data path. The webapp's DeviceDetail page renders a generic
// "Shell" button for any plugin advertising 'sshConsole'; the API proxies the
// browser's xterm.js to our /console WebSocket, which opens a PTY on the bound
// `ssh` slot (falling back to the primary username/password — one root login
// feeds both LuCI and SSH on OpenWRT).
const termPool = createTerminalPool();

const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const host = hostFromAddress(hello.managementAddress);
    if (!host) throw new Error('Missing management address');
    // The bound ssh slot wins; the primary username/password is a valid fallback
    // here because it IS an SSH credential on OpenWRT.
    const creds = resolveSshCredentials(hello.credentials as Record<string, unknown> | undefined);
    if (!creds) {
      throw new Error('No SSH credential available — bind a usernamePassword or sshKeyPair secret to the assignment (or its "ssh" slot).');
    }
    // Configured SSH port (plugin option `sshPort`, default 22) — delivered by
    // the API in the console hello frame so a per-device override is honored.
    const sshPort = resolveSshPort(hello.settings?.['sshPort']);
    const conn = await termPool.get(host, sshPort, creds, {
      // UNM certificate pinning — resolves the freshest trusted fingerprint at
      // handshake time (pooled sessions outlive single requests). A mismatch
      // rejects the handshake BEFORE any auth message is sent.
      hostKeyVerifier: dynamicSshHostVerifier(host, sshPort),
      onHostKey: (fp) => console.warn(`[openwrt-plugin] observed host key for ${host}:${sshPort} → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain dropbear login shell, like PuTTY
  },
});

/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI (LuCI)',
    description: "Open the appliance's LuCI web interface in a new tab",
    iconPath: '/icons/openwrt.svg',
    kind: 'url',
    url: {},
  },
  {
    id: 'shell',
    label: 'Shell',
    description: 'Interactive dropbear shell over SSH (requires a bound or primary credential)',
    iconPath: '/icons/openwrt.svg',
    kind: 'shell',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'openwrt-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Primary credential = a username/password login (the common OpenWRT case —
    // one root login feeds BOTH LuCI session auth and dropbear). An sshKeyPair
    // primary also works for the SSH data path.
    requiredSecretType: 'usernamePassword',
    // Optional dedicated SSH slot — used when the primary secret is NOT an SSH
    // credential (e.g. a shared read-only account) but shell access still should
    // work. The slot always wins over the primary when both are present.
    credentialSlots: [
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          "Optional dedicated SSH access for uci config reads/writes and the interactive web console. When unbound, the primary username/password credential is used (the typical OpenWRT root login).",
      },
    ],
    // Metric descriptors are generated DYNAMICALLY from each /monitoring poll —
    // the UI always matches the data this specific box returned.
    metrics: [],
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions) + module grouping. One
    // registry serves /discover, /plan and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
    // Quick actions for the Devices page "Device Actions" column. The LuCI URL
    // is resolved by THIS plugin (scheme https — matching the plugin's own
    // candidate order, port = the configured httpsPort option); shell reuses
    // the existing console dialog.
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/openwrt.svg',
  },
});
const app = server.app;

// POST /quick-action — resolve a kind:'url' quick action into the LuCI web-UI URL.
// The plugin owns all URL knowledge; no credentials are transmitted.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return { url: buildWebUiUrl(body.managementAddress, { webUiPort: resolveHttpsPort(settings.httpsPort), scheme: 'https' }, qa.url?.path) };
}, 'openwrt-plugin'));

// --- Settings helpers -----------------------------------------------------------

/** Reads the transport mode from effective settings (default auto). */
function transportOf(settings: Record<string, unknown>): 'auto' | 'luci' | 'ssh' {
  const v = typeof settings.transport === 'string' ? settings.transport : 'auto';
  return v === 'luci' || v === 'ssh' ? v : 'auto';
}

/** Reads the configured LuCI endpoint ports from effective settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): { httpsPort?: number; httpPort?: number } {
  const hp = resolveHttpsPort(settings.httpsPort);
  const tp = resolveHttpPort(settings.httpPort);
  return { httpsPort: hp !== 443 ? hp : undefined, httpPort: tp !== 80 ? tp : undefined };
}

/** Reads the configured SSH port from effective settings (default 22). */
function sshPortOf(settings: Record<string, unknown>): number {
  return resolveSshPort(settings.sshPort);
}

/** Maps the plugin's transport mode onto the pinning guard's scheme hint.
 * The guard only cares whether TLS is expected on the management endpoint:
 *   auto/luci → 'auto' (probe the configured https/http ports, TOFU unknowns)
 *   ssh       → 'http' (no web UI in play — nothing to pin; dropbear host-key
 *                verification happens separately via dynamicSshHostVerifier) */
function pinningTransportOf(mode: 'auto' | 'luci' | 'ssh'): 'auto' | 'http' {
  return mode === 'ssh' ? 'http' : 'auto';
}

/** Builds the per-request Backend for one device (negotiates LuCI/SSH once). */
async function backendFor(
  address: string,
  credentials: Record<string, unknown>,
  settings: Record<string, unknown>
): Promise<Backend> {
  return Backend.create({
    address,
    credentials,
    mode: transportOf(settings),
    ports: portsOf(settings),
    sshPort: sshPortOf(settings),
    // Transport-level diagnostics (e.g. ubus-over-ssh failures on custom firmware)
    // flow to the plugin logger → UNM device Logs view when logToApi is enabled.
    log: (level, message) => {
      if (level === 'warn') logger.warn(message);
      else logger.info(message);
    },
  });
}

/** Credential-free certificate probe (HTTPS cert + SSH host key) — best-effort. */
async function collectCerts(
  address: string,
  settings: Record<string, unknown>
): Promise<CertificateRow[]> {
  const target = parseProbeTarget(address, resolveHttpsPort(settings.httpsPort));
  if (!target) return [];
  try {
    // Probe the HTTPS endpoint only when it may actually speak TLS (a forced-ssh
    // device has no web UI to probe); the SSH host key is probed whenever a shell
    // path exists at all (auto/ssh modes).
    const httpsPort = transportOf(settings) === 'ssh' ? null : target.port;
    return await collectDeviceCertificates({
      host: target.host,
      httpsPort,
      servername: target.host,
      sshEnabled: true,
      sshPort: sshPortOf(settings),
      timeoutMs: 5_000,
    });
  } catch {
    return []; // best-effort — a failing cert probe must not sink the poll
  }
}

// ---------------------------------------------------------------------------
// POST /monitoring — two-tier cadence collection. ALWAYS responds 200 (the API's
// telemetry worker treats non-200 as transport failure); health carries the verdict.
// ---------------------------------------------------------------------------
app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Model/firmware selected in the webapp device form — forwarded by the API's
  // telemetry worker on every poll. Echoed back as system.* metrics (informational).
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  // Effective settings injected by the API (defaults ⊕ user overrides). The
  // plugin reads its options from here — it never stores them itself.
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  // Decrypted assignment fields incl. bound slots (slots.ssh when the user bound
  // a dedicated SSH credential) — feeds both LuCI session auth and dropbear.
  const credentials = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls (absent = full collection, old-API compatible).
  const collectInventoryFlag = body.collectInventory !== false;

  try {
    if (!managementAddress) throw new Error('Missing managementAddress');

    // Certificate pinning — verify the appliance's TLS cert against UNM's
    // inventory BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, pinningTransportOf(transportOf(settings)), portsOf(settings));

    const backend = await backendFor(managementAddress, credentials, settings);

    // Credential-free certificate probe — rides the 15-min inventory window.
    const certificates = collectInventoryFlag ? await collectCerts(managementAddress, settings) : [];

    const result = await collectMonitoring(managementAddress, backend, {
      collectInventory: collectInventoryFlag,
      certificates,
    });

    // Echo of the user-selected model/firmware (mirrors the opnsense plugin) —
    // informational only; shown as text cards in the device detail view.
    if (selectedModel) result.metrics['system.model'] = selectedModel;
    if (selectedFirmware) result.metrics['system.firmwareVersion'] = selectedFirmware;

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: result.health,
      metrics: result.metrics,
      // Descriptors are generated DYNAMICALLY from the metrics actually
      // collected, so the UI always matches the data (works across OpenWRT
      // versions and hardware).
      metricDescriptors: result.metricDescriptors,
      // Echo back the effective settings we received — proof that the
      // API→plugin settings injection loop works end to end.
      activeSettings: {
        transport: transportOf(settings),
        httpsPort: resolveHttpsPort(settings.httpsPort),
        httpPort: resolveHttpPort(settings.httpPort),
        sshPort: sshPortOf(settings),
        pollIntervalSec: settings.pollIntervalSec,
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      error: (err as Error).message,
    });
  }
});

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one appliance. This is the unit
// of work the API's config-job worker dispatches — either a single-device job
// (legacy shape: `{action, payload}`) or one step of a multi-device plan (registry
// shape: `{actionId, input, credentials}`). The plugin owns ALL logic: it validates
// the input against the action's schema and runs the executor. The API only propagates.
// ---------------------------------------------------------------------------
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Registry shape preferred; legacy `{action, payload}` maps onto it.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : (typeof body.action === 'string' ? body.action : undefined);
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object'
      ? (body.input as Record<string, unknown>)
      : body.payload && typeof body.payload === 'object'
        ? (body.payload as Record<string, unknown>)
        : {};

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }
  if (!managementAddress) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields are the base (the primary
  // username/password); bound slots arrive under `credentials.slots.<name>`.
  // Provisioned plan material arrives namespaced by secretRef and is merged as-is.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const stepCredentials: StepCredentials = { ...creds };

  try {
    // Certificate pinning — a config action transmits real credentials; refuse
    // the connection when the appliance's key differs from UNM's inventory.
    await assertPinned(req, managementAddress, pinningTransportOf(transportOf(settings)), portsOf(settings));

    const backend = await backendFor(managementAddress, creds, settings);

    const ctx: ActionContext = {
      backend,
      host: managementAddress,
      deviceId,
      credentials: stepCredentials,
    };

    // Validate input against the action's declared schema — the plugin is the
    // authority on what it accepts; the API only checks that the id exists.
    const issues = validateInput(action.inputSchema, input);
    if (issues.length > 0) {
      res.status(200).json({
        success: false,
        result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` },
      });
      return;
    }

    const result = await action.execute(ctx, input);
    if (!result.success) {
      logger.warn(`Config action ${actionId} reported failure for ${managementAddress}: ${typeof result.error === 'string' ? result.error : JSON.stringify(result.details ?? {})}`, { deviceId, context: { host: managementAddress, actionId } });
    }
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { host: managementAddress, actionId } });
    res.status(200).json({ success: false, result: { error: (err as Error).message } });
  }
});

// ---------------------------------------------------------------------------
// POST /plan — plans a multi-device intent (or fans out a single action across a
// batch). The plugin does ALL the planning — cross-device references, dependency
// ordering, credential provisioning requests. It never generates key material:
// provisionRequests are non-secret descriptors the API persists with the plan;
// the secrets provider owns crypto.
// ---------------------------------------------------------------------------
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};

  const planReq: PlanRequest = {
    intent: {
      actionId: typeof body.intent?.actionId === 'string' ? body.intent.actionId : '',
      inputs: (body.intent?.inputs && typeof body.intent.inputs === 'object' ? body.intent.inputs : {}) as Record<string, unknown>,
    },
    devices: Array.isArray(body.devices)
      ? (body.devices as PlanRequest['devices']).map((d) => ({
          deviceId: String(d.deviceId),
          managementAddress: String(d.managementAddress ?? ''),
          credentials: (d.credentials && typeof d.credentials === 'object' ? d.credentials : {}) as Record<string, unknown>,
        }))
      : [],
  };

  try {
    const plan = buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${(err as Error).message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: (err as Error).message });
  }
});

// ---------------------------------------------------------------------------
// POST /state — dynamic device-state document for the UNM Config page. The API
// broker calls this with fresh credentials + injected settings and returns the
// response verbatim to the webapp. Built from a fresh inventory snapshot so it
// always reflects current config; read-only (writes flow through actions).
// ---------------------------------------------------------------------------
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!body.managementAddress) throw new Error('Missing managementAddress');

  // Credentials: the assignment's decrypted fields are at top level of
  // `credentials` (primary username/password) — same model as /config.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  // Certificate pinning — /state reads live data with credentials; verify first.
  await assertPinned(req, body.managementAddress, pinningTransportOf(transportOf(settings)), portsOf(settings));

  const backend = await backendFor(body.managementAddress, creds, settings);

  // Fresh certificate probe so the state document's inventory is complete even
  // between monitoring windows (credential-free + best-effort). Warming the
  // cache here means buildOpenWrtState's own getInventory() returns it.
  const certificates = await collectCerts(body.managementAddress, settings);
  const hostKey = body.managementAddress;
  await getInventory(hostKey, backend, certificates);

  return buildOpenWrtState(backend, hostKey);
}, 'openwrt-plugin'));

// ---------------------------------------------------------------------------
// POST /probe — SHORT-CYCLE live telemetry (capability 'probe'). The webapp polls
// this every few seconds through the API broker. Keep it CHEAP: one pooled SSH
// exec batch + cached LuCI session, no long walks.
// Probe keys:
//   - 'systemStats' (default): CPU %, load averages, memory — /proc reads over
//     the shared SSH pool (connection reused).
//   - 'traffic': per-interface byte counters (/sys/class/net statistics).
//   - 'serviceStates': live state of ALL init.d services from ONE `ubus call
//     service list` — an EMPTY map is a valid answer and distinct from failure.
// Unknown keys are ignored; an empty/absent list means "the default set".
// ---------------------------------------------------------------------------
const PROBE_KEYS = new Set(['systemStats', 'traffic', 'serviceStates', 'deviceTime']);

app.post('/probe', probeHandler(async (body: ProbeRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  if (!body.managementAddress) throw new Error('Missing managementAddress');

  // Certificate pinning — the probe transmits credentials; verify first.
  await assertPinned(req, body.managementAddress, pinningTransportOf(transportOf(settings)), portsOf(settings));

  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const backend = await backendFor(body.managementAddress, creds, settings);

  // Which keys did the caller ask for? Absent/empty = default set. Unknown keys ignored.
  const requested = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : ['systemStats'];
  const wanted = new Set(requested.filter((k) => PROBE_KEYS.has(k)));
  if (wanted.size === 0) throw new Error(`No supported probe keys in [${requested.join(', ')}]`);

  // All collectors share the pooled session; run them in parallel when several
  // are requested.
  const [cpu, mem, traffic, services, deviceTime] = await Promise.all([
    wanted.has('systemStats') ? backend.cpuLoad().catch(() => null) : Promise.resolve(null),
    wanted.has('systemStats') ? backend.memory().catch(() => null) : Promise.resolve(null),
    wanted.has('traffic') ? backend.traffic().catch(() => ({ counters: {}, rates: {} } as { counters: Record<string, { rx: number; tx: number }>; rates: Record<string, { rxBitsPerSec: number; txBitsPerSec: number }> })) : Promise.resolve(null),
    wanted.has('serviceStates') ? backend.services().catch(() => null) : Promise.resolve(null),
    // 'deviceTime' — the box's current local wall clock + zone (SSH `date -Iseconds`).
    wanted.has('deviceTime') ? backend.deviceTime().catch(() => null) : Promise.resolve(null),
  ]);

  const metrics: Record<string, unknown> = {};
  if (wanted.has('systemStats')) {
    if (!cpu && !mem) throw new Error('No system stats collected — SSH path unavailable?');
    const c = cpu ?? { percent: null, load1: null, load5: null, load15: null };
    const m = mem ?? { used: null, total: null, percent: null };
    if (c.percent !== null) metrics['cpu.percent'] = c.percent;
    if (c.load1 !== null) metrics['load.1m'] = c.load1;
    if (c.load5 !== null) metrics['load.5m'] = c.load5;
    if (c.load15 !== null) metrics['load.15m'] = c.load15;
    if (m.used !== null) metrics['memory.used'] = m.used;
    if (m.total !== null) metrics['memory.total'] = m.total;
    if (m.percent !== null) metrics['memory.percent'] = m.percent;
  }
  if (wanted.has('traffic')) {
    const t = traffic?.counters ?? {};
    // Flat map keyed by interface NAME — the webapp joins it onto its rows.
    metrics['traffic'] = t;
    let rxTotal = 0, txTotal = 0;
    for (const r of Object.values(traffic?.rates ?? {})) {
      rxTotal += r.rxBitsPerSec;
      txTotal += r.txBitsPerSec;
    }
    if (rxTotal > 0) metrics['bandwidth.rx'] = rxTotal;
    if (txTotal > 0) metrics['bandwidth.tx'] = txTotal;
  }
  if (wanted.has('serviceStates')) {
    // null = collection failure → 502 (webapp keeps last good data); an EMPTY
    // list is a valid answer and must reach the caller.
    if (!services) throw new Error('Service state probe returned no data');
    const flat: Record<string, unknown> = {};
    for (const s of services) flat[s.name] = { enabled: s.enabled, running: s.running };
    metrics['serviceStates'] = flat;
  }
  if (wanted.has('deviceTime')) {
    // null = no SSH transport → 502. `date -Iseconds` carries a UTC offset so the
    // SDK resolves an absolute instant even without the IANA zone name.
    const localIso = deviceTime?.localIso ?? '';
    if (!localIso) throw new Error('Device time probe returned no data');
    metrics['system.deviceTime'] = buildDeviceTimeInfo(localIso, deviceTime?.timezone ?? null) ?? { localIso };
  }

  return { collectedAt: new Date().toISOString(), metrics };
}, 'openwrt-plugin'));

// --- Graceful shutdown ----------------------------------------------------------
process.on('SIGTERM', () => {
  termPool.closeAll();
  closeSshPools();
});
process.on('SIGINT', () => {
  termPool.closeAll();
  closeSshPools();
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[openwrt-plugin] fatal startup error:', err);
  process.exit(1);
});
