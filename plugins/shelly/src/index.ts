/**
 * Shelly plugin — monitoring + firmware updates for ALL Shelly generations on
 * one metric model.
 *
 *   - Monitoring: Gen1 (ESP8266, legacy REST) = one `GET /status`; Gen2+
 *     (Plus/Pro/Wave/Gen3/Gen4, JSON-RPC 2.0) = ONE batched `POST /rpc` with
 *     four methods (device info, component status, WiFi status, firmware
 *     status). The generation + namespace family are probed at runtime
 *     (`detect.ts`) and cached per device — one detection per inventory window,
 *     never per poll. Reports uptime/RAM/flash, WLAN as first-class metrics
 *     (RSSI gauge, SSID/channel/BSSID/station IP), best-effort relay states
 *     and power metering, plus the running firmware version. Health degrades
 *     to warning on weak RSSI / low RAM / flash ≥90 % / overtemp; unreachable
 *     or auth-rejected = critical.
 *   - Updates (the headline feature): `shelly.firmware.update` action
 *     (stage stable/beta, optional custom URL) + Updates-page rows from the
 *     device's own firmware status (Gen1 `/ota`, Gen2+ `Firmware.GetStatus`).
 *     The device reboots mid-flight — plans append a 120 s settle wait +
 *     inventory refresh automatically.
 *   - Reboot: `shelly.reboot` action (needed to verify update recovery).
 *
 * Credentials: monitoring is credential-free when the device's local login is
 * off (the default on fresh devices). When local login is enabled, bind a
 * `usernamePassword` secret to the optional `login` slot — Gen1 uses HTTP
 * Basic, Gen2+ runs the local-auth handshake and reuses the `shellyun-auth`
 * cookie until it expires.
 */

import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  QuickAction,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  quickActionHandler,
  buildWebUiUrl,
  readSettings,
  resolvePluginIdentity,
  validateInput,
  isTransientTransportError,
} from '@unm/plugin-sdk';
import type { ActionResult } from '@unm/plugin-sdk';
import type { ShellyClientOptions } from './client';
import { authSessionFor, ShellyCredentials } from './auth';
import { detectDevice, DeviceProfile } from './detect';
import { collectGen1, collectGen2 } from './monitoring';
import { getShellyUpdateRows } from './updates';
import { shellyActions, ShellyActionContext } from './actions';
import { buildPlan, PlanningError } from './plan';
import { SHELLY_DEVICE_SUPPORT } from './deviceSupport';

export const PLUGIN_UUID = 'fba9d8ed-f84b-4da7-98e3-aeac38e37b0f';
export const PLUGIN_NAME = 'Shelly Plugin';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    "Monitoring (WLAN/uptime/RAM/flash) + firmware updates for all Shelly generations — Gen1 REST and Gen2+ JSON-RPC on one metric model, with runtime generation detection.",
  version: '0.1.0',
  vendors: ['shelly'],
  // monitoring: /status (Gen1) or one batched /rpc (Gen2+) per poll.
  // updates: device firmware status → Updates page rows.
  // configuration: plan-executable actions (firmware update, reboot).
  // planning: POST /plan endpoint — the API builds plans from these intents.
  // quickActions: one-click open of the Shelly web UI from the Devices page.
  capabilities: ['monitoring', 'updates', 'configuration', 'planning', 'quickActions'],
});

/**
 * Configurable options — declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call.
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'http',
    enumOptions: ['http', 'https'],
    description: "Scheme used for bare addresses (Shelly serves plain HTTP by default; enable https only when you turned TLS on in the Shelly web UI).",
  },
  {
    key: 'timeoutMs',
    label: 'Request timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 200,
    max: 9000,
    description: "How long to wait for each device request before counting it unreachable. Capped so a poll stays inside the API's ~10 s budget.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

/** Metric descriptors — declared keys; best-effort model extras (relays, power) appear when the model reports them. */
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  // Canonical contract (docs/PLUGIN-DEVELOPMENT.md §5): every plugin emits the
  // running firmware/software version under system.swVersion on EVERY poll —
  // the Devices page "Software version" column reads exactly this key.
  { key: 'system.swVersion', label: 'Firmware version', type: 'string', visualization: 'text', group: 'System' },
  { key: 'shelly.model', label: 'Model', type: 'string', visualization: 'text', group: 'System' },
  { key: 'shelly.mac', label: 'MAC address', type: 'string', visualization: 'text', group: 'System' },
  { key: 'shelly.uptimeSeconds', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'System' },
  { key: 'shelly.ramFreeBytes', label: 'RAM free', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'gauge', group: 'System', color: '#22c55e' },
  { key: 'shelly.ramTotalBytes', label: 'RAM total', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System' },
  { key: 'shelly.fsFreeBytes', label: 'Flash free', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'gauge', group: 'System', color: '#ef4444' },
  // WLAN — first-class metrics (the plan's headline monitoring feature).
  { key: 'shelly.wifiRssiDbm', label: 'WiFi RSSI', unit: 'dBm', type: 'number', visualization: 'gauge', group: 'WiFi', min: -100, max: 0, color: '#8b5cf6' },
  { key: 'shelly.wifiSsid', label: 'WiFi SSID', type: 'string', visualization: 'text', group: 'WiFi' },
  { key: 'shelly.wifiChannel', label: 'WiFi channel', type: 'number', visualization: 'text', group: 'WiFi' },
  { key: 'shelly.wifiBssid', label: 'AP MAC (BSSID)', type: 'string', visualization: 'text', group: 'WiFi' },
  { key: 'shelly.wifiStaIp', label: 'Station IP', type: 'string', visualization: 'text', group: 'WiFi' },
  // Firmware update indicator — 1 when the device reports an available update.
  { key: 'shelly.fwUpdateAvailable', label: 'Firmware update available', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 1, color: '#f59e0b' },
  // Best-effort model extras (only emitted when the device reports them).
  { key: 'shelly.relay0On', label: 'Relay 0', type: 'number', visualization: 'gauge', group: 'Relays', min: 0, max: 1 },
  { key: 'shelly.relay1On', label: 'Relay 1', type: 'number', visualization: 'gauge', group: 'Relays', min: 0, max: 1 },
  { key: 'shelly.powerW', label: 'Power (W)', unit: 'W', type: 'number', visualization: 'plot', group: 'Power', color: '#f59e0b' },
  { key: 'shelly.energyWh', label: 'Energy total (Wh)', unit: 'Wh', type: 'number', visualization: 'plot', group: 'Power' },
];

/** Quick actions for the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the Shelly device's web interface in a new tab",
    iconPath: '/icons/shelly.svg',
    kind: 'url',
    url: {},
  },
];

const server = createPluginServer({
  identity,
  logTag: 'shelly-plugin',
  iconsDir: path.join(__dirname, '../../icons'),
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // License/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: SHELLY_DEVICE_SUPPORT,
    // Monitoring is credential-free when the device's local login is off. The
    // optional `login` slot carries the local username/password when it is on.
    requiredSecretType: null,
    credentialSlots: [
      {
        name: 'login',
        secretTypes: ['usernamePassword'],
        required: false,
        description:
          "Optional — bind a usernamePassword secret with the device's local login (Shelly web UI → Settings → Local Login). Needed for monitoring/updates on devices where local auth is enabled; most fresh devices work without it.",
      },
    ],
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: shellyActions.listCatalog(),
    modules: shellyActions.listModules(),
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/shelly.svg',
  },
});
const app = server.app;

// Structured logs shipped to the API (poll failures).
const logger = createPluginLogger(identity);

/** Resolves effective client options from injected settings. */
function clientOf(managementAddress: string, settings: Record<string, unknown>): ShellyClientOptions {
  const transport = typeof settings.transport === 'string' && ['http', 'https'].includes(settings.transport) ? (settings.transport as 'http' | 'https') : 'http';
  return {
    address: managementAddress,
    transport,
    timeoutMs: clampInt(settings.timeoutMs, 200, 9_000, 5_000),
  };
}

/** Reads the local-login credentials from a credentials object (bound `login` slot first, then top-level primary fields). */
function loginCreds(credentials: Record<string, unknown> | undefined): ShellyCredentials {
  const pick = (v: unknown): ShellyCredentials => {
    if (!v || typeof v !== 'object') return {};
    const o = v as Record<string, unknown>;
    const user = typeof o.username === 'string' && o.username ? o.username : undefined;
    const pass = typeof o.password === 'string' ? o.password : '';
    return { username: user, password: pass };
  };
  if (!credentials) return {};
  const slots = credentials['slots'];
  if (slots && typeof slots === 'object') {
    const login = (slots as Record<string, unknown>)['login'];
    if (login && typeof login === 'object') return pick(login);
  }
  return pick(credentials);
}

// ---------------------------------------------------------------------------
// POST /monitoring — ALWAYS responds 200 (the API's telemetry worker treats
// non-200 as transport failure); health carries the verdict.
// ---------------------------------------------------------------------------
app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Effective settings injected by the API (defaults ⊕ user overrides).
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls (absent = full collection, old-API compatible). The updates row and
  // detection ride the inventory window.
  const collectInventory = body.collectInventory !== false;

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [...METRIC_DESCRIPTORS, errorDescriptor()],
      error,
    });
  };

  if (!managementAddress.trim()) return fail('critical', 'No target address — set the device management address.');

  const client = clientOf(managementAddress, settings);
  const creds = loginCreds((body.credentials && typeof body.credentials === 'object' ? body.credentials : undefined) as Record<string, unknown> | undefined);
  const auth = authSessionFor(managementAddress, creds);

  // Runtime generation/namespace detection — cached per address (TtlCache in
  // detect.ts), so this probe chain runs ~once per inventory window.
  let profile: DeviceProfile;
  try {
    profile = await detectDevice(client, auth);
  } catch (err) {
    logger.error(`Detection failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { address: managementAddress } });
    return fail('critical', `Could not detect Shelly generation — ${(err as Error).message}`);
  }

  // One request per poll: Gen1 = GET /status; Gen2+ = ONE batched POST /rpc.
  const collected = profile.gen === 1 ? await collectGen1(client, profile, auth) : await collectGen2(client, profile, auth);
  if (collected.error) {
    logger.error(`Monitoring poll for ${managementAddress} failed: ${collected.error}`, { deviceId, context: { address: managementAddress } });
    return fail(collected.health, collected.error);
  }

  const metrics: Record<string, unknown> = { ...collected.metrics };

  // Updates page — rides the inventory window. Emission contract: present-but-
  // empty is authoritative (wipe stale rows); a transport failure OMITS the key
  // entirely so previously stored rows survive a transient device outage.
  if (collectInventory) {
    try {
      metrics['updates'] = await getShellyUpdateRows(client, profile, auth);
    } catch (e) {
      logger.error(`Firmware status check failed for ${managementAddress}: ${(e as Error).message}`, { deviceId, context: { address: managementAddress } });
      // No key on failure — the API keeps the previous rows.
    }
  }

  if (collected.warnings.length > 0) metrics['system.warning'] = collected.warnings.join('; ');

  res.status(200).json({
    deviceId,
    collectedAt: new Date().toISOString(),
    health: collected.health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
    // Echo back the effective settings — proof of the API→plugin loop.
    activeSettings: { transport: client.transport ?? 'http', timeoutMs: client.timeoutMs },
  });
});

// ---------------------------------------------------------------------------
// POST /plan — build an execution plan for an intent across devices. Called by
// the API's createPlanCore (POST /plans + automation intents). Shelly actions
// all target exactly one device, so this is a pure fan-out with input
// validation; firmware updates append settle-wait + inventory refresh.
// ---------------------------------------------------------------------------
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};

  const planReq: Parameters<typeof buildPlan>[0] = {
    intent: {
      actionId: typeof body.intent?.actionId === 'string' ? body.intent.actionId : '',
      inputs: (body.intent?.inputs && typeof body.intent.inputs === 'object' ? body.intent.inputs : {}) as Record<string, unknown>,
    },
    devices: Array.isArray(body.devices)
      ? (body.devices as { deviceId?: string; managementAddress?: string; credentials?: Record<string, unknown> }[]).map((d) => ({
          deviceId: String(d.deviceId ?? ''),
          managementAddress: String(d.managementAddress ?? ''),
          credentials: d.credentials ?? {},
        }))
      : [],
    deviceInputs: body.deviceInputs && typeof body.deviceInputs === 'object' ? (body.deviceInputs as Record<string, Record<string, unknown>>) : undefined,
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
    logger.error(`Planning crashed: ${(err as Error).message}`);
    res.status(500).json({ error: (err as Error).message });
  }
});

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step (the unit of work the API's plan
// executor dispatches). The plugin owns ALL logic: detection, input validation
// against the action schema + execution. The API only propagates.
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
  if (!managementAddress.trim()) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = shellyActions.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields (top-level for a bound
  // primary secret, namespaced under slots.<name> for declared slots).
  const creds = loginCreds((body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>);
  const client = clientOf(managementAddress, settings);
  const auth = authSessionFor(managementAddress, creds);

  // Actions validate against the live device at execution time — detect first.
  let profile: DeviceProfile;
  try {
    profile = await detectDevice(client, auth);
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: detection failed: ${(err as Error).message}`, { deviceId, context: { address: managementAddress, actionId } });
    res.status(200).json({ success: false, result: { error: `Could not detect Shelly generation — ${(err as Error).message}` } });
    return;
  }

  const ctx: ShellyActionContext = { client, profile, auth };

  try {
    // Validate input against the action's declared schema — the plugin is the
    // authority on what it accepts; the API only checks that the id exists.
    const issues = validateInput(action.inputSchema, input);
    if (issues.length > 0) {
      res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
      return;
    }

    const result: ActionResult = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { address: managementAddress, actionId } });
    // Transport-level failures (device down / not ready yet) are transient — the
    // plan executor re-dispatches them per the plan's retry policy. HTTP-level
    // outcomes already come back as ok:false results above and stay hard.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI URL.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return {
    url: buildWebUiUrl(body.managementAddress, {
      webUiPort: 80,
      scheme: typeof settings.transport === 'string' && settings.transport === 'https' ? 'https' : 'http',
    }, qa.url?.path),
  };
}, 'shelly-plugin'));

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[shelly-plugin] fatal startup error:', err);
  process.exit(1);
});
