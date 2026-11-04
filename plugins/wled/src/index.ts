/**
 * WLED plugin — monitoring + firmware updates for WLED light controllers.
 *
 *   - Monitoring: polls GET /json/info on each device (plain HTTP, port 80 by
 *     default) and reports heap, LED fps/count/power, uptime, WiFi RSSI/channel
 *     and the running version as metrics. Health degrades to warning on low
 *     free heap or weak WiFi signal; unreachable = critical.
 *   - Updates (the headline feature): resolves the device's firmware source from
 *     its own `info.repo` (default wled/WLED) via GitHub's releases/latest —
 *     downloaded through UNM's web-fetch broker, never directly by this plugin —
 *     and emits an UpdateRow pointing at `wled.firmware.update`. The action
 *     uploads the .bin to the device's /update endpoint (the same flow as WLED's
 *     official web UI) and verifies the version after the reboot.
 *   - Basic settings: rename + on/brightness actions; WiFi config changes are
 *     deliberately out of scope for v1.
 *
 * Credentials: monitoring is credential-free. When a controller has a settings
 * PIN, bind an `apiKey` secret to the optional `pin` slot — its key field
 * carries the PIN (used by /json/cfg writes and firmware uploads).
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
import { WledClientOptions, getCfg, getInfo, WledCfg, WledInfo } from './client';
import { getWledUpdateRows } from './updates';
import { wledActions, WledActionContext } from './actions';
import { buildPlan, PlanningError } from './plan';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000016';
export const PLUGIN_NAME = 'WLED Plugin';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    'Monitoring (heap/fps/WiFi) + firmware updates for WLED light controllers — the update flow mirrors WLED\'s own web UI and verifies the version after reboot.',
  // 0.3.0 — config backup: new read-level wled.config.backup action (full
  // /json/cfg snapshot as base64 in the step result), auto-prepended best-effort
  // before every firmware flash; schedulable on its own for periodic backups.
  version: '0.3.0',
  vendors: ['wled'],
  // monitoring: /json/info metrics every poll.
  // updates: GitHub release feed (via UNM's web-fetch broker) → Updates page rows.
  // configuration: plan-executable actions (firmware update/revert, rename, state).
  // planning: POST /plan endpoint — the API builds plans from these intents.
  // quickActions: one-click open of the WLED web UI from the Devices page.
  capabilities: ['monitoring', 'updates', 'configuration', 'planning', 'quickActions'],
});

/**
 * Configurable options — declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call.
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the WLED web/JSON API (default 80). Ignored when the management address carries an explicit scheme or port.",
  },
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'http',
    enumOptions: ['http', 'https'],
    description: "Scheme used for bare addresses (WLED serves plain HTTP by default; enable https only when you turned TLS on in the WLED UI).",
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

/** Metric descriptors — static; this plugin always emits exactly these keys when reachable. */
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'wled.freeHeapBytes', label: 'Free heap', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'gauge', group: 'System', summary: true, color: '#22c55e' },
  { key: 'wled.fps', label: 'Render FPS', unit: 'fps', type: 'number', visualization: 'plot', group: 'LEDs', color: '#3b82f6' },
  { key: 'wled.ledCount', label: 'LED count', type: 'number', visualization: 'text', group: 'LEDs' },
  { key: 'wled.ledPowerMa', label: 'LED power (mA)', unit: 'mA', type: 'number', visualization: 'plot', group: 'LEDs', color: '#f59e0b' },
  { key: 'wled.uptimeSeconds', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'System' },
  { key: 'wled.wifiRssiDbm', label: 'WiFi RSSI', unit: 'dBm', type: 'number', visualization: 'gauge', group: 'WiFi', min: -100, max: 0, color: '#8b5cf6' },
  { key: 'wled.wifiSignalPercent', label: 'WiFi signal (%)', unit: '%', type: 'number', visualization: 'plot', group: 'WiFi', min: 0, max: 100, color: '#a78bfa' },
  { key: 'wled.wifiChannel', label: 'WiFi channel', type: 'number', visualization: 'text', group: 'WiFi' },
  { key: 'wled.wifiBssid', label: 'AP MAC (BSSID)', type: 'string', visualization: 'text', group: 'WiFi' },
  { key: 'wled.wifiSsid', label: 'WiFi SSID', type: 'string', visualization: 'text', group: 'WiFi' },
  { key: 'wled.fsUsedKb', label: 'Flash used (KB)', unit: 'kB', format: 'bytes', type: 'number', visualization: 'gauge', group: 'System', color: '#ef4444' },
  { key: 'wled.fsTotalKb', label: 'Flash total (KB)', unit: 'kB', format: 'bytes', type: 'number', visualization: 'text', group: 'System' },
  { key: 'wled.ledMaxPowerMa', label: 'LED max power limit (mA)', unit: 'mA', type: 'number', visualization: 'text', group: 'LEDs' },
  { key: 'wled.coreVersion', label: 'Core version', type: 'string', visualization: 'text', group: 'System' },
  { key: 'wled.version', label: 'Firmware version', type: 'string', visualization: 'text', group: 'System' },
  { key: 'wled.release', label: 'Board variant', type: 'string', visualization: 'text', group: 'System' },
  { key: 'wled.name', label: 'Instance name', type: 'string', visualization: 'text', group: 'System' },
];

/** Quick actions for the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the WLED controller's web interface in a new tab",
    iconPath: '/icons/wled.svg',
    kind: 'url',
    url: {},
  },
];

const server = createPluginServer({
  identity,
  logTag: 'wled-plugin',
  iconsDir: path.join(__dirname, '../../icons'),
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Monitoring is credential-free — no primary secret needed. The optional
    // `pin` slot (below) carries the WLED settings PIN when one is set.
    requiredSecretType: null,
    credentialSlots: [
      {
        name: 'pin',
        secretTypes: ['apiKey'],
        required: false,
        description:
          "Optional — bind an apiKey secret whose key field carries the WLED settings PIN (Settings → Security in the WLED UI). Needed for rename and for firmware uploads on PIN-protected controllers; monitoring works without it.",
      },
    ],
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: wledActions.listCatalog(),
    modules: wledActions.listModules(),
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/wled.svg',
  },
});
const app = server.app;

// Structured logs shipped to the API (poll failures).
const logger = createPluginLogger(identity);

/** Resolves effective client options from injected settings. */
function clientOf(managementAddress: string, settings: Record<string, unknown>): WledClientOptions {
  const transport = typeof settings.transport === 'string' && ['http', 'https'].includes(settings.transport) ? (settings.transport as 'http' | 'https') : 'http';
  return {
    address: managementAddress,
    transport,
    httpPort: clampInt(settings.httpPort, 1, 65_535, 80),
    timeoutMs: clampInt(settings.timeoutMs, 200, 9_000, 5_000),
  };
}

/** Reads the optional PIN from a credentials object (top-level or `slots.pin`). */
function pinFromCredentials(credentials: Record<string, unknown> | undefined): string {
  if (!credentials) return '';
  const top = typeof credentials['apiKey'] === 'string' ? (credentials['apiKey'] as string).trim() : '';
  if (top) return top;
  const slots = credentials['slots'];
  if (slots && typeof slots === 'object') {
    const pinSlot = (slots as Record<string, unknown>)['pin'];
    if (pinSlot && typeof pinSlot === 'object' && typeof (pinSlot as Record<string, unknown>)['apiKey'] === 'string') {
      return ((pinSlot as Record<string, unknown>)['apiKey'] as string).trim();
    }
  }
  return '';
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
  // polls (absent = full collection, old-API compatible). The update feed rides
  // the inventory window — one GitHub lookup per device per 15 min at most.
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

  let infoRes;
  try {
    infoRes = await getInfo(client);
  } catch (err) {
    logger.error(`Monitoring poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { address: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }

  if (!infoRes.ok || !infoRes.data || typeof infoRes.data === 'string') {
    logger.error(`WLED not responding on ${managementAddress}: ${infoRes.error}`, { deviceId, context: { address: managementAddress } });
    return fail('critical', `WLED not reachable — ${infoRes.error ?? 'no response'}`);
  }

  const info = infoRes.data as WledInfo;
  const metrics: Record<string, unknown> = {};
  let health: Health = 'ok';
  const warnings: string[] = [];

  // System group.
  if (typeof info.freeheap === 'number') {
    metrics['wled.freeHeapBytes'] = info.freeheap;
    if (info.freeheap < 10 * 1024) {
      health = 'warning';
      warnings.push(`free heap critically low (${info.freeheap} B — fragmentation risk)`);
    }
  }
  if (typeof info.uptime === 'number') metrics['wled.uptimeSeconds'] = info.uptime;
  if (typeof info.ver === 'string' && info.ver) metrics['wled.version'] = info.ver;
  if (typeof info.release === 'string' && info.release) metrics['wled.release'] = info.release;
  if (typeof info.name === 'string' && info.name) {
    metrics['wled.name'] = info.name;
    // Hostname consistency for the Hosts/Devices pages.
    metrics['hostname'] = info.name;
  }

  // LEDs group.
  if (info.leds && typeof info.leds === 'object') {
    if (typeof info.leds.count === 'number') metrics['wled.ledCount'] = info.leds.count;
    if (typeof info.leds.fps === 'number') metrics['wled.fps'] = info.leds.fps;
    if (typeof info.leds.pwr === 'number') metrics['wled.ledPowerMa'] = info.leds.pwr;
    // The configured power LIMIT — useful to spot a misconfigured cap that
    // throttles the strip well below what it could do.
    if (typeof info.leds.maxpwr === 'number') metrics['wled.ledMaxPowerMa'] = info.leds.maxpwr;
  }

  // WiFi group — RSSI is the headline signal-quality metric; WLED also reports
  // a normalized 0–100 % figure (its own UI uses both).
  if (info.wifi && typeof info.wifi === 'object') {
    if (typeof info.wifi.rssi === 'number') {
      metrics['wled.wifiRssiDbm'] = info.wifi.rssi;
      if (info.wifi.rssi <= -85) {
        health = 'warning';
        warnings.push(`weak WiFi signal (${info.wifi.rssi} dBm)`);
      }
    }
    if (typeof info.wifi.signal === 'number') metrics['wled.wifiSignalPercent'] = info.wifi.signal;
    if (typeof info.wifi.channel === 'number') metrics['wled.wifiChannel'] = info.wifi.channel;
    // The AP the device is currently associated with (its MAC). With multiple
    // access points under one SSID this is what tells you which box serves it —
    // a changed BSSID means the device roamed.
    if (typeof info.wifi.bssid === 'string' && info.wifi.bssid) metrics['wled.wifiBssid'] = info.wifi.bssid;
  }

  // WiFi SSID — not in /json/info; read from GET /json/cfg (`nw.ins[]` is the
  // preferred-network list, first non-empty entry wins). Rides the inventory
  // window: the network name rarely changes, and metrics-only polls stay at a
  // single request. Best-effort — a cfg read failure must never break the poll.
  if (collectInventory) {
    try {
      const cfgRes = await getCfg(client);
      if (cfgRes.ok && cfgRes.data && typeof cfgRes.data === 'object') {
        const ins = (cfgRes.data as WledCfg).nw?.ins;
        if (Array.isArray(ins)) {
          const ssid = ins.map((n) => n.ssid).find((s) => typeof s === 'string' && s.length > 0);
          if (ssid) metrics['wled.wifiSsid'] = ssid;
        }
      }
    } catch {
      /* best-effort — omit the key, keep the poll green */
    }
  }

  // Filesystem group — WLED reports SPI-flash usage in KB. A full flash breaks
  // OTA updates and custom palettes/effects, so warn well before it is full.
  if (info.fs && typeof info.fs === 'object' && typeof info.fs.t === 'number' && info.fs.t > 0) {
    const used = typeof info.fs.u === 'number' ? info.fs.u : null;
    metrics['wled.fsTotalKb'] = info.fs.t;
    if (used !== null) {
      metrics['wled.fsUsedKb'] = used;
      const pct = Math.round((used / info.fs.t) * 100);
      if (pct >= 90) {
        health = 'warning';
        warnings.push(`flash nearly full (${pct} % — OTA updates and custom content will fail)`);
      }
    }
  }

  // Core version (ESP-IDF / Arduino core) — informational, next to the WLED version.
  if (typeof info.core === 'string' && info.core) metrics['wled.coreVersion'] = info.core;

  // Updates page — rides the inventory window. Emission contract: present-but-
  // empty is authoritative (wipe stale rows); a feed transport failure OMITS the
  // key entirely so previously stored rows survive a transient GitHub/provider outage.
  if (collectInventory) {
    try {
      metrics['updates'] = await getWledUpdateRows(info);
    } catch (e) {
      logger.error(`Firmware feed check failed for ${managementAddress}: ${(e as Error).message}`, { deviceId, context: { address: managementAddress } });
      // No key on failure — the API keeps the previous rows.
    }
  }

  if (warnings.length > 0) metrics['system.warning'] = warnings.join('; ');

  res.status(200).json({
    deviceId,
    collectedAt: new Date().toISOString(),
    health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
    // Echo back the effective settings — proof of the API→plugin loop.
    activeSettings: { httpPort: client.httpPort, transport: client.transport, timeoutMs: client.timeoutMs },
  });
});

// ---------------------------------------------------------------------------
// POST /plan — build an execution plan for an intent across devices. Called by
// the API's createPlanCore (POST /plans + automation intents). WLED actions all
// target exactly one device, so this is a pure fan-out with input validation;
// see src/plan.ts.
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
// executor dispatches). The plugin owns ALL logic: input validation against the
// action schema + execution. The API only propagates.
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

  const action = wledActions.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields (top-level for a bound
  // primary secret, namespaced under slots.<name> for declared slots).
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const ctx: WledActionContext = {
    client: clientOf(managementAddress, settings),
    deviceId: typeof body.deviceId === 'string' ? (body.deviceId as string) : undefined,
    pin: pinFromCredentials(creds),
  };

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
      webUiPort: clampInt(settings.httpPort, 1, 65_535, 80),
      scheme: typeof settings.transport === 'string' && settings.transport === 'https' ? 'https' : 'http',
    }, qa.url?.path),
  };
}, 'wled-plugin'));

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[wled-plugin] fatal startup error:', err);
  process.exit(1);
});
