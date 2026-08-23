import express from 'express';
import cors from 'cors';
import path from 'path';
import { Bonjour } from 'bonjour-service';
import { SwosClient, SwosAuthError } from './swosClient';
import { createPlatform } from './platform';
import { DEFAULT_OPTIONS, MonitoringResult, SwosOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { DEVICE_MODELS } from './deviceModels';
import { getAction, listCatalog } from './actions/registry';
import { ActionContext, ActionResult, validateInput } from './actions/types';
import { PlanRequest, PlanningError, buildPlan } from './plan';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000005';
export const PLUGIN_NAME = 'MikroTik SwOS Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);

// 0.1.0 — initial release: SwOS/SwOS Lite monitoring (system, ports, PoE, LAG,
// VLANs, SFP, SNMP) + inventory propagation (VLAN networks, MAC table hosts),
// plus the full action catalog from the reference project's proven write set
// (port config, PoE, LAG, per-port VLANs, VLAN table, SNMP, system identity/
// management access, backup download). SwOS only — RouterOS gets its own plugin.
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['mikrotik'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'configuration', 'inventory', 'planning'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4007);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS = [
  {
    key: 'cacheTtlSeconds',
    label: 'Snapshot cache TTL (seconds)',
    type: 'integer' as const,
    default: 60,
    min: 10,
    max: 600,
    description:
      'How long a collected switch snapshot stays fresh. The API polls every 30 s with a hard 10 s budget, so the full state (system + ports + PoE + LAG + VLANs + MAC table) is cached and only re-collected when stale.',
  },
  {
    key: 'requestTimeoutMs',
    label: 'Per-request timeout (ms)',
    type: 'integer' as const,
    default: DEFAULT_OPTIONS.requestTimeoutMs,
    min: 500,
    max: 9_000,
    description: 'Timeout for a single .b endpoint fetch. Kept well under the API\'s 10 s poll budget.',
  },
];

const app = express();
app.use(cors());
// Backup downloads can be several MB — allow generous bodies for /config results.
app.use(express.json({ limit: '32mb' }));

// Static icon assets (plugin + per-model icons), advertised in /discover and
// fetched by the API's icon proxy. dist/src/../../icons = <plugin root>/icons.
app.use('/icons', express.static(path.join(__dirname, '../../icons')));

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: EFFECTIVE_UUID,
    name: DISPLAY_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    // Credentials come from the existing 'usernamePassword' secret type — SwOS
    // uses HTTP Digest authentication with a username/password pair.
    requiredSecretType: 'usernamePassword',
    options: PLUGIN_OPTIONS,
    actions: listCatalog(),
    iconUrl: '/icons/swos.svg',
    deviceModels: DEVICE_MODELS,
  });
});

/**
 * Reads the effective settings the API injects on every call (defaults ⊕ user
 * overrides) from the `x-unm-settings` JSON header, merged over this plugin's
 * declared defaults so a missing header still yields sane values.
 */
function readSettings(req: { headers?: Record<string, unknown> }): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};
  for (const opt of PLUGIN_OPTIONS) if (opt.default !== undefined) defaults[opt.key] = opt.default;

  const raw = req.headers?.['x-unm-settings'];
  if (typeof raw !== 'string' || raw.trim() === '') return defaults;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return { ...defaults, ...(parsed as Record<string, unknown>) };
  } catch {
    // Malformed header: fall back to defaults rather than failing the call.
  }
  return defaults;
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' && Number.isInteger(value) ? value : fallback;
  return Math.min(max, Math.max(min, n));
}

/** Resolves collection options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): SwosOptions {
  return {
    cacheTtlMs: clampInt(settings.cacheTtlSeconds, 10, 600, Math.round(DEFAULT_OPTIONS.cacheTtlMs / 1_000)) * 1_000,
    requestTimeoutMs: clampInt(settings.requestTimeoutMs, 500, 9_000, DEFAULT_OPTIONS.requestTimeoutMs),
  };
}

/** Extracts username/password credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: { username: string; password: string }; error?: string } {
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  const username = typeof credentials.username === 'string' ? credentials.username : '';
  const password = typeof credentials.password === 'string' ? credentials.password : '';
  if (!username) return { error: 'Missing username in the assigned secret.' };
  // An empty password is legitimate on SwOS (default admin has none).
  return { creds: { username, password } };
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // User-selected hardware model / firmware version (forwarded by the API from
  // the device row). Surfaced as System metrics so the selection is visible in
  // the webapp's monitoring view.
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  const settings = readSettings(req);
  const opts = resolveOptions(settings);

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [
        { key: 'system.error', label: 'Error', type: 'string' as const, visualization: 'text' as const, group: 'System' },
      ],
      error,
    });
  };

  if (!managementAddress.trim()) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials(body);
  if (error || !creds) return fail('critical', error ?? 'Missing credentials.');

  try {
    const result: MonitoringResult = await getMonitoring(managementAddress.trim(), creds, opts);
    const s = result.snapshot;

    // Health mapping: unreachable/bad creds → critical (raised as an exception
    // above), stale snapshot → warning, otherwise ok. A switch that answers but
    // reports no ports at all is suspicious — warn rather than fail.
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (result.stale) warnings.push(result.error ?? 'stale snapshot');
    if (s.ports.length === 0 && !s.identity) warnings.push('no ports or identity reported');
    if (warnings.length > 0) {
      health = 'warning';
    }

    const metrics = buildMetrics(s, selectedModel, selectedFirmware);
    if (health !== 'ok') metrics['system.error'] = warnings.join('; ');

    let descriptors = buildDescriptors(s);
    if (selectedModel) {
      descriptors.push({ key: 'system.model', label: 'Selected Model', type: 'string', visualization: 'text', group: 'System' });
    }
    if (selectedFirmware) {
      descriptors.push({ key: 'system.firmwareVersion', label: 'Selected Firmware', type: 'string', visualization: 'text', group: 'System' });
    }
    if (health !== 'ok') {
      descriptors = [...descriptors, { key: 'system.error', label: 'Error', type: 'string', visualization: 'text', group: 'System' }];
    }

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      metricDescriptors: descriptors,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: {
        cacheTtlSeconds: Math.round(opts.cacheTtlMs / 1_000),
        requestTimeoutMs: opts.requestTimeoutMs,
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    if (err instanceof SwosAuthError) return fail('critical', err.message);
    const message = (err as Error).message;
    // "Not a recognized SwOS device" means the plugin is assigned to the wrong
    // device type — 'unknown' rather than 'critical' (mirrors LANCOM semantics).
    if (/not a recognized swos/i.test(message)) return fail('unknown', message);
    return fail('critical', `SwOS monitoring failed: ${message}`);
  }
});

/** Builds the ActionContext for one /config step. */
async function buildActionContext(args: { host: string; deviceId?: string; credentials: Record<string, unknown>; settings: Record<string, unknown> }): Promise<ActionContext> {
  const username = typeof args.credentials.username === 'string' ? (args.credentials.username as string) : '';
  const password = typeof args.credentials.password === 'string' ? (args.credentials.password as string) : '';
  if (!username) throw new Error('Missing username in the assigned secret');
  const opts = resolveOptions(args.settings);
  const client = new SwosClient(args.host, { username, password }, opts.requestTimeoutMs);
  const platform = await createPlatform(client);
  return { client, platform, host: args.host, deviceId: args.deviceId };
}

/**
 * Executes one action step. Accepts BOTH body shapes the API uses:
 *  - plan steps:      { actionId, input }
 *  - legacy config jobs: { action, payload }
 */
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const { deviceId, managementAddress } = body;
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : typeof body.action === 'string' ? body.action : undefined;
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object'
      ? (body.input as Record<string, unknown>)
      : body.payload && typeof body.payload === 'object'
        ? (body.payload as Record<string, unknown>)
        : {};

  const settings = readSettings(req);

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId (or legacy "action")' } });
    return;
  }
  if (typeof managementAddress !== 'string' || !managementAddress) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted fields (username/password).
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  try {
    const ctx = await buildActionContext({ host: managementAddress, deviceId: typeof deviceId === 'string' ? deviceId : undefined, credentials: creds, settings });

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
    if (err instanceof SwosAuthError) {
      res.status(200).json({ success: false, result: { error: err.message } });
      return;
    }
    res.status(200).json({ success: false, result: { error: (err as Error).message } });
  }
});

/**
 * Plans an intent across a batch of devices. The plugin does ALL the planning —
 * SwOS v1 has no multi-device intents, so this is a per-device fan-out with a
 * best-effort backup snapshot prepended for every device that gets writes.
 *
 * Body: { intent: { actionId, inputs }, devices: [{ deviceId, managementAddress, credentials }] }
 */
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
          credentials: {
            username: typeof d.credentials?.username === 'string' ? d.credentials.username : '',
            password: typeof d.credentials?.password === 'string' ? d.credentials.password : '',
          },
        }))
      : [],
  };

  try {
    const plan = buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the UnifiedNetworkManager API can
 * discover it automatically. Best-effort — the API also polls known endpoints.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: DISPLAY_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: EFFECTIVE_UUID,
        name: DISPLAY_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[swos-plugin] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[swos-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[swos-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});
