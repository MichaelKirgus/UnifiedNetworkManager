import path from 'path';
import {
  Health,
  PluginOptionDescriptor,
  TtlCache,
  clampInt,
  collectDeviceCertificates,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  modelFirmwareDescriptors,
  parseProbeTarget,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  createPinningGuard,
  StateRequestBody,
  CertificateRow,
} from '@unm/plugin-sdk';
import { SwosClient, SwosAuthError } from './swosClient';
import { createPlatform } from './platform';
import { DEFAULT_OPTIONS, MonitoringResult, SwosOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { buildSwosState } from './state';
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
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.1.0 — initial release: SwOS/SwOS Lite monitoring (system, ports, PoE, LAG,
  // VLANs, SFP, SNMP) + inventory propagation (VLAN networks, MAC table hosts),
  // plus the full action catalog from the reference project's proven write set
  // (port config, PoE, LAG, per-port VLANs, VLAN table, SNMP, system identity/
  // management access, backup download). SwOS only — RouterOS gets its own plugin.
  version: '0.1.0',
  vendors: ['mikrotik'],
  // 'deviceState' advertises POST /state — the dynamic document behind the
  // per-device Config page (ports with live state + PoE/LAG/VLAN actions).
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'deviceState'],
});

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
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
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// Pre-wired app: cors + json (32mb — backup downloads can be several MB) +
// /healthz + /discover (+ static icons, mDNS on listen) come from @unm/plugin-sdk
// — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'mikrotik-swos-plugin',
  jsonLimit: '32mb',
  // Static icon assets (plugin + per-model icons), advertised in /discover and
  // fetched by the API's icon proxy. dist/src/../../icons = <plugin root>/icons.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Credentials come from the existing 'usernamePassword' secret type — SwOS
    // uses HTTP Digest authentication with a username/password pair.
    requiredSecretType: 'usernamePassword',
    options: PLUGIN_OPTIONS,
    actions: listCatalog(),
    iconUrl: '/icons/swos.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the 60 s snapshot — they
// change rarely and each probe opens fresh TLS/SSH connections to the switch.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// Certificate pinning — one process-wide guard for every credential-bearing entry
// point. Strict mode + a known fingerprint MISMATCH throws before any credentials
// are transmitted; unknown endpoints are TOFU-accepted and land in UNM's inventory.
const assertPinned = createPinningGuard();

/** SwOS is HTTP-only unless the address carries an explicit https:// prefix — mirror
 *  that here so the pinning guard only runs a TLS preflight when the client actually
 *  speaks TLS (an http box has no certificate to pin). */
function swosTransportOf(address: string): 'http' | 'https' {
  return /^https:\/\//i.test(String(address ?? '').trim()) ? 'https' : 'http';
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

/**
 * POST /state — dynamic device-state document for the UNM Config page.
 * The API broker (api/src/deviceState.ts) calls this with fresh credentials +
 * injected settings and returns the response verbatim to the webapp. Built
 * from the TTL-cached snapshot: one Ports section item per physical port
 * (link state, speed/duplex, PoE draw, LAG membership, per-port VLANs, learned
 * MACs) with variant-aware action refs, plus a System summary.
 */
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const opts = resolveOptions(settings);

  // Credentials: the assignment's decrypted fields are at top level of
  // `credentials` (secret type `usernamePassword`) — same model as /monitoring.
  const { creds, error } = resolveCredentials(body as unknown as Record<string, unknown>);
  if (error || !creds) throw new Error(error ?? 'Missing credentials.');

  // Certificate pinning — /state reads live data with credentials; verify first.
  await assertPinned(req, body.managementAddress, swosTransportOf(body.managementAddress));

  const result = await getMonitoring(body.managementAddress.trim(), creds, opts);
  return buildSwosState(result.snapshot);
}, 'mikrotik-swos-plugin'));

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // User-selected hardware model / firmware version (forwarded by the API from
  // the device row). Surfaced as System metrics so the selection is visible in
  // the webapp's monitoring view.
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const opts = resolveOptions(settings);

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [errorDescriptor()],
      error,
    });
  };

  if (!managementAddress.trim()) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials(body);
  if (error || !creds) return fail('critical', error ?? 'Missing credentials.');

  try {
    // Certificate pinning — verify the switch's TLS cert against UNM's inventory
    // BEFORE any credentials are transmitted (throws on mismatch). Skipped for
    // HTTP-only boxes (no certificate to pin).
    await assertPinned(req, managementAddress, swosTransportOf(managementAddress));

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
      logger.warn(`SwOS monitoring degraded for ${managementAddress}: ${warnings.join('; ')}`, { deviceId, context: { host: managementAddress } });
    }

    const metrics = buildMetrics(s, selectedModel, selectedFirmware);
    if (health !== 'ok') metrics['system.error'] = warnings.join('; ');

    // --- Certificates (normalized for the cross-device Certificates page) ----
    // SwOS Lite is HTTP-only — there is no management HTTPS cert to read unless
    // an explicit https:// address was configured. The SSH host key on port 22
    // IS available and always probed. Both probes are credential-free and
    // best-effort; a failure simply contributes no row.
    {
      const cachedCerts = certCache.get(managementAddress, CERT_TTL_MS) ?? null;
      let certRows: CertificateRow[] | null = cachedCerts;
      if (!certRows) {
        const target = parseProbeTarget(managementAddress, 443);
        const explicitHttps = /^https:\/\//i.test(managementAddress.trim());
        certRows =
          target && explicitHttps
            ? await collectDeviceCertificates({
                host: target.host,
                httpsPort: target.port,
                servername: target.host,
                sshEnabled: true,
                timeoutMs: 5_000,
              })
            : target
              ? await collectDeviceCertificates({
                  host: target.host,
                  httpsPort: null, // HTTP-only management UI — no TLS cert to read
                  servername: target.host,
                  sshEnabled: true,
                  timeoutMs: 5_000,
                })
              : [];
        certCache.set(managementAddress, certRows);
      }
      if (certRows.length > 0) metrics['certificates'] = certRows;
    }

    let descriptors = [...buildDescriptors(s), ...modelFirmwareDescriptors(selectedModel, selectedFirmware)];
    if (health !== 'ok') {
      descriptors = [...descriptors, errorDescriptor()];
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
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof SwosAuthError) {
      logger.error(`SwOS authentication failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('critical', message);
    }
    // "Not a recognized SwOS device" means the plugin is assigned to the wrong
    // device type — 'unknown' rather than 'critical' (mirrors LANCOM semantics).
    if (/not a recognized swos/i.test(message)) {
      logger.warn(`SwOS probe for ${managementAddress} found no SwOS device: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('unknown', message);
    }
    logger.error(`SwOS monitoring failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
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

  const settings = readSettings(req, PLUGIN_OPTIONS);  logger.setEnabled(settings.logToApi === true);
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
    // Certificate pinning — a config action transmits real credentials; refuse
    // the connection when the switch's key differs from UNM's inventory.
    await assertPinned(req, managementAddress, swosTransportOf(managementAddress));

    const ctx = await buildActionContext({ host: managementAddress, deviceId: typeof deviceId === 'string' ? deviceId : undefined, credentials: creds, settings });

    // Validate input against the action's declared schema — the plugin is the
    // authority on what it accepts; the API only checks that the id exists.
    const issues = validateInput(action.inputSchema, input);
    if (issues.length > 0) {
      res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
      return;
    }

    const result: ActionResult = await action.execute(ctx, input);
    if (!result.success) {
      logger.warn(`Config action ${actionId} reported failure for ${managementAddress}: ${typeof result.error === 'string' ? result.error : JSON.stringify(result)}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
    }
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    if (err instanceof SwosAuthError) {
      logger.error(`Config action ${actionId} failed for ${managementAddress}: ${err.message}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
      res.status(200).json({ success: false, result: { error: err.message } });
      return;
    }
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
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
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

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
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${(err as Error).message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: (err as Error).message });
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[mikrotik-swos-plugin] fatal startup error:', err);
  process.exit(1);
});
