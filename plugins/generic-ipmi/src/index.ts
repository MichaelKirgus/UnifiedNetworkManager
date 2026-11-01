/**
 * UnifiedNetworkManager plugin for generic IPMI (RMCP+ over UDP 623) —
 * bare-metal server monitoring + plan-gated control, with NO external dependency:
 * the RMCP+ protocol stack (RAKP1-4 challenge/response, AES-CBC-128 payload
 * encryption, HMAC-SHA1-96 integrity) is implemented in-process in TypeScript.
 * The BMC password lives only in Node crypto memory — it never touches argv,
 * env or disk (no ipmitool subprocess).
 *
 * One UNM device = one BMC (username/password). The plugin:
 *   1. MONITORING (read): chassis power state → health; SDR sensor walk with live
 *      readings + threshold states → ipmi.sensors table; FRU identity fields;
 *      SEL tail → ipmi.sel table; LAN channel config → networks[] inventory row.
 *   2. CONFIGURATION (write): a catalog of plan-gated actions — power on /
 *      soft-off / hard-off / reset, boot options, SEL clear, NMI pulse and BMC
 *      LAN parameter writes. All verify by re-reading state afterwards; dangerous
 *      ones flow through the plan workflow with confirm dialogs.
 *   3. CONSOLE (sshConsole capability): an IPMI SOL (Serial-over-LAN) terminal on
 *      /console — the webapp's generic "Shell" button maps to a serial console.
 *
 * Everything boring — identity/multi-instance resolution, the express app with
 * /healthz + /discover, mDNS advertising, settings-header parsing, input
 * validation and plan finalization — comes from @unm/plugin-sdk. This file only
 * declares WHAT the plugin is and registers its own routes:
 *   - POST /monitoring  → health (BMC reachability/auth) + chassis/sensor/FRU/SEL tables + inventory rows
 *   - POST /config      → run one catalog action step
 *   - POST /plan        → fan a single-device intent out to per-device steps
 *   - POST /probe       → on-demand chassis status probe (Devices page)
 *   - WS   /console     → SOL serial console (capability 'sshConsole')
 */

import { Request, Response } from 'express';
import path from 'node:path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  SshTerminalSession,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  isTransientTransportError,
  makeConsoleUpgrade,
  probeHandler,
  readSettings,
  resolvePluginIdentity,
  validateInput,
} from '@unm/plugin-sdk';
import { GENERIC_IPMI_DEVICE_SUPPORT } from './deviceSupport';
import { IpmiActionContext, registry as actionRegistry } from './actions';
import { buildPlan, PlanningError } from './plan';
import { collectIpmiMonitoring } from './monitoring';
import { SolTerminalSession } from './solSession';
import { IpmiClient, IpmiError } from './client/ipmiClient';
import { getChassisStatus } from './client/ipmiCommands';

// --- Identity -----------------------------------------------------------------
const identity = resolvePluginIdentity({
  uuid: '00000000-0000-4000-8000-000000000015', // generic IPMI plugin — stable primary key in the API
  name: 'Generic IPMI Plugin',
  description:
    'IPMI 2.0 (RMCP+) server management — chassis power state, SDR sensor readings with threshold states, FRU identity and SEL events into UNM; plan-gated power/boot/SEL/LAN control; SOL serial console. Self-contained protocol stack (no ipmitool).',
  version: '0.1.0',
  vendors: ['generic'],
  capabilities: ['monitoring', 'inventory', 'configuration', 'probe', 'sshConsole'],
});

// --- Options --------------------------------------------------------------------
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'cipherSuiteId',
    label: 'IPMI cipher suite',
    type: 'integer' as const,
    default: 3,
    min: 0,
    max: 3,
    description:
      'Cipher suite for the RMCP+ session. 3 (default) = RAKP-HMAC-SHA1 + HMAC-SHA1-96 integrity + AES-CBC-128 payload encryption — recommended. 0 = no auth/integrity/encryption, only for legacy BMCs that reject cipher 3.',
  },
  { key: 'timeoutMs', label: 'Request timeout (ms)', type: 'integer' as const, default: 10000, min: 2000, max: 60000, description: 'Per-IPMI-request UDP timeout.' },
  {
    key: 'collectSensors',
    label: 'Collect sensor readings',
    type: 'boolean' as const,
    default: true,
    description: 'When enabled, each poll walks the SDR repository and reads every sensor. Disable for faster polls on BMCs with huge repositories.',
  },
  { key: 'logToApi', label: 'Send logs to UNM', type: 'boolean' as const, default: true, description: 'Ship structured log entries (poll/action failures) to the UNM API for the device Logs view.' },
  {
    key: 'aspeedFan',
    label: 'Read Aspeed OEM fan state',
    type: 'boolean' as const,
    default: false,
    description:
      'Enable on ASRock Rack / AST2600/AST2500 BMC boards (e.g. B650D4U-2L2T/BCM): each poll reads the OEM fan table (netfn 0x3a) and reports per-channel mode + duty in the ipmi.fan metric. Leave off on other BMCs — they do not answer these commands.',
  },
];

// --- Metric descriptors -----------------------------------------------------------
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  {
    key: 'ipmi.chassis',
    label: 'Chassis Status',
    type: 'string',
    visualization: 'table',
    columns: ['poweredOn', 'powerControlLost', 'restorePolicy'],
    group: 'IPMI',
  },
  {
    key: 'ipmi.sensors',
    label: 'Sensors (SDR)',
    type: 'string',
    visualization: 'table',
    columns: ['id', 'type', 'reading', 'unit', 'state'],
    group: 'IPMI',
  },
  {
    key: 'ipmi.fru',
    label: 'FRU Identity',
    type: 'string',
    visualization: 'table',
    columns: ['area', 'key', 'value'],
    group: 'IPMI',
  },
  {
    key: 'ipmi.sel',
    label: 'System Event Log (recent)',
    type: 'string',
    visualization: 'table',
    columns: ['timestamp', 'severity', 'sensorType', 'event'],
    group: 'IPMI',
  },
  {
    key: 'ipmi.fan',
    label: 'Fans (Aspeed OEM)',
    type: 'string',
    visualization: 'table',
    columns: ['channel', 'mode', 'dutyPercent'],
    group: 'IPMI',
  },
];

// ---------------------------------------------------------------------------
// Interactive SOL console (/console WebSocket, capability 'sshConsole').
// The webapp's DeviceDetail "Shell" button renders for any plugin advertising
// 'sshConsole'; the API proxies the browser's xterm.js to our /console endpoint.
// We map ANY context kind to an IPMI SOL session — a bare-metal server has no
// other interactive console, and SOL is exactly what `ipmitool sol activate` does.
// (Defined before createPluginServer so wsUpgrade can reference it.)
// ---------------------------------------------------------------------------

const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const ep = endpointsOf({}, hostOf(hello.managementAddress)); // defaults; settings ride in hello.settings
    if (!ep.host) throw new Error('Missing management address');

    const creds = (hello.credentials ?? {}) as Record<string, unknown>;
    const username = typeof creds['username'] === 'string' ? (creds['username'] as string) : '';
    const password = typeof creds['password'] === 'string' ? (creds['password'] as string) : '';
    if (!username || !password) throw new Error('Missing BMC credentials — bind a "Username & Password" secret to this device');

    // Honor per-device option overrides delivered in the hello frame.
    const settings = (hello.settings ?? {}) as Record<string, unknown>;
    ep.timeoutMs = clampInt(settings['timeoutMs'], 2000, 60000, 10000);
    ep.cipherSuiteId = clampInt(settings['cipherSuiteId'], 0, 3, 3);

    const client = await buildClient(ep, username, password);
    const session = new SolTerminalSession(client, 1);
    try {
      await session.open(); // activateSol — throws (→ WS error frame) when SOL is unavailable
    } catch (err) {
      client.close();
      throw err;
    }
    // The SDK types onOpen as Promise<SshTerminalSession>; SolTerminalSession is
    // structurally compatible (same events + write/resize/close surface).
    return session as unknown as SshTerminalSession;
  },
});

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'generic-ipmi-plugin',
  jsonLimit: '1mb',
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  // Interactive SOL console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  discovery: {
    // BMC login is a username/password pair (the RMCP+ RAKP handshake).
    requiredSecretType: 'usernamePassword',
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: actionRegistry.listCatalog(),
    modules: actionRegistry.listModules(),
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: GENERIC_IPMI_DEVICE_SUPPORT,
  },
});
const app = server.app;

// --- Structured logging ---------------------------------------------------------------
const logger = createPluginLogger(identity);

// --- Helpers --------------------------------------------------------------------------

/** Extracts the management address from a request body. */
function hostOf(managementAddress: unknown): string {
  return typeof managementAddress === 'string' ? managementAddress.trim() : '';
}

/** Resolves effective options from injected settings. */
function endpointsOf(settings: Record<string, unknown>, managementAddress: string): { host: string; port: number; timeoutMs: number; cipherSuiteId: number } {
  // The device's managementAddress is the BMC's IP (strip any :port if present).
  const raw = managementAddress !== '' ? managementAddress : '';
  const [host, portStr] = raw.includes(':') ? raw.split(':') : [raw, ''];
  return {
    host: host.trim(),
    port: portStr ? clampInt(parseInt(portStr, 10), 1, 65535, 623) : 623,
    timeoutMs: clampInt(settings['timeoutMs'], 2000, 60000, 10000),
    cipherSuiteId: clampInt(settings['cipherSuiteId'], 0, 3, 3),
  };
}

/** Resolves the BMC username/password from the request's credentials body. */
function resolveCredentials(credentials: Record<string, unknown> | undefined): { username?: string; password?: string; error?: string } {
  if (!credentials || typeof credentials !== 'object') return { error: 'Missing credentials' };
  const username = typeof credentials['username'] === 'string' && (credentials['username'] as string).length > 0 ? (credentials['username'] as string) : undefined;
  const password = typeof credentials['password'] === 'string' ? (credentials['password'] as string) : undefined;
  if (!username || !password) {
    return { error: 'Missing BMC username/password — bind a "Username & Password" secret to this device.' };
  }
  return { username, password };
}

/** Builds + connects an IpmiClient for one BMC. Throws IpmiError on failure. */
async function buildClient(ep: { host: string; port: number; timeoutMs: number; cipherSuiteId: number }, username: string, password: string): Promise<IpmiClient> {
  const client = new IpmiClient({ host: ep.host, port: ep.port, timeoutMs: ep.timeoutMs });
  await client.connect(username, password, { cipherSuiteId: ep.cipherSuiteId });
  return client;
}

/** Human-readable message from an unknown rejection reason. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------
// POST /monitoring — the telemetry worker polls every ~30 s (10 s budget).
// Health comes from BMC reachability + RAKP auth. On success we collect chassis,
// sensors (+ readings), and — on inventory-due polls only — FRU/SEL/LAN rows.
// A failed sub-read degrades to warning, never critical.
// ---------------------------------------------------------------------------

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId: string | undefined = typeof body.deviceId === 'string' ? body.deviceId : undefined;
  try {
    await handleMonitoring(req, res, body, deviceId);
  } catch (err) {
    // Safety net: Express does NOT catch rejections from async handlers.
    logger.error(`Monitoring poll crashed: ${errMsg(err)}`, { deviceId });
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: { 'system.error': errMsg(err) },
      metricDescriptors: [errorDescriptor()],
    });
  }
});

async function handleMonitoring(req: Request, res: Response, body: Record<string, unknown>, deviceId: string | undefined): Promise<void> {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const ep = endpointsOf(settings, hostOf(body.managementAddress));

  if (!ep.host) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': 'Missing managementAddress (set the BMC IP on the device)' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const { username, password, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!username || !password) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': credError ?? 'Missing credentials' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const fail = (health: Health, error: string): void => {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health, metrics: { 'system.error': error }, metricDescriptors: [errorDescriptor()], error });
  };

  let client: IpmiClient;
  try {
    client = await buildClient(ep, username, password);
  } catch (err) {
    // ANY connect failure means the BMC is unusable right now — wrong credentials
    // (auth), no RMCP+ answer at all (transport timeout / UDP black hole) or a
    // protocol mismatch. All of those are critical: the device cannot be managed.
    logger.error(`BMC connect failed for ${ep.host}: ${errMsg(err)}`, { deviceId });
    fail('critical', errMsg(err));
    return;
  }

  try {
    // collectInventory absent = true (pre-scheduler APIs + first poll).
    const collectInventory = body.collectInventory !== false;
    const result = await collectIpmiMonitoring(client, {
      collectInventory,
      collectSensors: settings.collectSensors !== false,
      aspeedFan: settings.aspeedFan === true,
    });

    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: result.health,
      metrics: result.metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
      // Echo back the effective settings we received — proof that the
      // API→plugin settings injection loop works end to end.
      activeSettings: {
        cipherSuiteId: ep.cipherSuiteId,
        collectSensors: settings.collectSensors !== false,
        aspeedFan: settings.aspeedFan === true,
        logToApi: settings.logToApi === true,
      },
    });
  } finally {
    client.close();
  }
}

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one BMC. The API's config-job
// worker dispatches here with {actionId, input, credentials}; the plugin owns ALL
// logic (schema validation + IPMI calls). Same contract as the other plugins:
// 200 + { success, result } on every path.
// ---------------------------------------------------------------------------

app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  // Registry shape preferred.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : undefined;
  const input: Record<string, unknown> = body.input && typeof body.input === 'object' ? (body.input as Record<string, unknown>) : {};

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId' } });
    return;
  }

  const ep = endpointsOf(settings, hostOf(body.managementAddress));
  if (!ep.host) {
    res.status(200).json({ success: false, result: { error: 'Missing managementAddress (set the BMC IP on the device)' } });
    return;
  }

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  const { username, password, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!username || !password) {
    res.status(200).json({ success: false, result: { error: credError ?? 'Missing credentials' } });
    return;
  }

  // Validate input against the action's declared schema — the plugin is the authority.
  const issues = validateInput(action.inputSchema, input);
  if (issues.length > 0) {
    res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
    return;
  }

  let client: IpmiClient | null = null;
  try {
    client = await buildClient(ep, username, password);
    const ctx: IpmiActionContext = { client, settings };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${ep.host}: ${errMsg(err)}`, { deviceId, context: { actionId } });
    // A BMC comcode/auth answer is final; transport-level failures are transient —
    // the plan executor re-dispatches them.
    const isFinal = err instanceof IpmiError && (err.kind === 'comcode' || err.kind === 'auth');
    const retryable = !isFinal && isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: errMsg(err), ...(retryable ? { retryable: true } : {}) } });
  } finally {
    client?.close();
  }
});

// ---------------------------------------------------------------------------
// POST /plan — fan a single-device intent out to one step per device.
// ---------------------------------------------------------------------------

app.post('/plan', async (req, res) => {
  const body = req.body ?? {};
  logger.setEnabled(readSettings(req, PLUGIN_OPTIONS).logToApi === true);

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
    logger.error(`Planning crashed: ${errMsg(err)}`);
    res.status(500).json({ error: errMsg(err) });
  }
});

// ---------------------------------------------------------------------------
// POST /probe — on-demand chassis status probe (Devices page, 1–5 s cadence).
// Keep it CHEAP: one connect + one Get Chassis Status.
// ---------------------------------------------------------------------------

app.post(
  '/probe',
  probeHandler(async (body, req) => {
    const settings = readSettings(req, PLUGIN_OPTIONS);
    const ep = endpointsOf(settings, hostOf(body.managementAddress));
    if (!ep.host) throw new Error('Missing management address');

    const creds = body.credentials as Record<string, unknown> | undefined;
    const username = typeof creds?.['username'] === 'string' ? (creds['username'] as string) : '';
    const password = typeof creds?.['password'] === 'string' ? (creds['password'] as string) : '';
    if (!username || !password) throw new Error('Missing BMC credentials');

    const client = await buildClient(ep, username, password);
    try {
      const chassis = await getChassisStatus(client);
      return {
        collectedAt: new Date().toISOString(),
        metrics: {
          'ipmi.chassis': { poweredOn: chassis.poweredOn, powerControlLost: chassis.powerControlLost, restorePolicy: chassis.restorePolicy },
        },
      };
    } finally {
      client.close();
    }
  }, identity.displayName),
);

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[generic-ipmi-plugin] fatal startup error:', err);
  process.exit(1);
});
