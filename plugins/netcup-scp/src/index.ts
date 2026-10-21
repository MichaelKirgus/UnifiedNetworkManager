/**
 * UnifiedNetworkManager plugin for netcup SCP (Server Control Panel) —
 * VM fleet monitoring + plan-gated VM/firewall management.
 *
 * One UNM device = one netcup account (one Bearer token). The plugin:
 *   1. MONITORING (read): polls the SCP REST API and reports the server
 *      inventory table, recent tasks, plus — for UNM's own pages — networks[]
 *      (every IP alias of every VM interface) and firewallRules[] (unified rows
 *      from each interface's firewall policies).
 *   2. CONFIGURATION (write): a catalog of ~20 plan-gated actions covering the
 *      "bare minimum" VM management (power, hostname/nickname), snapshots,
 *      rescue system, ISO attach/detach, OS image setup, firewall policy CRUD +
 *      interface apply, rDNS and task cancellation. All writes verify by
 *      re-reading state afterwards; dangerous ones flow through the plan
 *      workflow with confirm dialogs (and a pre-change rollback snapshot).
 *
 * Everything boring — identity/multi-instance resolution, the express app with
 * /healthz + /discover, mDNS advertising, settings-header parsing, input
 * validation and plan finalization — comes from @unm/plugin-sdk. This file only
 * declares WHAT the plugin is and registers its own routes:
 *   - POST /monitoring  → health (API reachability/auth) + server/task tables + inventory rows
 *   - POST /config      → run one catalog action step
 *   - POST /plan        → fan a single-device intent out to per-device steps (+ rollback snapshot)
 */

import { Request, Response } from 'express';
import path from 'node:path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  isTransientTransportError,
  readSettings,
  resolvePluginIdentity,
  validateInput,
} from '@unm/plugin-sdk';
import { NETCUP_SCP_DEVICE_SUPPORT } from './deviceSupport';
import { ScpActionContext, registry as actionRegistry } from './actions';
import { buildPlan, PlanningError } from './plan';
import { collectScpMonitoring } from './monitoring';
import { createScpClient, isAuthError, normalizeBaseUrl, ScpApiError } from './client/scpClient';

// --- Identity -----------------------------------------------------------------
const identity = resolvePluginIdentity({
  uuid: '00000000-0000-4000-8000-000000000014', // netcup SCP plugin — stable primary key in the API
  name: 'netcup SCP Plugin',
  description:
    'netcup Server Control Panel integration — VM inventory/state/task metrics, network + firewall rule inventory into UNM, and plan-gated VM management (power, snapshots, ISO, image setup, firewall policies).',
  version: '0.1.0',
  vendors: ['netcup'],
  capabilities: ['monitoring', 'inventory', 'configuration'],
});

// --- Options --------------------------------------------------------------------
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'baseUrl',
    label: 'SCP API base URL',
    type: 'string' as const,
    default: 'https://servercontrolpanel.de/scp-core',
    description: 'Base of the SCP REST API. The device managementAddress is used when set; this option is the fallback for multi-instance setups.',
  },
  { key: 'timeoutMs', label: 'Request timeout (ms)', type: 'integer' as const, default: 15000, min: 2000, max: 60000, description: 'Per-request timeout for SCP API calls.' },
  {
    key: 'collectFirewall',
    label: 'Collect firewall rules into UNM',
    type: 'boolean' as const,
    default: true,
    description: 'When enabled, each poll also reads every VM interface\'s firewall and feeds the unified Firewall page. Disable for faster polls on large fleets.',
  },
  { key: 'logToApi', label: 'Send logs to UNM', type: 'boolean' as const, default: true, description: 'Ship structured log entries (poll/action failures) to the UNM API for the device Logs view.' },
];

// --- Metric descriptors -----------------------------------------------------------
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  {
    key: 'netcup.servers',
    label: 'Servers (VMs)',
    type: 'string',
    visualization: 'table',
    columns: ['name', 'nickname', 'state', 'cpu', 'ramMiB', 'ips'],
    group: 'SCP',
  },
  {
    key: 'netcup.tasks',
    label: 'Recent Tasks',
    type: 'string',
    visualization: 'table',
    columns: ['task', 'state', 'startedAt'],
    group: 'SCP',
  },
];

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'netcup-scp-plugin',
  jsonLimit: '1mb',
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // SCP authenticates with a long-lived OAuth2 Bearer token (Keycloak device-code flow).
    requiredSecretType: 'apiKeyNoSecret',
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: actionRegistry.listCatalog(),
    modules: actionRegistry.listModules(),
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: NETCUP_SCP_DEVICE_SUPPORT,
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
function endpointsOf(settings: Record<string, unknown>, managementAddress: string): { baseUrl: string; timeoutMs: number } {
  // The device's managementAddress wins (it is the per-device identity); the
  // option is a fallback for setups where the address was left empty.
  const raw = managementAddress !== '' ? managementAddress : (typeof settings['baseUrl'] === 'string' ? (settings['baseUrl'] as string) : '');
  return {
    baseUrl: normalizeBaseUrl(raw),
    timeoutMs: clampInt(settings['timeoutMs'], 2000, 60000, 15000),
  };
}

/** Resolves the SCP Bearer token from the request's credentials body. */
function resolveCredentials(credentials: Record<string, unknown> | undefined): { token?: string; error?: string } {
  if (!credentials || typeof credentials !== 'object') return { error: 'Missing credentials' };
  const token = typeof credentials['apiKey'] === 'string' && credentials['apiKey'].length > 0 ? credentials['apiKey'].trim() : undefined;
  if (token) return { token };
  return { error: 'Missing SCP API token — bind an "API Key (without secret)" containing your netcup SCP Bearer token to this device.' };
}

/** Builds a bound client for one SCP account. */
function buildClient(baseUrl: string, token: string, timeoutMs?: number) {
  return createScpClient({ baseUrl, token, timeoutMs });
}

/** Human-readable message from an unknown rejection reason. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------
// POST /monitoring — the telemetry worker polls every ~30 s (10 s budget).
// Health comes from API reachability + auth. On success we fan out per-server
// detail reads in parallel; a failed sub-read degrades to warning, never critical.
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

  if (!ep.baseUrl) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': 'Missing managementAddress (set the SCP API base URL on the device)' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const { token, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!token) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': credError ?? 'Missing credentials' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const client = buildClient(ep.baseUrl, token, ep.timeoutMs);
  const fail = (health: Health, error: string): void => {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health, metrics: { 'system.error': error }, metricDescriptors: [errorDescriptor()], error });
  };

  const result = await collectScpMonitoring(client, { collectFirewall: settings.collectFirewall !== false });

  res.status(200).json({
    deviceId: deviceId ?? null,
    collectedAt: new Date().toISOString(),
    health: result.health,
    metrics: result.metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
    // Echo back the effective settings we received — proof that the
    // API→plugin settings injection loop works end to end.
    activeSettings: {
      baseUrl: ep.baseUrl,
      collectFirewall: settings.collectFirewall !== false,
      logToApi: settings.logToApi === true,
    },
  });
}

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one SCP account. The API's
// config-job worker dispatches here with {actionId, input, credentials}; the
// plugin owns ALL logic (schema validation + API calls). Same contract as the
// other plugins: 200 + { success, result } on every path.
// ---------------------------------------------------------------------------

app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  // Registry shape preferred.
  const actionId: string | undefined = typeof body.actionId === 'string' ? body.actionId : undefined;
  const input: Record<string, unknown> =
    body.input && typeof body.input === 'object' ? (body.input as Record<string, unknown>) : {};

  if (!actionId) {
    res.status(400).json({ success: false, result: { error: 'Missing actionId' } });
    return;
  }

  const ep = endpointsOf(settings, hostOf(body.managementAddress));
  if (!ep.baseUrl) {
    res.status(200).json({ success: false, result: { error: 'Missing managementAddress (set the SCP API base URL on the device)' } });
    return;
  }

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  const { token, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!token) {
    res.status(200).json({ success: false, result: { error: credError ?? 'Missing credentials' } });
    return;
  }

  // Validate input against the action's declared schema — the plugin is the authority.
  const issues = validateInput(action.inputSchema, input);
  if (issues.length > 0) {
    res.status(200).json({ success: false, result: { error: `Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}` } });
    return;
  }

  try {
    const client = buildClient(ep.baseUrl, token, action.timeoutMs ?? ep.timeoutMs);
    const ctx: ScpActionContext = { client, settings };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${ep.baseUrl}: ${errMsg(err)}`, { deviceId, context: { actionId } });
    // Transport-level failures are transient — the plan executor re-dispatches them.
    // A ScpApiError means the API answered (bad token, invalid input, …) — hard failure.
    const retryable = !(err instanceof ScpApiError) && isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: errMsg(err), ...(retryable ? { retryable: true } : {}) } });
  }
});

// ---------------------------------------------------------------------------
// POST /plan — fan a single-device intent out to one step per device (+ rollback snapshot).
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

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[netcup-scp-plugin] fatal startup error:', err);
  process.exit(1);
});
