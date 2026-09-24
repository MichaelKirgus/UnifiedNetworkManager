/**
 * UnifiedNetworkManager plugin for Zabbix — fleet monitoring + host inventory sync.
 *
 * Two jobs, one plugin:
 *   1. MONITORING (read): polls the Zabbix server's JSON-RPC API and reports the
 *      state of everything Zabbix watches — version, monitored-host count/status
 *      table and active problems — as UNM metrics for this device.
 *   2. INVENTORY SYNC (write, capability 'inventorySync'): keeps the external
 *      monitoring system in step with UNM's host inventory. The API serves the
 *      authoritative snapshot through its internal brokered read; a plan-gated
 *      action (zabbix.host.sync) reconciles it into Zabbix — create/update/delete.
 *      All mapping rules are plugin options, so adapting to another monitoring
 *      system's logic never needs code changes.
 *
 * Everything boring — identity/multi-instance resolution, the express app with
 * /healthz + /discover, mDNS advertising, settings-header parsing, input
 * validation and plan finalization — comes from @unm/plugin-sdk. This file only
 * declares WHAT the plugin is and registers its own routes:
 *   - POST /monitoring  → health (API reachability/auth) + version + host/problem tables
 *   - POST /config      → run one catalog action step (sync / create-host)
 *   - POST /plan        → fan a single-device intent out to per-device steps
 */

import { Request, Response } from 'express';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  isTransientTransportError,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  readSettings,
  resolvePluginIdentity,
  validateInput,
} from '@unm/plugin-sdk';
import { ZabbixActionContext } from './actions';
import { registry as actionRegistry } from './actions';
import { buildPlan, PlanningError } from './plan';
import { SYNC_OPTION_KEYS } from './sync';
import {
  ZabbixApiError,
  ZabbixCredentials,
  ZabbixPorts,
  ZabbixTransport,
  createZabbixClient,
  isAuthError,
} from './client/zabbixClient';

// --- Identity -----------------------------------------------------------------
const identity = resolvePluginIdentity({
  uuid: '00000000-0000-4000-8000-000000000010', // zabbix plugin — stable primary key in the API
  name: 'Zabbix Plugin',
  version: '0.1.0',
  vendors: ['zabbix'],
  capabilities: ['monitoring', 'inventorySync'],
});

// --- Options --------------------------------------------------------------------
// Declared in /discover so the API persists user-set values and injects them back
// via the `x-unm-settings` header on every call — this plugin never stores settings.
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  // --- Transport ---------------------------------------------------------------
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'http', 'https'],
    description: 'How to reach the Zabbix frontend API. auto prefers HTTPS (accepting self-signed certs) and falls back to HTTP.',
  },
  { key: 'httpsPort', label: 'HTTPS port', type: 'integer' as const, default: 443, min: 1, max: 65535, description: 'Management HTTPS port when the address has no explicit port.' },
  { key: 'httpPort', label: 'HTTP port', type: 'integer' as const, default: 80, min: 1, max: 65535, description: 'Management HTTP port when the address has no explicit port.' },
  {
    key: 'basePath',
    label: 'Frontend base path',
    type: 'string' as const,
    default: '/zabbix',
    description: 'URL path of the Zabbix frontend (e.g. /zabbix). The JSON-RPC endpoint is <base>/api_jsonrpc.php.',
  },
  { key: 'timeoutMs', label: 'Request timeout (ms)', type: 'integer' as const, default: 15000, min: 2000, max: 60000, description: 'Per-request timeout for Zabbix API calls.' },

  // --- Inventory sync mapping (the flexible configuration surface) --------------
  {
    key: SYNC_OPTION_KEYS.scope,
    label: 'Sync scope',
    type: 'string' as const,
    default: 'documented',
    enumOptions: ['documented', 'all'],
    description: 'Which UNM hosts the sync covers. "documented" = user-documented hosts only; "all" also includes live ARP/NDP/DHCP observations.',
  },
  {
    key: SYNC_OPTION_KEYS.tag,
    label: 'Sync tag filter',
    type: 'string' as const,
    default: '',
    description: 'Only sync UNM hosts carrying this tag (e.g. "zabbix"). Empty = all in-scope hosts.',
  },
  {
    key: SYNC_OPTION_KEYS.markerTag,
    label: 'Zabbix marker tag',
    type: 'string' as const,
    default: 'unm-managed',
    description: 'Host tag the sync writes onto every Zabbix host it manages (value = UNM host id). Drives matching + orphan detection — only hosts carrying this tag are ever touched.',
  },
  {
    key: SYNC_OPTION_KEYS.nameTemplate,
    label: 'Zabbix name template',
    type: 'string' as const,
    default: '{dns0}',
    description: 'Placeholder template for the Zabbix technical name. Placeholders: {dns0} (first DNS name), {friendlyName}, {ip0} (first IP). Empty falls back to {dns0}.',
  },
  {
    key: SYNC_OPTION_KEYS.groups,
    label: 'Zabbix groups',
    type: 'string' as const,
    default: '',
    description: 'Comma-separated Zabbix group names synced hosts are placed into (auto-created when missing and "auto-create groups" is on). Empty = no groups.',
  },
  { key: SYNC_OPTION_KEYS.autoCreateGroups, label: 'Auto-create groups', type: 'boolean' as const, default: true, description: 'Create the configured Zabbix groups when they do not exist yet.' },
  {
    key: SYNC_OPTION_KEYS.template,
    label: 'Zabbix template link',
    type: 'string' as const,
    default: '',
    description: 'Template name linked onto every synced host (e.g. "Linux by Zabbix agent"). Must already exist in Zabbix. Empty = no template.',
  },
  {
    key: SYNC_OPTION_KEYS.ipMode,
    label: 'IP interface mode',
    type: 'string' as const,
    default: 'all',
    enumOptions: ['all', 'primary'],
    description: 'Which UNM addresses become Zabbix IP interfaces. "all" = every known address; "primary" = only the first.',
  },
  {
    key: SYNC_OPTION_KEYS.deleteOrphans,
    label: 'Delete orphans',
    type: 'boolean' as const,
    default: false,
    description: 'When enabled, UNM-managed Zabbix hosts that are no longer in the inventory snapshot are DELETED. Off by default — retired hosts keep their monitoring history.',
  },
  {
    key: SYNC_OPTION_KEYS.inactiveAsDisabled,
    label: 'Inactive → disabled',
    type: 'boolean' as const,
    default: true,
    description: 'Map UNM\'s inactive (stale/retired) hosts onto a DISABLED Zabbix host instead of deleting them.',
  },
  {
    key: SYNC_OPTION_KEYS.adoptExisting,
    label: 'Adopt existing hosts',
    type: 'boolean' as const,
    default: false,
    description: 'When an untagged (manually created) Zabbix host has the same technical name as a rendered UNM host, CLAIM it — write the marker tag and manage it from now on — instead of failing with "already exists". Off by default.',
  },

  // --- Logging -------------------------------------------------------------------
  { key: 'logToApi', label: 'Send logs to UNM', type: 'boolean' as const, default: true, description: 'Ship structured log entries (poll/action failures) to the UNM API for the device Logs view.' },
];

// --- Metric descriptors -----------------------------------------------------------
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'system.version', label: 'Zabbix Version', type: 'string', visualization: 'text', group: 'System' },
  {
    key: 'zabbix.hosts',
    label: 'Monitored Hosts',
    type: 'string',
    visualization: 'table',
    columns: ['host', 'status'],
    group: 'Zabbix',
  },
  {
    key: 'zabbix.problems',
    label: 'Active Problems',
    type: 'string',
    visualization: 'table',
    columns: ['object', 'name', 'severity'],
    group: 'Zabbix',
  },
];

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'zabbix-plugin',
  jsonLimit: '1mb',
  discovery: {
    // Zabbix authenticates with an API token (preferred) or a user login.
    requiredSecretType: 'apiKeyNoSecret',
    requiredSecretTypes: ['apiKeyNoSecret', 'usernamePassword'],
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: actionRegistry.listCatalog(),
    modules: actionRegistry.listModules(),
    // One-click "Sync to Zabbix" in the Devices page — runs zabbix.host.sync
    // through the standard plan workflow (write risk = confirm dialog).
    quickActions: [
      { id: 'sync-inventory', label: 'Sync inventory', kind: 'action' as const, actionId: 'zabbix.host.sync', description: 'Reconcile UNM\'s host inventory into this Zabbix server (create/update/delete per the sync options).' },
    ],
  },
});
const app = server.app;

// --- Structured logging ---------------------------------------------------------------
const logger = createPluginLogger(identity);

// --- Helpers --------------------------------------------------------------------------

/** Extracts the management address (host[:port]) from a request body. */
function hostOf(managementAddress: unknown): string {
  return typeof managementAddress === 'string' ? managementAddress.trim() : '';
}

/** Resolves effective transport + ports + base path from injected settings. */
function endpointsOf(settings: Record<string, unknown>): { transport: ZabbixTransport; ports: ZabbixPorts; basePath: string } {
  const t = typeof settings['transport'] === 'string' ? (settings['transport'] as ZabbixTransport) : 'auto';
  return {
    transport: t,
    ports: {
      httpsPort: clampInt(settings['httpsPort'], 1, 65535, 443),
      httpPort: clampInt(settings['httpPort'], 1, 65535, 80),
    },
    basePath: typeof settings['basePath'] === 'string' && settings['basePath'].trim() ? (settings['basePath'] as string).trim() : '/zabbix',
  };
}

/** Resolves Zabbix credentials from the request's credentials body. */
function resolveCredentials(credentials: Record<string, unknown> | undefined): { creds?: ZabbixCredentials; error?: string } {
  if (!credentials || typeof credentials !== 'object') return { error: 'Missing credentials' };
  const token = typeof credentials['apiKey'] === 'string' && credentials['apiKey'].length > 0 ? credentials['apiKey'] : undefined;
  if (token) return { creds: { token } };
  const username = typeof credentials['username'] === 'string' ? credentials['username'] : undefined;
  const password = typeof credentials['password'] === 'string' ? credentials['password'] : undefined;
  if (username && password) return { creds: { username, password } };
  return { error: 'Missing Zabbix credentials — bind an "API Key (without secret)" (Zabbix API token) or a Username/Password secret to this device.' };
}

/** Builds a bound client for one Zabbix frontend. */
function buildClient(host: string, settings: Record<string, unknown>, creds: ZabbixCredentials, timeoutMs?: number) {
  const ep = endpointsOf(settings);
  return createZabbixClient(host, creds, ep.transport, ep.ports, ep.basePath, timeoutMs ?? clampInt(settings['timeoutMs'], 2000, 60000, 15000));
}

/** Human-readable message from an unknown rejection reason. */
function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

// ---------------------------------------------------------------------------
// POST /monitoring — the telemetry worker polls every ~30 s (10 s budget).
// Health comes from API reachability + auth. The version call doubles as the
// liveness probe; on success we fan out host.get + problem reads in parallel.
// A failed sub-read degrades to warning, never critical — partial data is useful.
// ---------------------------------------------------------------------------

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId: string | undefined = typeof body.deviceId === 'string' ? body.deviceId : undefined;
  const host = hostOf(body.managementAddress);
  try {
    await handleMonitoring(req, res, body, deviceId, host);
  } catch (err) {
    // Safety net: Express 4 does NOT catch rejections from async handlers.
    logger.error(`Monitoring poll crashed: ${errMsg(err)}`, { deviceId, context: { host } });
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: { 'system.error': errMsg(err) },
      metricDescriptors: [errorDescriptor()],
    });
  }
});

async function handleMonitoring(req: Request, res: Response, body: Record<string, unknown>, deviceId: string | undefined, host: string): Promise<void> {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const timeoutMs = clampInt(settings['timeoutMs'], 2000, 60000, 15000);

  if (!host) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': 'Missing managementAddress' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!creds) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': credError ?? 'Missing credentials' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const client = buildClient(host, settings, creds, timeoutMs);
  const fail = (health: Health, error: string): void => {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health, metrics: { 'system.error': error }, metricDescriptors: [errorDescriptor()], error });
  };

  // Liveness + auth probe. A token-mode client needs no session; a login failure
  // surfaces as an auth error here.
  let version = '';
  try {
    version = await client.version();
  } catch (err) {
    if (isAuthError(err)) return fail('critical', 'Invalid Zabbix credentials (API token rejected or user.login failed).');
    logger.error(`Zabbix API unreachable at ${client.url}: ${errMsg(err)}`, { deviceId, context: { host } });
    return fail('critical', `Zabbix API unreachable: ${errMsg(err)}`);
  }

  const metrics: Record<string, unknown> = {};
  if (version) metrics['system.version'] = version;

  let health: Health = 'ok';
  let firstError = '';

  // Fan out the inventory reads in parallel — one slow RPC must not block the others.
  const [hostsRes, problemsRes] = await Promise.allSettled([client.getHosts(), client.getProblems(50)]);

  if (hostsRes.status === 'fulfilled') {
    metrics['zabbix.hosts'] = hostsRes.value.map((h) => ({ host: h.name || h.host, status: h.status === '1' ? 'disabled' : 'enabled' }));
  } else {
    firstError = firstError || `host list failed: ${errMsg(hostsRes.reason)}`;
    if (!isAuthError(hostsRes.reason)) health = 'warning';
  }

  if (problemsRes.status === 'fulfilled') {
    metrics['zabbix.problems'] = problemsRes.value.map((p) => ({ object: p.object, name: p.name, severity: String(p.severity) }));
  } else {
    firstError = firstError || `problem list failed: ${errMsg(problemsRes.reason)}`;
    if (!isAuthError(problemsRes.reason)) health = 'warning';
  }

  if (firstError && !('system.error' in metrics)) metrics['system.error'] = firstError;

  res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health, metrics, metricDescriptors: METRIC_DESCRIPTORS });
}

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one Zabbix server. The API's
// config-job worker dispatches here with {actionId, input, credentials}; the
// plugin owns ALL logic (schema validation + RPC calls). Same contract as the
// other plugins: 200 + { success, result } on every path.
// ---------------------------------------------------------------------------

app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const host = hostOf(body.managementAddress);

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
  if (!host) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  const { creds, error: credError } = resolveCredentials(body.credentials as Record<string, unknown> | undefined);
  if (!creds) {
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
    const client = buildClient(host, settings, creds, action.timeoutMs ?? clampInt(settings['timeoutMs'], 2000, 60000, 15000));
    const ctx: ZabbixActionContext = { client, settings };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${host}: ${errMsg(err)}`, { deviceId, context: { host, actionId } });
    // Transport-level failures (server down / not ready yet) are transient — the plan
    // executor re-dispatches them per the plan's retry policy. A ZabbixApiError means
    // the API answered (bad token, duplicate host, missing template, …) — hard failure.
    const retryable = !(err instanceof ZabbixApiError) && isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: errMsg(err), ...(retryable ? { retryable: true } : {}) } });
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
    const plan = await buildPlan(planReq);
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
  console.error('[zabbix-plugin] fatal startup error:', err);
  process.exit(1);
});
