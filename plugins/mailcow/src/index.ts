/**
 * UnifiedNetworkManager plugin for mailcow-dockerized — manages domains,
 * mailboxes and aliases through the mailcow REST API (the same endpoints the
 * web UI uses). Capabilities: monitoring (health + version), inventory
 * (domains/mailboxes/aliases rows into UNM's Mail page) and configuration
 * (CRUD actions served to the plans system).
 *
 * Everything boring — identity/multi-instance resolution, the express app with
 * /healthz + /discover, mDNS advertising, settings-header parsing, input
 * validation and plan finalization — comes from @unm/plugin-sdk. This file only
 * declares WHAT the plugin is and registers its own routes:
 *   - POST /monitoring  → health (API reachability/auth) + version + inventory rows
 *   - POST /config      → run one catalog action step (CRUD)
 *   - POST /plan        → fan a single-device intent out to per-device steps
 */

import path from 'path';
import { Request, Response } from 'express';
import type { AxiosInstance } from 'axios';
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
import { MAILCOW_DEVICE_SUPPORT } from './deviceSupport';
import { MailcowActionContext } from './actions';
import { registry as actionRegistry } from './actions';
import { collectSecurityChecks } from './security';
import { buildPlan, PlanningError } from './plan';
import {
  MailcowApiError,
  MailcowCredentials,
  MailcowPorts,
  MailcowTransport,
  createClient,
  getAliases,
  getDomains,
  getMailboxes,
  getStatusVersion,
  isAuthError,
} from './client/mailcowClient';

// --- Identity -----------------------------------------------------------------
const identity = resolvePluginIdentity({
  uuid: '00000000-0000-4000-8000-00000000000f', // mailcow plugin — stable primary key in the API
  name: 'Mailcow Plugin',
  description:
    'mailcow-dockerized management — domains, mailboxes and aliases via the REST API, with DKIM/fail2ban security checks.',
  version: '0.1.0',
  vendors: ['mailcow'],
  // securityChecks: fail2ban (rate limiting) + per-domain DKIM over the REST API.
  capabilities: ['monitoring', 'inventory', 'configuration', 'planning', 'securityChecks'],
});

// --- Options --------------------------------------------------------------------
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'http', 'https'],
    description: 'How to reach the mailcow API. auto prefers HTTPS (accepting self-signed certs) and falls back to HTTP.',
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description: 'Management HTTPS port when the address has no explicit port.',
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: 'Management HTTP port when the address has no explicit port.',
  },
  {
    key: 'timeoutMs',
    label: 'Request timeout (ms)',
    type: 'integer' as const,
    default: 15000,
    min: 2000,
    max: 60000,
    description: 'Per-request timeout for mailcow API calls.',
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description: 'Ship structured log entries (poll/action failures) to the UNM API for the device Logs view.',
  },
  {
    key: 'securityChecksEnabled',
    label: 'Security checks',
    type: 'boolean' as const,
    default: true,
    description:
      'Run per-instance security checks (fail2ban brute-force protection state and per-domain DKIM key presence/strength). Findings appear in the cross-device Security page.',
  },
];

// --- Metric descriptors -----------------------------------------------------------
// The three inventory tables are THE data of this plugin — declared statically so
// the webapp renders them even before the first poll, and re-emitted every poll.
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  { key: 'system.version', label: 'Version', type: 'string', visualization: 'text', group: 'System' },
  {
    key: 'mailDomains',
    label: 'Mail Domains',
    type: 'string',
    visualization: 'table',
    columns: ['domain', 'active', 'description', 'quotaBytes', 'mailboxCount', 'aliasCount'],
    group: 'Mail',
  },
  {
    key: 'mailMailboxes',
    label: 'Mailboxes',
    type: 'string',
    visualization: 'table',
    columns: ['username', 'domain', 'name', 'active', 'quotaBytes', 'quotaUsedBytes', 'messageCount'],
    group: 'Mail',
  },
  {
    key: 'mailAliases',
    label: 'Aliases',
    type: 'string',
    visualization: 'table',
    columns: ['address', 'domain', 'goto', 'active', 'isCatchAll', 'isMailboxBound', 'senderAllowed'],
    group: 'Mail',
  },
];

// --- Pre-wired server ---------------------------------------------------------------
const server = createPluginServer({
  identity,
  logTag: 'mailcow-plugin',
  jsonLimit: '1mb',
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Generic single-field bearer-key secret type — see secrets-provider.
    requiredSecretType: 'apiKeyNoSecret',
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    actions: actionRegistry.listCatalog(),
    modules: actionRegistry.listModules(),
    iconUrl: '/icons/mailcow.svg',
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: MAILCOW_DEVICE_SUPPORT,
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

/** Resolves effective transport + ports from injected settings. */
function endpointsOf(settings: Record<string, unknown>): { transport: MailcowTransport; ports: MailcowPorts } {
  const t = typeof settings['transport'] === 'string' ? (settings['transport'] as MailcowTransport) : 'auto';
  return {
    transport: t,
    ports: {
      httpsPort: clampInt(settings['httpsPort'], 1, 65535, 443),
      httpPort: clampInt(settings['httpPort'], 1, 65535, 80),
    },
  };
}

/** Resolves the mailcow API key from the request's credentials body. */
function resolveKey(credentials: Record<string, unknown> | undefined): { key?: string; error?: string } {
  if (!credentials || typeof credentials !== 'object') return { error: 'Missing credentials' };
  const k = credentials['apiKey'];
  if (typeof k === 'string' && k.length > 0) return { key: k };
  // Also accept a bound slot named apiKey under slots.
  const slots = credentials['slots'] as Record<string, unknown> | undefined;
  const slotKey = slots ? (slots['apiKey'] as Record<string, unknown> | undefined)?.['apiKey'] : undefined;
  if (typeof slotKey === 'string' && slotKey.length > 0) return { key: slotKey };
  return { error: 'Missing mailcow API key — bind an "API Key (without secret)" secret to this device.' };
}

/** Builds a bound axios client for one host with the resolved key. */
function buildClient(host: string, settings: Record<string, unknown>, key: string): AxiosInstance {
  const { transport, ports } = endpointsOf(settings);
  return createClient(host, { apiKey: key } satisfies MailcowCredentials, transport, ports);
}

/** Human-readable message from an unknown rejection reason. */
function errMsg(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}

// --- Row normalization ---------------------------------------------------------------
// mailcow returns raw row objects with a mix of "0"/"1" strings and numbers. We
// normalize to the UNM Mail-page contract: booleans as real booleans, quotas in
// bytes (numbers), counts as numbers. Absent fields become undefined (omitted).

function normBool(v: unknown): boolean {
  if (typeof v === 'boolean') return v;
  if (typeof v === 'number') return v !== 0;
  if (typeof v === 'string') return v === '1' || v.toLowerCase() === 'true';
  return false;
}

function normNum(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function normStr(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** Normalizes one raw mailcow domain row into the UNM Mail-domain contract. */
function normalizeDomain(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const domain = normStr(r['domain_name']) ?? normStr(r['domain']);
  if (domain) out['domain'] = domain;
  out['active'] = normBool(r['active']);
  const desc = normStr(r['description']);
  if (desc) out['description'] = desc;
  const quota = normNum(r['quota']) ?? normNum(r['max_quota_for_domain']);
  if (quota !== undefined) out['quotaBytes'] = quota;
  const maxMboxQuota = normNum(r['max_quota_for_mbox']);
  if (maxMboxQuota !== undefined) out['maxQuotaPerMailboxBytes'] = maxMboxQuota;
  const defMboxQuota = normNum(r['def_quota_for_mbox']) ?? normNum(r['def_new_mailbox_quota']);
  if (defMboxQuota !== undefined) out['defaultQuotaBytes'] = defMboxQuota;
  const mboxes = normNum(r['mboxes_in_domain']);
  if (mboxes !== undefined) out['mailboxCount'] = mboxes;
  const aliases = normNum(r['aliases_in_domain']);
  if (aliases !== undefined) out['aliasCount'] = aliases;
  out['backupMx'] = normBool(r['backupmx']);
  return out;
}

/** Normalizes one raw mailcow mailbox row into the UNM Mail-mailbox contract. */
function normalizeMailbox(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const username = normStr(r['username']);
  if (username) out['username'] = username;
  const domain = normStr(r['domain']);
  if (domain) out['domain'] = domain;
  const localPart = normStr(r['local_part']);
  if (localPart) out['localPart'] = localPart;
  const name = normStr(r['name']);
  if (name) out['name'] = name;
  out['active'] = normBool(r['active']);
  const quota = normNum(r['quota']) ?? normNum(r['max_new_quota']);
  if (quota !== undefined) out['quotaBytes'] = quota;
  const used = normNum(r['quota_used']);
  if (used !== undefined) out['quotaUsedBytes'] = used;
  const msgs = normNum(r['messages']);
  if (msgs !== undefined) out['messageCount'] = msgs;
  // attributes sub-object carries the per-mailbox flags.
  const attrs = (r['attributes'] ?? {}) as Record<string, unknown>;
  out['forcePwUpdate'] = normBool(attrs['force_pw_update']);
  out['forceTfa'] = normBool(attrs['force_tfa']);
  out['sogoAccess'] = normBool(attrs['sogo_access']);
  return out;
}

/** Normalizes one raw mailcow alias row into the UNM Mail-alias contract. */
function normalizeAlias(r: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  const id = normNum(r['id']);
  if (id !== undefined) out['mailcowId'] = id; // needed for edit/delete by numeric id
  const address = normStr(r['address']);
  if (address) out['address'] = address;
  const domain = normStr(r['domain']);
  if (domain) out['domain'] = domain;
  const goto = normStr(r['goto']);
  if (goto) out['goto'] = goto;
  out['active'] = normBool(r['active']);
  out['isCatchAll'] = normBool(r['is_catch_all']) || String(r['address'] ?? '').startsWith('@');
  // Mailbox-bound ("internal") aliases attach the address to a specific mailbox —
  // mailcow's per-mailbox "Aliases" tab. `sender_allowed` controls whether that
  // mailbox may send as the alias (false = receive-only).
  out['isMailboxBound'] = normBool(r['internal']);
  out['senderAllowed'] = normBool(r['sender_allowed']);
  return out;
}

// ---------------------------------------------------------------------------
// POST /monitoring — the telemetry worker polls every ~30 s (10 s budget).
// Health comes from API reachability + auth (401 → critical with a clear
// message). On inventory-due polls we also fetch domains/mailboxes/aliases and
// emit them as metric arrays. Absent key = no wipe; present-but-empty = the
// authoritative "there are none" signal, so we always emit all three keys on an
// inventory poll (even empty) to keep UNM's tables in sync with reality.
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
  // Window-based scheduling: the API sends collectInventory=false on metrics-only polls.
  const collectInventory = body.collectInventory !== false;

  if (!host) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': 'Missing managementAddress' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const { key, error: credError } = resolveKey(body.credentials as Record<string, unknown> | undefined);
  if (!key) {
    res.status(200).json({ deviceId: deviceId ?? null, collectedAt: new Date().toISOString(), health: 'critical', metrics: { 'system.error': credError ?? 'Missing credentials' }, metricDescriptors: [errorDescriptor()] });
    return;
  }

  const client = buildClient(host, settings, key);
  // Apply the per-request timeout to this client instance.
  (client as unknown as { defaults: { timeout: number } }).defaults.timeout = timeoutMs;

  const metrics: Record<string, unknown> = {};
  let health: Health = 'ok';
  let firstError = '';

  try {
    // Version doubles as the liveness + auth probe (cheap GET). A 401 here means
    // bad key or IP-not-whitelisted — surface it clearly. NOTE: some mailcow
    // releases answer an INVALID key with HTTP 200 + EMPTY body instead of 401,
    // so a missing version on a reachable host is treated as the same auth
    // failure (verified live against MAIL04).
    const version = await getStatusVersion(client);
    if (!version) {
      res.status(200).json({
        deviceId: deviceId ?? null,
        collectedAt: new Date().toISOString(),
        health: 'critical',
        metrics: { 'system.error': 'Invalid mailcow API key or this host is not on the instance API whitelist (API answered without data).' },
        metricDescriptors: [errorDescriptor()],
      });
      return;
    }
    metrics['system.version'] = version;

    if (collectInventory) {
      // Fan out the three inventory reads in parallel — one slow list shouldn't
      // block the others, and a failure of any single list is non-fatal to health.
      const [domainsRes, mailboxesRes, aliasesRes] = await Promise.allSettled([getDomains(client), getMailboxes(client), getAliases(client)]);

      if (domainsRes.status === 'fulfilled') {
        metrics['mailDomains'] = domainsRes.value.map(normalizeDomain);
      } else {
        firstError = firstError || `domain list failed: ${errMsg(domainsRes.reason)}`;
        // Emit empty so a transient failure doesn't wipe existing rows? No — by
        // contract a collection FAILURE must not emit an authoritative-empty. We
        // omit the key (no wipe) and flag health below.
        if (!isAuthError(domainsRes.reason)) health = 'warning';
      }

      if (mailboxesRes.status === 'fulfilled') {
        metrics['mailMailboxes'] = mailboxesRes.value.map(normalizeMailbox);
      } else {
        firstError = firstError || `mailbox list failed: ${errMsg(mailboxesRes.reason)}`;
        if (!isAuthError(mailboxesRes.reason)) health = 'warning';
      }

      if (aliasesRes.status === 'fulfilled') {
        metrics['mailAliases'] = aliasesRes.value.map(normalizeAlias);
      } else {
        firstError = firstError || `alias list failed: ${errMsg(aliasesRes.reason)}`;
        if (!isAuthError(aliasesRes.reason)) health = 'warning';
      }

      // Security checks (fail2ban + per-domain DKIM). Throttled internally to a
      // ~15-min cadence; best-effort — a failure omits the key entirely (absent
      // = no wipe, per the ingestion contract).
      if (settings.securityChecksEnabled !== false) {
        try {
          const domainNames = domainsRes.status === 'fulfilled'
            ? domainsRes.value.map((r) => normStr(r['domain_name']) ?? normStr(r['domain'])).filter((d): d is string => !!d)
            : [];
          metrics['securityChecks'] = await collectSecurityChecks(host, client, domainNames);
        } catch {
          /* best-effort — a failed check must never sink the poll */
        }
      }
    }
  } catch (err) {
    // A version/auth failure is the dominant signal.
    if (isAuthError(err)) {
      res.status(200).json({
        deviceId: deviceId ?? null,
        collectedAt: new Date().toISOString(),
        health: 'critical',
        metrics: { 'system.error': 'Invalid mailcow API key or this host is not on the instance API whitelist (HTTP 401).' },
        metricDescriptors: [errorDescriptor()],
      });
      return;
    }
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: { 'system.error': `Monitoring failed: ${errMsg(err)}` },
      metricDescriptors: [errorDescriptor()],
    });
    return;
  }

  if (firstError && !('system.error' in metrics)) metrics['system.error'] = firstError;

  res.status(200).json({
    deviceId: deviceId ?? null,
    collectedAt: new Date().toISOString(),
    health,
    metrics,
    metricDescriptors: METRIC_DESCRIPTORS,
  });
}

// ---------------------------------------------------------------------------
// POST /config — executes ONE action step against one mail server. The API's
// config-job worker dispatches here with {actionId, input, credentials}; the
// plugin owns ALL logic (schema validation + REST call). Same contract as the
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
  const timeoutMs = clampInt(settings['timeoutMs'], 2000, 60000, 15000);

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

  const { key, error: credError } = resolveKey(body.credentials as Record<string, unknown> | undefined);
  if (!key) {
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
    const client = buildClient(host, settings, key);
    (client as unknown as { defaults: { timeout: number } }).defaults.timeout = action.timeoutMs ?? timeoutMs;
    const ctx: MailcowActionContext = { client };
    const result = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${host}: ${errMsg(err)}`, { deviceId, context: { host, actionId } });
    // Transport-level failures (instance down / not ready yet) are transient —
    // the plan executor re-dispatches them per the plan's retry policy. A
    // MailcowApiError means the API answered (bad key, duplicate object, …) —
    // that stays a hard failure.
    const retryable = !(err instanceof MailcowApiError) && isTransientTransportError(err);
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
    const message = errMsg(err);
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: message });
  }
});

// ---------------------------------------------------------------------------
// Startup — bind the port + start mDNS advertising (SDK handles both).
// ---------------------------------------------------------------------------
server.listen().catch((err) => {
  console.error('[mailcow-plugin] fatal startup error:', err);
  process.exit(1);
});
