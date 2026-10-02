import path from 'path';
import fs from 'fs';
import {
  Health,
  PluginOptionDescriptor,
  SshCredentials,
  createSftpPool,
  createSshPool,
  clampInt,
  createPluginLogger,
  createPluginServer,
  createTerminalPool,
  errorDescriptor,
  hostFromAddress,
  makeConsoleUpgrade,
  modelFirmwareDescriptors,
  pickString,
  readSettings,
  resolvePluginIdentity,
  createPinningGuard,
  dynamicSshHostVerifier,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  resolveUserPass,
  quickActionHandler,
  buildWebUiUrl,
  catalogFirmwareRow,
  isTransientTransportError,
  DETECTED_FEATURES_METRIC_KEY,
  type QuickAction,
} from '@unm/plugin-sdk';
import { ROUTEROS_DEVICE_SUPPORT } from './deviceSupport';
import { RouterOsAuthError, RouterOsClient } from './routerosClient';
import { getAction, listCatalog, listModules } from './actions/registry';
import { ActionContext, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest } from './plan';
import { PREFLIGHT_RESOLVERS } from './actions/preflight';
import { DEFAULT_OPTIONS, MonitoringResult, RouterOsOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { collectSecurityChecks, type SecuritySettings } from './security';
import { DEVICE_MODELS } from './deviceModels';

/** Every firmware line known across the RouterOS catalog — the Updates page
 * compares a device's live version against this set (always in sync with
 * /discover). */
const KNOWN_ROS_LINES = Array.from(new Set(DEVICE_MODELS.flatMap((m) => m.firmwareVersions ?? [])));

export const PLUGIN_UUID = '00000000-0000-4000-8000-00000000000a';
export const PLUGIN_NAME = 'MikroTik RouterOS Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.1.0 — initial release: RouterOS monitoring via the REST API (/rest) —
  // system resources (CPU/memory/uptime), interfaces + throughput rates, IP
  // addresses, ARP, DHCP leases, routes, wireless clients — with network/host/
  // route inventory propagation. Configuration + planning capabilities are
  // planned for a later release (the action-catalog/planner file layout is the
  // same as mikrotik-swos).
  // 0.2.0 — Updates page support (capability 'updates'): firmware `updates[]`
  // row from the live RouterOS version vs the static release catalog
  // (available-without-apply — RouterOS OS updates go through the web UI /
  // package server, there is no safe programmatic update API).
  // 0.3.0 — Configuration + planning: canonical fleet intents over the REST
  // API (`l2.topology.read`, `network.create`, `network.delete`) with a
  // /preflight resolver for per-device attach-point suggestions.
  // 0.4.0 — Feature-complete configuration surface (verified live on RouterOS
  // 7.21 LTS): System (info/status/identity/users/services/reboot/halt/
  // scripts/scheduler/logging), Network (interfaces/VLANs/routes/gateways/DHCP
  // server stack + static leases/DNS servers + hosts), Firewall (filter/NAT
  // rule CRUD+toggle, address lists), VPN (WireGuard server/peer CRUD with
  // auto key generation, IPsec inventory), config backup/restore over SSH+SFTP
  // into UNM's file repository, and firmware check/update via the package
  // manager. All writes apply immediately and are verified by re-read.
  version: '0.4.0',
  vendors: ['mikrotik'],
  // monitoring + inventory over the REST API, plus an interactive SSH console
  // ('sshConsole') — RouterOS exposes a full CLI shell over SSH (port 22).
  // securityChecks: per-appliance security checks over the REST API (service
  // exposure of telnet/ftp/www, failed logins from /log/print) → Security page.
  // configuration + planning (0.3.0): canonical fleet intents over the REST
  // API — l2.topology.read / network.create / network.delete with preflight.
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'sshConsole', 'updates', 'quickActions', 'securityChecks'],
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
      'How long a collected router snapshot stays fresh. The API polls every 30 s with a hard 10 s budget, so the full state (system + interfaces + addresses + ARP + DHCP leases + routes) is cached and only re-collected when stale.',
  },
  {
    key: 'requestTimeoutMs',
    label: 'Per-request timeout (ms)',
    type: 'integer' as const,
    default: DEFAULT_OPTIONS.requestTimeoutMs,
    min: 500,
    max: 9_000,
    description: "Timeout for a single REST fetch. Kept well under the API's 10 s poll budget (in auto scheme mode a fallback attempt may cost up to twice this).",
  },
  {
    key: 'schemeMode',
    label: 'Transport scheme',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'https', 'http'],
    description:
      "How the plugin reaches the router's REST API. auto = try HTTPS first and fall back to HTTP when TLS fails (default); https/http force a single scheme. An explicit http:// or https:// prefix in the device management address always wins.",
  },
  {
    key: 'insecureTls',
    label: 'Accept self-signed TLS certificates',
    type: 'boolean' as const,
    default: false,
    description:
      "RouterOS boxes almost always present a SELF-SIGNED certificate for www-ssl. Enable this (or import the box's CA into the trusted roots) or every HTTPS poll fails with a certificate error.",
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the router's HTTPS REST API (www-ssl). Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the router's plain-HTTP REST API (www) — used when schemeMode is http or auto falls back to it.",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the router's SSH daemon. Used for the interactive web console and host-key pinning when the management address carries no explicit port.",
  },
  {
    key: 'securityChecksEnabled',
    label: 'Security checks',
    type: 'boolean' as const,
    default: true,
    description:
      'Run per-appliance security checks (management service exposure — telnet/ftp/www bound to non-loopback interfaces — and failed logins from the router log). Findings appear in the cross-device Security page.',
  },
  {
    key: 'securityAuthFailureWindowHours',
    label: 'Failed-login window (hours)',
    type: 'integer' as const,
    default: 24,
    min: 1,
    max: 720,
    description: 'Look-back window for counting failed login attempts from the router log.',
  },
  {
    key: 'securityAuthFailureWarnThreshold',
    label: 'Failed-login warning threshold',
    type: 'integer' as const,
    default: 10,
    min: 1,
    description: '≥ this many failed logins in the window raises a warning (below = info).',
  },
  {
    key: 'securityAuthFailureCriticalThreshold',
    label: 'Failed-login critical threshold',
    type: 'integer' as const,
    default: 50,
    min: 2,
    description: '≥ this many failed logins in the window raises a critical finding (likely brute force).',
  },
];

// Static icon assets (plugin + per-model icons), advertised in /discover and
// fetched by the API's icon proxy. The layout differs between dev (src/) and
// built (dist/src/) runs — resolve whichever contains the icons dir.
const ICONS_DIR = [path.join(__dirname, '../icons'), path.join(__dirname, '../../icons')].find((p) => fs.existsSync(p)) ?? path.join(__dirname, '../../icons');

// --- Interactive SSH console (capability 'sshConsole') -------------------------
// RouterOS exposes a full interactive CLI over SSH (port 22). The webapp's
// DeviceDetail page renders a generic "Shell" button for any plugin advertising
// 'sshConsole'; the API proxies the browser's xterm.js to our /console WebSocket,
// which opens a PTY. Unlike LCOS/LX, RouterOS uses ONE credential set for both the
// REST API and the SSH console — so the primary username/password secret doubles as
// the SSH login (no extra binding needed). An optional `ssh` slot can override it
// with a dedicated user or an ed25519/rsa key. A local resolver is used instead of
// the SDK's because RouterOS default admin often has an EMPTY password, which the
// SDK's username+password check would reject.
function resolveRouterOsSsh(creds?: Record<string, unknown> | null): SshCredentials | undefined {
  if (!creds || typeof creds !== 'object') return undefined;
  const slots = (creds['slots'] ?? {}) as Record<string, Record<string, string>>;
  // A bound ssh slot wins — it may carry a key or a dedicated user.
  const slot = slots['ssh'];
  if (slot && typeof slot === 'object') {
    const privateKey = pickString(slot, ['privateKey']);
    if (privateKey) {
      return { username: pickString(slot, ['username']) ?? 'admin', privateKey, ...(pickString(slot, ['passphrase']) ? { passphrase: pickString(slot, ['passphrase']) } : {}) };
    }
    const slotUser = pickString(slot, ['username']);
    if (slotUser) return { username: slotUser, password: pickString(slot, ['password']) ?? '' };
  }
  // Fallback: the primary username/password secret IS the SSH login. An empty
  // password is legitimate on RouterOS (default admin has none).
  const username = pickString(creds, ['username']);
  if (!username) return undefined;
  return { username, password: pickString(creds, ['password']) ?? '' };
}

// Certificate pinning — one process-wide guard for every credential-bearing
// entry point. Strict mode + a known fingerprint MISMATCH throws before any
// credentials are transmitted; unknown endpoints are TOFU-accepted and land in
// UNM's inventory via the `certificates` metric.
const assertPinned = createPinningGuard();

const termPool = createTerminalPool();
// Pooled SSH/SFTP transports for the config backup/restore actions (0.4.0) —
// keyed by host|port|username, closed on shutdown like the terminal pool.
const sshPool = createSshPool();
const sftpPool = createSftpPool();
process.on('SIGTERM', () => {
  termPool.closeAll();
  sshPool.closeAll();
  sftpPool.closeAll();
});
process.on('SIGINT', () => {
  termPool.closeAll();
  sshPool.closeAll();
  sftpPool.closeAll();
});

const consoleUpgrade = makeConsoleUpgrade({
  expectedApiKey: () => process.env.PLUGIN_API_KEY ?? null,
  path: '/console',
  onOpen: async (hello) => {
    const host = hostFromAddress(hello.managementAddress);
    if (!host) throw new Error('Missing management address');
    const creds = resolveRouterOsSsh(hello.credentials as Record<string, unknown> | undefined);
    if (!creds) {
      throw new Error('No usable SSH credential — the primary username/password secret (or a bound "ssh" slot) is required.');
    }
    // Configured SSH port (plugin option `sshPort`, default 22) — delivered by
    // the API in the console hello frame so a per-device override is honored.
    const sshPort = resolveSshPort(hello.settings?.['sshPort']);
    const conn = await termPool.get(host, sshPort, creds, {
      // UNM certificate pinning — resolves the freshest trusted fingerprint at
      // handshake time (pooled sessions outlive single requests). A mismatch
      // rejects the handshake BEFORE any auth message is sent.
      hostKeyVerifier: dynamicSshHostVerifier(host, sshPort),
      onHostKey: (fp) => console.warn(`[mikrotik-routeros-plugin] observed host key for ${host}:${sshPort} → ${fp} (pin it in the device's SSH settings to enforce strict verification)`),
    });
    return conn.openShell(creds); // a plain RouterOS login shell, like PuTTY
  },
});

/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the router's management web interface in a new tab",
    iconPath: '/icons/routeros.svg',
    kind: 'url',
    url: {},
  },
  {
    id: 'shell',
    label: 'Shell',
    description: 'Interactive RouterOS CLI shell over SSH (uses the bound or primary credential)',
    iconPath: '/icons/routeros.svg',
    kind: 'shell',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'mikrotik-routeros-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  iconsDir: ICONS_DIR,
  // Static doc/license assets served at /assets/* — the built-in documentation
  // (docs/README.md) and LICENSE.md referenced from discovery.deviceSupport.
  // Fetched by the API's asset proxy.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // Credentials come from the existing 'usernamePassword' secret type — RouterOS
    // REST uses HTTP Basic authentication with a console username/password pair.
    requiredSecretType: 'usernamePassword',
    // Optional dedicated SSH credential. When unbound, the primary username/password
    // secret is reused for the interactive shell (RouterOS shares one login across
    // REST + SSH). Bind here to use a separate user or an ed25519/rsa key.
    credentialSlots: [
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          "Optional dedicated SSH access (port 22) for the interactive web console. Leave unbound to reuse the primary username/password login; bind a usernamePassword or sshKeyPair secret here to use a separate user or key.",
      },
    ],
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions + multi-device intents) —
    // advertised so the API persists it and validates plan inputs against the
    // inputSchema (previously this plugin never sent `actions`, leaving its
    // stored catalog empty).
    actions: listCatalog(),
    modules: listModules(),
    // Quick actions for the Devices page "Device Actions" column. The web-UI URL
    // is resolved by THIS plugin (scheme follows schemeMode, port = httpsPort);
    // shell reuses the existing console dialog.
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/routeros.svg',
    deviceModels: DEVICE_MODELS,
    // Device support metadata — license/help/docs + the supported-device matrix
    // (wifi gated on detected radios, ssh console always effective via primary-
    // credential reuse). See ./deviceSupport.ts.
    deviceSupport: ROUTEROS_DEVICE_SUPPORT,
  },
});
const app = server.app;

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI
// URL. The plugin owns all URL knowledge; no credentials are transmitted.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return {
    url: buildWebUiUrl(body.managementAddress, {
      webUiPort: resolveHttpsPort(settings.httpsPort),
      scheme: typeof settings.schemeMode === 'string' && settings.schemeMode === 'http' ? 'http' : 'https',
    }, qa.url?.path),
  };
}, 'mikrotik-routeros-plugin'));

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/** Resolves collection options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): RouterOsOptions {
  const schemeRaw = typeof settings.schemeMode === 'string' ? settings.schemeMode : '';
  return {
    cacheTtlMs: clampInt(settings.cacheTtlSeconds, 10, 600, Math.round(DEFAULT_OPTIONS.cacheTtlMs / 1_000)) * 1_000,
    requestTimeoutMs: clampInt(settings.requestTimeoutMs, 500, 9_000, DEFAULT_OPTIONS.requestTimeoutMs),
    insecureTls: settings.insecureTls === true,
    schemeMode: schemeRaw === 'https' || schemeRaw === 'http' ? schemeRaw : 'auto',
    httpsPort: resolveHttpsPort(settings.httpsPort) !== 443 ? resolveHttpsPort(settings.httpsPort) : undefined,
    httpPort: resolveHttpPort(settings.httpPort) !== 80 ? resolveHttpPort(settings.httpPort) : undefined,
    sshPort: resolveSshPort(settings.sshPort) !== 22 ? resolveSshPort(settings.sshPort) : undefined,
  };
}

/** Extracts the configured endpoint ports from injected settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): { httpsPort?: number; httpPort?: number } {
  const hp = resolveHttpsPort(settings.httpsPort);
  const tp = resolveHttpPort(settings.httpPort);
  return { httpsPort: hp !== 443 ? hp : undefined, httpPort: tp !== 80 ? tp : undefined };
}

/** Extracts username/password credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: { username: string; password: string }; error?: string } {
  // Shared SDK helper — a username IS required here; an empty password is
  // legitimate on RouterOS (default admin has none).
  return resolveUserPass((body.credentials ?? {}) as Record<string, unknown>, { requireUsername: true });
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
    // Certificate pinning — verify the router's TLS cert against UNM's
    // inventory BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, opts.schemeMode, portsOf(settings));

    const result: MonitoringResult = await getMonitoring(managementAddress.trim(), creds, opts);
    const s = result.snapshot;

    // Health mapping: unreachable/bad creds → critical (raised as an exception
    // above), stale snapshot → warning, otherwise ok. A router that answers but
    // reports no interfaces at all is suspicious — warn rather than fail.
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (result.stale) warnings.push(result.error ?? 'stale snapshot');
    if (s.interfaces.length === 0 && !s.identity) warnings.push('no interfaces or identity reported');
    if (warnings.length > 0) {
      health = 'warning';
      logger.warn(`RouterOS monitoring degraded for ${managementAddress}: ${warnings.join('; ')}`, { deviceId, context: { host: managementAddress } });
    }

    const metrics = buildMetrics(s, selectedModel, selectedFirmware);

    // Detected features for the support matrix (see deviceSupport.ts). Derived
    // from the (possibly cached) snapshot on EVERY poll, so the API's
    // latest-snapshot evaluation always sees this key. No metric descriptor on
    // purpose: it is not a display metric. Feature ids: 'wifi' — the box has
    // wireless radios (an interface of type wfi/wireless, or associated clients
    // in the ROS 7 registration table). Wired-only hardware reports none.
    const detectedFeatures = new Set<string>();
    if (s.interfaces.some((i) => i.type === 'wfi' || i.type === 'wireless') || s.wlanClients.length > 0) {
      detectedFeatures.add('wifi');
    }
    metrics[DETECTED_FEATURES_METRIC_KEY] = Array.from(detectedFeatures);

    // Updates page: firmware row from the live RouterOS version (e.g. "7.14")
    // vs the newest known release line — major.minor comparison. Available-
    // without-apply (no safe programmatic OS-update API).
    if (s.version) {
      // Release notes: the official RouterOS changelog lists every version of
      // the target line (e.g. 7.14 → /changelog/7_14).
      const fwRow = catalogFirmwareRow(s.version, KNOWN_ROS_LINES, {
        releaseNotesUrl: (target) => `https://wiki.mikrotik.com/wiki/Changelog/${String(target).replace(/\./g, '_')}`,
      });
      if (fwRow) metrics['updates'] = [fwRow];
    }
    // Certificates (management HTTPS cert + SSH host key) — emitted when present;
    // an empty array is authoritative for this device+plugin at ingest.
    if (result.certificates.length > 0) {
      metrics['certificates'] = result.certificates;
    }

    // Security checks over the REST API (service exposure + failed logins).
    // Throttled internally to a ~15-min cadence per host; failure → omit the key
    // entirely (absent = no wipe, per the ingestion contract).
    try {
      const secSettings: SecuritySettings = {
        enabled: settings.securityChecksEnabled !== false,
        authFailureWindowHours: Number(settings.securityAuthFailureWindowHours ?? 24),
        authFailureWarnThreshold: Number(settings.securityAuthFailureWarnThreshold ?? 10),
        authFailureCriticalThreshold: Number(settings.securityAuthFailureCriticalThreshold ?? 50),
      };
      metrics['securityChecks'] = await collectSecurityChecks(managementAddress.trim(), creds, opts, secSettings);
    } catch {
      /* best-effort — a failed check must never sink the poll */
    }

    if (health !== 'ok') metrics['system.error'] = warnings.join('; ');

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
        schemeMode: opts.schemeMode,
        insecureTls: opts.insecureTls,
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof RouterOsAuthError) {
      logger.error(`RouterOS authentication failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('critical', message);
    }
    // "Not a recognized RouterOS device" means the plugin is assigned to the wrong
    // device type — 'unknown' rather than 'critical' (mirrors LANCOM semantics).
    if (/not a recognized routeros/i.test(message)) {
      logger.warn(`RouterOS probe for ${managementAddress} found no RouterOS device: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('unknown', message);
    }
    logger.error(`RouterOS monitoring failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `RouterOS monitoring failed: ${message}`);
  }
});

/** Builds the ActionContext for a /config or /preflight call (REST client). */
function buildActionContext(args: {
  address: string;
  deviceId?: string;
  deviceName?: string;
  credentials: StepCredentials;
  settings: Record<string, unknown>;
}): ActionContext {
  const opts = resolveOptions(args.settings);
  return {
    client: new RouterOsClient(args.address, {
      username: args.credentials.username,
      password: args.credentials.password,
      timeoutMs: Math.max(opts.requestTimeoutMs, 8_000), // config actions get a generous budget
      insecureTls: opts.insecureTls,
      schemeMode: opts.schemeMode,
      httpsPort: opts.httpsPort,
      httpPort: opts.httpPort,
    }),
    address: args.address,
    host: hostFromAddress(args.address) ?? args.address.replace(/^https?:\/\//i, '').split('/')[0],
    sshPort: resolveSshPort(args.settings.sshPort),
    deviceId: args.deviceId,
    deviceName: args.deviceName,
    credentials: args.credentials,
    sshPool,
    sftpPool,
  };
}

/**
 * Executes ONE action step against one router — the unit of work the API's
 * config-job worker dispatches (registry shape `{actionId, input, credentials}`).
 * The plugin owns ALL logic: it validates the input against the action's schema
 * and runs the executor. The API only propagates — it never interprets payloads.
 */
app.post('/config', async (req, res) => {
  const body = req.body ?? {};
  const { deviceId, managementAddress } = body;
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
  if (typeof managementAddress !== 'string' || !managementAddress) {
    res.status(400).json({ success: false, result: { error: 'Missing managementAddress' } });
    return;
  }

  const action = getAction(actionId);
  if (!action) {
    res.status(400).json({ success: false, result: { error: `Unknown action "${actionId}"` } });
    return;
  }

  // Credentials: the assignment's decrypted username/password fields (the SAME
  // login as monitoring — RouterOS shares one credential set across REST + SSH).
  const credsFields = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const { creds, error } = resolveCredentials({ credentials: credsFields });
  if (error || !creds) {
    res.status(200).json({ success: false, result: { error: error ?? 'Missing username/password credentials.' } });
    return;
  }
  const stepCredentials: StepCredentials = {
    username: creds.username,
    password: creds.password,
    ...credsFields,
  };

  try {
    // Certificate pinning — a config action transmits real credentials; refuse
    // the connection when the router's key differs from UNM's inventory.
    await assertPinned(req, managementAddress, resolveOptions(settings).schemeMode, portsOf(settings));

    const ctx = buildActionContext({
      address: managementAddress,
      deviceId: typeof deviceId === 'string' ? deviceId : undefined,
      deviceName: typeof body.deviceName === 'string' && body.deviceName !== '' ? body.deviceName : undefined,
      credentials: stepCredentials,
      settings,
    });

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
    // Every successful write in this plugin is CONFIRMED by a post-apply re-read
    // of device state (or an idempotent skip against current state) — surface
    // that to the plan executor so plans reach 'succeeded' instead of
    // 'unverified'. The fire-and-forget actions are excluded: they succeed on a
    // command acknowledgement / connection drop and cannot re-read afterwards.
    const NOT_VERIFIABLE = new Set(['system.reboot', 'system.halt', 'firmware.update']);
    if (result.success && action.riskLevel !== 'read' && !NOT_VERIFIABLE.has(action.id)) {
      result.verified = true;
    }
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
    // Transport-level failures (router down / not ready yet) are transient — the
    // plan executor re-dispatches them per the plan's retry policy. HTTP-level
    // outcomes already come back as ok:false results above and stay hard.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

/**
 * Plans a multi-device intent (or fans out a single action across a batch).
 * The plugin does ALL the planning — RouterOS v1 is purely structural fan-out.
 *
 * Body: { intent: { actionId, inputs }, devices: [{ deviceId, managementAddress,
 * credentials }], deviceInputs? }
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
    // Per-device overrides from the rollout wizard's confirmed preflight values.
    deviceInputs: body.deviceInputs && typeof body.deviceInputs === 'object'
      ? (body.deviceInputs as PlanRequest['deviceInputs'])
      : undefined,
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

/**
 * POST /preflight — resolve best-guess per-device values for a canonical fleet
 * intent BEFORE planning (the "smart" half of the rollout wizard). Body:
 * { intentActionId, inputs?, device: { deviceId, managementAddress, credentials } }
 * READ-ONLY by contract: resolvers probe live state (L2 topology batch) and
 * return suggestions; they never write. The webapp shows the values with
 * confidence + notes and lets the user override them before plan creation
 * (overrides ride back in deviceInputs).
 */
app.post('/preflight', async (req, res) => {
  const body = req.body ?? {};
  const intentActionId: string | undefined = typeof body.intentActionId === 'string' ? body.intentActionId : undefined;
  const inputs: Record<string, unknown> =
    body.inputs && typeof body.inputs === 'object' ? (body.inputs as Record<string, unknown>) : {};
  const dev = body.device ?? {};
  const managementAddress: string | undefined = typeof dev.managementAddress === 'string' ? dev.managementAddress : undefined;

  if (!intentActionId || !managementAddress) {
    res.status(400).json({ error: 'intentActionId and device.managementAddress are required' });
    return;
  }
  const resolver = PREFLIGHT_RESOLVERS[intentActionId];
  if (!resolver) {
    res.status(400).json({ error: `No preflight resolver for intent "${intentActionId}"` });
    return;
  }

  // Same credential assembly as /config — the primary username/password fields.
  const credsFields = (dev.credentials && typeof dev.credentials === 'object' ? dev.credentials : {}) as Record<string, unknown>;
  const { creds, error } = resolveCredentials({ credentials: credsFields });
  if (error || !creds) {
    res.status(200).json({ result: { deviceId: String(dev.deviceId ?? ''), values: [], degraded: true, error: error ?? 'Missing username/password credentials.' } });
    return;
  }

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  try {
    const ctx = buildActionContext({
      address: managementAddress,
      deviceId: typeof dev.deviceId === 'string' ? dev.deviceId : undefined,
      credentials: { username: creds.username, password: creds.password, ...credsFields },
      settings,
    });
    const result = await resolver(ctx, inputs);
    res.status(200).json({ result });
  } catch (err) {
    // Preflight is advisory — a probe failure degrades the suggestion, it must
    // never block planning. The UI shows the device as degraded.
    res.status(200).json({ result: { deviceId: String(dev.deviceId ?? ''), values: [], degraded: true, error: (err as Error).message } });
  }
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[mikrotik-routeros-plugin] fatal startup error:', err);
  process.exit(1);
});
