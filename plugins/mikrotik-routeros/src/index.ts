import path from 'path';
import fs from 'fs';
import {
  Health,
  PluginOptionDescriptor,
  SshCredentials,
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
} from '@unm/plugin-sdk';
import { RouterOsAuthError } from './routerosClient';
import { DEFAULT_OPTIONS, MonitoringResult, RouterOsOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { DEVICE_MODELS } from './deviceModels';

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
  version: '0.1.0',
  vendors: ['mikrotik'],
  // monitoring + inventory over the REST API, plus an interactive SSH console
  // ('sshConsole') — RouterOS exposes a full CLI shell over SSH (port 22).
  capabilities: ['monitoring', 'inventory', 'sshConsole'],
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
    pattern: '^(auto|https|http)$',
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
process.on('SIGTERM', () => termPool.closeAll());
process.on('SIGINT', () => termPool.closeAll());

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

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'mikrotik-routeros-plugin',
  // Interactive SSH console (capability 'sshConsole') — WS upgrades for /console.
  wsUpgrade: consoleUpgrade,
  iconsDir: ICONS_DIR,
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
    iconUrl: '/icons/routeros.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

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
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  const username = typeof credentials.username === 'string' ? credentials.username : '';
  const password = typeof credentials.password === 'string' ? credentials.password : '';
  if (!username) return { error: 'Missing username in the assigned secret.' };
  // An empty password is legitimate on RouterOS (default admin has none).
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
    // Certificates (management HTTPS cert + SSH host key) — emitted when present;
    // an empty array is authoritative for this device+plugin at ingest.
    if (result.certificates.length > 0) {
      metrics['certificates'] = result.certificates;
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

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[mikrotik-routeros-plugin] fatal startup error:', err);
  process.exit(1);
});
