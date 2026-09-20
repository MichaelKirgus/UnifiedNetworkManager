/**
 * FBox Plugin — monitoring + inventory for the supported router class.
 *
 * v0.1.0 scope (phased plan): web-UI session transport, comprehensive system/
 * WAN/LAN/WiFi metrics and inventory propagation (LAN devices → Hosts page,
 * LAN subnet → Networks page, WLAN clients + SSIDs → WiFi page). Follow-up
 * phases add TR-064 control actions and advanced inventory (mesh/routes/VPN).
 */

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
  parseProbeTarget,
  readSettings,
  resolvePluginIdentity,
  createPinningGuard,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  quickActionHandler,
  buildWebUiUrl,
  CertificateRow,
  resolveUserPass,
  type QuickAction,
} from '@unm/plugin-sdk';
import { FBoxAuthError, FBoxCredentials, FBoxUnsupportedTargetError, FBoxTransport } from './fboxClient';
import { DEFAULT_OPTIONS, FBoxApiMode, FBoxOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { FBoxTr064AuthError, getTr064Snapshot } from './tr064';
import { DEVICE_MODELS } from './deviceModels';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000008';
export const PLUGIN_NAME = 'FBox Plugin';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['avm'],
  capabilities: ['monitoring', 'inventory', 'quickActions'],
});

const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'apiMode',
    label: 'Query method',
    type: 'string' as const,
    default: 'webui',
    enumOptions: ['webui', 'tr064'],
    description:
      "How the plugin queries the device. 'webui' (default) uses the management web interface with a session login; 'tr064' uses the TR-064/UPnP SOAP control channel — stateless per request, no login rate-limit penalty, but fewer metrics. Note: TR-064 only answers from the router's own local network (LAN), so boxes managed via their WAN address must stay on 'webui'.",
  },
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'http', 'https'],
    description:
      "How to reach the box's web UI. 'auto' (default) tries https first — these routers serve self-signed TLS by default — and falls back to plain http only on network-level failures.",
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the box's HTTPS web UI. Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the box's plain-HTTP web UI (used when transport is http or auto falls back to it).",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the box's SSH daemon. Used for the host-key inventory probe when the management address carries no explicit port.",
  },
  {
    key: 'tr064Port',
    label: 'TR-064 port',
    type: 'integer' as const,
    default: 49003,
    min: 1,
    max: 65535,
    description: "TCP port of the TR-064/UPnP SOAP control channel (used when Query method is tr064).",
  },
  {
    key: 'requestTimeoutMs',
    label: 'Per-request timeout (ms)',
    type: 'integer' as const,
    default: DEFAULT_OPTIONS.requestTimeoutMs,
    min: 500,
    max: 15_000,
    description:
      "Timeout for a single web-UI request. The data pages run in parallel, so this only bounds slow branches — raise it when polls degrade to 'warning' with per-page timeouts (e.g. boxes reached through extra routing hops). Must stay under the API's 30 s poll budget.",
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

/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the box's management web interface in a new tab",
    iconPath: '/icons/fbox.svg',
    kind: 'url',
    url: {},
  },
];

const server = createPluginServer({
  identity,
  logTag: 'fbox-plugin',
  jsonLimit: '100kb',
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // Credentials come from the existing 'usernamePassword' secret type — the
    // web UI logs in with a username/password pair (SID cookie session).
    requiredSecretType: 'usernamePassword',
    options: PLUGIN_OPTIONS,
    // Quick action for the Devices page "Device Actions" column. The web-UI URL
    // is resolved by THIS plugin (scheme follows the transport option, port =
    // the configured httpsPort option).
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/fbox.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI
// URL. The plugin owns all URL knowledge; no credentials are transmitted.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return { url: buildWebUiUrl(body.managementAddress, { webUiPort: resolveHttpsPort(settings.httpsPort), scheme: typeof settings.transport === 'string' && settings.transport === 'http' ? 'http' : 'https' }, qa.url?.path) };
}, 'fbox-plugin'));

const logger = createPluginLogger(identity);

// --- Certificates (capability: cross-device Certificates page) -----------------
// Certificate rows are probed on a slower cadence than the 30 s poll — they
// change rarely and each probe opens fresh TLS/SSH connections to the box.
const CERT_TTL_MS = 10 * 60_000;
const certCache = new TtlCache<CertificateRow[]>({ isFresh: (v) => Array.isArray(v) });

// Certificate pinning — one process-wide guard for the credential-bearing entry
// point. Strict mode + a known fingerprint MISMATCH throws before any credentials
// are transmitted; unknown endpoints are TOFU-accepted and land in UNM's inventory
// via the `certificates` metric.
const assertPinned = createPinningGuard();

function resolveOptions(
  settings: Record<string, unknown>
): FBoxOptions & { transport: FBoxTransport; apiMode: FBoxApiMode } {
  const t = typeof settings.transport === 'string' ? settings.transport : 'auto';
  return {
    apiMode: typeof settings.apiMode === 'string' && settings.apiMode === 'tr064' ? 'tr064' : 'webui',
    transport: (t === 'http' || t === 'https' ? t : 'auto') as FBoxTransport,
    requestTimeoutMs: clampInt(settings.requestTimeoutMs, 500, 15_000, DEFAULT_OPTIONS.requestTimeoutMs),
    httpsPort: resolveHttpsPort(settings.httpsPort) !== 443 ? resolveHttpsPort(settings.httpsPort) : undefined,
    httpPort: resolveHttpPort(settings.httpPort) !== 80 ? resolveHttpPort(settings.httpPort) : undefined,
    sshPort: resolveSshPort(settings.sshPort) !== 22 ? resolveSshPort(settings.sshPort) : undefined,
    tr064Port: clampInt(settings.tr064Port, 1, 65_535, 49003),
  };
}

/** Extracts the configured endpoint ports from injected settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): { httpsPort?: number; httpPort?: number } {
  const hp = resolveHttpsPort(settings.httpsPort);
  const tp = resolveHttpPort(settings.httpPort);
  return { httpsPort: hp !== 443 ? hp : undefined, httpPort: tp !== 80 ? tp : undefined };
}

/** Extracts username/password credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: FBoxCredentials; error?: string } {
  // Routers without a configured user list authenticate PASSWORD-ONLY — the
  // secret stores "none" (or empty) as a placeholder for "no username", and the
  // login request must carry an EMPTY username in that case. Shared SDK helper:
  // no username required + "none" normalized to ''.
  return resolveUserPass((body.credentials ?? {}) as Record<string, unknown>, { requireUsername: false, treatNoneAsEmpty: true });
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // User-selected hardware model / firmware version (forwarded by the API from
  // the device row). Surfaced as System metrics so the selection is visible.
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
    // Certificate pinning — verify the box's TLS cert against UNM's inventory
    // BEFORE any credentials are transmitted (throws on mismatch). Only relevant
    // for the web-UI method; TR-064 speaks plain HTTP and carries no TLS.
    if (opts.apiMode !== 'tr064') {
      await assertPinned(req, managementAddress, opts.transport, portsOf(settings));
    }

    const result =
      opts.apiMode === 'tr064'
        ? await getTr064Snapshot(managementAddress.trim(), creds, opts)
        : await getMonitoring(managementAddress.trim(), creds, opts);
    const s = result.snapshot;

    // Health mapping: unreachable/bad creds → critical (raised above), partial
    // endpoint failures or a box that reports no identity at all → warning.
    let health: Health = 'ok';
    if (!s.system && !s.overview) {
      return fail('unknown', 'Device is reachable but reported no system data — check the query-method and transport options.');
    }
    if (result.warnings.length > 0 || !s.system) {
      health = 'warning';
      logger.warn(`FBox monitoring degraded for ${managementAddress}: ${[...result.warnings, !s.system ? 'no systeminfo64.json' : ''].filter(Boolean).join('; ')}`, {
        deviceId,
        context: { host: managementAddress },
      });
    }

    const metrics = buildMetrics(s, selectedModel, selectedFirmware);
    if (health !== 'ok') metrics['system.error'] = result.warnings.join('; ');

    // --- Certificates (normalized for the cross-device Certificates page) ----
    // Management HTTPS cert + SSH host key on port 22. Both probes are
    // credential-free and best-effort; a failure simply contributes no row.
    {
      const cachedCerts = certCache.get(managementAddress, CERT_TTL_MS) ?? null;
      let certRows: CertificateRow[] | null = cachedCerts;
      if (!certRows) {
        // These routers default to an HTTPS management UI — probe TLS on the
        // configured port (default 443; no row when the box is HTTP-only) plus SSH.
        const p = portsOf(settings);
        const target = parseProbeTarget(managementAddress, p.httpsPort ?? 443);
        certRows =
          target && opts.transport !== 'http'
            ? await collectDeviceCertificates({
                host: target.host,
                httpsPort: target.port,
                servername: target.host,
                sshEnabled: true,
                sshPort: resolveSshPort(settings.sshPort),
                timeoutMs: 5_000,
              })
            : [];
        certCache.set(managementAddress, certRows);
      }
      if (certRows.length > 0) metrics['certificates'] = certRows;
    }

    let descriptors = buildDescriptors(s, selectedModel, selectedFirmware);
    if (health !== 'ok') descriptors = [...descriptors, errorDescriptor()];

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      metricDescriptors: descriptors,
      activeSettings: { apiMode: opts.apiMode, transport: opts.transport, requestTimeoutMs: opts.requestTimeoutMs, model: selectedModel, firmwareVersion: selectedFirmware },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof FBoxAuthError || err instanceof FBoxTr064AuthError) {
      logger.error(`FBox authentication failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('critical', message);
    }
    // "Unsupported target" means the plugin is assigned to the wrong device
    // type — 'unknown' rather than 'critical' (mirrors LANCOM/SwOS semantics).
    if (err instanceof FBoxUnsupportedTargetError || /does not look like a supported router/i.test(message)) {
      return fail('unknown', message);
    }
    logger.error(`FBox monitoring poll for ${managementAddress} failed: ${message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${message}`);
  }
});

server.listen().catch((err) => {
  console.error('[fbox-plugin] fatal startup error:', err);
  process.exit(1);
});
