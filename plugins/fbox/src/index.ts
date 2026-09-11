/**
 * FBox Plugin — monitoring + inventory for AVM FRITZ!Box-class routers.
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
  CertificateRow,
} from '@unm/plugin-sdk';
import { FBoxAuthError, FBoxCredentials, FBoxNotFritzError, FBoxTransport } from './fboxClient';
import { DEFAULT_OPTIONS, FBoxOptions, buildDescriptors, buildMetrics, getMonitoring } from './monitoring';
import { DEVICE_MODELS } from './deviceModels';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000008';
export const PLUGIN_NAME = 'FBox Plugin';

const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['avm'],
  capabilities: ['monitoring', 'inventory'],
});

const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|http|https)$',
    description:
      "How to reach the box's web UI. 'auto' (default) tries https first — FRITZ!Boxes serve self-signed TLS by default — and falls back to plain http only on network-level failures.",
  },
  {
    key: 'requestTimeoutMs',
    label: 'Per-request timeout (ms)',
    type: 'integer' as const,
    default: DEFAULT_OPTIONS.requestTimeoutMs,
    min: 500,
    max: 9_000,
    description: "Timeout for a single web-UI request. Kept well under the API's 10 s poll budget (login + one parallel batch).",
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
    iconUrl: '/icons/fbox.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

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

function resolveOptions(settings: Record<string, unknown>): FBoxOptions & { transport: FBoxTransport } {
  const t = typeof settings.transport === 'string' ? settings.transport : 'auto';
  return {
    transport: (t === 'http' || t === 'https' ? t : 'auto') as FBoxTransport,
    requestTimeoutMs: clampInt(settings.requestTimeoutMs, 500, 9_000, DEFAULT_OPTIONS.requestTimeoutMs),
  };
}

/** Extracts username/password credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: FBoxCredentials; error?: string } {
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  let username = typeof credentials.username === 'string' ? credentials.username : '';
  const password = typeof credentials.password === 'string' ? credentials.password : '';
  // FRITZ!Boxes without a configured user list authenticate PASSWORD-ONLY — the
  // secret stores "none" (or empty) as a placeholder for "no username", and the
  // login request must carry an EMPTY username in that case.
  if (username.trim().toLowerCase() === 'none') username = '';
  return { creds: { username, password } };
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
    // BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, opts.transport);

    const result = await getMonitoring(managementAddress.trim(), creds, opts);
    const s = result.snapshot;

    // Health mapping: unreachable/bad creds → critical (raised above), partial
    // endpoint failures or a box that reports no identity at all → warning.
    let health: Health = 'ok';
    if (!s.system && !s.overview) {
      return fail('unknown', 'Box is reachable but reported no system data — check the transport option.');
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
        // FRITZ!Boxes default to an HTTPS management UI — probe TLS on 443
        // (no row is contributed when the box is HTTP-only) plus SSH host key.
        const target = parseProbeTarget(managementAddress, 443);
        certRows =
          target && opts.transport !== 'http'
            ? await collectDeviceCertificates({
                host: target.host,
                httpsPort: target.port,
                servername: target.host,
                sshEnabled: true,
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
      activeSettings: { transport: opts.transport, requestTimeoutMs: opts.requestTimeoutMs, model: selectedModel, firmwareVersion: selectedFirmware },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    if (err instanceof FBoxAuthError) {
      logger.error(`FBox authentication failed for ${managementAddress}: ${message}`, { deviceId, context: { host: managementAddress } });
      return fail('critical', message);
    }
    // "Not a FRITZ!OS device" means the plugin is assigned to the wrong device
    // type — 'unknown' rather than 'critical' (mirrors LANCOM/SwOS semantics).
    if (err instanceof FBoxNotFritzError || /does not look like an AVM router/i.test(message)) {
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
