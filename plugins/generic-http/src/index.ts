/**
 * Generic HTTP(S) plugin — main entry point.
 *
 * A credential-free web-service health checker for ANY host that serves HTTP(S):
 *   - Checks whether the configured endpoints (default port 80 and/or 443, both
 *     adjustable in the plugin settings) answer a GET request, and reports the
 *     response time + status code as live metrics.
 *   - On inventory polls it probes the TLS endpoint with a raw handshake and
 *     emits the served certificate (issuer, expiry, key info, chain verdict)
 *     into `metrics['certificates']` — ingested by the API into the cross-device
 *     Certificates page (expiry notifications included).
 *
 * No credentials are needed: both checks are plain TCP/TLS connects. The device's
 * management address is the probe target; an explicit scheme/port in it wins over
 * the configured ports (e.g. "https://example.com:8443" probes exactly that).
 */

import http from 'http';
import https from 'https';
import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  collectDeviceCertificates,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  parseProbeTarget,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import type { CertificateRow } from '@unm/plugin-sdk';

export const PLUGIN_UUID = '00000000-0000-4000-8000-00000000000d';
export const PLUGIN_NAME = 'Generic HTTP(S) Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "Generic HTTP(S) Plugin (site-a)". Unset =
 * single-instance behavior. (Convention implemented in @unm/plugin-sdk's
 * resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['generic'],
  // monitoring: live response-time/status metrics every poll.
  // inventory: TLS certificate probe at the SDK's 15-min interval (Certificates page).
  capabilities: ['monitoring', 'inventory'],
});

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description:
      "TCP port of the plain-HTTP endpoint to check (default 80). Ignored when the management address carries an explicit scheme or port.",
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the HTTPS endpoint to check and probe for its TLS certificate (default 443). Ignored when the management address carries an explicit scheme or port.",
  },
  {
    key: 'path',
    label: 'Request path',
    type: 'string' as const,
    default: '/',
    pattern: '^/[^\\s]*$',
    maxLength: 2048,
    description: "URL path requested on each endpoint (default \"/\"). A leading slash is added automatically when missing.",
  },
  {
    key: 'timeoutMs',
    label: 'Request timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 200,
    max: 9000,
    description: 'How long to wait for each endpoint before counting it unreachable. Capped so a poll stays inside the API\'s ~10 s budget.',
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

/**
 * Metric descriptors (static — this plugin always emits exactly these keys).
 * The webapp renders from these, so no per-plugin UI code is needed.
 */
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  {
    key: 'http.responseTimeMs',
    label: 'Response time',
    unit: 'ms',
    format: 'number',
    type: 'number',
    visualization: 'plot',
    group: 'HTTP',
    color: '#3b82f6',
    summary: true, // headline metric in the device overview table
  },
  {
    key: 'http.status',
    label: 'Status code',
    type: 'number',
    visualization: 'text',
    group: 'HTTP',
  },
  {
    key: 'http.reachable',
    label: 'Web service reachable',
    type: 'boolean',
    visualization: 'text',
    group: 'HTTP',
  },
  {
    key: 'http.detail',
    label: 'Endpoint results',
    type: 'string',
    visualization: 'text',
    group: 'HTTP',
  },
  {
    key: 'tls.supported',
    label: 'TLS supported',
    type: 'boolean',
    visualization: 'text',
    group: 'TLS',
  },
  {
    key: 'tls.daysToExpiry',
    label: 'Certificate days to expiry',
    unit: 'days',
    format: 'number',
    type: 'number',
    visualization: 'text',
    group: 'TLS',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'generic-http-plugin',
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // No credentials needed — plain HTTP(S) probes against the management address.
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    iconUrl: '/icons/generic-http.svg',
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() below.
const logger = createPluginLogger(identity);

// ---------------------------------------------------------------------------
// Probe primitives
// ---------------------------------------------------------------------------

/** One endpoint to probe: scheme + host + port (path comes from settings). */
interface EndpointCheck {
  scheme: 'http' | 'https';
  host: string;
  port: number;
}

/**
 * Resolves the endpoints to probe from a management address + configured ports.
 *   - An explicit `http(s)://` scheme in the address ALWAYS wins — exactly that
 *     endpoint is checked (including any port already in it).
 *   - A bare host[:port] checks BOTH configured ports, HTTPS first (the SDK's
 *     candidate order); an explicit port in a bare address applies to both.
 */
function resolveEndpoints(address: string, s: { httpPort: number; httpsPort: number }): EndpointCheck[] {
  const raw = String(address ?? '').trim().replace(/\/+$/, '');
  if (!raw) return [];

  // Explicit scheme (+ optional port) wins verbatim.
  if (/^https?:\/\//i.test(raw)) {
    const scheme = raw.slice(0, raw.indexOf(':')).toLowerCase() as 'http' | 'https';
    const target = parseProbeTarget(raw, scheme === 'https' ? s.httpsPort : s.httpPort);
    return target ? [{ scheme, host: target.host, port: target.port }] : [];
  }

  // Bare address — split an optional explicit port (IPv6 literals ok).
  let host = raw;
  let explicitPort: number | null = null;
  const v6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) {
    host = v6[1];
    if (v6[2]) explicitPort = Number(v6[2]);
  } else {
    const idx = raw.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
      host = raw.slice(0, idx);
      explicitPort = Number(raw.slice(idx + 1));
    }
  }
  if (!host || !Number.isFinite(explicitPort as number) || (explicitPort as number) < 1 || (explicitPort as number) > 65535) {
    explicitPort = null;
  }

  return [
    { scheme: 'https', host, port: explicitPort ?? s.httpsPort },
    { scheme: 'http', host, port: explicitPort ?? s.httpPort },
  ];
}

/**
 * Issues one GET request and resolves when the response HEADERS arrive — that
 * is the "response time" (the body is never downloaded; a health check only
 * needs status + latency). Resolves null on any network-level failure.
 */
function checkEndpoint(ep: EndpointCheck, urlPath: string, timeoutMs: number): Promise<{ status: number; ms: number } | null> {
  return new Promise((resolve) => {
    const lib = ep.scheme === 'https' ? https : http;
    const startedAt = Date.now();
    let settled = false;
    const finish = (r: { status: number; ms: number } | null) => {
      if (!settled) {
        settled = true;
        resolve(r);
      }
    };

    let req: http.ClientRequest;
    try {
      req = lib.request(
        {
          host: ep.host,
          port: ep.port,
          path: urlPath,
          method: 'GET',
          headers: { 'User-Agent': 'UnifiedNetworkManager/0.1 (generic-http plugin)', Accept: '*/*' },
          // Self-signed/invalid TLS is ACCEPTED here — the point of this probe is
          // to reach the service and read its certificate, not to judge it. The
          // chain verdict lives in the Certificates page data instead.
          ...(ep.scheme === 'https' ? { rejectUnauthorized: false } : {}),
        },
        (res) => {
          const ms = Date.now() - startedAt;
          clearTimeout(timer);
          finish({ status: res.statusCode ?? 0, ms });
          req.destroy(); // headers are enough — don't download the body
        },
      );
    } catch {
      finish(null);
      return;
    }

    const timer = setTimeout(() => {
      try {
        req.destroy(new Error(`request timed out after ${timeoutMs} ms`));
      } catch {
        // already closed.
      }
    }, timeoutMs);

    req.on('error', () => {
      clearTimeout(timer);
      finish(null);
    });
    req.end();
  });
}

// ---------------------------------------------------------------------------
// POST /monitoring — ALWAYS responds 200 (the API's telemetry worker treats
// non-200 as transport failure); health carries the verdict.
// ---------------------------------------------------------------------------
app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Effective settings injected by the API (defaults ⊕ user overrides).
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  const httpPort = clampInt(settings.httpPort, 1, 65_535, 80);
  const httpsPort = clampInt(settings.httpsPort, 1, 65_535, 443);
  let requestPath = typeof settings.path === 'string' && settings.path.trim() !== '' ? settings.path.trim() : '/';
  if (!requestPath.startsWith('/')) requestPath = `/${requestPath}`;
  const timeoutMs = clampInt(settings.timeoutMs, 200, 9_000, 5_000);

  // Window-based scheduling: the API sends collectInventory=false on metrics-only
  // polls (absent = full collection, old-API compatible).
  const collectInventoryFlag = body.collectInventory !== false;

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [...METRIC_DESCRIPTORS, errorDescriptor()],
      error,
    });
  };

  if (!managementAddress.trim()) return fail('critical', 'No target address — set the device management address.');

  const endpoints = resolveEndpoints(managementAddress, { httpPort, httpsPort });
  if (endpoints.length === 0) return fail('critical', `Cannot parse a probe target from "${managementAddress}".`);

  try {
    // All probes run in parallel — each is bounded by timeoutMs, so the whole
    // poll stays inside the API's ~10 s budget regardless of settings.
    const tlsEp = endpoints.find((e) => e.scheme === 'https') ?? null;
    // Certificate probe (raw TLS handshake + X.509 parse + chain validation via
    // the SDK). `null` result = "don't report certificates this cycle" (the key
    // is omitted, so previously stored rows are untouched); an EMPTY array is
    // authoritative ("no TLS endpoint right now") and wipes stale rows.
    const certPromise: Promise<CertificateRow[] | null> =
      collectInventoryFlag && tlsEp
        ? collectDeviceCertificates({ host: tlsEp.host, httpsPort: tlsEp.port, sshEnabled: false, timeoutMs })
        : Promise.resolve(null);

    const [endpointResults, certificates] = await Promise.all([
      Promise.all(endpoints.map((ep) => checkEndpoint(ep, requestPath, timeoutMs).then((result) => ({ ep, result })))),
      certPromise,
    ]);

    // Headline endpoint: the first one that answered in probe order (HTTPS first),
    // so a TLS service reports its 443 numbers and a plain-HTTP box its port-80.
    const answered = endpointResults.find((x) => x.result !== null);
    if (!answered || !answered.result) {
      const targets = endpoints.map((e) => `${e.scheme}://${e.host}:${e.port}${requestPath}`).join(', ');
      logger.error(`Web service not responding on ${targets}`, { deviceId, context: { address: managementAddress } });
      return fail('critical', `Web service not responding — no HTTP response from ${targets}.`);
    }

    const status = answered.result.status;
    const healthyStatus = status >= 200 && status < 400;

    // Per-endpoint outcome summary (which port actually served the request).
    const detail = endpointResults
      .map(({ ep, result }) => {
        const url = `${ep.scheme}://${ep.host}:${ep.port}${requestPath}`;
        return result ? `${url} → ${result.status} in ${result.ms} ms` : `${url} → no response`;
      })
      .join('  |  ');

    const metrics: Record<string, unknown> = {
      'http.responseTimeMs': answered.result.ms,
      'http.status': status,
      'http.reachable': true,
      'http.detail': detail,
    };

    // TLS facts ride the inventory window (15 min) — on metrics-only polls the
    // keys are omitted and keep their last values.
    if (certificates !== null) {
      metrics['tls.supported'] = certificates.length > 0;
      if (certificates.length > 0) {
        metrics['tls.daysToExpiry'] = certificates[0].daysToExpiry;
        // Inventory propagation → the API's cross-device Certificates page.
        metrics['certificates'] = certificates;
      }
    }

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: healthyStatus ? 'ok' : 'warning', // up but erroring (4xx/5xx) → warning
      metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: { httpPort, httpsPort, path: requestPath, timeoutMs },
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }
});

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[generic-http-plugin] fatal startup error:', err);
  process.exit(1);
});
