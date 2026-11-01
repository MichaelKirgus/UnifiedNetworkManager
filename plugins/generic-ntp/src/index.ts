/**
 * Generic (S)NTP plugin — main entry point.
 *
 * A credential-free NTP/SNTP time-service checker for ANY host that serves NTP
 * (RFC 1305 / RFC 4330):
 *   - Sends one SNTP client request to the configured port (default 123,
 *     adjustable in the plugin settings) and verifies a well-formed server
 *     reply arrives — i.e. "is there a running NTP/SNTP service on this port?".
 *   - Decodes the reply's transmit timestamp → the absolute instant the device
 *     SERVES over NTP, plus stratum / precision / root delay+dispersion /
 *     reference ID as live metrics.
 *   - Emits `system.ntpServed` so the API ingests it into the cross-device Time
 *     page — shown SEPARATELY from each device's own system clock (the two can
 *     differ: a box may serve accurate NTP while its local wall clock is off).
 *   - Serves a short-cycle `ntpServed` probe key so the Time page can refresh
 *     the served-time drift every few seconds.
 *
 * No credentials are needed — it's one UDP datagram to port 123. The device's
 * management address is the target; an explicit port in it wins over the
 * configured default (e.g. "host:323" or "[v6]:123").
 */

import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  ProbeRequestBody,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  probeHandler,
  queryNtp,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import { GENERIC_NTP_DEVICE_SUPPORT } from './deviceSupport';
import type { NtpQueryResult } from '@unm/plugin-sdk';

export const PLUGIN_UUID = '00000000-0000-4000-8000-00000000000e';
export const PLUGIN_NAME = 'Generic (S)NTP Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * Unset = single-instance behavior (see @unm/plugin-sdk resolvePluginIdentity).
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  description:
    'NTP time-source monitoring for any host — reachability and served-time metrics feeding the cross-device Time page.',
  version: '0.1.0',
  vendors: ['generic'],
  // monitoring: live NTP reachability + served-time metrics every poll.
  // inventory: the `system.ntpServed` blob feeds the cross-device Time page.
  // probe: short-cycle live served-time refresh for the Time page.
  capabilities: ['monitoring', 'inventory', 'probe'],
});

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'ntpPort',
    label: 'NTP port',
    type: 'integer' as const,
    default: 123,
    min: 1,
    max: 65535,
    description:
      "UDP port of the NTP/SNTP service to query (default 123). Ignored when the management address carries an explicit port.",
  },
  {
    key: 'timeoutMs',
    label: 'Query timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 200,
    max: 9000,
    description: 'How long to wait for the NTP reply before counting it unreachable. Capped so a poll stays inside the API\'s ~10 s budget.',
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
    key: 'ntp.responseTimeMs',
    label: 'NTP response time',
    unit: 'ms',
    format: 'number',
    type: 'number',
    visualization: 'plot',
    group: 'NTP',
    color: '#3b82f6',
    summary: true, // headline metric in the device overview table
  },
  {
    key: 'ntp.reachable',
    label: 'NTP service reachable',
    type: 'boolean',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.timeUtc',
    label: 'Served time (UTC)',
    type: 'string',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.driftMs',
    label: 'Served-time drift vs UNM',
    unit: 'ms',
    format: 'number',
    type: 'number',
    visualization: 'plot',
    group: 'NTP',
    color: '#f59e0b',
  },
  {
    key: 'ntp.stratum',
    label: 'Stratum',
    type: 'number',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.precision',
    label: 'Precision (2^exp)',
    type: 'number',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.rootDelaySeconds',
    label: 'Root delay (s)',
    unit: 's',
    format: 'number',
    type: 'number',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.rootDispersionSeconds',
    label: 'Root dispersion (s)',
    unit: 's',
    format: 'number',
    type: 'number',
    visualization: 'text',
    group: 'NTP',
  },
  {
    key: 'ntp.referenceId',
    label: 'Reference ID',
    type: 'string',
    visualization: 'text',
    group: 'NTP',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'generic-ntp-plugin',
  // Static icon assets, advertised in /discover and fetched by the API's icon proxy.
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* (proxied by the API's
  // GET /plugins/:id/asset) — referenced from discovery.deviceSupport.
  assetsDir: path.join(__dirname, '../..'),
  discovery: {
    // No credentials needed — a single UDP NTP datagram to the management address.
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
    iconUrl: '/icons/generic-ntp.svg',
    // License/help/docs metadata for UNM's Plugins page (see ./deviceSupport.ts).
    deviceSupport: GENERIC_NTP_DEVICE_SUPPORT,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() below.
const logger = createPluginLogger(identity);

// ---------------------------------------------------------------------------
// Target resolution + NTP query wrapper
// ---------------------------------------------------------------------------

/** One resolved NTP target: host (literal or DNS) + UDP port. */
interface NtpTarget {
  host: string;
  port: number;
}

/**
 * Resolves the NTP target from a management address + configured default port.
 *   - An explicit scheme is stripped (the address may have been set for another
 *     plugin, e.g. "https://host").
 *   - A bare host[:port] uses the explicit port when present; otherwise the
 *     configured `ntpPort`. IPv6 literals are accepted bracketed ("[v6]:123") or
 *     bare (no port possible).
 */
function resolveNtpTarget(address: string, ntpPort: number): NtpTarget | null {
  let raw = String(address ?? '').trim().replace(/\/+$/, '');
  if (!raw) return null;

  const schemeIdx = raw.indexOf('://');
  if (schemeIdx > 0) raw = raw.slice(schemeIdx + 3);

  let host = raw;
  let port: number | null = null;
  const v6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) {
    host = v6[1];
    if (v6[2]) port = Number(v6[2]);
  } else {
    const idx = raw.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
      host = raw.slice(0, idx);
      port = Number(raw.slice(idx + 1));
    } else if (raw.includes(':')) {
      host = raw; // bare IPv6 literal — no explicit port
    }
  }

  if (!host) return null;
  if (port !== null && (!Number.isFinite(port) || port < 1 || port > 65535)) port = null;
  return { host, port: port ?? ntpPort };
}

/** The `system.ntpServed` blob shape — ingested by the API into the Time page. */
interface NtpServedInfo {
  timeUtc: string;
  epochMs: number;
  stratum: number | null;
  referenceId: string | null;
  rootDelaySeconds: number | null;
  rootDispersionSeconds: number | null;
  precision: number | null;
  leapIndicator: number | null;
}

/** A successful NTP read: the decoded blob + its drift vs "now" at read time. */
interface NtpReading {
  served: NtpServedInfo;
  /** Served instant − Date.now() at read time, ms (positive = serves ahead). */
  driftMs: number;
}

/**
 * Runs one NTP query and, on success, derives the served-time blob + a drift
 * figure. Returns `null` when no usable reply arrived. The drift is measured
 * against Date.now() HERE so it reflects how far the served clock is from a
 * correctly-synced reference — NOT against some later reading timestamp.
 */
async function probeNtp(target: NtpTarget, timeoutMs: number): Promise<{ result: NtpQueryResult; reading: NtpReading | null }> {
  const result = await queryNtp(target.host, target.port, timeoutMs);
  if (!result.ok || typeof result.timeEpochMs !== 'number' || !Number.isFinite(result.timeEpochMs)) {
    return { result, reading: null };
  }

  const epochMs = Math.round(result.timeEpochMs);
  const served: NtpServedInfo = {
    timeUtc: result.timeIsoUtc ?? new Date(epochMs).toISOString(),
    epochMs,
    stratum: typeof result.stratum === 'number' ? result.stratum : null,
    referenceId: result.referenceId ?? null,
    rootDelaySeconds: typeof result.rootDelaySeconds === 'number' ? result.rootDelaySeconds : null,
    rootDispersionSeconds: typeof result.rootDispersionSeconds === 'number' ? result.rootDispersionSeconds : null,
    precision: typeof result.precision === 'number' ? result.precision : null,
    leapIndicator: typeof result.leapIndicator === 'number' ? result.leapIndicator : null,
  };

  return { result, reading: { served, driftMs: Math.round(epochMs - Date.now()) } };
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

  const ntpPort = clampInt(settings.ntpPort, 1, 65_535, 123);
  const timeoutMs = clampInt(settings.timeoutMs, 200, 9_000, 5_000);

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

  const target = resolveNtpTarget(managementAddress, ntpPort);
  if (!target) return fail('critical', `Cannot parse an NTP target from "${managementAddress}".`);

  try {
    const { result, reading } = await probeNtp(target, timeoutMs);

    // No well-formed reply → no NTP/SNTP service answering on this port.
    if (!reading) {
      logger.error(`No NTP response from ${target.host}:${target.port}`, { deviceId, context: { address: managementAddress } });
      return fail('critical', `No NTP/SNTP service responding — no reply from udp/${target.host}:${target.port} (${result.error ?? 'unreachable'}).`);
    }

    const served = reading.served;

    // Service is up. A stratum-15 / kiss-o'-death (stratum 0) or alarm leap
    // indicator means it's answering but NOT synchronized → warning, not ok.
    const unsynchronized = served.stratum === 0 || served.stratum === 15 || served.leapIndicator === 3;

    const metrics: Record<string, unknown> = {
      'ntp.reachable': true,
      'ntp.responseTimeMs': typeof result.rttMs === 'number' ? result.rttMs : null,
      'ntp.timeUtc': served.timeUtc,
      'ntp.driftMs': reading.driftMs,
      'ntp.stratum': served.stratum ?? 0,
      'ntp.precision': served.precision,
      'ntp.rootDelaySeconds': served.rootDelaySeconds,
      'ntp.rootDispersionSeconds': served.rootDispersionSeconds,
      'ntp.referenceId': served.referenceId ?? '',
    };

    // The Time page blob — emitted EVERY poll (not inventory-gated) so the
    // served-time drift stays fresh, exactly like `system.deviceTime`.
    metrics['system.ntpServed'] = {
      timeUtc: served.timeUtc,
      epochMs: served.epochMs,
      stratum: served.stratum,
      referenceId: served.referenceId,
      rootDelaySeconds: served.rootDelaySeconds,
      rootDispersionSeconds: served.rootDispersionSeconds,
      precision: served.precision,
      leapIndicator: served.leapIndicator,
    };

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: unsynchronized ? 'warning' : 'ok',
      metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: { ntpPort: target.port, timeoutMs },
    });
  } catch (err) {
    logger.error(`NTP poll for ${managementAddress} failed: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
    return fail('critical', `Monitoring failed: ${(err as Error).message}`);
  }
});

// ---------------------------------------------------------------------------
// POST /probe — SHORT-CYCLE live served-time (capability 'probe'). The Time page
// polls this every few seconds through the API broker to refresh the NTP-served
// drift without waiting for the next telemetry cycle. One cheap UDP query.
// Probe keys: 'ntpServed' (the only key). Unknown/absent list = default set.
// ---------------------------------------------------------------------------
const PROBE_KEYS = new Set(['ntpServed']);

app.post('/probe', probeHandler(async (body: ProbeRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

  const ntpPort = clampInt(settings.ntpPort, 1, 65_535, 123);
  const timeoutMs = clampInt(settings.timeoutMs, 200, 9_000, 5_000);

  const target = resolveNtpTarget(body.managementAddress, ntpPort);
  if (!target) throw new Error(`Cannot parse an NTP target from "${body.managementAddress}"`);

  const requested = Array.isArray(body.keys) && body.keys.length > 0 ? body.keys : ['ntpServed'];
  const wanted = new Set(requested.filter((k) => PROBE_KEYS.has(k)));
  if (wanted.size === 0) throw new Error(`No supported probe keys in [${requested.join(', ')}]`);

  const { result, reading } = await probeNtp(target, timeoutMs);
  if (!reading) throw new Error(`No NTP/SNTP service responding on udp/${target.host}:${target.port} (${result.error ?? 'unreachable'})`);

  const served = reading.served;
  return {
    collectedAt: new Date().toISOString(),
    metrics: {
      // Same blob shape as /monitoring so the Time page can treat live + telemetry alike.
      'system.ntpServed': {
        timeUtc: served.timeUtc,
        epochMs: served.epochMs,
        stratum: served.stratum,
        referenceId: served.referenceId,
        rootDelaySeconds: served.rootDelaySeconds,
        rootDispersionSeconds: served.rootDispersionSeconds,
        precision: served.precision,
        leapIndicator: served.leapIndicator,
      },
    },
  };
}, 'generic-ntp-plugin'));

// listen() binds the conventional plugin port (4080 by default; override with
// the PORT env var) and starts mDNS advertising — both handled by the SDK.
server.listen().catch((err) => {
  console.error('[generic-ntp-plugin] fatal startup error:', err);
  process.exit(1);
});
