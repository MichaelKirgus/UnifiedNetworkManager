import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import { pingHost, PingResult } from './pinger';
import { collectInventory, TargetInventory } from './inventory';

export const PLUGIN_UUID = 'c9d5e7f8-2a3b-4c5d-8e6f-0a1b2c3d4e5f';
export const PLUGIN_NAME = 'Ping Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "Ping Plugin (site-a)". Unset = single-instance behavior.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['generic'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'inventory'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4004);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

/**
 * Hard wall-clock budget for one ping run. The API's telemetry worker gives a
 * plugin ~10s per poll, so the whole measurement (count × per-packet wait) is
 * kept under this even if the user configures aggressive values — the plugin
 * clamps the per-packet timeout rather than failing the poll.
 */
const PING_BUDGET_MS = 8_000;

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * Metric descriptors (static — this plugin always emits exactly these keys).
 * The webapp renders from these, so no per-plugin UI code is needed.
 */
const METRIC_DESCRIPTORS = [
  {
    key: 'ping.latency',
    label: 'Latency (avg RTT)',
    unit: 'ms',
    format: 'number' as const,
    type: 'number' as const,
    visualization: 'plot' as const,
    group: 'Ping',
    color: '#3b82f6',
    summary: true, // headline metric in the device overview table
  },
  {
    key: 'ping.lossPercent',
    label: 'Packet loss',
    unit: '%',
    format: 'number' as const,
    type: 'number' as const,
    visualization: 'gauge' as const,
    group: 'Ping',
    min: 0,
    max: 100,
    color: '#ef4444',
  },
  {
    key: 'ping.jitter',
    label: 'Jitter (RTT stddev)',
    unit: 'ms',
    format: 'number' as const,
    type: 'number' as const,
    visualization: 'text' as const,
    group: 'Ping',
  },
  {
    key: 'ping.reachable',
    label: 'Reachable',
    type: 'boolean' as const,
    visualization: 'text' as const,
    group: 'Ping',
  },
  {
    key: 'inventory.target',
    label: 'Pinged target',
    type: 'string' as const,
    visualization: 'text' as const,
    group: 'Inventory',
  },
  {
    key: 'inventory.ip',
    label: 'Resolved IP',
    type: 'string' as const,
    visualization: 'text' as const,
    group: 'Inventory',
  },
  {
    key: 'inventory.mac',
    label: 'MAC address',
    type: 'string' as const,
    visualization: 'text' as const,
    group: 'Inventory',
  },
];

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS = [
  {
    key: 'pingHost',
    label: 'Ping host override',
    type: 'string' as const,
    // Characters valid in hostnames / IPv4 / IPv6 literals (incl. brackets).
    pattern: '^[a-zA-Z0-9._:\\-\\[\\]]+$',
    maxLength: 253,
    description:
      'Optional hostname or IP to ping instead of the device\'s primary IP — e.g. a secondary interface when the management one is on a different network. Leave empty to ping the primary IP.',
  },
  {
    key: 'pingCount',
    label: 'Ping count',
    type: 'integer' as const,
    default: 4,
    min: 1,
    max: 20,
    description: 'How many ICMP echo requests to send per poll. Total run time is capped at ~8s.',
  },
  {
    key: 'timeoutMs',
    label: 'Per-packet timeout (ms)',
    type: 'integer' as const,
    default: 3000,
    min: 500,
    max: 10000,
    description: 'How long to wait for each reply before counting it lost.',
  },
];

const app = express();
app.use(cors());
app.use(express.json());

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: EFFECTIVE_UUID,
    name: DISPLAY_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    // No credentials needed — the plugin pings from its own container.
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
  });
});

/**
 * Reads the effective settings the API injects on every call (defaults ⊕ user
 * overrides) from the `x-unm-settings` JSON header, merged over this plugin's
 * declared defaults so a missing header still yields sane values.
 */
function readSettings(req: { headers?: Record<string, unknown> }): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};
  for (const opt of PLUGIN_OPTIONS) if (opt.default !== undefined) defaults[opt.key] = opt.default;

  const raw = req.headers?.['x-unm-settings'];
  if (typeof raw !== 'string' || raw.trim() === '') return defaults;
  try {
    const parsed = JSON.parse(raw);
    if (parsed && typeof parsed === 'object') return { ...defaults, ...(parsed as Record<string, unknown>) };
  } catch {
    // Malformed header: fall back to defaults rather than failing the call.
  }
  return defaults;
}

function clampInt(value: unknown, min: number, max: number, fallback: number): number {
  const n = typeof value === 'number' && Number.isInteger(value) ? value : fallback;
  return Math.min(max, Math.max(min, n));
}

/** Extracts a bare host (no scheme/port/brackets) from a management address. */
function hostFromAddress(address: string): string {
  const trimmed = (address ?? '').trim();
  if (!trimmed) return '';
  try {
    const u = new URL(trimmed.includes('://') ? trimmed : `http://${trimmed}`);
    return u.hostname.replace(/^\[|\]$/g, ''); // strip IPv6 literal brackets
  } catch {
    return trimmed.split('/')[0].split(':')[0];
  }
}

/** Maps a ping result to the plugin health vocabulary. */
function healthFromPing(ping: PingResult): Health {
  if (ping.error) return 'critical'; // binary itself failed — not just unreachable
  if (!ping.reachable) return 'critical'; // 100% loss
  if (ping.lossPercent > 0) return 'warning'; // partial loss
  return 'ok';
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  // Effective settings injected by the API (defaults ⊕ user overrides).
  const settings = readSettings(req);

  // Target: per-device/global pingHost override wins, else the device's
  // management address.
  const pingHostOverride = typeof settings.pingHost === 'string' ? settings.pingHost.trim() : '';
  const target = pingHostOverride || hostFromAddress(managementAddress);

  if (!target) {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      metricDescriptors: METRIC_DESCRIPTORS,
      error: 'No ping target: set the pingHost option or a device management address.',
    });
    return;
  }

  const count = clampInt(settings.pingCount, 1, 20, 4);
  let timeoutMs = clampInt(settings.timeoutMs, 500, 10_000, 3000);
  // Keep the whole run inside the API's poll budget regardless of settings.
  timeoutMs = Math.min(timeoutMs, Math.floor(PING_BUDGET_MS / count));

  try {
    // Ping and inventory are independent — run in parallel (the ping itself
    // populates the ARP/NDP entry that collectInventory reads).
    const [ping, inventory] = await Promise.all([
      pingHost(target, count, timeoutMs),
      collectInventory(target),
    ]);

    const health = healthFromPing(ping);
    const metrics: Record<string, unknown> = {
      'ping.latency': ping.avgMs, // null when no replies — UI renders "—"
      'ping.lossPercent': ping.lossPercent,
      'ping.jitter': ping.jitterMs,
      'ping.reachable': ping.reachable,
      'inventory.target': inventory.target,
      'inventory.ip': inventory.ip,
      'inventory.mac': inventory.mac,
    };

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      metricDescriptors: METRIC_DESCRIPTORS,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: {
        pingHost: pingHostOverride || null,
        pingCount: count,
        timeoutMs,
      },
    });
  } catch (err) {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      metricDescriptors: METRIC_DESCRIPTORS,
      error: (err as Error).message,
    });
  }
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the UnifiedNetworkManager API can
 * discover it automatically. Best-effort — the API also polls known endpoints.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: DISPLAY_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: EFFECTIVE_UUID,
        name: DISPLAY_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[ping-plugin] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[ping-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[ping-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});
