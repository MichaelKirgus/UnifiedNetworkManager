import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginLogger,
  createPluginServer,
  hostFromAddress,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import { pingHost, PingResult } from './ping';
import { collectInventory, TargetInventory } from './inventory';

export const PLUGIN_UUID = 'c9d5e7f8-2a3b-4c5d-8e6f-0a1b2c3d4e5f';
export const PLUGIN_NAME = 'ICMP Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "ICMP Plugin (site-a)". Unset = single-instance behavior.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.1.0',
  vendors: ['generic'],
  capabilities: ['monitoring', 'inventory'],
});

/**
 * Hard wall-clock budget for one ping run. The API's telemetry worker gives a
 * plugin ~10s per poll, so the whole measurement (count × per-packet wait) is
 * kept under this even if the user configures aggressive values — the plugin
 * clamps the per-packet timeout rather than failing the poll.
 */
const PING_BUDGET_MS = 8_000;

/**
 * Metric descriptors (static — this plugin always emits exactly these keys).
 * The webapp renders from these, so no per-plugin UI code is needed.
 */
const METRIC_DESCRIPTORS: MetricDescriptor[] = [
  {
    key: 'ping.latency',
    label: 'Latency (avg RTT)',
    unit: 'ms',
    format: 'number',
    type: 'number',
    visualization: 'plot',
    group: 'ICMP',
    color: '#3b82f6',
    summary: true, // headline metric in the device overview table
  },
  {
    key: 'ping.lossPercent',
    label: 'Packet loss',
    unit: '%',
    format: 'number',
    type: 'number',
    visualization: 'gauge',
    group: 'ICMP',
    min: 0,
    max: 100,
    color: '#ef4444',
  },
  {
    key: 'ping.jitter',
    label: 'Jitter (RTT stddev)',
    unit: 'ms',
    format: 'number',
    type: 'number',
    visualization: 'text',
    group: 'ICMP',
  },
  {
    key: 'ping.reachable',
    label: 'Reachable',
    type: 'boolean',
    visualization: 'text',
    group: 'ICMP',
  },
  {
    key: 'inventory.target',
    label: 'Target host',
    type: 'string',
    visualization: 'text',
    group: 'Inventory',
  },
  {
    key: 'inventory.ip',
    label: 'Resolved IP',
    type: 'string',
    visualization: 'text',
    group: 'Inventory',
  },
  {
    key: 'inventory.mac',
    label: 'MAC address',
    type: 'string',
    visualization: 'text',
    group: 'Inventory',
  },
];

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'pingHost',
    label: 'Target host override',
    type: 'string',
    // Characters valid in hostnames / IPv4 / IPv6 literals (incl. brackets).
    pattern: '^[a-zA-Z0-9._:\\-\\[\\]]+$',
    maxLength: 253,
    description:
      "Optional hostname or IP to probe with ICMP echo instead of the device's primary IP — e.g. a secondary interface when the management one is on a different network. Leave empty to use the primary IP.",
  },
  {
    key: 'pingCount',
    label: 'Echo request count',
    type: 'integer',
    default: 4,
    min: 1,
    max: 20,
    description: 'How many ICMP echo requests to send per poll. Total run time is capped at ~8s.',
  },
  {
    key: 'timeoutMs',
    label: 'Per-packet timeout (ms)',
    type: 'integer',
    default: 3000,
    min: 500,
    max: 10000,
    description: 'How long to wait for each reply before counting it lost.',
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

// Pre-wired app: cors + json + /healthz + /discover (+ mDNS on listen) come
// from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'icmp-plugin',
  discovery: {
    // No credentials needed — the plugin pings from its own container.
    requiredSecretType: null,
    metrics: METRIC_DESCRIPTORS,
    options: PLUGIN_OPTIONS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

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
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

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
    logger.error(`Ping run for ${target} failed: ${(err as Error).message}`, { deviceId, context: { target, count, timeoutMs } });
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

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[icmp-plugin] fatal startup error:', err);
  process.exit(1);
});
