import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  clampInt,
  createPluginLogger,
  createPluginServer,
  errorDescriptor,
  INVENTORY_INTERVAL_MS,
  hostFromAddress,
  readSettings,
  resolvePluginIdentity,
} from '@unm/plugin-sdk';
import {
  SnmpCredentials,
  SystemInfo,
  WifiAccessPoint,
  WifiClient,
  WalkOptions,
  getInventory,
  walkCounters,
  computeRates,
} from './snmpClient';
// Per-version credential validation (v1/v2c community + v3 USM) is shared by
// all SNMP-based plugins — one implementation in @unm/snmp-client.
import { buildSnmpCredentials } from '@unm/snmp-client';
import { buildDescriptors, DISCOVER_METRICS } from './metrics';

export const PLUGIN_UUID = '00000000-0000-4000-8000-000000000003';
export const PLUGIN_NAME = 'SNMP Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "SNMP Plugin (site-a)". Unset = single-instance behavior.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  // 0.3.0 — WiFi (802.11) collection: IEEE 802.11 MIB walks for access-point
  // and client facts, gated by the boolean `collectWifi` option (default on).
  version: '0.3.0',
  vendors: ['generic'],
  capabilities: ['monitoring', 'inventory'],
});

/**
 * Configurable options. Declared in /discover so the API persists user-set
 * values and injects them back via the `x-unm-settings` header on every call —
 * this plugin never stores settings itself (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
  {
    key: 'timeoutMs',
    label: 'SNMP timeout (ms)',
    type: 'integer' as const,
    default: 5000,
    min: 1000,
    max: 30000,
    description: 'Per-request SNMP timeout. Kept well under the API\'s 10s poll budget.',
  },
  {
    key: 'retries',
    label: 'SNMP retries',
    type: 'integer' as const,
    default: 2,
    min: 0,
    max: 10,
    description: 'How many times an SNMP request is retried before giving up.',
  },
  {
    key: 'inventoryTtlMs',
    label: 'Inventory refresh interval (ms)',
    type: 'integer' as const,
    default: INVENTORY_INTERVAL_MS,
    min: 60_000,
    max: 86_400_000,
    description:
      'How often the slow-changing inventory walks (system group + interface table) are re-run. Live throughput counters still refresh every poll cycle.',
  },
  {
    key: 'collectWifi',
    label: 'Collect WiFi data (802.11 MIBs)',
    type: 'boolean' as const,
    default: true,
    description:
      'Walk IEEE 802.11 MIB tables for access-point and client info (SSID, BSSID, channel, security + connected client MACs). Refreshes with the inventory interval. Turn off per-device when a dedicated WiFi plugin covers the device.',
  },
  {
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (SNMP walk failures) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ mDNS on listen) come
// from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'snmp-plugin',
  discovery: {
    // Credentials come from the existing 'snmp' secret type (version + community for v1/v2c, USM fields for v3).
    requiredSecretType: 'snmp',
    metrics: DISCOVER_METRICS,
    options: PLUGIN_OPTIONS,
  },
});
const app = server.app;

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

/** Resolves walk options from effective settings. */
function resolveOptions(settings: Record<string, unknown>): WalkOptions {
  return {
    timeoutMs: clampInt(settings.timeoutMs, 1_000, 30_000, 5_000),
    retries: clampInt(settings.retries, 0, 10, 2),
    inventoryTtlMs: clampInt(settings.inventoryTtlMs, 60_000, 86_400_000, INVENTORY_INTERVAL_MS),
    // WiFi collection is ON by default — only an explicit false disables it.
    collectWifi: settings.collectWifi !== false,
  };
}

/** Extracts SNMP credentials from the monitoring body (decrypted by the API). */
function resolveCredentials(body: Record<string, unknown>): { creds?: SnmpCredentials; error?: string } {
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  return buildSnmpCredentials(credentials);
}

/** Builds the per-interface rate map keyed by unique display name. */
function buildInterfaceRateMap(
  interfaces: Array<{ ifIndex: string; name: string }>,
  ratesByIndex: Record<string, { rx: number | null; tx: number | null }>
): { map: Record<string, { rx: number | null; tx: number | null }>; names: string[] } {
  const seen = new Set<string>();
  const map: Record<string, { rx: number | null; tx: number | null }> = {};
  const names: string[] = [];

  for (const iface of interfaces) {
    let key = iface.name || `if${iface.ifIndex}`;
    while (seen.has(key)) key += '…'; // defensive — duplicate display names
    seen.add(key);
    map[key] = ratesByIndex[iface.ifIndex] ?? { rx: null, tx: null };
    names.push(key);
  }

  return { map, names };
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const deviceId = typeof body.deviceId === 'string' ? body.deviceId : null;
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const opts = resolveOptions(settings);
  const host = hostFromAddress(managementAddress);

  const fail = (health: Health, error: string) => {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics: { 'system.error': error },
      metricDescriptors: [
        ...buildDescriptors([], opts.inventoryTtlMs),
        errorDescriptor(),
      ],
      error,
    });
  };

  if (!host) return fail('critical', 'No target address — set the device management address.');

  const { creds, error } = resolveCredentials(body);
  if (error || !creds) return fail('critical', error ?? 'Missing SNMP credentials.');

  try {
    // Slow path: system group + interface table, TTL-cached per host.
    const inventory = await getInventory(host, creds, opts);
    const snapshot = inventory.snapshot;

    if (!snapshot) {
      logger.error(`SNMP collection from ${host} failed: ${inventory.error ?? 'no data available'}`, { deviceId, context: { host } });
      return fail('critical', inventory.error ?? 'SNMP collection failed — no data available.');
    }

    if (inventory.error) {
      // Partial walk failure — the snapshot is usable but some subtrees are empty.
      logger.warn(`Partial SNMP data from ${host}: ${inventory.error}`, { deviceId, context: { host } });
    }

    // Fast path: counter-only walk every cycle for fresh rates.
    let counters = await walkCounters(host, creds, opts, snapshot.useHc);
    if (!counters) {
      // Counter walk failed this cycle — fall back to the cached table's
      // counters so we still emit *something* (rates will be stale/skipped).
      counters = snapshot.counters;
    }

    const ratesByIndex = computeRates(host, counters);
    const { map: interfaceMap, names } = buildInterfaceRateMap(snapshot.interfaces, ratesByIndex);

    // Aggregated throughput (bits/s): sum of all non-null rx + tx.
    let total: number | null = null;
    for (const r of Object.values(interfaceMap)) {
      if (r.rx !== null || r.tx !== null) {
        total = (total ?? 0) + (r.rx ?? 0) + (r.tx ?? 0);
      }
    }

    const metrics: Record<string, unknown> = {};
    const sys = snapshot.system;
    if (sys) {
      metrics['system.description'] = sys.description || null;
      metrics['system.objectId'] = sys.objectId || null;
      metrics['system.name'] = sys.name || null;
      metrics['system.location'] = sys.location || null;
      metrics['system.contact'] = sys.contact || null;
      metrics['system.uptime'] = sys.uptimeSeconds; // seconds — format:'duration' renders "1d 2h …"
    }

    metrics.interfaces = interfaceMap; // { <name>: { rx, tx } } bits/s (null until 2nd sample)
    metrics['throughput.total'] = total;

    // Inventory: per-interface attributes for later use.
    metrics['inventory.interfaces'] = snapshot.interfaces.map((i) => ({
      name: i.name || `if${Number(i.ifIndex)}`,
      type: i.type,
      speed: i.speedBps !== null ? `${(i.speedBps / 1_000_000).toFixed(0)} Mbit` : '—',
      mac: i.mac || '—',
      status: i.status,
    }));

    // WiFi (IEEE 802.11 MIBs): emitted only when collection is enabled AND the
    // device actually exposed WLAN data — absence on non-AP devices is normal
    // and must not degrade health or add descriptors.
    const wifi = snapshot.wifi;
    if (wifi && (wifi.accessPoints.length > 0 || wifi.clients.length > 0)) {
      metrics['wifi.accessPoints'] = wifi.accessPoints.map((ap) => ({
        ssid: ap.ssid || '—',
        bssid: ap.bssid || '—',
        channel: ap.channel !== null ? String(ap.channel) : '—',
        security: ap.security || '—',
      }));
      metrics['wifi.clients'] = wifi.clients.map((c) => ({
        mac: c.mac,
        ssid: c.ssid || '—',
        rate: c.rateMbps !== null ? `${c.rateMbps} Mbit` : '—',
      }));
    }

    // Health: partial data (or a failed counter walk) degrades to warning.
    let health: Health = 'ok';
    const warnings: string[] = [];
    if (!sys) warnings.push('system group unavailable');
    if (snapshot.interfaces.length === 0) warnings.push('no interfaces reported');
    if (inventory.error) warnings.push(inventory.error);
    if (warnings.length > 0) {
      health = 'warning';
      metrics['system.error'] = warnings.join('; ');
    }

    const hasWifi = !!wifi && (wifi.accessPoints.length > 0 || wifi.clients.length > 0);
    const descriptors: MetricDescriptor[] = buildDescriptors(names, opts.inventoryTtlMs, hasWifi);
    if (metrics['system.error']) {
      descriptors.push(errorDescriptor());
    }

    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      metricDescriptors: descriptors,
      // Echo back the effective settings — proof of the API→plugin loop.
      activeSettings: {
        timeoutMs: opts.timeoutMs,
        retries: opts.retries,
        inventoryTtlMs: opts.inventoryTtlMs,
        collectWifi: opts.collectWifi !== false,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll for ${host} failed: ${(err as Error).message}`, { deviceId, context: { host } });
    return fail('critical', (err as Error).message);
  }
});

/** Shared inventory response shape + the walk/serialize core. */
interface InventoryResponse {
  capability: 'inventory';
  collectedAt: string;
  system: SystemInfo | null;
  interfaces: Array<{
    name: string;
    ifIndex: number;
    type: string;
    speedBps: number | null;
    mac: string;
    status: string;
  }>;
  /** WiFi facts when collectWifi is enabled (null = no 802.11 data on device). */
  wifi?: {
    accessPoints: WifiAccessPoint[];
    clients: WifiClient[];
    source: 'ieee802dot11-2' | 'legacy';
  } | null;
  error?: string;
}

function inventoryError(message: string): InventoryResponse {
  return { capability: 'inventory', collectedAt: new Date().toISOString(), system: null, interfaces: [], error: message };
}

async function runInventory(host: string, creds: SnmpCredentials, opts: WalkOptions): Promise<InventoryResponse> {
  try {
    const inventory = await getInventory(host, creds, opts);
    return {
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      system: inventory.snapshot?.system ?? null,
      interfaces: (inventory.snapshot?.interfaces ?? []).map((i) => ({
        name: i.name || `if${Number(i.ifIndex)}`,
        ifIndex: Number(i.ifIndex),
        type: i.type,
        speedBps: i.speedBps,
        mac: i.mac,
        status: i.status,
      })),
      // WiFi rides the same TTL-cached snapshot — no extra walks here.
      ...(inventory.snapshot?.wifi !== undefined ? { wifi: inventory.snapshot.wifi } : {}),
      ...(inventory.error ? { error: inventory.error } : {}),
    };
  } catch (err) {
    return inventoryError((err as Error).message);
  }
}

/**
 * Dedicated inventory endpoint (opnsense parity): full system + interface
 * facts on demand, usable by external/programmatic consumers without a device
 * assignment. Two routes share the same core:
 *
 *   GET  /inventory?managementAddress=…&community=…[&version=v1|v2c]
 *        Convenience form for community-based credentials — low-sensitivity
 *        shared strings that are acceptable in URLs (and shell history).
 *
 *   POST /inventory  { managementAddress, credentials: { version, … } }
 *        Same body contract as /monitoring. REQUIRED for SNMPv3: USM auth/priv
 *        passwords must not travel in query strings (URLs end up in caller
 *        history, proxy/firewall logs, and any future access logging).
 */
app.get('/inventory', async (req, res) => {
  const q = req.query ?? {};
  const host = typeof q.managementAddress === 'string' ? hostFromAddress(q.managementAddress) : '';

  if (!host) {
    return res.status(200).json(inventoryError('Provide managementAddress as a query param.'));
  }

  // v3 via GET is rejected: USM passwords must not appear in URLs.
  const versionRaw = typeof q.version === 'string' && q.version.trim() ? q.version.trim() : 'v2c';
  if (versionRaw === 'v3') {
    return res.status(200).json(
      inventoryError('SNMPv3 is not supported via GET query params — POST /inventory with a JSON body: { managementAddress, credentials: { version: "v3", username, securityLevel, … } }.')
    );
  }

  const { creds, error } = buildSnmpCredentials(q);
  if (error || !creds) {
    return res.status(200).json(inventoryError(error ?? 'Missing SNMP credentials.'));
  }

  res.status(200).json(await runInventory(host, creds, resolveOptions(readSettings(req, PLUGIN_OPTIONS))));
});

app.post('/inventory', async (req, res) => {
  const body = req.body ?? {};
  const managementAddress = typeof body.managementAddress === 'string' ? body.managementAddress : '';
  const host = hostFromAddress(managementAddress);

  if (!host) {
    return res.status(200).json(inventoryError('Provide managementAddress in the JSON body.'));
  }

  // Same credential contract as /monitoring: decrypted `snmp` secret fields.
  const credentials = (body.credentials ?? {}) as Record<string, unknown>;
  const { creds, error } = buildSnmpCredentials(credentials);
  if (error || !creds) {
    return res.status(200).json(inventoryError(error ?? 'Missing SNMP credentials.'));
  }

  res.status(200).json(await runInventory(host, creds, resolveOptions(readSettings(req, PLUGIN_OPTIONS))));
});

// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[snmp-plugin] fatal startup error:', err);
  process.exit(1);
});
