import express from 'express';
import cors from 'cors';
import { Bonjour } from 'bonjour-service';
import {
  getSystemStatus,
  getSystemResources,
  getSystemInformation,
  getInterfaces,
  getInterfaceStats,
  getCpuUsage,
  getArpTable,
  getNdpTable,
  applyConfig,
} from './opnsenseClient';

export const PLUGIN_UUID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';
export const PLUGIN_NAME = 'OPNsense Plugin';
export const PLUGIN_VERSION = '0.1.0';
export const PLUGIN_VENDORS = ['opnsense'];
export const PLUGIN_CAPABILITIES = ['monitoring', 'configuration', 'inventory'];
export const PLUGIN_AUTH_TYPE = 'none';

const PORT = Number(process.env.PORT ?? 4001);
const ADVERTISED_ENDPOINT = process.env.ADVERTISED_ENDPOINT ?? `http://localhost:${PORT}`;

const app = express();
app.use(cors());
app.use(express.json());

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok' });
});

/**
 * A metric descriptor: the plugin's self-description of a single metric it
 * emits. This is the extensible contract the webapp renders from, so adding a
 * new metric (or a new plugin) requires NO webapp code changes — the UI is
 * driven entirely by these descriptors.
 *
 *   key           metric id; must match a key in the telemetry `metrics` map
 *   label         human-readable name
 *   unit          unit of measure (%, MB, bps, s, ...) — the raw unit, kept for
 *                 machine comparison across plugins
 *   format        how the webapp should render the value: bytes | bits | duration
 *                 | number | text. This is the extensible rendering hint — a
 *                 plugin declares how its value should be humanized, and the
 *                 webapp stays generic (no per-plugin code).
 *   type          value type
 *   visualization default render hint: gauge | plot | text | table
 *   group         optional section grouping (e.g. "System", "Network")
 *   min/max       gauge bounds
 *   color         optional accent color
 *   rows          for 'table': the row keys (e.g. interface names)
 *   summary       when true, this metric is a headline value the webapp shows
 *                 inline in the device OVERVIEW table (not just the detail view).
 *                 This is the flexible "most important metrics" hook — a plugin
 *                 marks its key metrics and the list view renders them.
 *   intervalMs    how often this metric group should be re-fetched from the
 *                 appliance. The plugin CACHES slow data (inventory: ARP/NDP,
 *                 MACs, hostname) and only re-polls the appliance when the
 *                 interval elapses — so the API can poll /monitoring every 30s
 *                 (cheap local call) without hammering the device. This is the
 *                 extensible "refresh cadence" contract: any plugin declares
 *                 per-metric intervals and scales to many devices.
 */
export interface MetricDescriptor {
  key: string;
  label: string;
  unit?: string;
  format?: 'bytes' | 'bits' | 'duration' | 'number' | 'text';
  type: 'number' | 'string' | 'boolean' | 'enum';
  visualization: 'gauge' | 'plot' | 'text' | 'table';
  group?: string;
  min?: number;
  max?: number;
  color?: string;
  rows?: string[];
  columns?: string[];
  summary?: boolean;
  intervalMs?: number;
}

/**
 * Refresh cadence per metric class. Live metrics (CPU, memory, traffic) are
 * cheap and change fast → 30s. Inventory (ARP/NDP tables, interface MACs,
 * hostname, version) changes rarely → 15 min. The plugin caches inventory in
 * memory and only re-fetches from the appliance when the TTL elapses, so the
 * API's 30s poll never re-hammers the device. This is what makes the system
 * scale to many devices: appliance load is bounded by intervalMs, not by the
 * number of API polls.
 */
const LIVE_INTERVAL_MS = 30_000;
const INVENTORY_INTERVAL_MS = 15 * 60 * 1000;

/**
 * In-memory inventory cache, keyed by management host. Holds the slow-changing
 * data (hostname, version, ARP table, NDP table) so repeated /monitoring polls
 * within the TTL don't re-fetch it from the appliance.
 */
interface InventorySnapshot {
  collectedAt: number;
  hostname?: string;
  version?: string;
  arp: Record<string, unknown>[];
  ndp: Record<string, unknown>[];
}

const inventoryCache = new Map<string, InventorySnapshot>();

/**
 * Returns the inventory snapshot for a host, fetching from the appliance only
 * when the cache is older than INVENTORY_INTERVAL_MS. All three calls run in
 * parallel and are best-effort — a failing endpoint yields an empty field, not
 * an error.
 */
async function getInventory(
  host: string,
  apiKey: string,
  apiSecret: string
): Promise<InventorySnapshot> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < INVENTORY_INTERVAL_MS) {
    return cached;
  }

  const [info, arp, ndp] = await Promise.all([
    getSystemInformation(host, apiKey, apiSecret).catch(() => undefined),
    getArpTable(host, apiKey, apiSecret).catch(() => undefined),
    getNdpTable(host, apiKey, apiSecret).catch(() => undefined),
  ]);

  const snap: InventorySnapshot = { collectedAt: Date.now(), arp: [], ndp: [] };
  if (info?.ok && info.data && typeof info.data === 'object') {
    const d = info.data as Record<string, unknown>;
    if (d['name'] !== undefined) snap.hostname = String(d['name']);
    const versions = d['versions'];
    if (Array.isArray(versions) && versions.length > 0) snap.version = String(versions[0]);
  }
  if (arp?.ok && arp.data && typeof arp.data === 'object') {
    const rows = (arp.data as Record<string, unknown>)['rows'];
    if (Array.isArray(rows)) snap.arp = rows as Record<string, unknown>[];
  }
  if (ndp?.ok && ndp.data && typeof ndp.data === 'object') {
    const rows = (ndp.data as Record<string, unknown>)['rows'];
    if (Array.isArray(rows)) snap.ndp = rows as Record<string, unknown>[];
  }

  inventoryCache.set(host, snap);
  return snap;
}

/**
 * Builds the metric descriptors this plugin serves. The traffic table's rows
 * are the interfaces actually present on the device, so the descriptor is
 * accurate for the specific appliance.
 */
function buildMetricDescriptors(interfaces: string[]): MetricDescriptor[] {
  const descriptors: MetricDescriptor[] = [
    {
      key: 'metadata.system.status',
      label: 'System Status',
      type: 'number',
      visualization: 'gauge',
      group: 'System',
      min: 0,
      max: 2,
      color: '#22c55e',
      intervalMs: LIVE_INTERVAL_MS,
    },
    {
      key: 'cpu.percent',
      label: 'CPU',
      unit: '%',
      type: 'number',
      visualization: 'gauge',
      group: 'System',
      min: 0,
      max: 100,
      color: '#f59e0b',
      summary: true,
      intervalMs: LIVE_INTERVAL_MS,
    },
    {
      key: 'memory.percent',
      label: 'Memory',
      unit: '%',
      type: 'number',
      visualization: 'gauge',
      group: 'System',
      min: 0,
      max: 100,
      color: '#8b5cf6',
      summary: true,
      intervalMs: LIVE_INTERVAL_MS,
    },
    {
      key: 'memory.used',
      label: 'Memory Used',
      unit: 'bytes',
      format: 'bytes',
      type: 'number',
      visualization: 'text',
      group: 'System',
      intervalMs: LIVE_INTERVAL_MS,
    },
    {
      key: 'memory.total',
      label: 'Memory Total',
      unit: 'bytes',
      format: 'bytes',
      type: 'number',
      visualization: 'text',
      group: 'System',
      intervalMs: LIVE_INTERVAL_MS,
    },
    {
      key: 'hostname',
      label: 'Hostname',
      type: 'string',
      visualization: 'text',
      group: 'Inventory',
      intervalMs: INVENTORY_INTERVAL_MS,
    },
    {
      key: 'version',
      label: 'Version',
      type: 'string',
      visualization: 'text',
      group: 'Inventory',
      intervalMs: INVENTORY_INTERVAL_MS,
    },
    {
      key: 'arp',
      label: 'ARP Table',
      type: 'string',
      visualization: 'table',
      group: 'Inventory',
      columns: ['mac', 'ip', 'intf', 'manufacturer'],
      intervalMs: INVENTORY_INTERVAL_MS,
    },
    {
      key: 'ndp',
      label: 'NDP Table',
      type: 'string',
      visualization: 'table',
      group: 'Inventory',
      columns: ['mac', 'ip', 'intf', 'manufacturer'],
      intervalMs: INVENTORY_INTERVAL_MS,
    },
    {
      key: 'interfaces',
      label: 'Interfaces',
      type: 'string',
      visualization: 'table',
      group: 'Inventory',
      columns: ['name', 'mac'],
      intervalMs: LIVE_INTERVAL_MS,
    },
  ];

  if (interfaces.length > 0) {
    descriptors.push({
      key: 'traffic',
      label: 'Interface Traffic',
      unit: 'bytes',
      format: 'bytes',
      type: 'number',
      visualization: 'table',
      group: 'Network',
      rows: interfaces,
      columns: ['rx', 'tx'],
    });
  }

  return descriptors;
}

/**
 * Builds metric descriptors DYNAMICALLY from the metrics actually collected.
 * This is the robust, extensible approach: the UI always matches the data the
 * appliance really returned, so it works across OPNsense versions and any
 * plugin — no hard-coded field names, no empty cards. Each known metric maps
 * to a visualization; unknown numeric metrics fall back to a 'text' card.
 */
function descriptorsFromMetrics(metrics: Record<string, unknown>): MetricDescriptor[] {
  const descriptors: MetricDescriptor[] = [];
  const seen = new Set<string>();

  const push = (d: MetricDescriptor) => {
    if (!seen.has(d.key)) {
      seen.add(d.key);
      descriptors.push(d);
    }
  };

  // System status (always present on OPNsense) — a 0-2 health gauge.
  const status = metrics['metadata.system.status'];
  if (typeof status === 'number') {
    push({
      key: 'metadata.system.status',
      label: 'System Status',
      type: 'number',
      visualization: 'gauge',
      group: 'System',
      min: 0,
      max: 2,
      color: '#22c55e',
      intervalMs: LIVE_INTERVAL_MS,
    });
  }

  // CPU (when the appliance exposes the usage stream).
  if (typeof metrics['cpu.percent'] === 'number') {
    push({ key: 'cpu.percent', label: 'CPU', unit: '%', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100, color: '#f59e0b', summary: true, intervalMs: LIVE_INTERVAL_MS });
  }
  // Memory (when the appliance exposes it).
  if (typeof metrics['memory.percent'] === 'number') {
    push({ key: 'memory.percent', label: 'Memory', unit: '%', type: 'number', visualization: 'gauge', group: 'System', min: 0, max: 100, color: '#8b5cf6', summary: true, intervalMs: LIVE_INTERVAL_MS });
  }
  if (typeof metrics['memory.used'] === 'number') {
    push({ key: 'memory.used', label: 'Memory Used', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System', intervalMs: LIVE_INTERVAL_MS });
  }
  if (typeof metrics['memory.total'] === 'number') {
    push({ key: 'memory.total', label: 'Memory Total', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'text', group: 'System', intervalMs: LIVE_INTERVAL_MS });
  }
  // Identity (hostname + version) — inventory, slow refresh.
  if (metrics['hostname'] !== undefined) {
    push({ key: 'hostname', label: 'Hostname', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (metrics['version'] !== undefined) {
    push({ key: 'version', label: 'Version', type: 'string', visualization: 'text', group: 'Inventory', intervalMs: INVENTORY_INTERVAL_MS });
  }

  // Traffic table (rows = interfaces present in the data).
  if (metrics['traffic'] && typeof metrics['traffic'] === 'object') {
    const traffic = metrics['traffic'] as Record<string, unknown>;
    const rows = Object.keys(traffic);
    if (rows.length > 0) {
      push({ key: 'traffic', label: 'Interface Traffic', unit: 'bytes', format: 'bytes', type: 'number', visualization: 'table', group: 'Network', rows, columns: ['rx', 'tx'], intervalMs: LIVE_INTERVAL_MS });
    }
  }

  // Neighbor tables (ARP/NDP) — inventory, slow refresh (cached in the plugin).
  if (Array.isArray(metrics['arp']) && (metrics['arp'] as unknown[]).length > 0) {
    push({ key: 'arp', label: 'ARP Table', type: 'string', visualization: 'table', group: 'Inventory', columns: ['mac', 'ip', 'intf', 'manufacturer'], intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (Array.isArray(metrics['ndp']) && (metrics['ndp'] as unknown[]).length > 0) {
    push({ key: 'ndp', label: 'NDP Table', type: 'string', visualization: 'table', group: 'Inventory', columns: ['mac', 'ip', 'intf', 'manufacturer'], intervalMs: INVENTORY_INTERVAL_MS });
  }
  // Interface MACs (name + mac per interface).
  if (Array.isArray(metrics['interfaces']) && (metrics['interfaces'] as unknown[]).length > 0) {
    push({ key: 'interfaces', label: 'Interfaces', type: 'string', visualization: 'table', group: 'Inventory', columns: ['name', 'mac'], intervalMs: LIVE_INTERVAL_MS });
  }

  // Fallback: any other numeric metric becomes a text card so nothing is lost.
  for (const [key, value] of Object.entries(metrics)) {
    if (seen.has(key)) continue;
    if (typeof value === 'number') {
      push({ key, label: key, type: 'number', visualization: 'text', group: 'Other' });
    }
  }

  return descriptors;
}

/**
 * Plugin identity endpoint. The UnifiedNetworkManager API can poll this
 * endpoint (as a fallback to mDNS discovery) to discover and upsert this
 * plugin. Returns the full, self-describing identity of this plugin, including
 * the metric descriptors that drive the webapp's visualization.
 */
app.get('/discover', (_req, res) => {
  res.status(200).json({
    uuid: PLUGIN_UUID,
    name: PLUGIN_NAME,
    version: PLUGIN_VERSION,
    vendors: PLUGIN_VENDORS,
    capabilities: PLUGIN_CAPABILITIES,
    endpoint: ADVERTISED_ENDPOINT,
    authType: PLUGIN_AUTH_TYPE,
    // The secret type this plugin expects for device credentials. The API
    // broker reads this to filter which secrets/providers are applicable to
    // devices managed by this plugin.
    requiredSecretType: 'apiKey',
    // Static metric descriptors (system metrics). The traffic table descriptor
    // is emitted dynamically from /monitoring (it needs the live interface
    // list, which is only available when polling a specific device).
    metrics: buildMetricDescriptors([]),
  });
});

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * Reads a numeric value from an object, trying several candidate keys (OPNsense
 * field names vary by version). Returns `undefined` when none is present.
 */
function pickNumber(obj: Record<string, unknown>, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = obj[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  }
  return undefined;
}

/**
 * Collects a rich set of metrics from the OPNsense appliance: CPU load,
 * memory usage, uptime, and per-interface traffic. Each sub-call is
 * best-effort so a single failing endpoint doesn't sink the whole poll.
 */
async function collectMetrics(
  host: string,
  apiKey: string,
  apiSecret: string
): Promise<{ metrics: Record<string, unknown>; interfaces: string[] }> {
  const metrics: Record<string, unknown> = {};
  const interfaces: string[] = [];
  const interfaceMacs: { name: string; mac: string }[] = [];

  // System status (health + basic info). OPNsense returns
  // { metadata: { system: { status: 0|1|2 } } } — capture the status code.
  const status = await getSystemStatus(host, apiKey, apiSecret);
  if (status.ok && status.data && typeof status.data === 'object') {
    const d = status.data as Record<string, unknown>;
    const meta = d['metadata'] as Record<string, unknown> | undefined;
    const sys = meta?.['system'] as Record<string, unknown> | undefined;
    const sysStatus = sys?.['status'];
    if (typeof sysStatus === 'number') metrics['metadata.system.status'] = sysStatus;
  }

  // CPU usage (%) from the SSE stream /api/diagnostics/cpu_usage/stream.
  // Emits { total, user, nice, sys, intr, idle } per second; `total` is the
  // percentage of CPU in use. Best-effort — older firmware may not expose it.
  try {
    const cpu = await getCpuUsage(host, apiKey, apiSecret);
    if (cpu && typeof cpu.total === 'number') {
      metrics['cpu.percent'] = cpu.total;
      metrics['cpu.user'] = cpu.user;
      metrics['cpu.sys'] = cpu.sys;
      metrics['cpu.intr'] = cpu.intr;
    }
  } catch {
    // best-effort
  }

  // Memory usage (bytes) from /api/diagnostics/system/system_resources.
  // Shape: { memory: { total: "<bytes>", used: <bytes>, ... } }
  try {
    const resources = await getSystemResources(host, apiKey, apiSecret);
    if (resources.ok && resources.data && typeof resources.data === 'object') {
      const d = resources.data as Record<string, unknown>;
      const mem = d['memory'] as Record<string, unknown> | undefined;
      if (mem) {
        const memUsed = pickNumber(mem, ['used', 'used_frmt']);
        const memTotal = pickNumber(mem, ['total', 'total_frmt']);
        if (memUsed !== undefined) metrics['memory.used'] = memUsed;
        if (memTotal !== undefined) metrics['memory.total'] = memTotal;
        if (memUsed !== undefined && memTotal !== undefined && memTotal > 0) {
          metrics['memory.percent'] = Math.round((memUsed / memTotal) * 100);
        }
      }
    }
  } catch {
    // best-effort
  }

  // Inventory (hostname, version, ARP + NDP neighbor tables) — slow-changing.
  // Served from the in-memory cache; the appliance is only re-polled when the
  // 15-min TTL elapses (see getInventory), so the API's 30s poll is cheap.
  const inventory = await getInventory(host, apiKey, apiSecret);
  if (inventory.hostname) metrics['hostname'] = inventory.hostname;
  if (inventory.version) metrics['version'] = inventory.version;
  if (inventory.arp.length > 0) metrics['arp'] = inventory.arp;
  if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;

  // Interface names (for the traffic table rows)
  try {
    const ifaces = await getInterfaces(host, apiKey, apiSecret);
    if (ifaces.ok && ifaces.data && typeof ifaces.data === 'object') {
      interfaces.push(...Object.keys(ifaces.data as Record<string, unknown>));
    }
  } catch {
    // best-effort
  }

  // Per-interface traffic (byte counters) from
  // /api/diagnostics/interface/get_interface_statistics.
  // Shape: { statistics: { "[igc0] / <mac>": { name, received-bytes, sent-bytes, ... } } }
  // Emitted as a nested object keyed by interface: { traffic: { igc0: { rx, tx } } }
  // so the webapp can render it as a table (rows = interfaces, columns = rx/tx).
  try {
    const stats = await getInterfaceStats(host, apiKey, apiSecret);
    if (stats.ok && stats.data && typeof stats.data === 'object') {
      const data = stats.data as Record<string, unknown>;
      const statistics = (data['statistics'] ?? data) as Record<string, unknown>;
      const traffic: Record<string, Record<string, number>> = {};
      for (const [rawKey, raw] of Object.entries(statistics)) {
        if (raw === null || typeof raw !== 'object') continue;
        const r = raw as Record<string, unknown>;
        // Prefer the interface's own `name` field; fall back to the key.
        const iface = typeof r['name'] === 'string' ? (r['name'] as string) : rawKey;
        const rx = pickNumber(r, ['received-bytes', 'received_bytes', 'rx', 'rxBytes', 'inOctets']);
        const tx = pickNumber(r, ['sent-bytes', 'sent_bytes', 'tx', 'txBytes', 'outOctets']);
        const entry: Record<string, number> = {};
        if (rx !== undefined) entry.rx = rx;
        if (tx !== undefined) entry.tx = tx;
        // Skip interfaces with no traffic at all — the appliance exposes
        // ~100 interfaces (vlans, wireguard peers, pfsync, ...) and most are
        // idle. Only active ones are worth showing in the table.
        if (Object.keys(entry).length > 0 && (entry.rx > 0 || entry.tx > 0)) traffic[iface] = entry;
        if (interfaces.length === 0) interfaces.push(iface);
        // MAC address per interface — important for later use (inventory).
        const mac = typeof r['address'] === 'string' ? (r['address'] as string) : undefined;
        if (mac) interfaceMacs.push({ name: iface, mac });
      }
      if (Object.keys(traffic).length > 0) metrics['traffic'] = traffic;
      if (interfaceMacs.length > 0) metrics['interfaces'] = interfaceMacs;
    }
  } catch {
    // best-effort
  }

  return { metrics, interfaces };
}

app.post('/monitoring', async (req, res) => {
  const { deviceId, apiKey, apiSecret, managementAddress } = req.body ?? {};

  try {
    const { metrics, interfaces } = await collectMetrics(managementAddress, apiKey, apiSecret);

    // Health: prefer the appliance's own status code (0=critical, 1=warning,
    // 2=ok); fall back to "did we collect anything at all".
    let health: Health = 'unknown';
    const sysStatus = metrics['metadata.system.status'];
    if (typeof sysStatus === 'number') {
      health = sysStatus === 2 ? 'ok' : sysStatus === 1 ? 'warning' : 'critical';
    } else if (Object.keys(metrics).length > 0) {
      health = 'ok';
    } else {
      health = 'critical';
    }

    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health,
      metrics,
      // Descriptors are generated DYNAMICALLY from the metrics actually
      // collected, so the UI always matches the data (works across OPNsense
      // versions and any plugin). The API persists these from /discover too.
      metricDescriptors: descriptorsFromMetrics(metrics),
    });
  } catch (err) {
    res.status(200).json({
      deviceId: deviceId ?? null,
      collectedAt: new Date().toISOString(),
      health: 'critical',
      metrics: {},
      error: (err as Error).message,
    });
  }
});

app.post('/config', async (req, res) => {
  const { action, payload, apiKey, apiSecret, managementAddress } = req.body ?? {};

  try {
    const result = await applyConfig({ action, payload }, managementAddress, apiKey, apiSecret);
    res.status(200).json({
      success: result.ok,
      result: { status: result.status, data: result.data },
    });
  } catch (err) {
    res.status(200).json({
      success: false,
      result: { error: (err as Error).message },
    });
  }
});

app.get('/inventory', async (req, res) => {
  const { apiKey, apiSecret, managementAddress } = req.query ?? {};

  try {
    const mAddress = typeof managementAddress === 'string' ? managementAddress : '';
    const mApiKey = typeof apiKey === 'string' ? apiKey : '';
    const mApiSecret = typeof apiSecret === 'string' ? apiSecret : '';

    const interfaces = await getInterfaces(mAddress, mApiKey, mApiSecret);
    const items = interfaces.data && typeof interfaces.data === 'object' ? interfaces.data : {};

    res.status(200).json({
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      interfaces: Object.entries(items as Record<string, unknown>).map(([name, details]) => ({
        name,
        details,
      })),
    });
  } catch (err) {
    res.status(200).json({
      capability: 'inventory',
      collectedAt: new Date().toISOString(),
      interfaces: [],
      error: (err as Error).message,
    });
  }
});

/**
 * Advertises this plugin over mDNS/DNS-SD so the UnifiedNetworkManager API
 * can discover it automatically. Uses service type `_unm-plugin._tcp`.
 *
 * mDNS multicast may be isolated by Docker bridge networks, so this is a
 * best-effort advertisement; the API also polls known plugin endpoints as a
 * fallback.
 */
function startMdnsAdvertising(): void {
  try {
    const bonjour = new Bonjour();
    bonjour.publish({
      name: PLUGIN_NAME,
      type: 'unm-plugin',
      port: PORT,
      txt: {
        uuid: PLUGIN_UUID,
        name: PLUGIN_NAME,
        version: PLUGIN_VERSION,
        vendors: PLUGIN_VENDORS.join(','),
        capabilities: PLUGIN_CAPABILITIES.join(','),
        endpoint: ADVERTISED_ENDPOINT,
        authType: PLUGIN_AUTH_TYPE,
      },
    });
    // eslint-disable-next-line no-console
    console.log(`[opnsense-plugin] advertising via mDNS as "${PLUGIN_NAME}" (${PLUGIN_UUID})`);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn('[opnsense-plugin] mDNS advertising unavailable, falling back to polling discovery only:', (err as Error).message);
  }
}

app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`[opnsense-plugin] listening on port ${PORT}`);
  startMdnsAdvertising();
});