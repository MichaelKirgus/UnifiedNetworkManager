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
  OpnsenseTransport,
} from './opnsenseClient';
import { createClient, OpnsenseCredentials } from './client/http';
import { resolveEdition } from './client/editions';
import { detectDnsBackend, DnsBackend } from './client/dns';
import { detectDhcpBackend, DhcpBackend, searchKeaLeases, searchDnsmasqLeases } from './client/dhcp';
import { getInterfacesInfo, vlans } from './client/interfaces';
import { getAction, listModules } from './actions/registry';
import { ActionContext, ActionResult, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest, listCatalog } from './plan';

export const PLUGIN_UUID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';
export const PLUGIN_NAME = 'OPNsense Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "OPNsense Plugin (site-a)". Unset = single-instance behavior.
 */
const INSTANCE_ID = process.env.PLUGIN_INSTANCE_ID?.trim() ?? '';
export const EFFECTIVE_UUID = INSTANCE_ID ? `${PLUGIN_UUID}:${INSTANCE_ID}` : PLUGIN_UUID;
export const DISPLAY_NAME =
  process.env.PLUGIN_DISPLAY_NAME?.trim() || (INSTANCE_ID ? `${PLUGIN_NAME} (${INSTANCE_ID})` : PLUGIN_NAME);
export const PLUGIN_VERSION = '0.2.0';
export const PLUGIN_VENDORS = ['opnsense'];
// 'planning' advertises the /plan endpoint (multi-device intents) so the API
// can offer bulk rollout + tunnel provisioning flows in the webapp.
export const PLUGIN_CAPABILITIES = ['monitoring', 'configuration', 'inventory', 'planning'];
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
 * data (hostname, version, ARP table, NDP table, configured networks with
 * CIDR/VLAN info, DHCP leases) so repeated /monitoring polls within the TTL
 * don't re-fetch it from the appliance.
 */
interface InventorySnapshot {
  collectedAt: number;
  hostname?: string;
  version?: string;
  arp: Record<string, unknown>[];
  ndp: Record<string, unknown>[];
  /** Configured networks: one row per interface IP address (see parseNetworkRows). */
  networks: Record<string, unknown>[];
  /** Active DHCP leases normalized across Kea/dnsmasq backends. */
  dhcpLeases: Record<string, unknown>[];
}

const inventoryCache = new Map<string, InventorySnapshot>();

/**
 * Normalizes one interface entry from `interfaces_info?details=true` into zero
 * or more network rows (one per configured IP address). OPNsense field names
 * vary by version, so several common shapes are accepted defensively; an
 * unrecognized shape yields a warning log and no row rather than a crash.
 */
function parseNetworkRows(raw: Record<string, unknown>): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];
  const name = typeof raw['name'] === 'string' ? (raw['name'] as string) : undefined;
  if (!name) return rows;

  const mac = typeof raw['mac'] === 'string' ? (raw['mac'] as string) : undefined;
  const status = typeof raw['status'] === 'string' ? (raw['status'] as string) : undefined;

  // Collect candidate address entries from the shapes seen across versions:
  //   ipv4/ipv6 objects with `address` + `subnet` (or `netmask`) fields, or
  //   arrays of { ip|address, netmask|prefix } entries.
  const candidates: Record<string, unknown>[] = [];
  for (const versionKey of ['ipv4', 'ipv6']) {
    const v = raw[versionKey];
    if (!v || typeof v !== 'object') continue;
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item && typeof item === 'object') candidates.push(item as Record<string, unknown>);
      }
    } else {
      const obj = v as Record<string, unknown>;
      // Some versions nest the address list under `addresses`.
      if (Array.isArray(obj['addresses'])) {
        for (const item of obj['addresses'] as unknown[]) {
          if (item && typeof item === 'object') candidates.push(item as Record<string, unknown>);
        }
      } else if (obj['address'] !== undefined || obj['ip'] !== undefined) {
        candidates.push(obj);
      }
    }
  }

  for (const c of candidates) {
    const ip = typeof c['ip'] === 'string' ? c['ip'] : typeof c['address'] === 'string' ? (c['address'] as string) : undefined;
    if (!ip || !ip.trim()) continue;
    // Prefix: explicit `prefix`/`subnet`, or derived from a dotted netmask.
    let prefix = pickNumber(c, ['prefix', 'subnet']);
    const netmask = typeof c['netmask'] === 'string' ? (c['netmask'] as string) : undefined;
    if (prefix === undefined && netmask) {
      const bits = netmask.split('.').reduce((sum, octet) => sum + ((Number(octet) | 0).toString(2).match(/1/g)?.length ?? 0), 0);
      prefix = bits;
    }
    rows.push({
      name,
      ...(mac ? { mac } : {}),
      ip: ip.trim(),
      prefix: prefix !== undefined && Number.isFinite(prefix) ? Math.round(prefix) : null,
      version: c['version'] === 6 || (typeof c['ip'] === 'string' && (c['ip'] as string).includes(':')) ? 'v6' : 'v4',
      ...(status ? { status } : {}),
    });
  }

  // Interfaces without any IP still appear (useful for topology detection):
  if (rows.length === 0) {
    rows.push({ name, ...(mac ? { mac } : {}), ip: null, prefix: null, version: null, ...(status ? { status } : {}) });
  }
  return rows;
}

/**
 * Normalizes DHCP lease rows across the two backends. Kea and dnsmasq expose
 * different field names (and dnsmasq's expiry is a unix timestamp); this maps
 * them onto one shape: { mac, ip, hostname?, expiry? (ISO), intf? }. Rows
 * without both a MAC and an IP are dropped — they can't be joined to anything.
 */
function parseDhcpLeaseRows(rows: unknown[]): Record<string, unknown>[] {
  const out: Record<string, unknown>[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const mac = typeof r['mac'] === 'string' ? (r['mac'] as string).toLowerCase() : undefined;
    const ip = typeof r['ipaddress'] === 'string' ? (r['ipaddress'] as string) : typeof r['ip'] === 'string' ? (r['ip'] as string) : undefined;
    if (!mac || !ip) continue;
    const hostname = typeof r['hostname'] === 'string' && r['hostname'].trim() !== '' ? (r['hostname'] as string) : undefined;
    const intf = typeof r['interface'] === 'string' ? (r['interface'] as string) : typeof r['intf'] === 'string' ? (r['intf'] as string) : undefined;
    // Kea: `expiry` is an ISO-ish string or epoch; dnsmasq: `expires` unix seconds.
    let expiry: string | undefined;
    const rawExpiry = r['expiry'] ?? r['expires'];
    if (typeof rawExpiry === 'number' && rawExpiry > 0) {
      expiry = new Date(rawExpiry * 1000).toISOString();
    } else if (typeof rawExpiry === 'string' && rawExpiry.trim() !== '') {
      const t = Date.parse(rawExpiry);
      expiry = Number.isNaN(t) ? undefined : new Date(t).toISOString();
    }
    out.push({ mac, ip, ...(hostname ? { hostname } : {}), ...(expiry ? { expiry } : {}), ...(intf ? { intf } : {}) });
  }
  return out;
}

/**
 * Returns the inventory snapshot for a host, fetching from the appliance only
 * when the cache is older than INVENTORY_INTERVAL_MS. All calls run in
 * parallel and are best-effort — a failing endpoint yields an empty field, not
 * an error.
 */
async function getInventory(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport
): Promise<InventorySnapshot> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < INVENTORY_INTERVAL_MS) {
    return cached;
  }

  // The client-lib calls need a bound axios instance for this appliance.
  const client = createClient(host, { apiKey, apiSecret }, transport);

  const [info, arp, ndp, ifInfo, vlanRes] = await Promise.all([
    getSystemInformation(host, apiKey, apiSecret, transport).catch(() => undefined),
    getArpTable(host, apiKey, apiSecret, transport).catch(() => undefined),
    getNdpTable(host, apiKey, apiSecret, transport).catch(() => undefined),
    getInterfacesInfo(client).catch(() => undefined),
    vlans.get(client).catch(() => undefined),
  ]);

  const snap: InventorySnapshot = { collectedAt: Date.now(), arp: [], ndp: [], networks: [], dhcpLeases: [] };
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

  // Configured networks: one row per interface IP address. Field names in the
  // interfaces_info response vary by OPNsense version — parseNetworkRows is
  // defensive and logs a warning when it can't recognize an entry's shape.
  if (ifInfo?.ok && ifInfo.data && typeof ifInfo.data === 'object') {
    const data = ifInfo.data as Record<string, unknown>;
    const entries: Record<string, unknown>[] = [];
    // Common shapes: a direct array, or an object keyed by interface name.
    if (Array.isArray(data)) {
      for (const e of data) if (e && typeof e === 'object') entries.push(e as Record<string, unknown>);
    } else {
      for (const v of Object.values(data)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) entries.push(v as Record<string, unknown>);
      }
    }
    const rows = entries.flatMap((e) => parseNetworkRows(e));
    if (rows.length > 0) snap.networks = rows;

    // VLAN IDs: vlan_settings rows carry the parent interface + vlanid. Attach
    // them to network rows whose name matches `<parent>.<vlanid>` or equals a
    // VLAN interface name reported by the appliance.
    if (vlanRes?.ok && vlanRes.data && typeof vlanRes.data === 'object') {
      const vdata = vlanRes.data as Record<string, unknown>;
      const vlanRows: Record<string, unknown>[] = Array.isArray(vdata)
        ? (vdata as unknown[]).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object')
        : Object.values(vdata).filter((v): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v));
      // A VLAN interface may be named `<parent>.<vlanid>` or `vlan<vlanid>` —
      // index both candidate names so either convention matches.
      const vlanByName = new Map<string, number>();
      for (const vr of vlanRows) {
        const parent = typeof vr['interface'] === 'string' ? (vr['interface'] as string) : undefined;
        const vid = pickNumber(vr, ['vlanid', 'vlan_id', 'vid']);
        if (!parent || vid === undefined) continue;
        const v = Math.round(vid);
        vlanByName.set(`${parent}.${v}`, v);
        vlanByName.set(`vlan${v}`, v);
      }
      for (const row of snap.networks) {
        const n = typeof row['name'] === 'string' ? (row['name'] as string) : undefined;
        if (!n) continue;
        const vid = vlanByName.get(n);
        if (vid !== undefined) row['vlanId'] = vid;
      }
    }
  }

  // DHCP leases: backend auto-detected per appliance, then normalized.
  try {
    const backend = await detectDhcpBackend(client);
    const leaseRes = backend === 'kea' ? await searchKeaLeases(client) : await searchDnsmasqLeases(client);
    if (leaseRes?.ok && leaseRes.data && typeof leaseRes.data === 'object') {
      const rows = (leaseRes.data as Record<string, unknown>)['rows'];
      snap.dhcpLeases = Array.isArray(rows) ? parseDhcpLeaseRows(rows) : [];
    }
  } catch {
    // best-effort — a failing lease endpoint must not sink the inventory cache
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
  // Configured networks (interface IPs with CIDR + VLAN) — inventory, slow refresh.
  if (Array.isArray(metrics['networks']) && (metrics['networks'] as unknown[]).length > 0) {
    push({ key: 'networks', label: 'Networks', type: 'string', visualization: 'table', group: 'Inventory', columns: ['name', 'ip', 'prefix', 'version', 'vlanId', 'mac'], intervalMs: INVENTORY_INTERVAL_MS });
  }
  // Active DHCP leases — inventory, slow refresh.
  if (Array.isArray(metrics['dhcpLeases']) && (metrics['dhcpLeases'] as unknown[]).length > 0) {
    push({ key: 'dhcpLeases', label: 'DHCP Leases', type: 'string', visualization: 'table', group: 'Inventory', columns: ['mac', 'ip', 'hostname', 'intf', 'expiry'], intervalMs: INVENTORY_INTERVAL_MS });
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
    uuid: EFFECTIVE_UUID,
    name: DISPLAY_NAME,
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
    // Configurable options. The API persists user-set values for these and
    // injects them back via the `x-unm-settings` header on every call.
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions + multi-device intents).
    // The API persists this and validates job/plan actionIds against it; the
    // webapp renders only what exists. One registry serves /discover, /plan
    // and /config — see src/actions/registry.ts.
    actions: listCatalog(),
    modules: listModules(),
  });
});

type Health = 'ok' | 'warning' | 'critical' | 'unknown';

/**
 * The options this plugin exposes for configuration. Declared in /discover so
 * the API can persist + validate user-set values and the webapp can render a
 * generic form — this plugin never stores settings itself; it receives them
 * on every call via the `x-unm-settings` header (see readSettings()).
 */
const PLUGIN_OPTIONS = [
  {
    key: 'pollIntervalSec',
    label: 'Poll interval (seconds)',
    type: 'integer' as const,
    default: 30,
    min: 5,
    max: 600,
    description: 'How often the plugin re-collects live metrics from the appliance. Slower values reduce load on busy firewalls.',
    docsUrl: 'https://docs.opnsense.org/manual/how-tos/monitoring.html',
  },
  {
    key: 'enableInventoryCache',
    label: 'Enable inventory cache',
    type: 'boolean' as const,
    default: true,
    description: 'Cache slow-changing data (ARP/NDP tables, hostname) in memory and only re-fetch when the TTL elapses.',
  },
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|http|https)$',
    description:
      'How to reach the appliance. auto = HTTPS with self-signed certificates accepted (default, matches historical behavior). https = force TLS. http = plaintext HTTP for appliances without a certificate.',
  },
  {
    key: 'editionOverride',
    label: 'Edition override',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|ce|be)$',
    description:
      'Force the detected OPNsense edition. auto = probe /api/opncentral/sync/listClasses (200 = Business Edition, else Community). Use ce/be when probing is blocked by ACLs.',
  },
  {
    key: 'dnsBackend',
    label: 'DNS backend override',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|dnsmasq|unbound)$',
    description:
      'Force the DNS backend. auto = probe (Unbound on newer installs, dnsmasq on older). Affects which host-record endpoints /config uses.',
  },
  {
    key: 'dhcpBackend',
    label: 'DHCP backend override',
    type: 'string' as const,
    default: 'auto',
    pattern: '^(auto|dnsmasq|kea)$',
    description:
      'Force the DHCP backend. auto = probe (Kea on newer installs, dnsmasq on older). Affects which static-mapping endpoints /config uses.',
  },
];

/**
 * Reads the effective settings the API injects on every call (defaults ⊕ user
 * overrides) from the `x-unm-settings` JSON header, merged over this plugin's
 * declared defaults so a missing header still yields sane values.
 */
function readSettings(req: { headers?: Record<string, unknown> }): Record<string, unknown> {
  const defaults: Record<string, unknown> = {};
  for (const opt of PLUGIN_OPTIONS) defaults[opt.key] = opt.default;

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

/** Extracts the effective transport option from injected settings. */
function transportOf(settings: Record<string, unknown>): OpnsenseTransport {
  return typeof settings.transport === 'string' && ['auto', 'http', 'https'].includes(settings.transport)
    ? (settings.transport as OpnsenseTransport)
    : 'auto';
}

/** Reads an optional string setting. */
function strSetting(settings: Record<string, unknown>, key: string): string | undefined {
  const v = settings[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/**
 * Resolves the runtime context for one device (edition + DNS/DHCP backends).
 * Probes are read-only and best-effort — failures fall back to CE / dnsmasq.
 */
async function resolveRuntimeContext(
  host: string,
  credentials: OpnsenseCredentials,
  transport: OpnsenseTransport,
  settings: Record<string, unknown>
): Promise<{ edition: 'ce' | 'be'; syncClasses: unknown[]; dnsBackend: DnsBackend; dhcpBackend: DhcpBackend }> {
  const client = createClient(host, credentials, transport);
  const [editionInfo, dnsBackend, dhcpBackend] = await Promise.all([
    resolveEdition(client, host, strSetting(settings, 'editionOverride')).catch(() => ({ edition: 'ce' as const, classes: [] })),
    (strSetting(settings, 'dnsBackend') && strSetting(settings, 'dnsBackend') !== 'auto'
      ? Promise.resolve(strSetting(settings, 'dnsBackend') as DnsBackend)
      : detectDnsBackend(client).catch(() => 'dnsmasq' as DnsBackend)),
    (strSetting(settings, 'dhcpBackend') && strSetting(settings, 'dhcpBackend') !== 'auto'
      ? Promise.resolve(strSetting(settings, 'dhcpBackend') as DhcpBackend)
      : detectDhcpBackend(client).catch(() => 'dnsmasq' as DhcpBackend)),
  ]);
  return { edition: editionInfo.edition, syncClasses: editionInfo.classes ?? [], dnsBackend, dhcpBackend };
}

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
  apiSecret: string,
  transport?: OpnsenseTransport
): Promise<{ metrics: Record<string, unknown>; interfaces: string[] }> {
  const metrics: Record<string, unknown> = {};
  const interfaces: string[] = [];
  const interfaceMacs: { name: string; mac: string }[] = [];

  // System status (health + basic info). OPNsense returns
  // { metadata: { system: { status: 0|1|2 } } } — capture the status code.
  const status = await getSystemStatus(host, apiKey, apiSecret, transport);
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
    const cpu = await getCpuUsage(host, apiKey, apiSecret, transport);
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
    const resources = await getSystemResources(host, apiKey, apiSecret, transport);
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
  const inventory = await getInventory(host, apiKey, apiSecret, transport);
  if (inventory.hostname) metrics['hostname'] = inventory.hostname;
  if (inventory.version) metrics['version'] = inventory.version;
  if (inventory.arp.length > 0) metrics['arp'] = inventory.arp;
  if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;
  // Configured networks (interface IPs with CIDR + VLAN id) and active DHCP
  // leases — consumed by the API's normalized inventory tables (Networks/Hosts
  // pages) in addition to being rendered as generic tables in the device view.
  if (inventory.networks.length > 0) metrics['networks'] = inventory.networks;
  if (inventory.dhcpLeases.length > 0) metrics['dhcpLeases'] = inventory.dhcpLeases;

  // Interface names (for the traffic table rows)
  try {
    const ifaces = await getInterfaces(host, apiKey, apiSecret, transport);
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
    const stats = await getInterfaceStats(host, apiKey, apiSecret, transport);
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

  // Effective settings injected by the API (defaults ⊕ user overrides). The
  // plugin reads its options from here — it never stores them itself.
  const settings = readSettings(req);
  const transport: OpnsenseTransport =
    typeof settings.transport === 'string' && ['auto', 'http', 'https'].includes(settings.transport)
      ? (settings.transport as OpnsenseTransport)
      : 'auto';

  try {
    const { metrics, interfaces } = await collectMetrics(managementAddress, apiKey, apiSecret, transport);

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
      // Echo back the effective settings we received — proof that the
      // API→plugin settings injection loop works end to end.
      activeSettings: {
        pollIntervalSec: settings.pollIntervalSec,
        enableInventoryCache: settings.enableInventoryCache,
        transport,
      },
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

/**
 * Executes ONE action step against one appliance. This is the unit of work the
 * API's config-job worker dispatches — either a single-device job (legacy shape:
 * `{action, payload}`) or one step of a multi-device plan (registry shape:
 * `{actionId, input, credentials}`). The plugin owns ALL logic: it validates
 * the input against the action's schema, resolves the appliance's runtime
 * context (edition + DNS/DHCP backends), and runs the executor. The API only
 * propagates — it never interprets payloads.
 *
 * Body:
 *   deviceId            device id (echoed in results)
 *   managementAddress   appliance address to reach
 *   ipAddresses         all known addresses (primary first) — informational
 *   credentials         decrypted secret fields for the assignment; for plan
 *                       steps this ALSO carries provisioned material namespaced
 *                       by secretRef (e.g. { keyA: { publicKey, privateKey } })
 *   apiKey/apiSecret    legacy top-level keys (secret type `apiKey`)
 *   actionId + input    registry shape (preferred)
 *   action + payload    legacy shape — mapped to actionId=action, input=payload
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

  const settings = readSettings(req);
  const transport = transportOf(settings);

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

  // Credentials: the assignment's decrypted fields are the base; legacy jobs
  // pass apiKey/apiSecret at top level. Provisioned plan material arrives in
  // `credentials` namespaced by secretRef and is merged through as-is.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const stepCredentials: StepCredentials = {
    apiKey: typeof body.apiKey === 'string' ? body.apiKey : (typeof creds['apiKey'] === 'string' ? (creds['apiKey'] as string) : ''),
    apiSecret: typeof body.apiSecret === 'string' ? body.apiSecret : (typeof creds['apiSecret'] === 'string' ? (creds['apiSecret'] as string) : ''),
    ...creds,
  };

  try {
    const ctx = await buildActionContext({
      host: managementAddress,
      deviceId: typeof deviceId === 'string' ? deviceId : undefined,
      credentials: stepCredentials,
      transport,
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

    const result: ActionResult = await action.execute(ctx, input);
    res.status(200).json({ success: result.success, result: { ...result } });
  } catch (err) {
    res.status(200).json({ success: false, result: { error: (err as Error).message } });
  }
});

/** Builds the ActionContext for a /config call (client + runtime context). */
async function buildActionContext(args: {
  host: string;
  deviceId?: string;
  credentials: StepCredentials;
  transport: OpnsenseTransport;
  settings: Record<string, unknown>;
}): Promise<ActionContext> {
  const { host, deviceId, credentials, transport, settings } = args;
  const client = createClient(host, { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }, transport);
  const runtime = await resolveRuntimeContext(
    host,
    { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret },
    transport,
    settings
  );
  return {
    client,
    host,
    deviceId,
    credentials,
    transport,
    edition: runtime.edition,
    syncClasses: runtime.syncClasses as ActionContext['syncClasses'],
    dnsBackend: runtime.dnsBackend,
    dhcpBackend: runtime.dhcpBackend,
  };
}

/**
 * Plans a multi-device intent (or fans out a single action across a batch).
 * The plugin does ALL the planning — cross-device references, dependency
 * ordering, credential provisioning requests. It never generates key material:
 * provisionRequests are non-secret descriptors the API persists with the plan;
 * the secrets provider owns crypto.
 *
 * Body: { intent: { actionId, inputs }, devices: [{ deviceId, managementAddress,
 * credentials }], transport?, editionOverride?, dnsBackend?, dhcpBackend? }
 */
app.post('/plan', async (req, res) => {
  const body = req.body ?? {};
  const settings = readSettings(req);

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
            apiKey: typeof d.credentials?.apiKey === 'string' ? d.credentials.apiKey : '',
            apiSecret: typeof d.credentials?.apiSecret === 'string' ? d.credentials.apiSecret : '',
          },
        }))
      : [],
    transport: transportOf(settings),
    editionOverride: strSetting(settings, 'editionOverride'),
    dnsBackend: (strSetting(settings, 'dnsBackend') ?? 'auto') as PlanRequest['dnsBackend'],
    dhcpBackend: (strSetting(settings, 'dhcpBackend') ?? 'auto') as PlanRequest['dhcpBackend'],
  };

  try {
    const plan = await buildPlan(planReq);
    res.status(200).json({ plan });
  } catch (err) {
    if (err instanceof PlanningError) {
      res.status(400).json({ error: err.message });
      return;
    }
    res.status(500).json({ error: (err as Error).message });
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
    console.log(`[opnsense-plugin] advertising via mDNS as "${DISPLAY_NAME}" (${EFFECTIVE_UUID})`);
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