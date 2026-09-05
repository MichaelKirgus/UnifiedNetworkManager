import path from 'path';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  INVENTORY_INTERVAL_MS,
  createPluginLogger,
  createPluginServer,
  pickNumber,
  pickString,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  PortRow,
  StateRequestBody,
} from '@unm/plugin-sdk';
import {
  getSystemStatus,
  getSystemResources,
  getSystemInformation,
  getSystemDisk,
  getInterfaces,
  getInterfaceStats,
  getCpuUsage,
  getArpTable,
  getNdpTable,
  OpnsenseTransport,
} from './opnsenseClient';
import { DEVICE_MODELS } from './deviceModels';
import { createClient, OpnsenseCredentials } from './client/http';
import { resolveEdition } from './client/editions';
import { detectDnsBackend, DnsBackend } from './client/dns';
import { detectDhcpBackend, DhcpBackend, searchKeaLeases, searchDnsmasqLeases } from './client/dhcp';
import { getInterfacesInfo, vlans } from './client/interfaces';
import { searchGateways } from './client/routes';
import { collectTunnels, attachTunnelRates, enrichTunnelsWithLiveState, TunnelRow } from './tunnels';
import { collectRoutes, deriveConnectedAndDefaultRoutes, enrichRoutesWithGatewayStatus, RouteRow } from './routes';
import { collectFirewallRules, fetchFilterRuleStats } from './firewall';
import { collectZfsViaSsh } from './zfsSsh';
import { getAction, listModules } from './actions/registry';
import { ActionContext, ActionResult, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest, listCatalog } from './plan';
import { InventorySnapshot } from './inventoryTypes';
import { buildOpnsenseState } from './state';

export const PLUGIN_UUID = 'b0e6c8a2-4f1e-4a3d-9c7b-1a2b3c4d5e6f';
export const PLUGIN_NAME = 'OPNsense Plugin';

/**
 * Multi-instance support: set `PLUGIN_INSTANCE_ID` (e.g. "site-a") to run several
 * instances of the same plugin type — each advertises a distinct identity
 * (`<uuid>:<instanceId>`) so the API registers them as separate plugins.
 * `PLUGIN_DISPLAY_NAME` optionally overrides the advertised name; without it,
 * the instance id is appended: "OPNsense Plugin (site-a)". Unset = single-instance behavior.
 * (Convention implemented in @unm/plugin-sdk's resolvePluginIdentity.)
 */
const identity = resolvePluginIdentity({
  uuid: PLUGIN_UUID,
  name: PLUGIN_NAME,
  version: '0.2.0',
  vendors: ['opnsense'],
  // 'planning' advertises the /plan endpoint (multi-device intents) so the API
  // can offer bulk rollout + tunnel provisioning flows in the webapp.
  // 'deviceState' advertises POST /state — the dynamic document behind the
  // per-device Config page (interfaces with live status + system power actions).
  // 'ssh' = optional SSH data path for ZFS pool/dataset inventory (the API has
  // no ZFS listing) — only used when an `ssh` credential slot is bound.
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'deviceState', 'ssh'],
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
 *
 * The type itself lives in @unm/plugin-sdk (imported above).
 */

/**
 * Refresh cadence per metric class. Live metrics (CPU, memory, traffic) are
 * cheap and change fast → 30s. Inventory (ARP/NDP tables, interface MACs,
 * hostname, version) changes rarely → 15 min. The plugin caches inventory in
 * memory and only re-fetches from the appliance when the TTL elapses, so the
 * API's 30s poll never re-hammers the device. This is what makes the system
 * scale to many devices: appliance load is bounded by intervalMs, not by the
 * number of API polls.
 */
const LIVE_INTERVAL_MS = 30_000; // (INVENTORY_INTERVAL_MS comes from @unm/plugin-sdk)

/**
 * In-memory inventory cache, keyed by management host. Holds the slow-changing
 * data (hostname, version, ARP table, NDP table, configured networks with
 * CIDR/VLAN info, DHCP leases) so repeated /monitoring polls within the TTL
 * don't re-fetch it from the appliance. The shape lives in ./inventoryTypes
 * so the /state builder can share it without a circular import.
 */
const inventoryCache = new Map<string, InventorySnapshot>();
/** In-flight cold collections per host — concurrent /monitoring calls share ONE
 * fetch instead of each starting its own (see getInventory). */
const inventoryInFlight = new Map<string, Promise<InventorySnapshot>>();

/**
 * Normalizes one interface entry from `interfaces_info?details=true` into zero
 * or more network rows (one per configured IP address). OPNsense has no explicit
 * "network" object — a network is IMPLICIT in an interface assignment's IP +
 * prefix, so this converts each assigned address into a CIDR row.
 *
 * Two shape families are accepted defensively:
 *   - recordset rows (the real /api/interfaces/overview/interfaces_info via
 *     searchRecordsetBase): `identifier` (lan/wan/opt1), `macaddr`, `status`,
 *     `vlan_tag`, and ipv4/ipv6 arrays of { ipaddr: "192.168.1.1/24" } entries.
 *     Unassigned interfaces (no `config`) are skipped — they aren't networks.
 *   - legacy shapes keyed by `name` with separate address/subnet/netmask fields.
 */
function parseNetworkRows(raw: Record<string, unknown>): Record<string, unknown>[] {
  const rows: Record<string, unknown>[] = [];

  // Recordset rows carry a `config` object only when the interface is ASSIGNED,
  // plus its logical identifier (lan/wan/opt1). Unassigned interfaces (no
  // config, no identifier, no name) are not networks — they yield no row at
  // all. Legacy shapes are keyed by `name`. The identifier wins over any other
  // name field so rows stay joinable with ARP/NDP/DHCP interface names.
  const hasConfig = raw['config'] !== undefined;
  const id = typeof raw['identifier'] === 'string' ? (raw['identifier'] as string).trim() : '';
  const legacyName = typeof raw['name'] === 'string' ? (raw['name'] as string).trim() : '';
  if (!hasConfig && !id && !legacyName) return rows;

  let name: string | undefined;
  if (hasConfig || id !== '') {
    const desc = typeof raw['description'] === 'string' ? (raw['description'] as string).trim() : '';
    name = id || desc;
  } else {
    name = legacyName;
  }
  if (!name) return rows;

  const mac = pickString(raw, ['mac', 'macaddr']);
  const status = typeof raw['status'] === 'string' ? (raw['status'] as string) : undefined;
  // VLAN: recordset rows carry the tag directly (`vlan_tag`); the vlan_settings
  // cross-match in getInventory fills in what this can't see.
  const vlanTag = pickNumber(raw, ['vlan_tag', 'vlanId']);

  // Collect candidate address entries per protocol family so the version is
  // known from the key itself (ipv4/ipv6), not guessed from the address text.
  const candidates: { entry: Record<string, unknown>; version: 'v4' | 'v6' }[] = [];
  for (const versionKey of ['ipv4', 'ipv6'] as const) {
    const v = raw[versionKey];
    if (!v || typeof v !== 'object') continue;
    const version: 'v4' | 'v6' = versionKey === 'ipv6' ? 'v6' : 'v4';
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item && typeof item === 'object') candidates.push({ entry: item as Record<string, unknown>, version });
      }
    } else {
      const obj = v as Record<string, unknown>;
      // Some versions nest the address list under `addresses`.
      if (Array.isArray(obj['addresses'])) {
        for (const item of obj['addresses'] as unknown[]) {
          if (item && typeof item === 'object') candidates.push({ entry: item as Record<string, unknown>, version });
        }
      } else if (obj['address'] !== undefined || obj['ip'] !== undefined) {
        candidates.push({ entry: obj, version });
      }
    }
  }

  for (const { entry: c, version } of candidates) {
    let ip: string | undefined;
    let prefix: number | undefined;
    // Real recordset entries pack the address as a CIDR string ("192.168.1.1/24").
    const cidr = typeof c['ipaddr'] === 'string' ? (c['ipaddr'] as string) : undefined;
    if (cidr && cidr.includes('/')) {
      const [addr, bits] = cidr.split('/');
      ip = addr.trim();
      const p = Number(bits);
      prefix = Number.isFinite(p) ? Math.round(p) : undefined;
    } else {
      // Legacy entries: separate fields — explicit `prefix`/`subnet`, or a
      // dotted netmask converted to its bit count.
      ip = typeof c['ip'] === 'string' ? (c['ip'] as string) : typeof c['address'] === 'string' ? (c['address'] as string) : undefined;
      prefix = pickNumber(c, ['prefix', 'subnet']);
      const netmask = typeof c['netmask'] === 'string' ? (c['netmask'] as string) : undefined;
      if (prefix === undefined && netmask) {
        prefix = netmask.split('.').reduce((sum, octet) => sum + ((Number(octet) | 0).toString(2).match(/1/g)?.length ?? 0), 0);
      }
    }
    if (!ip || !ip.trim()) continue;
    rows.push({
      name,
      ...(mac ? { mac } : {}),
      ip: ip.trim(),
      prefix: prefix !== undefined && Number.isFinite(prefix) ? Math.round(prefix) : null,
      version,
      ...(status ? { status } : {}),
      ...(vlanTag !== undefined ? { vlanId: vlanTag } : {}),
    });
  }

  // Assigned interfaces without any IP still appear (useful for topology detection):
  if (rows.length === 0) {
    rows.push({ name, ...(mac ? { mac } : {}), ip: null, prefix: null, version: null, ...(status ? { status } : {}), ...(vlanTag !== undefined ? { vlanId: vlanTag } : {}) });
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
 * Parses the ZFS pool status + USB storage responses into Storage-page rows.
 * Both endpoints are version-dependent and only exist on appliances that have
 * the respective hardware — a missing/404 response yields empty arrays (the
 * caller then omits the metric keys entirely). Field names vary across
 * OPNsense releases, so every read is defensive multi-key.
 */
/** Parses OPNsense's base-10 human size strings ("5.2G", "800M") into bytes —
 * the SAME format + units (K=1000) the appliance's own Disk widget uses in
 * `_convertToBytes`. Accepts a raw number too, for defensive multi-shape reads. */
function parseBase10Bytes(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v);
  if (typeof v !== 'string') return null;
  const m = v.trim().match(/^(\d+(?:\.\d+)?)([BKMGTPE]?)$/i);
  if (!m) return null;
  const num = parseFloat(m[1]);
  if (!Number.isFinite(num)) return null;
  const unit = (m[2] ?? '').toUpperCase();
  const mult: Record<string, number> = { '': 1, B: 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };
  return Math.round(num * (mult[unit] ?? 1));
}

/** Maps OPNsense's mounted-filesystem `type` to a Storage-page filesystem type.
 * OPNsense exposes NO ZFS pool/dataset tree — only the mounted root (`zfs`) and
 * any other mounts, so the zfs root is surfaced as the top-level `zfs-pool`. */
function opnsenseFsType(raw: string | null): string {
  switch ((raw ?? '').toLowerCase()) {
    case 'zfs': return 'zfs-pool';
    case 'ext2':
    case 'ext3':
    case 'ext4': return 'ext4';
    case 'squashfs': return 'squashfs';
    default: return 'other'; // ufs and anything else — no dedicated badge
  }
}

/**
 * Parses the mounted-filesystem overview (`/api/diagnostics/system/system_disk`)
 * into Storage-page rows. This is the ONLY storage data OPNsense's API exposes
 * (there is no ZFS pool/dataset listing endpoint). A missing/404 response yields
 * empty arrays — the caller then omits the metric keys entirely. Size fields are
 * base-10 human strings ("5.2G"); `blocks` = total capacity, `used`/`available`
 * as consumed by OPNsense's own Disk widget.
 */
function collectStorage(
  diskRes: { ok: boolean; data?: unknown } | undefined
): { filesystems: Record<string, unknown>[]; disks: Record<string, unknown>[] } {
  const filesystems: Record<string, unknown>[] = [];
  if (!diskRes?.ok) return { filesystems, disks: [] };

  // system_disk returns `{ devices: [...] }` (not a recordset). Be defensive.
  const d = diskRes.data as Record<string, unknown> | undefined;
  const rows = Array.isArray(d?.['devices']) ? (d!['devices'] as unknown[]) : [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const name = pickString(r, ['device', 'name']);
    if (!name) continue;
    // `blocks` = total capacity; `used`/`available` are base-10 human strings.
    const sizeBytes = parseBase10Bytes(r['blocks']);
    const usedBytes = parseBase10Bytes(r['used']);
    const freeBytes = parseBase10Bytes(r['available']);
    filesystems.push({
      name,
      type: opnsenseFsType(pickString(r, ['type']) ?? null),
      mountpoint: pickString(r, ['mountpoint', 'mounted-on']) ?? null,
      sizeBytes: sizeBytes ?? null,
      usedBytes: usedBytes ?? (sizeBytes !== null && freeBytes !== null ? sizeBytes - freeBytes : null),
      freeBytes: freeBytes ?? (sizeBytes !== null && usedBytes !== null ? Math.max(0, sizeBytes - usedBytes) : null),
      status: 'online', // present in the mounted list = active + readable
    });
  }

  return { filesystems, disks: [] };
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
  transport?: OpnsenseTransport,
  credentials?: Record<string, unknown>
): Promise<InventorySnapshot> {
  const cached = inventoryCache.get(host);
  if (cached && Date.now() - cached.collectedAt < INVENTORY_INTERVAL_MS) {
    return cached;
  }
  // A cold collection on a busy appliance can take LONGER than the API's hard
  // 10s poll budget — without this guard every timed-out poll would kick off its
  // own full re-collection, stacking N concurrent fetches against one box (which
  // only makes each of them slower). Share ONE in-flight promise per host so the
  // slow collection completes and warms the cache; later polls are fast.
  const inFlight = inventoryInFlight.get(host);
  if (inFlight) return inFlight;
  const p = collectInventory(host, apiKey, apiSecret, transport, credentials).finally(() => {
    inventoryInFlight.delete(host);
  });
  inventoryInFlight.set(host, p);
  return p;
}

/** Performs one full cold inventory collection (all endpoints, best-effort).
 * `credentials` carries the assignment's decrypted fields incl. bound slots —
 * used ONLY for the optional SSH ZFS enrichment (slots.ssh). */
async function collectInventory(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  credentials?: Record<string, unknown>
): Promise<InventorySnapshot> {
  // The client-lib calls need a bound axios instance for this appliance.
  const client = createClient(host, { apiKey, apiSecret }, transport);

  const [info, arp, ndp, ifInfo, vlanRes, gwRes, diskRes] = await Promise.all([
    getSystemInformation(host, apiKey, apiSecret, transport).catch(() => undefined),
    getArpTable(host, apiKey, apiSecret, transport).catch(() => undefined),
    getNdpTable(host, apiKey, apiSecret, transport).catch(() => undefined),
    getInterfacesInfo(client).catch(() => undefined),
    vlans.get(client).catch(() => undefined),
    searchGateways(client).catch(() => undefined),
    // Storage (best-effort — the only storage data OPNsense exposes):
    getSystemDisk(host, apiKey, apiSecret, transport).catch(() => undefined),
  ]);

  // Raw interfaces_info entries — kept for the PPPoE tunnel detector (which
  // needs the interface TYPE fields that parseNetworkRows discards).
  let ifEntries: Record<string, unknown>[] = [];
  const snap: InventorySnapshot = { collectedAt: Date.now(), arp: [], ndp: [], networks: [], dhcpLeases: [], tunnels: [], routes: [], firewallRules: null, gateways: [], filesystems: [], disks: [] };
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
    // Real OPNsense shape: searchRecordsetBase wraps the interface list in a
    // recordset ({ rows: [...], total }). Fallbacks for other shapes: a direct
    // array, or an object keyed by interface name.
    if (Array.isArray(data['rows'])) {
      for (const e of data['rows'] as unknown[]) if (e && typeof e === 'object') ifEntries.push(e as Record<string, unknown>);
    } else if (Array.isArray(data)) {
      for (const e of data) if (e && typeof e === 'object') ifEntries.push(e as Record<string, unknown>);
    } else {
      for (const v of Object.values(data)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) ifEntries.push(v as Record<string, unknown>);
      }
    }
    const rows = ifEntries.flatMap((e) => parseNetworkRows(e));
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
        if (row['vlanId'] !== undefined) continue; // recordset rows carry vlan_tag directly
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

  // Tunnels (WireGuard/OpenVPN/IPsec/PPPoE/GRE) — slow-changing like networks.
  // PPPoE rows reuse the interfaces_info entries collected above; the other
  // types hit their own endpoints. Each section is independent and best-effort.
  try {
    snap.tunnels = await collectTunnels(client, ifEntries);
  } catch {
    // best-effort — a failing tunnel endpoint must not sink the inventory cache
  }

  // Static routes (routes/routes module) — slow-changing like networks.
  try {
    snap.routes = await collectRoutes(client);
  } catch {
    // best-effort — a failing route endpoint must not sink the inventory cache
  }

  // Firewall rules (filter + NAT kinds) — slow-changing config. null on failure:
  // /monitoring then omits the key entirely so the API keeps previously stored
  // rows instead of wiping them (present-but-empty is authoritative there).
  try {
    snap.firewallRules = await collectFirewallRules(client);
  } catch {
    // best-effort — a failing firewall endpoint must not sink the inventory cache
  }

  // Configured gateways (routing/settings) — used to derive default-route rows
  // so hosts that only use their WAN gateway still appear on the Routes page.
  if (gwRes?.ok && gwRes.data && typeof gwRes.data === 'object') {
    const d = gwRes.data as Record<string, unknown>;
    const rows = Array.isArray(d['rows']) ? d['rows'] : Array.isArray(gwRes.data) ? gwRes.data : Object.values(d);
    snap.gateways = (rows as unknown[]).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
  }

  // Storage (mounted filesystems) — the only storage data OPNsense's API
  // exposes; empty array when the endpoint is missing/404 or the key lacks access.
  const storage = collectStorage(diskRes);
  snap.filesystems = storage.filesystems;
  snap.disks = storage.disks;

  // Optional SSH ZFS enrichment (best-effort, inventory cadence): when an `ssh`
  // slot is bound, the full pool/dataset tree REPLACES the API's single zfs-root
  // row; non-ZFS mounts from system_disk are kept. A failed/absent SSH path
  // leaves the API-only rows untouched (null = keep previous data).
  const sshZfs = await collectZfsViaSsh(host, credentials, (level, message) => {
    if (level === 'warn') logger.warn(message);
    else logger.info(message);
  });
  if (sshZfs && sshZfs.filesystems.length > 0) {
    // Keep non-ZFS API rows; SSH rows win on name collisions (the zroot pool).
    const apiNonZfs = snap.filesystems.filter((f) => f['type'] !== 'zfs-pool');
    const fsByName = new Map<string, Record<string, unknown>>();
    for (const row of [...apiNonZfs, ...sshZfs.filesystems]) {
      fsByName.set(String(row['name']), row as Record<string, unknown>);
    }
    snap.filesystems = Array.from(fsByName.values());
    // Disks: SSH vdev leaves + any API disk rows (deduped by name).
    const diskByName = new Map<string, Record<string, unknown>>();
    for (const d of [...snap.disks, ...sshZfs.disks]) {
      diskByName.set(String(d['name']), d as Record<string, unknown>);
    }
    snap.disks = Array.from(diskByName.values());
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
  // Selected model/firmware echoed from the device form (see /monitoring).
  if (metrics['system.model'] !== undefined) {
    push({ key: 'system.model', label: 'Selected Model', type: 'string', visualization: 'text', group: 'System' });
  }
  if (metrics['system.firmwareVersion'] !== undefined) {
    push({ key: 'system.firmwareVersion', label: 'Selected Firmware', type: 'string', visualization: 'text', group: 'System' });
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
  // Configured tunnels (WireGuard/OpenVPN/IPsec/PPPoE/GRE) — inventory, slow
  // refresh; also normalized into the API's cross-device `tunnels` table.
  if (Array.isArray(metrics['tunnels']) && (metrics['tunnels'] as unknown[]).length > 0) {
    push({ key: 'tunnels', label: 'Tunnels', type: 'string', visualization: 'table', group: 'Inventory', columns: ['name', 'type', 'peerAddress', 'localAddress', 'subnet', 'status', 'interfaceName'], intervalMs: INVENTORY_INTERVAL_MS });
  }
  // Configured static routes — inventory, slow refresh; also normalized into
  // the API's cross-device `routes` table.
  if (Array.isArray(metrics['routes']) && (metrics['routes'] as unknown[]).length > 0) {
    push({ key: 'routes', label: 'Routes', type: 'string', visualization: 'table', group: 'Inventory', columns: ['destination', 'gateway', 'protocol', 'distance', 'status'], intervalMs: INVENTORY_INTERVAL_MS });
    push({ key: 'firewallRules', label: 'Firewall Rules', type: 'string', visualization: 'table', group: 'Inventory', columns: ['ruleType', 'position', 'protocol', 'sourceIp', 'destIp', 'action', 'enabled'], intervalMs: INVENTORY_INTERVAL_MS });
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
 * The options this plugin exposes for configuration. Declared in /discover so
 * the API can persist + validate user-set values and the webapp can render a
 * generic form — this plugin never stores settings itself; it receives them
 * on every call via the `x-unm-settings` header (see readSettings()).
 */
const PLUGIN_OPTIONS: PluginOptionDescriptor[] = [
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
    key: 'logToApi',
    label: 'Send logs to UNM',
    type: 'boolean' as const,
    default: true,
    description:
      'Ship structured log entries (poll failures, config/plan errors) to the UNM API for the device Logs view. Disable to keep logging container-local only.',
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

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'opnsense-plugin',
  // Static icon assets (plugin + per-model icons), advertised in /discover and
  // fetched by the API's icon proxy. dist/src/../../icons = <plugin root>/icons.
  iconsDir: path.join(__dirname, '../../icons'),
  discovery: {
    // The secret type this plugin expects for device credentials. The API
    // broker reads this to filter which secrets/providers are applicable to
    // devices managed by this plugin.
    requiredSecretType: 'apiKey',
    // Optional SSH slot — unlocks the ZFS pool/dataset inventory (the OPNsense
    // API exposes no ZFS listing at all). Accepts BOTH credential styles:
    // a username/password login OR an ed25519 key pair. Unbound = API-only mode.
    credentialSlots: [
      {
        name: 'ssh',
        secretTypes: ['usernamePassword', 'sshKeyPair'],
        required: false,
        description:
          'Optional SSH access for ZFS pool/dataset inventory (pools, datasets, zvols, scrub state, snapshots, per-disk health). The OPNsense API has no ZFS listing — without this slot only the mounted-root overview is collected. Read-only commands; runs at 15-min inventory cadence.',
      },
    ],
    // Static metric descriptors (system metrics). The traffic table descriptor
    // is emitted dynamically from /monitoring (it needs the live interface
    // list, which is only available when polling a specific device).
    metrics: buildMetricDescriptors([]),
    options: PLUGIN_OPTIONS,
    // The full action catalog (single-device actions + multi-device intents).
    actions: listCatalog(),
    modules: listModules(),
    iconUrl: '/icons/opnsense.svg',
    deviceModels: DEVICE_MODELS,
  },
});
const app = server.app;

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

// pickNumber / pickString (multi-key field readers) come from @unm/plugin-sdk.

/**
 * Collects a rich set of metrics from the OPNsense appliance: CPU load,
 * memory usage, uptime, and per-interface traffic. Each sub-call is
 * best-effort so a single failing endpoint doesn't sink the whole poll.
 */
async function collectMetrics(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  deviceId?: string | null,
  credentials?: Record<string, unknown>
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
  // `credentials` carries bound slots (slots.ssh) for the optional ZFS path.
  const inventory = await getInventory(host, apiKey, apiSecret, transport, credentials);
  if (inventory.hostname) metrics['hostname'] = inventory.hostname;
  if (inventory.version) metrics['version'] = inventory.version;
  if (inventory.arp.length > 0) metrics['arp'] = inventory.arp;
  if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;
  // Configured networks (interface IPs with CIDR + VLAN id) and active DHCP
  // leases — consumed by the API's normalized inventory tables (Networks/Hosts
  // pages) in addition to being rendered as generic tables in the device view.
  if (inventory.networks.length > 0) metrics['networks'] = inventory.networks;
  if (inventory.dhcpLeases.length > 0) metrics['dhcpLeases'] = inventory.dhcpLeases;

  // Storage inventory for the cross-device Storage page. Emitted ONLY when the
  // appliance actually has ZFS pools / USB storage — an absent key means "no
  // data" (the API must not wipe rows of other devices on this plugin).
  if (inventory.filesystems.length > 0) metrics['filesystems'] = inventory.filesystems;
  if (inventory.disks.length > 0) metrics['disks'] = inventory.disks;

  // Ports: one row per configured interface (the networks rows are one-per-IP,
  // so dedupe by name). Consumed by the API's normalized device_ports table —
  // this is what powers cross-device port views and the Config page fallback.
  if (inventory.networks.length > 0) {
    const seen = new Map<string, PortRow>();
    for (const row of inventory.networks) {
      const name = typeof row['name'] === 'string' ? (row['name'] as string).trim() : '';
      if (!name || seen.has(name)) continue;
      const mac = pickString(row, ['mac', 'macaddr']);
      const statusRaw = typeof row['status'] === 'string' ? (row['status'] as string) : undefined;
      const vlanId = pickNumber(row, ['vlanId', 'vlan_tag']);
      const ip = typeof row['ip'] === 'string' ? (row['ip'] as string) : undefined;
      const extra: Record<string, unknown> = {};
      if (mac) extra.mac = mac;
      if (ip) extra.ip = ip;
      seen.set(name, {
        name,
        ...(statusRaw ? { status: statusRaw.toLowerCase() } : {}),
        ...(Object.keys(extra).length > 0 ? { extra } : {}),
        ...(vlanId !== undefined ? { vlanId } : {}),
      });
    }
    const portRows = Array.from(seen.values());
    if (portRows.length > 0) metrics['ports'] = portRows;
  }

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
  const traffic: Record<string, Record<string, number>> = {};
  try {
    const stats = await getInterfaceStats(host, apiKey, apiSecret, transport);
    if (stats.ok && stats.data && typeof stats.data === 'object') {
      const data = stats.data as Record<string, unknown>;
      const statistics = (data['statistics'] ?? data) as Record<string, unknown>;
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

  // Tunnels: emit the cached config-level inventory enriched with LIVE runtime
  // state (WireGuard last-handshake + real peer endpoint from service/show; IPsec
  // SA status from sessions), then attach per-tunnel rates. The rate tracker
  // keeps one counter sample per host in memory and computes bytes/s deltas —
  // first poll after (re)start has no delta, so those rows simply carry no
  // rxRate/txRate (expected warm-up behavior). Emitted even when the stats
  // endpoint failed: tunnel inventory is independent of traffic data.
  // Live enrichment (tunnels / routes / firewall counters) hits appliance
  // endpoints on EVERY poll — not cached with the inventory. Each is independent
  // and best-effort: a failure falls back to the config-level rows unchanged.
  // They run in PARALLEL so their endpoint round-trips don't stack up against
  // the API's hard 10s poll budget (sequential enrichment timed out on busy
  // appliances with large rule sets).
  const allRoutes = [...inventory.routes, ...deriveConnectedAndDefaultRoutes(inventory.networks, inventory.gateways, inventory.routes)];

  const tunnelPromise: Promise<unknown> | null =
    inventory.tunnels.length > 0
      ? enrichTunnelsWithLiveState(createClient(host, { apiKey, apiSecret }, transport), inventory.tunnels).catch(() => inventory.tunnels)
      : null;
  const routePromise: Promise<unknown> | null =
    allRoutes.length > 0
      ? enrichRoutesWithGatewayStatus(createClient(host, { apiKey, apiSecret }, transport), allRoutes, {
          log: (_level, message, context) => logger.warn(message, { deviceId, context }),
        }).catch(() => allRoutes)
      : null;
  const fwStatsPromise: Promise<Map<string, { packets: number | null; bytes: number | null; states: number | null }>> | null =
    inventory.firewallRules !== null && inventory.firewallRules.length > 0
      ? fetchFilterRuleStats(createClient(host, { apiKey, apiSecret }, transport)).catch(() => new Map())
      : null;

  const [tunnelsOut, routesOut, fwStats] = await Promise.all([tunnelPromise, routePromise, fwStatsPromise]);

  if (tunnelsOut) metrics['tunnels'] = attachTunnelRates(host, tunnelsOut as typeof inventory.tunnels, traffic);
  if (routesOut) metrics['routes'] = routesOut;
  // Firewall rules (filter + NAT kinds): emit the cached unified rows enriched
  // with LIVE pf hit counters (rule_stats is keyed by rule uuid). The key is only
  // present when collection SUCCEEDED — a failed cycle keeps the previous
  // snapshot's rows alive on the API side; an appliance with genuinely zero
  // rules emits [] which authoritatively clears stale rows.
  if (inventory.firewallRules !== null) {
    let fwRows = inventory.firewallRules;
    if (fwStats && fwStats.size > 0) {
      fwRows = fwRows.map((r) =>
        r.ruleType === 'filter' && fwStats.has(r.vendorRuleId)
          ? { ...r, ...(fwStats.get(r.vendorRuleId) as { packets: number | null; bytes: number | null; states: number | null }) }
          : r
      );
    }
    metrics['firewallRules'] = fwRows;
  }

  return { metrics, interfaces };
}

app.post('/monitoring', async (req, res) => {
  const body = req.body ?? {};
  const { deviceId, apiKey, apiSecret, managementAddress } = body;
  // Model/firmware selected in the webapp device form — forwarded by the API's
  // telemetry worker on every poll. Echoed back as system.* metrics (informational).
  const selectedModel = typeof body.model === 'string' && body.model ? body.model : null;
  const selectedFirmware = typeof body.firmwareVersion === 'string' && body.firmwareVersion ? body.firmwareVersion : null;

  // Effective settings injected by the API (defaults ⊕ user overrides). The
  // plugin reads its options from here — it never stores them itself.
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const transport: OpnsenseTransport =
    typeof settings.transport === 'string' && ['auto', 'http', 'https'].includes(settings.transport)
      ? (settings.transport as OpnsenseTransport)
      : 'auto';

  // Decrypted assignment fields incl. bound slots (slots.ssh when the user
  // bound an SSH credential) — forwarded to the inventory for ZFS enrichment.
  const credentials = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  try {
    const { metrics, interfaces } = await collectMetrics(managementAddress, apiKey, apiSecret, transport, deviceId, credentials);

    // Echo of the user-selected model/firmware (mirrors the LANCOM plugin) —
    // informational only; shown as text cards in the device detail view.
    if (selectedModel) metrics['system.model'] = selectedModel;
    if (selectedFirmware) metrics['system.firmwareVersion'] = selectedFirmware;

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
        model: selectedModel,
        firmwareVersion: selectedFirmware,
      },
    });
  } catch (err) {
    logger.error(`Monitoring poll failed for ${managementAddress}: ${(err as Error).message}`, { deviceId, context: { host: managementAddress } });
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

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
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
    logger.error(`Config action ${actionId} failed for ${managementAddress}: ${(err as Error).message}`, { deviceId: typeof deviceId === 'string' ? deviceId : null, context: { host: managementAddress, actionId } });
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
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);

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
      logger.error(`Planning ${planReq.intent.actionId} failed: ${err.message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
      res.status(400).json({ error: err.message });
      return;
    }
    logger.error(`Planning ${planReq.intent.actionId} failed unexpectedly: ${(err as Error).message}`, { context: { actionId: planReq.intent.actionId, deviceCount: planReq.devices.length } });
    res.status(500).json({ error: (err as Error).message });
  }
});

/**
 * POST /state — dynamic device-state document for the UNM Config page.
 * The API broker (api/src/deviceState.ts) calls this with fresh credentials +
 * injected settings and returns the response verbatim to the webapp. Built
 * from the cached inventory snapshot: one Interfaces section item per
 * configured interface (MAC, IPs, live status) plus a System section with the
 * power actions (system.reboot / system.halt are DANGEROUS catalog entries —
 * executing them always flows through the plan workflow).
 */
app.post('/state', stateHandler(async (body: StateRequestBody, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  const transport = transportOf(settings);

  // Credentials: the assignment's decrypted fields are at top level of
  // `credentials` (secret type `apiKey`) — same model as /config.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const apiKey = typeof creds['apiKey'] === 'string' ? (creds['apiKey'] as string) : '';
  const apiSecret = typeof creds['apiSecret'] === 'string' ? (creds['apiSecret'] as string) : '';

  // `creds` also carries bound slots (slots.ssh) for the optional ZFS path.
  const snapshot = await getInventory(body.managementAddress, apiKey, apiSecret, transport, creds);

  // Interface MACs: the networks rows already carry `mac` from interfaces_info;
  // fall back to the live interface-statistics MACs collected this poll.
  const macs: { name: string; mac: string }[] = [];
  for (const row of snapshot.networks) {
    const name = typeof row['name'] === 'string' ? (row['name'] as string).trim() : '';
    const mac = pickString(row, ['mac', 'macaddr']);
    if (name && mac) macs.push({ name, mac });
  }

  return buildOpnsenseState(snapshot, macs);
}, 'opnsense-plugin'));

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
// listen() binds the conventional plugin port (4080 by default) and starts
// mDNS advertising — both handled by @unm/plugin-sdk.
server.listen().catch((err) => {
  console.error('[opnsense-plugin] fatal startup error:', err);
  process.exit(1);
});