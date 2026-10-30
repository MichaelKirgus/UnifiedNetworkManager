import path from 'path';
import axios from 'axios';
import {
  Health,
  MetricDescriptor,
  PluginOptionDescriptor,
  INVENTORY_INTERVAL_MS,
  createPluginLogger,
  createNotifier,
  createPluginServer,
  pickNumber,
  pickString,
  readSettings,
  resolvePluginIdentity,
  stateHandler,
  PortRow,
  StateRequestBody,
  collectDeviceCertificates,
  parseProbeTarget,
  createPinningGuard,
  quickActionHandler,
  buildWebUiUrl,
  isTransientTransportError,
  resolveHttpsPort,
  resolveHttpPort,
  resolveSshPort,
  buildDeviceTimeInfo,
  parseLooseDeviceDatetime,
  tzAbbrToOffsetMinutes,
  warnOnce,
  DETECTED_FEATURES_METRIC_KEY,
  type DeviceTimeInfo,
  type UpdateRow,
  type QuickAction,
} from '@unm/plugin-sdk';
import { OPNSENSE_DEVICE_SUPPORT } from './deviceSupport';
import {
  getSystemStatus,
  getSystemResources,
  getSystemInformation,
  getSystemTime,
  getSystemTimezone,
  getSystemDisk,
  getInterfaces,
  getInterfaceStats,
  getCpuUsage,
  getArpTable,
  getNdpTable,
  OpnsenseTransport,
} from './opnsenseClient';
import { DEVICE_MODELS, RELEASES } from './deviceModels';
import { createClient, get as opnsenseGet, OpnsenseCredentials, OpnsensePorts, resolveBase } from './client/http';
import * as firmware from './client/firmware';
import { resolveEdition } from './client/editions';
import { detectDnsBackend, searchHostRecords, parseHostRecordRows, DnsBackend } from './client/dns';
import { detectDhcpBackend, DhcpBackend, searchKeaLeases, searchDnsmasqLeases } from './client/dhcp';
import { getInterfacesInfo, vlans } from './client/interfaces';
import { searchGateways } from './client/routes';
import { collectTunnels, attachTunnelRates, enrichTunnelsWithLiveState, TunnelRow } from './tunnels';
import { collectRoutes, deriveConnectedAndDefaultRoutes, enrichRoutesWithGatewayStatus, RouteRow } from './routes';
import { collectFirewallRules, fetchFilterRuleStats } from './firewall';
import {
  fetchFirewallEvents,
  fetchStateSummary,
  fetchStateTimeouts,
  fetchPfStats,
  FirewallEventRow,
} from './client/firewallEvents';
import { fetchStateIdentities, countOpenStates, diffStates, buildHostStateRows } from './client/hostStates';
import { decideUpdateSearch, DEFAULT_UPDATE_CHECK_INTERVAL_SEC, type UpdateSearchEntry } from './updateSearch';
import { collectServices } from './services';
import { collectZfsViaSsh } from './zfsSsh';
import { collectSecurityChecks, DEFAULT_WATCHED_FILES, type SecuritySettings } from './security';
import { getAction, listModules } from './actions/registry';
import { ActionContext, ActionResult, StepCredentials, validateInput } from './actions/types';
import { buildPlan, PlanningError, PlanRequest, listCatalog } from './plan';
import { PREFLIGHT_RESOLVERS } from './actions/preflight';
import { InventorySnapshot } from './inventoryTypes';
import { buildOpnsenseState } from './state';
import { mirrorOpnsenseConditions, type ZfsPoolCondition, type SecurityFinding } from './notifications';

// Base UUID + shared state store live in ./stateStore so the monitoring path,
// the security actions AND the firewall-event cursor all bind to the SAME
// instance-scoped effective uuid.
import { PLUGIN_UUID, stateStore } from './stateStore';
export { PLUGIN_UUID };
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
  description:
    'OPNsense firewall management — system/network metrics, ZFS pools, security checks and config actions over REST + SSH.',
  // 0.5.0 — Automatic update search (option `updateCheckIntervalSec`, default
  // 6 h, 0 disables): OPNsense only advertises available updates after an
  // update SEARCH has run on-device (POST /api/core/firmware/status — a
  // synchronous ~30–90 s probe against pkg.opnsense.org), while monitoring
  // reads the appliance's CACHED check result. Devices that never ran a search
  // therefore showed no updates forever. The plugin now triggers a fresh probe
  // in the background at its own cadence (fire-and-forget — it must never block
  // or fail a poll, since the API times out /monitoring POSTs at 30 s); once it
  // finishes, the next fast GET surfaces the result. A forced refresh ("Check
  // now" on the Updates page) passes forceUpdateCheck and bypasses both cadence
  // and a zero interval — but a forced check younger than 5 min is skipped: the
  // cache was just refreshed by that probe, and re-probing would serialize every
  // REST call behind configd's lock for another 30–90 s.
  // 0.4.0 — Notification-center mirroring (SDK createNotifier): /monitoring now
  // mirrors appliance-level conditions into the UNM notification center with
  // stable dedupe keys + resolve-on-disappearance, like ix-truenas's alert.list:
  //   - ZFS pool states DEGRADED/FAULTED/OFFLINE (ssh-slot-gated), and
  //   - security-check findings at warning/critical (file-integrity change,
  //     brute-force login burst, unexpected uid-0 account).
  // Gated by the `notifyAlerts` option. Device-state mirroring stays API-side.
  version: '0.5.0',
  vendors: ['opnsense'],
  // 'planning' advertises the /plan endpoint (multi-device intents) so the API
  // can offer bulk rollout + tunnel provisioning flows in the webapp.
  // 'deviceState' advertises POST /state — the dynamic document behind the
  // per-device Config page (interfaces with live status + system power actions).
  // 'ssh' = optional SSH data path for ZFS pool/dataset inventory (the API has
  // no ZFS listing) — only used when an `ssh` credential slot is bound.
  // securityChecks: per-appliance security checks over the same ssh slot (file
  // integrity, failed logins, active rate limiting, account hygiene).
  capabilities: ['monitoring', 'configuration', 'inventory', 'planning', 'deviceState', 'ssh', 'updates', 'quickActions', 'securityChecks'],
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

// Last known detected-features set per host (support matrix, see
// deviceSupport.ts). Inventory keys only exist on inventory-due polls, so the
// set is cached and re-emitted on metrics-only polls — the API evaluates
// capabilities from the LATEST snapshot, which must therefore always carry the
// key. Feature ids: 'zfs' (ZFS storage present) gates the zfsInventory capability.
const lastDetectedFeatures = new Map<string, string[]>();

// Certificate pinning guard: before ANY credentials are transmitted to an
// appliance, the management endpoint's TLS certificate is verified against UNM's
// certificate inventory (strict mode — a mismatch throws and the request stops;
// unknown endpoints are accepted once via TOFU). See @unm/plugin-sdk/pinning.
const assertPinned = createPinningGuard();

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
 * Collects the CONFIGURED DHCP server surface for the cross-device DHCP page:
 *   - dnsmasq backend: `GET /api/dnsmasq/settings/search_range` rows carry
 *     `{ interface, start_addr, end_addr }` (the same shape networkIntents.ts
 *     writes via add_range); staticmaps come from services/dhcp.
 *   - Kea backend: subnets come from the `search_subnet` recordset (rows[] with
 *     uuid/subnet CIDR/pools/description) — on current firmware the full config
 *     (`GET /api/kea/dhcpv4/get`) carries NO subnets, so it is only a fallback;
 *     reservations come from `search_reservation`. Field names vary by OPNsense
 *     release, so every read is defensive multi-key.
 * Returns [networks | null, reservations | null] — a null means "read failed"
 * (the caller omits the metric key so stored rows survive); an empty array is
 * authoritative ("this appliance has no DHCP ranges/reservations").
 */
async function collectDhcpConfig(
  client: import('axios').AxiosInstance,
  backend: DhcpBackend
): Promise<[Record<string, unknown>[] | null, Record<string, unknown>[] | null]> {
  if (backend === 'dnsmasq') {
    const [rangeRes, mapRes] = await Promise.all([
      opnsenseGet(client, '/api/dnsmasq/settings/search_range'),
      import('./client/dhcp').then((m) => m.searchStaticMappings(client, 'dnsmasq')),
    ]);
    let networks: Record<string, unknown>[] | null = null;
    if (rangeRes?.ok && rangeRes.data && typeof rangeRes.data === 'object') {
      const d = rangeRes.data as Record<string, unknown>;
      const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : Array.isArray(d) ? (d as Record<string, unknown>[]) : [];
      networks = rows.flatMap((r) => {
        const iface = pickString(r, ['interface', 'if']);
        let start = pickString(r, ['start_addr', 'start', 'range_start']);
        let end = pickString(r, ['end_addr', 'end', 'range_end']);
        if (!iface || !start) return [];
        // A range row may carry a bare "a-b" string in one field — split defensively.
        const dash = start.match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/);
        if (dash) { start = dash[1]; end = dash[2]; }
        // uuid is the delete handle for dhcp.network.delete.
        return [{ name: iface, interface: iface, rangeStart: start, rangeEnd: end ?? start, refId: pickString(r, ['uuid']) }];
      });
    }
    let reservations: Record<string, unknown>[] | null = null;
    if (mapRes?.ok && mapRes.data && typeof mapRes.data === 'object') {
      const d = mapRes.data as Record<string, unknown>;
      const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
      reservations = rows.map((r) => ({
        mac: (pickString(r, ['mac', 'macaddr']) ?? '').toLowerCase(),
        ip: pickString(r, ['ipaddr', 'ip', 'address']),
        hostname: pickString(r, ['hostname', 'host']),
        // dnsmasq staticmaps are per-interface — the add action needs it back.
        interface: pickString(r, ['interface', 'if']),
        refId: pickString(r, ['uuid']),
      })).filter((r) => typeof r['mac'] === 'string' && (r['mac'] as string).length > 0);
    }
    return [networks, reservations];
  }

  // Kea backend. Subnets live in the `search_subnet` recordset on current
  // firmware (rows[] with uuid/subnet_id/subnet CIDR/pools/description); older
  // releases surface them inside the full config (`GET /api/kea/dhcpv4/get`) —
  // try the recordset first, fall back to the config containers.
  const { getKeaDhcpv4Config, searchStaticMappings, searchKeaSubnets } = await import('./client/dhcp');
  let subnets: Record<string, unknown>[] | null = null;
  const subnetRes = await searchKeaSubnets(client);
  if (subnetRes?.ok && subnetRes.data && typeof subnetRes.data === 'object') {
    const d = subnetRes.data as Record<string, unknown>;
    subnets = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
  }
  if (!subnets) {
    const cfgRes = await getKeaDhcpv4Config(client);
    if (cfgRes?.ok && cfgRes.data && typeof cfgRes.data === 'object') {
      const d = cfgRes.data as Record<string, unknown>;
      // Kea config shapes vary by release — accept the common containers.
      subnets = Array.isArray(d['subnets'])
        ? (d['subnets'] as Record<string, unknown>[])
        : d['config'] && typeof d['config'] === 'object' && Array.isArray((d['config'] as Record<string, unknown>)['subnets'])
          ? ((d['config'] as Record<string, unknown>)['subnets'] as Record<string, unknown>[])
          : [];
    }
  }
  let networks: Record<string, unknown>[] | null = null;
  if (subnets !== null) {
    networks = subnets.flatMap((sn) => {
      // The recordset's `uuid` is the delete handle for dhcp.network.delete
      // (Kea del_subnet); fall back to the numeric subnet id on older shapes.
      const refId = pickString(sn, ['uuid']) ?? (() => {
        const idRaw = sn['id'] ?? sn['subnet_id'];
        return typeof idRaw === 'string' && idRaw.trim() !== '' ? idRaw : typeof idRaw === 'number' ? String(idRaw) : undefined;
      })();
      // The subnet's own `subnet` field is a CIDR ("10.25.0.0/16") — surface it.
      const cidr = (pickString(sn, ['subnet']) ?? '').match(/^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/)?.[0] ?? null;
      // Display name: the recordset carries a human `description` ("NET_GUEST");
      // fall back to the numeric id so unnamed subnets still render distinctly.
      const name = pickString(sn, ['description', 'name']) ?? refId ?? 'kea-subnet';
      // Pool entries are canonically ONE "start-end" STRING in the recordset
      // (`pools: "10.25.2.1-10.25.2.255"`); some releases surface an array of
      // strings or objects — normalize all three to a record list before the
      // multi-key reads below.
      const rawPools = sn['pools'];
      const poolList: unknown[] = Array.isArray(rawPools) ? (rawPools as unknown[]) : typeof rawPools === 'string' && rawPools.trim() !== '' ? [rawPools] : [];
      const pools: Record<string, unknown>[] = poolList.map((raw) => {
        if (typeof raw === 'string') return { pool: raw };
        return raw && typeof raw === 'object' ? (raw as Record<string, unknown>) : {};
      });
      if (pools.length === 0) return [];
      return pools.map((p) => {
        // Kea stores a pool range either as ONE "start-end" string (`pool`) or as
        // separate start/end fields — accept both.
        let start = pickString(p, ['start', 'range_start']);
        let end = pickString(p, ['end', 'range_end']);
        if (!start) {
          const dash = (pickString(p, ['pool']) ?? '').match(/^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$/);
          if (dash) { start = dash[1]; end = end ?? dash[2]; }
        }
        return { name, interface: null, rangeStart: start, rangeEnd: end ?? start, cidr, refId };
      }).filter((r) => typeof r['rangeStart'] === 'string' && (r['rangeStart'] as string).length > 0);
    });
  }
  const mapRes = await searchStaticMappings(client, 'kea');
  let reservations: Record<string, unknown>[] | null = null;
  if (mapRes?.ok && mapRes.data && typeof mapRes.data === 'object') {
    const d = mapRes.data as Record<string, unknown>;
    const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
    reservations = rows.map((r) => ({
      // Current firmware's recordset uses `hw_address`/`ip_address`; older
      // releases surface `mac`/`ip` — accept all. Kea rows carry no interface
      // (the reservation is bound to a subnet uuid, not an interface).
      mac: (pickString(r, ['mac', 'hwaddr', 'hw_address']) ?? '').toLowerCase(),
      ip: pickString(r, ['ip', 'ipaddress', 'ip_address', 'address']),
      hostname: pickString(r, ['hostname', 'host']),
      interface: pickString(r, ['interface', 'if']),
      refId: pickString(r, ['uuid', 'id']),
    })).filter((r) => typeof r['mac'] === 'string' && (r['mac'] as string).length > 0);
  }
  return [networks, reservations];
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
  credentials?: Record<string, unknown>,
  ports?: OpnsensePorts,
  sshPort = 22,
  dhcpBackendOverride?: DhcpBackend
): Promise<InventorySnapshot> {
  // UNM_NO_INVENTORY_CACHE=1 disables the read-through cache — used by the smoke
  // test, which flips the mock appliance's DHCP backend between two /monitoring
  // calls and needs each one to re-collect. Writes still warm the cache.
  const cached = process.env['UNM_NO_INVENTORY_CACHE'] === '1' ? undefined : inventoryCache.get(host);
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
  const p = collectInventory(host, apiKey, apiSecret, transport, credentials, ports, sshPort, dhcpBackendOverride).finally(() => {
    inventoryInFlight.delete(host);
  });
  inventoryInFlight.set(host, p);
  return p;
}

/** Performs one full cold inventory collection (all endpoints, best-effort).
 * `credentials` carries the assignment's decrypted fields incl. bound slots —
 * used ONLY for the optional SSH ZFS enrichment (slots.ssh).
 * `dhcpBackendOverride` is the user-set `dhcpBackend` option ('dnsmasq'|'kea') —
 * when present it wins over auto-detection so READS and WRITES always agree on
 * the backend (the override exists precisely for appliances where the Kea
 * service-status probe is inconclusive). */
async function collectInventory(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  credentials?: Record<string, unknown>,
  ports?: OpnsensePorts,
  sshPort = 22,
  dhcpBackendOverride?: DhcpBackend
): Promise<InventorySnapshot> {
  // The client-lib calls need a bound axios instance for this appliance.
  const client = createClient(host, { apiKey, apiSecret }, transport, ports);

  const [info, arp, ndp, ifInfo, vlanRes, gwRes, diskRes] = await Promise.all([
    getSystemInformation(host, apiKey, apiSecret, transport, ports).catch(() => undefined),
    getArpTable(host, apiKey, apiSecret, transport, ports).catch(() => undefined),
    getNdpTable(host, apiKey, apiSecret, transport, ports).catch(() => undefined),
    getInterfacesInfo(client).catch(() => undefined),
    vlans.get(client).catch(() => undefined),
    searchGateways(client).catch(() => undefined),
    // Storage (best-effort — the only storage data OPNsense exposes):
    getSystemDisk(host, apiKey, apiSecret, transport, ports).catch(() => undefined),
  ]);

  // Raw interfaces_info entries — kept for the PPPoE tunnel detector (which
  // needs the interface TYPE fields that parseNetworkRows discards).
  let ifEntries: Record<string, unknown>[] = [];
  const snap: InventorySnapshot = { collectedAt: Date.now(), arp: [], ndp: [], networks: [], dhcpLeases: [], dhcpNetworks: null, dhcpReservations: null, tunnels: [], routes: [], firewallRules: null, services: null, gateways: [], filesystems: [], disks: [], certificates: [], dnsEntries: null };
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

  // DHCP leases: backend resolved per appliance (user override wins, else
  // auto-detect), then normalized.
  let dhcpBackend: DhcpBackend | null = null;
  try {
    dhcpBackend = dhcpBackendOverride ?? await detectDhcpBackend(client);
    const leaseRes = dhcpBackend === 'kea' ? await searchKeaLeases(client) : await searchDnsmasqLeases(client);
    if (leaseRes?.ok && leaseRes.data && typeof leaseRes.data === 'object') {
      const rows = (leaseRes.data as Record<string, unknown>)['rows'];
      snap.dhcpLeases = Array.isArray(rows) ? parseDhcpLeaseRows(rows) : [];
    }
  } catch {
    // best-effort — a failing lease endpoint must not sink the inventory cache
  }

  // Configured DHCP networks + static reservations (DHCP page): backend auto-detected
  // above, then normalized per backend. null on failure so /monitoring omits the keys
  // and a transient error never wipes previously ingested rows.
  try {
    if (!dhcpBackend) dhcpBackend = dhcpBackendOverride ?? await detectDhcpBackend(client);
    const [netRows, resRows] = await collectDhcpConfig(client, dhcpBackend);
    snap.dhcpNetworks = netRows;
    snap.dhcpReservations = resRows;
  } catch {
    // best-effort — keep the keys absent (null) on failure
  }

  // Static DNS host entries (DNS page): backend auto-detected per appliance,
  // then normalized to {name, ip}. null on failure so /monitoring omits the key
  // and a transient error never wipes previously ingested rows.
  try {
    const dnsBackend = await detectDnsBackend(client);
    const hostRes = await searchHostRecords(client, dnsBackend);
    snap.dnsEntries = hostRes?.ok && hostRes.data ? parseHostRecordRows(hostRes.data) : null;
  } catch {
    // best-effort — keep the key absent (null) on failure
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

  // rc-managed services + running state (Services page) — same registry the
  // appliance's System → Services UI reads. null on failure: /monitoring then
  // omits the key so previously stored rows survive a transient outage.
  try {
    snap.services = await collectServices(client);
  } catch {
    // best-effort — a failing service endpoint must not sink the inventory cache
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

  // Certificates (Certificates page) — probe the management HTTPS cert (only when
  // the UI actually speaks TLS; a plain-http appliance has no cert to read) plus
  // the SSH host key on port 22. Both are credential-free and best-effort, so a
  // failure simply contributes no row. Collected at inventory cadence.
  try {
    // Probe the SAME endpoint the client talks to — configured ports included
    // (an explicit port in the management address wins over the option default).
    const base = resolveBase(host, transport, ports);
    const target = parseProbeTarget(base, ports?.httpsPort ?? 443);
    if (target) {
      const isHttps = /^https:/i.test(base);
      snap.certificates = await collectDeviceCertificates({
        host: target.host,
        httpsPort: isHttps ? target.port : null,
        servername: target.host,
        sshEnabled: true,
        sshPort,
        timeoutMs: 5_000,
      });
    }
  } catch {
    // best-effort — a failing cert probe must not sink the inventory cache
  }

  // Optional SSH ZFS enrichment (best-effort, inventory cadence): when an `ssh`
  // slot is bound, the full pool/dataset tree REPLACES the API's single zfs-root
  // row; non-ZFS mounts from system_disk are kept. A failed/absent SSH path
  // leaves the API-only rows untouched (null = keep previous data).
  const sshZfs = await collectZfsViaSsh(host, credentials, (level, message) => {
    if (level === 'warn') logger.warn(message);
    else logger.info(message);
  }, { port: sshPort });
  // A non-null result means the SSH ZFS enrichment SUCCEEDED (a bound slot
  // answered with a real pool listing) — mark it so /monitoring can mirror pool
  // states authoritatively. null = no slot / failure → keep previous data AND
  // leave live pool alerts untouched (see notifications.ts anti-flap contract).
  snap.zfsSshCollected = sshZfs !== null;
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
  // Firewall state table (Sessions section) — live on every beat.
  if (typeof metrics['firewall.states.total'] === 'number') {
    push({ key: 'firewall.states.total', label: 'Active Sessions', type: 'number', visualization: 'plot', group: 'Firewall', summary: true, intervalMs: LIVE_INTERVAL_MS });
  }
  if (typeof metrics['firewall.states.limit'] === 'number') {
    push({ key: 'firewall.states.limit', label: 'State Limit', type: 'number', visualization: 'text', group: 'Firewall', intervalMs: LIVE_INTERVAL_MS });
  }
  if (typeof metrics['firewall.states.oldestAgeSec'] === 'number') {
    push({ key: 'firewall.states.oldestAgeSec', label: 'Oldest Session Age', unit: 's', format: 'duration', type: 'number', visualization: 'plot', group: 'Firewall', intervalMs: LIVE_INTERVAL_MS });
  }

  // Adaptive-timeout settings + pf counters — inventory cadence, quasi-static.
  if (metrics['firewall.stateConfig'] && typeof metrics['firewall.stateConfig'] === 'object') {
    const timeouts = metrics['firewall.stateConfig'] as Record<string, unknown>;
    push({ key: 'firewall.stateConfig', label: 'State Timeouts (adaptive)', type: 'string', visualization: 'table', group: 'Firewall', columns: Object.keys(timeouts).slice(0, 24), intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (metrics['firewall.stats'] && typeof metrics['firewall.stats'] === 'object') {
    push({ key: 'firewall.stats', label: 'State Table Counters', type: 'string', visualization: 'table', group: 'Firewall', columns: ['stateTableSearchesRate', 'stateTableInsertsRate', 'stateTableRemovalsRate'], intervalMs: INVENTORY_INTERVAL_MS });
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
  // Configured DHCP ranges + static reservations (cross-device DHCP page) —
  // inventory, slow refresh. Emitted whenever the read SUCCEEDED (empty = none).
  if (Array.isArray(metrics['dhcpNetworks'])) {
    push({ key: 'dhcpNetworks', label: 'DHCP Ranges', type: 'string', visualization: 'table', group: 'Inventory', columns: ['name', 'interface', 'rangeStart', 'rangeEnd', 'cidr'], intervalMs: INVENTORY_INTERVAL_MS });
  }
  if (Array.isArray(metrics['dhcpReservations'])) {
    push({ key: 'dhcpReservations', label: 'DHCP Reservations', type: 'string', visualization: 'table', group: 'Inventory', columns: ['mac', 'ip', 'hostname', 'interface'], intervalMs: INVENTORY_INTERVAL_MS });
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
  // rc-managed services (Services page) — inventory, slow refresh; also
  // normalized into the API's cross-device `device_services` table.
  if (Array.isArray(metrics['services']) && (metrics['services'] as unknown[]).length > 0) {
    push({ key: 'services', label: 'Services', type: 'string', visualization: 'table', group: 'Inventory', columns: ['name', 'type', 'status', 'description'], intervalMs: INVENTORY_INTERVAL_MS });
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
    key: 'stateWalkIntervalSec',
    label: 'State-table walk interval (seconds)',
    type: 'integer' as const,
    default: 900,
    min: 0,
    max: 86400,
    description:
      'How often the plugin walks the appliance\'s FULL live state table to track per-host open states + created/destroyed churn (Hosts/Networks "States" columns). Each walk is one big query_states call — a full table scan on the appliance (~30 s / ~115 MB on a 240k-state box), so keep this slow. 0 disables per-host state tracking.',
  },
  {
    key: 'updateCheckIntervalSec',
    label: 'Update search interval (seconds)',
    type: 'integer' as const,
    default: DEFAULT_UPDATE_CHECK_INTERVAL_SEC,
    min: 0,
    max: 86400,
    description:
      'How often the plugin triggers a fresh update SEARCH on the appliance (POST /api/core/firmware/status — a synchronous probe against pkg.opnsense.org that takes ~30–90 s). OPNsense only advertises available updates after such a search has run; without it, devices that never checked show no updates at all. The probe runs in the background and never blocks or fails a poll — its result surfaces on the next monitoring beat via the cached status read. 0 disables automatic searches (updates then only appear after an explicit "Check now" or the firmware.check plan action).',
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
    key: 'notifyAlerts',
    label: 'Mirror alerts to notification center',
    type: 'boolean' as const,
    default: true,
    description:
      'Push appliance-level conditions into the UNM notification center: ZFS pool states (DEGRADED/FAULTED/OFFLINE — requires a bound SSH slot) and security-check findings at warning/critical. Conditions that clear are auto-resolved.',
  },
  {
    key: 'securityChecksEnabled',
    label: 'Security checks',
    type: 'boolean' as const,
    default: true,
    description:
      'Run per-appliance security checks on the inventory window (file integrity of identity/config files, failed sshd logins, active rate limiting, account hygiene). Requires a bound SSH credential slot — skipped silently in API-only mode. Findings appear in the cross-device Security page.',
  },
  {
    key: 'securityWatchedFiles',
    label: 'Watched files (integrity)',
    type: 'string' as const,
    default: DEFAULT_WATCHED_FILES.join(', '),
    description:
      'Comma-separated absolute paths to hash and watch for changes. First sight baselines silently; a later change raises a critical finding until you re-baseline via the security.rebaseline action.',
  },
  {
    key: 'securityAuthFailureWindowHours',
    label: 'Failed-login window (hours)',
    type: 'integer' as const,
    default: 24,
    min: 1,
    max: 720,
    description: 'Look-back window for counting unsuccessful sshd login attempts.',
  },
  {
    key: 'securityAuthFailureWarnThreshold',
    label: 'Failed-login warning threshold',
    type: 'integer' as const,
    default: 10,
    min: 1,
    description: '≥ this many failed logins in the window raises a warning (below = info).',
  },
  {
    key: 'securityAuthFailureCriticalThreshold',
    label: 'Failed-login critical threshold',
    type: 'integer' as const,
    default: 50,
    min: 2,
    description: '≥ this many failed logins in the window raises a critical finding (likely brute force).',
  },
  {
    key: 'transport',
    label: 'Transport',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'http', 'https'],
    description:
      'How to reach the appliance. auto = HTTPS with self-signed certificates accepted (default, matches historical behavior). https = force TLS. http = plaintext HTTP for appliances without a certificate.',
  },
  {
    key: 'httpsPort',
    label: 'HTTPS port',
    type: 'integer' as const,
    default: 443,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's HTTPS management UI. Used when the management address carries no explicit port (an explicit https://host:<port> always wins). Also the port certificate pinning verifies against.",
  },
  {
    key: 'httpPort',
    label: 'HTTP port',
    type: 'integer' as const,
    default: 80,
    min: 1,
    max: 65535,
    description: "TCP port of the appliance's plain-HTTP management UI (used when transport is http or auto falls back to it).",
  },
  {
    key: 'sshPort',
    label: 'SSH port',
    type: 'integer' as const,
    default: 22,
    min: 1,
    max: 65535,
    description:
      "TCP port of the appliance's SSH daemon. Used for the optional ZFS inventory (ssh slot) and host-key pinning when the management address carries no explicit port.",
  },
  {
    key: 'editionOverride',
    label: 'Edition override',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'ce', 'be'],
    description:
      'Force the detected OPNsense edition. auto = probe /api/opncentral/sync/listClasses (200 = Business Edition, else Community). Use ce/be when probing is blocked by ACLs.',
  },
  {
    key: 'dnsBackend',
    label: 'DNS backend override',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'dnsmasq', 'unbound'],
    description:
      'Force the DNS backend. auto = probe (Unbound on newer installs, dnsmasq on older). Affects which host-record endpoints /config uses.',
  },
  {
    key: 'dhcpBackend',
    label: 'DHCP backend override',
    type: 'string' as const,
    default: 'auto',
    enumOptions: ['auto', 'dnsmasq', 'kea'],
    description:
      'Force the DHCP backend. auto = probe (Kea on newer installs, dnsmasq on older). Affects which static-mapping endpoints /config uses.',
  },
];

// Structured logs shipped to the API (see docs/PLUGIN-DEVELOPMENT.md, Logging).
// Emission is gated per call by the `logToApi` option via setEnabled() — it
// flows through the settings loop, so it works globally and per-device.
const logger = createPluginLogger(identity);

// Notification-center pushes for appliance-level conditions (ZFS pool states +
// security findings). Gated per call by the `notifyAlerts` option, same pattern
// as logging — see ./notifications.ts for the diff/resolve semantics.
const notifier = createNotifier(identity);



/** Quick actions propagated to the Devices page "Device Actions" column. */
const QUICK_ACTIONS: QuickAction[] = [
  {
    id: 'webui',
    label: 'Web UI',
    description: "Open the appliance's management web interface in a new tab",
    iconPath: '/icons/opnsense.svg',
    kind: 'url',
    url: {},
  },
];

// Pre-wired app: cors + json + /healthz + /discover (+ static icons, mDNS on
// listen) come from @unm/plugin-sdk — this file only registers its own routes.
const server = createPluginServer({
  identity,
  logTag: 'opnsense-plugin',
  // config.restore accepts an inline base64 payload (fileBase64) — OPNsense
  // configs are tens of KB; raise the JSON limit like LCOS/SwOS/TrueNAS.
  jsonLimit: '32mb',
  // Static icon assets (plugin + per-model icons), advertised in /discover and
  // fetched by the API's icon proxy. dist/src/../../icons = <plugin root>/icons.
  iconsDir: path.join(__dirname, '../../icons'),
  // Static doc/license assets served at /assets/* — the built-in documentation
  // (docs/README.md) and LICENSE.md referenced from discovery.deviceSupport.
  // dist/src/../.. = <plugin root>. Fetched by the API's asset proxy.
  assetsDir: path.join(__dirname, '../..'),
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
          'Optional SSH access for ZFS pool/dataset inventory (pools, datasets, zvols, scrub state, snapshots, per-disk health) and config.restore (the API has no upload endpoint — the restore stages the file over SSH and applies it with rc.reload_all). Without this slot only the mounted-root overview is collected. Inventory commands are read-only at 15-min cadence; restore is an explicit dangerous action.',
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
    // Quick actions for the Devices page "Device Actions" column. The web-UI
    // URL is resolved by THIS plugin from its own knowledge — scheme follows the
    // transport option, port = the configured httpsPort (the management UI port),
    // path = root. No credentials are involved in opening a browser tab.
    quickActions: QUICK_ACTIONS,
    iconUrl: '/icons/opnsense.svg',
    deviceModels: DEVICE_MODELS,
    // Device support metadata — license/help/docs + the supported-device matrix
    // (firmware-split write paths for the network intents, ssh-slot-gated ZFS
    // inventory + security checks). See ./deviceSupport.ts.
    deviceSupport: OPNSENSE_DEVICE_SUPPORT,
  },
});
const app = server.app;

/** Extracts the effective transport option from injected settings. */
function transportOf(settings: Record<string, unknown>): OpnsenseTransport {
  return typeof settings.transport === 'string' && ['auto', 'http', 'https'].includes(settings.transport)
    ? (settings.transport as OpnsenseTransport)
    : 'auto';
}

/** Extracts the configured endpoint ports from injected settings (defaults 443/80). */
function portsOf(settings: Record<string, unknown>): OpnsensePorts {
  return { httpsPort: resolveHttpsPort(settings.httpsPort), httpPort: resolveHttpPort(settings.httpPort) };
}

/** Extracts the configured SSH port from injected settings (default 22). */
function sshPortOf(settings: Record<string, unknown>): number {
  return resolveSshPort(settings.sshPort);
}

/** Reads an optional string setting. */
function strSetting(settings: Record<string, unknown>, key: string): string | undefined {
  const v = settings[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** The user-set `dhcpBackend` option as a backend ('auto'/absent → undefined). */
function dhcpBackendOverrideOf(settings: Record<string, unknown>): DhcpBackend | undefined {
  const v = strSetting(settings, 'dhcpBackend');
  return v === 'dnsmasq' || v === 'kea' ? v : undefined;
}

/**
 * Resolves the runtime context for one device (edition + DNS/DHCP backends).
 * Probes are read-only and best-effort — failures fall back to CE / dnsmasq.
 */
async function resolveRuntimeContext(
  host: string,
  credentials: OpnsenseCredentials,
  transport: OpnsenseTransport,
  settings: Record<string, unknown>,
  ports?: OpnsensePorts
): Promise<{ edition: 'ce' | 'be'; syncClasses: unknown[]; dnsBackend: DnsBackend; dhcpBackend: DhcpBackend }> {
  const client = createClient(host, credentials, transport, ports);
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

// POST /quick-action — resolve a kind:'url' quick action into the management web-UI
// URL. The plugin owns all URL knowledge: scheme follows the transport option,
// port = the configured httpsPort (the management UI port), path = root. No
// credentials are transmitted — opening a browser tab is credential-free.
app.post('/quick-action', quickActionHandler(async (body, req) => {
  const settings = readSettings(req, PLUGIN_OPTIONS);
  const qa = QUICK_ACTIONS.find((q) => q.id === body.actionId && q.kind === 'url');
  if (!qa) throw new Error(`Unknown url quick action: ${body.actionId}`);
  return {
    url: buildWebUiUrl(body.managementAddress, {
      webUiPort: resolveHttpsPort(settings.httpsPort),
      scheme: transportOf(settings) === 'http' ? 'http' : 'https',
    }, qa.url?.path),
  };
}, 'opnsense-plugin'));

/**
 * Collects a rich set of metrics from the OPNsense appliance: CPU load,
 * memory usage, uptime, and per-interface traffic. Each sub-call is
 * best-effort so a single failing endpoint doesn't sink the whole poll.
 */
/**
 * Window-based scheduling flag from the API's telemetry worker:
 *   true/absent → full collection (slow inventory + live enrichment);
 *   false       → fast metrics only (status/cpu/mem/traffic). The plugin skips
 *                 its slow config collection AND the tunnel/route/firewall live
 *                 enrichment — those tables refresh at the inventory cadence.
 * Absent must mean "collect" for backward compatibility with pre-scheduler APIs.
 */
function wantsInventory(collectInventory: unknown): boolean {
  return collectInventory !== false;
}

// OPNsense's `system_time` datetime is normalized by the shared SDK parser
// (parseLooseDeviceDatetime): it handles both observed forms — "YYYY-MM-DD
// HH:MM:SS" and the C-locale asctime(3) form "Sun Sep 13 23:06:02 CEST 2026"
// (observed live on 24.x). The asctime's timezone abbreviation is mapped to a
// fixed offset via tzAbbrToOffsetMinutes so an absolute instant can be resolved
// even when the appliance has no get_timezone endpoint.

async function collectMetrics(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  deviceId?: string | null,
  credentials?: Record<string, unknown>,
  collectInventory?: boolean,
  ports?: OpnsensePorts,
  sshPort = 22,
  dhcpBackendOverride?: DhcpBackend
): Promise<{ metrics: Record<string, unknown>; interfaces: string[]; zfsFresh: boolean }> {
  const metrics: Record<string, unknown> = {};
  const interfaces: string[] = [];
  const interfaceMacs: { name: string; mac: string }[] = [];
  // True only when the SSH ZFS enrichment SUCCEEDED this cycle (a bound ssh slot
  // answered with a real pool listing). Drives notification mirroring: a false
  // value means "no fresh authoritative ZFS data" so live pool alerts are kept,
  // never wrongly cleared by a transient SSH failure or an API-only poll.
  let zfsFresh = false;

  // Device clock (Time page) — the appliance's CURRENT local wall time from
  // /api/diagnostics/system/system_time plus its IANA zone from
  // /api/system/timezone/get_timezone. Runs on EVERY poll (two cheap authenticated
  // GETs, independent of the inventory gate) so drift stays fresh: with the zone,
  // buildDeviceTimeInfo resolves an absolute instant and the API can compute drift.
  try {
    const [st, tzRes] = await Promise.all([
      getSystemTime(host, apiKey, apiSecret, transport, ports),
      getSystemTimezone(host, apiKey, apiSecret, transport, ports).catch(() => null),
    ]);
    if (st.ok && st.data && typeof st.data === 'object') {
      const dtRaw = (st.data as Record<string, unknown>)['datetime'];
      if (typeof dtRaw === 'string' && dtRaw.trim() !== '') {
        // OPNsense returns either "2026-09-13 14:32:07" or the C-locale asctime
        // form "Sun Sep 13 23:06:02 CEST 2026" (observed live) — normalize both.
        const parsed = parseLooseDeviceDatetime(dtRaw);
        if (parsed) {
          // Prefer the IANA zone from get_timezone (newer appliances); older ones
          // return "Endpoint not found", so fall back to a FIXED offset derived
          // from the asctime's timezone abbreviation (CEST=+120, EST=-300, ...).
          const tzRaw = tzRes?.ok && tzRes.data ? (tzRes.data as Record<string, unknown>)['timezone'] : null;
          const ianaZone = typeof tzRaw === 'string' && tzRaw.trim() !== '' ? tzRaw.trim() : null;
          let info: DeviceTimeInfo | null = null;
          if (ianaZone) info = buildDeviceTimeInfo(parsed.localIso, ianaZone);
          else {
            const abbrOffset = tzAbbrToOffsetMinutes(parsed.tzAbbr);
            if (abbrOffset !== null) info = buildDeviceTimeInfo(parsed.localIso, null, abbrOffset);
          }
          metrics['system.deviceTime'] = info ?? { localIso: parsed.localIso };
        }
      }
    }
    // One-shot diagnostic (stdout-visible, once per host): when no clock blob
    // ended up in metrics, log exactly what the endpoints returned so a wrong
    // field name / auth failure / missing endpoint surfaces. warnOnce is NOT the
    // SDK logger — that one ships to the API and is invisible in docker logs.
    if (!('system.deviceTime' in metrics)) {
      const dtRaw0 = st.ok && st.data && typeof st.data === 'object' ? (st.data as Record<string, unknown>)['datetime'] : null;
      warnOnce('opnsense-plugin', host, `deviceTime: no usable clock from ${host} — system_time ok=${st.ok} status=${st.status} datetime=${JSON.stringify(dtRaw0)}; timezone ok=${tzRes?.ok ?? false}`);
    }
  } catch { /* best-effort — a missing clock must never break monitoring */ }

  // System status (health + basic info). OPNsense returns
  // { metadata: { system: { status: 0|1|2 } } } — capture the status code.
  const status = await getSystemStatus(host, apiKey, apiSecret, transport, ports);
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
    const cpu = await getCpuUsage(host, apiKey, apiSecret, transport, ports);
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
    const resources = await getSystemResources(host, apiKey, apiSecret, transport, ports);
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

  // Firewall state table (Sessions section) — LIVE on every beat: total +
  // capacity from pf_states plus the oldest session age from a tiny sample.
  // Two cheap calls, independent of the inventory gate; best-effort like the
  // other live scalars (a failure simply omits the keys → no wipe).
  try {
    const fwClient = createClient(host, { apiKey, apiSecret }, transport, ports);
    const summary = await fetchStateSummary(fwClient);
    if (summary) {
      metrics['firewall.states.total'] = summary.totalSessions;
      if (summary.stateLimit !== null) metrics['firewall.states.limit'] = summary.stateLimit;
      if (summary.oldestAgeSec !== null) metrics['firewall.states.oldestAgeSec'] = summary.oldestAgeSec;
    }
  } catch {
    /* best-effort — a dead states endpoint must never break the poll */
  }

  // Adaptive-timeout settings + pf counters — quasi-static, inventory cadence.
  if (wantsInventory(collectInventory)) {
    try {
      const fwClient = createClient(host, { apiKey, apiSecret }, transport, ports);
      const [timeouts, pfStats] = await Promise.all([fetchStateTimeouts(fwClient), fetchPfStats(fwClient)]);
      if (timeouts) metrics['firewall.stateConfig'] = timeouts;
      if (pfStats) metrics['firewall.stats'] = pfStats;
    } catch {
      /* best-effort */
    }
  }

  // Inventory (hostname, version, ARP + NDP neighbor tables) — slow-changing.
  // Served from the in-memory cache; the appliance is only re-polled when the
  // TTL elapses (see getInventory). Gated by the API's collectInventory flag:
  // metrics-only polls skip the heavy config collection (no arp/ndp/interfaces/
  // gateways/disk, no SSH ZFS) but keep the identity scalars fresh with ONE
  // cheap system-info call so the device view never blanks between windows.
  let inventory: InventorySnapshot | null = null;
  if (!wantsInventory(collectInventory)) {
    const info = await getSystemInformation(host, apiKey, apiSecret, transport, ports).catch(() => undefined);
    if (info?.ok && info.data && typeof info.data === 'object') {
      const d = info.data as Record<string, unknown>;
      if (d['name'] !== undefined) metrics['hostname'] = String(d['name']);
      const versions = d['versions'];
      if (Array.isArray(versions) && versions.length > 0) metrics['version'] = String(versions[0]);
    }
  } else {
    inventory = await getInventory(host, apiKey, apiSecret, transport, credentials, ports, sshPort, dhcpBackendOverride);
    // Fresh authoritative ZFS data only when the SSH enrichment succeeded for this
    // snapshot (served from cache like the rest of the inventory — pool states are
    // slow-changing). Drives notification mirroring in /monitoring.
    zfsFresh = inventory.zfsSshCollected === true;
    if (inventory.hostname) metrics['hostname'] = inventory.hostname;
    if (inventory.version) metrics['version'] = inventory.version;
    if (inventory.arp.length > 0) metrics['arp'] = inventory.arp;
    if (inventory.ndp.length > 0) metrics['ndp'] = inventory.ndp;
    // Configured networks (interface IPs with CIDR + VLAN id) and active DHCP
    // leases — consumed by the API's normalized inventory tables (Networks/Hosts
    // pages) in addition to being rendered as generic tables in the device view.
    if (inventory.networks.length > 0) metrics['networks'] = inventory.networks;
    if (inventory.dhcpLeases.length > 0) metrics['dhcpLeases'] = inventory.dhcpLeases;

    // Configured DHCP networks + static reservations for the cross-device DHCP page.
    // Emitted whenever the read SUCCEEDED — present-but-empty is authoritative
    // (the appliance has no ranges/reservations); null (read failed) keeps the key
    // absent so a transient error never wipes previously ingested rows.
    if (Array.isArray(inventory.dhcpNetworks)) metrics['dhcpNetworks'] = inventory.dhcpNetworks;
    if (Array.isArray(inventory.dhcpReservations)) metrics['dhcpReservations'] = inventory.dhcpReservations;

    // Static DNS host entries for the cross-device DNS page. Emitted whenever
    // the read SUCCEEDED — present-but-empty is authoritative (the appliance
    // has no hosts); null (read failed) keeps the key absent so a transient
    // error never wipes previously ingested rows.
    if (Array.isArray(inventory.dnsEntries)) metrics['dnsEntries'] = inventory.dnsEntries;

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
  }

  // Interface names (for the traffic table rows)
  try {
    const ifaces = await getInterfaces(host, apiKey, apiSecret, transport, ports);
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
    const stats = await getInterfaceStats(host, apiKey, apiSecret, transport, ports);
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
  // Tunnels / routes / firewall rules — config rows from the cached inventory
  // snapshot enriched with LIVE runtime state (WG handshake age, IPsec SAs,
  // pf rule counters). Gated like the inventory itself: on metrics-only polls
  // these tables simply refresh at the next inventory-due poll.
  if (inventory !== null) {
    const allRoutes = [...inventory.routes, ...deriveConnectedAndDefaultRoutes(inventory.networks, inventory.gateways, inventory.routes)];

    const tunnelPromise: Promise<unknown> | null =
      inventory.tunnels.length > 0
        ? enrichTunnelsWithLiveState(createClient(host, { apiKey, apiSecret }, transport, ports), inventory.tunnels).catch(() => inventory.tunnels)
        : null;
    const routePromise: Promise<unknown> | null =
      allRoutes.length > 0
        ? enrichRoutesWithGatewayStatus(createClient(host, { apiKey, apiSecret }, transport, ports), allRoutes, {
            log: (_level, message, context) => logger.warn(message, { deviceId, context }),
          }).catch(() => allRoutes)
        : null;
    const fwStatsPromise: Promise<Map<string, { packets: number | null; bytes: number | null; states: number | null }>> | null =
      inventory.firewallRules !== null && inventory.firewallRules.length > 0
        ? fetchFilterRuleStats(createClient(host, { apiKey, apiSecret }, transport, ports)).catch(() => new Map())
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
    // Services (Services page): emit the cached rc-service rows with their running
    // state. Only present when collection SUCCEEDED — a failed cycle keeps the
    // previous snapshot's rows alive on the API side; an appliance that reports
    // zero services emits [] which authoritatively clears stale rows.
    if (inventory.services !== null) {
      metrics['services'] = inventory.services;
    }
    // Certificates — emit the collected rows (HTTPS cert + SSH host key). Always
    // emitted when present so a renewed/changed cert refreshes in place; an empty
    // array is authoritative for this device+plugin (delete-on-absent at ingest).
    if (inventory.certificates.length > 0) {
      metrics['certificates'] = inventory.certificates;
    }
  }

  return { metrics, interfaces, zfsFresh };
}

// --- Firewall events push pipeline (fire-and-forget batches) ------------------
// The appliance's firewall log is an append-only stream; instead of shipping it
// through the telemetry snapshot we PUSH new rows to the API's internal
// /plugin/firewall-events endpoint (same pattern as flow-collector → /plugin/flows).
// Incremental reads use the per-row `__digest__` cursor: GET .../log?digest=D
// returns the rows at-or-newer-than D, so we store the newest-seen digest in the
// shared state store and dedupe by vendorEventId on ingest (unique index).

const EVENT_STATE_NAMESPACE = 'firewall-events';
/** Max events fetched + pushed per beat — backlog protection on busy firewalls. */
const EVENT_FETCH_LIMIT = 2000;

const eventApi = axios.create({
  baseURL: (process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, ''),
  timeout: 5_000,
  headers: process.env.PLUGIN_API_KEY ? { 'x-plugin-api-key': process.env.PLUGIN_API_KEY } : undefined,
});

/** Pushes one batch with a single retry; resolves true when the API accepted it. */
async function pushEventBatch(deviceId: string, events: FirewallEventRow[]): Promise<boolean> {
  const body = { pluginId: identity.effectiveUuid, deviceId, events };
  try {
    await eventApi.post('/plugin/firewall-events', body);
    return true;
  } catch {
    await new Promise((r) => setTimeout(r, 500));
    try {
      await eventApi.post('/plugin/firewall-events', body);
      return true;
    } catch (err) {
      logger.warn(`Dropped firewall-event batch of ${events.length} rows for device ${deviceId}`, { context: { error: String((err as Error)?.message ?? err) } });
      return false; // cursor NOT advanced — the same rows are re-fetched next beat
    }
  }
}

/**
 * Collects new firewall events for one host and pushes them to the API. Runs
 * fire-and-forget from /monitoring (never blocks or fails the poll). The digest
 * cursor lives in the shared state store keyed by management address, so it
 * survives container restarts; a missing cursor takes a ≤2000-row baseline of
 * the newest events.
 */
async function collectAndPushFirewallEvents(
  host: string,
  deviceId: string | null | undefined,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  ports?: OpnsensePorts
): Promise<void> {
  if (!deviceId) return; // no device scope → nothing to attribute rows to
  const key = host;
  let cursor: string | null = null;
  try {
    const stored = await stateStore.get(EVENT_STATE_NAMESPACE, key);
    if (stored && typeof stored === 'object' && typeof (stored as Record<string, unknown>)['digest'] === 'string') {
      cursor = ((stored as Record<string, unknown>)['digest'] as string) || null;
    }
  } catch { /* best-effort — no cursor means a fresh baseline */ }

  const client = createClient(host, { apiKey, apiSecret }, transport, ports);
  let rows: FirewallEventRow[];
  try {
    rows = await fetchFirewallEvents(client, { digest: cursor, limit: EVENT_FETCH_LIMIT });
  } catch {
    return; // best-effort — a dead endpoint must never break the poll
  }
  if (rows.length === 0) return;

  const ok = await pushEventBatch(String(deviceId), rows);
  if (!ok) return; // cursor NOT advanced — the same rows are re-fetched next beat

  // Advance the cursor only after a successful push. The API dedupes by
  // (deviceId, pluginId, vendorEventId), so even a lost-ack race can't create
  // duplicate rows.
  const newest = rows[0]; // appliance returns newest-first
  try {
    await stateStore.put([{ namespace: EVENT_STATE_NAMESPACE, key, value: { digest: newest.vendorEventId }, deviceId: String(deviceId) }]);
  } catch { /* best-effort — worst case the next beat re-sends and dedupe absorbs it */ }
}

// --- Per-host state-table walk (Hosts/Networks "States" columns) --------------
// The appliance's live pf state table is walked at its own cadence (option
// `stateWalkIntervalSec`, default 15 min — each walk is a full table scan on the
// box). The previous snapshot lives in memory per device; diffing it against
// the new one yields per-endpoint created/destroyed deltas. Only aggregated
// rows are pushed to POST /plugin/host-states (never the raw states). A failed
// or empty walk keeps the old baseline untouched — no bogus churn spike.

interface HostStateWalkEntry {
  lastRunAt: number;
  /** Previous snapshot's state identities, keyed by state id (null = first walk pending). */
  prev: Map<string, { srcIp: string; dstIp: string }> | null;
}
const hostStateWalks = new Map<string, HostStateWalkEntry>(); // key = management address

/** Pushes one walk's aggregated rows with a single retry (same pattern as events). */
async function pushHostStateBatch(deviceId: string, rows: { ip: string; openStates: number; created: number | null; destroyed: number | null }[]): Promise<boolean> {
  const body = { pluginId: identity.effectiveUuid, deviceId, rows };
  try {
    await eventApi.post('/plugin/host-states', body);
    return true;
  } catch {
    await new Promise((r) => setTimeout(r, 500));
    try {
      await eventApi.post('/plugin/host-states', body);
      return true;
    } catch (err) {
      logger.warn(`Dropped host-state batch of ${rows.length} rows for device ${deviceId}`, { context: { error: String((err as Error)?.message ?? err) } });
      return false; // baseline NOT advanced — the next walk re-diffs against the same prev
    }
  }
}

/**
 * Walks one appliance's full state table, diffs it against the previous
 * snapshot, and pushes per-host aggregates to the API. Runs fire-and-forget
 * from /monitoring (never blocks or fails the poll). The walk is serialized per
 * device via lastRunAt + a single in-flight guard: overlapping polls simply skip.
 */
async function collectAndPushHostStates(
  host: string,
  deviceId: string | null | undefined,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  ports?: OpnsensePorts,
  intervalSec?: number
): Promise<void> {
  if (!deviceId) return; // no device scope → nothing to attribute rows to
  const everyMs = Math.max(0, Number(intervalSec ?? 900)) * 1000;
  if (everyMs === 0) return; // per-host state tracking disabled

  let entry = hostStateWalks.get(host);
  if (!entry) {
    entry = { lastRunAt: 0, prev: null };
    hostStateWalks.set(host, entry);
  }
  const now = Date.now();
  if (now - entry.lastRunAt < everyMs) return; // cadence not elapsed yet
  entry.lastRunAt = now; // claim the slot BEFORE the slow walk — no overlap

  const client = createClient(host, { apiKey, apiSecret }, transport, ports);
  const states = await fetchStateIdentities(client);
  if (states === null) return; // walk failed — baseline untouched, retry next beat

  const open = countOpenStates(states);
  const diff = diffStates(entry.prev, states);
  const rows = buildHostStateRows(open, diff);
  if (rows.length === 0) {
    // Nothing to report — no internal endpoints in this snapshot AND no churn
    // deltas (e.g. empty table with an empty baseline). The API rejects empty
    // batches, so just advance the baseline and skip the push. A non-empty
    // baseline against an empty table always yields destroyed-churn rows, so
    // that case is never skipped here.
    const next = new Map<string, { srcIp: string; dstIp: string }>();
    for (const s of states) next.set(s.id, { srcIp: s.srcIp, dstIp: s.dstIp });
    entry.prev = next;
    return;
  }

  const ok = await pushHostStateBatch(String(deviceId), rows);
  if (!ok) return; // baseline NOT advanced — next walk re-diffs against the same prev

  // Advance the baseline only after a successful push. The API stores snapshots
  // append-only, so even a lost-ack race can't corrupt history (worst case one
  // extra snapshot row).
  const next = new Map<string, { srcIp: string; dstIp: string }>();
  for (const s of states) next.set(s.id, { srcIp: s.srcIp, dstIp: s.dstIp });
  entry.prev = next;
}

// --- Automatic update search (Updates page freshness) -------------------------
// OPNsense only advertises available updates after an update SEARCH has run on-
// device — POST /api/core/firmware/status is a SYNCHRONOUS probe against
// pkg.opnsense.org that takes ~30–90 s. The monitoring path reads the
// appliance's CACHED check result (fast GET), so a device that never ran a
// search shows no updates forever. This trigger runs the probe in the
// BACKGROUND at its own cadence (option `updateCheckIntervalSec`, 0 disables):
// it must NEVER block or fail a poll — the API times out /monitoring POSTs at
// 30 s, well below one probe. Once the probe finishes, the appliance's cache is
// fresh and the very next fast GET (≤ one beat later) surfaces the result with
// the existing wipe/throw semantics of getFirmwareUpdateRows() untouched.

const updateSearches = new Map<string, UpdateSearchEntry>(); // key = management address

/**
 * Triggers a fresh update search on one appliance when its cadence has elapsed
 * (or this is an explicit forced check). Runs fire-and-forget from /monitoring;
 * all failures are contained here — a failed probe only logs and retries on the
 * next beat, it never degrades device health or fails the poll. A forced check
 * younger than 5 min is skipped: the appliance's cache was just refreshed by
 * that probe, and re-probing would serialize every REST call behind configd's
 * lock for another 30–90 s (rapid "Check now" clicks / overlapping refreshes).
 */
async function maybeRunUpdateSearch(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: OpnsenseTransport,
  ports?: OpnsensePorts,
  intervalSec?: number,
  force = false
): Promise<void> {
  const everyMs = Math.max(0, Number(intervalSec ?? DEFAULT_UPDATE_CHECK_INTERVAL_SEC)) * 1000;
  let entry = updateSearches.get(host);
  if (!entry) {
    entry = { lastRunAt: 0, inFlight: false };
    updateSearches.set(host, entry);
  }
  const decision = decideUpdateSearch(entry, Date.now(), everyMs, force);
  if (decision !== 'run') return;

  // Claim the slot BEFORE the slow probe — overlapping polls / rapid "Check now"
  // clicks simply skip while it is in flight. lastRunAt advances on SUCCESS only:
  // a failed probe retries on the next beat instead of waiting out the interval.
  entry.inFlight = true;
  try {
    const client = createClient(host, { apiKey, apiSecret }, transport, ports);
    const res = await firmware.checkForUpdates(client);
    if (!res.ok || !res.data) throw new Error(`update search failed (HTTP ${res.status})`);
    const st = firmware.parseFirmwareStatus(res.data);
    entry.lastRunAt = Date.now();
    // eslint-disable-next-line no-console
    console.log(
      `[opnsense] update search done for ${host} — ${st.packages.length + st.majorSets.length} pending item(s), reboot required: ${st.needsReboot}`
    );
  } catch (err) {
    // eslint-disable-next-line no-console
    console.warn(`[opnsense] update search failed for ${host}: ${(err as Error)?.message ?? err}`);
  } finally {
    entry.inFlight = false;
  }
}

// --- Updates page: live firmware status --------------------------------------
// Reads the appliance's CACHED update check (fast GET — no synchronous probe)
// and turns it into UpdateRows:
//   - one 'firmware' row for the OS itself. Minor point releases apply via
//     `firmware.update`; a pending MAJOR release line applies via
//     `firmware.upgrade` (the appliance reboots into the new line).
//   - one 'os-package' row per other pending package — all of them are applied
//     by the SAME minor update job, so every row points at `firmware.update`
//     with an EMPTY input (one plan step = one job start; the webapp merges a
//     device's kind-groups into single steps).
// Returns [] when nothing is pending — that empty array IS authoritative (the
// API wipes stale rows). THROWS on transport failure so the caller omits the
// key entirely (no wipe on a transient outage).
async function getFirmwareUpdateRows(host: string, client: import('axios').AxiosInstance): Promise<UpdateRow[]> {
  const res = await firmware.getFirmwareStatus(client);
  if (!res.ok || !res.data) throw new Error(`firmware status failed (HTTP ${res.status})`);
  const st = firmware.parseFirmwareStatus(res.data);
  if (!st.checked) return [];

  const rows: UpdateRow[] = [];
  const osPkg = st.packages.find((p) => p.name === (st.productId ?? '') || /opnsense-(business|community)$/.test(p.name));
  const pkgRows = st.packages.filter((p) => p !== osPkg);

  // Firmware row: major line wins (it subsumes the minor update — upgrading to
  // a new series installs everything), otherwise the minor point release.
  if (st.majorSets.length > 0) {
    rows.push({
      name: 'os',
      kind: 'firmware',
      currentVersion: st.productVersion ?? null,
      latestVersion: st.nextSeries ? `${st.nextSeries} (new release line)` : null,
      available: true,
      rebootRequired: true, // major upgrades always boot a new environment
      applyActionId: 'firmware.upgrade',
      applyInput: {},
      extra: { downloadSize: st.downloadSize ?? undefined },
    });
  } else if (osPkg) {
    rows.push({
      name: 'os',
      kind: 'firmware',
      currentVersion: osPkg.currentVersion ?? st.productVersion ?? null,
      latestVersion: osPkg.newVersion ?? null,
      available: true,
      rebootRequired: st.needsReboot,
      applyActionId: 'firmware.update',
      applyInput: {},
      extra: { downloadSize: st.downloadSize ?? undefined },
    });
  }

  // Package rows — each applied by the same minor update job (empty input).
  for (const p of pkgRows) {
    if (!p.newVersion) continue;
    rows.push({
      name: p.name,
      kind: 'os-package',
      currentVersion: p.currentVersion ?? null,
      latestVersion: p.newVersion,
      available: true,
      rebootRequired: false,
      applyActionId: 'firmware.update',
      applyInput: {},
    });
  }

  return rows;
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
  notifier.setEnabled(settings.notifyAlerts !== false);
  const transport: OpnsenseTransport =
    typeof settings.transport === 'string' && ['auto', 'http', 'https'].includes(settings.transport)
      ? (settings.transport as OpnsenseTransport)
      : 'auto';
  const ports = portsOf(settings);
  const sshPort = sshPortOf(settings);

  // Decrypted assignment fields incl. bound slots (slots.ssh when the user
  // bound an SSH credential) — forwarded to the inventory for ZFS enrichment.
  const credentials = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;

  // Window-based scheduling: the API sends collectInventory=false on
  // metrics-only polls (absent = full collection, old-API compatible).
  const collectInventory = body.collectInventory !== false;

  try {
    // Certificate pinning — verify the appliance's TLS cert against UNM's
    // inventory BEFORE any credentials are transmitted (throws on mismatch).
    await assertPinned(req, managementAddress, transport, ports);

    // The user-set `dhcpBackend` option (when not 'auto') wins over auto-detect
    // for the READ path too — reads and writes must agree on the backend.
    const { metrics, interfaces, zfsFresh } = await collectMetrics(managementAddress, apiKey, apiSecret, transport, deviceId, credentials, collectInventory, ports, sshPort, dhcpBackendOverrideOf(settings));

    // Firewall events: fetch new log rows since the last digest cursor and push
    // them to the API's internal endpoint. Fire-and-forget — NOT awaited, so it
    // runs in parallel with the response below and can never block or fail this
    // poll; all failures are contained inside collectAndPushFirewallEvents.
    void collectAndPushFirewallEvents(managementAddress, deviceId, apiKey, apiSecret, transport, ports).catch(() => { /* best-effort */ });

    // Per-host state-table walk (Hosts/Networks "States" columns): full table
    // scan at its own slow cadence (option stateWalkIntervalSec), diffed against
    // the previous snapshot in memory. Fire-and-forget like the events push —
    // a 30 s+ walk must never block or fail this poll.
    const stateWalkIntervalSec = typeof settings.stateWalkIntervalSec === 'number' ? settings.stateWalkIntervalSec : undefined;
    void collectAndPushHostStates(managementAddress, deviceId, apiKey, apiSecret, transport, ports, stateWalkIntervalSec).catch(() => { /* best-effort */ });

    // Automatic update search (option updateCheckIntervalSec): a fresh probe at
    // its own slow cadence so the appliance's CACHED check result — which the
    // updates row below reads on every beat — stays current. An explicit forced
    // refresh ("Check now" on the Updates page) bypasses both cadence and a zero
    // interval. Fire-and-forget like the state walk: a 30–90 s probe must never
    // block or fail this poll (the API times out /monitoring at 30 s).
    const updateCheckIntervalSec = typeof settings.updateCheckIntervalSec === 'number' ? settings.updateCheckIntervalSec : undefined;
    void maybeRunUpdateSearch(managementAddress, apiKey, apiSecret, transport, ports, updateCheckIntervalSec, body.forceUpdateCheck === true).catch(() => { /* best-effort */ });

    // Echo of the user-selected model/firmware (mirrors the LANCOM plugin) —
    // informational only; shown as text cards in the device detail view.
    if (selectedModel) metrics['system.model'] = selectedModel;
    if (selectedFirmware) metrics['system.firmwareVersion'] = selectedFirmware;

    // Detected features for the support matrix (see deviceSupport.ts). Derived
    // from THIS poll's inventory when available, otherwise re-emitted from the
    // last known set — the API evaluates capabilities from the LATEST snapshot,
    // which must therefore always carry this key. No metric descriptor on
    // purpose: it is not a display metric.
    const detectedFeatures = new Set(lastDetectedFeatures.get(managementAddress) ?? []);
    if (collectInventory && Array.isArray(metrics['filesystems'])) {
      // ZFS storage present? The inventory's filesystem rows carry the mapped
      // type — 'zfs-pool' for the API's zfs root row and every SSH-enriched
      // pool/dataset. Absent key = fetch failed → keep the previously known set.
      const fsRows = metrics['filesystems'] as Record<string, unknown>[];
      if (fsRows.some((f) => String(f['type']) === 'zfs-pool')) detectedFeatures.add('zfs');
    }
    lastDetectedFeatures.set(managementAddress, Array.from(detectedFeatures));
    metrics[DETECTED_FEATURES_METRIC_KEY] = Array.from(detectedFeatures);

    // Updates page — LIVE firmware status from the appliance's own update
    // engine (System → Updates in its web UI): a fast GET of the cached check
    // result. Emits one firmware row (minor `firmware.update` / major
    // `firmware.upgrade`) plus one os-package row per pending package — all
    // applied through the appliance's own update jobs, so the Updates page can
    // trigger them with a single action.
    try {
      const fwClient = createClient(managementAddress, { apiKey, apiSecret }, transport, ports);
      metrics['updates'] = await getFirmwareUpdateRows(managementAddress, fwClient);
    } catch (e) {
      // No key on failure — the API keeps the previous rows (no wipe).
      console.error(`[opnsense-plugin] firmware updates failed for ${managementAddress}: ${(e as Error)?.message ?? e}`);
    }

    // Security checks ride the INVENTORY window: file-integrity baselines +
    // failed-login/rate-limit/account scans over the optional `ssh` slot.
    // null = did not run this cycle (disabled / no ssh slot / SSH failure) → omit
    // the key entirely so stored rows survive AND live security alerts are kept;
    // [] = ran and clean → authoritative wipe + resolve lingering notifications.
    let securityFindings: SecurityFinding[] | null = null;
    if (collectInventory) {
      try {
        const secSettings: SecuritySettings = {
          enabled: settings.securityChecksEnabled !== false,
          watchedFiles: String(settings.securityWatchedFiles ?? DEFAULT_WATCHED_FILES.join(', '))
            .split(',')
            .map((s) => s.trim())
            .filter((s) => s.startsWith('/')),
          authFailureWindowHours: Number(settings.securityAuthFailureWindowHours ?? 24),
          authFailureWarnThreshold: Number(settings.securityAuthFailureWarnThreshold ?? 10),
          authFailureCriticalThreshold: Number(settings.securityAuthFailureCriticalThreshold ?? 50),
        };
        const secRows = await collectSecurityChecks(managementAddress, credentials, sshPort, deviceId, secSettings);
        if (secRows !== null) {
          metrics['securityChecks'] = secRows;
          // Only warning/critical are actionable — 'info' rows (e.g. rate limiting
          // active) stay on the Security page but never hit the notification center.
          securityFindings = [];
          for (const r of secRows) {
            if (r.status !== 'warning' && r.status !== 'critical') continue;
            securityFindings.push({ kind: String(r.kind), name: String(r.name), status: r.status, detail: typeof r.detail === 'string' ? r.detail : undefined });
          }
        }
      } catch {
        /* best-effort — a failed check must never sink the poll */
      }
    }

    // Notification-center mirroring (gated by `notifyAlerts`): appliance-level
    // conditions that are NOT derivable from the scalar health value. Both sources
    // pass `null` when there is no fresh authoritative data this cycle, which
    // leaves their known-sets untouched — a transient SSH failure or an API-only
    // poll can never wrongly clear a live alert (see ./notifications.ts).
    if (notifier.enabled) {
      const fsRows = Array.isArray(metrics['filesystems']) ? (metrics['filesystems'] as Record<string, unknown>[]) : [];
      const zfsPools: ZfsPoolCondition[] | null = zfsFresh
        ? fsRows
            .filter((f) => String(f['type']) === 'zfs-pool')
            .map((f) => ({ name: String(f['name'] ?? ''), status: String(f['status'] ?? 'online').toLowerCase() }))
            .filter((p) => p.name !== '' && p.status !== 'online' && p.status !== 'healthy')
        : null;
      mirrorOpnsenseConditions(
        notifier,
        managementAddress,
        deviceId ?? null,
        typeof metrics['hostname'] === 'string' ? metrics['hostname'] : undefined,
        zfsPools,
        securityFindings,
      );
    }

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
        logToApi: settings.logToApi === true,
        notifyAlerts: settings.notifyAlerts !== false,
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
  const ports = portsOf(settings);

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
    // Certificate pinning — a config action transmits real credentials; refuse
    // the connection when the appliance's key differs from UNM's inventory.
    await assertPinned(req, managementAddress, transport, ports);

    const ctx = await buildActionContext({
      host: managementAddress,
      deviceId: typeof deviceId === 'string' ? deviceId : undefined,
      deviceName: typeof body.deviceName === 'string' && body.deviceName !== '' ? (body.deviceName as string) : undefined,
      credentials: stepCredentials,
      transport,
      settings,
      ports,
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
    // Transport-level failures (device down / not ready yet) are transient — the
    // plan executor re-dispatches them per the plan's retry policy. HTTP-level
    // outcomes already come back as ok:false results above and stay hard.
    const retryable = isTransientTransportError(err);
    res.status(200).json({ success: false, result: { error: (err as Error).message, ...(retryable ? { retryable: true } : {}) } });
  }
});

/** Builds the ActionContext for a /config call (client + runtime context). */
async function buildActionContext(args: {
  host: string;
  deviceId?: string;
  deviceName?: string;
  credentials: StepCredentials;
  transport: OpnsenseTransport;
  settings: Record<string, unknown>;
  ports?: OpnsensePorts;
}): Promise<ActionContext> {
  const { host, deviceId, deviceName, credentials, transport, settings, ports } = args;
  const client = createClient(host, { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret }, transport, ports);
  const runtime = await resolveRuntimeContext(
    host,
    { apiKey: credentials.apiKey, apiSecret: credentials.apiSecret },
    transport,
    settings,
    ports
  );
  return {
    client,
    host,
    deviceId,
    deviceName,
    credentials,
    transport,
    edition: runtime.edition,
    syncClasses: runtime.syncClasses as ActionContext['syncClasses'],
    dnsBackend: runtime.dnsBackend,
    dhcpBackend: runtime.dhcpBackend,
    // SSH port for actions that ride the optional `ssh` slot (ZFS inventory,
    // security re-baseline) — mirrors the monitoring path's sshPortOf(settings).
    extra: { sshPort: resolveSshPort(settings.sshPort) },
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
    ports: portsOf(settings),
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
    // Per-device overrides from the rollout wizard's confirmed preflight values.
    deviceInputs: body.deviceInputs && typeof body.deviceInputs === 'object' ? (body.deviceInputs as Record<string, Record<string, unknown>>) : undefined,
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
 * POST /preflight — resolve best-guess per-device values for a canonical fleet
 * intent BEFORE planning (the "smart" half of the rollout wizard). Body:
 * { intentActionId, inputs?, device: { deviceId, managementAddress, credentials } }
 * READ-ONLY by contract: resolvers probe live state (interfaces_info, L2
 * topology, an assignment-path GET) and return suggestions; they never write.
 * The webapp shows the values with confidence + notes and lets the user
 * override them before plan creation (overrides ride back in deviceInputs).
 */
app.post('/preflight', async (req, res) => {
  const body = req.body ?? {};
  const intentActionId: string | undefined = typeof body.intentActionId === 'string' ? body.intentActionId : undefined;
  const inputs: Record<string, unknown> =
    body.inputs && typeof body.inputs === 'object' ? (body.inputs as Record<string, unknown>) : {};
  const dev = body.device ?? {};
  const managementAddress: string | undefined = typeof dev.managementAddress === 'string' ? dev.managementAddress : undefined;

  if (!intentActionId || !managementAddress) {
    res.status(400).json({ error: 'intentActionId and device.managementAddress are required' });
    return;
  }
  const resolver = PREFLIGHT_RESOLVERS[intentActionId];
  if (!resolver) {
    res.status(400).json({ error: `No preflight resolver for intent "${intentActionId}"` });
    return;
  }

  // Same credential assembly as /config — the primary secret fields plus bound
  // slots under credentials.slots.<name> (SSH is needed for ≤26.4 writes).
  const credsFields = (dev.credentials && typeof dev.credentials === 'object' ? dev.credentials : {}) as Record<string, unknown>;
  const stepCredentials: StepCredentials = {
    apiKey: typeof credsFields['apiKey'] === 'string' ? (credsFields['apiKey'] as string) : '',
    apiSecret: typeof credsFields['apiSecret'] === 'string' ? (credsFields['apiSecret'] as string) : '',
    ...credsFields,
  };

  const settings = readSettings(req, PLUGIN_OPTIONS);
  logger.setEnabled(settings.logToApi === true);
  try {
    const ctx = await buildActionContext({
      host: managementAddress,
      deviceId: typeof dev.deviceId === 'string' ? dev.deviceId : undefined,
      credentials: stepCredentials,
      transport: transportOf(settings),
      settings,
      ports: portsOf(settings),
    });
    const result = await resolver(ctx, inputs);
    res.status(200).json({ result });
  } catch (err) {
    // Preflight is advisory — a probe failure degrades the suggestion, it must
    // never block planning. The UI shows the device as degraded.
    res.status(200).json({ result: { deviceId: String(dev.deviceId ?? ''), values: [], degraded: true, error: (err as Error).message } });
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
  const ports = portsOf(settings);

  // Credentials: the assignment's decrypted fields are at top level of
  // `credentials` (secret type `apiKey`) — same model as /config.
  const creds = (body.credentials && typeof body.credentials === 'object' ? body.credentials : {}) as Record<string, unknown>;
  const apiKey = typeof creds['apiKey'] === 'string' ? (creds['apiKey'] as string) : '';
  const apiSecret = typeof creds['apiSecret'] === 'string' ? (creds['apiSecret'] as string) : '';

  // Certificate pinning — /state reads live data with credentials; verify first.
  await assertPinned(req, body.managementAddress, transport, ports);

  // `creds` also carries bound slots (slots.ssh) for the optional ZFS path.
  const snapshot = await getInventory(body.managementAddress, apiKey, apiSecret, transport, creds, ports, sshPortOf(settings), dhcpBackendOverrideOf(settings));

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