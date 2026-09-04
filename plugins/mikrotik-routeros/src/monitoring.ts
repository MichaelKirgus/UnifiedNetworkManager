/**
 * Monitoring snapshot collection for MikroTik RouterOS routers.
 *
 * The API polls /monitoring every 30 s with a HARD 10 s timeout, so the full
 * router state (system + interfaces + addresses + ARP + DHCP leases + routes +
 * wireless clients) is TTL-cached per host: fresh polls reuse the last good
 * snapshot; only stale or missing snapshots trigger a re-collection. A failed
 * re-collection still serves the stale data with health 'warning' rather than
 * dropping to critical (the router is reachable — one endpoint just misbehaved).
 *
 * All REST values arrive as strings; parsing normalizes them here so the metric
 * builders deal in plain numbers/booleans.
 */

import { createHash } from 'crypto';
import type { MetricDescriptor } from '@unm/plugin-sdk';
import { CounterTracker, TtlCache } from '@unm/plugin-sdk';
import { RouterOsClient, rosNumber, rosString, parseCidr, parseSpeedBitsPerSec } from './routerosClient';

export interface RouterOsOptions {
  /** How long a collected snapshot stays fresh (ms). */
  cacheTtlMs: number;
  /** Per-request timeout for individual REST fetches (ms). */
  requestTimeoutMs: number;
  /** Accept self-signed TLS certificates. */
  insecureTls: boolean;
  /** Scheme policy: auto = HTTPS first + HTTP fallback, https/http pinned. */
  schemeMode: 'auto' | 'https' | 'http';
}

export const DEFAULT_OPTIONS: RouterOsOptions = {
  cacheTtlMs: 60_000,
  requestTimeoutMs: 4_000,
  insecureTls: false,
  schemeMode: 'auto',
};

// --- Snapshot types -----------------------------------------------------------------

export interface RosInterfaceInfo {
  name: string;
  type: string; // ether | bridge | vlan | wireless | lte | ...
  running: boolean;
  disabled: boolean;
  mtu: number | null;
  macAddress: string | null;
  speedLabel: string | null; // e.g. "1G", "auto" (ether only)
  rxBytesTotal: number;
  txBytesTotal: number;
  rxBitsPerSec: number | null;
  txBitsPerSec: number | null;
}

export interface RosAddressRow {
  interface: string;
  address: string; // CIDR as reported ("10.0.0.1/24")
  ip: string;
  prefix: number | null;
  version: 'v4' | 'v6';
}

export interface RosArpRow {
  mac: string;
  ip: string;
  intf: string;
}

export interface RosDhcpLeaseRow {
  mac: string;
  ip: string;
  hostname: string | null;
  expiry: string | null; // ISO timestamp (lease 'expires-after' normalized)
  intf: string | null;
}

export interface RosRouteRow {
  destination: string;
  gateway: string;
  protocol: string; // static | connected | ospf | bgp | rip | other
  distance: number | null;
  status: 'active' | 'inactive';
}

export interface RosWlanClientRow {
  mac: string;
  ip: string;
  hostname: string | null;
  intf: string; // radio name
}

/** One firewall rule (filter or NAT) normalized to the unified Firewall-page shape. */
export interface RosFirewallRuleRow {
  ruleType: 'filter' | 'dnat' | 'snat';
  vendorRuleId: string; // RouterOS .id — stable per table
  position: number;
  protocol: string; // normalized name ('tcp', 'udp', …); '' = any
  sourceIp: string;
  destIp: string;
  sourcePort: string | null;
  destPort: string | null;
  action: 'allow' | 'deny' | 'other';
  enabled: boolean;
  description: string; // rule comment
  scope: string; // chain (+ interface lists)
  /** IP family the rule applies to — derived from the address text. */
  ipVersion: 'v4' | 'v6' | 'both';
  /** Live hit counters (free in the same REST response); null when absent. */
  packets: number | null;
  bytes: number | null;
  extra: Record<string, unknown>;
}

export interface RouterOsSnapshot {
  identity: string; // /system/identity
  version: string; // e.g. "7.14"
  buildTime: string;
  platform: string; // architecture-name, e.g. "x86_64"
  boardName: string; // e.g. "CCR2004-1G-12S+2XS+"
  hostname: string;
  cpuLoadPercent: number | null;
  freeMemoryBytes: number | null;
  totalMemoryBytes: number | null;
  // Root filesystem (squashfs/ext4 on the router's flash) — /system/resource.
  freeDiskBytes: number | null;
  totalDiskBytes: number | null;
  uptimeSeconds: number | null;
  interfaces: RosInterfaceInfo[];
  addresses: RosAddressRow[];
  arp: RosArpRow[];
  dhcpLeases: RosDhcpLeaseRow[];
  routes: RosRouteRow[];
  firewallRules: RosFirewallRuleRow[]; // /ip/firewall/filter + /ip/firewall/nat
  wlanClients: RosWlanClientRow[];
  totalRxBitsPerSec: number | null;
  totalTxBitsPerSec: number | null;
}

// --- Parsing helpers ------------------------------------------------------------------

/** RouterOS uptime strings look like "2d20h12m20s" / "3h5m" / "45s". */
function parseUptimeSeconds(raw: string | undefined): number | null {
  if (!raw) return null;
  const m = raw.match(/(?:(\d+)d)?(?:([0-9.]+)h)?(?:([0-9.]+)m)?(?:([0-9.]+)s)?/);
  if (!m || raw.trim() === '') return null;
  const d = Number(m[1] ?? 0);
  const h = Number(m[2] ?? 0);
  const min = Number(m[3] ?? 0);
  const s = Number(m[4] ?? 0);
  if (!Number.isFinite(d + h + min + s)) return null;
  return Math.floor(d * 86_400 + h * 3_600 + min * 60 + s);
}

/** Normalizes a MAC to lowercase colon form ("AA:BB:CC:DD:EE:FF"); null when absent/invalid. */
function normMac(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const hex = raw.replace(/[^0-9a-fA-F]/g, '').toLowerCase();
  if (hex.length !== 12) return null;
  if (hex === '000000000000') return null; // RouterOS uses all-zero for "no MAC"
  return hex.replace(/(.{2})/g, '$1:').replace(/:$/, '');
}

/** Derives the Routes-page protocol label from a /ip/route row. */
function routeProtocol(row: Record<string, unknown>): string {
  const kind = rosString(row, ['kind']); // static | connected | ecmp | ...
  if (kind === 'static') return 'static';
  if (kind === 'connected') return 'connected';
  const proto = rosString(row, ['routing-protocol', 'scope']) ?? '';
  const p = proto.toLowerCase();
  if (p.includes('ospf')) return 'ospf';
  if (p.includes('bgp')) return 'bgp';
  if (p.includes('rip')) return 'rip';
  return 'other';
}

// --- Firewall rule parsing -----------------------------------------------------------

/** RouterOS reports protocols as numbers or names ('6'/'tcp', '17'/'udp', …). */
const ROS_PROTOCOL_NAMES: Record<string, string> = {
  '1': 'icmp', '2': 'igmp', '6': 'tcp', '17': 'udp', '41': 'ipv6-encap',
  '43': 'ipv6-route', '44': 'ipv6-frag', '47': 'gre', '50': 'esp', '51': 'ah',
  '58': 'ipv6-icmp', '89': 'ospf', '132': 'sctp',
};

/** Normalizes a RouterOS protocol value to a lowercase name ('' = any/absent). */
function normRosProtocol(raw: string | undefined): string {
  if (!raw) return '';
  const p = raw.trim().toLowerCase();
  if (p === '') return '';
  return ROS_PROTOCOL_NAMES[p] ?? p; // already a name ('tcp') or unknown number → keep as-is
}

/** Normalizes a RouterOS filter action to the unified allow/deny/other verdict. */
function normFilterAction(raw: string | undefined): 'allow' | 'deny' | 'other' {
  const a = (raw ?? '').trim().toLowerCase();
  if (a === 'accept') return 'allow';
  if (a === 'drop' || a === 'reject') return 'deny';
  return 'other'; // passthrough, add-to-logging, …
}

/** Builds the scope label: chain + any interface lists that narrow it. */
function ruleScope(row: Record<string, unknown>): string {
  const parts = [rosString(row, ['chain']) ?? ''];
  for (const k of ['in-interface-list', 'out-interface-list']) {
    const v = rosString(row, [k]);
    if (v) parts.push(`${k.replace('-interface-list', '')}: ${v}`);
  }
  return parts.filter(Boolean).join(' | ');
}

/** Derives the IP family from a rule's address text. RouterOS has no explicit
 * family field — an IPv6 literal contains ':', CIDR suffixes like /128 are v6,
 * everything else is treated as v4 (the common case). Empty addresses = any → 'both'. */
function deriveIpVersion(src: string, dst: string): 'v4' | 'v6' | 'both' {
  const fams = [src, dst].filter(Boolean).map((a) => (a.includes(':') ? 'v6' : 'v4'));
  if (fams.length === 0) return 'both'; // no address constraint — matches both families
  if (fams.every((f) => f === 'v4')) return 'v4';
  if (fams.every((f) => f === 'v6')) return 'v6';
  return 'both'; // mixed families in one rule
}

/** Expands a comma list of address-list names into name → contents entries. */
function expandAddressLists(lists: Map<string, string[]>, raw: string | undefined): Record<string, string[]> {
  if (!raw) return {};
  const out: Record<string, string[]> = {};
  for (const name of raw.split(',').map((n) => n.trim()).filter(Boolean)) {
    const contents = lists.get(name);
    if (contents) out[name] = contents; // unknown list → omitted (best-effort)
  }
  return out;
}

/** Maps one /ip/firewall/filter row onto the unified shape. */
function parseFilterRule(row: Record<string, unknown>, position: number, addrLists?: Map<string, string[]>): RosFirewallRuleRow | null {
  const id = rosString(row, ['.id']);
  if (!id) return null;
  const extra: Record<string, unknown> = { chain: rosString(row, ['chain']) ?? '' };
  for (const k of ['connection-state', 'time', 'address-list', 'src-address-list', 'dst-address-list', 'in-interface', 'out-interface', 'log']) {
    const v = rosString(row, [k]);
    if (v) extra[k] = v;
  }
  // Expand referenced address lists to their contents — the Firewall page uses
  // these for cross-device resolution (a list name alone is not intuitive).
  const srcLists = expandAddressLists(addrLists ?? new Map(), rosString(row, ['src-address-list']));
  if (Object.keys(srcLists).length > 0) extra['srcAddressLists'] = srcLists;
  const dstLists = expandAddressLists(addrLists ?? new Map(), rosString(row, ['dst-address-list']));
  if (Object.keys(dstLists).length > 0) extra['dstAddressLists'] = dstLists;
  // Live hit counters — free in the same response; surfaced as first-class columns.
  const packets = rosNumber(row, ['packets']) ?? null;
  const bytes = rosNumber(row, ['bytes']) ?? null;
  const sourceIp = rosString(row, ['src-address']) ?? '';
  const destIp = rosString(row, ['dst-address']) ?? '';
  return {
    ruleType: 'filter',
    vendorRuleId: id,
    position,
    protocol: normRosProtocol(rosString(row, ['protocol'])),
    sourceIp,
    destIp,
    sourcePort: rosString(row, ['src-port']) || null,
    destPort: rosString(row, ['dst-port']) || null,
    action: normFilterAction(rosString(row, ['action'])),
    enabled: rosString(row, ['disabled']) !== 'true', // key absent = enabled
    description: rosString(row, ['comment']) ?? '',
    scope: ruleScope(row),
    ipVersion: deriveIpVersion(sourceIp, destIp),
    packets,
    bytes,
    extra,
  };
}

/** Maps one /ip/firewall/nat row (chain srcnat → snat, dstnat → dnat). */
function parseNatRule(row: Record<string, unknown>, position: number, addrLists?: Map<string, string[]>): RosFirewallRuleRow | null {
  const id = rosString(row, ['.id']);
  if (!id) return null;
  const chain = (rosString(row, ['chain']) ?? '').toLowerCase();
  // srcnat/dstnat are the only NAT chains that carry per-rule address/port data.
  if (chain !== 'srcnat' && chain !== 'dstnat') return null;
  const ruleType: RosFirewallRuleRow['ruleType'] = chain === 'srcnat' ? 'snat' : 'dnat';
  const extra: Record<string, unknown> = { chain };
  for (const k of ['to-addresses', 'to-ports', 'address-list', 'in-interface', 'out-interface']) {
    const v = rosString(row, [k]);
    if (v) extra[k] = v;
  }
  // NAT rules can also reference address lists — expand them the same way.
  const srcLists = expandAddressLists(addrLists ?? new Map(), rosString(row, ['src-address-list']));
  if (Object.keys(srcLists).length > 0) extra['srcAddressLists'] = srcLists;
  const dstLists = expandAddressLists(addrLists ?? new Map(), rosString(row, ['dst-address-list']));
  if (Object.keys(dstLists).length > 0) extra['dstAddressLists'] = dstLists;
  // Live hit counters — free in the same response; surfaced as first-class columns.
  const packets = rosNumber(row, ['packets']) ?? null;
  const bytes = rosNumber(row, ['bytes']) ?? null;
  const sourceIp = rosString(row, ['src-address']) ?? '';
  const destIp = rosString(row, ['dst-address']) ?? '';
  return {
    ruleType,
    vendorRuleId: id,
    position,
    protocol: normRosProtocol(rosString(row, ['protocol'])),
    sourceIp,
    destIp,
    sourcePort: rosString(row, ['src-port']) || null,
    destPort: rosString(row, ['dst-port']) || null,
    action: 'other', // NAT actions (masquerade/src-nat/dst-nat/redirect) have no allow/deny verdict
    enabled: rosString(row, ['disabled']) !== 'true',
    description: rosString(row, ['comment']) ?? '',
    scope: ruleScope(row),
    ipVersion: deriveIpVersion(sourceIp, destIp),
    packets,
    bytes,
    extra,
  };
}

/** Parses both firewall tables into unified rows (position = array index per table). */
function parseFirewallRules(
  filterRows: Record<string, unknown>[],
  natRows: Record<string, unknown>[],
  addrLists?: Map<string, string[]>
): RosFirewallRuleRow[] {
  const out: RosFirewallRuleRow[] = [];
  filterRows.forEach((row, i) => {
    const mapped = parseFilterRule(row, i, addrLists);
    if (mapped) out.push(mapped);
  });
  natRows.forEach((row, i) => {
    const mapped = parseNatRule(row, i, addrLists);
    if (mapped) out.push(mapped);
  });
  return out;
}

/** Builds the address-list name → contents map from /ip/firewall/address-list rows. */
function buildAddressListMap(raw: unknown): Map<string, string[]> {
  const map = new Map<string, string[]>();
  if (!Array.isArray(raw)) return map;
  for (const row of raw) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const name = rosString(r, ['list']);
    const address = rosString(r, ['address']);
    if (!name || !address) continue;
    // `address` is a comma-separated list of IPs/CIDRs.
    map.set(name, address.split(',').map((a) => a.trim()).filter(Boolean));
  }
  return map;
}

// --- Collection ---------------------------------------------------------------------

/** REST single-row tables (/system/resource, /system/identity) come back as a one-element array. */
function firstRow(raw: unknown): Record<string, unknown> {
  if (Array.isArray(raw)) return (raw[0] && typeof raw[0] === 'object' ? raw[0] : {}) as Record<string, unknown>;
  return (raw && typeof raw === 'object' ? raw : {}) as Record<string, unknown>;
}

/** Collects one full snapshot from the router. Throws on transport/auth failure. */
export async function collectSnapshot(client: RouterOsClient): Promise<RouterOsSnapshot> {
  // Probe gate first — /system/resource is cheap and proves REST + auth work.
  const resource = firstRow(await client.get('/system/resource'));
  if (Object.keys(resource).length === 0) {
    throw new Error('Not a recognized RouterOS device — /rest/system/resource returned no data.');
  }

  // Everything else in one parallel batch; each endpoint is best-effort so a
  // missing feature (e.g. no DHCP server) degrades to an empty table instead of
  // failing the whole poll. Total budget stays well under the API's 10 s cap:
  // per-request timeout × 2 (auto scheme fallback) ≈ 8 s worst case, and the
  // batch runs concurrently.
  const [identityRes, ifaceRes, addrRes, arpRes, dhcpRes, routeRes, fwFilterRes, fwNatRes, fwAddrListRes, wlanRes] = await Promise.allSettled([
    client.get('/system/identity'),
    client.get<Record<string, unknown>[]>('/interface'),
    client.get<Record<string, unknown>[]>('/ip/address'),
    client.get<Record<string, unknown>[]>('/arp'),
    client.get<Record<string, unknown>[]>('/ip/dhcp-server/lease'),
    client.get<Record<string, unknown>[]>('/ip/route'),
    client.get<Record<string, unknown>[]>('/ip/firewall/filter'), // firewall filter rules (forward/input/output)
    client.get<Record<string, unknown>[]>('/ip/firewall/nat'), // NAT rules (srcnat/dstnat chains)
    client.get<Record<string, unknown>[]>('/ip/firewall/address-list'), // list contents — expands rule src/dst-address-list refs
    client.get<Record<string, unknown>[]>('/interface/wifi/registration-table'), // ROS 7 WiFi; absent on legacy wireless stacks
  ]);

  const identity = identityRes.status === 'fulfilled' ? firstRow(identityRes.value) : {};

  // --- system ------------------------------------------------------------------
  const cpuLoadRaw = rosNumber(resource, ['cpu-load']);
  const snapshot: RouterOsSnapshot = {
    identity: rosString(identity, ['identity']) ?? '',
    version: rosString(resource, ['version']) ?? '',
    buildTime: rosString(resource, ['build-time']) ?? '',
    platform: rosString(resource, ['architecture-name', 'cpu']) ?? '',
    boardName: rosString(resource, ['board-name']) ?? '',
    hostname: rosString(identity, ['name']) ?? '',
    cpuLoadPercent: cpuLoadRaw !== undefined && Number.isFinite(cpuLoadRaw) ? Math.round(cpuLoadRaw * 10) / 10 : null,
    freeMemoryBytes: rosNumber(resource, ['free-memory']) ?? null,
    totalMemoryBytes: rosNumber(resource, ['total-memory']) ?? null,
    // RouterOS 7 exposes the flash filesystem as free-disk-space/total-disk-space.
    freeDiskBytes: rosNumber(resource, ['free-disk-space', 'free-disk']) ?? null,
    totalDiskBytes: rosNumber(resource, ['total-disk-space', 'total-disk']) ?? null,
    uptimeSeconds: parseUptimeSeconds(rosString(resource, ['uptime'])),
    interfaces: [],
    addresses: [],
    arp: [],
    dhcpLeases: [],
    routes: [],
    firewallRules: [],
    wlanClients: [],
    totalRxBitsPerSec: null,
    totalTxBitsPerSec: null,
  };

  // --- interfaces + throughput rates --------------------------------------------
  if (ifaceRes.status === 'fulfilled' && Array.isArray(ifaceRes.value)) {
    const nowMs = Date.now();
    rateTracker.evictStale(nowMs);
    for (const raw of ifaceRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const name = rosString(row, ['name']);
      if (!name) continue;
      const type = rosString(row, ['type']) ?? '';
      // Virtual interfaces (bridge members, vlan sub-ifs of the same NIC...) are
      // kept — they carry addresses and counters that matter for topology.
      const rxBytes = rosNumber(row, ['rx-byytes', 'rx-bytes']) ?? 0; // RouterOS spells it "byytes"
      const txBytes = rosNumber(row, ['tx-byytes', 'tx-bytes']) ?? 0;
      const rxBitsPerSec = rateTracker.sample(`${client.address}:rx:${name}`, rxBytes, nowMs);
      const txBitsPerSec = rateTracker.sample(`${client.address}:tx:${name}`, txBytes, nowMs);
      snapshot.interfaces.push({
        name,
        type,
        running: rosString(row, ['running']) === 'true',
        disabled: rosString(row, ['disabled']) === 'true',
        mtu: rosNumber(row, ['mtu']) ?? null,
        macAddress: normMac(rosString(row, ['mac-address'])),
        speedLabel: type === 'ether' ? (rosString(row, ['speed']) ?? null) : null,
        rxBytesTotal: rxBytes,
        txBytesTotal: txBytes,
        rxBitsPerSec: rxBitsPerSec === null ? null : Math.round(rxBitsPerSec),
        txBitsPerSec: txBitsPerSec === null ? null : Math.round(txBitsPerSec),
      });
    }
    // Aggregate only when at least one interface produced a rate (first sample → null).
    const anyRate = snapshot.interfaces.some((i) => i.rxBitsPerSec !== null || i.txBitsPerSec !== null);
    if (anyRate) {
      let rx = 0;
      let tx = 0;
      for (const i of snapshot.interfaces) {
        rx += i.rxBitsPerSec ?? 0;
        tx += i.txBitsPerSec ?? 0;
      }
      snapshot.totalRxBitsPerSec = rx;
      snapshot.totalTxBitsPerSec = tx;
    }
  }

  // --- IP addresses ---------------------------------------------------------------
  if (addrRes.status === 'fulfilled' && Array.isArray(addrRes.value)) {
    for (const raw of addrRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const address = rosString(row, ['address']);
      const iface = rosString(row, ['interface', 'actual-interface']) ?? '';
      if (!address) continue;
      const { ip, prefix, version } = parseCidr(address);
      snapshot.addresses.push({ interface: iface, address, ip, prefix, version });
    }
  }

  // --- ARP ------------------------------------------------------------------------
  if (arpRes.status === 'fulfilled' && Array.isArray(arpRes.value)) {
    for (const raw of arpRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const mac = normMac(rosString(row, ['mac-address']));
      const ip = rosString(row, ['address']) ?? '';
      if (!mac || !ip) continue;
      snapshot.arp.push({ mac, ip, intf: rosString(row, ['interface']) ?? '' });
    }
  }

  // --- DHCP leases ------------------------------------------------------------------
  if (dhcpRes.status === 'fulfilled' && Array.isArray(dhcpRes.value)) {
    for (const raw of dhcpRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const mac = normMac(rosString(row, ['mac-address']));
      const ip = rosString(row, ['address']) ?? '';
      if (!mac || !ip) continue;
      // 'expires-after' is a duration string ("1d2h3m4s") — convert to an ISO
      // timestamp relative to now so the Hosts page can show real expiry.
      const ttl = parseUptimeSeconds(rosString(row, ['expires-after']));
      snapshot.dhcpLeases.push({
        mac,
        ip,
        hostname: rosString(row, ['host-name', 'hostname']) ?? null,
        expiry: ttl !== null ? new Date(Date.now() + ttl * 1_000).toISOString() : null,
        intf: rosString(row, ['interface']) ?? null,
      });
    }
  }

  // --- routes ------------------------------------------------------------------------
  if (routeRes.status === 'fulfilled' && Array.isArray(routeRes.value)) {
    for (const raw of routeRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const destination = rosString(row, ['dst-address', 'destination']);
      if (!destination) continue;
      snapshot.routes.push({
        destination,
        gateway: rosString(row, ['gateway']) ?? '',
        protocol: routeProtocol(row),
        distance: rosNumber(row, ['distance']) ?? null,
        status: rosString(row, ['disabled']) === 'true' ? 'inactive' : 'active',
      });
    }
  }

  // --- firewall rules (filter + NAT; best-effort — a missing table degrades to []) ----
  const fwFilterRows = fwFilterRes.status === 'fulfilled' && Array.isArray(fwFilterRes.value) ? fwFilterRes.value : [];
  const fwNatRows = fwNatRes.status === 'fulfilled' && Array.isArray(fwNatRes.value) ? fwNatRes.value : [];
  // Address-list contents (best-effort — the table exists on every ROS version,
  // but a failure must not sink the firewall snapshot).
  const addrLists = buildAddressListMap(fwAddrListRes.status === 'fulfilled' ? fwAddrListRes.value : undefined);
  snapshot.firewallRules = parseFirewallRules(
    fwFilterRows.filter((r): r is Record<string, unknown> => !!r && typeof r === 'object'),
    fwNatRows.filter((r): r is Record<string, unknown> => !!r && typeof r === 'object'),
    addrLists
  );

  // --- wireless clients (ROS 7 WiFi registration table; best-effort) ------------------
  if (wlanRes.status === 'fulfilled' && Array.isArray(wlanRes.value)) {
    for (const raw of wlanRes.value) {
      if (!raw || typeof raw !== 'object') continue;
      const row = raw as Record<string, unknown>;
      const mac = normMac(rosString(row, ['mac-address']));
      const ip = rosString(row, ['address']) ?? '';
      if (!mac || !ip) continue; // IP-less associations are skipped (API requires an IP for wlan rows)
      snapshot.wlanClients.push({
        mac,
        ip,
        hostname: rosString(row, ['hostname']) ?? null,
        intf: rosString(row, ['interface']) ?? '',
      });
    }
  }

  return snapshot;
}

// --- Throughput rate state (per host) ---------------------------------------------------------
// /interface exposes CUMULATIVE byte counters ("rx-byytes"); the Web UI polls it
// and derives rates client-side. We do the same across API poll intervals with
// the shared CounterTracker: first sample → null, counter reset/wrap → skip.
const rateTracker = new CounterTracker();

/** Humanizes a bits/s rate for table cells (the webapp renders table values verbatim). */
function formatBitsPerSec(v: number | null): string {
  if (v === null || !Number.isFinite(v) || v < 0) return '—';
  const units = ['bps', 'Kbps', 'Mbps', 'Gbps', 'Tbps'];
  let x = v;
  let i = 0;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i++;
  }
  return `${x >= 100 ? Math.round(x) : x.toFixed(2)} ${units[i]}`;
}

// --- TTL cache ------------------------------------------------------------------------------
const snapshotCache = new TtlCache<RouterOsSnapshot>();
const lastKnown = new Map<string, RouterOsSnapshot>();

function rememberLastKnown(key: string, snapshot: RouterOsSnapshot): void {
  lastKnown.set(key, snapshot);
  if (lastKnown.size > 512) {
    const oldest = lastKnown.keys().next().value; // Map iteration = insertion order
    if (oldest !== undefined) lastKnown.delete(oldest);
  }
}

export interface MonitoringResult {
  snapshot: RouterOsSnapshot;
  /** True when the served snapshot is stale (re-collection failed). */
  stale: boolean;
  error?: string;
}

/**
 * Returns a fresh-or-cached snapshot for one host. Never throws — transport and
 * auth failures surface as `error` so /monitoring can map them to health.
 */
export async function getMonitoring(
  address: string,
  credentials: { username: string; password: string },
  opts: RouterOsOptions
): Promise<MonitoringResult> {
  // The password is part of the key (hashed) — a cached snapshot collected with
  // one credential set must never be served for another.
  const pwHash = createHash('md5').update(credentials.password, 'utf8').digest('hex');
  const key = `${address}|${credentials.username}:${pwHash}`;

  const cached = snapshotCache.get(key, opts.cacheTtlMs);
  if (cached) {
    return { snapshot: cached, stale: false };
  }

  try {
    const client = new RouterOsClient(address, {
      username: credentials.username,
      password: credentials.password,
      timeoutMs: opts.requestTimeoutMs,
      insecureTls: opts.insecureTls,
      schemeMode: opts.schemeMode,
    });
    const snapshot = await collectSnapshot(client);
    snapshotCache.set(key, snapshot);
    rememberLastKnown(key, snapshot);
    return { snapshot, stale: false };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const stale = lastKnown.get(key); // expired-but-usable fallback
    if (stale) {
      // Serve the last good data rather than flapping to critical on a blip.
      return { snapshot: stale, stale: true, error: `Snapshot is stale — refresh failed: ${message}` };
    }
    throw err;
  }
}

/** Test hook: clears the per-host cache, stale fallbacks + rate baselines. */
export function clearMonitoringCache(): void {
  snapshotCache.clear();
  lastKnown.clear();
  rateTracker.clear();
}

// --- Metric descriptors ---------------------------------------------------------------------------
export type { MetricDescriptor };

/** Builds the descriptor set for one snapshot (groups appear only when present). */
export function buildDescriptors(s: RouterOsSnapshot): MetricDescriptor[] {
  const d: MetricDescriptor[] = [
    // --- System ---------------------------------------------------------------
    { key: 'system.identity', label: 'Identity', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.version', label: 'RouterOS version', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.buildTime', label: 'Build time', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.platform', label: 'Platform', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.boardName', label: 'Board name', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.hostname', label: 'Hostname', type: 'string', visualization: 'text', group: 'System' },
    { key: 'system.uptime', label: 'Uptime', unit: 's', format: 'duration', type: 'number', visualization: 'text', group: 'System' },

    // --- Summary (device overview table) ----------------------------------------
    { key: 'system.cpuLoad', label: 'CPU load', unit: '%', type: 'number', visualization: 'gauge', group: 'Summary', min: 0, max: 100, color: '#3b82f6', summary: true },
    { key: 'system.memoryUsedPercent', label: 'Memory used', unit: '%', type: 'number', visualization: 'gauge', group: 'Summary', min: 0, max: 100, color: '#8b5cf6' },
    { key: 'router.interfacesUp', label: 'Interfaces up', type: 'string', visualization: 'text', group: 'Summary', summary: true },
  ];

  if (s.totalRxBitsPerSec !== null || s.totalTxBitsPerSec !== null) {
    // Gauge ceiling = sum of known ether link speeds; falls back to 1 Gbps.
    const capacity = totalLinkCapacityBitsPerSec(s.interfaces) || 1e9;
    d.push(
      { key: 'router.rxThroughput', label: 'Total RX throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Traffic', color: '#3b82f6', summary: true, min: 0, max: capacity },
      { key: 'router.txThroughput', label: 'Total TX throughput', unit: 'bps', format: 'bits', type: 'number', visualization: 'gauge', group: 'Traffic', color: '#10b981', summary: true, min: 0, max: capacity }
    );
  }

  if (s.interfaces.length > 0) {
    d.push({ key: 'router.interfaces', label: 'Interfaces', type: 'string', visualization: 'table', group: 'Interfaces', columns: ['name', 'type', 'status', 'speed', 'mtu', 'macAddress', 'rxRate', 'txRate'] });
  }

  if (s.addresses.length > 0) {
    d.push({ key: 'router.ipAddresses', label: 'IP addresses', type: 'string', visualization: 'table', group: 'Interfaces', columns: ['interface', 'address', 'version'] });
  }

  return d;
}

/** Nominal bits/s of the router's ether interfaces (unknown speeds count as 0). */
export function totalLinkCapacityBitsPerSec(interfaces: RosInterfaceInfo[]): number {
  let sum = 0;
  for (const i of interfaces) {
    if (i.type !== 'ether') continue;
    const bits = parseSpeedBitsPerSec(i.speedLabel ?? undefined);
    if (bits !== null && bits > 0) sum += bits;
  }
  return sum;
}

/** Builds the metrics map for one snapshot (consumed by /monitoring). */
export function buildMetrics(s: RouterOsSnapshot, selectedModel?: string | null, selectedFirmware?: string | null): Record<string, unknown> {
  const m: Record<string, unknown> = {};
  m['system.identity'] = s.identity || null;
  m['system.version'] = s.version || null;
  m['system.buildTime'] = s.buildTime || null;
  m['system.platform'] = s.platform || null;
  m['system.boardName'] = s.boardName || null;
  m['system.hostname'] = s.hostname || null;
  m['system.uptime'] = s.uptimeSeconds;

  // User-selected model/firmware (device form) — echoed like the other plugins.
  if (selectedModel) m['system.model'] = selectedModel;
  if (selectedFirmware) m['system.firmwareVersion'] = selectedFirmware;

  m['system.cpuLoad'] = s.cpuLoadPercent;
  const memUsedPct =
    s.totalMemoryBytes !== null && s.freeMemoryBytes !== null && s.totalMemoryBytes > 0
      ? Math.round(((s.totalMemoryBytes - s.freeMemoryBytes) / s.totalMemoryBytes) * 1_000) / 10
      : null;
  m['system.memoryUsedPercent'] = memUsedPct;

  const upCount = s.interfaces.filter((i) => i.running).length;
  m['router.interfacesUp'] = `${upCount}/${s.interfaces.length}`;

  if (s.totalRxBitsPerSec !== null || s.totalTxBitsPerSec !== null) {
    m['router.rxThroughput'] = s.totalRxBitsPerSec ?? 0;
    m['router.txThroughput'] = s.totalTxBitsPerSec ?? 0;
  }

  if (s.interfaces.length > 0) {
    m['router.interfaces'] = s.interfaces.map((i) => ({
      name: i.name,
      type: i.type || '—',
      status: i.disabled ? 'disabled' : i.running ? 'up' : 'down',
      speed: i.speedLabel ?? (i.macAddress ? '—' : 'virtual'),
      mtu: i.mtu !== null ? String(i.mtu) : '—',
      macAddress: i.macAddress ?? '—',
      rxRate: formatBitsPerSec(i.rxBitsPerSec),
      txRate: formatBitsPerSec(i.txBitsPerSec),
    }));
  }

  if (s.addresses.length > 0) {
    m['router.ipAddresses'] = s.addresses.map((a) => ({ interface: a.interface || '—', address: a.address, version: a.version === 'v6' ? 'IPv6' : 'IPv4' }));
  }

  // --- Inventory propagation (consumed by the API's ingestInventory) --------------
  // networks[]: one row per IP address — the router's own subnets. Name = interface
  // name; ip/prefix/version drive the Networks page subnet grouping.
  const netSeen = new Set<string>();
  const networks: Record<string, unknown>[] = [];
  for (const a of s.addresses) {
    if (!a.ip || !a.prefix) continue; // link-local/placeholder rows add no value
    const name = a.interface || 'default';
    const dedupeKey = `${name}|${a.ip}`;
    if (netSeen.has(dedupeKey)) continue;
    netSeen.add(dedupeKey);
    networks.push({ name, ip: a.ip, prefix: a.prefix, version: a.version, status: 'up' });
  }
  if (networks.length > 0) m['networks'] = networks;

  // arp[] → hosts table with source 'arp'.
  if (s.arp.length > 0) {
    m['arp'] = s.arp.map((x) => ({ mac: x.mac, ip: x.ip, intf: x.intf || null }));
  }

  // dhcpLeases[] → hosts table with source 'dhcp' (hostname + expiry enrich the row).
  if (s.dhcpLeases.length > 0) {
    m['dhcpLeases'] = s.dhcpLeases.map((x) => ({ mac: x.mac, ip: x.ip, hostname: x.hostname ?? undefined, expiry: x.expiry ?? undefined, intf: x.intf ?? undefined }));
  }

  // routes[] → cross-device Routes page (present-but-empty is authoritative).
  m['routes'] = s.routes.map((r) => ({ destination: r.destination, gateway: r.gateway || null, protocol: r.protocol, distance: r.distance ?? undefined, status: r.status }));

  // firewallRules[] → cross-device Firewall page (present-but-empty is
  // authoritative — the REST tables always return the complete rule list).
  m['firewallRules'] = s.firewallRules;

  // filesystems[] → cross-device Storage page. RouterOS runs from a single
  // flash filesystem (squashfs on most boards) — one row when the resource
  // endpoint reports disk space; absent otherwise (no wipe of other data).
  if (s.totalDiskBytes !== null && s.totalDiskBytes > 0) {
    m['filesystems'] = [{
      name: 'root',
      type: 'squashfs',
      mountpoint: '/',
      sizeBytes: s.totalDiskBytes,
      usedBytes: s.freeDiskBytes !== null ? Math.max(0, s.totalDiskBytes - s.freeDiskBytes) : null,
      freeBytes: s.freeDiskBytes ?? null,
      status: 'up',
    }];
  }

  // wlanClients[] → hosts table with source 'wlan'.
  if (s.wlanClients.length > 0) {
    m['wlanClients'] = s.wlanClients.map((x) => ({ mac: x.mac, ip: x.ip, hostname: x.hostname ?? undefined, intf: x.intf || null }));
  }

  return m;
}
