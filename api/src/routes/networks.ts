import { Router, Request, Response } from 'express';
import { and, asc, desc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { subnetOf } from '../utils/address';
import { buildFirewallInventoryIndex, enrichFirewallAddress, getCachedFirewallIndex } from '../utils/firewallEnrichment';
import type { FirewallAddressResolution } from '../utils/firewallEnrichment';

/** One stored row of the `networks` table (per device + plugin instance). */
type StoredNetwork = typeof schema.networks.$inferSelect;

const router = Router();

/**
 * Cross-device inventory views (Networks + Hosts pages). The rows live in the
 * normalized `networks` / `hosts` tables, populated by the telemetry worker
 * from each plugin's /monitoring metrics. Every response row is joined with
 * the device it was collected on and the plugin instance that produced it —
 * plugins.name carries multi-instance suffixes ("OPNsense Plugin (site-a)").
 */

interface DeviceView {
  id: string;
  name: string;
  managementAddress: string;
  siteName: string | null;
}

/**
 * Batch-loads device + site display data for the given ids. Returns a map of
 * deviceId -> view (missing devices are simply absent — stale rows are swept
 * by the worker, but a delete race must not break the response).
 */
async function loadDeviceViews(deviceIds: string[]): Promise<Map<string, DeviceView>> {
  const map = new Map<string, DeviceView>();
  if (deviceIds.length === 0) return map;
  const devices = await db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) });
  const siteIds = Array.from(new Set(devices.map((d) => d.siteId).filter((s): s is string => !!s)));
  const sites = siteIds.length > 0 ? await db.query.sites.findMany({ where: inArray(schema.sites.id, siteIds) }) : [];
  const siteNameById = new Map(sites.map((s) => [s.id, s.name] as const));
  for (const d of devices) {
    map.set(d.id, {
      id: d.id,
      name: d.name,
      managementAddress: d.managementAddress,
      siteName: d.siteId ? (siteNameById.get(d.siteId) ?? null) : null,
    });
  }
  return map;
}

/** Batch-loads plugin display names for the given ids. */
async function loadPluginNames(pluginIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (pluginIds.length === 0) return map;
  const plugins = await db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) });
  for (const p of plugins) map.set(p.id, p.name);
  return map;
}

/** One device+plugin instance that observed a merged host. */
interface HostDeviceMember {
  deviceId: string;
  pluginId: string;
  /** Interface(s) on the observing device where the host was seen (e.g. "lan", "wlan0"). */
  interfaces: string[];
}

/** One physical host as presented by GET /hosts — merged across devices and plugins. */
interface MergedHost {
  mac: string;
  /** All addresses of this host, IPv4 first (a dual-stack device has both). */
  ips: string[];
  /** Discovery sources that reported this MAC anywhere on the network. */
  sources: string[];
  hostname: string | null;
  manufacturer: string | null;
  expiry: string | null;
  lastSeenAt: string;
  /** Every device+plugin instance that observed this host (one entry each). */
  devices: HostDeviceMember[];
}

/** Canonical display order for discovery sources. */
const SOURCE_ORDER: Record<string, number> = { arp: 0, ndp: 1, dhcp: 2, wlan: 3, docker: 4, vm: 5 };

/**
 * Merges stored host rows into one row per physical host: the same MAC seen
 * anywhere on the network is a single machine — e.g. its IPv4 in the router's
 * ARP table AND as a WLAN client on an AP are merged into one row, with all
 * observing devices listed. Storage keeps the per-device granularity (needed
 * for topology detection); this merge only shapes the GET /hosts response.
 */
export function mergeHostRows(rows: typeof schema.hosts.$inferSelect[]): MergedHost[] {
  const groups = new Map<string, typeof rows>();
  for (const r of rows) {
    // Same MAC on ANY device + plugin instance = one physical host. Ingestion
    // lowercases MACs; normalize again defensively so mixed-case rows merge too.
    const key = r.mac.toLowerCase();
    const list = groups.get(key);
    if (list) list.push(r);
    else groups.set(key, [r]);
  }

  return Array.from(groups.values()).map((group) => {
    // IPv4 first, then IPv6 — the usual reading order for a dual-stack host.
    // IP-less rows (source 'mac' — switch MAC tables) contribute no address.
    const ips = Array.from(new Set(group.map((r) => r.ip).filter((ip) => ip !== ''))).sort((a, b) => {
      const av = a.includes(':') ? 1 : 0;
      const bv = b.includes(':') ? 1 : 0;
      return av !== bv ? av - bv : a.localeCompare(b);
    });
    const sources = Array.from(new Set(group.map((r) => r.source))).sort(
      (a, b) => (SOURCE_ORDER[a] ?? 9) - (SOURCE_ORDER[b] ?? 9)
    );
    // DHCP rows carry the richest metadata — prefer their hostname/expiry.
    const dhcp = group.find((r) => r.source === 'dhcp');
    // Consolidate per device+plugin: one member entry with all its interfaces.
    const byDevice = new Map<string, HostDeviceMember>();
    for (const r of group) {
      const dkey = `${r.deviceId}|${r.pluginId}`;
      let d = byDevice.get(dkey);
      if (!d) {
        d = { deviceId: r.deviceId, pluginId: r.pluginId, interfaces: [] };
        byDevice.set(dkey, d);
      }
      if (r.intf && !d.interfaces.includes(r.intf)) d.interfaces.push(r.intf);
    }
    return {
      mac: group[0].mac,
      ips,
      sources,
      hostname: dhcp?.hostname ?? group.find((r) => r.hostname)?.hostname ?? null,
      manufacturer: group.find((r) => r.manufacturer)?.manufacturer ?? null,
      expiry: dhcp?.expiry ?? null,
      // Latest observation across all devices/sources (ISO strings compare lexicographically).
      lastSeenAt: group.reduce((max, r) => (r.lastSeenAt > max ? r.lastSeenAt : max), group[0].lastSeenAt),
      devices: Array.from(byDevice.values()).sort((a, b) => a.deviceId.localeCompare(b.deviceId)),
    };
  });
}

/** One interface as seen on one device — a member of a logical network. */
interface NetworkDeviceMember {
  deviceId: string;
  pluginId: string;
  /** Interface name(s) carrying this network on the device (e.g. "lan", "WLAN-1"). */
  interfaces: string[];
  /** Addresses configured on those interfaces, IPv4 first. */
  cidrs: string[];
  mac: string | null;
  status: string | null;
}

/** One LOGICAL network as presented by GET /networks — merged across devices. */
interface MergedNetwork {
  /** Canonical identity of the logical network (subnet, vlan:<id>, or name). */
  key: string;
  /** Display label: subnet when known ("192.168.1.0/24"), else "VLAN <id>", else the interface name. */
  name: string;
  /** Subnet (network address + prefix) when any member row carries an IP — null for pure SSID/VLAN rows. */
  subnet: string | null;
  /** ALL real subnets of this logical network, IPv4 first (dual-stack groups carry both). Empty for pure SSID/VLAN rows. */
  subnets: string[];
  vlanId: number | null;
  versions: ('v4' | 'v6')[];
  /** Every device/interface that reports this network (one entry per device+plugin). */
  devices: NetworkDeviceMember[];
  collectedAt: string;
}

/** Normalizes the free-form `version` values plugins emit to v4/v6. */
function normalizeVersion(v: string | null): 'v4' | 'v6' | null {
  if (v === 'v4' || v === 'ipv4') return 'v4';
  if (v === 'v6' || v === 'ipv6') return 'v6';
  return null;
}

/** Sorts address strings IPv4-first, then lexicographically. */
function sortAddresses(addrs: string[]): string[] {
  return [...addrs].sort((a, b) => {
    const av = a.includes(':') ? 1 : 0;
    const bv = b.includes(':') ? 1 : 0;
    return av !== bv ? av - bv : a.localeCompare(b);
  });
}

/** One interface as seen on one device — the grouping unit. */
interface InterfaceMember {
  deviceId: string;
  pluginId: string;
  name: string;
  cidrs: string[];
  subnets: Set<string>;
  vlanId: number | null;
  versions: Set<'v4' | 'v6'>;
  mac: string | null;
  status: string | null;
  collectedAt: string;
}

/** One logical network group while it is being built (pre-response shape). */
interface NetworkGroup {
  id: string;
  label: string;
  subnet: string | null;
  subnets: Set<string>;
  vlans: Set<number>;
  versions: Set<'v4' | 'v6'>;
  latestAt: string;
  members: InterfaceMember[];
}

/** Most specific (longest prefix) subnet of a set, or null when empty. */
function bestSubnet(subnets: Set<string>): string | null {
  if (subnets.size === 0) return null;
  return Array.from(subnets).sort((a, b) => Number(b.split('/')[1]) - Number(a.split('/')[1]))[0];
}

/** Best subnet that identifies a real network (loopback/link-local excluded). */
function networkSubnet(subnets: Set<string>): string | null {
  const net = new Set(Array.from(subnets).filter((s) => !isNonNetworkSubnet(s)));
  return bestSubnet(net);
}

/**
 * True for subnets that do NOT identify a real network — loopback and
 * link-local addresses exist on (almost) every interface and would merge
 * unrelated interfaces into one bogus group. Such rows fall back to VLAN/name
 * grouping instead; the address is still shown in the member's cidrs.
 */
function isNonNetworkSubnet(subnet: string): boolean {
  const [addr, prefix] = subnet.split('/');
  if (prefix === undefined) return false;
  // IPv4: 127/8 loopback, 169.254/16 link-local (APIPA).
  if (!addr.includes(':')) {
    const o = addr.split('.').map(Number);
    return o[0] === 127 || (o[0] === 169 && o[1] === 254);
  }
  // IPv6: ::1 loopback, fe80::/10 link-local (first group fe80..febf).
  if (addr === '::1') return true;
  const firstGroup = addr.split(':')[0];
  return /^fe[89ab][0-9a-f]$/i.test(firstGroup);
}

/**
 * Groups stored network rows into LOGICAL networks across devices. Storage
 * stays per-device (topology detection needs that granularity); this only
 * shapes the GET /networks response, mirroring mergeHostRows.
 *
 * Grouping keys, in priority order:
 *   1. subnet:<cidr> — an interface with an IP + prefix defines its network
 *      address; all interfaces whose addresses fall in that subnet join it
 *      (several interfaces in the same range are ONE network).
 *   2. VLAN bridge — an interface carrying BOTH a VLAN id and an IP teaches us
 *      "VLAN <id> = <subnet>"; IP-less members with that VLAN id then join the
 *      subnet group (e.g. AP SSIDs merging with the router's tagged port).
 *   3. vlan:<id> — shared VLAN without any known subnet (pure SSID groups).
 *   4. name:<interface> — unmergeable rows stay per device+interface.
 */
export function mergeNetworkRows(rows: StoredNetwork[]): MergedNetwork[] {
  // Pass 1: one member per interface (dual-stack interfaces stored as two
  // rows collapse into a single member with both addresses).
  const members = new Map<string, InterfaceMember>();
  for (const r of rows) {
    const key = `${r.deviceId}|${r.pluginId}|${r.name}`;
    let m = members.get(key);
    if (!m) {
      m = { deviceId: r.deviceId, pluginId: r.pluginId, name: r.name, cidrs: [], subnets: new Set(), vlanId: null, versions: new Set(), mac: null, status: null, collectedAt: '' };
      members.set(key, m);
    }
    if (r.collectedAt > m.collectedAt) m.collectedAt = r.collectedAt;
    if (r.ip !== '') {
      const addr = r.prefix !== null ? `${r.ip}/${r.prefix}` : r.ip;
      if (!m.cidrs.includes(addr)) m.cidrs.push(addr);
      const subnet = subnetOf(r.ip, r.prefix);
      if (subnet) m.subnets.add(subnet);
    }
    if (r.vlanId !== null && m.vlanId === null) m.vlanId = r.vlanId;
    const v = normalizeVersion(r.version);
    if (v) m.versions.add(v);
    if (!m.mac && r.mac) m.mac = r.mac;
    if (!m.status && r.status) m.status = r.status;
  }

  // Pass 2: VLAN → subnet bridge from members that carry both.
  const vlanToSubnet = new Map<number, string>();
  for (const m of members.values()) {
    if (m.vlanId !== null) {
      const s = networkSubnet(m.subnets);
      if (s && !vlanToSubnet.has(m.vlanId)) vlanToSubnet.set(m.vlanId, s);
    }
  }

  // Pass 3: assign every interface to a logical network group. The map key is
  // the row's canonical identity — unique per group by construction.
  const groups = new Map<string, NetworkGroup>();
  const memberGroupKey = new Map<InterfaceMember, string>();
  for (const m of members.values()) {
    let key: string;
    const own = networkSubnet(m.subnets);
    if (own) {
      key = `subnet:${own}`;
    } else if (m.vlanId !== null && vlanToSubnet.has(m.vlanId)) {
      key = `subnet:${vlanToSubnet.get(m.vlanId)}`; // VLAN bridge into the subnet group
    } else if (m.vlanId !== null) {
      key = `vlan:${m.vlanId}`;
    } else {
      key = `name:${m.name || 'unknown'}`;
    }
    let g = groups.get(key);
    if (!g) {
      const subnet = key.startsWith('subnet:') ? key.slice('subnet:'.length) : null;
      const vlanId = key.startsWith('vlan:') ? Number(key.slice('vlan:'.length)) : null;
      g = { id: key, label: subnet ?? (vlanId !== null ? `VLAN ${vlanId}` : m.name || 'unknown'), subnet, subnets: new Set(), vlans: new Set(), versions: new Set(), latestAt: '', members: [] };
      groups.set(key, g);
    }
    // Every REAL subnet of every member (loopback/link-local excluded) — a
    // dual-stack group thus carries both its v4 and v6 CIDRs.
    for (const s of m.subnets) {
      if (!isNonNetworkSubnet(s)) g.subnets.add(s);
    }
    if (m.vlanId !== null) g.vlans.add(m.vlanId);
    for (const v of m.versions) g.versions.add(v);
    if (m.collectedAt > g.latestAt) g.latestAt = m.collectedAt;
    g.members.push(m);
    memberGroupKey.set(m, key);
  }

  // Pass 3b: merge subnet groups that a single interface carries together. One
  // interface with several real subnets (dual-stack LAN, multi-address port)
  // proves those CIDRs are ONE logical network — so a v4-only row from another
  // device in any of them joins the group instead of forming its own. Only
  // groups that actually exist (have members) can merge; union-find keeps it
  // transitive (A∩B and B∩C ⇒ A, B, C together).
  const parent = new Map<string, string>();
  const findRoot = (key: string): string => {
    if (!parent.has(key)) parent.set(key, key);
    let root = key;
    while (parent.get(root) !== root) root = parent.get(root)!;
    let cur = key; // path compression
    while (cur !== root) {
      const next = parent.get(cur)!;
      parent.set(cur, root);
      cur = next;
    }
    return root;
  };
  for (const m of members.values()) {
    const ownKey = memberGroupKey.get(m)!;
    for (const s of m.subnets) {
      if (isNonNetworkSubnet(s)) continue; // loopback/link-local never bridge groups
      const sk = `subnet:${s}`;
      if (groups.has(sk) && sk !== ownKey) {
        const ra = findRoot(ownKey);
        const rb = findRoot(sk);
        if (ra !== rb) parent.set(ra, rb);
      }
    }
  }

  // Consolidate each union into one group; the canonical identity is the most
  // specific subnet of the merged set (identical to before for unmerged groups).
  const consolidated = new Map<string, NetworkGroup>();
  for (const [key, g] of groups) {
    const root = findRoot(key);
    let c = consolidated.get(root);
    if (!c) {
      c = { id: key, label: g.label, subnet: g.subnet, subnets: new Set(g.subnets), vlans: new Set(g.vlans), versions: new Set(g.versions), latestAt: g.latestAt, members: [...g.members] };
      consolidated.set(root, c);
    } else {
      for (const s of g.subnets) c.subnets.add(s);
      for (const v of g.vlans) c.vlans.add(v);
      for (const v of g.versions) c.versions.add(v);
      if (g.latestAt > c.latestAt) c.latestAt = g.latestAt;
      c.members.push(...g.members);
    }
  }
  for (const c of consolidated.values()) {
    const canon = networkSubnet(c.subnets);
    if (canon) {
      c.id = `subnet:${canon}`;
      c.label = canon;
      c.subnet = canon;
    }
  }

  // Pass 4: shape the response — one row per logical network, consolidating a
  // device's several interfaces in the same group into one member entry.
  return Array.from(consolidated.values()).map((g): MergedNetwork => {
    const byDevice = new Map<string, NetworkDeviceMember>();
    for (const m of g.members) {
      const dkey = `${m.deviceId}|${m.pluginId}`;
      let d = byDevice.get(dkey);
      if (!d) {
        d = { deviceId: m.deviceId, pluginId: m.pluginId, interfaces: [], cidrs: [], mac: null, status: null };
        byDevice.set(dkey, d);
      }
      if (m.name && !d.interfaces.includes(m.name)) d.interfaces.push(m.name);
      for (const c of sortAddresses(m.cidrs)) {
        if (!d.cidrs.includes(c)) d.cidrs.push(c);
      }
      if (!d.mac && m.mac) d.mac = m.mac;
      if (!d.status && m.status) d.status = m.status;
    }
    const versions: ('v4' | 'v6')[] = [];
    if (g.versions.has('v4')) versions.push('v4');
    if (g.versions.has('v6')) versions.push('v6');
    // IPv4 first, then lexicographic — the usual reading order for dual-stack.
    const subnets = Array.from(g.subnets).sort((a, b) => {
      const av = a.includes(':') ? 1 : 0;
      const bv = b.includes(':') ? 1 : 0;
      return av !== bv ? av - bv : a.localeCompare(b);
    });
    return {
      key: g.id,
      name: g.label,
      subnet: g.subnet,
      subnets,
      vlanId: g.vlans.size === 1 ? Array.from(g.vlans)[0] : null,
      versions,
      devices: Array.from(byDevice.values()).sort((a, b) => a.deviceId.localeCompare(b.deviceId)),
      collectedAt: g.latestAt,
    };
  });
}

// GET /networks - All configured networks across devices.
// Query params: deviceId (exact), siteId (filter by device's site).
router.get('/networks', requireAuth, requirePermission('networks:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = eq(schema.networks.deviceId, deviceId);
    } else if (deviceId) {
      where = eq(schema.networks.deviceId, deviceId);
    } else if (siteId) {
      // Subquery: devices belonging to the site.
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      where = inArray(schema.networks.deviceId, deviceIds);
    } else if (allowed !== null) {
      where = inArray(schema.networks.deviceId, [...allowed]);
    }

    const rows = await db.query.networks.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.networks.deviceId), asc(schema.networks.name)],
    });

    // Group per-device rows into logical networks (subnet/VLAN/name).
    const merged = mergeNetworkRows(rows);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(merged.flatMap((m) => m.devices.map((d) => d.deviceId))))),
      loadPluginNames(Array.from(new Set(merged.flatMap((m) => m.devices.map((d) => d.pluginId))))),
    ]);

    res.status(200).json(
      merged.map((m) => ({
        ...m,
        devices: m.devices.map((d) => {
          const device = deviceViews.get(d.deviceId);
          return {
            ...d,
            deviceName: device?.name ?? null,
            managementAddress: device?.managementAddress ?? null,
            siteName: device?.siteName ?? null,
            pluginName: pluginNames.get(d.pluginId) ?? null,
          };
        }),
      }))
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /hosts - All discovered hosts across devices (ARP/NDP neighbors + DHCP leases).
// Query params: deviceId, siteId, source ('arp'|'ndp'|'dhcp'|'wlan').
router.get('/hosts', requireAuth, requirePermission('hosts:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, source } = _req.query as Record<string, string | undefined>;

    // 'self' = the appliance's own interfaces (plugins emit them with their hostname).
    if (source && !['arp', 'ndp', 'dhcp', 'wlan', 'self'].includes(source)) {
      res.status(400).json({ error: '"source" must be one of: arp, ndp, dhcp, wlan, self' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    const sourceClause = source ? eq(schema.hosts.source, source) : undefined;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = sourceClause ? and(eq(schema.hosts.deviceId, deviceId), sourceClause) : eq(schema.hosts.deviceId, deviceId);
    } else if (deviceId) {
      where = sourceClause ? and(eq(schema.hosts.deviceId, deviceId), sourceClause) : eq(schema.hosts.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.hosts.deviceId, deviceIds);
      where = sourceClause ? and(deviceClause, sourceClause) : deviceClause;
    } else if (sourceClause) {
      where = allowed !== null ? and(sourceClause, inArray(schema.hosts.deviceId, [...allowed])) : sourceClause;
    } else if (allowed !== null) {
      where = inArray(schema.hosts.deviceId, [...allowed]);
    }

    const rows = await db.query.hosts.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.hosts.deviceId), asc(schema.hosts.ip)],
    });

    // Merge per-source rows into one row per physical host (same MAC).
    const merged = mergeHostRows(rows);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(merged.flatMap((m) => m.devices.map((d) => d.deviceId))))),
      loadPluginNames(Array.from(new Set(merged.flatMap((m) => m.devices.map((d) => d.pluginId))))),
    ]);

    res.status(200).json(
      merged.map((m) => ({
        ...m,
        devices: m.devices.map((d) => {
          const device = deviceViews.get(d.deviceId);
          return {
            ...d,
            deviceName: device?.name ?? null,
            managementAddress: device?.managementAddress ?? null,
            siteName: device?.siteName ?? null,
            pluginName: pluginNames.get(d.pluginId) ?? null,
          };
        }),
      }))
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /tunnels - All configured tunnels across devices.
// Query params: deviceId (exact), siteId (filter by device's site),
// type ('wireguard'|'openvpn'|'ipsec'|'pppoe'|'gre').
// Unlike networks/hosts, no cross-device merge is needed — a tunnel row is
// already one logical tunnel on one device.
router.get('/tunnels', requireAuth, requirePermission('tunnels:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, type } = _req.query as Record<string, string | undefined>;

    if (type && !['wireguard', 'openvpn', 'ipsec', 'pppoe', 'gre'].includes(type)) {
      res.status(400).json({ error: '"type" must be one of: wireguard, openvpn, ipsec, pppoe, gre' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    const typeClause = type ? eq(schema.tunnels.type, type) : undefined;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = typeClause ? and(eq(schema.tunnels.deviceId, deviceId), typeClause) : eq(schema.tunnels.deviceId, deviceId);
    } else if (deviceId) {
      where = typeClause ? and(eq(schema.tunnels.deviceId, deviceId), typeClause) : eq(schema.tunnels.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.tunnels.deviceId, deviceIds);
      where = typeClause ? and(deviceClause, typeClause) : deviceClause;
    } else if (typeClause) {
      where = allowed !== null ? and(typeClause, inArray(schema.tunnels.deviceId, [...allowed])) : typeClause;
    } else if (allowed !== null) {
      where = inArray(schema.tunnels.deviceId, [...allowed]);
    }

    const rows = await db.query.tunnels.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.tunnels.deviceId), asc(schema.tunnels.type), asc(schema.tunnels.name)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          extra: safeParseJson<Record<string, unknown>>(r.extra),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /certificates - All certificate endpoints across devices (Certificates page).
// Query params: deviceId (exact), siteId (filter by device's site),
// type ('https'|'ssh'). One row per endpoint on a device — the management HTTPS
// cert and/or the SSH host key. No cross-device merge needed (a row is already one
// logical endpoint on one device). `sanNames`/`chain` are returned as parsed arrays.
router.get('/certificates', requireAuth, requirePermission('certificates:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, type } = _req.query as Record<string, string | undefined>;

    if (type && !['https', 'ssh'].includes(type)) {
      res.status(400).json({ error: '"type" must be one of: https, ssh' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    const typeClause = type ? eq(schema.certificates.type, type) : undefined;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = typeClause ? and(eq(schema.certificates.deviceId, deviceId), typeClause) : eq(schema.certificates.deviceId, deviceId);
    } else if (deviceId) {
      where = typeClause ? and(eq(schema.certificates.deviceId, deviceId), typeClause) : eq(schema.certificates.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.certificates.deviceId, deviceIds);
      where = typeClause ? and(deviceClause, typeClause) : deviceClause;
    } else if (typeClause) {
      where = allowed !== null ? and(typeClause, inArray(schema.certificates.deviceId, [...allowed])) : typeClause;
    } else if (allowed !== null) {
      where = inArray(schema.certificates.deviceId, [...allowed]);
    }

    const rows = await db.query.certificates.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.certificates.deviceId), asc(schema.certificates.type), asc(schema.certificates.name)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          sanNames: safeParseJson<string[]>(r.sanNames),
          chain: safeParseJson<Record<string, unknown>[]>(r.chain),
          // True when the endpoint currently presents a DIFFERENT key than the
          // trusted (pinned) one — strict pinning refuses connections until the
          // new key is accepted via POST /certificates/accept.
          fingerprintMismatch: !!(r.fingerprint && r.trustedFingerprint && r.fingerprint !== r.trustedFingerprint),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /certificates/history - Append-only fingerprint history for one endpoint.
// Query params: deviceId + name (both required — the page opens this per row),
// limit (default 20, max 100). Newest first. Powers the "certificate changed"
// audit view: every distinct key ever observed on the endpoint with its
// first/last-seen window and cert metadata as of that observation.
router.get('/certificates/history', requireAuth, requirePermission('certificates:read'), async (req: Request, res: Response) => {
  try {
    const { deviceId, name } = req.query as Record<string, string | undefined>;
    if (!deviceId || !name) {
      res.status(400).json({ error: 'deviceId and name are required' });
      return;
    }

    // Device-level access control — scoped callers only see their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    const limitRaw = Number((req.query as Record<string, string | undefined>)['limit']);
    const limit = Math.min(Math.max(Number.isFinite(limitRaw) ? Math.trunc(limitRaw) : 20, 1), 100);

    const rows = await db.query.certificateHistory.findMany({
      where: and(
        eq(schema.certificateHistory.deviceId, deviceId),
        eq(schema.certificateHistory.name, name)
      ),
      orderBy: [desc(schema.certificateHistory.lastSeenAt)],
      limit,
    });

    res.status(200).json(rows);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /certificates/accept - Accept the CURRENTLY OBSERVED key of an endpoint
// as the new trusted (pinned) fingerprint. Body: { deviceId, name }. This is the
// explicit user action that clears a "certificate changed" condition after a
// legitimate re-key; it also lets a user RE-PIN to a previously-seen key from
// history by passing `fingerprint` in the body (must match a history row).
// Gated on certificates:write — accepting a key is a security decision.
router.post('/certificates/accept', requireAuth, requirePermission('certificates:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body as Record<string, unknown>;
    const deviceId = typeof body['deviceId'] === 'string' ? body['deviceId'].trim() : '';
    const name = typeof body['name'] === 'string' ? body['name'].trim() : '';
    if (!deviceId || !name) {
      res.status(400).json({ error: 'deviceId and name are required' });
      return;
    }

    // Device-level access control — scoped callers may only re-pin their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && !allowed.has(deviceId)) {
      res.status(403).json({ error: 'No access to this device' });
      return;
    }

    const row = await db.query.certificates.findFirst({
      where: and(eq(schema.certificates.deviceId, deviceId), eq(schema.certificates.name, name)),
    });
    if (!row) {
      res.status(404).json({ error: `No certificate endpoint "${name}" on this device` });
      return;
    }

    // Default: pin the key currently observed. An explicit fingerprint must be a
    // previously-seen one (history row) — never an arbitrary string.
    let target = row.fingerprint;
    if (typeof body['fingerprint'] === 'string' && body['fingerprint'].trim() !== '') {
      const wanted = body['fingerprint'].trim();
      const hist = await db.query.certificateHistory.findFirst({
        where: and(
          eq(schema.certificateHistory.deviceId, deviceId),
          eq(schema.certificateHistory.name, name),
          eq(schema.certificateHistory.fingerprint, wanted)
        ),
      });
      if (!hist) {
        res.status(400).json({ error: 'Fingerprint is not in this endpoint\'s history' });
        return;
      }
      target = wanted;
    }
    if (!target) {
      res.status(409).json({ error: 'No fingerprint observed for this endpoint yet — nothing to accept' });
      return;
    }

    await db.update(schema.certificates)
      .set({ trustedFingerprint: target })
      .where(and(eq(schema.certificates.deviceId, deviceId), eq(schema.certificates.name, name)));

    res.status(200).json({ ok: true, deviceId, name, trustedFingerprint: target });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /routes - All route entries across devices (Routes page).
// Query params: deviceId (exact), siteId (filter by device's site),
// protocol ('static'|'connected'|'ospf'|'bgp'|'rip'|'other').
// No cross-device merge — a route row is one entry on one device. Static and
// dynamically-learned routes to the same destination appear as separate rows
// (protocol is part of the PK).
router.get('/routes', requireAuth, requirePermission('routes:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, protocol } = _req.query as Record<string, string | undefined>;

    if (protocol && !['static', 'connected', 'ospf', 'bgp', 'rip', 'other'].includes(protocol)) {
      res.status(400).json({ error: '"protocol" must be one of: static, connected, ospf, bgp, rip, other' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    const protocolClause = protocol ? eq(schema.routes.protocol, protocol) : undefined;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = protocolClause ? and(eq(schema.routes.deviceId, deviceId), protocolClause) : eq(schema.routes.deviceId, deviceId);
    } else if (deviceId) {
      where = protocolClause ? and(eq(schema.routes.deviceId, deviceId), protocolClause) : eq(schema.routes.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.routes.deviceId, deviceIds);
      where = protocolClause ? and(deviceClause, protocolClause) : deviceClause;
    } else if (protocolClause) {
      where = allowed !== null ? and(protocolClause, inArray(schema.routes.deviceId, [...allowed])) : protocolClause;
    } else if (allowed !== null) {
      where = inArray(schema.routes.deviceId, [...allowed]);
    }

    const rows = await db.query.routes.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.routes.deviceId), asc(schema.routes.protocol), asc(schema.routes.destination)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          extra: safeParseJson<Record<string, unknown>>(r.extra),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /firewall-rules - All firewall rules across devices (Firewall page).
// Query params: deviceId (exact), siteId (filter by device's site),
// ruleType ('filter'|'dnat'|'snat'|'one-to-one'|'npt').
// No cross-device merge — a row is one rule on one device. Vendors normalize to
// the unified shape at collection time, so OPNsense and RouterOS rules share the
// same columns; vendor-specific fields live in `extra`.
router.get('/firewall-rules', requireAuth, requirePermission('firewall:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, ruleType } = _req.query as Record<string, string | undefined>;

    if (ruleType && !['filter', 'dnat', 'snat', 'one-to-one', 'npt'].includes(ruleType)) {
      res.status(400).json({ error: '"ruleType" must be one of: filter, dnat, snat, one-to-one, npt' });
      return;
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json([]);
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json([]);
      return;
    }

    let where;
    const ruleTypeClause = ruleType ? eq(schema.firewallRules.ruleType, ruleType) : undefined;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = ruleTypeClause ? and(eq(schema.firewallRules.deviceId, deviceId), ruleTypeClause) : eq(schema.firewallRules.deviceId, deviceId);
    } else if (deviceId) {
      where = ruleTypeClause ? and(eq(schema.firewallRules.deviceId, deviceId), ruleTypeClause) : eq(schema.firewallRules.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.firewallRules.deviceId, deviceIds);
      where = ruleTypeClause ? and(deviceClause, ruleTypeClause) : deviceClause;
    } else if (ruleTypeClause) {
      where = allowed !== null ? and(ruleTypeClause, inArray(schema.firewallRules.deviceId, [...allowed])) : ruleTypeClause;
    } else if (allowed !== null) {
      where = inArray(schema.firewallRules.deviceId, [...allowed]);
    }

    const rows = await db.query.firewallRules.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.firewallRules.deviceId), asc(schema.firewallRules.ruleType), asc(schema.firewallRules.position)],
    });

    // --- Cross-device address resolution -------------------------------------
    // Resolve each rule's source/dest against the networks + hosts inventory so
    // alias names and bare IPs become intuitive (real subnets, matched hostnames).
    // The index is cached briefly; when a siteId filter is set we scope it to that
    // site's devices (a smaller, more relevant resolution context).
    const deviceViews = await loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId))));
    const pluginNames = await loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId))));

    let indexScope: string[] | null = null; // null = all devices
    if (siteId) {
      const siteDeviceIds = new Set(
        (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id)
      );
      indexScope = Array.from(siteDeviceIds);
    } else if (allowed !== null) {
      // Scoped callers resolve addresses against their own devices only.
      indexScope = [...allowed];
    }

    // Device names for interface labels — ALL devices (the inventory may carry
    // subnets/hosts from devices that have no firewall rules of their own).
    // Scoped callers only get the names of their own devices.
    const allDevices = await db.query.devices.findMany(
      allowed !== null ? { where: inArray(schema.devices.id, [...allowed]) } : undefined
    );
    const deviceNameById = new Map(allDevices.map((d) => [d.id, d.name] as const));
    // The index cache is shared across users — fold the caller's scope into the
    // key so a scoped user never resolves against another user's inventory.
    const indexKey = `fw:${allowed !== null ? _req.user!.sub : 'all'}:${siteId ?? 'all'}`;
    const index = await getCachedFirewallIndex(indexKey, async () => {
      const scopeClause = indexScope ? inArray(schema.networks.deviceId, indexScope) : undefined;
      const [networkRows, hostRows] = await Promise.all([
        db.query.networks.findMany(scopeClause ? { where: scopeClause } : undefined),
        db.query.hosts.findMany(indexScope ? { where: inArray(schema.hosts.deviceId, indexScope) } : undefined),
      ]);
      return buildFirewallInventoryIndex(networkRows, hostRows);
    });

    // Memoize per distinct (device, raw value) — most rules share a handful of
    // addresses. The key includes the device because interface-name tokens are
    // resolved against that specific device's inventory.
    const resolutionMemo = new Map<string, FirewallAddressResolution | null>();
    const resolveAddr = (raw: string, deviceId: string): FirewallAddressResolution | null => {
      if (!raw || raw.trim() === '' || raw.trim().toLowerCase() === 'any') return null;
      const key = `${deviceId}\u0000${raw}`;
      let r = resolutionMemo.get(key);
      if (r === undefined) {
        // deviceId lets interface-name tokens ("lan", "opt26") and "(self)" resolve
        // against the rule's own device.
        r = enrichFirewallAddress(raw, index, deviceNameById, deviceId);
        resolutionMemo.set(key, r);
      }
      return r;
    };

    // RouterOS rules often constrain via address LISTS instead of src/dst-address:
    // the plugin stores the list contents in extra.srcAddressLists/dstAddressLists.
    const listAddresses = (extra: Record<string, unknown>, key: 'srcAddressLists' | 'dstAddressLists'): string[] => {
      const v = extra[key];
      if (!v || typeof v !== 'object') return [];
      return Object.values(v as Record<string, unknown>)
        .flat()
        .filter((x): x is string => typeof x === 'string' && x.trim() !== '');
    };

    // OPNsense rules reference alias names; the plugin already expanded them at
    // collection time into extra.resolvedSource/resolvedDest (comma-joined address
    // text — for interface-group aliases that's a list of INTERFACE NAMES, which
    // the resolver then maps to real subnets/hosts). Fold both expansions in.
    const aliasExpansion = (extra: Record<string, unknown>, key: 'resolvedSource' | 'resolvedDest'): string => {
      const v = extra[key];
      return typeof v === 'string' ? v : '';
    };

    res.status(200).json(
      rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        const extra = safeParseJson<Record<string, unknown>>(r.extra);
        // Attach only when something actually matched — keeps the payload lean.
        const sourceResolved = resolveAddr(
          [r.sourceIp, aliasExpansion(extra, 'resolvedSource'), ...listAddresses(extra, 'srcAddressLists')].filter(Boolean).join(', '),
          r.deviceId
        );
        const destResolved = resolveAddr(
          [r.destIp, aliasExpansion(extra, 'resolvedDest'), ...listAddresses(extra, 'dstAddressLists')].filter(Boolean).join(', '),
          r.deviceId
        );
        return {
          ...r,
          extra,
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
          sourceResolved: sourceResolved && (sourceResolved.subnets.length > 0 || sourceResolved.hostCount > 0) ? sourceResolved : null,
          destResolved: destResolved && (destResolved.subnets.length > 0 || destResolved.hostCount > 0) ? destResolved : null,
        };
      })
    );
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /wifi - Cross-device WiFi overview (WiFi page).
// Groups the normalized `wifi_ssids` rows by SSID name across all devices and
// joins per-channel airtime (`wifi_channels`) + connected-client counts
// (`wifi_clients`). Also returns a per-band entry list for the spectrum view.
// Query params: siteId (filter to one site's devices).
router.get('/wifi', requireAuth, requirePermission('wifi:read'), async (_req, res: Response) => {
  try {
    const { siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ ssids: [], bands: [] });
      return;
    }

    let deviceIds: string[] | null = null;
    if (siteId) {
      deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ ssids: [], bands: [] });
        return;
      }
    } else if (allowed !== null) {
      deviceIds = [...allowed];
    }

    const [ssidRows, channelRows, clientRows, radioRows, neighborRows] = await Promise.all([
      db.query.wifiSsids.findMany(deviceIds ? { where: inArray(schema.wifiSsids.deviceId, deviceIds) } : undefined),
      db.query.wifiChannels.findMany(deviceIds ? { where: inArray(schema.wifiChannels.deviceId, deviceIds) } : undefined),
      db.query.wifiClients.findMany(deviceIds ? { where: inArray(schema.wifiClients.deviceId, deviceIds) } : undefined),
      db.query.wifiRadios.findMany(deviceIds ? { where: inArray(schema.wifiRadios.deviceId, deviceIds) } : undefined),
      db.query.wifiNeighbors.findMany(deviceIds ? { where: inArray(schema.wifiNeighbors.deviceId, deviceIds) } : undefined),
    ]);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set([...ssidRows.map((r) => r.deviceId), ...neighborRows.map((r) => r.deviceId)]))),
      loadPluginNames(Array.from(new Set(ssidRows.map((r) => r.pluginId)))),
    ]);

    // Per-device channel -> utilization lookup (airtime join).
    const utilByDeviceChannel = new Map<string, number | null>();
    for (const c of channelRows) {
      utilByDeviceChannel.set(`${c.deviceId}|${c.channel}`, c.utilizationPct);
    }

    // Per-SSID connected-client counts (a client's latest SSID wins — the row
    // is upserted by MAC, so each station appears exactly once per device).
    const clientsBySsid = new Map<string, number>();
    for (const c of clientRows) {
      if (!c.ssid) continue;
      clientsBySsid.set(c.ssid, (clientsBySsid.get(c.ssid) ?? 0) + 1);
    }

    // --- Group SSID rows by name -------------------------------------------
    interface SsidGroup {
      name: string;
      channels: Array<{ channel: number | null; band: string }>;
      security: string[];
      vlanId: number | null; // only when unique across the whole group
      clientCount: number;
      airtimeMeanPct: number | null;
      airtimeMaxPct: number | null;
      // pluginId is an internal join key (one chip per device+plugin instance) —
      // it is not part of the serialized response shape.
      devices: Array<{ deviceId: string; pluginId?: string; deviceName: string | null; managementAddress: string | null; siteName: string | null; pluginName: string | null; interfaces: string[] }>;
    }

    const groups = new Map<string, SsidGroup>();
    for (const r of ssidRows) {
      let g = groups.get(r.name);
      if (!g) {
        g = { name: r.name, channels: [], security: [], vlanId: null, clientCount: clientsBySsid.get(r.name) ?? 0, airtimeMeanPct: null, airtimeMaxPct: null, devices: [] };
        groups.set(r.name, g);
      }
      // Channels: one entry per distinct (band, channel) pair.
      if (!g.channels.some((c) => c.band === r.band && c.channel === r.channel)) {
        g.channels.push({ channel: r.channel, band: r.band });
      }
      // Security: distinct non-empty values across all rows of the group.
      if (r.encryption && !g.security.includes(r.encryption)) g.security.push(r.encryption);
      // Devices: one chip per device+plugin, radio interfaces listed.
      let dev = g.devices.find((d) => d.deviceId === r.deviceId && (d as { pluginId?: string }).pluginId === r.pluginId);
      if (!dev) {
        const view = deviceViews.get(r.deviceId);
        dev = { deviceId: r.deviceId, deviceName: view?.name ?? null, managementAddress: view?.managementAddress ?? null, siteName: view?.siteName ?? null, pluginName: pluginNames.get(r.pluginId) ?? null, interfaces: [] };
        (dev as { pluginId?: string }).pluginId = r.pluginId; // internal join key, not serialized
        g.devices.push(dev);
      }
      if (r.ifc && !dev.interfaces.includes(r.ifc)) dev.interfaces.push(r.ifc);
    }

    // Second pass: airtime mean/max + unique VLAN. Collect per-group utilizations
    // and distinct VLAN ids in one loop over the raw rows.
    const utilsByGroup = new Map<string, number[]>();
    const vlansByGroup = new Map<string, Set<number>>();
    for (const r of ssidRows) {
      if (r.channel !== null) {
        const util = utilByDeviceChannel.get(`${r.deviceId}|${r.channel}`);
        if (typeof util === 'number' && Number.isFinite(util)) {
          let arr = utilsByGroup.get(r.name);
          if (!arr) { arr = []; utilsByGroup.set(r.name, arr); }
          arr.push(util);
        }
      }
      if (r.vlanId !== null) {
        let set = vlansByGroup.get(r.name);
        if (!set) { set = new Set(); vlansByGroup.set(r.name, set); }
        set.add(r.vlanId);
      }
    }
    for (const g of groups.values()) {
      const utils = utilsByGroup.get(g.name);
      if (utils && utils.length > 0) {
        g.airtimeMeanPct = Math.round((utils.reduce((a, b) => a + b, 0) / utils.length) * 10) / 10;
        g.airtimeMaxPct = Math.max(...utils);
      } else {
        g.airtimeMeanPct = null;
        g.airtimeMaxPct = null;
      }
      const vlans = vlansByGroup.get(g.name);
      g.vlanId = vlans && vlans.size === 1 ? Array.from(vlans)[0] : null;
    }

    // --- Band view (spectrum) ----------------------------------------------
    // inSSIDer-style: ONE bar per channel (airtime utilization), a noise-floor
    // line from the radio table, and markers for own SSIDs at their channel.
    // Band '' rows are excluded (the device cannot place them on the spectrum).
    const BANDS = ['2.4', '5', '6'] as const;
    const bandOfChannel = (ch: number): string => (ch >= 1 && ch <= 14 ? '2.4' : ch >= 36 && ch <= 165 ? '5' : '6');

    // Per-band channel → worst-case utilization across ALL devices reporting
    // that channel (multiple APs can share a channel; the chart shows how busy
    // it is, so the max wins).
    const utilByBandChannel = new Map<string, number>();
    for (const c of channelRows) {
      if (typeof c.utilizationPct !== 'number' || !Number.isFinite(c.utilizationPct)) continue;
      const key = `${bandOfChannel(c.channel)}|${c.channel}`;
      utilByBandChannel.set(key, Math.max(utilByBandChannel.get(key) ?? -1, c.utilizationPct));
    }

    const bands = BANDS.map((band) => {
      // Channel set = channels with airtime data ∪ own-SSID channels, so a bar
      // exists even when only one of the two sources reported it.
      const channelSet = new Set<number>();
      for (const c of channelRows) if (bandOfChannel(c.channel) === band) channelSet.add(c.channel);
      for (const r of ssidRows) {
        if (r.band === band && r.channel !== null) channelSet.add(r.channel);
      }

      // Noise floor: one line per band — take the noisiest radio on that band
      // (highest dBm = worst case). Band '' radios (dual-band) cannot be placed
      // and are skipped.
      const noiseFloors: number[] = [];
      for (const r of radioRows) {
        if (r.band !== band || typeof r.noiseFloorDbm !== 'number' || !Number.isFinite(r.noiseFloorDbm)) continue;
        noiseFloors.push(r.noiseFloorDbm);
      }

      const channels = Array.from(channelSet).sort((a, b) => a - b).map((ch) => ({
        channel: ch,
        utilizationPct: utilByBandChannel.get(`${band}|${ch}`) ?? null,
      }));

      // Own-SSID markers (deduped per name+channel — one dot per SSID).
      const seenMarkers = new Set<string>();
      const markers: Array<{ name: string; channel: number }> = [];
      for (const r of ssidRows) {
        if (r.band !== band || r.channel === null) continue;
        const key = `${r.name}|${r.channel}`;
        if (seenMarkers.has(key)) continue;
        seenMarkers.add(key);
        markers.push({ name: r.name, channel: r.channel });
      }

      return {
        band,
        minChannel: channels.length > 0 ? Math.min(...channels.map((c) => c.channel)) : null,
        maxChannel: channels.length > 0 ? Math.max(...channels.map((c) => c.channel)) : null,
        noiseFloorDbm: noiseFloors.length > 0 ? Math.max(...noiseFloors) : null,
        channels,
        markers,
      };
    });

    // --- Neighbor list (scanner view) ---------------------------------------
    // Own BSSIDs are excluded — they already appear as SSID groups above.
    const ownBssids = new Set(ssidRows.map((r) => r.bssid).filter((b): b is string => !!b));
    const neighbors: Array<{
      deviceId: string; deviceName: string | null; managementAddress: string | null; siteName: string | null;
      bssid: string; ssid: string | null; band: string; channel: number | null; signalDbm: number | null;
    }> = [];
    for (const n of neighborRows) {
      if (ownBssids.has(n.bssid)) continue; // own network seen by another AP's scan
      const view = deviceViews.get(n.deviceId);
      neighbors.push({
        deviceId: n.deviceId,
        deviceName: view?.name ?? null,
        managementAddress: view?.managementAddress ?? null,
        siteName: view?.siteName ?? null,
        bssid: n.bssid,
        ssid: n.ssid,
        band: n.band,
        channel: n.channel,
        signalDbm: n.signalDbm,
      });
    }
    neighbors.sort((a, b) => (b.signalDbm ?? -200) - (a.signalDbm ?? -200));

    const ssids = Array.from(groups.values()).sort((a, b) => a.name.localeCompare(b.name));
    res.status(200).json({ ssids, bands, neighbors });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /storage - Cross-device storage overview (Storage page).
// Returns the normalized `storage_filesystems` rows (pools, ZFS datasets,
// ext4/squashfs/USB filesystems) and `storage_disks` rows (physical disks /
// flash media) with device + plugin views joined. No cross-device merge — a
// row is one filesystem/disk on one device.
// Query params: deviceId (exact), siteId (filter by device's site).
router.get('/storage', requireAuth, requirePermission('storage:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ filesystems: [], disks: [] });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ filesystems: [], disks: [] });
      return;
    }

    // Resolve the device filter once, then build per-table where clauses.
    let fsWhere;
    let diskWhere;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ filesystems: [], disks: [] });
        return;
      }
      fsWhere = eq(schema.storageFilesystems.deviceId, deviceId);
      diskWhere = eq(schema.storageDisks.deviceId, deviceId);
    } else if (deviceId) {
      fsWhere = eq(schema.storageFilesystems.deviceId, deviceId);
      diskWhere = eq(schema.storageDisks.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ filesystems: [], disks: [] });
        return;
      }
      fsWhere = inArray(schema.storageFilesystems.deviceId, deviceIds);
      diskWhere = inArray(schema.storageDisks.deviceId, deviceIds);
    } else if (allowed !== null) {
      fsWhere = inArray(schema.storageFilesystems.deviceId, [...allowed]);
      diskWhere = inArray(schema.storageDisks.deviceId, [...allowed]);
    }

    const [fsRows, diskRows] = await Promise.all([
      db.query.storageFilesystems.findMany({
        ...(fsWhere ? { where: fsWhere } : {}),
        orderBy: [asc(schema.storageFilesystems.deviceId), asc(schema.storageFilesystems.parent), asc(schema.storageFilesystems.name)],
      }),
      db.query.storageDisks.findMany({
        ...(diskWhere ? { where: diskWhere } : {}),
        orderBy: [asc(schema.storageDisks.deviceId), asc(schema.storageDisks.poolName), asc(schema.storageDisks.name)],
      }),
    ]);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set([...fsRows.map((r) => r.deviceId), ...diskRows.map((r) => r.deviceId)]))),
      loadPluginNames(Array.from(new Set([...fsRows.map((r) => r.pluginId), ...diskRows.map((r) => r.pluginId)]))),
    ]);

    const decorate = <T extends { deviceId: string; pluginId: string }>(row: T) => {
      const device = deviceViews.get(row.deviceId);
      return {
        ...row,
        deviceName: device?.name ?? null,
        managementAddress: device?.managementAddress ?? null,
        siteName: device?.siteName ?? null,
        pluginName: pluginNames.get(row.pluginId) ?? null,
      };
    };

    res.status(200).json({
      filesystems: fsRows.map(decorate),
      disks: diskRows.map(decorate),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /shares - Cross-device file-share overview (Shares page).
// Returns the normalized `shares` rows (SMB/CIFS, NFS, iSCSI and NVMe-oF exports)
// with device + plugin views joined, plus the live `share_sessions` rows (active
// CIFS/SMB + NFS client connections) for the page's bottom panel. No cross-device
// merge — a row is one share/session on one device. Query params: deviceId (exact),
// siteId (filter by device's site).
router.get('/shares', requireAuth, requirePermission('shares:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ shares: [], sessions: [] });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ shares: [], sessions: [] });
      return;
    }

    // Resolve the device filter once, then build per-table where clauses.
    let shareWhere;
    let sessionWhere;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ shares: [], sessions: [] });
        return;
      }
      shareWhere = eq(schema.shares.deviceId, deviceId);
      sessionWhere = eq(schema.shareSessions.deviceId, deviceId);
    } else if (deviceId) {
      shareWhere = eq(schema.shares.deviceId, deviceId);
      sessionWhere = eq(schema.shareSessions.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ shares: [], sessions: [] });
        return;
      }
      shareWhere = inArray(schema.shares.deviceId, deviceIds);
      sessionWhere = inArray(schema.shareSessions.deviceId, deviceIds);
    } else if (allowed !== null) {
      shareWhere = inArray(schema.shares.deviceId, [...allowed]);
      sessionWhere = inArray(schema.shareSessions.deviceId, [...allowed]);
    }

    const [shareRows, sessionRows] = await Promise.all([
      db.query.shares.findMany({
        ...(shareWhere ? { where: shareWhere } : {}),
        orderBy: [asc(schema.shares.deviceId), asc(schema.shares.type), asc(schema.shares.name)],
      }),
      db.query.shareSessions.findMany({
        ...(sessionWhere ? { where: sessionWhere } : {}),
        orderBy: [asc(schema.shareSessions.deviceId), asc(schema.shareSessions.type), asc(schema.shareSessions.shareName)],
      }),
    ]);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set([...shareRows.map((r) => r.deviceId), ...sessionRows.map((r) => r.deviceId)]))),
      loadPluginNames(Array.from(new Set([...shareRows.map((r) => r.pluginId), ...sessionRows.map((r) => r.pluginId)]))),
    ]);

    const decorate = <T extends { deviceId: string; pluginId: string }>(row: T) => {
      const device = deviceViews.get(row.deviceId);
      return {
        ...row,
        deviceName: device?.name ?? null,
        managementAddress: device?.managementAddress ?? null,
        siteName: device?.siteName ?? null,
        pluginName: pluginNames.get(row.pluginId) ?? null,
      };
    };

    res.status(200).json({
      shares: shareRows.map(decorate),
      sessions: sessionRows.map(decorate),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /containers - Cross-device container/App overview (Containers page).
// Returns the normalized `containers` rows (TrueNAS SCALE Apps today; any plugin
// may emit the generic `containers[]` metric) with device + plugin views joined,
// plus the normalized `docker_images` rows (any plugin may emit the generic
// `images[]` metric) for the page's collapsible images panel. One row per app /
// image on one device — no cross-device merge. The `extra` JSON column carries
// networks[], ips[], ports[] and per-service detail for expandable rows.
// Query params: deviceId (exact), siteId (filter by device's site).
router.get('/containers', requireAuth, requirePermission('containers:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ containers: [], images: [] });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ containers: [], images: [] });
      return;
    }

    let contWhere;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ containers: [], images: [] });
        return;
      }
      contWhere = eq(schema.containers.deviceId, deviceId);
    } else if (deviceId) {
      contWhere = eq(schema.containers.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ containers: [], images: [] });
        return;
      }
      contWhere = inArray(schema.containers.deviceId, deviceIds);
    } else if (allowed !== null) {
      contWhere = inArray(schema.containers.deviceId, [...allowed]);
    }

    const [rows, imageRows] = await Promise.all([
      db.query.containers.findMany({
        ...(contWhere ? { where: contWhere } : {}),
        orderBy: [asc(schema.containers.deviceId), asc(schema.containers.name)],
      }),
      // Images share the device filter (same site/device scoping as containers).
      db.query.dockerImages.findMany({
        ...(contWhere ? { where: contWhere } : {}),
        orderBy: [asc(schema.dockerImages.deviceId), asc(schema.dockerImages.name)],
      }),
    ]);

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set([...rows.map((r) => r.deviceId), ...imageRows.map((r) => r.deviceId)]))),
      loadPluginNames(Array.from(new Set([...rows.map((r) => r.pluginId), ...imageRows.map((r) => r.pluginId)]))),
    ]);

    const decorate = <T extends { deviceId: string; pluginId: string }>(row: T, extra?: string) => {
      const device = deviceViews.get(row.deviceId);
      return {
        ...row,
        ...(extra !== undefined ? { extra: safeParseJson<Record<string, unknown>>(extra) } : {}),
        deviceName: device?.name ?? null,
        managementAddress: device?.managementAddress ?? null,
        siteName: device?.siteName ?? null,
        pluginName: pluginNames.get(row.pluginId) ?? null,
      };
    };

    res.status(200).json({
      containers: rows.map((row) => decorate(row, row.extra)),
      images: imageRows.map((row) => decorate(row, row.extra)),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /vms - Cross-device virtual machine overview (VMs page).
// Returns the normalized `vms` rows (TrueNAS SCALE VMs today; any plugin may
// emit the generic `vms[]` metric — e.g. a future Proxmox plugin) with device +
// plugin views joined. One row per VM on one device — no cross-device merge.
// The `extra` JSON column carries nics[] {mac, type?, nicAttach?}, disks[],
// description and other plugin-specific detail for expandable rows (the NICs
// render as child rows under the collapsed-by-default parent). Query params:
// deviceId (exact), siteId (filter by device's site).
router.get('/vms', requireAuth, requirePermission('vms:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ vms: [] });
      return;
    }
    if (deviceId && allowed !== null && !allowed.has(deviceId)) {
      res.status(200).json({ vms: [] });
      return;
    }

    let vmWhere;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ vms: [] });
        return;
      }
      vmWhere = eq(schema.vms.deviceId, deviceId);
    } else if (deviceId) {
      vmWhere = eq(schema.vms.deviceId, deviceId);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json({ vms: [] });
        return;
      }
      vmWhere = inArray(schema.vms.deviceId, deviceIds);
    } else if (allowed !== null) {
      vmWhere = inArray(schema.vms.deviceId, [...allowed]);
    }

    const rows = await db.query.vms.findMany({
      ...(vmWhere ? { where: vmWhere } : {}),
      orderBy: [asc(schema.vms.deviceId), asc(schema.vms.name)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    const decorate = <T extends { deviceId: string; pluginId: string }>(row: T, extra?: string) => {
      const device = deviceViews.get(row.deviceId);
      return {
        ...row,
        ...(extra !== undefined ? { extra: safeParseJson<Record<string, unknown>>(extra) } : {}),
        deviceName: device?.name ?? null,
        managementAddress: device?.managementAddress ?? null,
        siteName: device?.siteName ?? null,
        pluginName: pluginNames.get(row.pluginId) ?? null,
      };
    };

    res.status(200).json({ vms: rows.map((row) => decorate(row, row.extra)) });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

/** Parses a JSON text column defensively — corrupt rows must not break the list. */
function safeParseJson<T>(raw: string): T {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return {} as T;
  }
}

export default router;
