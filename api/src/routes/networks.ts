import { Router, Response } from 'express';
import { and, asc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';
import { subnetOf } from '../utils/address';

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
const SOURCE_ORDER: Record<string, number> = { arp: 0, ndp: 1, dhcp: 2, wlan: 3 };

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
router.get('/networks', requireAuth, async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

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
      const deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      where = inArray(schema.networks.deviceId, deviceIds);
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
router.get('/hosts', requireAuth, async (_req, res: Response) => {
  try {
    const { deviceId, siteId, source } = _req.query as Record<string, string | undefined>;

    if (source && !['arp', 'ndp', 'dhcp', 'wlan'].includes(source)) {
      res.status(400).json({ error: '"source" must be one of: arp, ndp, dhcp, wlan' });
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
      const deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      const deviceClause = inArray(schema.hosts.deviceId, deviceIds);
      where = sourceClause ? and(deviceClause, sourceClause) : deviceClause;
    } else if (sourceClause) {
      where = sourceClause;
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

export default router;
