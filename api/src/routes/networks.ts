import { Router, Request, Response } from 'express';
import { and, asc, desc, eq, gte, inArray, like, lt, or, sql } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { ipScope, subnetOf } from '@unm/plugin-sdk';
import { consensusDrift } from '../workers/ntpReferences';
import { suggestFreeRanges } from '../utils/networkCheck';
import { buildFirewallInventoryIndex, enrichFirewallAddress, getCachedFirewallIndex } from '../utils/firewallEnrichment';
import type { FirewallAddressResolution } from '../utils/firewallEnrichment';
import { loadDeviceViews, loadPluginNames } from '../utils/deviceViews';

/** One stored row of the `networks` table (per device + plugin instance). */
type StoredNetwork = typeof schema.networks.$inferSelect;

const router = Router();

/**
 * Cross-device inventory views (Networks + Hosts pages). The rows live in the
 * normalized `networks` / `hosts` tables, populated by the telemetry worker
 * from each plugin's /monitoring metrics. Every response row is joined with
 * the device it was collected on and the plugin instance that produced it —
 * plugins.name carries multi-instance suffixes ("OPNsense Plugin (site-a)").
 *
 * DeviceView / loadDeviceViews / loadPluginNames come from utils/deviceViews (shared).
 */

/** One device+plugin instance that observed a merged host. */
interface HostDeviceMember {
  deviceId: string;
  pluginId: string;
  /** Interface(s) on the observing device where the host was seen (e.g. "lan", "wlan0"). */
  interfaces: string[];
}

/** One physical host as presented by GET /hosts — merged across devices and plugins. */
export interface MergedHost {
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
export interface MergedNetwork {
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
  const scope = ipScope(addr);
  return scope === 'loopback' || scope === 'link-local';
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

// GET /networks/suggestions - Free-range suggestions computed from gaps in the
// live inventory (next free /24 after the highest observed v4 subnet, lowest
// unused VLAN id). Powers the rollout dialog's one-click "suggest" fills.
router.get('/networks/suggestions', requireAuth, requirePermission('networks:read'), async (_req, res: Response) => {
  try {
    // No freshness filter — the telemetry worker sweeps stale rows; what is in
    // the table IS the current view (same data GET /networks renders).
    const rows = await db.query.networks.findMany();
    res.status(200).json(suggestFreeRanges(mergeNetworkRows(rows)));
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

// GET /services - All services across devices (Services page).
// Query params: deviceId (exact), siteId (filter by device's site),
// type ('systemd'|'openrc'|'runit'|'sysvinit'|'freebsd-rc'|'truenas'),
// status ('running'|'stopped'|'failed'|'unknown'). One row per service on one
// device — no cross-device merge needed (a row is already one logical service).
router.get('/services', requireAuth, requirePermission('services:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, type, status } = _req.query as Record<string, string | undefined>;

    if (type && !['systemd', 'openrc', 'runit', 'sysvinit', 'freebsd-rc', 'truenas', 'openwrt'].includes(type)) {
      res.status(400).json({ error: '"type" must be one of: systemd, openrc, runit, sysvinit, freebsd-rc, truenas, openwrt' });
      return;
    }
    if (status && !['running', 'stopped', 'failed', 'unknown'].includes(status)) {
      res.status(400).json({ error: '"status" must be one of: running, stopped, failed, unknown' });
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

    const typeClause = type ? eq(schema.deviceServices.type, type) : undefined;
    const statusClause = status ? eq(schema.deviceServices.status, status) : undefined;
    let where;
    if (deviceId && siteId) {
      // Both filters: verify the device belongs to the site first.
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json([]);
        return;
      }
      where = and(eq(schema.deviceServices.deviceId, deviceId), typeClause, statusClause);
    } else if (deviceId) {
      where = and(eq(schema.deviceServices.deviceId, deviceId), typeClause, statusClause);
    } else if (siteId) {
      let deviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) deviceIds = deviceIds.filter((id) => allowed.has(id));
      if (deviceIds.length === 0) {
        res.status(200).json([]);
        return;
      }
      where = and(inArray(schema.deviceServices.deviceId, deviceIds), typeClause, statusClause);
    } else {
      const clauses = [typeClause, statusClause].filter(Boolean);
      if (allowed !== null) clauses.push(inArray(schema.deviceServices.deviceId, [...allowed]));
      where = clauses.length > 0 ? and(...clauses) : undefined;
    }

    const rows = await db.query.deviceServices.findMany({
      ...(where ? { where } : {}),
      orderBy: [asc(schema.deviceServices.deviceId), asc(schema.deviceServices.type), asc(schema.deviceServices.name)],
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

/** Maps one ca_certificates row (UNM's own CA-issued mTLS leaf) into the same
 *  shape as a device certificate row — type 'mtls', no device. The Certificates
 *  page renders both kinds in one table; deviceId/pluginId are empty strings so
 *  existing consumers keep working. */
function mapCaLeafToCertRow(r: typeof schema.caCertificates.$inferSelect): Record<string, unknown> {
  const now = Date.now();
  const notAfterMs = new Date(r.notAfter).getTime();
  const daysToExpiry = Number.isFinite(notAfterMs) ? Math.floor((notAfterMs - now) / 86_400_000) : null;
  return {
    deviceId: '',
    pluginId: '',
    deviceName: 'UNM',
    managementAddress: null,
    siteName: null,
    pluginName: r.source === 'plugin' ? r.subject : `${r.subject} (${r.source})`,
    name: r.subject,
    type: 'mtls',
    host: '',
    port: null,
    fingerprint: null,
    trustedFingerprint: null,
    fingerprintMismatch: false,
    commonName: safeParseJson<string[]>(r.dnsNames)[0] ?? r.subject,
    subject: `CN = ${r.subject}`,
    issuer: r.issuer || 'UNM CA',
    selfSigned: false,
    notBefore: r.notBefore,
    notAfter: r.notAfter,
    keyAlgorithm: 'ECDSA',
    keySizeBits: null,
    curveName: 'P-256',
    signatureAlgorithm: 'ecdsa-with-SHA256',
    sanNames: safeParseJson<string[]>(r.dnsNames),
    serialNumber: r.serial,
    valid: r.status === 'revoked' ? false : daysToExpiry !== null && daysToExpiry < 0 ? false : true,
    invalidReason: r.status === 'revoked' ? `revoked ${r.revokedAt ?? ''}`.trim() : daysToExpiry !== null && daysToExpiry < 0 ? 'expired' : null,
    daysToExpiry,
    chainDaysToExpiry: null,
    chain: [],
    collectedAt: r.createdAt,
    revoked: r.status === 'revoked',
  };
}

// GET /certificates - All certificate endpoints across devices (Certificates page).
// Query params: deviceId (exact), siteId (filter by device's site),
// type ('https'|'ssh'|'mtls'). Device rows are one per endpoint on a device —
// the management HTTPS cert and/or the SSH host key. 'mtls' rows come from the
// ca_certificates registry: UNM's OWN CA-issued leaves (plugins, api, mcp) —
// fleet infrastructure certs with no device to hang off. `sanNames`/`chain` are
// returned as parsed arrays.
router.get('/certificates', requireAuth, requirePermission('certificates:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId, type } = _req.query as Record<string, string | undefined>;

    if (type && !['https', 'ssh', 'mtls'].includes(type)) {
      res.status(400).json({ error: '"type" must be one of: https, ssh, mtls' });
      return;
    }

    // mTLS rows are fleet infrastructure — they have no device/site scope and
    // are visible to every certificates:read caller. A deviceId or siteId filter
    // excludes them (the caller asked for a specific device's certs); a bare
    // type=mtls filter returns ONLY them.
    const includeMtls = !deviceId && !siteId && (!type || type === 'mtls');

    let mtlsRows: Record<string, unknown>[] = [];
    if (includeMtls) {
      // The registry keeps EVERY issued leaf per subject (audit trail — the
      // /ca/certificates endpoint shows all of them). The Certificates page
      // wants the CURRENT one: newest notAfter wins per subject.
      const caRows = await db.query.caCertificates.findMany({
        orderBy: [asc(schema.caCertificates.subject), desc(schema.caCertificates.notAfter)],
      });
      const currentBySubject = new Map<string, (typeof caRows)[number]>();
      for (const r of caRows) if (!currentBySubject.has(r.subject)) currentBySubject.set(r.subject, r);
      mtlsRows = [...currentBySubject.values()].map(mapCaLeafToCertRow);
      if (type === 'mtls') {
        res.status(200).json(mtlsRows);
        return;
      }
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json(mtlsRows);
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

    res.status(200).json([
      ...rows.map((r) => {
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
      }),
      ...mtlsRows,
    ]);
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

// GET /firewall-events - Firewall event-log rows across devices (Firewall Events page).
// Append-only log pushed by plugins via POST /plugin/firewall-events — blocked/allowed
// traffic events from the appliance's firewall log. Newest-first, windowed on tsMs
// (epoch ms resolved at ingest from the appliance-local timestamp + device offset).
// Query params: from/to (ISO or epoch-ms; default last hour), deviceId, siteId,
// action ('pass'|'block'|'rdr'|'nat'|'binat', or 'other' = rdr/nat/binat group),
// search (matches src/dst IP or rule name), limit (default 500, max 2000).
const FIREWALL_EVENT_ACTIONS = new Set(['pass', 'block', 'rdr', 'nat', 'binat']);
router.get('/firewall-events', requireAuth, requirePermission('firewall:read'), async (_req, res: Response) => {
  try {
    const q = _req.query as Record<string, string | undefined>;

    // --- Window (same pattern as routes/flows.ts resolveWindow) -------------
    const parseTimeParam = (v: unknown): number | null => {
      if (typeof v !== 'string' || !v.trim()) return null;
      const t = Date.parse(v);
      return Number.isFinite(t) ? t : null;
    };
    const now = Date.now();
    let toMs = parseTimeParam(q.to) ?? now;
    let fromMs = parseTimeParam(q.from) ?? toMs - 3600_000; // default: last hour
    if (fromMs >= toMs) fromMs = toMs - 3600_000;
    const MAX_RANGE_MS = 400 * 86_400_000;
    if (toMs - fromMs > MAX_RANGE_MS) fromMs = toMs - MAX_RANGE_MS;

    // --- Filters -------------------------------------------------------------
    let actionClause;
    if (q.action && q.action !== 'all') {
      const actions = q.action === 'other' ? ['rdr', 'nat', 'binat'] : [q.action];
      for (const a of actions) {
        if (!FIREWALL_EVENT_ACTIONS.has(a)) {
          res.status(400).json({ error: `"action" must be one of: pass, block, rdr, nat, binat, other` });
          return;
        }
      }
      actionClause = inArray(schema.firewallEvents.action, actions);
    }

    const search = typeof q.search === 'string' ? q.search.trim() : '';
    let searchClause;
    if (search) {
      // LIKE on the three text fields — good enough at this volume.
      const pat = `%${search.replace(/[%_]/g, '')}%`;
      searchClause = or(like(schema.firewallEvents.srcIp, pat), like(schema.firewallEvents.dstIp, pat), like(schema.firewallEvents.ruleName, pat));
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { blocked: 0, passed: 0, other: 0 } });
      return;
    }
    if (q.deviceId && allowed !== null && !allowed.has(q.deviceId)) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { blocked: 0, passed: 0, other: 0 } });
      return;
    }

    let deviceClause;
    if (q.deviceId && q.siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, q.deviceId) });
      if (!device || device.siteId !== q.siteId) {
        res.status(200).json({ fromMs, toMs, rows: [], summary: { blocked: 0, passed: 0, other: 0 } });
        return;
      }
      deviceClause = eq(schema.firewallEvents.deviceId, q.deviceId);
    } else if (q.deviceId) {
      deviceClause = eq(schema.firewallEvents.deviceId, q.deviceId);
    } else if (q.siteId) {
      let siteDeviceIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, q.siteId) })).map((d) => d.id);
      if (allowed !== null) siteDeviceIds = siteDeviceIds.filter((id) => allowed.has(id));
      if (siteDeviceIds.length === 0) {
        res.status(200).json({ fromMs, toMs, rows: [], summary: { blocked: 0, passed: 0, other: 0 } });
        return;
      }
      deviceClause = inArray(schema.firewallEvents.deviceId, siteDeviceIds);
    } else if (allowed !== null) {
      deviceClause = inArray(schema.firewallEvents.deviceId, [...allowed]);
    }

    const limitParam = Number(q.limit);
    const limit = Math.max(1, Math.min(2000, Number.isFinite(limitParam) ? Math.floor(limitParam) : 500));

    // tsMs is the queryable axis; rows with an unparseable timestamp (tsMs NULL)
    // are excluded from windowed queries rather than mis-ordered.
    const baseClauses = [gte(schema.firewallEvents.tsMs, fromMs), lt(schema.firewallEvents.tsMs, toMs)];
    if (deviceClause) baseClauses.push(deviceClause);
    if (actionClause) baseClauses.push(actionClause);
    if (searchClause) baseClauses.push(searchClause);

    const where = and(...baseClauses);
    // Rows + per-action counts over the SAME window/filters (SQL-side, cheap).
    const [rows, summaryAgg] = await Promise.all([
      db.query.firewallEvents.findMany({ where, orderBy: [desc(schema.firewallEvents.tsMs)], limit }),
      db.select({
        blocked: sql<number>`count(*) filter (where ${schema.firewallEvents.action} = 'block')`,
        passed: sql<number>`count(*) filter (where ${schema.firewallEvents.action} = 'pass')`,
        other: sql<number>`count(*) filter (where ${schema.firewallEvents.action} in ('rdr','nat','binat'))`,
      }).from(schema.firewallEvents).where(where),
    ]);

    // Device + plugin display names for the rows.
    const deviceViews = await loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId))));
    const pluginNames = await loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId))));

    res.status(200).json({
      fromMs,
      toMs,
      rows: rows.map((r) => ({
        ...r,
        deviceName: deviceViews.get(r.deviceId)?.name ?? null,
        siteName: deviceViews.get(r.deviceId)?.siteName ?? null,
        pluginName: pluginNames.get(r.pluginId) ?? null,
      })),
      summary: {
        blocked: Number(summaryAgg[0]?.blocked ?? 0),
        passed: Number(summaryAgg[0]?.passed ?? 0),
        other: Number(summaryAgg[0]?.other ?? 0),
      },
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /firewall-sessions - Per-device live connection-state overview (Firewall page, Sessions section).
// Reads each device's LATEST telemetry row and extracts the `firewall.states.*` metrics
// (collected every poll by OS-capable plugins — OPNsense today) plus the inventory-cycle
// `firewall.stateConfig` / `firewall.stats` objects. Telemetry stores FLAT dotted keys
// (`"firewall.states.total": 42`, not nested), so the SQL pre-filter uses jsonb key-existence
// and the TS parsing reads flat keys. Non-firewall devices never appear because their
// snapshots lack the key entirely. collectedAt is an ISO string, so lexicographic max = newest.
router.get('/firewall-sessions', requireAuth, requirePermission('firewall:read'), async (_req, res: Response) => {
  try {
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ devices: [] });
      return;
    }

    // Latest telemetry row per device that reports session data. We use a text LIKE
    // existence check rather than casting to jsonb: some devices emit metric values
    // containing raw control bytes (e.g. NUL) which make Postgres reject the `::jsonb`
    // cast for the ENTIRE table, and there is no index on metrics anyway — so a plain
    // text match on the flat dotted key is both safer and just as fast at this size.
    const { rows: latest } = await pool.query<{ deviceId: string; collectedAt: string; metrics: string }>(
      `SELECT t."deviceId", t."collectedAt", t."metrics"
         FROM telemetry t
        WHERE t.id IN (
          SELECT DISTINCT ON ("deviceId") id
            FROM telemetry
           WHERE "metrics" LIKE '%"firewall.states.total":%'
           ORDER BY "deviceId", "collectedAt" DESC
        )`,
    );

    const devices: {
      deviceId: string;
      deviceName: string | null;
      siteName: string | null;
      collectedAt: string;
      totalSessions: number | null;
      stateLimit: number | null;
      oldestAgeSec: number | null;
      adaptiveEnabled: boolean | null;
      adaptiveStartStates: number | null;
      stateTableSearchesRate: number | null;
      stateTableInsertsRate: number | null;
      stateTableRemovalsRate: number | null;
      synfloodsDetectedTotal: number | null;
    }[] = [];

    for (const row of latest) {
      if (allowed !== null && !allowed.has(row.deviceId)) continue;
      let m: Record<string, unknown> = {};
      try {
        m = JSON.parse(row.metrics);
      } catch {
        continue; // corrupt snapshot — skip rather than fail the whole page
      }
      // Flat dotted keys (see plugin emission): "firewall.states.total" etc.
      const total = m['firewall.states.total'];
      if (typeof total !== 'number') continue;

      const timeouts = (m['firewall.stateConfig'] ?? {}) as Record<string, unknown>;
      let adaptiveEnabled: boolean | null = null;
      let adaptiveStartStates: number | null = null;
      // Plugin camelCases the pf keys: "adaptive.start" → "adaptiveStart".
      const startRaw = typeof timeouts['adaptiveStart'] === 'string' ? (timeouts['adaptiveStart'] as string) : '';
      if (startRaw !== '') {
        // "0 states" = disabled, "10000 states" = enabled at that threshold.
        adaptiveStartStates = parseInt(startRaw, 10);
        if (!Number.isNaN(adaptiveStartStates)) adaptiveEnabled = adaptiveStartStates > 0;
      }

      const stats = (m['firewall.stats'] ?? {}) as Record<string, unknown>;
      const numOrNull = (v: unknown): number | null => {
        if (typeof v === 'number' && Number.isFinite(v)) return v;
        if (typeof v === 'string') {
          const n = Number(v);
          if (v.trim() !== '' && Number.isFinite(n)) return n;
        }
        return null;
      };

      devices.push({
        deviceId: row.deviceId,
        deviceName: null, // filled below
        siteName: null,
        collectedAt: row.collectedAt,
        totalSessions: total,
        stateLimit: numOrNull(m['firewall.states.limit']),
        oldestAgeSec: numOrNull(m['firewall.states.oldestAgeSec']),
        adaptiveEnabled,
        adaptiveStartStates,
        stateTableSearchesRate: numOrNull(stats.stateTableSearchesRate),
        stateTableInsertsRate: numOrNull(stats.stateTableInsertsRate),
        stateTableRemovalsRate: numOrNull(stats.stateTableRemovalsRate),
        synfloodsDetectedTotal: numOrNull(stats.synfloodsDetectedTotal),
      });
    }

    const views = await loadDeviceViews(devices.map((d) => d.deviceId));
    for (const d of devices) {
      d.deviceName = views.get(d.deviceId)?.name ?? null;
      d.siteName = views.get(d.deviceId)?.siteName ?? null;
    }
    devices.sort((a, b) => (a.deviceName ?? '').localeCompare(b.deviceName ?? ''));

    res.status(200).json({ devices });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /host-states - Per-endpoint firewall state snapshots + churn over a window.
// Powers the "States" columns on the Hosts and Networks pages. Data comes from
// plugins that walk their appliance's live state table (OPNsense query_states,
// RouterOS connection table) and push per-host aggregates via POST
// /plugin/host-states — one snapshot row per (device, endpoint IP) per walk.
//   openStates      = the LATEST snapshot for that device+IP ("open now")
//   createdWindow   = SUM of createdSinceLastWalk over the window (null when no
//                     walk in the window had a baseline to diff against)
//   destroyedWindow = same for destroyedSinceLastWalk
// Query params: deviceId, siteId, windowHours (default 24, clamped 1..336).
router.get('/host-states', requireAuth, requirePermission('hosts:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;
    let windowHours = Number(_req.query['windowHours'] ?? 24);
    if (!Number.isFinite(windowHours)) windowHours = 24;
    windowHours = Math.min(336, Math.max(1, windowHours));

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ rows: [], devices: {}, windowHours });
      return;
    }

    let deviceFilter: string[] | null = null;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) {
        res.status(200).json({ rows: [], devices: {}, windowHours });
        return;
      }
      deviceFilter = [deviceId];
    } else if (deviceId) {
      deviceFilter = allowed !== null && !allowed.has(deviceId) ? [] : [deviceId];
    } else if (siteId) {
      let ids = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
      if (allowed !== null) ids = ids.filter((id) => allowed.has(id));
      deviceFilter = ids;
    } else if (allowed !== null) {
      deviceFilter = [...allowed];
    }
    if (deviceFilter !== null && deviceFilter.length === 0) {
      res.status(200).json({ rows: [], devices: {}, windowHours });
      return;
    }

    // Each query gets its OWN param list — node-postgres rejects a statement
    // whose placeholder count differs from the supplied params. The snapshot
    // query filters by device only; the churn query adds the window cutoff as $1
    // (device ids then start at $2).
    const idClause = deviceFilter !== null ? `AND "deviceId" IN (${deviceFilter.map((_, i) => `$${i + 1}`).join(', ')})` : '';
    const snapshotParams: (string | number)[] = deviceFilter ?? [];

    // Latest snapshot per (device, endpoint IP) — the "open now" view.
    const { rows: latest } = await pool.query<{ deviceId: string; hostIp: string; openStates: number; walkedAtMs: number | bigint }>(
      `SELECT DISTINCT ON ("deviceId", "hostIp") "deviceId", "hostIp", "openStates", "walkedAtMs"
         FROM host_states
        WHERE 1 = 1 ${idClause}
        ORDER BY "deviceId", "hostIp", "walkedAtMs" DESC`,
      snapshotParams,
    );

    // Churn over the window — SUM skips NULL deltas (no baseline); all-NULL
    // windows stay null so the UI can show "—" instead of a fake zero.
    const churnParams: (string | number)[] = [Date.now() - windowHours * 60 * 60 * 1000];
    if (deviceFilter !== null) churnParams.push(...deviceFilter);
    const churnIdClause = deviceFilter !== null ? `AND "deviceId" IN (${deviceFilter.map((_, i) => `$${i + 2}`).join(', ')})` : '';
    const { rows: churn } = await pool.query<{ deviceId: string; hostIp: string; created: number | null; destroyed: number | null }>(
      `SELECT "deviceId", "hostIp", SUM("createdSinceLastWalk") AS created, SUM("destroyedSinceLastWalk") AS destroyed
         FROM host_states
        WHERE "walkedAtMs" > $1 ${churnIdClause}
        GROUP BY "deviceId", "hostIp"`,
      churnParams,
    );

    // SUM() over int columns comes back as a BIGINT string from node-postgres —
    // coerce to number so the webapp can aggregate numerically (string concat
    // would render "+002" instead of "+2"). NULL stays null (no baseline).
    const churnByKey = new Map<string, { created: number | null; destroyed: number | null }>();
    for (const c of churn) churnByKey.set(`${c.deviceId}|${c.hostIp}`, { created: c.created === null ? null : Number(c.created), destroyed: c.destroyed === null ? null : Number(c.destroyed) });

    const rows = latest.map((l) => {
      const c = churnByKey.get(`${l.deviceId}|${l.hostIp}`);
      return {
        deviceId: l.deviceId,
        hostIp: l.hostIp,
        openStates: l.openStates,
        walkedAtMs: Number(l.walkedAtMs),
        createdWindow: c?.created ?? null,
        destroyedWindow: c?.destroyed ?? null,
      };
    });

    const views = await loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId))));
    const devices: Record<string, { name: string | null; managementAddress: string | null; lastWalkedAtMs: number | null }> = {};
    for (const r of rows) {
      const v = views.get(r.deviceId);
      const d = (devices[r.deviceId] ??= { name: v?.name ?? null, managementAddress: v?.managementAddress ?? null, lastWalkedAtMs: null });
      if (d.lastWalkedAtMs === null || r.walkedAtMs > d.lastWalkedAtMs) d.lastWalkedAtMs = r.walkedAtMs;
    }

    res.status(200).json({ rows, devices, windowHours });
  } catch (err) {
    const e = err as { status?: number; message: string };
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

// GET /device-time - Cross-device clock overview (Time page).
// Reads the dedicated `device_times` table — one row per (device, plugin) that can
// read a wall clock, upserted by the telemetry worker on EVERY poll from the
// `system.deviceTime` metric. Only clock-capable plugins ever write there, so the
// newest row per device is always valid clock data and never masked by an ICMP/SNMP
// poll (those emit no such key). This keeps the route a trivial indexed read instead
// of scanning the multi-GB telemetry table. Two design points:
//   - drift = deviceEpochMs − readingInstant: comparing against Date.now() would
//     bake the reading's staleness into every value; measuring at the reading time
//     yields a stable offset (the page shows how old each reading is separately).
//   - Drift is timezone-aware: we compare absolute instants (epoch ms), so a device
//     in any IANA zone compares correctly without being forced to UTC — the app
//     normalizes only for comparison, never rewriting the device's displayed time.
// `available` is false when no clock reading exists or it has no resolvable instant;
// those devices still appear so the page shows which boxes are covered. Query params:
// deviceId (exact), siteId (filter by device's site).
router.get('/device-time', requireAuth, requirePermission('time:read'), async (_req, res: Response) => {
  try {
    const { deviceId, siteId } = _req.query as Record<string, string | undefined>;

    // Device-level access control — scoped callers only see their own devices.
    const allowed = await allowedDeviceIds(_req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ unmNowMs: Date.now(), devices: [] });
      return;
    }

    let deviceWhere;
    if (deviceId && siteId) {
      const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
      if (!device || device.siteId !== siteId) { res.status(200).json({ unmNowMs: Date.now(), devices: [] }); return; }
      deviceWhere = eq(schema.devices.id, deviceId);
    } else if (deviceId) {
      deviceWhere = eq(schema.devices.id, deviceId);
    } else if (siteId) {
      deviceWhere = eq(schema.devices.siteId, siteId);
    }

    let devices = await db.query.devices.findMany({ ...(deviceWhere ? { where: deviceWhere } : {}) });
    if (allowed !== null) devices = devices.filter((d) => allowed.has(d.id));
    if (devices.length === 0) { res.status(200).json({ unmNowMs: Date.now(), devices: [] }); return; }

    // All clock rows for these devices — the table is small (one row per
    // device+plugin, upserted every poll), so a plain indexed read suffices. A
    // device watched by SEVERAL plugins has one row PER plugin: an OS-capable
    // plugin fills the system-clock columns, the generic-ntp plugin fills the
    // NTP-served columns. We merge per device — newest system-clock reading +
    // newest NTP-served reading — so both kinds of data survive on one page row.
    const { rows: allRows } = await pool.query(
      `SELECT "deviceId", "pluginId", "localIso", "timezone", "utcOffsetMinutes", "epochMs",
              "ntpTimeUtc", "ntpEpochMs", "ntpStratum", "ntpReferenceId", "collectedAt"
         FROM device_times
        WHERE "deviceId" = ANY($1)`,
      [devices.map((d) => d.id)],
    );

    interface ClockRow {
      pluginId: string; localIso: string | null; timezone: string | null;
      utcOffsetMinutes: number | null; epochMs: number | null; collectedAt: string;
      ntpTimeUtc: string | null; ntpEpochMs: number | null; ntpStratum: number | null;
      ntpReferenceId: string | null;
    }
    const rowsByDevice = new Map<string, ClockRow[]>();
    for (const r of allRows as Array<Record<string, unknown>>) {
      // pg returns BIGINT as a STRING — coerce to JS numbers (epoch ms ~1.7e12,
      // well within safe-integer range) so the JSON contract stays `type: integer`.
      const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
      const row: ClockRow = {
        pluginId: String(r['pluginId']),
        localIso: (r['localIso'] as string) ?? null,
        timezone: (r['timezone'] as string) ?? null,
        utcOffsetMinutes: num(r['utcOffsetMinutes']),
        epochMs: (() => { const n = num(r['epochMs']); return n !== null && Number.isFinite(n) ? n : null; })(),
        collectedAt: String(r['collectedAt']),
        ntpTimeUtc: (r['ntpTimeUtc'] as string) ?? null,
        ntpEpochMs: (() => { const n = num(r['ntpEpochMs']); return n !== null && Number.isFinite(n) ? n : null; })(),
        ntpStratum: num(r['ntpStratum']),
        ntpReferenceId: (r['ntpReferenceId'] as string) ?? null,
      };
      const key = String(r['deviceId']);
      const list = rowsByDevice.get(key);
      if (list) list.push(row); else rowsByDevice.set(key, [row]);
    }

    const unmNowMs = Date.now();
    const out: Array<Record<string, unknown>> = [];
    for (const d of devices) {
      const rows = rowsByDevice.get(d.id) ?? [];
      // Newest row carrying a SYSTEM clock reading (localIso or resolvable epoch).
      let sys: ClockRow | null = null;
      for (const r of rows) {
        if ((r.localIso !== null || r.epochMs !== null) && (!sys || r.collectedAt > sys.collectedAt)) sys = r;
      }
      // Newest row carrying an NTP-SERVED reading.
      let ntp: ClockRow | null = null;
      for (const r of rows) {
        if ((r.ntpEpochMs !== null || r.ntpTimeUtc !== null) && (!ntp || r.collectedAt > ntp.collectedAt)) ntp = r;
      }

      // System-clock drift: measured against the READING's own timestamp — not
      // Date.now() — so a stale reading yields its true offset instead of baking
      // staleness into every value. Same rule for the NTP-served instant.
      const deviceEpochMs = sys?.epochMs ?? null;
      const sysReadingInstantMs = sys ? Date.parse(sys.collectedAt) : NaN;
      const driftMs = deviceEpochMs !== null && Number.isFinite(sysReadingInstantMs) ? deviceEpochMs - sysReadingInstantMs : null;

      const ntpEpochMs = ntp?.ntpEpochMs ?? null;
      const ntpReadingInstantMs = ntp ? Date.parse(ntp.collectedAt) : NaN;
      const ntpDriftMs = ntpEpochMs !== null && Number.isFinite(ntpReadingInstantMs) ? ntpEpochMs - ntpReadingInstantMs : null;

      out.push({
        deviceId: d.id,
        name: d.name,
        managementAddress: d.managementAddress,
        siteId: d.siteId,
        // Plugin that produced the latest SYSTEM-clock reading — lets the page
        // target a live probe at exactly that plugin (a device may have several).
        pluginId: sys?.pluginId ?? null,
        collectedAt: sys?.collectedAt ?? ntp?.collectedAt ?? null,
        available: deviceEpochMs !== null,
        localIso: sys?.localIso ?? null,
        timezone: sys?.timezone ?? null,
        utcOffsetMinutes: sys?.utcOffsetMinutes ?? null,
        deviceEpochMs,
        unmNowMs,
        driftMs,
        // NTP-served time — the instant this device transmits to its clients.
        ntpAvailable: ntp !== null && (ntpEpochMs !== null || ntp.ntpTimeUtc !== null),
        ntpPluginId: ntp?.pluginId ?? null,
        ntpCollectedAt: ntp?.collectedAt ?? null,
        ntpTimeUtc: ntp?.ntpTimeUtc ?? null,
        ntpEpochMs,
        ntpStratum: ntp?.ntpStratum ?? null,
        ntpReferenceId: ntp?.ntpReferenceId ?? null,
        ntpDriftMs,
      });
    }

    res.status(200).json({ unmNowMs, devices: out });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /ntp-references - Public NTP reference overview (Time page "Time base" card).
// Reads the `ntp_reference_readings` table — one row per configured public
// server, upserted by the ntpReferences worker. The consensus verdict (median
// drift across healthy references) is computed HERE at read time via the same
// pure helper the worker uses, so it always reflects the freshest rows without
// a stored aggregate to keep in sync. `consensusMs` = UNM clock offset vs the
// international consensus: positive means UNM's clock lags (behind), negative
// means it leads (ahead). Null when no reference is currently healthy.
router.get('/ntp-references', requireAuth, requirePermission('time:read'), async (_req, res: Response) => {
  try {
    const rows = await db.query.ntpReferenceReadings.findMany({ orderBy: asc(schema.ntpReferenceReadings.server) });

    // pg returns BIGINT as a string — coerce for the JSON contract.
    const num = (v: unknown): number | null => (v === null || v === undefined ? null : Number(v));
    const references = rows.map((r) => ({
      server: r.server,
      port: r.port,
      status: r.status as 'ok' | 'unreachable' | 'unsynced',
      error: r.error || null,
      rttMs: num(r.rttMs),
      driftMs: (() => { const n = num(r.driftMs); return n !== null && Number.isFinite(n) ? n : null; })(),
      stratum: num(r.stratum),
      referenceId: r.referenceId || null,
      timeUtc: r.timeUtc || null,
      collectedAt: r.collectedAt,
    }));

    const consensus = consensusDrift(
      references.map((r) => ({ server: r.server, status: r.status, error: r.error ?? '', driftMs: r.driftMs, stratum: r.stratum }))
    );

    res.status(200).json({
      unmNowMs: Date.now(),
      consensusMs: consensus.value,
      sampleCount: consensus.sampleCount,
      references,
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
