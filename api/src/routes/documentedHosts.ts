import { Router, Request, Response } from 'express';
import { asc, eq, inArray, or } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { isIP } from 'node:net';
import { ipFamily, ipv4ToInt, ipv6ToBigInt, ipInCidr, isPublicIpv4, isPublicIpv6 } from '@unm/plugin-sdk';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { mergeHostRows, mergeNetworkRows, type MergedHost } from './networks';
import { loadSuggestedLayers } from './topology';
import { classifyLayer } from '../utils/topology';
import { readStringArray, parseStringArrayField } from '../utils/stringArrays';

const router = Router();

/**
 * Documented hosts — the USER-MAINTAINED host inventory (the "Hosts
 * documentation" page). Distinct from the live `hosts` table: these are
 * permanent records of what SHOULD exist on the network (DNS names, friendly
 * name/description, site/layer placement, per-address documented MAC +
 * network), while `hosts` holds transient ARP/NDP/DHCP observations.
 *
 * At read time every documented host is cross-referenced against the live
 * table: a matching observed MAC or IP marks it "discovered" (with last-seen
 * timestamp and observed hostname). A documented MAC that differs from what
 * is currently observed for the same address is flagged as `macMismatch` —
 * the foundation for future change-detection notifications.
 */

// ---------------------------------------------------------------------------
// Value normalization + validation
// ---------------------------------------------------------------------------

/** RFC 1123 label (mirrors api/src/utils/address.ts). */
const DNS_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

/** Normalizes a DNS name: trim, lowercase, strip one trailing dot. '' when invalid. */
function normalizeDnsName(value: string): string {
  let v = value.trim().toLowerCase();
  if (v.endsWith('.')) v = v.slice(0, -1);
  if (v.length === 0 || v.length > 253) return '';
  const labels = v.split('.');
  for (const label of labels) {
    if (!DNS_LABEL.test(label)) return '';
  }
  return v;
}

/** True for a bare IPv4/IPv6 literal. */
function isIpLiteral(value: string): boolean {
  return isIP(value.trim()) !== 0;
}

/** Normalizes a MAC to lowercase colon form ("aa:bb:cc:dd:ee:ff"); null when invalid. */
function normalizeMac(value: string): string | null {
  const compact = value.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (compact.length !== 12) return null;
  return formatMac(compact);
}

/** Formats a 12-hex-char MAC into colon form. */
function formatMac(compact: string): string {
  return compact.replace(/([0-9a-f]{2})(?=[0-9a-f])/g, '$1:');
}

// readStringArray / parseStringArrayField come from utils/stringArrays (shared).

/** Case-insensitive union of tag lists — first occurrence's casing wins. */
function mergeTagLists(...lists: string[][]): string[] {
  const out: string[] = [];
  for (const list of lists) {
    for (const t of list) {
      if (!out.some((x) => x.toLowerCase() === t.toLowerCase())) out.push(t);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Live-observation lookup (discovery)
// ---------------------------------------------------------------------------

/** Aggregated live observations for one MAC. */
interface LiveMacInfo {
  hostname: string | null;
  dhcpHostname: string | null;
  manufacturer: string | null;
  lastSeenAt: string;
  ips: Set<string>;
}

/** Aggregated live observations for one IP address. */
interface LiveIpInfo {
  macs: Set<string>;
  hostname: string | null;
  dhcpHostname: string | null;
  lastSeenAt: string;
}

/** Strips MAC separators — the canonical comparison key. */
function macKey(value: string): string {
  return value.toLowerCase().replace(/[^0-9a-f]/g, '');
}

/**
 * Loads the live `hosts` rows that match ANY of the given MACs or addresses
 * and aggregates them into per-MAC / per-IP maps. The live table is swept by
 * the telemetry worker (24h), so every row present counts as "recently seen".
 * Documented MACs are stored in colon form, but plugins emit their own
 * separator style — both forms go into the SQL filter and aggregation keys
 * on the compact (separator-free) hex string.
 */
async function loadLiveObservations(macs: string[], addrs: string[]) {
  const byMac = new Map<string, LiveMacInfo>();
  const byIp = new Map<string, LiveIpInfo>();

  // Every documented MAC in BOTH colon and compact form (plugins vary).
  const macCandidates = Array.from(new Set(macs.flatMap((m) => [m, macKey(m)])));
  const conditions = [];
  if (macCandidates.length > 0) conditions.push(inArray(schema.hosts.mac, macCandidates));
  if (addrs.length > 0) conditions.push(inArray(schema.hosts.ip, addrs));
  if (conditions.length === 0) return { byMac, byIp };

  const rows = await db.query.hosts.findMany({ where: or(...conditions) });
  for (const r of rows) {
    const m = macKey(r.mac);
    let mi = byMac.get(m);
    if (!mi) {
      mi = { hostname: null, dhcpHostname: null, manufacturer: null, lastSeenAt: r.lastSeenAt, ips: new Set() };
      byMac.set(m, mi);
    }
    if (r.ip !== '') mi.ips.add(r.ip);
    if (r.hostname) {
      if (r.source === 'dhcp') mi.dhcpHostname = r.hostname;
      else if (!mi.hostname) mi.hostname = r.hostname;
    }
    if (r.manufacturer && !mi.manufacturer) mi.manufacturer = r.manufacturer;
    if (r.lastSeenAt > mi.lastSeenAt) mi.lastSeenAt = r.lastSeenAt;

    if (r.ip !== '') {
      let ii = byIp.get(r.ip);
      if (!ii) {
        ii = { macs: new Set(), hostname: null, dhcpHostname: null, lastSeenAt: r.lastSeenAt };
        byIp.set(r.ip, ii);
      }
      ii.macs.add(formatMac(m));
      if (r.hostname) {
        if (r.source === 'dhcp') ii.dhcpHostname = r.hostname;
        else if (!ii.hostname) ii.hostname = r.hostname;
      }
      if (r.lastSeenAt > ii.lastSeenAt) ii.lastSeenAt = r.lastSeenAt;
    }
  }
  return { byMac, byIp };
}

// ---------------------------------------------------------------------------
// Network label resolution
// ---------------------------------------------------------------------------

/**
 * Resolves a stored networkLabel to display data. Labels are either the
 * canonical key of a merged logical network (see mergeNetworkRows:
 * "subnet:<cidr>" / "vlan:<id>" / "name:<interface>"), a bare CIDR that falls
 * into one, or free-form text for networks not in the inventory yet.
 */
async function buildNetworkLabelResolver(): Promise<(label: string) => { name: string; known: boolean } | null> {
  const rows = await db.query.networks.findMany();
  const merged = mergeNetworkRows(rows);
  const keyToName = new Map<string, string>();
  // Display labels (e.g. "VLAN 100", interface names) resolve too — the webapp
  // datalist offers them as pickable values.
  const nameToDisplay = new Map<string, string>();
  const subnetToKey = new Map<string, string>();
  for (const n of merged) {
    keyToName.set(n.key, n.name);
    nameToDisplay.set(n.name.toLowerCase(), n.name);
    for (const s of n.subnets ?? []) subnetToKey.set(s, n.key);
  }
  return (label: string): { name: string; known: boolean } | null => {
    const v = label.trim();
    if (!v) return null;
    // Canonical key of a merged network — the label IS the display name.
    if (keyToName.has(v)) return { name: keyToName.get(v)!, known: true };
    // Display label of a known logical network (case-insensitive).
    const byName = nameToDisplay.get(v.toLowerCase());
    if (byName) return { name: byName, known: true };
    // Bare CIDR that falls into a known logical network.
    if (v.includes('/')) {
      const key = subnetToKey.get(v);
      if (key && keyToName.has(key)) return { name: keyToName.get(key)!, known: true };
    }
    // Free-form label for an unknown network — display as-is.
    return { name: v, known: false };
  };
}

// ---------------------------------------------------------------------------
// Response shaping
// ---------------------------------------------------------------------------

/** One documented IP address as presented in the API response. */
export interface DocumentedHostIpView {
  id: string;
  address: string;
  version: 'v4' | 'v6';
  /** The DOCUMENTED (expected) MAC, or null when unknown. */
  mac: string | null;
  networkLabel: string | null;
  /** VLAN id the address lives in (null = unknown). */
  vlanId: number | null;
  /** Resolved display name of the referenced network (null = no reference). */
  networkName: string | null;
  /** True when the label refers to a known logical network (vs free-form). */
  networkKnown: boolean;
  /** True when this address was observed in the live inventory recently. */
  discovered: boolean;
  /** MAC currently observed for this address (null = not observed). */
  observedMac: string | null;
  /** Documented MAC is set AND differs from what is currently observed here. */
  macMismatch: boolean;
}

/** One documented host as presented in the API response. */
export interface DocumentedHostView {
  id: string;
  dnsNames: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  siteName: string | null;
  layerId: string | null;
  layerName: string | null;
  /** User-assigned free-form tags (same data basis as devices.tags). */
  tags: string[];
  /** Additional known MACs of this host (rotated/randomized client MACs synced from the inventory). */
  macs: string[];
  ips: DocumentedHostIpView[];
  /** True when any documented MAC or IP was observed in the live inventory. */
  discovered: boolean;
  /** Most recent observation matching this host (null = never seen). */
  lastSeenAt: string | null;
  /** Hostname reported by the best-matching live row (DHCP preferred). */
  observedHostname: string | null;
  /** Any documented MAC differs from what is currently observed for its address. */
  macMismatch: boolean;
  /** User-maintained lifecycle flag — false = stale/retired (row stays, dimmed in the UI). Default true. */
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

interface HostWithIps {
  host: typeof schema.documentedHosts.$inferSelect;
  ips: typeof schema.documentedHostIps.$inferSelect[];
}

/** Sorts addresses IPv4-first, then lexicographically (repo convention). */
function sortAddresses(addrs: string[]): string[] {
  return [...addrs].sort((a, b) => {
    const av = a.includes(':') ? 1 : 0;
    const bv = b.includes(':') ? 1 : 0;
    return av !== bv ? av - bv : a.localeCompare(b);
  });
}

/** Shapes one documented host (+ its IP rows) into the API view. */
function shapeHost(
  h: HostWithIps,
  siteNameById: Map<string, string>,
  layerNameById: Map<string, string>,
  resolveNetworkLabel: (label: string) => { name: string; known: boolean } | null,
  byMac: Map<string, LiveMacInfo>,
  byIp: Map<string, LiveIpInfo>
): DocumentedHostView {
  const ips = sortAddresses(h.ips.map((i) => i.address)).map((addr) => {
    const row = h.ips.find((i) => i.address === addr)!;
    const live = byIp.get(addr);
    const observedMac = live ? [...live.macs][0] ?? null : null;
    // Stored MACs are already normalized to colon form at write time.
    const docMac = row.mac ?? null;
    const resolved = row.networkLabel ? resolveNetworkLabel(row.networkLabel) : null;
    return {
      id: row.id,
      address: addr,
      version: (addr.includes(':') ? 'v6' : 'v4') as 'v4' | 'v6',
      mac: docMac,
      networkLabel: row.networkLabel ?? null,
      vlanId: row.vlanId ?? null,
      networkName: resolved?.name ?? null,
      networkKnown: resolved?.known ?? false,
      discovered: !!live,
      observedMac,
      macMismatch: !!(docMac && live && observedMac !== docMac),
    };
  });

  // Discovery: any documented MAC seen live OR any address seen live.
  let lastSeenAt: string | null = null;
  let discovered = false;
  let macMismatch = false;
  const hostNameCandidates: { dhcp: boolean; value: string }[] = [];

  for (const row of h.ips) {
    if (row.mac) {
      const mi = byMac.get(macKey(row.mac));
      if (mi) {
        discovered = true;
        if (mi.lastSeenAt > (lastSeenAt ?? '')) lastSeenAt = mi.lastSeenAt;
        hostNameCandidates.push({ dhcp: !!mi.dhcpHostname, value: mi.dhcpHostname ?? mi.hostname! });
      }
    }
    const live = byIp.get(row.address);
    if (live) {
      discovered = true;
      if (live.lastSeenAt > (lastSeenAt ?? '')) lastSeenAt = live.lastSeenAt;
      hostNameCandidates.push({ dhcp: !!live.dhcpHostname, value: live.dhcpHostname ?? live.hostname! });
    }
  }
  // Additional known MACs (rotated/randomized client MACs synced from the inventory)
  // also count as discovery evidence — a re-keyed host stays "discovered".
  for (const m of safeParseStringArray(h.host.macs)) {
    const mi = byMac.get(macKey(m));
    if (mi) {
      discovered = true;
      if (mi.lastSeenAt > (lastSeenAt ?? '')) lastSeenAt = mi.lastSeenAt;
    }
  }
  for (const ip of ips) {
    if (ip.macMismatch) macMismatch = true;
  }

  // DHCP-reported hostnames win over ARP/NDP ones.
  const bestName =
    hostNameCandidates.find((c) => c.dhcp)?.value ?? hostNameCandidates.find((c) => !c.dhcp)?.value ?? null;

  return {
    id: h.host.id,
    dnsNames: safeParseStringArray(h.host.dnsNames),
    friendlyName: h.host.friendlyName,
    description: h.host.description,
    siteId: h.host.siteId,
    siteName: h.host.siteId ? (siteNameById.get(h.host.siteId) ?? null) : null,
    layerId: h.host.layerId,
    layerName: h.host.layerId ? (layerNameById.get(h.host.layerId) ?? null) : null,
    tags: readStringArray(h.host.tags),
    macs: safeParseStringArray(h.host.macs),
    ips,
    discovered,
    lastSeenAt,
    observedHostname: bestName,
    macMismatch,
    isActive: h.host.isActive !== false, // defensive — the column is NOT NULL DEFAULT TRUE
    createdAt: h.host.createdAt,
    updatedAt: h.host.updatedAt,
  };
}

function safeParseStringArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value);
    return Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

/** Batch-loads site + layer display names for the given ids. */
async function loadReferenceNames(hosts: HostWithIps[]) {
  const siteIds = Array.from(new Set(hosts.map((h) => h.host.siteId).filter((s): s is string => !!s)));
  const layerIds = Array.from(new Set(hosts.map((h) => h.host.layerId).filter((l): l is string => !!l)));
  const [sites, layers] = await Promise.all([
    siteIds.length > 0 ? db.query.sites.findMany({ where: inArray(schema.sites.id, siteIds) }) : [],
    layerIds.length > 0 ? db.query.networkLayers.findMany({ where: inArray(schema.networkLayers.id, layerIds) }) : [],
  ]);
  return {
    siteNameById: new Map(sites.map((s) => [s.id, s.name] as const)),
    layerNameById: new Map(layers.map((l) => [l.id, l.name] as const)),
  };
}

/** Loads documented hosts (optionally filtered by site) with their IP rows. */
async function loadHostsWithIps(siteId?: string): Promise<HostWithIps[]> {
  const where = siteId ? eq(schema.documentedHosts.siteId, siteId) : undefined;
  const hostRows = await db.query.documentedHosts.findMany({
    ...(where ? { where } : {}),
    orderBy: [asc(schema.documentedHosts.createdAt)],
  });
  if (hostRows.length === 0) return [];
  const ipRows = await db.query.documentedHostIps.findMany({
    where: inArray(schema.documentedHostIps.hostId, hostRows.map((h) => h.id)),
  });
  const ipsByHost = new Map<string, typeof schema.documentedHostIps.$inferSelect[]>();
  for (const ip of ipRows) {
    const list = ipsByHost.get(ip.hostId);
    if (list) list.push(ip);
    else ipsByHost.set(ip.hostId, [ip]);
  }
  return hostRows.map((h) => ({ host: h, ips: ipsByHost.get(h.id) ?? [] }));
}

/** Full view for a set of hosts — shared by the list route and single-row responses. */
async function buildViews(hosts: HostWithIps[]): Promise<DocumentedHostView[]> {
  if (hosts.length === 0) return [];
  // Primary per-address MACs + additional known MACs (rotated/randomized clients).
  const macs = Array.from(
    new Set(hosts.flatMap((h) => [...h.ips.map((i) => i.mac), ...safeParseStringArray(h.host.macs)].filter((m): m is string => !!m)))
  );
  const addrs = Array.from(new Set(hosts.flatMap((h) => h.ips.map((i) => i.address))));
  const [{ byMac, byIp }, { siteNameById, layerNameById }, resolveNetworkLabel] = await Promise.all([
    loadLiveObservations(macs, addrs),
    loadReferenceNames(hosts),
    buildNetworkLabelResolver(),
  ]);
  return hosts.map((h) => shapeHost(h, siteNameById, layerNameById, resolveNetworkLabel, byMac, byIp));
}

// ---------------------------------------------------------------------------
// Input validation (shared by create / update / import)
// ---------------------------------------------------------------------------

interface HostInput {
  dnsNames?: unknown;
  friendlyName?: unknown;
  description?: unknown;
  siteId?: unknown;
  layerId?: unknown;
  tags?: unknown;
  isActive?: unknown;
  ips?: unknown;
}

interface ValidatedHost {
  dnsNames: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  layerId: string | null;
  /** Free-form tags (same data basis as devices.tags); [] = none. */
  tags: string[];
  /** Lifecycle flag — absent in the payload means "keep current" (true for new hosts). */
  isActive: boolean;
  ips: { address: string; mac: string | null; networkLabel: string | null; vlanId: number | null }[];
}

/** Parses a VLAN id (integer ≥ 0); null when absent/empty, -1 when invalid. */
function parseVlanId(value: unknown): number | null | -1 {
  if (value === undefined || value === null) return null;
  const n = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(n) || n < 0 || n > 4095) return -1;
  return n;
}

/** Validates + normalizes one host payload. Returns the normalized shape or an error message. */
async function validateHostInput(body: HostInput): Promise<{ ok: true; value: ValidatedHost } | { ok: false; error: string }> {
  // DNS names — at least one required, unique after normalization.
  const rawNames = Array.isArray(body.dnsNames) ? body.dnsNames : [];
  if (rawNames.length === 0) return { ok: false, error: '"dnsNames" must be a non-empty array' };
  const dnsNames: string[] = [];
  for (const n of rawNames) {
    if (typeof n !== 'string') return { ok: false, error: '"dnsNames" entries must be strings' };
    const norm = normalizeDnsName(n);
    if (!norm) return { ok: false, error: `Invalid DNS name: "${n}"` };
    if (!dnsNames.includes(norm)) dnsNames.push(norm);
  }

  // Optional text fields.
  const friendlyName = typeof body.friendlyName === 'string' && body.friendlyName.trim() ? body.friendlyName.trim() : null;
  const description = typeof body.description === 'string' && body.description.trim() ? body.description.trim() : null;

  // Lifecycle flag — only an explicit boolean changes it; anything else is ignored.
  let isActive: boolean | null = null;
  if (typeof body.isActive === 'boolean') isActive = body.isActive;

  // Site / layer references — must exist when provided.
  let siteId: string | null = null;
  if (body.siteId !== undefined && body.siteId !== null) {
    if (typeof body.siteId !== 'string' || !body.siteId) return { ok: false, error: '"siteId" must be a non-empty string or null' };
    const site = await db.query.sites.findFirst({ where: eq(schema.sites.id, body.siteId) });
    if (!site) return { ok: false, error: `Unknown siteId "${body.siteId}"` };
    siteId = site.id;
  }
  let layerId: string | null = null;
  if (body.layerId !== undefined && body.layerId !== null) {
    if (typeof body.layerId !== 'string' || !body.layerId) return { ok: false, error: '"layerId" must be a non-empty string or null' };
    const layer = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, body.layerId) });
    if (!layer) return { ok: false, error: `Unknown layerId "${body.layerId}"` };
    layerId = layer.id;
  }

  // Free-form tags (same data basis as devices.tags). Absent/undefined keeps
  // the current value on a PATCH; an explicit [] clears them.
  let tags: string[] | null = null;
  if (body.tags !== undefined) {
    const ref = parseStringArrayField(body.tags, 'tags');
    if (ref.error) return { ok: false, error: ref.error };
    tags = ref.value!;
  }

  // IP addresses — at least one required, unique per host.
  const rawIps = Array.isArray(body.ips) ? body.ips : [];
  if (rawIps.length === 0) return { ok: false, error: '"ips" must be a non-empty array' };
  const ips: ValidatedHost['ips'] = [];
  for (const ip of rawIps) {
    if (typeof ip !== 'object' || ip === null) return { ok: false, error: '"ips" entries must be objects' };
    const rec = ip as Record<string, unknown>;
    const address = typeof rec.address === 'string' ? rec.address.trim() : '';
    if (!isIpLiteral(address)) return { ok: false, error: `Invalid IP address: "${rec.address}"` };
    if (ips.some((x) => x.address === address)) return { ok: false, error: `Duplicate IP address in host: ${address}` };

    let mac: string | null = null;
    if (typeof rec.mac === 'string' && rec.mac.trim()) {
      const norm = normalizeMac(rec.mac);
      if (!norm) return { ok: false, error: `Invalid MAC address for ${address}: "${rec.mac}"` };
      mac = norm;
    }

    let networkLabel: string | null = null;
    if (typeof rec.networkLabel === 'string' && rec.networkLabel.trim()) {
      networkLabel = rec.networkLabel.trim();
    }

    const vlanId = parseVlanId(rec.vlanId);
    if (vlanId === -1) return { ok: false, error: `Invalid VLAN id for ${address}: "${String(rec.vlanId)}"` };

    ips.push({ address, mac, networkLabel, vlanId });
  }

  return { ok: true, value: { dnsNames, friendlyName, description, siteId, layerId, tags: tags ?? [], isActive: isActive ?? true, ips } };
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Loads one documented host with its IP rows; null when missing. */
async function loadOneHost(id: string): Promise<HostWithIps | null> {
  const host = await db.query.documentedHosts.findFirst({ where: eq(schema.documentedHosts.id, id) });
  if (!host) return null;
  const ips = await db.query.documentedHostIps.findMany({ where: eq(schema.documentedHostIps.hostId, id) });
  return { host, ips };
}

// GET /documented-hosts — list all documented hosts with live discovery info.
// Query params: siteId (filter by placement).
router.get('/documented-hosts', requireAuth, requirePermission('documented-hosts:read'), async (_req: Request, res: Response) => {
  try {
    const { siteId } = _req.query as Record<string, string | undefined>;
    const hosts = await loadHostsWithIps(siteId);
    const views = await buildViews(hosts);
    // Most recently updated first — the page is a working inventory.
    views.sort((a, b) => (b.updatedAt > a.updatedAt ? 1 : -1));
    res.status(200).json(views);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /documented-hosts — create a documented host. Requires documented-hosts:write.
router.post('/documented-hosts', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as HostInput;
    const validated = await validateHostInput(body);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const now = new Date().toISOString();
    const id = uuidv4();
    const v = validated.value;
    await db.insert(schema.documentedHosts).values({
      id,
      dnsNames: JSON.stringify(v.dnsNames),
      friendlyName: v.friendlyName,
      description: v.description,
      siteId: v.siteId,
      layerId: v.layerId,
      tags: JSON.stringify(v.tags),
      isActive: v.isActive, // new hosts default to active
      createdAt: now,
      updatedAt: now,
    });
    if (v.ips.length > 0) {
      await db.insert(schema.documentedHostIps).values(
        v.ips.map((ip) => ({ id: uuidv4(), hostId: id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
      );
    }

    const [created] = await buildViews([(await loadOneHost(id))!]);
    res.status(201).json(created);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PATCH /documented-hosts/:id — update a documented host (all-or-nothing replace
// of the provided fields; `ips` replaces the full address list when present).
router.patch('/documented-hosts/:id', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const existing = await loadOneHost(String(req.params.id ?? ''));
    if (!existing) {
      res.status(404).json({ error: 'Documented host not found' });
      return;
    }

    const body = (req.body ?? {}) as HostInput;
    // Merge the patch over the current values so partial updates work, then run
    // the SAME validation as create (the merged result must be a complete host).
    const current: HostInput = {
      dnsNames: safeParseStringArray(existing.host.dnsNames),
      friendlyName: existing.host.friendlyName,
      description: existing.host.description,
      siteId: existing.host.siteId,
      layerId: existing.host.layerId,
      tags: readStringArray(existing.host.tags),
      isActive: existing.host.isActive !== false, // defensive — the column is NOT NULL DEFAULT TRUE
      ips: existing.ips.map((i) => ({ address: i.address, mac: i.mac ?? null, networkLabel: i.networkLabel, vlanId: i.vlanId ?? null })),
    };
    const merged: HostInput = { ...current };
    for (const key of ['dnsNames', 'friendlyName', 'description', 'siteId', 'layerId', 'tags', 'isActive', 'ips'] as const) {
      if (body[key] !== undefined) (merged as Record<string, unknown>)[key] = body[key];
    }

    const validated = await validateHostInput(merged);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    const v = validated.value;
    const now = new Date().toISOString();
    await db.update(schema.documentedHosts)
      .set({
        dnsNames: JSON.stringify(v.dnsNames),
        friendlyName: v.friendlyName,
        description: v.description,
        siteId: v.siteId,
        layerId: v.layerId,
        tags: JSON.stringify(v.tags),
        isActive: v.isActive, // merged value — keeps the current flag when not provided
        updatedAt: now,
      })
      .where(eq(schema.documentedHosts.id, existing.host.id));

    // Replace the address list wholesale (simplest correct semantics for a
    // small per-host set; keeps the unique (hostId,address) constraint clean).
    await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, existing.host.id));
    if (v.ips.length > 0) {
      await db.insert(schema.documentedHostIps).values(
        v.ips.map((ip) => ({ id: uuidv4(), hostId: existing.host.id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
      );
    }

    const [updated] = await buildViews([(await loadOneHost(existing.host.id))!]);
    res.status(200).json(updated);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /documented-hosts/:id — remove a documented host + its addresses.
router.delete('/documented-hosts/:id', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const existing = await loadOneHost(String(req.params.id ?? ''));
    if (!existing) {
      res.status(404).json({ error: 'Documented host not found' });
      return;
    }
    await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, existing.host.id));
    await db.delete(schema.documentedHosts).where(eq(schema.documentedHosts.id, existing.host.id));
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// CSV import (flexible header mapping — the webapp maps columns client-side and
// sends already-structured rows; this endpoint only validates + upserts)
// ---------------------------------------------------------------------------

interface ImportRow {
  dnsNames?: unknown;
  friendlyName?: unknown;
  description?: unknown;
  siteId?: unknown;
  layerId?: unknown;
  tags?: unknown;
  ips?: unknown;
}

/** Matches an import row against existing hosts. */
function findExistingHost(
  rows: HostWithIps[],
  byDns: Map<string, string>, // normalized dns name -> host id
  byMac: Map<string, string>, // documented mac (compact) -> host id
  row: ImportRow,
  matchBy: 'dns' | 'mac'
): string | null {
  if (matchBy === 'dns') {
    const names = Array.isArray(row.dnsNames) ? row.dnsNames : [];
    for (const n of names) {
      if (typeof n !== 'string') continue;
      const norm = normalizeDnsName(n);
      if (!norm) continue;
      const id = byDns.get(norm);
      if (id) return id;
    }
    return null;
  }
  // matchBy === 'mac' — any documented MAC in the row identifies the host.
  const ips = Array.isArray(row.ips) ? row.ips : [];
  for (const ip of ips) {
    if (typeof ip !== 'object' || ip === null) continue;
    const mac = (ip as Record<string, unknown>).mac;
    if (typeof mac !== 'string') continue;
    const norm = normalizeMac(mac);
    if (!norm) continue;
    const id = byMac.get(macKey(norm));
    if (id) return id;
  }
  return null;
}

// POST /documented-hosts/import — bulk-create/update documented hosts.
// Body: { hosts: [...], matchBy?: 'dns'|'mac', updateExisting?: boolean }.
// Rows are validated independently — one bad row never aborts the batch.
router.post('/documented-hosts/import', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const rows = Array.isArray(body.hosts) ? body.hosts : null;
    if (!rows || rows.length === 0) {
      res.status(400).json({ error: '"hosts" must be a non-empty array' });
      return;
    }
    if (rows.length > 5000) {
      res.status(400).json({ error: 'At most 5000 hosts per import batch' });
      return;
    }
    const matchBy: 'dns' | 'mac' = body.matchBy === 'mac' ? 'mac' : 'dns';
    const updateExisting = body.updateExisting !== false;

    // Index existing hosts for matching.
    const existingRows = await loadHostsWithIps();
    const byDns = new Map<string, string>();
    const byMac = new Map<string, string>();
    for (const h of existingRows) {
      for (const n of safeParseStringArray(h.host.dnsNames)) byDns.set(n, h.host.id);
      for (const ip of h.ips) if (ip.mac) byMac.set(macKey(ip.mac), h.host.id);
    }

    let created = 0;
    let updated = 0;
    let skipped = 0;
    const errors: { index: number; error: string }[] = [];
    const now = new Date().toISOString();

    for (let i = 0; i < rows.length; i++) {
      const row = (rows[i] ?? {}) as ImportRow;
      const validated = await validateHostInput(row);
      if (!validated.ok) {
        errors.push({ index: i, error: validated.error });
        continue;
      }
      const v = validated.value;

      const existingId = findExistingHost(existingRows, byDns, byMac, row, matchBy);
      if (existingId && !updateExisting) {
        skipped++;
        continue;
      }

      if (existingId) {
        // Update in place — keep the original id + createdAt. isActive is NOT
        // touched by a CSV import (the lifecycle flag is user-managed); tags are
        // merged additively so an import never drops existing labels.
        const existingHost = existingRows.find((h) => h.host.id === existingId);
        const mergedTags = mergeTagLists(readStringArray(existingHost?.host.tags), v.tags);
        await db.update(schema.documentedHosts)
          .set({
            dnsNames: JSON.stringify(v.dnsNames),
            friendlyName: v.friendlyName,
            description: v.description,
            siteId: v.siteId,
            layerId: v.layerId,
            tags: JSON.stringify(mergedTags),
            updatedAt: now,
          })
          .where(eq(schema.documentedHosts.id, existingId));
        await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, existingId));
        if (v.ips.length > 0) {
          await db.insert(schema.documentedHostIps).values(
            v.ips.map((ip) => ({ id: uuidv4(), hostId: existingId, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
          );
        }
        updated++;
      } else {
        const id = uuidv4();
        await db.insert(schema.documentedHosts).values({
          id,
          dnsNames: JSON.stringify(v.dnsNames),
          friendlyName: v.friendlyName,
          description: v.description,
          siteId: v.siteId,
          layerId: v.layerId,
          tags: JSON.stringify(v.tags),
          isActive: true, // imported hosts start active
          createdAt: now,
          updatedAt: now,
        });
        if (v.ips.length > 0) {
          await db.insert(schema.documentedHostIps).values(
            v.ips.map((ip) => ({ id: uuidv4(), hostId: id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
          );
        }
        created++;
      }
    }

    res.status(200).json({ created, updated, skipped, errors });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /documented-hosts/bulk — batch updates. Body:
// { ids: string[], isActive?: boolean, siteId?: string|null, layerId?: string|null }
// Marks every existing id active/stale and/or sets its site/layer placement in
// one call (the webapp bulk actions send the current selection). Unknown ids
// are reported, never fatal; at most 5000 ids per call. Omitted fields = no-op.
router.post('/documented-hosts/bulk', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const ids = Array.isArray(body.ids) ? (body.ids as unknown[]).filter((x): x is string => typeof x === 'string' && !!x) : [];
    if (ids.length === 0) {
      res.status(400).json({ error: '"ids" must be a non-empty array of documented host ids' });
      return;
    }
    if (ids.length > 5000) {
      res.status(400).json({ error: 'At most 5000 ids per bulk update' });
      return;
    }

    // Optional fields — each omitted = no-op on that field. siteId/layerId must
    // reference an existing registry entry (or null to clear the placement).
    const hasFlag = typeof body.isActive === 'boolean';
    let siteId: string | null | undefined;
    if (body.siteId !== undefined) {
      if (body.siteId === null) siteId = null;
      else if (typeof body.siteId === 'string' && body.siteId) {
        const site = await db.query.sites.findFirst({ where: eq(schema.sites.id, body.siteId) });
        if (!site) { res.status(400).json({ error: `Unknown siteId "${body.siteId}"` }); return; }
        siteId = site.id;
      } else { res.status(400).json({ error: '"siteId" must be a non-empty string or null' }); return; }
    }
    let layerId: string | null | undefined;
    if (body.layerId !== undefined) {
      if (body.layerId === null) layerId = null;
      else if (typeof body.layerId === 'string' && body.layerId) {
        const layer = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, body.layerId) });
        if (!layer) { res.status(400).json({ error: `Unknown layerId "${body.layerId}"` }); return; }
        layerId = layer.id;
      } else { res.status(400).json({ error: '"layerId" must be a non-empty string or null' }); return; }
    }

    const existing = await db.query.documentedHosts.findMany({ where: inArray(schema.documentedHosts.id, Array.from(new Set(ids))) });
    const foundIds = new Set(existing.map((h) => h.id));
    const missing = ids.filter((id) => !foundIds.has(id));

    if ((hasFlag || siteId !== undefined || layerId !== undefined) && existing.length > 0) {
      const set: Record<string, unknown> = { updatedAt: new Date().toISOString() };
      if (hasFlag) set.isActive = body.isActive as boolean;
      if (siteId !== undefined) set.siteId = siteId;
      if (layerId !== undefined) set.layerId = layerId;
      await db.update(schema.documentedHosts).set(set).where(inArray(schema.documentedHosts.id, Array.from(foundIds)));
    }

    res.status(200).json({ updated: hasFlag || siteId !== undefined || layerId !== undefined ? existing.length : 0, missing });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Import from live inventory — copies the observed hosts (GET /hosts data)
// into the documented-hosts table. The merge is ADDITIVE and never loses user
// data: existing DNS names, friendly name, description, site/layer placement
// are preserved; new addresses/MACs/network references from the observation
// are added to the host's address list (matched hosts by MAC or observed IP).
// ---------------------------------------------------------------------------

/**
 * How to treat publicly routable addresses of one family during the import.
 * - 'keep'      : import every address as-is (default).
 * - 'strip'     : drop ONLY the public addresses, still import the host with its
 *                 internal ones (private v4 / ULA stay) — dual-stack friendly.
 * - 'skip-host' : any public address of this family → skip the whole host.
 */
type PublicIpPolicy = 'keep' | 'strip' | 'skip-host';

/**
 * How to reconcile a documented MAC that differs from what is currently observed
 * for the same address (e.g. docker container re-creation or a client with a
 * randomized MAC):
 * - 'keep'     : never touch documented MACs — mismatches stay flagged in the UI (default).
 * - 'replace'  : set the address's documented MAC to the observed one.
 * - 'add'      : keep the documented MAC and remember the observed one as an
 *                ADDITIONAL identity of the host (documented_hosts.macs) — discovery
 *                + future import matching keep working after a re-key.
 */
type MacSyncPolicy = 'keep' | 'replace' | 'add';

/** Options for the inventory import. */
interface InventoryImportOptions {
  /** Skip live hosts without a usable hostname (no DNS name can be derived). Default true. */
  skipWithoutHostname?: boolean;
  /** Skip live hosts whose addresses match no known logical network. Default false. */
  skipUnknownNetworks?: boolean;
  /** Policy for publicly routable IPv4 addresses (RFC 1918 + loopback/link-local count as internal). Default 'keep'. */
  publicIpv4Policy?: PublicIpPolicy;
  /** Policy for publicly routable IPv6 addresses (GUA 2000::/3; ULA fc00::/7 counts as internal). Default 'keep'. */
  publicIpv6Policy?: PublicIpPolicy;
  /** Range filter mode: 'include-only' imports only matching hosts, 'exclude' skips them. Default 'keep-all'. */
  rangeMode?: 'keep-all' | 'include-only' | 'exclude';
  /** CIDR networks / IP ranges the range filter applies to (empty = no filtering). */
  ranges?: string[];
  /** Skip live hosts whose addresses resolve to no known logical network with a discovered VLAN id. Default false. */
  skipWithoutVlan?: boolean;
  /** Only import hosts observed within this many hours (0 = all, default 24 — the sweep window). */
  maxAgeHours?: number;
  /** How to reconcile documented vs observed MACs: keep = never touch (default), replace = set the address's documented MAC to the observed one, add = keep it and remember the observed MAC as an additional identity of the host. */
  macSyncPolicy?: MacSyncPolicy;
  /** Preview only — compute what would change without writing anything. Default true. */
  dryRun?: boolean;
}

/** One planned change for a single live host (or merged hostname group). */
interface InventoryImportPlanEntry {
  mac: string;
  hostname: string | null;
  ips: number;
  /** 'create' = new documented host, 'update' = merge into an existing one, 'skip' = unchanged/filtered out. */
  action: 'create' | 'update' | 'skip';
  reason?: string;
  /** Public addresses removed by a 'strip' policy (action=create/update only). */
  stripped?: number;
  /** Extra MACs folded into this entry by the hostname merge (multi-NIC host); empty/absent = single-MAC row. */
  mergedFrom?: string[];
  /** Documented-vs-observed MAC mismatches that would be REPLACED with the observed MAC (macSyncPolicy='replace'). */
  macReplaced?: number;
  /** Observed MACs that would be ADDED as additional identities of the host (macSyncPolicy='add'). */
  macAdded?: number;
}

/** Result of the inventory import (dry-run or applied). */
interface InventoryImportResult {
  dryRun: boolean;
  totalLiveHosts: number;
  planned: InventoryImportPlanEntry[];
  created: number;
  updated: number;
  skipped: number;
  /** How many live MAC rows were folded into one entry by the hostname merge (dry-run only). */
  mergedGroups?: number;
  /** Total documented-vs-observed MAC mismatches replaced with the observed MAC. */
  macReplaced?: number;
  /** Total observed MACs added as additional identities of their host. */
  macAdded?: number;
}

/** Normalizes an observed hostname into a documentable DNS name. */
function hostnameToDnsName(hostname: string | null): string {
  if (!hostname) return '';
  let v = hostname.trim().toLowerCase();
  // Strip zone suffixes ("host%eth0") and trailing dots.
  const pct = v.indexOf('%');
  if (pct >= 0) v = v.slice(0, pct);
  if (v.endsWith('.')) v = v.slice(0, -1);
  return normalizeDnsName(v);
}

/** True for addresses that are not documentable host addresses. */
function isNonDocumentableAddress(addr: string): boolean {
  const a = addr.trim().toLowerCase();
  if (a.includes('%')) return true; // zone-suffixed link-local
  if (!isIpLiteral(a)) return false;
  // Link-locals are per-interface, not documentable inventory addresses.
  if (a.startsWith('169.254.')) return true;
  if (a === '::' || a === '0.0.0.0') return true;
  if (a.startsWith('fe80:')) return true;
  return false;
}

/** Most specific known subnet containing the address (+ its VLAN); null when unknown. */
function mostSpecificSubnet(
  subnets: { cidr: string; vlanId: number | null }[],
  addr: string
): { cidr: string; vlanId: number | null } | null {
  let best: { cidr: string; vlanId: number | null } | null = null;
  let bestPrefix = -1;
  for (const s of subnets) {
    const i = s.cidr.indexOf('/');
    if (i < 0) continue;
    const prefix = Number(s.cidr.slice(i + 1));
    // Family must match the address.
    if (s.cidr.includes(':') !== addr.includes(':')) continue;
    if (!ipInCidr(addr, s.cidr)) continue;
    if (prefix > bestPrefix) {
      best = s;
      bestPrefix = prefix;
    }
  }
  return best;
}

/** Coerces a request value into a PublicIpPolicy ('keep' when absent/unknown). */
function parsePublicIpPolicy(value: unknown): PublicIpPolicy {
  if (value === 'strip' || value === 'skip-host') return value;
  return 'keep';
}

/** One parsed network/range entry — a CIDR block or an inclusive IP range. */
export interface RangeEntry {
  family: 'v4' | 'v6';
  kind: 'cidr' | 'range';
  cidr?: string;
  lo?: bigint;
  hi?: bigint;
}

/** Parses a single "a.b.c.d/p", "fd00::/64" or "1.2.3.4-1.2.3.9" entry; null when malformed. */
export function parseRangeEntry(raw: string): RangeEntry | null {
  const v = raw.trim();
  if (!v) return null;
  // CIDR block.
  const slash = v.indexOf('/');
  if (slash > 0) {
    const net = v.slice(0, slash);
    const prefix = Number(v.slice(slash + 1));
    const fam = ipFamily(net);
    if (!fam || !Number.isInteger(prefix)) return null;
    if ((fam === 'v4' && (prefix < 0 || prefix > 32)) || (fam === 'v6' && (prefix < 0 || prefix > 128))) return null;
    return { family: fam, kind: 'cidr', cidr: v };
  }
  // Inclusive IP range "lo-hi".
  const dash = v.indexOf('-');
  if (dash > 0) {
    const loRaw = v.slice(0, dash).trim();
    const hiRaw = v.slice(dash + 1).trim();
    const famLo = ipFamily(loRaw);
    const famHi = ipFamily(hiRaw);
    if (!famLo || famLo !== famHi) return null;
    let lo: bigint;
    let hi: bigint;
    if (famLo === 'v4') {
      const a = ipv4ToInt(loRaw);
      const b = ipv4ToInt(hiRaw);
      if (a === null || b === null) return null;
      lo = BigInt(a);
      hi = BigInt(b);
    } else {
      const a = ipv6ToBigInt(loRaw);
      const b = ipv6ToBigInt(hiRaw);
      if (a === null || b === null) return null;
      lo = a;
      hi = b;
    }
    if (lo > hi) return null; // reversed range
    return { family: famLo, kind: 'range', lo, hi };
  }
  return null;
}

/** True when any of the addresses falls into ANY of the parsed entries (family-aware). */
export function hostInRanges(addrs: string[], ranges: RangeEntry[]): boolean {
  for (const a of addrs) {
    const fam = ipFamily(a);
    if (!fam) continue;
    for (const r of ranges) {
      if (r.family !== fam) continue;
      if (r.kind === 'cidr') {
        if (ipInCidr(a, r.cidr!)) return true;
      } else {
        let v: bigint | null;
        if (fam === 'v4') {
          const n = ipv4ToInt(a);
          if (n === null) continue;
          v = BigInt(n);
        } else {
          v = ipv6ToBigInt(a);
          if (v === null) continue;
        }
        if (v >= r.lo! && v <= r.hi!) return true;
      }
    }
  }
  return false;
}

/** Parses all raw range entries once; throws a 400 on the first malformed entry. */
export function parseRanges(rawRanges: string[] | undefined): RangeEntry[] {
  const out: RangeEntry[] = [];
  for (const r of rawRanges ?? []) {
    const e = parseRangeEntry(r);
    if (!e) throw Object.assign(new Error(`Invalid network/range entry: "${r}" — expected a CIDR block (192.168.1.0/24, fd00::/64) or an inclusive IP range (192.168.1.10-192.168.1.50)`), { status: 400 });
    out.push(e);
  }
  return out;
}

/**
 * Applies the network/range filter to a live host's addresses. Returns 'skip' with
 * a reason, or null when the host passes (and no ranges are configured). Runs
 * BEFORE all other options.
 */
/** Applies the network/range filter to an address list (shared with documented networks). */
export function rangeFilterDecision(
  addrs: string[],
  mode: 'keep-all' | 'include-only' | 'exclude',
  ranges: RangeEntry[]
): { skip?: boolean; reason?: string } {
  if (mode === 'keep-all' || ranges.length === 0) return {};
  const matches = hostInRanges(addrs, ranges);
  if (mode === 'include-only' && !matches) return { skip: true, reason: 'outside selected ranges' };
  if (mode === 'exclude' && matches) return { skip: true, reason: 'excluded range' };
  return {};
}

/**
 * Applies the per-family public-address policies to an address list. Returns the
 * addresses to keep, how many were stripped, and a skip reason when a 'skip-host'
 * policy matched (or kept is empty after stripping).
 */
function applyPublicPolicies(
  addrs: string[],
  v4Policy: PublicIpPolicy,
  v6Policy: PublicIpPolicy
): { kept: string[]; stripped: number; skipReason?: string } {
  if (v4Policy === 'skip-host' && addrs.some((a) => !a.includes(':') && isPublicIpv4(a))) {
    return { kept: [], stripped: 0, skipReason: 'public IPv4 address' };
  }
  if (v6Policy === 'skip-host' && addrs.some((a) => a.includes(':') && isPublicIpv6(a))) {
    return { kept: [], stripped: 0, skipReason: 'public IPv6 address' };
  }
  const stripV4 = v4Policy === 'strip';
  const stripV6 = v6Policy === 'strip';
  if (!stripV4 && !stripV6) return { kept: addrs, stripped: 0 };
  const kept = addrs.filter((a) => {
    if (a.includes(':')) return !(stripV6 && isPublicIpv6(a));
    return !(stripV4 && isPublicIpv4(a));
  });
  return { kept, stripped: addrs.length - kept.length };
}

/** One live host after the smart hostname merge (see groupLiveHostsByHostname). */
interface LiveHostGroup {
  /** Representative hostname (null when no row has one) — the merge key. */
  hostname: string | null;
  /** Every MAC of the group, first-seen order. */
  macs: string[];
  /** First MAC — representative for plan display + fallback DNS name. */
  mac: string;
  /** Union of all addresses across the group's rows (deduped, case-insensitive). */
  addrs: string[];
  /** Address → the MAC that reported it (lowercased address key). */
  addrMac: Map<string, string>;
}

/**
 * SMART MERGE — one physical machine with several NICs shows up in the live
 * inventory as ONE ROW PER MAC (mergeHostRows merges by MAC). Group those rows
 * by their observed hostname so a multi-NIC host is imported/updated as a
 * SINGLE documented host carrying every address + MAC. Rows without a usable
 * hostname keep the legacy per-MAC behavior: each stands alone on its own.
 */
function groupLiveHostsByHostname(live: MergedHost[]): LiveHostGroup[] {
  const groups = new Map<string, LiveHostGroup>();
  for (const h of live) {
    const key = hostnameToDnsName(h.hostname);
    if (!key) {
      // No usable hostname — legacy per-MAC behavior: one group per row.
      groups.set(`mac:${h.mac.toLowerCase()}`, {
        hostname: null,
        macs: [h.mac],
        mac: h.mac,
        addrs: [...h.ips],
        addrMac: new Map(h.ips.map((a) => [a.toLowerCase(), h.mac])),
      });
    } else {
      let g = groups.get(key);
      if (!g) {
        g = { hostname: h.hostname, macs: [], mac: h.mac, addrs: [], addrMac: new Map() };
        groups.set(key, g);
      }
      if (!g.macs.includes(h.mac)) g.macs.push(h.mac);
      for (const a of h.ips) {
        const k = a.toLowerCase();
        if (!g.addrMac.has(k)) {
          g.addrs.push(a);
          g.addrMac.set(k, h.mac);
        }
      }
    }
  }
  return Array.from(groups.values());
}

// ---------------------------------------------------------------------------
// Device placement — a host that is ALSO known in the device inventory can
// inherit its site / layer / tags (the same registries devices use). The live
// `hosts` table only holds rows collected ON registered devices, so "known in
// the devices" = at least one of the group's MACs/addresses was observed on a
// device. Placement uses the SAME precedence as GET /topology for the layer:
// manual override > plugin-suggested model default > type/vendor heuristic.
// ---------------------------------------------------------------------------

/** Resolved placement data of one known device. */
interface DevicePlacement {
  deviceId: string;
  name: string;
  siteId: string | null;
  /** Resolved topology-layer id (override > suggestion > heuristic). */
  layerId: string | null;
  tags: string[];
}

/** Index of device placements + which devices observed each MAC / address. */
interface DevicePlacementIndex {
  placements: Map<string, DevicePlacement>;
  /** Compact MAC key -> observing device ids (first-seen order). */
  byMac: Map<string, string[]>;
  /** Lowercased address -> observing device ids (first-seen order). */
  byAddr: Map<string, string[]>;
}

/** Loads the placement of every device that observed any of the given MACs/addresses. */
async function loadDevicePlacements(macs: string[], addrs: string[]): Promise<DevicePlacementIndex> {
  const idx: DevicePlacementIndex = { placements: new Map(), byMac: new Map(), byAddr: new Map() };
  if (macs.length === 0 && addrs.length === 0) return idx;

  const macCandidates = Array.from(new Set(macs.flatMap((m) => [m, macKey(m)])));
  const conditions = [];
  if (macCandidates.length > 0) conditions.push(inArray(schema.hosts.mac, macCandidates));
  if (addrs.length > 0) conditions.push(inArray(schema.hosts.ip, addrs));
  if (conditions.length === 0) return idx;

  const rows = await db.query.hosts.findMany({ where: or(...conditions) });
  for (const r of rows) {
    // Which registered device observed this MAC / address.
    const push = (map: Map<string, string[]>, key: string) => {
      const list = map.get(key);
      if (!list) map.set(key, [r.deviceId]);
      else if (!list.includes(r.deviceId)) list.push(r.deviceId);
    };
    push(idx.byMac, macKey(r.mac));
    if (r.ip !== '') push(idx.byAddr, r.ip.toLowerCase());
  }

  const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId)));
  if (deviceIds.length === 0) return idx;

  const [devices, layerRows, assignments] = await Promise.all([
    db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }),
    db.query.networkLayers.findMany(),
    db.query.devicePlugins.findMany({ where: inArray(schema.devicePlugins.deviceId, deviceIds) }),
  ]);
  const validLayerIds = new Set(layerRows.map((l) => l.id));
  const suggestedByDevice = await loadSuggestedLayers(
    devices.map((d) => ({ id: d.id, vendor: d.vendor, model: d.model })),
    assignments,
    validLayerIds
  );

  for (const d of devices) {
    let types: string[] = [];
    try {
      const parsed = JSON.parse(d.deviceTypes);
      if (Array.isArray(parsed)) types = parsed.filter((t): t is string => typeof t === 'string');
    } catch {
      /* malformed array — the heuristic simply sees no types */
    }
    idx.placements.set(d.id, {
      deviceId: d.id,
      name: d.name,
      siteId: d.siteId ?? null,
      layerId: classifyLayer({
        id: d.id,
        name: d.name,
        status: d.status,
        siteId: d.siteId,
        managementAddress: d.managementAddress,
        deviceTypes: types,
        vendor: d.vendor,
        model: d.model ?? null,
        layerOverride: d.layerOverride && validLayerIds.has(d.layerOverride) ? d.layerOverride : null,
        suggestedLayerId: suggestedByDevice.get(d.id) ?? null,
      }, []), // no port detail — the switch-VLAN heuristic falls through to 'access'
      tags: readStringArray(d.tags),
    });
  }
  return idx;
}

/** The placement of the FIRST known device that observed this group (name-sorted for determinism). */
function placementForGroup(g: LiveHostGroup, idx: DevicePlacementIndex): DevicePlacement | null {
  const ids = new Set<string>();
  for (const m of g.macs) for (const id of idx.byMac.get(macKey(m)) ?? []) ids.add(id);
  for (const a of g.addrs) for (const id of idx.byAddr.get(a.toLowerCase()) ?? []) ids.add(id);
  const list = [...ids]
    .map((id) => idx.placements.get(id))
    .filter((p): p is DevicePlacement => !!p)
    .sort((a, b) => a.name.localeCompare(b.name));
  return list[0] ?? null;
}

/**
 * Applies a known device's placement to a documented host — OPTIONALLY: only
 * fills gaps. A NEW host takes everything the device knows (site/layer/tags);
 * an EXISTING host keeps its user values and only gains what it lacks (tags are
 * merged additively). Returns the fields to write + whether anything changed.
 */
function applyDevicePlacement(
  target: { siteId: string | null; layerId: string | null; tags: string[] } | null,
  placement: DevicePlacement
): { siteId?: string | null; layerId?: string | null; tags?: string[]; changed: boolean } {
  const out: { siteId?: string | null; layerId?: string | null; tags?: string[]; changed: boolean } = { changed: false };
  if (!target) {
    // New host — inherit the device's placement.
    if (placement.siteId) { out.siteId = placement.siteId; out.changed = true; }
    if (placement.layerId) { out.layerId = placement.layerId; out.changed = true; }
    if (placement.tags.length > 0) { out.tags = [...placement.tags]; out.changed = true; }
    return out;
  }
  // Existing host — fill gaps only, user values always win.
  if (!target.siteId && placement.siteId) { out.siteId = placement.siteId; out.changed = true; }
  if (!target.layerId && placement.layerId) { out.layerId = placement.layerId; out.changed = true; }
  const mergedTags = mergeTagLists(target.tags, placement.tags);
  if (mergedTags.length !== target.tags.length) { out.tags = mergedTags; out.changed = true; }
  return out;
}

/**
 * Builds the import plan from the live inventory + current documented hosts.
 * Pure function of its inputs — shared by dry-run and apply so both agree.
 */
async function buildInventoryImportPlan(opts: InventoryImportOptions): Promise<InventoryImportResult> {
  const [hostRows, networkRows, existing] = await Promise.all([
    db.query.hosts.findMany(),
    db.query.networks.findMany(),
    loadHostsWithIps(),
  ]);

  // Merged logical networks — every real subnet + VLAN id per group.
  const mergedNetworks = mergeNetworkRows(networkRows);
  const subnets: { cidr: string; vlanId: number | null }[] = [];
  for (const n of mergedNetworks) {
    for (const s of n.subnets ?? []) subnets.push({ cidr: s, vlanId: n.vlanId });
  }

  const maxAgeHours = Number.isFinite(opts.maxAgeHours as number) && (opts.maxAgeHours as number) > 0 ? (opts.maxAgeHours as number) : 24;
  const cutoff = new Date(Date.now() - maxAgeHours * 3600_000).toISOString();

  // Index existing documented hosts by MAC and by address.
  const docByMac = new Map<string, HostWithIps>();
  const docByAddr = new Map<string, HostWithIps[]>();
  for (const h of existing) {
    for (const ip of h.ips) {
      const list = docByAddr.get(ip.address.toLowerCase());
      if (list) list.push(h);
      else docByAddr.set(ip.address.toLowerCase(), [h]);
    }
    // Primary per-address MACs + additional known MACs — a re-keyed host must
    // still match its documented row instead of creating a duplicate.
    for (const m of [...h.ips.map((i) => i.mac), ...safeParseStringArray(h.host.macs)]) {
      if (m && !docByMac.has(macKey(m))) docByMac.set(macKey(m), h);
    }
  }

  const live = mergeHostRows(hostRows).filter((h) => h.lastSeenAt >= cutoff);
  // Parse the range filter ONCE (throws 400 on a malformed entry).
  const ranges = parseRanges(opts.ranges);
  const macSyncPolicy: MacSyncPolicy = opts.macSyncPolicy ?? 'keep';
  const planned: InventoryImportPlanEntry[] = [];
  let created = 0;
  let updated = 0;
  let skipped = 0;
  let totalMacReplaced = 0;
  let totalMacAdded = 0;

  // SMART MERGE — fold the per-MAC live rows into hostname groups so a
  // multi-NIC machine is planned as ONE documented host (see above).
  const groups = groupLiveHostsByHostname(live);
  const mergedGroups = groups.filter((g) => g.macs.length > 1).length;

  // Device placement — hosts that are also known in the device inventory can
  // inherit site/layer/tags from their observing device (see above).
  const placementIdx = await loadDevicePlacements(
    groups.flatMap((g) => g.macs),
    groups.flatMap((g) => g.addrs.filter((a) => !isNonDocumentableAddress(a)))
  );

  for (const g of groups) {
    // Documentable addresses only.
    let addrs = g.addrs.filter((a) => !isNonDocumentableAddress(a));
    if (addrs.length === 0) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: 0, action: 'skip', reason: 'no documentable address' });
      skipped++;
      continue;
    }

    // Network/range filter FIRST — include-only / exclude runs before every other option.
    const rf = rangeFilterDecision(addrs, opts.rangeMode ?? 'keep-all', ranges);
    if (rf.skip) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: addrs.length, action: 'skip', reason: rf.reason });
      skipped++;
      continue;
    }

    // Public-address policies per family — dual-stack friendly (strip keeps the
    // host with its internal addresses; skip-host drops it entirely).
    const pol = applyPublicPolicies(addrs, opts.publicIpv4Policy ?? 'keep', opts.publicIpv6Policy ?? 'keep');
    if (pol.skipReason) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: addrs.length, action: 'skip', reason: pol.skipReason });
      skipped++;
      continue;
    }
    const stripped = pol.stripped;
    addrs = pol.kept;
    if (addrs.length === 0) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: 0, action: 'skip', reason: 'only public addresses' });
      skipped++;
      continue;
    }

    let dnsName = hostnameToDnsName(g.hostname);
    if (!dnsName) {
      if (opts.skipWithoutHostname !== false) {
        planned.push({ mac: g.mac, hostname: null, ips: addrs.length, action: 'skip', reason: 'no hostname' });
        skipped++;
        continue;
      }
      // No usable hostname — fall back to the MAC as the DNS name (still valid RFC 1123).
      dnsName = g.mac.replace(/:/g, '');
    }

    const nets = addrs.map((a) => mostSpecificSubnet(subnets, a));
    if (opts.skipUnknownNetworks === true && !nets.some((n) => n !== null)) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: addrs.length, action: 'skip', reason: 'no known network' });
      skipped++;
      continue;
    }
    if (opts.skipWithoutVlan === true && !nets.some((n) => n !== null && n.vlanId != null)) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: addrs.length, action: 'skip', reason: 'no VLAN discovered' });
      skipped++;
      continue;
    }

    // Match an existing documented host — by MAC first (the stable identity),
    // then by any shared address. A multi-NIC group matches when ANY of its
    // MACs or addresses is already documented.
    let target: HostWithIps | null = null;
    for (const m of g.macs) {
      const t = docByMac.get(macKey(m));
      if (t) {
        target = t;
        break;
      }
    }
    if (!target) {
      for (const a of addrs) {
        const cands = docByAddr.get(a.toLowerCase());
        if (cands && cands.length > 0) {
          target = cands[0];
          break;
        }
      }
    }

    // MAC sync — documented vs observed for the addresses this group reports.
    let macReplaced = 0;
    const macAddedList: string[] = [];
    if (target && macSyncPolicy !== 'keep') {
      const existingMacs = new Set(target.ips.map((i) => i.mac).filter((m): m is string => !!m).map(macKey));
      for (const a of addrs) {
        const rowMac = g.addrMac.get(a.toLowerCase()) ?? g.mac;
        const norm = normalizeMac(rowMac);
        if (!norm) continue;
        const docRow = target.ips.find((i) => i.address.toLowerCase() === a.toLowerCase());
        if (docRow?.mac && macKey(docRow.mac) !== macKey(norm)) {
          // Documented MAC differs from what is observed for this address.
          if (macSyncPolicy === 'replace') {
            macReplaced++;
          } else if (!existingMacs.has(macKey(norm))) {
            macAddedList.push(norm);
          }
        }
      }
    }

    // Would the merge actually change anything?
    let wouldChange = false;
    const placement = placementForGroup(g, placementIdx);
    if (!target) {
      wouldChange = true;
    } else {
      const existingAddrs = new Set(target.ips.map((i) => i.address.toLowerCase()));
      for (const a of addrs) if (!existingAddrs.has(a.toLowerCase())) wouldChange = true;
      // A missing MAC or network reference on an already-documented address also counts.
      for (const ip of target.ips) {
        const net = nets.find((n, i2) => n !== null && addrs[i2].toLowerCase() === ip.address.toLowerCase());
        if (!ip.mac || !ip.networkLabel) wouldChange = true;
        else if (net && ip.vlanId == null && net.vlanId != null) wouldChange = true;
      }
      const names = safeParseStringArray(target.host.dnsNames);
      if (dnsName && !names.includes(dnsName)) wouldChange = true;
      // A known device's placement filling a gap also counts.
      if (placement && applyDevicePlacement({ siteId: target.host.siteId, layerId: target.host.layerId, tags: readStringArray(target.host.tags) }, placement).changed) {
        wouldChange = true;
      }
      // Planned MAC sync changes count too — a pure re-key is still an update.
      if (macReplaced > 0 || macAddedList.length > 0) wouldChange = true;
    }

    if (!wouldChange) {
      planned.push({ mac: g.mac, hostname: g.hostname, ips: addrs.length, action: 'skip', reason: 'already fully documented' });
      skipped++;
      continue;
    }

    if (target) updated++;
    else created++;
    totalMacReplaced += macReplaced;
    totalMacAdded += macAddedList.length;
    planned.push({
      mac: g.mac,
      hostname: g.hostname ?? dnsName,
      ips: addrs.length,
      action: target ? 'update' : 'create',
      stripped: stripped > 0 ? stripped : undefined,
      mergedFrom: g.macs.length > 1 ? g.macs.slice(1) : undefined,
      macReplaced: macReplaced > 0 ? macReplaced : undefined,
      macAdded: macAddedList.length > 0 ? macAddedList.length : undefined,
    });
  }

  return { dryRun: true, totalLiveHosts: live.length, planned, created, updated, skipped, mergedGroups, macReplaced: totalMacReplaced || undefined, macAdded: totalMacAdded || undefined };
}

/** Applies the plan — writes only what buildInventoryImportPlan() computed. */
async function applyInventoryImport(opts: InventoryImportOptions): Promise<InventoryImportResult> {
  const [hostRows, networkRows, existing] = await Promise.all([
    db.query.hosts.findMany(),
    db.query.networks.findMany(),
    loadHostsWithIps(),
  ]);

  const mergedNetworks = mergeNetworkRows(networkRows);
  const subnets: { cidr: string; vlanId: number | null }[] = [];
  for (const n of mergedNetworks) {
    for (const s of n.subnets ?? []) subnets.push({ cidr: s, vlanId: n.vlanId });
  }
  const maxAgeHours = Number.isFinite(opts.maxAgeHours as number) && (opts.maxAgeHours as number) > 0 ? (opts.maxAgeHours as number) : 24;
  const cutoff = new Date(Date.now() - maxAgeHours * 3600_000).toISOString();

  const docByMac = new Map<string, HostWithIps>();
  const docByAddr = new Map<string, HostWithIps[]>();
  for (const h of existing) {
    for (const ip of h.ips) {
      const list = docByAddr.get(ip.address.toLowerCase());
      if (list) list.push(h);
      else docByAddr.set(ip.address.toLowerCase(), [h]);
    }
    // Primary per-address MACs + additional known MACs (same index as the plan).
    for (const m of [...h.ips.map((i) => i.mac), ...safeParseStringArray(h.host.macs)]) {
      if (m && !docByMac.has(macKey(m))) docByMac.set(macKey(m), h);
    }
  }

  const live = mergeHostRows(hostRows).filter((h) => h.lastSeenAt >= cutoff);
  // Parse the range filter ONCE (throws 400 on a malformed entry).
  const ranges = parseRanges(opts.ranges);
  const macSyncPolicy: MacSyncPolicy = opts.macSyncPolicy ?? 'keep';
  let created = 0;
  let updated = 0;
  let skipped = 0;
  let totalMacReplaced = 0;
  let totalMacAdded = 0;
  const now = new Date().toISOString();

  // SMART MERGE — same hostname grouping as the plan, so apply and dry-run agree.
  const groups = groupLiveHostsByHostname(live);
  // Device placement — same index as the plan (see above).
  const placementIdx = await loadDevicePlacements(
    groups.flatMap((g) => g.macs),
    groups.flatMap((g) => g.addrs.filter((a) => !isNonDocumentableAddress(a)))
  );

  for (const g of groups) {
    let addrs = g.addrs.filter((a) => !isNonDocumentableAddress(a));
    if (addrs.length === 0) {
      skipped++;
      continue;
    }
    // Network/range filter FIRST — include-only / exclude runs before every other option.
    const rf = rangeFilterDecision(addrs, opts.rangeMode ?? 'keep-all', ranges);
    if (rf.skip) {
      skipped++;
      continue;
    }

    // Public-address policies per family — dual-stack friendly.
    const pol = applyPublicPolicies(addrs, opts.publicIpv4Policy ?? 'keep', opts.publicIpv6Policy ?? 'keep');
    if (pol.skipReason || pol.kept.length === 0) {
      skipped++;
      continue;
    }
    addrs = pol.kept;
    let dnsName = hostnameToDnsName(g.hostname);
    if (!dnsName) {
      if (opts.skipWithoutHostname !== false) {
        skipped++;
        continue;
      }
      // MAC as fallback DNS name — valid RFC 1123, keeps the host documentable.
      dnsName = g.mac.replace(/:/g, '');
    }

    const nets = addrs.map((a) => mostSpecificSubnet(subnets, a));
    if (opts.skipUnknownNetworks === true && !nets.some((n) => n !== null)) {
      skipped++;
      continue;
    }
    if (opts.skipWithoutVlan === true && !nets.some((n) => n !== null && n.vlanId != null)) {
      skipped++;
      continue;
    }

    // Match by ANY of the group's MACs first, then by any shared address.
    let target: HostWithIps | null = null;
    for (const m of g.macs) {
      const t = docByMac.get(macKey(m));
      if (t) {
        target = t;
        break;
      }
    }
    if (!target) {
      for (const a of addrs) {
        const cands = docByAddr.get(a.toLowerCase());
        if (cands && cands.length > 0) {
          target = cands[0];
          break;
        }
      }
    }

    // --- Merge: ADDITIVE — never drop user data -----------------------------
    const mergedIps: { address: string; mac: string | null; networkLabel: string | null; vlanId: number | null }[] = [];
    if (target) {
      for (const ip of target.ips) mergedIps.push({ address: ip.address, mac: ip.mac ?? null, networkLabel: ip.networkLabel ?? null, vlanId: ip.vlanId ?? null });
    }
    let changed = false;
    addrs.forEach((a, i2) => {
      const net = nets[i2];
      // The MAC that reported this address (multi-NIC groups carry one per NIC).
      const rowMac = g.addrMac.get(a.toLowerCase()) ?? g.mac;
      const existingAddr = mergedIps.find((x) => x.address.toLowerCase() === a.toLowerCase());
      if (!existingAddr) {
        mergedIps.push({ address: a, mac: rowMac, networkLabel: net?.cidr ?? null, vlanId: net?.vlanId ?? null });
        changed = true;
      } else {
        // Fill gaps only — user values always win.
        if (!existingAddr.mac) { existingAddr.mac = rowMac; changed = true; }
        if (!existingAddr.networkLabel && net) { existingAddr.networkLabel = net.cidr; changed = true; }
        if (existingAddr.vlanId == null && net?.vlanId != null) { existingAddr.vlanId = net.vlanId; changed = true; }
      }
    });

    // MAC sync — reconcile documented vs observed for the addresses this group reports.
    let newMacs: string[] | null = null;
    if (target && macSyncPolicy !== 'keep') {
      const existingMacs = new Set(target.ips.map((i) => i.mac).filter((m): m is string => !!m).map(macKey));
      for (const a of addrs) {
        const rowMac = g.addrMac.get(a.toLowerCase()) ?? g.mac;
        const norm = normalizeMac(rowMac);
        if (!norm) continue;
        const docRow = target.ips.find((i) => i.address.toLowerCase() === a.toLowerCase());
        if (docRow?.mac && macKey(docRow.mac) !== macKey(norm)) {
          // Documented MAC differs from what is observed for this address.
          if (macSyncPolicy === 'replace') {
            const m = mergedIps.find((x) => x.address.toLowerCase() === a.toLowerCase());
            if (m && m.mac !== norm) { m.mac = norm; changed = true; }
            totalMacReplaced++;
          } else if (!existingMacs.has(macKey(norm))) {
            // Keep the documented MAC — remember the observed one as an additional identity.
            newMacs ??= [...safeParseStringArray(target.host.macs)];
            newMacs.push(norm);
            existingMacs.add(macKey(norm));
            totalMacAdded++;
            changed = true;
          }
        }
      }
    }

    const names = target ? safeParseStringArray(target.host.dnsNames) : [];
    if (!names.includes(dnsName)) {
      names.push(dnsName);
      changed = true;
    }

    // Friendly name: keep the user's, else derive from the hostname.
    let friendlyName = target?.host.friendlyName ?? null;
    if (!friendlyName && g.hostname) {
      const base = g.hostname.trim().split('.')[0];
      if (base) {
        friendlyName = base;
        changed = true;
      }
    }

    // Device placement — a host that is ALSO known in the device inventory
    // inherits site/layer/tags from its observing device (gaps only, user
    // values always win). See applyDevicePlacement().
    const placement = placementForGroup(g, placementIdx);
    let newSiteId = target?.host.siteId ?? null;
    let newLayerId = target?.host.layerId ?? null;
    let newTags: string[] = target ? readStringArray(target.host.tags) : [];
    if (placement) {
      const applied = applyDevicePlacement(
        target ? { siteId: target.host.siteId, layerId: target.host.layerId, tags: newTags } : null,
        placement
      );
      if (applied.changed) changed = true;
      if (applied.siteId !== undefined) newSiteId = applied.siteId;
      if (applied.layerId !== undefined) newLayerId = applied.layerId;
      if (applied.tags !== undefined) newTags = applied.tags;
    }

    if (!changed) {
      skipped++;
      continue;
    }

    if (target) {
      await db.update(schema.documentedHosts)
        .set({ dnsNames: JSON.stringify(names), friendlyName, siteId: newSiteId, layerId: newLayerId, tags: JSON.stringify(newTags), macs: JSON.stringify(newMacs ?? safeParseStringArray(target.host.macs)), updatedAt: now })
        .where(eq(schema.documentedHosts.id, target.host.id));
      // Replace the address list with the MERGED one (existing rows kept + new ones added).
      await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, target.host.id));
      if (mergedIps.length > 0) {
        await db.insert(schema.documentedHostIps).values(
          mergedIps.map((ip) => ({ id: uuidv4(), hostId: target!.host.id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
        );
      }
      updated++;
    } else {
      const id = uuidv4();
      await db.insert(schema.documentedHosts).values({
        id,
        dnsNames: JSON.stringify(names),
        friendlyName,
        description: null,
        siteId: newSiteId, // inherited from a known device when available (see above)
        layerId: newLayerId,
        tags: JSON.stringify(newTags),
        macs: '[]', // fresh hosts start without additional MAC identities
        isActive: true, // imported hosts start active
        createdAt: now,
        updatedAt: now,
      });
      if (mergedIps.length > 0) {
        await db.insert(schema.documentedHostIps).values(
          mergedIps.map((ip) => ({ id: uuidv4(), hostId: id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
        );
      }
      created++;
    }
  }

  return { dryRun: false, totalLiveHosts: live.length, planned: [], created, updated, skipped, macReplaced: totalMacReplaced || undefined, macAdded: totalMacAdded || undefined };
}

// POST /documented-hosts/import-from-inventory — copy the LIVE host inventory
// into the documented hosts (additive merge; dry-run by default).
router.post('/documented-hosts/import-from-inventory', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const opts: InventoryImportOptions = {
      skipWithoutHostname: body.skipWithoutHostname !== false,
      skipUnknownNetworks: body.skipUnknownNetworks === true,
      publicIpv4Policy: parsePublicIpPolicy(body.publicIpv4Policy),
      publicIpv6Policy: parsePublicIpPolicy(body.publicIpv6Policy),
      rangeMode: body.rangeMode === 'include-only' || body.rangeMode === 'exclude' ? body.rangeMode : 'keep-all',
      ranges: Array.isArray(body.ranges) ? (body.ranges as unknown[]).filter((r): r is string => typeof r === 'string') : [],
      skipWithoutVlan: body.skipWithoutVlan === true,
      maxAgeHours: typeof body.maxAgeHours === 'number' ? body.maxAgeHours : 24,
      macSyncPolicy: body.macSyncPolicy === 'replace' || body.macSyncPolicy === 'add' ? body.macSyncPolicy : 'keep',
      dryRun: body.dryRun !== false, // preview first — explicit opt-in to write
    };

    if (opts.dryRun) {
      const result = await buildInventoryImportPlan(opts);
      res.status(200).json(result);
      return;
    }
    const result = await applyInventoryImport(opts);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// MAC sync — replace documented per-address MACs with what the live inventory
// currently observes (the single-host / bulk counterpart of the import wizard's
// macSyncPolicy='replace'). A client that re-keyed (docker container recreated,
// randomized MAC) shows up as a `macMismatch` on its row; this endpoint writes
// the observed MAC back to the documentation. Stale additional-MAC entries
// (documented_hosts.macs) that are no longer observed anywhere for the host are
// pruned at the same time — a re-keyed client that came back to its original
// MAC stops carrying the old one as an "additional identity".
// ---------------------------------------------------------------------------

/** Per-host outcome of a MAC sync. */
interface MacSyncHostDetail {
  id: string;
  /** Primary name for display (first DNS name, else first address). */
  name: string;
  /** Documented per-address MACs replaced with the currently observed ones. */
  macReplaced: number;
}

/** Replaces mismatching documented MACs on the given hosts from live observations. */
async function syncHostMacs(ids: string[]): Promise<{ updated: number; unchanged: number; missing: string[]; details: MacSyncHostDetail[] }> {
  const hostRows = await db.query.documentedHosts.findMany({ where: inArray(schema.documentedHosts.id, ids) });
  const foundIds = new Set(hostRows.map((h) => h.id));
  const missing = ids.filter((id) => !foundIds.has(id));
  if (hostRows.length === 0) return { updated: 0, unchanged: 0, missing, details: [] };

  // All documented MACs + addresses of the requested hosts — one live sweep.
  const ipRows = await db.query.documentedHostIps.findMany({ where: inArray(schema.documentedHostIps.hostId, hostRows.map((h) => h.id)) });
  const ipsByHost = new Map<string, typeof schema.documentedHostIps.$inferSelect[]>();
  for (const ip of ipRows) {
    const list = ipsByHost.get(ip.hostId);
    if (list) list.push(ip);
    else ipsByHost.set(ip.hostId, [ip]);
  }
  const macs: string[] = [];
  const addrs: string[] = [];
  for (const h of hostRows) {
    for (const m of [...(ipsByHost.get(h.id) ?? []).map((i) => i.mac), ...safeParseStringArray(h.macs)].filter((m): m is string => !!m)) macs.push(m);
    for (const a of (ipsByHost.get(h.id) ?? []).map((i) => i.address)) addrs.push(a);
  }
  const { byMac, byIp } = await loadLiveObservations(Array.from(new Set(macs)), Array.from(new Set(addrs)));

  let updated = 0;
  let unchanged = 0;
  const details: MacSyncHostDetail[] = [];
  for (const h of hostRows) {
    const ips = ipsByHost.get(h.id) ?? [];
    // Pre-mutation snapshots — change detection + targeted row rewrites.
    const originalMacs = h.macs;
    const originalIpMacById = new Map(ips.map((ip) => [ip.id, ip.mac] as const));

    // Replace documented per-address MACs that differ from the current observation.
    let macReplaced = 0;
    for (const ip of ips) {
      if (!ip.mac) continue; // nothing documented — the import wizard fills gaps, not here
      const live = byIp.get(ip.address);
      const observedMac = live ? [...live.macs][0] ?? null : null;
      if (!observedMac || macKey(observedMac) === macKey(ip.mac)) continue; // matches (or unobserved — leave alone)
      ip.mac = normalizeMac(observedMac) ?? observedMac.toLowerCase();
      macReplaced++;
    }

    // Prune additional MACs that are no longer observed anywhere for this host.
    const keptAdditional = safeParseStringArray(h.macs).filter((m) => byMac.has(macKey(m)));

    if (macReplaced === 0 && JSON.stringify(keptAdditional) === originalMacs) { unchanged++; continue; }

    await db.update(schema.documentedHosts).set({ macs: JSON.stringify(keptAdditional), updatedAt: new Date().toISOString() }).where(eq(schema.documentedHosts.id, h.id));
    for (const ip of ips) {
      if (!ip.mac || originalIpMacById.get(ip.id) === ip.mac) continue; // only rewrite rows that changed
      await db.update(schema.documentedHostIps).set({ mac: ip.mac }).where(eq(schema.documentedHostIps.id, ip.id));
    }
    updated++;
    details.push({ id: h.id, name: safeParseStringArray(h.dnsNames)[0] ?? ips[0]?.address ?? h.id, macReplaced });
  }

  return { updated, unchanged, missing, details };
}

// POST /documented-hosts/sync-macs — replace documented MACs with the currently
// observed ones for a set of hosts (single row or bulk selection). Body:
// { ids: string[] }. Hosts without any mismatch are reported as `unchanged`.
router.post('/documented-hosts/sync-macs', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    if (!Array.isArray(body.ids)) throw Object.assign(new Error('"ids" must be an array of host ids'), { status: 400 });
    const ids = (body.ids as unknown[]).filter((v): v is string => typeof v === 'string' && v.trim() !== '');
    if (ids.length === 0) throw Object.assign(new Error('"ids" must contain at least one host id'), { status: 400 });
    if (ids.length > 5000) throw Object.assign(new Error('At most 5000 hosts per call'), { status: 400 });
    res.status(200).json(await syncHostMacs(ids));
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Merging duplicate rows — one physical host with several NICs/MACs can end up
// documented as multiple rows (e.g. imported once per MAC from the live
// inventory). This endpoint merges a set of rows into ONE: addresses are
// unioned (per-address user data preserved), DNS names + friendly name merged,
// placement taken from the first row that has one, lifecycle = any active wins.
// ---------------------------------------------------------------------------

/** Merges two address lists — an address already present keeps its FIRST occurrence's data. */
function mergeAddressLists(
  a: { address: string; mac: string | null; networkLabel: string | null; vlanId: number | null }[],
  b: { address: string; mac: string | null; networkLabel: string | null; vlanId: number | null }[]
): { address: string; mac: string | null; networkLabel: string | null; vlanId: number | null }[] {
  const out = [...a];
  for (const x of b) {
    if (!out.some((y) => y.address.toLowerCase() === x.address.toLowerCase())) out.push(x);
  }
  return out;
}

/** Merges several documented hosts into one canonical shape (oldest row leads). */
function mergeHostShapes(hosts: HostWithIps[]): ValidatedHost {
  const dnsNames: string[] = [];
  for (const h of hosts) {
    for (const n of safeParseStringArray(h.host.dnsNames)) if (!dnsNames.includes(n)) dnsNames.push(n);
  }
  let friendlyName: string | null = null;
  let description: string | null = null;
  let siteId: string | null = null;
  let layerId: string | null = null;
  for (const h of hosts) {
    if (!friendlyName && h.host.friendlyName) friendlyName = h.host.friendlyName;
    if (!description && h.host.description) description = h.host.description;
    if (!siteId && h.host.siteId) siteId = h.host.siteId;
    if (!layerId && h.host.layerId) layerId = h.host.layerId;
  }
  // Tags are unioned (case-insensitive dedupe, first occurrence's casing wins).
  const tags: string[] = [];
  for (const h of hosts) {
    for (const t of readStringArray(h.host.tags)) if (!tags.some((x) => x.toLowerCase() === t.toLowerCase())) tags.push(t);
  }
  let ips: ValidatedHost['ips'] = [];
  for (const h of hosts) {
    ips = mergeAddressLists(ips, h.ips.map((i) => ({ address: i.address, mac: i.mac ?? null, networkLabel: i.networkLabel ?? null, vlanId: i.vlanId ?? null })));
  }
  // Any row still in active use keeps the merged host active.
  const isActive = hosts.some((h) => h.host.isActive !== false);
  return { dnsNames, friendlyName, description, siteId, layerId, tags, isActive, ips };
}

// POST /documented-hosts/merge — merge several documented rows into ONE. Body:
// { ids: string[] } (2..5000). The surviving row is the OLDEST by createdAt;
// all other ids are deleted after their data was merged in. Returns the merged host.
router.post('/documented-hosts/merge', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const ids = Array.from(new Set(((Array.isArray(body.ids) ? body.ids : []) as unknown[]).filter((x): x is string => typeof x === 'string' && !!x)));
    if (ids.length < 2) {
      res.status(400).json({ error: '"ids" must contain at least 2 documented host ids to merge' });
      return;
    }
    if (ids.length > 5000) {
      res.status(400).json({ error: 'At most 5000 ids per merge' });
      return;
    }

    const hosts = await Promise.all(ids.map((id) => loadOneHost(id)));
    const missing = ids.filter((_, i) => !hosts[i]);
    if (missing.length > 0) {
      res.status(400).json({ error: `Unknown documented host id(s): ${missing.join(', ')}` });
      return;
    }

    // Oldest row survives — its id + createdAt are kept.
    const ordered = hosts
      .filter((h): h is HostWithIps => !!h)
      .sort((a, b) => (a.host.createdAt < b.host.createdAt ? -1 : a.host.createdAt > b.host.createdAt ? 1 : a.host.id.localeCompare(b.host.id)));
    const [survivor, ...rest] = ordered;

    // The union of valid hosts is still a valid host — run the shared validation anyway.
    const mergedShape = mergeHostShapes(ordered);
    const validated = await validateHostInput({
      dnsNames: mergedShape.dnsNames,
      friendlyName: mergedShape.friendlyName,
      description: mergedShape.description,
      siteId: mergedShape.siteId,
      layerId: mergedShape.layerId,
      tags: mergedShape.tags,
      isActive: mergedShape.isActive,
      ips: mergedShape.ips,
    });
    if (!validated.ok) {
      res.status(400).json({ error: `Merged host is invalid: ${validated.error}` });
      return;
    }

    const now = new Date().toISOString();
    await db.update(schema.documentedHosts)
      .set({
        dnsNames: JSON.stringify(validated.value.dnsNames),
        friendlyName: validated.value.friendlyName,
        description: validated.value.description,
        siteId: validated.value.siteId,
        layerId: validated.value.layerId,
        tags: JSON.stringify(validated.value.tags),
        isActive: validated.value.isActive,
        updatedAt: now,
      })
      .where(eq(schema.documentedHosts.id, survivor.host.id));

    // Replace the address list with the union (per-address data preserved).
    await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, survivor.host.id));
    if (validated.value.ips.length > 0) {
      await db.insert(schema.documentedHostIps).values(
        validated.value.ips.map((ip) => ({ id: uuidv4(), hostId: survivor.host.id, address: ip.address, mac: ip.mac, networkLabel: ip.networkLabel, vlanId: ip.vlanId, createdAt: now }))
      );
    }

    // Delete the merged-away rows + their addresses.
    for (const h of rest) {
      await db.delete(schema.documentedHostIps).where(eq(schema.documentedHostIps.hostId, h.host.id));
      await db.delete(schema.documentedHosts).where(eq(schema.documentedHosts.id, h.host.id));
    }

    const [merged] = await buildViews([(await loadOneHost(survivor.host.id))!]);
    res.status(200).json({ merged, removed: rest.map((h) => h.host.id), count: ordered.length });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
