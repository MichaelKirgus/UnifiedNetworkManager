import { Router, Request, Response } from 'express';
import { asc, eq, inArray, or } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { isIP } from 'node:net';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { mergeHostRows, mergeNetworkRows } from './networks';

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
  ips: DocumentedHostIpView[];
  /** True when any documented MAC or IP was observed in the live inventory. */
  discovered: boolean;
  /** Most recent observation matching this host (null = never seen). */
  lastSeenAt: string | null;
  /** Hostname reported by the best-matching live row (DHCP preferred). */
  observedHostname: string | null;
  /** Any documented MAC differs from what is currently observed for its address. */
  macMismatch: boolean;
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
    ips,
    discovered,
    lastSeenAt,
    observedHostname: bestName,
    macMismatch,
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
  const macs = Array.from(
    new Set(hosts.flatMap((h) => h.ips.map((i) => i.mac).filter((m): m is string => !!m)))
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
  ips?: unknown;
}

interface ValidatedHost {
  dnsNames: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  layerId: string | null;
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

  return { ok: true, value: { dnsNames, friendlyName, description, siteId, layerId, ips } };
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
    const existing = await loadOneHost(req.params.id);
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
      ips: existing.ips.map((i) => ({ address: i.address, mac: i.mac ?? null, networkLabel: i.networkLabel, vlanId: i.vlanId ?? null })),
    };
    const merged: HostInput = { ...current };
    for (const key of ['dnsNames', 'friendlyName', 'description', 'siteId', 'layerId', 'ips'] as const) {
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
    const existing = await loadOneHost(req.params.id);
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
        // Update in place — keep the original id + createdAt.
        await db.update(schema.documentedHosts)
          .set({
            dnsNames: JSON.stringify(v.dnsNames),
            friendlyName: v.friendlyName,
            description: v.description,
            siteId: v.siteId,
            layerId: v.layerId,
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

// ---------------------------------------------------------------------------
// Import from live inventory — copies the observed hosts (GET /hosts data)
// into the documented-hosts table. The merge is ADDITIVE and never loses user
// data: existing DNS names, friendly name, description, site/layer placement
// are preserved; new addresses/MACs/network references from the observation
// are added to the host's address list (matched hosts by MAC or observed IP).
// ---------------------------------------------------------------------------

/** Options for the inventory import. */
interface InventoryImportOptions {
  /** Skip live hosts without a usable hostname (no DNS name can be derived). Default true. */
  skipWithoutHostname?: boolean;
  /** Skip live hosts whose addresses match no known logical network. Default false. */
  skipUnknownNetworks?: boolean;
  /** Skip live hosts that carry a publicly routable IPv4 address (RFC 1918 + loopback/link-local count as internal). Default false. */
  skipPublicIpv4?: boolean;
  /** Skip live hosts that carry a publicly routable IPv6 address (ULA fc00::/7, loopback and link-local count as internal). Default false. */
  skipPublicIpv6?: boolean;
  /** Skip live hosts whose addresses resolve to no known logical network with a discovered VLAN id. Default false. */
  skipWithoutVlan?: boolean;
  /** Only import hosts observed within this many hours (0 = all, default 24 — the sweep window). */
  maxAgeHours?: number;
  /** Preview only — compute what would change without writing anything. Default true. */
  dryRun?: boolean;
}

/** One planned change for a single live host. */
interface InventoryImportPlanEntry {
  mac: string;
  hostname: string | null;
  ips: number;
  /** 'create' = new documented host, 'update' = merge into an existing one, 'skip' = unchanged/filtered out. */
  action: 'create' | 'update' | 'skip';
  reason?: string;
}

/** Result of the inventory import (dry-run or applied). */
interface InventoryImportResult {
  dryRun: boolean;
  totalLiveHosts: number;
  planned: InventoryImportPlanEntry[];
  created: number;
  updated: number;
  skipped: number;
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

/** True for a publicly routable IPv4 address (RFC 1918 private ranges count as internal). */
function isPublicIpv4(addr: string): boolean {
  const parts = addr.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return false;
  const [a, b] = parts;
  // RFC 1918 private ranges.
  if (a === 10) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  // Loopback + link-local are already filtered as non-documentable, but be safe.
  if (a === 127 || a === 169) return false;
  return true;
}

/** First hextet of an IPv6 literal without full expansion; null when not parseable. */
function ipv6FirstHextet(addr: string): number | null {
  const bare = addr.split('%')[0]; // strip zone id defensively
  if (!bare.includes(':')) return null;
  if (bare.startsWith('::')) return 0; // leading :: means the first group is zero
  const v = parseInt(bare.split(':')[0], 16);
  return Number.isNaN(v) ? null : v;
}

/** True for a publicly routable IPv6 address (ULA fc00::/7, loopback and link-local count as internal). */
function isPublicIpv6(addr: string): boolean {
  if (!addr.includes(':')) return false;
  const bare = addr.split('%')[0].toLowerCase();
  if (bare === '::1' || bare === '::') return false; // loopback / unspecified
  const first = ipv6FirstHextet(bare);
  if (first == null) return false;
  if ((first & 0xfe) === 0xfc) return false; // fc00::/7 — unique local addresses
  if ((first & 0xffc) === 0xfe80) return false; // fe80::/10 — link-local (already filtered)
  return true;
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

  /** Most specific known subnet containing the address (+ its VLAN); null when unknown. */
  const netFor = (addr: string): { cidr: string; vlanId: number | null } | null => {
    let best: { cidr: string; vlanId: number | null } | null = null;
    let bestPrefix = -1;
    for (const s of subnets) {
      const i = s.cidr.indexOf('/');
      if (i < 0) continue;
      const prefix = Number(s.cidr.slice(i + 1));
      // Family must match the address.
      if (s.cidr.includes(':') !== addr.includes(':')) continue;
      try {
        const netPart = s.cidr.slice(0, i);
        const mask = prefix === 0 ? 0n : (~0n << BigInt(128 - prefix)) & ((1n << 128n) - 1n);
        // Compare via node:net-free BigInt expansion for v6; simple octet math for v4.
        if (!addr.includes(':')) {
          const a = addr.split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
          const n = netPart.split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
          const m4 = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
          if ((a & m4) !== (n & m4)) continue;
        } else {
          // v6: expand both to BigInt and mask.
          const expand = (v: string): bigint => {
            let s = v.replace(/%[a-zA-Z0-9._-]+$/, '');
            if (!s.includes('::')) s += '::';
            const [l, r] = s.split('::');
            const lg = l === '' ? [] : l.split(':').map((x) => parseInt(x, 16));
            const rg = r === '' ? [] : r.split(':').map((x) => parseInt(x, 16));
            const mid = Array(8 - lg.length - rg.length).fill(0);
            return [...lg, ...mid, ...rg].reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
          };
          if ((expand(addr) & mask) !== (expand(netPart) & mask)) continue;
        }
      } catch {
        continue; // malformed subnet — ignore
      }
      if (prefix > bestPrefix) {
        best = s;
        bestPrefix = prefix;
      }
    }
    return best;
  };

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
    for (const ip of h.ips) {
      if (ip.mac && !docByMac.has(macKey(ip.mac))) docByMac.set(macKey(ip.mac), h);
    }
  }

  const live = mergeHostRows(hostRows).filter((h) => h.lastSeenAt >= cutoff);
  const planned: InventoryImportPlanEntry[] = [];
  let created = 0;
  let updated = 0;
  let skipped = 0;

  for (const h of live) {
    // Documentable addresses only.
    const addrs = h.ips.filter((a) => !isNonDocumentableAddress(a));
    if (addrs.length === 0) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: 0, action: 'skip', reason: 'no documentable address' });
      skipped++;
      continue;
    }

    // Publicly routable addresses — opt-out for big fleets that only want internal hosts.
    if (opts.skipPublicIpv4 === true && addrs.some((a) => !a.includes(':') && isPublicIpv4(a))) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: addrs.length, action: 'skip', reason: 'public IPv4 address' });
      skipped++;
      continue;
    }
    if (opts.skipPublicIpv6 === true && addrs.some((a) => a.includes(':') && isPublicIpv6(a))) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: addrs.length, action: 'skip', reason: 'public IPv6 address' });
      skipped++;
      continue;
    }

    let dnsName = hostnameToDnsName(h.hostname);
    if (!dnsName) {
      if (opts.skipWithoutHostname !== false) {
        planned.push({ mac: h.mac, hostname: null, ips: addrs.length, action: 'skip', reason: 'no hostname' });
        skipped++;
        continue;
      }
      // No usable hostname — fall back to the MAC as the DNS name (still valid RFC 1123).
      dnsName = h.mac.replace(/:/g, '');
    }

    const nets = addrs.map((a) => netFor(a));
    if (opts.skipUnknownNetworks === true && !nets.some((n) => n !== null)) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: addrs.length, action: 'skip', reason: 'no known network' });
      skipped++;
      continue;
    }
    if (opts.skipWithoutVlan === true && !nets.some((n) => n !== null && n.vlanId != null)) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: addrs.length, action: 'skip', reason: 'no VLAN discovered' });
      skipped++;
      continue;
    }

    // Match an existing documented host — by MAC first (the stable identity),
    // then by any shared address.
    let target = docByMac.get(macKey(h.mac)) ?? null;
    if (!target) {
      for (const a of addrs) {
        const cands = docByAddr.get(a.toLowerCase());
        if (cands && cands.length > 0) {
          target = cands[0];
          break;
        }
      }
    }

    // Would the merge actually change anything?
    let wouldChange = false;
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
    }

    if (!wouldChange) {
      planned.push({ mac: h.mac, hostname: h.hostname, ips: addrs.length, action: 'skip', reason: 'already fully documented' });
      skipped++;
      continue;
    }

    if (target) updated++;
    else created++;
    planned.push({ mac: h.mac, hostname: h.hostname ?? dnsName, ips: addrs.length, action: target ? 'update' : 'create' });
  }

  return { dryRun: true, totalLiveHosts: live.length, planned, created, updated, skipped };
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
  const netFor = (addr: string): { cidr: string; vlanId: number | null } | null => {
    let best: { cidr: string; vlanId: number | null } | null = null;
    let bestPrefix = -1;
    for (const s of subnets) {
      const i = s.cidr.indexOf('/');
      if (i < 0) continue;
      const prefix = Number(s.cidr.slice(i + 1));
      if (s.cidr.includes(':') !== addr.includes(':')) continue;
      try {
        const netPart = s.cidr.slice(0, i);
        if (!addr.includes(':')) {
          const a = addr.split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
          const n = netPart.split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
          const m4 = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
          if ((a & m4) !== (n & m4)) continue;
        } else {
          const mask = prefix === 0 ? 0n : (~0n << BigInt(128 - prefix)) & ((1n << 128n) - 1n);
          const expand = (v: string): bigint => {
            let s = v.replace(/%[a-zA-Z0-9._-]+$/, '');
            if (!s.includes('::')) s += '::';
            const [l, r] = s.split('::');
            const lg = l === '' ? [] : l.split(':').map((x) => parseInt(x, 16));
            const rg = r === '' ? [] : r.split(':').map((x) => parseInt(x, 16));
            const mid = Array(8 - lg.length - rg.length).fill(0);
            return [...lg, ...mid, ...rg].reduce((acc, g) => (acc << 16n) | BigInt(g), 0n);
          };
          if ((expand(addr) & mask) !== (expand(netPart) & mask)) continue;
        }
      } catch {
        continue;
      }
      if (prefix > bestPrefix) {
        best = s;
        bestPrefix = prefix;
      }
    }
    return best;
  };

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
    for (const ip of h.ips) {
      if (ip.mac && !docByMac.has(macKey(ip.mac))) docByMac.set(macKey(ip.mac), h);
    }
  }

  const live = mergeHostRows(hostRows).filter((h) => h.lastSeenAt >= cutoff);
  let created = 0;
  let updated = 0;
  let skipped = 0;
  const now = new Date().toISOString();

  for (const h of live) {
    const addrs = h.ips.filter((a) => !isNonDocumentableAddress(a));
    if (addrs.length === 0) {
      skipped++;
      continue;
    }
    // Publicly routable addresses — opt-out for big fleets that only want internal hosts.
    if (opts.skipPublicIpv4 === true && addrs.some((a) => !a.includes(':') && isPublicIpv4(a))) {
      skipped++;
      continue;
    }
    if (opts.skipPublicIpv6 === true && addrs.some((a) => a.includes(':') && isPublicIpv6(a))) {
      skipped++;
      continue;
    }
    let dnsName = hostnameToDnsName(h.hostname);
    if (!dnsName) {
      if (opts.skipWithoutHostname !== false) {
        skipped++;
        continue;
      }
      // MAC as fallback DNS name — valid RFC 1123, keeps the host documentable.
      dnsName = h.mac.replace(/:/g, '');
    }

    const nets = addrs.map((a) => netFor(a));
    if (opts.skipUnknownNetworks === true && !nets.some((n) => n !== null)) {
      skipped++;
      continue;
    }
    if (opts.skipWithoutVlan === true && !nets.some((n) => n !== null && n.vlanId != null)) {
      skipped++;
      continue;
    }

    let target = docByMac.get(macKey(h.mac)) ?? null;
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
      const existingAddr = mergedIps.find((x) => x.address.toLowerCase() === a.toLowerCase());
      if (!existingAddr) {
        mergedIps.push({ address: a, mac: h.mac, networkLabel: net?.cidr ?? null, vlanId: net?.vlanId ?? null });
        changed = true;
      } else {
        // Fill gaps only — user values always win.
        if (!existingAddr.mac) { existingAddr.mac = h.mac; changed = true; }
        if (!existingAddr.networkLabel && net) { existingAddr.networkLabel = net.cidr; changed = true; }
        if (existingAddr.vlanId == null && net?.vlanId != null) { existingAddr.vlanId = net.vlanId; changed = true; }
      }
    });

    const names = target ? safeParseStringArray(target.host.dnsNames) : [];
    if (!names.includes(dnsName)) {
      names.push(dnsName);
      changed = true;
    }

    // Friendly name: keep the user's, else derive from the hostname.
    let friendlyName = target?.host.friendlyName ?? null;
    if (!friendlyName && h.hostname) {
      const base = h.hostname.trim().split('.')[0];
      if (base) {
        friendlyName = base;
        changed = true;
      }
    }

    if (!changed) {
      skipped++;
      continue;
    }

    if (target) {
      await db.update(schema.documentedHosts)
        .set({ dnsNames: JSON.stringify(names), friendlyName, updatedAt: now })
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
        siteId: null,
        layerId: null,
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

  return { dryRun: false, totalLiveHosts: live.length, planned: [], created, updated, skipped };
}

// POST /documented-hosts/import-from-inventory — copy the LIVE host inventory
// into the documented hosts (additive merge; dry-run by default).
router.post('/documented-hosts/import-from-inventory', requireAuth, requirePermission('documented-hosts:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const opts: InventoryImportOptions = {
      skipWithoutHostname: body.skipWithoutHostname !== false,
      skipUnknownNetworks: body.skipUnknownNetworks === true,
      skipPublicIpv4: body.skipPublicIpv4 === true,
      skipPublicIpv6: body.skipPublicIpv6 === true,
      skipWithoutVlan: body.skipWithoutVlan === true,
      maxAgeHours: typeof body.maxAgeHours === 'number' ? body.maxAgeHours : 24,
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

export default router;
