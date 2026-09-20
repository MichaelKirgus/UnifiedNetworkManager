import { Router, Request, Response } from 'express';
import { asc, eq, inArray, or } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { isIP } from 'node:net';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { mergeNetworkRows } from './networks';

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

export default router;
