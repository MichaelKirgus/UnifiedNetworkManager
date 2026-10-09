import { Router, Request, Response } from 'express';
import { asc, eq, inArray } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { isIP } from 'node:net';
import { ipFamily, splitCidr, subnetOf, ipv4ToInt, ipv4FromInt, ipv6ToBigInt, ipv6FromBigInt, ipInCidr, isPublicIpv4, isPublicIpv6 } from '@unm/plugin-sdk';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { mergeNetworkRows, type MergedNetwork } from './networks';
// Shared CIDR/IP-range parsing (the entries themselves are family-aware; the
// matching below is CIDR-aware — hostInRanges only understands bare IPs).
import { parseRanges, type RangeEntry } from './documentedHosts';
import { readStringArray, parseStringArrayField } from '../utils/stringArrays';

const router = Router();

/**
 * Documented networks — the USER-MAINTAINED network inventory (the "Networks
 * documentation" page). The documented-network counterpart of documented hosts:
 * permanent records of what SHOULD exist on the network (name, subnets, VLAN,
 * gateways, DNS servers, site/layer placement), while `networks` holds
 * transient interface observations collected by plugins.
 *
 * At read time every documented network is cross-referenced against the live
 * table: a matching merged logical network (by name, CIDR containment either
 * direction, or VLAN id) marks it "discovered" with its observed subnets and
 * last-seen timestamp — the foundation for future change-detection.
 */

// ---------------------------------------------------------------------------
// Value normalization + validation
// ---------------------------------------------------------------------------

/** True for a bare IPv4/IPv6 literal (no prefix). */
function isIpLiteral(value: string): boolean {
  return isIP(value.trim()) !== 0;
}

/**
 * Normalizes a CIDR block ("10.40.0.5/23" → "10.40.0.0/23", host bits cleared).
 * Returns null when the value is not a valid CIDR (bare IPs are rejected —
 * subnets must carry an explicit prefix, mirroring the live inventory's rows).
 */
function normalizeCidr(value: string): string | null {
  const s = splitCidr(value);
  if (!s) return null;
  if (!isIpLiteral(s.net)) return null;
  // Canonicalize — clear host bits so "10.40.0.5/23" and "10.40.0.0/23" dedupe.
  const canonical = subnetOf(s.net, s.prefix);
  if (!canonical) return null;
  return canonical;
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

/** Parses a VLAN id (integer ≥ 0); null when absent/empty, -1 when invalid. */
function parseVlanId(value: unknown): number | null | -1 {
  if (value === undefined || value === null) return null;
  const n = typeof value === 'number' ? value : Number(String(value).trim());
  if (!Number.isInteger(n) || n < 0 || n > 4095) return -1;
  return n;
}

/** Sorts addresses/subnets IPv4-first, then lexicographically (repo convention). */
function sortAddresses(addrs: string[]): string[] {
  return [...addrs].sort((a, b) => {
    const av = a.includes(':') ? 1 : 0;
    const bv = b.includes(':') ? 1 : 0;
    return av !== bv ? av - bv : a.localeCompare(b);
  });
}

// ---------------------------------------------------------------------------
// Live-observation lookup (discovery)
// ---------------------------------------------------------------------------

/** One merged live logical network that matches a documented network. */
interface LiveNetworkMatch {
  name: string;
  subnets: string[];
  vlanId: number | null;
  collectedAt: string;
}

/**
 * Matches the given documented networks against ALL merged live logical
 * networks (GET /networks data). A match is established when ANY of holds:
 *   - case-insensitive name equality (documented name vs group display label),
 *   - CIDR containment in EITHER direction between a documented subnet and a
 *     member subnet (a documented /16 matches the observed /24s inside it,
 *     and vice versa — subnets are canonicalized before comparison),
 *   - VLAN id equality (both sides carry one).
 * Returns per-documented-network-id the union of all matching live groups.
 */
async function loadLiveNetworkMatches(
  docs: { id: string; name: string; subnets: string[]; vlanId: number | null }[]
): Promise<Map<string, LiveNetworkMatch[]>> {
  const out = new Map<string, LiveNetworkMatch[]>();
  if (docs.length === 0) return out;

  const rows = await db.query.networks.findMany();
  const liveGroups = mergeNetworkRows(rows);
  // Canonicalize every live subnet once — containment checks need network addresses.
  const liveSubnets: { id: string; canonical: string }[] = [];
  for (const g of liveGroups) {
    for (const s of g.subnets ?? []) {
      const c = normalizeCidr(s);
      if (c) liveSubnets.push({ id: g.key, canonical: c });
    }
  }

  for (const d of docs) {
    const docSubnets = d.subnets.map((s) => normalizeCidr(s)).filter((s): s is string => !!s);
    const matches: LiveNetworkMatch[] = [];
    for (const g of liveGroups) {
      let hit = false;
      if (d.name.trim().toLowerCase() === g.name.trim().toLowerCase()) hit = true;
      if (!hit && d.vlanId != null && g.vlanId != null && d.vlanId === g.vlanId) hit = true;
      if (!hit) {
        for (const ds of docSubnets) {
          for (const ls of liveSubnets) {
            if (ls.id !== g.key) continue;
            // Containment either direction — same family only.
            if (cidrsOverlap(ds, ls.canonical)) { hit = true; break; }
          }
          if (hit) break;
        }
      }
      if (hit) matches.push({ name: g.name, subnets: [...(g.subnets ?? [])], vlanId: g.vlanId, collectedAt: g.collectedAt });
    }
    out.set(d.id, matches);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Host-address statistics (computed from the documented hosts at read time)
// ---------------------------------------------------------------------------

/** Per-subnet usable-host stats for one IPv4 CIDR; null for v6 / invalid. */
/**
 * Per-subnet host-address statistics — one entry per documented subnet, both
 * families. `total`/`free` are STRINGS because a v6 /64's 2^64 addresses
 * overflow Number.MAX_SAFE_INTEGER; v4 values fit in numbers but are stringified
 * for a uniform shape.
 */
export interface SubnetHostStats {
  cidr: string;
  family: 'v4' | 'v6';
  /** Total usable addresses in this subnet (string — see above). */
  total: string;
  /** Distinct documented host IPs inside this subnet. */
  used: number;
  /** Free = total − used, clamped at 0 (string like `total`). */
  free: string;
  /** First usable address of the subnet. */
  firstHost: string | null;
  lastHost: string | null;
  /** Broadcast address — v4 /30 and larger only (RFC 3021 /31 + /32 have none); null for v6. */
  broadcastAddress: string | null;
}

/**
 * Host-address stats for ONE documented subnet. IPv4 reserves the network +
 * broadcast addresses (the usual convention; RFC 3021 point-to-point /31 and
 * /32 reserve nothing). IPv6 has no such reservations — every address is
 * usable, so totals are exact powers of two.
 */
function subnetHostStats(cidr: string, allDocumentedIps: string[]): SubnetHostStats | null {
  const s = splitCidr(cidr);
  if (!s) return null;
  const fam = ipFamily(s.net);
  // Distinct documented IPs inside this exact subnet (family-matched).
  const usedSet = new Set<string>();
  for (const ip of allDocumentedIps) {
    if (ipFamily(ip) !== fam) continue;
    if (ipInCidr(ip, cidr)) usedSet.add(ip);
  }

  if (fam === 'v4') {
    const n = ipv4ToInt(s.net);
    if (n === null) return null;
    const size = 1 << (32 - s.prefix); // /31 → 2, /32 → 1
    let total: number;
    let firstHost: string | null;
    let lastHost: string | null;
    let broadcastAddress: string | null;
    if (s.prefix <= 30) {
      total = size - 2;
      firstHost = ipv4FromInt(n + 1);
      lastHost = ipv4FromInt(n + size - 2);
      broadcastAddress = ipv4FromInt(n + size - 1);
    } else if (s.prefix === 31) {
      total = 2;
      firstHost = ipv4FromInt(n);
      lastHost = ipv4FromInt(n + 1);
      broadcastAddress = null;
    } else { // /32
      total = 1;
      firstHost = ipv4FromInt(n);
      lastHost = ipv4FromInt(n);
      broadcastAddress = null;
    }
    return {
      cidr, family: 'v4',
      total: String(total), used: usedSet.size,
      free: String(Math.max(0, total - usedSet.size)),
      firstHost, lastHost, broadcastAddress,
    };
  }

  if (fam === 'v6') {
    const totalBig = 1n << BigInt(128 - s.prefix);
    // v6 has no reserved network address — the first usable host IS the
    // network address; there is no broadcast concept, so lastHost is the
    // final address of the block.
    const netBig = ipv6ToBigInt(s.net) ?? 0n;
    return {
      cidr, family: 'v6',
      total: totalBig.toString(), used: usedSet.size,
      free: (totalBig - BigInt(usedSet.size)).toString(),
      firstHost: ipv6FromBigInt(netBig), lastHost: ipv6FromBigInt(netBig + totalBig - 1n), broadcastAddress: null,
    };
  }

  return null; // malformed / unknown family — the row's subnets are validated anyway
}

/** Aggregated host stats for a documented network. */
interface NetworkHostStats {
  /** Sum of usable hosts over all v4 subnets; null when the row has none. */
  totalHosts: number | null;
  /** Usable v4 hosts minus distinct documented host IPs inside any v4 subnet (≥ 0); null like totalHosts. */
  freeHosts: number | null;
  /** First usable host of each v4 subnet, ", "-joined; null when none. */
  firstHost: string | null;
  lastHost: string | null;
  broadcastAddress: string | null;
  /** First address of each v6 subnet (the network address itself), ", "-joined; null when none. */
  firstHostV6: string | null;
  lastHostV6: string | null;
  /** Per-subnet breakdown (v4 + v6) — the dual-stack view with different prefixes per family. */
  subnetStats: SubnetHostStats[];
}

/**
 * Computes the network's host-address statistics from its documented subnets
 * and ALL documented host IPs (the documented-hosts page data). The aggregate
 * columns stay IPv4-only (broadcast semantics); `subnetStats` covers every
 * subnet in both families. Stale hosts still count: their addresses are
 * documented as expected to exist.
 */
function computeHostStats(subnets: string[], allDocumentedIps: string[]): NetworkHostStats {
  const perSubnet = subnets.map((s) => subnetHostStats(s, allDocumentedIps)).filter((x): x is SubnetHostStats => x !== null);

  const v4 = perSubnet.filter((s) => s.family === 'v4');
  if (v4.length === 0) return { totalHosts: null, freeHosts: null, firstHost: null, lastHost: null, broadcastAddress: null, firstHostV6: null, lastHostV6: null, subnetStats: perSubnet };

  const v4Subnets = subnets.filter((s) => !s.split('/')[0].includes(':'));
  // Distinct documented IPs that fall inside ANY of the network's v4 subnets.
  const used = new Set<string>();
  for (const ip of allDocumentedIps) {
    if (ipFamily(ip) !== 'v4') continue;
    if (v4Subnets.some((s) => ipInCidr(ip, s))) used.add(ip);
  }

  const totalHosts = v4.reduce((sum, s) => sum + Number(s.total), 0);
  // v6 aggregates — first/last address of each v6 subnet (no broadcast concept).
  const v6 = perSubnet.filter((s) => s.family === 'v6');
  return {
    totalHosts,
    freeHosts: Math.max(0, totalHosts - used.size),
    firstHost: v4.map((s) => s.firstHost).filter(Boolean).join(', ') || null,
    lastHost: v4.map((s) => s.lastHost).filter(Boolean).join(', ') || null,
    broadcastAddress: v4.map((s) => s.broadcastAddress).filter(Boolean).join(', ') || null,
    firstHostV6: v6.map((s) => s.firstHost).filter(Boolean).join(', ') || null,
    lastHostV6: v6.map((s) => s.lastHost).filter(Boolean).join(', ') || null,
    subnetStats: perSubnet,
  };
}

/** Loads every documented host IP address (the basis for the free-host counts). */
async function loadDocumentedHostIps(): Promise<string[]> {
  const rows = await db.query.documentedHostIps.findMany();
  return rows.map((r) => r.address);
}

// ---------------------------------------------------------------------------
// Response shaping
// ---------------------------------------------------------------------------

/** One documented network as presented in the API response. */
export interface DocumentedNetworkView {
  id: string;
  name: string;
  /** Canonicalized CIDR blocks, IPv4 first (may be empty for name-only rows). */
  subnets: string[];
  vlanId: number | null;
  gateways: string[];
  dnsServers: string[];
  ntpServers: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  siteName: string | null;
  layerId: string | null;
  layerName: string | null;
  tags: string[];
  /** True when a merged live logical network matches this documented one. */
  discovered: boolean;
  /** Most recent collection of any matching live group (null = never seen). */
  lastSeenAt: string | null;
  /** Subnets observed on the matching live groups (union, IPv4 first). */
  observedSubnets: string[];
  /** VLAN id observed on a matching live group (null when none known). */
  observedVlanId: number | null;
  /** Usable IPv4 host addresses over all v4 subnets; null for name-only / v6-only rows. */
  totalHosts: number | null;
  /** Usable hosts minus documented host IPs inside the network's v4 subnets (≥ 0). */
  freeHosts: number | null;
  /** First usable host of each v4 subnet, ", "-joined; null when no v4 subnet. */
  firstHost: string | null;
  lastHost: string | null;
  broadcastAddress: string | null;
  /** First address of each v6 subnet (the network address itself), ", "-joined; null when none. */
  firstHostV6: string | null;
  lastHostV6: string | null;
  /** Per-subnet used/free breakdown for EVERY documented subnet (v4 + v6). */
  subnetStats: SubnetHostStats[];
  isActive: boolean;
  createdAt: string;
  updatedAt: string;
}

/** Shapes one documented network row into the API view. */
function shapeNetwork(
  n: typeof schema.documentedNetworks.$inferSelect,
  siteNameById: Map<string, string>,
  layerNameById: Map<string, string>,
  matches: LiveNetworkMatch[] | undefined,
  allDocumentedIps: string[]
): DocumentedNetworkView {
  let lastSeenAt: string | null = null;
  const observed = new Set<string>();
  let observedVlanId: number | null = null;
  for (const m of matches ?? []) {
    if (m.collectedAt > (lastSeenAt ?? '')) lastSeenAt = m.collectedAt;
    for (const s of m.subnets) observed.add(s);
    if (observedVlanId == null && m.vlanId != null) observedVlanId = m.vlanId;
  }

  const subnets = sortAddresses(readStringArray(n.subnets));
  const hostStats = computeHostStats(subnets, allDocumentedIps);

  return {
    id: n.id,
    name: n.name,
    subnets,
    vlanId: n.vlanId ?? null,
    gateways: readStringArray(n.gateways),
    dnsServers: readStringArray(n.dnsServers),
    ntpServers: readStringArray(n.ntpServers),
    friendlyName: n.friendlyName,
    description: n.description,
    siteId: n.siteId,
    siteName: n.siteId ? (siteNameById.get(n.siteId) ?? null) : null,
    layerId: n.layerId,
    layerName: n.layerId ? (layerNameById.get(n.layerId) ?? null) : null,
    tags: readStringArray(n.tags),
    discovered: (matches?.length ?? 0) > 0,
    lastSeenAt,
    observedSubnets: sortAddresses(Array.from(observed)),
    observedVlanId,
    totalHosts: hostStats.totalHosts,
    freeHosts: hostStats.freeHosts,
    firstHost: hostStats.firstHost,
    lastHost: hostStats.lastHost,
    broadcastAddress: hostStats.broadcastAddress,
    firstHostV6: hostStats.firstHostV6,
    lastHostV6: hostStats.lastHostV6,
    subnetStats: hostStats.subnetStats,
    isActive: n.isActive !== false, // defensive — the column is NOT NULL DEFAULT TRUE
    createdAt: n.createdAt,
    updatedAt: n.updatedAt,
  };
}

/** Batch-loads site + layer display names for the given ids. */
async function loadReferenceNames(rows: typeof schema.documentedNetworks.$inferSelect[]) {
  const siteIds = Array.from(new Set(rows.map((r) => r.siteId).filter((s): s is string => !!s)));
  const layerIds = Array.from(new Set(rows.map((r) => r.layerId).filter((l): l is string => !!l)));
  const [sites, layers] = await Promise.all([
    siteIds.length > 0 ? db.query.sites.findMany({ where: inArray(schema.sites.id, siteIds) }) : [],
    layerIds.length > 0 ? db.query.networkLayers.findMany({ where: inArray(schema.networkLayers.id, layerIds) }) : [],
  ]);
  return {
    siteNameById: new Map(sites.map((s) => [s.id, s.name] as const)),
    layerNameById: new Map(layers.map((l) => [l.id, l.name] as const)),
  };
}

/** Loads documented networks (optionally filtered by site). */
async function loadNetworks(siteId?: string): Promise<typeof schema.documentedNetworks.$inferSelect[]> {
  const where = siteId ? eq(schema.documentedNetworks.siteId, siteId) : undefined;
  return db.query.documentedNetworks.findMany({
    ...(where ? { where } : {}),
    orderBy: [asc(schema.documentedNetworks.createdAt)],
  });
}

/** Full view for a set of rows — shared by the list route and single-row responses. */
async function buildViews(rows: typeof schema.documentedNetworks.$inferSelect[]): Promise<DocumentedNetworkView[]> {
  if (rows.length === 0) return [];
  const [{ siteNameById, layerNameById }, matches, allDocumentedIps] = await Promise.all([
    loadReferenceNames(rows),
    loadLiveNetworkMatches(
      rows.map((r) => ({ id: r.id, name: r.name, subnets: readStringArray(r.subnets), vlanId: r.vlanId ?? null }))
    ),
    loadDocumentedHostIps(),
  ]);
  return rows.map((r) => shapeNetwork(r, siteNameById, layerNameById, matches.get(r.id), allDocumentedIps));
}

// ---------------------------------------------------------------------------
// Input validation (shared by create / update / import)
// ---------------------------------------------------------------------------

interface NetworkInput {
  name?: unknown;
  subnets?: unknown;
  vlanId?: unknown;
  gateways?: unknown;
  dnsServers?: unknown;
  ntpServers?: unknown;
  friendlyName?: unknown;
  description?: unknown;
  siteId?: unknown;
  layerId?: unknown;
  tags?: unknown;
  isActive?: unknown;
}

interface ValidatedNetwork {
  name: string;
  subnets: string[];
  vlanId: number | null;
  gateways: string[];
  dnsServers: string[];
  ntpServers: string[];
  friendlyName: string | null;
  description: string | null;
  siteId: string | null;
  layerId: string | null;
  tags: string[];
  isActive: boolean;
}

/** Validates + normalizes one network payload. Returns the normalized shape or an error message. */
async function validateNetworkInput(body: NetworkInput): Promise<{ ok: true; value: ValidatedNetwork } | { ok: false; error: string }> {
  // Name — required, non-empty after trim (uniqueness is checked by callers).
  if (typeof body.name !== 'string' || !body.name.trim()) return { ok: false, error: '"name" must be a non-empty string' };
  const name = body.name.trim();

  // Subnets — optional array of CIDR blocks; canonicalized + deduped.
  let subnets: string[] = [];
  if (body.subnets !== undefined) {
    if (!Array.isArray(body.subnets)) return { ok: false, error: '"subnets" must be an array of CIDR strings' };
    for (const s of body.subnets as unknown[]) {
      if (typeof s !== 'string') return { ok: false, error: '"subnets" entries must be CIDR strings' };
      const norm = normalizeCidr(s);
      if (!norm) return { ok: false, error: `Invalid subnet: "${s}" — expected a CIDR block like 192.168.1.0/24 or fd00::/64` };
      if (!subnets.includes(norm)) subnets.push(norm);
    }
  }

  // VLAN id.
  const vlanId = parseVlanId(body.vlanId);
  if (vlanId === -1) return { ok: false, error: `Invalid VLAN id: "${String(body.vlanId)}" — expected an integer 0–4095` };

  // Gateways / DNS servers / NTP servers — optional arrays of bare IP literals.
  const parseIpList = (raw: unknown, field: string): { value?: string[]; error?: string } => {
    if (!Array.isArray(raw)) return { error: `"${field}" must be an array of IP address strings` };
    const out: string[] = [];
    for (const v of raw as unknown[]) {
      if (typeof v !== 'string' || !isIpLiteral(v)) return { error: `Invalid ${field} entry: "${String(v)}" — expected a bare IPv4/IPv6 address` };
      const t = v.trim();
      if (!out.includes(t)) out.push(t);
    }
    return { value: out };
  };
  const gw = parseIpList(body.gateways, 'gateways');
  if (gw.error) return { ok: false, error: gw.error };
  const dns = parseIpList(body.dnsServers, 'dnsServers');
  if (dns.error) return { ok: false, error: dns.error };
  const ntp = parseIpList(body.ntpServers, 'ntpServers');
  if (ntp.error) return { ok: false, error: ntp.error };

  // Optional text fields.
  const friendlyName = typeof body.friendlyName === 'string' && body.friendlyName.trim() ? body.friendlyName.trim() : null;
  const description = typeof body.description === 'string' && body.description.trim() ? body.description.trim() : null;

  // Lifecycle flag — only an explicit boolean changes it.
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

  return {
    ok: true,
    value: {
      name,
      subnets,
      vlanId: vlanId as number | null,
      gateways: gw.value ?? [],
      dnsServers: dns.value ?? [],
      ntpServers: ntp.value ?? [],
      friendlyName,
      description,
      siteId,
      layerId,
      tags: tags ?? [],
      isActive: isActive ?? true,
    },
  };
}

/**
 * True when two CIDR blocks overlap — for CIDRs that means one contains the
 * other (blocks are either disjoint or nested). Families must match. Both sides
 * may be non-canonical; only the network-prefix bits are compared.
 */
function cidrsOverlap(a: string, b: string): boolean {
  const sa = splitCidr(a);
  const sb = splitCidr(b);
  if (!sa || !sb) return false;
  // Families must match (v4 vs v6 never overlap).
  if (sa.net.includes(':') !== sb.net.includes(':')) return false;
  if (!sa.net.includes(':')) {
    const na = ipv4ToInt(sa.net);
    const nb = ipv4ToInt(sb.net);
    if (na === null || nb === null) return false;
    const pfx = Math.min(sa.prefix, sb.prefix);
    const mask = pfx === 0 ? 0 : (~0 << (32 - pfx)) >>> 0;
    return (na & mask) === (nb & mask);
  }
  const na = ipv6ToBigInt(sa.net);
  const nb = ipv6ToBigInt(sb.net);
  if (na === null || nb === null) return false;
  const pfx = Math.min(sa.prefix, sb.prefix);
  const mask = pfx === 0 ? 0n : ((1n << 128n) - 1n) ^ ((1n << BigInt(128 - pfx)) - 1n);
  return (na & mask) === (nb & mask);
}

/** True when two subnet lists share ANY CIDR containment in either direction. */
function subnetsOverlap(a: string[], b: string[]): boolean {
  const ca = a.map((s) => normalizeCidr(s)).filter((s): s is string => !!s);
  const cb = b.map((s) => normalizeCidr(s)).filter((s): s is string => !!s);
  for (const x of ca) {
    for (const y of cb) {
      if (cidrsOverlap(x, y)) return true;
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/** Loads one documented network; null when missing. */
async function loadOneNetwork(id: string): Promise<typeof schema.documentedNetworks.$inferSelect | null> {
  return (await db.query.documentedNetworks.findFirst({ where: eq(schema.documentedNetworks.id, id) })) ?? null;
}

// GET /documented-networks — list all documented networks with live discovery info.
// Query params: siteId (filter by placement).
router.get('/documented-networks', requireAuth, requirePermission('documented-networks:read'), async (_req: Request, res: Response) => {
  try {
    const { siteId } = _req.query as Record<string, string | undefined>;
    const rows = await loadNetworks(siteId);
    const views = await buildViews(rows);
    // Most recently updated first — the page is a working inventory.
    views.sort((a, b) => (b.updatedAt > a.updatedAt ? 1 : -1));
    res.status(200).json(views);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /documented-networks — create a documented network. Requires documented-networks:write.
router.post('/documented-networks', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as NetworkInput;
    const validated = await validateNetworkInput(body);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    // Name uniqueness (case-insensitive at the API layer; the DB index is a
    // plain unique on name as a backstop).
    const all = await loadNetworks();
    const byName = all.find((r) => r.name.toLowerCase() === validated.value.name.toLowerCase());
    if (byName) {
      res.status(409).json({ error: `A documented network with the name "${validated.value.name}" already exists` });
      return;
    }
    // A different name covering the SAME subnets is a duplicate too — reject it
    // here so the page never carries two rows for one network.
    if (validated.value.subnets.length > 0) {
      const overlap = all.find((r) => subnetsOverlap(readStringArray(r.subnets), validated.value.subnets));
      if (overlap) {
        res.status(409).json({ error: `Subnet range already covered by documented network "${overlap.name}"` });
        return;
      }
    }

    const now = new Date().toISOString();
    const id = uuidv4();
    const v = validated.value;
    await db.insert(schema.documentedNetworks).values({
      id,
      name: v.name,
      subnets: JSON.stringify(v.subnets),
      vlanId: v.vlanId,
      gateways: JSON.stringify(v.gateways),
      dnsServers: JSON.stringify(v.dnsServers),
      ntpServers: JSON.stringify(v.ntpServers),
      friendlyName: v.friendlyName,
      description: v.description,
      siteId: v.siteId,
      layerId: v.layerId,
      tags: JSON.stringify(v.tags),
      isActive: v.isActive, // new networks default to active
      createdAt: now,
      updatedAt: now,
    });

    const [created] = await buildViews([(await loadOneNetwork(id))!]);
    res.status(201).json(created);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PATCH /documented-networks/:id — update a documented network (all-or-nothing
// replace of the provided fields; `subnets`/`gateways`/`dnsServers`/
// `ntpServers` arrays are replaced wholesale when present).
router.patch('/documented-networks/:id', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const existing = await loadOneNetwork(String(req.params.id ?? ''));
    if (!existing) {
      res.status(404).json({ error: 'Documented network not found' });
      return;
    }

    const body = (req.body ?? {}) as NetworkInput;
    // Merge the patch over the current values so partial updates work, then run
    // the SAME validation as create (the merged result must be a complete row).
    const current: NetworkInput = {
      name: existing.name,
      subnets: readStringArray(existing.subnets),
      vlanId: existing.vlanId ?? null,
      gateways: readStringArray(existing.gateways),
      dnsServers: readStringArray(existing.dnsServers),
      ntpServers: readStringArray(existing.ntpServers),
      friendlyName: existing.friendlyName,
      description: existing.description,
      siteId: existing.siteId,
      layerId: existing.layerId,
      tags: readStringArray(existing.tags),
      isActive: existing.isActive !== false, // defensive — the column is NOT NULL DEFAULT TRUE
    };
    const merged: NetworkInput = { ...current };
    for (const key of ['name', 'subnets', 'vlanId', 'gateways', 'dnsServers', 'ntpServers', 'friendlyName', 'description', 'siteId', 'layerId', 'tags', 'isActive'] as const) {
      if (body[key] !== undefined) (merged as Record<string, unknown>)[key] = body[key];
    }

    const validated = await validateNetworkInput(merged);
    if (!validated.ok) {
      res.status(400).json({ error: validated.error });
      return;
    }

    // Name uniqueness against OTHER rows (case-insensitive + subnet overlap).
    const others = await loadNetworks();
    const clash = others.find((r) => r.id !== existing.id && (r.name.toLowerCase() === validated.value.name.toLowerCase() || subnetsOverlap(readStringArray(r.subnets), validated.value.subnets)));
    if (clash) {
      res.status(409).json({ error: `Name or subnet range already used by documented network "${clash.name}"` });
      return;
    }

    const v = validated.value;
    await db.update(schema.documentedNetworks)
      .set({
        name: v.name,
        subnets: JSON.stringify(v.subnets),
        vlanId: v.vlanId,
        gateways: JSON.stringify(v.gateways),
        dnsServers: JSON.stringify(v.dnsServers),
        ntpServers: JSON.stringify(v.ntpServers),
        friendlyName: v.friendlyName,
        description: v.description,
        siteId: v.siteId,
        layerId: v.layerId,
        tags: JSON.stringify(v.tags),
        isActive: v.isActive, // merged value — keeps the current flag when not provided
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.documentedNetworks.id, existing.id));

    const [updated] = await buildViews([(await loadOneNetwork(existing.id))!]);
    res.status(200).json(updated);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /documented-networks/:id — remove a documented network.
router.delete('/documented-networks/:id', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const existing = await loadOneNetwork(String(req.params.id ?? ''));
    if (!existing) {
      res.status(404).json({ error: 'Documented network not found' });
      return;
    }
    await db.delete(schema.documentedNetworks).where(eq(schema.documentedNetworks.id, existing.id));
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /documented-networks/bulk — batch updates. Body:
// { ids: string[], isActive?: boolean, siteId?: string|null, layerId?: string|null }
// Marks every existing id active/stale and/or sets its site/layer placement in
// one call (the webapp bulk actions send the current selection). Unknown ids
// are reported, never fatal; at most 5000 ids per call. Omitted fields = no-op.
router.post('/documented-networks/bulk', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const ids = Array.isArray(body.ids) ? (body.ids as unknown[]).filter((x): x is string => typeof x === 'string' && !!x) : [];
    if (ids.length === 0) {
      res.status(400).json({ error: '"ids" must be a non-empty array of documented network ids' });
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

    const existing = await db.query.documentedNetworks.findMany({ where: inArray(schema.documentedNetworks.id, Array.from(new Set(ids))) });
    const foundIds = new Set(existing.map((n) => n.id));
    const missing = ids.filter((id) => !foundIds.has(id));

    if ((hasFlag || siteId !== undefined || layerId !== undefined) && existing.length > 0) {
      const set: Record<string, unknown> = { updatedAt: new Date().toISOString() };
      if (hasFlag) set.isActive = body.isActive as boolean;
      if (siteId !== undefined) set.siteId = siteId;
      if (layerId !== undefined) set.layerId = layerId;
      await db.update(schema.documentedNetworks).set(set).where(inArray(schema.documentedNetworks.id, Array.from(foundIds)));
    }

    res.status(200).json({ updated: hasFlag || siteId !== undefined || layerId !== undefined ? existing.length : 0, missing });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// CSV import (flexible header mapping — the webapp maps columns client-side and
// sends already-structured rows; this endpoint only validates + upserts)
// ---------------------------------------------------------------------------

/** Matches an import row against existing networks. */
function findExistingNetwork(
  rows: typeof schema.documentedNetworks.$inferSelect[],
  byName: Map<string, string>, // lowercased name -> id
  row: NetworkInput
): { id: string; how: 'name' | 'subnet' } | null {
  if (typeof row.name === 'string') {
    const n = row.name.trim().toLowerCase();
    if (n && byName.has(n)) return { id: byName.get(n)!, how: 'name' };
  }
  // Subnet overlap fallback — a different name covering the same range is the
  // same network.
  const subnets = Array.isArray(row.subnets) ? row.subnets : [];
  for (const r of rows) {
    if (subnetsOverlap(readStringArray(r.subnets), subnets as string[])) return { id: r.id, how: 'subnet' };
  }
  return null;
}

// POST /documented-networks/import — bulk-create/update documented networks.
// Body: { networks: [...], matchBy?: 'name'|'subnet', updateExisting?: boolean }.
// Rows are validated independently — one bad row never aborts the batch.
router.post('/documented-networks/import', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const rows = Array.isArray(body.networks) ? body.networks : null;
    if (!rows || rows.length === 0) {
      res.status(400).json({ error: '"networks" must be a non-empty array' });
      return;
    }
    if (rows.length > 5000) {
      res.status(400).json({ error: 'At most 5000 networks per import batch' });
      return;
    }
    const matchBy: 'name' | 'subnet' = body.matchBy === 'subnet' ? 'subnet' : 'name';
    const updateExisting = body.updateExisting !== false;

    // Index existing networks for matching.
    const existingRows = await loadNetworks();
    const byName = new Map<string, string>();
    for (const r of existingRows) byName.set(r.name.toLowerCase(), r.id);

    let created = 0;
    let updated = 0;
    let skipped = 0;
    const errors: { index: number; error: string }[] = [];
    const now = new Date().toISOString();

    for (let i = 0; i < rows.length; i++) {
      const row = (rows[i] ?? {}) as NetworkInput;
      const validated = await validateNetworkInput(row);
      if (!validated.ok) {
        errors.push({ index: i, error: validated.error });
        continue;
      }
      const v = validated.value;

      let existingId: string | null = null;
      if (matchBy === 'name') {
        existingId = byName.get(v.name.toLowerCase()) ?? null;
        // Name miss — fall back to subnet overlap so a renamed network still merges.
        if (!existingId) existingId = findExistingNetwork(existingRows, byName, row)?.id ?? null;
      } else {
        existingId = findExistingNetwork(existingRows, byName, row)?.id ?? null;
      }

      if (existingId && !updateExisting) {
        skipped++;
        continue;
      }

      if (existingId) {
        // Update in place — keep the original id + createdAt. isActive is NOT
        // touched by a CSV import (the lifecycle flag is user-managed); tags are
        // merged additively so an import never drops existing labels.
        const existing = existingRows.find((r) => r.id === existingId)!;
        const mergedTags = mergeTagLists(readStringArray(existing.tags), v.tags);
        await db.update(schema.documentedNetworks)
          .set({
            name: v.name,
            subnets: JSON.stringify(v.subnets),
            vlanId: v.vlanId,
            gateways: JSON.stringify(v.gateways),
            dnsServers: JSON.stringify(v.dnsServers),
            ntpServers: JSON.stringify(v.ntpServers),
            friendlyName: v.friendlyName,
            description: v.description,
            siteId: v.siteId,
            layerId: v.layerId,
            tags: JSON.stringify(mergedTags),
            updatedAt: now,
          })
          .where(eq(schema.documentedNetworks.id, existingId));
        updated++;
      } else {
        const id = uuidv4();
        await db.insert(schema.documentedNetworks).values({
          id,
          name: v.name,
          subnets: JSON.stringify(v.subnets),
          vlanId: v.vlanId,
          gateways: JSON.stringify(v.gateways),
          dnsServers: JSON.stringify(v.dnsServers),
          ntpServers: JSON.stringify(v.ntpServers),
          friendlyName: v.friendlyName,
          description: v.description,
          siteId: v.siteId,
          layerId: v.layerId,
          tags: JSON.stringify(v.tags),
          isActive: true, // imported networks start active
          createdAt: now,
          updatedAt: now,
        });
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
// Import from live inventory — copies the observed logical networks (GET
// /networks data) into the documented-networks table. The merge is ADDITIVE and
// never loses user data: existing name, subnets, gateways, DNS/NTP servers,
// description, site/layer placement are preserved; new subnets/VLAN ids from
// the observation are added (matched networks by name or subnet overlap).
// ---------------------------------------------------------------------------

/** Options for the inventory import. */
interface NetworkInventoryImportOptions {
  /** Skip live logical networks without any real subnet (pure SSID/VLAN groups). Default true. */
  skipWithoutSubnet?: boolean;
  /** Skip live logical networks with no discovered VLAN id. Default false. */
  skipWithoutVlan?: boolean;
  /** Only import networks carrying this address family ('all' = both). Default 'all'. */
  version?: 'all' | 'v4' | 'v6';
  /** Range filter mode: 'include-only' imports only matching networks, 'exclude' skips them. Default 'keep-all'. */
  rangeMode?: 'keep-all' | 'include-only' | 'exclude';
  /** CIDR networks / IP ranges the range filter applies to (empty = no filtering). */
  ranges?: string[];
  /** Policy for publicly routable IPv4 subnets (RFC 1918 + loopback/link-local count as internal). Default 'keep'. */
  publicIpv4Policy?: PublicIpPolicy;
  /** Policy for publicly routable IPv6 subnets (GUA 2000::/3; ULA fc00::/7 counts as internal). Default 'keep'. */
  publicIpv6Policy?: PublicIpPolicy;
  /** Only import networks observed within this many hours (0 = all, default 24 — the sweep window). */
  maxAgeHours?: number;
  /** Preview only — compute what would change without writing anything. Default true. */
  dryRun?: boolean;
}

/** One planned change for a single live logical network. */
interface NetworkInventoryImportPlanEntry {
  name: string;
  subnets: string[];
  vlanId: number | null;
  /** 'create' = new documented network, 'update' = merge into an existing one, 'skip' = unchanged/filtered out. */
  action: 'create' | 'update' | 'skip';
  reason?: string;
  /** Public subnets removed by a 'strip' policy (action=create/update only). */
  stripped?: number;
}

/** Result of the inventory import (dry-run or applied). */
interface NetworkInventoryImportResult {
  dryRun: boolean;
  totalLiveNetworks: number;
  planned: NetworkInventoryImportPlanEntry[];
  created: number;
  updated: number;
  skipped: number;
  /** Ids of the documented rows this run created or updated (empty on a pure dry-run). */
  affectedIds: string[];
}

/** True when the live group carries at least one subnet of the requested family. */
function hasVersion(g: MergedNetwork, version: 'all' | 'v4' | 'v6'): boolean {
  if (version === 'all') return true;
  // Classify on the NETWORK ADDRESS — ipFamily() rejects CIDR strings outright.
  return (g.subnets ?? []).some((s) => ipFamily(s.split('/')[0]) === version);
}

/** Numeric address-space bounds [lo, hi] of a CIDR block; null when malformed. */
function subnetBounds(cidr: string): { lo: bigint; hi: bigint } | null {
  const sc = splitCidr(cidr);
  if (!sc) return null;
  if (!sc.net.includes(':')) {
    const n = ipv4ToInt(sc.net);
    if (n === null) return null;
    const lo = BigInt(n);
    return { lo, hi: lo + (1n << BigInt(32 - sc.prefix)) - 1n };
  }
  const n = ipv6ToBigInt(sc.net);
  if (n === null) return null;
  const lo = n;
  return { lo, hi: lo + ((1n << BigInt(128 - sc.prefix)) - 1n) };
}

/** True when any of the network's subnets intersects ANY parsed range entry. */
function subnetIntersectsRanges(subnets: string[], ranges: RangeEntry[]): boolean {
  for (const s of subnets) {
    const b = subnetBounds(s);
    if (!b) continue;
    const fam = ipFamily(s.split('/')[0]);
    if (!fam) continue;
    for (const r of ranges) {
      if (r.family !== fam) continue;
      // CIDR blocks are nested or disjoint — interval intersection is exact.
      if (r.kind === 'cidr') {
        const rb = subnetBounds(r.cidr!);
        if (!rb) continue;
        if (b.lo <= rb.hi && rb.lo <= b.hi) return true;
      } else if (b.lo <= r.hi! && r.lo! <= b.hi) {
        return true;
      }
    }
  }
  return false;
}

/**
 * Applies the network/range filter to a live network's subnets. Same modes and
 * reasons as the hosts import, but CIDR-aware (hostInRanges only matches bare IPs).
 */
function subnetRangeFilterDecision(
  subnets: string[],
  mode: 'keep-all' | 'include-only' | 'exclude',
  ranges: RangeEntry[]
): { skip?: boolean; reason?: string } {
  if (mode === 'keep-all' || ranges.length === 0) return {};
  const matches = subnetIntersectsRanges(subnets, ranges);
  if (mode === 'include-only' && !matches) return { skip: true, reason: 'outside selected ranges' };
  if (mode === 'exclude' && matches) return { skip: true, reason: 'excluded range' };
  return {};
}

/**
 * Policy for publicly routable subnets of one address family — same basis as the
 * documented-hosts import, adapted to network-level rows:
 * - 'keep'        : import every subnet as-is (default).
 * - 'strip'       : drop ONLY the public subnets, still document the network with its
 *                   internal ones (private v4 / ULA stay) — dual-stack friendly.
 * - 'skip-network': any public subnet of this family → skip the whole network.
 */
type PublicIpPolicy = 'keep' | 'strip' | 'skip-network';

/** Coerces a request value into a PublicIpPolicy ('keep' when absent/unknown). */
function parsePublicIpPolicy(value: unknown): PublicIpPolicy {
  if (value === 'strip' || value === 'skip-network') return value;
  return 'keep';
}

/**
 * Applies the per-family public-subnet policies to a live network's subnets.
 * Returns the subnets to keep, how many were stripped, and a skip reason when a
 * 'skip-network' policy matched (or kept is empty after stripping).
 */
/** True when a CIDR block's NETWORK ADDRESS is publicly routable (family-aware). */
function isPublicSubnet(cidr: string): boolean {
  // The SDK classifiers take BARE IP literals — "a.b.c.d/p" would parse as null.
  const net = cidr.split('/')[0];
  if (!net) return false;
  return ipFamily(net) === 'v4' ? isPublicIpv4(net) : isPublicIpv6(net);
}

function applyPublicSubnetPolicies(
  subnets: string[],
  v4Policy: PublicIpPolicy,
  v6Policy: PublicIpPolicy
): { kept: string[]; stripped: number; skipReason?: string } {
  // Family is read from the NETWORK ADDRESS — ipFamily() rejects CIDR strings.
  const famOf = (s: string) => ipFamily(s.split('/')[0]);
  if (v4Policy === 'skip-network' && subnets.some((s) => famOf(s) === 'v4' && isPublicSubnet(s))) {
    return { kept: [], stripped: 0, skipReason: 'public IPv4 subnet' };
  }
  if (v6Policy === 'skip-network' && subnets.some((s) => famOf(s) === 'v6' && isPublicSubnet(s))) {
    return { kept: [], stripped: 0, skipReason: 'public IPv6 subnet' };
  }
  const stripV4 = v4Policy === 'strip';
  const stripV6 = v6Policy === 'strip';
  if (!stripV4 && !stripV6) return { kept: subnets, stripped: 0 };
  let stripped = 0;
  const kept = subnets.filter((s) => {
    const fam = famOf(s);
    if (fam === 'v4' && stripV4 && isPublicSubnet(s)) { stripped++; return false; }
    if (fam === 'v6' && stripV6 && isPublicSubnet(s)) { stripped++; return false; }
    return true;
  });
  return { kept, stripped };
}

/**
 * Display name for an imported network — the live group's label, RE-DERIVED
 * from the kept subnets when that label was itself stripped away. A dual-stack
 * LAN is labeled by its most specific subnet (mergeNetworkRows); if the strip
 * policy removed exactly that CIDR (e.g. a public v6 /64), naming the row after
 * it would document a network under an address we deliberately excluded.
 * Falls back to "VLAN <id>", then the original label.
 */
function deriveImportName(g: MergedNetwork, keptSubnets: string[]): string {
  if (keptSubnets.includes(g.name)) return g.name;
  // Most specific KEPT subnet — mirrors mergeNetworkRows' canonical identity.
  // It is a kept subnet by definition (the user chose "keep" for its family),
  // so it is always a valid name even when publicly routable.
  const best = [...keptSubnets].sort((a, b) => Number(b.split('/')[1]) - Number(a.split('/')[1]))[0];
  if (best) return best;
  if (g.vlanId != null) return `VLAN ${g.vlanId}`;
  return g.name; // nothing better — keep the original label rather than an empty name
}

/**
 * Builds the import plan from the live inventory + current documented networks.
 * Pure function of its inputs — shared by dry-run and apply so both agree.
 */
async function buildNetworkInventoryImportPlan(opts: NetworkInventoryImportOptions): Promise<NetworkInventoryImportResult> {
  const [networkRows, existing] = await Promise.all([db.query.networks.findMany(), loadNetworks()]);

  // Merged logical networks — the same groups GET /networks presents.
  const liveGroups = mergeNetworkRows(networkRows);
  const maxAgeHours = Number.isFinite(opts.maxAgeHours as number) && (opts.maxAgeHours as number) > 0 ? (opts.maxAgeHours as number) : 24;
  const cutoff = new Date(Date.now() - maxAgeHours * 3600_000).toISOString();
  const live = liveGroups.filter((g) => g.collectedAt >= cutoff);

  // Parse the range filter ONCE (throws 400 on a malformed entry).
  const ranges = parseRanges(opts.ranges);

  // Index existing documented networks by name + subnets.
  const docByName = new Map<string, typeof schema.documentedNetworks.$inferSelect>();
  for (const r of existing) docByName.set(r.name.toLowerCase(), r);

  const planned: NetworkInventoryImportPlanEntry[] = [];
  let created = 0;
  let updated = 0;
  let skipped = 0;

  for (const g of live) {
    let subnets = [...(g.subnets ?? [])];
    if (opts.skipWithoutSubnet !== false && subnets.length === 0) {
      planned.push({ name: g.name, subnets: [], vlanId: g.vlanId, action: 'skip', reason: 'no subnet' });
      skipped++;
      continue;
    }
    if (opts.skipWithoutVlan === true && g.vlanId == null) {
      planned.push({ name: g.name, subnets, vlanId: null, action: 'skip', reason: 'no VLAN discovered' });
      skipped++;
      continue;
    }
    const version = opts.version === 'v4' || opts.version === 'v6' ? opts.version : 'all';
    if (!hasVersion(g, version)) {
      planned.push({ name: g.name, subnets, vlanId: g.vlanId, action: 'skip', reason: `no ${version} subnet` });
      skipped++;
      continue;
    }
    // Network/range filter — include-only / exclude runs before every other option.
    const rf = subnetRangeFilterDecision(subnets, opts.rangeMode ?? 'keep-all', ranges);
    if (rf.skip) {
      planned.push({ name: g.name, subnets, vlanId: g.vlanId, action: 'skip', reason: rf.reason });
      skipped++;
      continue;
    }

    // Public-subnet policies per family — dual-stack friendly (strip keeps the
    // network with its internal subnets; skip-network drops it entirely).
    const pol = applyPublicSubnetPolicies(subnets, opts.publicIpv4Policy ?? 'keep', opts.publicIpv6Policy ?? 'keep');
    if (pol.skipReason) {
      planned.push({ name: g.name, subnets, vlanId: g.vlanId, action: 'skip', reason: pol.skipReason });
      skipped++;
      continue;
    }
    const stripped = pol.stripped;
    subnets = pol.kept;
    if (subnets.length === 0) {
      planned.push({ name: g.name, subnets: [], vlanId: g.vlanId, action: 'skip', reason: 'only public subnets' });
      skipped++;
      continue;
    }

    // The label may have been stripped away — re-derive it from the kept set.
    const importName = deriveImportName(g, subnets);

    // Match an existing documented network — by name (original OR derived) first,
    // then subnet overlap.
    const target = docByName.get(g.name.toLowerCase()) ?? docByName.get(importName.toLowerCase()) ?? existing.find((r) => subnetsOverlap(readStringArray(r.subnets), subnets)) ?? null;

    // Would the merge actually change anything?
    let wouldChange = false;
    if (!target) {
      wouldChange = true;
    } else {
      const existingSubnets = new Set(readStringArray(target.subnets).map((s) => normalizeCidr(s)).filter(Boolean));
      for (const s of subnets) {
        const c = normalizeCidr(s);
        if (c && !existingSubnets.has(c)) wouldChange = true;
      }
      // A missing VLAN id on the documented row also counts.
      if (target.vlanId == null && g.vlanId != null) wouldChange = true;
    }

    if (!wouldChange) {
      planned.push({ name: importName, subnets, vlanId: g.vlanId, action: 'skip', reason: 'already fully documented' });
      skipped++;
      continue;
    }

    if (target) updated++;
    else created++;
    planned.push({ name: importName, subnets, vlanId: g.vlanId, action: target ? 'update' : 'create', ...(stripped > 0 ? { stripped } : {}) });
  }

  return { dryRun: true, totalLiveNetworks: live.length, planned, created, updated, skipped, affectedIds: [] };
}

/** Applies the plan — writes only what buildNetworkInventoryImportPlan() computed. */
async function applyNetworkInventoryImport(opts: NetworkInventoryImportOptions): Promise<NetworkInventoryImportResult> {
  const [networkRows, existing] = await Promise.all([db.query.networks.findMany(), loadNetworks()]);

  const liveGroups = mergeNetworkRows(networkRows);
  const maxAgeHours = Number.isFinite(opts.maxAgeHours as number) && (opts.maxAgeHours as number) > 0 ? (opts.maxAgeHours as number) : 24;
  const cutoff = new Date(Date.now() - maxAgeHours * 3600_000).toISOString();
  const live = liveGroups.filter((g) => g.collectedAt >= cutoff);

  // Parse the range filter ONCE (throws 400 on a malformed entry).
  const ranges = parseRanges(opts.ranges);

  const docByName = new Map<string, typeof schema.documentedNetworks.$inferSelect>();
  for (const r of existing) docByName.set(r.name.toLowerCase(), r);

  let created = 0;
  let updated = 0;
  let skipped = 0;
  const affectedIds: string[] = [];
  const now = new Date().toISOString();

  for (const g of live) {
    let subnets = [...(g.subnets ?? [])];
    if (opts.skipWithoutSubnet !== false && subnets.length === 0) { skipped++; continue; }
    if (opts.skipWithoutVlan === true && g.vlanId == null) { skipped++; continue; }
    const version = opts.version === 'v4' || opts.version === 'v6' ? opts.version : 'all';
    if (!hasVersion(g, version)) { skipped++; continue; }
    const rf = subnetRangeFilterDecision(subnets, opts.rangeMode ?? 'keep-all', ranges);
    if (rf.skip) { skipped++; continue; }

    // Public-subnet policies per family — dual-stack friendly.
    const pol = applyPublicSubnetPolicies(subnets, opts.publicIpv4Policy ?? 'keep', opts.publicIpv6Policy ?? 'keep');
    if (pol.skipReason || pol.kept.length === 0) { skipped++; continue; }
    subnets = pol.kept;

    // The label may have been stripped away — re-derive it from the kept set.
    const importName = deriveImportName(g, subnets);

    // Match by name (original OR derived) first, then subnet overlap.
    let target = docByName.get(g.name.toLowerCase()) ?? docByName.get(importName.toLowerCase()) ?? null;
    if (!target) target = existing.find((r) => subnetsOverlap(readStringArray(r.subnets), subnets)) ?? null;

    // --- Merge: ADDITIVE — never drop user data -----------------------------
    const mergedSubnets = [...(target ? readStringArray(target.subnets) : [])];
    let changed = false;
    for (const s of subnets) {
      const c = normalizeCidr(s);
      if (!c) continue;
      const known = new Set(mergedSubnets.map((x) => normalizeCidr(x)).filter(Boolean));
      if (!known.has(c)) { mergedSubnets.push(c); changed = true; }
    }
    let vlanId = target?.vlanId ?? null;
    if (vlanId == null && g.vlanId != null) { vlanId = g.vlanId; changed = true; }

    // Friendly name: keep the user's, else derive from a subnet-based label.
    let friendlyName = target?.friendlyName ?? null;
    if (!friendlyName && subnets.length > 0) {
      const base = subnets[0].split('/')[0];
      if (base) { friendlyName = base; changed = true; }
    }

    if (!changed) { skipped++; continue; }

    if (target) {
      await db.update(schema.documentedNetworks)
        .set({ subnets: JSON.stringify(mergedSubnets), vlanId, friendlyName, updatedAt: now })
        .where(eq(schema.documentedNetworks.id, target.id));
      affectedIds.push(target.id);
      updated++;
    } else {
      const id = uuidv4();
      await db.insert(schema.documentedNetworks).values({
        id,
        name: importName,
        subnets: JSON.stringify(mergedSubnets),
        vlanId,
        gateways: '[]',
        dnsServers: '[]',
        ntpServers: '[]',
        friendlyName,
        description: null,
        siteId: null, // placement is user-managed — the live inventory has none
        layerId: null,
        tags: '[]',
        isActive: true, // imported networks start active
        createdAt: now,
        updatedAt: now,
      });
      affectedIds.push(id);
      created++;
    }
  }

  return { dryRun: false, totalLiveNetworks: live.length, planned: [], created, updated, skipped, affectedIds };
}

// POST /documented-networks/import-from-inventory — copy the LIVE network
// inventory into the documented networks (additive merge; dry-run by default).
router.post('/documented-networks/import-from-inventory', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const opts: NetworkInventoryImportOptions = {
      skipWithoutSubnet: body.skipWithoutSubnet !== false,
      skipWithoutVlan: body.skipWithoutVlan === true,
      version: body.version === 'v4' || body.version === 'v6' ? body.version : 'all',
      publicIpv4Policy: parsePublicIpPolicy(body.publicIpv4Policy),
      publicIpv6Policy: parsePublicIpPolicy(body.publicIpv6Policy),
      rangeMode: body.rangeMode === 'include-only' || body.rangeMode === 'exclude' ? body.rangeMode : 'keep-all',
      ranges: Array.isArray(body.ranges) ? (body.ranges as unknown[]).filter((r): r is string => typeof r === 'string') : [],
      maxAgeHours: typeof body.maxAgeHours === 'number' ? body.maxAgeHours : 24,
      dryRun: body.dryRun !== false, // preview first — explicit opt-in to write
    };

    if (opts.dryRun) {
      const result = await buildNetworkInventoryImportPlan(opts);
      res.status(200).json(result);
      return;
    }
    const result = await applyNetworkInventoryImport(opts);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Merging duplicate rows — one physical network can end up documented as
// multiple rows (e.g. imported once per subnet with different names, or a
// renamed network re-imported). This endpoint merges a set of rows into ONE:
// subnets/gateways/DNS servers are unioned, name/friendly name/description/
// placement taken from the first row that has one, lifecycle = any active wins.
// ---------------------------------------------------------------------------

/** Merges several documented networks into one canonical shape (oldest row leads). */
function mergeNetworkShapes(rows: typeof schema.documentedNetworks.$inferSelect[]): ValidatedNetwork {
  const ordered = [...rows].sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.id.localeCompare(b.id)));
  const first = ordered[0];

  // Subnets / gateways / DNS servers / NTP servers — unioned + deduped.
  const subnets: string[] = [];
  for (const r of ordered) {
    for (const s of readStringArray(r.subnets)) {
      const c = normalizeCidr(s);
      if (c && !subnets.includes(c)) subnets.push(c);
    }
  }
  const gateways: string[] = [];
  for (const r of ordered) for (const g of readStringArray(r.gateways)) if (!gateways.includes(g)) gateways.push(g);
  const dnsServers: string[] = [];
  for (const r of ordered) for (const d of readStringArray(r.dnsServers)) if (!dnsServers.includes(d)) dnsServers.push(d);
  const ntpServers: string[] = [];
  for (const r of ordered) for (const t of readStringArray(r.ntpServers)) if (!ntpServers.includes(t)) ntpServers.push(t);

  // First non-null wins — the oldest row leads.
  let vlanId: number | null = null;
  let friendlyName: string | null = null;
  let description: string | null = null;
  let siteId: string | null = null;
  let layerId: string | null = null;
  for (const r of ordered) {
    if (vlanId == null && r.vlanId != null) vlanId = r.vlanId;
    if (!friendlyName && r.friendlyName) friendlyName = r.friendlyName;
    if (!description && r.description) description = r.description;
    if (!siteId && r.siteId) siteId = r.siteId;
    if (!layerId && r.layerId) layerId = r.layerId;
  }

  // Tags are unioned (case-insensitive dedupe, first occurrence's casing wins).
  const tags: string[] = [];
  for (const r of ordered) {
    for (const t of readStringArray(r.tags)) if (!tags.some((x) => x.toLowerCase() === t.toLowerCase())) tags.push(t);
  }

  // Any row still in active use keeps the merged network active.
  const isActive = rows.some((r) => r.isActive !== false);

  return { name: first.name, subnets, vlanId, gateways, dnsServers, ntpServers, friendlyName, description, siteId, layerId, tags, isActive };
}

// POST /documented-networks/merge — merge several documented rows into ONE. Body:
// { ids: string[] } (2..5000). The surviving row is the OLDEST by createdAt;
// all other ids are deleted after their data was merged in. Returns the merged network.
router.post('/documented-networks/merge', requireAuth, requirePermission('documented-networks:write'), async (req: Request, res: Response) => {
  try {
    const body = req.body ?? {};
    const ids = Array.from(new Set(((Array.isArray(body.ids) ? body.ids : []) as unknown[]).filter((x): x is string => typeof x === 'string' && !!x)));
    if (ids.length < 2) {
      res.status(400).json({ error: '"ids" must contain at least 2 documented network ids to merge' });
      return;
    }
    if (ids.length > 5000) {
      res.status(400).json({ error: 'At most 5000 ids per merge' });
      return;
    }

    const rows = await db.query.documentedNetworks.findMany({ where: inArray(schema.documentedNetworks.id, ids) });
    const foundIds = new Set(rows.map((r) => r.id));
    const missing = ids.filter((id) => !foundIds.has(id));
    if (missing.length > 0) {
      res.status(400).json({ error: `Unknown documented network id(s): ${missing.join(', ')}` });
      return;
    }

    // Oldest row survives — its id + createdAt are kept.
    const ordered = [...rows].sort((a, b) => (a.createdAt < b.createdAt ? -1 : a.createdAt > b.createdAt ? 1 : a.id.localeCompare(b.id)));
    const [survivor, ...rest] = ordered;

    // The union of valid rows is still a valid row — run the shared validation anyway.
    const mergedShape = mergeNetworkShapes(ordered);
    const validated = await validateNetworkInput({
      name: mergedShape.name,
      subnets: mergedShape.subnets,
      vlanId: mergedShape.vlanId,
      gateways: mergedShape.gateways,
      dnsServers: mergedShape.dnsServers,
      ntpServers: mergedShape.ntpServers,
      friendlyName: mergedShape.friendlyName,
      description: mergedShape.description,
      siteId: mergedShape.siteId,
      layerId: mergedShape.layerId,
      tags: mergedShape.tags,
      isActive: mergedShape.isActive,
    });
    if (!validated.ok) {
      res.status(400).json({ error: `Merged network is invalid: ${validated.error}` });
      return;
    }

    await db.update(schema.documentedNetworks)
      .set({
        name: validated.value.name,
        subnets: JSON.stringify(validated.value.subnets),
        vlanId: validated.value.vlanId,
        gateways: JSON.stringify(validated.value.gateways),
        dnsServers: JSON.stringify(validated.value.dnsServers),
        ntpServers: JSON.stringify(validated.value.ntpServers),
        friendlyName: validated.value.friendlyName,
        description: validated.value.description,
        siteId: validated.value.siteId,
        layerId: validated.value.layerId,
        tags: JSON.stringify(validated.value.tags),
        isActive: validated.value.isActive,
        updatedAt: new Date().toISOString(),
      })
      .where(eq(schema.documentedNetworks.id, survivor.id));

    // Delete the merged-away rows.
    for (const r of rest) {
      await db.delete(schema.documentedNetworks).where(eq(schema.documentedNetworks.id, r.id));
    }

    const [merged] = await buildViews([(await loadOneNetwork(survivor.id))!]);
    res.status(200).json({ merged, removed: rest.map((r) => r.id), count: ordered.length });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
