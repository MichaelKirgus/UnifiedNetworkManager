/**
 * Per-host connection-table walk for the cross-device "Hosts" / "Networks"
 * pages (open states now + created/destroyed churn over a window).
 *
 * RouterOS keeps its stateful-connection table at `/ip/firewall/connection` —
 * one row per tracked 5-tuple. Unlike OPNsense's query_states (a full scan of
 * ~240k rows taking ~30 s), this table is small on typical routers (thousands
 * of rows) and the REST print endpoint returns it in a single fast GET, so the
 * walk can run at a comfortable cadence. The walk runs FIRE-AND-FORGET from
 * /monitoring (never blocks or fails the poll), diffs each snapshot against the
 * previous one in memory to derive per-endpoint created/destroyed deltas, and
 * pushes only aggregated per-host rows to the API's POST /plugin/host-states
 * endpoint. Public internet destinations are filtered out — only internal hosts
 * are tracked (same contract as the OPNsense plugin).
 */

import { ipScope } from '@unm/plugin-sdk';
import type { RouterOsClient } from './routerosClient';

/** One aggregated per-endpoint row pushed to the API for a single walk. */
export interface HostStateRow {
  /** The endpoint address (src-address or dst-address) — internal only. */
  ip: string;
  /** Open connections touching this endpoint in THIS snapshot. */
  openStates: number;
  /** Connections created since the previous walk (null = no baseline). */
  created: number | null;
  /** Connections destroyed since the previous walk (null = no baseline). */
  destroyed: number | null;
}

/** A single connection's identity + endpoints, as needed for diffing. */
interface ConnectionIdentity {
  id: string;
  srcIp: string;
  dstIp: string;
}

/** One big page size — comfortably above any realistic connection-table total. */
const WALK_COUNT = 100_000;

/**
 * Hard safety cap on live session rows pushed per walk for the Firewall page's
 * "Sessions" tab (POST /plugin/firewall-sessions). The RouterOS connection
 * print returns the WHOLE table in one call, so at this cap the full picture
 * is replicated for any realistic deployment; the slice only guards against a
 * misbehaving router returning an unbounded table. The API receives the rows
 * as bounded 25k-row chunks (SESSION_PUSH_CHUNK_SIZE), never one big request.
 */
export const SESSION_REPLICATION_MAX_ROWS = 1_000_000;

/** True when an address is an internal endpoint worth tracking as a "host". */
function isInternalEndpoint(addr: string): boolean {
  if (typeof addr !== 'string') return false;
  const t = addr.trim();
  if (t === '' || t === '*') return false; // RouterOS uses '*' for wildcard/any
  return ipScope(t) === 'private';
}

/**
 * Reads one string field from a RouterOS row, tolerating the hyphenated REST
 * naming (`src-address`) and falling back to alternates. Returns '' when absent.
 */
function rosStr(row: Record<string, unknown>, keys: string[]): string {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

/** Result of one connection-table walk. */
export interface ConnectionWalkResult {
  /** Internal-endpoint identities (deduped by id) — feeds host-state aggregation. */
  identities: ConnectionIdentity[];
  /**
   * EVERY row of the table as live session rows (unfiltered — internet
   * destinations included) — pushed to POST /plugin/firewall-sessions for the
   * Firewall page's "Sessions" tab. Same single GET as the identity parse.
   */
  liveRows: LiveConnectionRow[];
}

/**
 * Walks the router's full live connection table in ONE REST GET and returns
 * both the internal-endpoint identities (for host-state aggregation) and the
 * complete unfiltered row set (for session replication). Returns NULL on any
 * failure so the caller can tell a dead endpoint apart from a genuinely EMPTY
 * table — an empty result is a real observation (e.g. right after a reboot)
 * and must still be diffed. Public internet destinations are dropped from the
 * IDENTITIES only; liveRows keeps them (a session viewer wants everything).
 */
export async function fetchConnectionIdentities(client: RouterOsClient): Promise<ConnectionWalkResult | null> {
  let raw: unknown;
  try {
    raw = await client.get(`/ip/firewall/connection/print?count=${WALK_COUNT}`);
  } catch {
    return null; // transport/auth failure — best-effort
  }
  if (!Array.isArray(raw)) return null;

  const liveRows = parseLiveConnections(raw);

  const out: ConnectionIdentity[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const r = entry as Record<string, unknown>;
    // Identity: the internal `.id` when present, else a stable composite of the
    // tracked tuple (+ direction/state fields where the version exposes them).
    let id = rosStr(r, ['.id']);
    if (id === '') {
      const parts = [
        rosStr(r, ['src-address', 'src_address']),
        rosStr(r, ['dst-address', 'dst_address']),
        rosStr(r, ['proto', 'protocol']),
        rosStr(r, ['src-port', 'src_port']),
        rosStr(r, ['dst-port', 'dst_port']),
        rosStr(r, ['connection-state', 'state']),
        rosStr(r, ['direction']),
      ];
      id = parts.join('|');
    }
    if (id === '') continue; // no stable identity — can't diff reliably
    const srcIp = rosStr(r, ['src-address', 'src_address']);
    const dstIp = rosStr(r, ['dst-address', 'dst_address']);
    if (!isInternalEndpoint(srcIp) && !isInternalEndpoint(dstIp)) continue; // internet-only connection
    out.push({ id, srcIp: isInternalEndpoint(srcIp) ? srcIp : '', dstIp: isInternalEndpoint(dstIp) ? dstIp : '' });
  }
  return { identities: out, liveRows }; // [] = genuinely empty table (a real observation)
}

/** Per-endpoint open-connection counts for one snapshot (internal endpoints only). */
export function countOpenStates(states: ConnectionIdentity[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const s of states) {
    if (s.srcIp !== '') counts.set(s.srcIp, (counts.get(s.srcIp) ?? 0) + 1);
    if (s.dstIp !== '' && s.dstIp !== s.srcIp) counts.set(s.dstIp, (counts.get(s.dstIp) ?? 0) + 1);
  }
  return counts;
}

/**
 * Diffs two consecutive snapshots into per-endpoint created/destroyed deltas.
 * A connection "created" since the last walk is one whose id was NOT in
 * `before`; a connection "destroyed" is one that WAS in `before` but is gone
 * now. Each delta is attributed to BOTH of the connection's internal endpoints.
 * Returns null deltas when there was no baseline (`before === null`) — the
 * caller must not treat those as 0.
 */
export function diffStates(
  before: Map<string, { srcIp: string; dstIp: string }> | null,
  now: ConnectionIdentity[]
): { created: Map<string, number>; destroyed: Map<string, number> } | null {
  if (before === null) return null; // first walk — no baseline to diff against

  const nowIds = new Set(now.map((s) => s.id));
  const created = new Map<string, number>();
  const destroyed = new Map<string, number>();

  for (const s of now) {
    if (!before.has(s.id)) {
      if (s.srcIp !== '') created.set(s.srcIp, (created.get(s.srcIp) ?? 0) + 1);
      if (s.dstIp !== '' && s.dstIp !== s.srcIp) created.set(s.dstIp, (created.get(s.dstIp) ?? 0) + 1);
    }
  }
  for (const [id, s] of before.entries()) {
    if (!nowIds.has(id)) {
      if (s.srcIp !== '') destroyed.set(s.srcIp, (destroyed.get(s.srcIp) ?? 0) + 1);
      if (s.dstIp !== '' && s.dstIp !== s.srcIp) destroyed.set(s.dstIp, (destroyed.get(s.dstIp) ?? 0) + 1);
    }
  }
  return { created, destroyed };
}

/** Merges open-state counts + churn deltas into the push rows for one walk. */
export function buildHostStateRows(
  open: Map<string, number>,
  diff: { created: Map<string, number>; destroyed: Map<string, number> } | null
): HostStateRow[] {
  const ips = new Set<string>([...open.keys()]);
  if (diff) {
    for (const ip of diff.created.keys()) ips.add(ip);
    for (const ip of diff.destroyed.keys()) ips.add(ip);
  }
  return Array.from(ips).map((ip) => ({
    ip,
    openStates: open.get(ip) ?? 0,
    // Baseline exists → a missing delta is a real zero. No baseline (first
    // walk / restart) → null so the API's window SUM skips it instead of
    // counting a bogus spike.
    created: diff ? (diff.created.get(ip) ?? 0) : null,
    destroyed: diff ? (diff.destroyed.get(ip) ?? 0) : null,
  }));
}

// ---------------------------------------------------------------------------
// Live connection snapshot (on-demand, single bounded page)
// ---------------------------------------------------------------------------

/** One row of the live connection table (`/ip/firewall/connection/print`). */
export interface LiveConnectionRow {
  id: string;
  srcAddress: string;
  dstAddress: string;
  srcPort: number | null;
  dstPort: number | null;
  protocol: string;
  state: string;
  direction: string;
}

/** Reads one integer field (ports arrive as strings in the REST API). */
function rosInt(row: Record<string, unknown>, keys: string[]): number | null {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
    if (typeof v === 'string') {
      const n = parseInt(v, 10);
      if (Number.isFinite(n)) return n;
    }
  }
  return null;
}

/**
 * Parses raw `/ip/firewall/connection/print` rows into LiveConnectionRow
 * values. Used both by `fetchLiveConnections` (on-demand read) and by the
 * identity walk's session collection — one parser, one row shape. NOT
 * filtered to internal endpoints: a session viewer wants everything.
 */
export function parseLiveConnections(raw: unknown[]): LiveConnectionRow[] {
  const out: LiveConnectionRow[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const r = entry as Record<string, unknown>;
    out.push({
      id: rosStr(r, ['.id', 'id']),
      srcAddress: rosStr(r, ['src-address', 'src_address']),
      dstAddress: rosStr(r, ['dst-address', 'dst_address']),
      srcPort: rosInt(r, ['src-port', 'src_port']),
      dstPort: rosInt(r, ['dst-port', 'dst_port']),
      protocol: rosStr(r, ['proto', 'protocol']).toUpperCase(),
      state: rosStr(r, ['connection-state', 'state']),
      direction: rosStr(r, ['direction']),
    });
  }
  return out; // [] = genuinely empty table (a real observation)
}

/**
 * Fetches the first `limit` rows of the live connection table — on-demand
 * snapshot for the sessions view. Unlike the polling walk this is NOT
 * filtered to internal endpoints: a session viewer wants to see everything,
 * internet destinations included. Returns null when the endpoint is
 * unavailable or answers with an unexpected shape.
 */
export async function fetchLiveConnections(
  client: RouterOsClient,
  limit: number,
): Promise<LiveConnectionRow[] | null> {
  let raw: unknown;
  try {
    raw = await client.get(`/ip/firewall/connection/print?count=${limit}`);
  } catch {
    return null; // transport/auth failure — best-effort read
  }
  if (!Array.isArray(raw)) return null;

  return parseLiveConnections(raw); // [] = genuinely empty table (a real observation)
}
