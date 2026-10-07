/**
 * Per-host firewall state-table walk for the cross-device "Hosts" / "Networks"
 * pages (open states now + created/destroyed churn over a window).
 *
 * The appliance's live pf state table is walked with ONE big query_states call.
 * Live-verified on OPNsense 26.x: every query_states request performs a FULL
 * table scan (~13–35 s) regardless of rowCount, and the `filter` param is
 * silently ignored — so there is no cheap per-host path. A single large page
 * (rowCount well above the total) returns the whole table in one scan, which is
 * far cheaper for the appliance than N pages (each page = another full scan).
 * On a 243k-state box that is ~30 s / ~115 MB; on a small box it is seconds.
 *
 * The walk runs FIRE-AND-FORGET from /monitoring (never blocks or fails the
 * poll) at its own cadence, diffs each snapshot against the previous one in
 * memory to derive per-endpoint created/destroyed deltas, and pushes only the
 * aggregated per-host rows to the API's POST /plugin/host-states endpoint. The
 * raw state table is never shipped — only a few thousand distinct internal
 * endpoint addresses (public internet destinations are filtered out).
 */

import type { AxiosInstance } from 'axios';
import { post } from './http';
import { ipScope } from '@unm/plugin-sdk';

/** One aggregated per-endpoint row pushed to the API for a single walk. */
export interface HostStateRow {
  /** The endpoint address (src_addr or dst_addr) — internal only. */
  ip: string;
  /** Open states touching this endpoint in THIS snapshot. */
  openStates: number;
  /** States created since the previous walk (null = no baseline). */
  created: number | null;
  /** States destroyed since the previous walk (null = no baseline). */
  destroyed: number | null;
}

/** A single state's identity + endpoints, as needed for diffing. */
interface StateIdentity {
  id: string;
  srcIp: string;
  dstIp: string;
}

/** The one big page size — comfortably above any realistic state-table total. */
const WALK_ROW_COUNT = 1_000_000;
/** Per-call timeout for the full walk (a busy box needs ~30 s). */
const WALK_TIMEOUT_MS = 90_000;

/** True when an address is an internal endpoint worth tracking as a "host". */
function isInternalEndpoint(addr: string): boolean {
  if (typeof addr !== 'string') return false;
  const t = addr.trim();
  if (t === '' || t === '0' || t === '::') return false; // pf uses these for wildcard/any
  return ipScope(t) === 'private';
}

/**
 * Walks the appliance's full live state table in ONE query_states call and
 * returns each state's identity + internal endpoints. Returns NULL on any
 * failure (transport error, non-2xx, malformed body) so the caller can tell a
 * dead endpoint apart from a genuinely EMPTY table — an empty result is a real
 * observation (e.g. right after a reboot: every previous state was destroyed)
 * and must still be diffed. Public internet destinations are dropped here so
 * only internal hosts reach the aggregation step.
 */
export async function fetchStateIdentities(client: AxiosInstance): Promise<StateIdentity[] | null> {
  let res;
  try {
    res = await post(
      client,
      '/api/diagnostics/firewall/query_states',
      { rowCount: WALK_ROW_COUNT, current: 1 },
      { timeoutMs: WALK_TIMEOUT_MS }
    );
  } catch {
    return null; // transport failure — best-effort
  }
  if (!res.ok || !res.data || typeof res.data !== 'object') return null;
  const rows = (res.data as Record<string, unknown>)['rows'];
  if (!Array.isArray(rows)) return null;

  const out: StateIdentity[] = [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const id = typeof r['id'] === 'string' ? r['id'].trim() : '';
    if (id === '') continue; // no stable identity — can't diff reliably
    const srcIp = typeof r['src_addr'] === 'string' ? r['src_addr'].trim() : '';
    const dstIp = typeof r['dst_addr'] === 'string' ? r['dst_addr'].trim() : '';
    if (!isInternalEndpoint(srcIp) && !isInternalEndpoint(dstIp)) continue; // internet-only state
    out.push({ id, srcIp: isInternalEndpoint(srcIp) ? srcIp : '', dstIp: isInternalEndpoint(dstIp) ? dstIp : '' });
  }
  return out; // [] = genuinely empty table (a real observation)
}

/** Per-endpoint open-state counts for one snapshot (internal endpoints only). */
export function countOpenStates(states: StateIdentity[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const s of states) {
    if (s.srcIp !== '') counts.set(s.srcIp, (counts.get(s.srcIp) ?? 0) + 1);
    if (s.dstIp !== '' && s.dstIp !== s.srcIp) counts.set(s.dstIp, (counts.get(s.dstIp) ?? 0) + 1);
  }
  return counts;
}

/**
 * Diffs two consecutive snapshots into per-endpoint created/destroyed deltas.
 * A state "created" since the last walk is one whose id was NOT in `before`; a
 * state "destroyed" is one that WAS in `before` but is gone now. Each delta is
 * attributed to BOTH of the state's internal endpoints (a new connection to an
 * internal host counts as churn for that host). Returns null deltas when there
 * was no baseline (`before === null`) — the caller must not treat those as 0.
 *
 * `before` maps state id → its endpoints (the id is only needed as the map key,
 * so callers may store a lighter value than the full StateIdentity).
 */
export function diffStates(
  before: Map<string, { srcIp: string; dstIp: string }> | null,
  now: StateIdentity[]
): { created: Map<string, number>; destroyed: Map<string, number> } | null {
  if (before === null) return null; // first walk — no baseline to diff against

  const nowIds = new Set(now.map((s) => s.id));
  const created = new Map<string, number>();
  const destroyed = new Map<string, number>();

  for (const s of now) {
    if (!before.has(s.id)) {
      // New state — attribute to its internal endpoints.
      if (s.srcIp !== '') created.set(s.srcIp, (created.get(s.srcIp) ?? 0) + 1);
      if (s.dstIp !== '' && s.dstIp !== s.srcIp) created.set(s.dstIp, (created.get(s.dstIp) ?? 0) + 1);
    }
  }
  for (const [id, s] of before.entries()) {
    if (!nowIds.has(id)) {
      // Gone state — attribute to its internal endpoints.
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
