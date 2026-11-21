/**
 * Per-host firewall state-table walk for the cross-device "Hosts" / "Networks"
 * pages (open states now + created/destroyed churn over a window).
 *
 * The appliance's live pf state table is walked in BOUNDED PAGES of query_states.
 * Live-verified on OPNsense 26.x: every query_states request performs a FULL
 * table scan (~13–35 s) regardless of rowCount, and the `filter` param is
 * silently ignored — so there is no cheap per-host path, and each page costs one
 * full scan. configd slices server-side (the stock UI paginates this same table),
 * so PHP memory per response is bounded by the PAGE SIZE: a single whole-table
 * response for ~250k+ states OOM-crashes an Apache worker at OPNsense's default
 * 1 GB memory_limit (verified live: a 284k-state box fataled in Response.php
 * json_encode with "tried to allocate ~120 MB" every walk), while one 50k page
 * peaks well under it. The price of pagination is N full scans per walk — on a
 * 284k-state box that is ~6 pages / a few minutes, so the walk cadence stays slow.
 * Because the table mutates DURING a multi-page walk, each snapshot carries a
 * consistency flag (total_entries drift between first and last page); an
 * inconsistent snapshot still updates open-state counts but its churn deltas are
 * nulled rather than pushed as noise.
 *
 * The walk runs FIRE-AND-FORGET from /monitoring (never blocks or fails the
 * poll) at its own cadence, diffs each snapshot against the previous one in
 * memory to derive per-endpoint created/destroyed deltas, and pushes only the
 * aggregated per-host rows to the API's POST /plugin/host-states endpoint. The
 * raw state table is never shipped — only a few thousand distinct internal
 * endpoint addresses (public internet destinations are filtered out).
 */

import type { AxiosInstance } from 'axios';
import { get, post } from './http';
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

/**
 * Page size for the paginated walk. Bounded on purpose: one query_states
 * response for N states needs roughly ~3–4 KB of PHP memory per row on the
 * appliance (configd JSON string + decoded array + json_encode buffer), so a
 * 50k page peaks well under OPNsense's default 1 GB memory_limit while a
 * whole-table response OOMs above ~250k states.
 */
const STATE_WALK_PAGE_SIZE = 50_000;
/** Absolute page-count backstop (→ up to 2M states) — bounds walk duration. */
const MAX_STATE_WALK_PAGES = 40;
/** Max relative drift of total_entries between first and last page before a snapshot is deemed inconsistent (the table mutated during the walk). */
const STATE_WALK_DRIFT_MAX = 0.05;
/** Per-page timeout for the full scan (a busy box needs ~30 s). */
const WALK_TIMEOUT_MS = 90_000;

/** True when an address is an internal endpoint worth tracking as a "host". */
function isInternalEndpoint(addr: string): boolean {
  if (typeof addr !== 'string') return false;
  const t = addr.trim();
  if (t === '' || t === '0' || t === '::') return false; // pf uses these for wildcard/any
  return ipScope(t) === 'private';
}

/** Parses one page's raw rows into internal-endpoint identities. */
function parseStatePageRows(rows: unknown[]): StateIdentity[] {
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
  return out;
}

/** Fetches ONE page of the state table. Returns null on any failure. */
async function fetchStatePage(
  client: AxiosInstance,
  current: number
): Promise<{ states: StateIdentity[]; rawCount: number; total: number | null } | null> {
  let res;
  try {
    res = await post(client, '/api/diagnostics/firewall/query_states', { rowCount: STATE_WALK_PAGE_SIZE, current }, { timeoutMs: WALK_TIMEOUT_MS });
  } catch {
    return null; // transport failure — best-effort
  }
  if (!res.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const rows = Array.isArray(d['rows']) ? (d['rows'] as unknown[]) : null;
  if (rows === null) return null;
  // configd's total_entries for the WHOLE table — used for drift detection.
  const t = Number(d['total']);
  return { states: parseStatePageRows(rows), rawCount: rows.length, total: Number.isFinite(t) && t >= 0 ? Math.trunc(t) : null };
}

/** Result of one paginated full-table walk. */
export interface StateWalkResult {
  /** Internal-endpoint identities across all pages (deduped by state id). */
  states: StateIdentity[];
  /** false when the table visibly changed size DURING the walk — churn deltas for this snapshot are unreliable and must be nulled. */
  consistent: boolean;
}

/**
 * Consistency check for a paginated walk (pure, unit-tested): true only when
 * BOTH page totals were reported AND their drift stayed within
 * STATE_WALK_DRIFT_MAX. Unverifiable (missing total) → false — conservative,
 * because the alternative is pushing churn deltas computed from a snapshot we
 * cannot prove complete.
 */
export function isStateWalkConsistent(totalFirst: number | null, totalLast: number | null): boolean {
  if (totalFirst === null || totalLast === null || totalFirst <= 0) return false;
  return Math.abs(totalLast - totalFirst) / totalFirst <= STATE_WALK_DRIFT_MAX;
}

/**
 * A SHORT page (fewer rows than requested) is only proof of table completeness
 * when configd's `total` agrees within the drift tolerance. If the total claims
 * more states exist than we received, unseen states would be diffed as
 * "destroyed" — a false churn spike from an incomplete snapshot. Unverifiable
 * (missing total) → not complete: conservative, matching isStateWalkConsistent.
 */
export function isShortPageComplete(rawCount: number, total: number | null): boolean {
  if (total === null) return false;
  return total <= rawCount * (1 + STATE_WALK_DRIFT_MAX);
}

/**
 * Walks the appliance's full live state table in bounded pages and returns each
 * state's identity + internal endpoints (deduped by id — a mutating table can
 * repeat or drop rows between page scans). Returns NULL on any failure so the
 * caller can tell a dead endpoint apart from a genuinely EMPTY table — an empty
 * result is a real observation (e.g. right after a reboot: every previous state
 * was destroyed) and must still be diffed. Public internet destinations are
 * dropped per page so only internal hosts reach the aggregation step.
 */
export async function walkAllStates(client: AxiosInstance): Promise<StateWalkResult | null> {
  const first = await fetchStatePage(client, 1);
  if (first === null) return null;

  // Dedupe by state id across pages (a mutating table can repeat rows).
  const byId = new Map<string, StateIdentity>();
  for (const s of first.states) byId.set(s.id, s);
  let totalLast = first.total;

  // Fast path: one page covered the whole table. A short page only proves
  // completeness when configd's total agrees (see isShortPageComplete); a full
  // page with total ≤ page size is complete by construction.
  if (first.rawCount < STATE_WALK_PAGE_SIZE) {
    return { states: [...byId.values()], consistent: isShortPageComplete(first.rawCount, first.total) };
  }
  if (totalLast !== null && totalLast <= STATE_WALK_PAGE_SIZE) {
    return { states: [...byId.values()], consistent: true };
  }

  for (let page = 2; page <= MAX_STATE_WALK_PAGES; page++) {
    const res = await fetchStatePage(client, page);
    if (res === null) return null; // mid-walk failure → discard everything (a partial snapshot is useless for diffing)
    for (const s of res.states) byId.set(s.id, s);
    if (res.total !== null) totalLast = res.total;
    if (res.rawCount < STATE_WALK_PAGE_SIZE) break; // short page = last one
  }

  return { states: [...byId.values()], consistent: isStateWalkConsistent(first.total, totalLast) };
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

/**
 * Current live state count via the cheap pf_states probe (`filter diag
 * state_size` — reads a counter, NO table scan). Returns null on any failure;
 * callers must treat that as "unknown", never "zero".
 */
export async function fetchPfStateCount(client: AxiosInstance): Promise<number | null> {
  try {
    const res = await get<{ current?: string | number }>(client, '/api/diagnostics/firewall/pf_states');
    if (!res.ok || !res.data || typeof res.data !== 'object') return null;
    const n = Number((res.data as Record<string, unknown>)['current']);
    return Number.isFinite(n) && n >= 0 ? Math.trunc(n) : null;
  } catch {
    return null; // transport failure — best-effort
  }
}

/**
 * Default upper bound for the full state-table walk (live states). The walk is
 * PAGINATED with bounded per-page PHP memory, so this cap is a LOAD control,
 * not an OOM guard: every page still costs one FULL table scan on the appliance
 * (~13–35 s), so walking a 284k-state box means ~6 scans / a few minutes each
 * cycle. The default (1M) walks any realistic table completely; lower it to cut
 * scan load on busy firewalls (the Hosts/Networks "States" columns then go stale
 * while the table is above the cap).
 */
export const DEFAULT_STATE_WALK_MAX_STATES = 1_000_000;

/**
 * Decides whether the full state-table walk should be SKIPPED because the live
 * table exceeds `maxStates` (load control — see DEFAULT_STATE_WALK_MAX_STATES).
 * total=null (count probe failed) → do NOT skip: the cheap probe failing is no
 * evidence of table size, and a paginated walk is memory-bounded anyway.
 */
export function shouldSkipStateWalk(total: number | null, maxStates: number): boolean {
  return total !== null && maxStates > 0 && total > maxStates;
}
