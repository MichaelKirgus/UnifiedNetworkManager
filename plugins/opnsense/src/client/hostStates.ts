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
): Promise<{ states: StateIdentity[]; rawCount: number; total: number | null; rawRows: Record<string, unknown>[] } | null> {
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
  return {
    states: parseStatePageRows(rows),
    rawCount: rows.length,
    total: Number.isFinite(t) && t >= 0 ? Math.trunc(t) : null,
    // Raw page rows — consumed ONLY for session replication (parseSessionRows);
    // the identity parse above is unchanged.
    rawRows: rows.filter((r): r is Record<string, unknown> => !!r && typeof r === 'object'),
  };
}

/** Result of one paginated full-table walk. */
export interface StateWalkResult {
  /** Internal-endpoint identities across all pages (deduped by state id). */
  states: StateIdentity[];
  /** false when the table visibly changed size DURING the walk — churn deltas for this snapshot are unreliable and must be nulled. */
  consistent: boolean;
  /**
   * Live session rows sampled from this walk (capped, deduped by state id) —
   * pushed to POST /plugin/firewall-sessions so the Firewall page's Sessions
   * tab shows a current cross-device sample of the state table. Empty when
   * collection was disabled (maxSessions = 0).
   */
  sessions: LiveSessionRow[];
}

/** Options for {@link walkAllStates}. */
export interface StateWalkOptions {
  /**
   * Cap on live session rows collected during the walk (default
   * SESSION_REPLICATION_MAX_ROWS, 0 disables collection). At the default the
   * FULL table is replicated (the walk pages through everything anyway); only
   * a table larger than the cap is sampled — first N rows encountered while
   * paging. The API replaces the device's previous snapshot per push.
   */
  maxSessions?: number;
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
export async function walkAllStates(client: AxiosInstance, opts?: StateWalkOptions): Promise<StateWalkResult | null> {
  const maxSessions = Math.max(0, Math.trunc(opts?.maxSessions ?? SESSION_REPLICATION_MAX_ROWS));

  // Session replication piggybacks on the identity walk: each page's RAW rows
  // are parsed into LiveSessionRows and kept until the cap is reached. The cap
  // makes this a bounded SAMPLE of the table (first N rows encountered) — on a
  // 284k-state box that fills within the first few pages, so no extra scans.
  // Deduped by state id (a mutating table can repeat rows across page scans).
  const sessionById = new Map<string, LiveSessionRow>();
  const collectSessions = (rawRows: Record<string, unknown>[]): void => {
    if (maxSessions === 0 || sessionById.size >= maxSessions) return; // cap reached — skip the parse cost
    for (const row of parseSessionRows(rawRows)) {
      if (sessionById.size >= maxSessions) break;
      const key = row.id !== '' ? `id:${row.id}` : `${row.srcIp}:${row.dstIp}:${row.srcPort ?? ''}:${row.state}`;
      if (!sessionById.has(key)) sessionById.set(key, row);
    }
  };

  const first = await fetchStatePage(client, 1);
  if (first === null) return null;
  collectSessions(first.rawRows);

  // Dedupe by state id across pages (a mutating table can repeat rows).
  const byId = new Map<string, StateIdentity>();
  for (const s of first.states) byId.set(s.id, s);
  let totalLast = first.total;

  // Fast path: one page covered the whole table. A short page only proves
  // completeness when configd's total agrees (see isShortPageComplete); a full
  // page with total ≤ page size is complete by construction.
  if (first.rawCount < STATE_WALK_PAGE_SIZE) {
    return { states: [...byId.values()], consistent: isShortPageComplete(first.rawCount, first.total), sessions: [...sessionById.values()] };
  }
  if (totalLast !== null && totalLast <= STATE_WALK_PAGE_SIZE) {
    return { states: [...byId.values()], consistent: true, sessions: [...sessionById.values()] };
  }

  for (let page = 2; page <= MAX_STATE_WALK_PAGES; page++) {
    const res = await fetchStatePage(client, page);
    if (res === null) return null; // mid-walk failure → discard everything (a partial snapshot is useless for diffing)
    collectSessions(res.rawRows);
    for (const s of res.states) byId.set(s.id, s);
    if (res.total !== null) totalLast = res.total;
    if (res.rawCount < STATE_WALK_PAGE_SIZE) break; // short page = last one
  }

  return { states: [...byId.values()], consistent: isStateWalkConsistent(first.total, totalLast), sessions: [...sessionById.values()] };
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
 * Hard cap on live session rows collected per state-table walk for the
 * Firewall page's Sessions tab (POST /plugin/firewall-sessions). Set to match
 * DEFAULT_STATE_WALK_MAX_STATES — the walk is skipped above 1M states anyway,
 * so at this cap the FULL table is replicated (prod firewalls run ~400k states;
 * the API receives it as bounded 25k-row chunks, never one big request). Only
 * a table between the cap and the skip threshold would be sampled. Memory: the
 * dedup map holds at most this many rows (~200B each ≈ 200MB worst case) — the
 * same order the identity walk already carries, so no new ceiling is added.
 */
export const SESSION_REPLICATION_MAX_ROWS = 1_000_000;

/**
 * Decides whether the full state-table walk should be SKIPPED because the live
 * table exceeds `maxStates` (load control — see DEFAULT_STATE_WALK_MAX_STATES).
 * total=null (count probe failed) → do NOT skip: the cheap probe failing is no
 * evidence of table size, and a paginated walk is memory-bounded anyway.
 */
export function shouldSkipStateWalk(total: number | null, maxStates: number): boolean {
  return total !== null && maxStates > 0 && total > maxStates;
}

// ---------------------------------------------------------------------------
// Live session snapshot (on-demand, single bounded page)
// ---------------------------------------------------------------------------

/**
 * A single row from the live state table — one bounded page of
 * `/api/diagnostics/firewall/query_states` (see `fetchLiveSessions`).
 */
export interface LiveSessionRow {
  id: string;
  srcIp: string;
  dstIp: string;
  srcPort: number | null;
  dstPort: number | null;
  proto: string;
  state: string;
  /** Remaining connection timeout in seconds (null when not reported). */
  timeoutSec: number | null;
  queue: string;
  iface: string;
}

export interface LiveSessionsPage {
  rows: LiveSessionRow[];
  /** Total rows in the table (null when the appliance didn't report one). */
  total: number | null;
}

function liveStr(r: Record<string, unknown>, ...keys: string[]): string {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

function liveInt(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return Math.trunc(v);
  if (typeof v === 'string') {
    const n = parseInt(v, 10);
    if (Number.isFinite(n) && n >= 0) return n;
  }
  return null;
}

/** Accepts "297", "297s", "5m" or "1h5m" → seconds (null when unparseable). */
function liveTimeoutSec(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v) && v >= 0) return Math.trunc(v);
  if (typeof v !== 'string') return null;
  const s = v.trim().toLowerCase();
  if (s === '') return null;
  let total = 0;
  let matched = false;
  for (const m of s.matchAll(/(\d+)([smhd])?/g)) {
    const n = parseInt(m[1], 10);
    const unit = m[2] ?? 's';
    total += n * (unit === 'h' ? 3600 : unit === 'm' ? 60 : unit === 'd' ? 86_400 : 1);
    matched = true;
  }
  return matched && s.replace(/\d|[smhd]/g, '') === '' ? total : null;
}

/** Splits "10.0.0.5(54321)" → { ip: '10.0.0.5', port: 54321 }. */
function splitAddrPort(addr: string): { ip: string; port: number | null } {
  const m = addr.match(/^(.*?)\((\d+)\)$/);
  if (m) return { ip: m[1], port: liveInt(m[2]) };
  return { ip: addr, port: null };
}

/**
 * Parses raw query_states rows into LiveSessionRow values (tolerant of the
 * key spellings configd has used across versions). Used both by
 * `fetchLiveSessions` (single-page read) and by the identity walk's session
 * collection — one parser, one row shape.
 */
export function parseSessionRows(rawRows: unknown[]): LiveSessionRow[] {
  const rows: LiveSessionRow[] = [];
  for (const raw of rawRows) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const srcRaw = liveStr(r, 'src_addr', 'source', 'src');
    const dstRaw = liveStr(r, 'dst_addr', 'destination', 'dst');
    if (srcRaw === '' && dstRaw === '') continue; // no usable endpoints — not a session row
    const src = splitAddrPort(srcRaw);
    const dst = splitAddrPort(dstRaw);
    rows.push({
      id: liveStr(r, 'id'),
      srcIp: src.ip,
      dstIp: dst.ip,
      srcPort: liveInt(r['src_port'] ?? r['sport']) ?? src.port,
      dstPort: liveInt(r['dst_port'] ?? r['dport']) ?? dst.port,
      proto: liveStr(r, 'proto', 'protocol').toUpperCase(),
      state: liveStr(r, 'state'),
      timeoutSec: liveTimeoutSec(r['timeout']),
      queue: liveStr(r, 'queue'),
      iface: liveStr(r, 'interface', 'if'),
    });
  }
  return rows;
}

/**
 * Fetches exactly ONE bounded page of the live state table.
 *
 * OPNsense's `query_states` performs a full scan of the state table on EVERY
 * request — this is deliberately NOT part of the polling path and must never
 * be paged in a loop (see the note in `parseStatePageRows`). Returns null when
 * the endpoint is unavailable or answers with an unexpected shape.
 */
export async function fetchLiveSessions(
  client: AxiosInstance,
  limit: number,
): Promise<LiveSessionsPage | null> {
  let res;
  try {
    res = await post(client, '/api/diagnostics/firewall/query_states', { rowCount: limit, current: 1 }, { timeoutMs: WALK_TIMEOUT_MS });
  } catch {
    return null; // transport/auth failure — best-effort read
  }
  if (!res.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const rawRows = Array.isArray(d['rows']) ? (d['rows'] as unknown[]) : null;
  if (rawRows === null) return null;

  return { rows: parseSessionRows(rawRows), total: liveInt(d['total']) };
}
