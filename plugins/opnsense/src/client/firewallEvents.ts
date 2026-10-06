/**
 * Firewall event-log + state-table collection for the cross-device
 * "Firewall Events" page and the per-device Sessions section.
 *
 * Endpoints (live-verified on OPNsense 26.4.x — the legacy flat API surface
 * was removed in 26.x, everything lives under /api/diagnostics/firewall/):
 *
 *   GET  /api/diagnostics/firewall/log?limit=N[&digest=D]
 *     Bare JSON array (no wrapper), newest-first, up to `limit` rows. Each row
 *     carries a unique per-row `__digest__`; passing `digest=D` returns the
 *     rows at-or-newer-than D (inclusive) — that is the incremental cursor:
 *     store the newest-seen digest, re-fetch with it next beat, dedupe by id.
 *   POST /api/diagnostics/firewall/query_states  {rowCount, current, sort?}
 *     `{rows, rowCount, total}` — busy appliances hold >200k states, so we
 *     NEVER page through them: one small sample (sorted by age desc) is all
 *     the aggregate metrics need.
 *   GET  /api/diagnostics/firewall/pf_states
 *     `{current, limit}` as strings — state count + capacity.
 *   GET  /api/diagnostics/firewall/pf_statistics/timeouts
 *     Live effective pf timeout values incl. `adaptive.start`/`adaptive.end`
 *     ("0 states" = adaptive timeouts disabled). Better than reading the raw
 *     config: this is what pf actually runs with, including defaults.
 *   GET  /api/diagnostics/firewall/pf_statistics/info
 *     State-table counters + per-second rates (session churn) and limit
 *     counters — small set of plot-friendly scalars.
 */

import type { AxiosInstance } from 'axios';
import { get, post } from './http';

/** One normalized firewall event row as pushed to the API's `firewall_events` table. */
export interface FirewallEventRow {
  /** The appliance's per-row `__digest__` — stable + unique (dedupe key). */
  vendorEventId: string;
  /** Appliance-local timestamp, verbatim ("YYYY-MM-DDTHH:MM:SS", no TZ). */
  ts: string;
  /** pass | block | rdr | nat | binat. */
  action: string;
  reason: string | null;
  interfaceName: string;
  srcIp: string;
  dstIp: string;
  proto: string | null;
  srcPort: number | null;
  dstPort: number | null;
  /** Rule uuid (`rid`); "0" on the appliance means no rule → null. */
  ruleId: string | null;
  /** The rule's description text (the `label` field). */
  ruleName: string | null;
}

/** Aggregate state-table summary for one poll beat. */
export interface StateSummary {
  totalSessions: number;
  stateLimit: number | null;
  /** Oldest session lifetime in seconds (null when no sample rows came back). */
  oldestAgeSec: number | null;
}

/** Live effective pf timeout values, keys camelCased (`tcp.first` → `tcpFirst`). */
export type StateTimeouts = Record<string, string>;

/** A few plot-friendly scalars from pf_statistics/info. */
export interface PfStats {
  stateTableSearchesRate: number | null;
  stateTableInsertsRate: number | null;
  stateTableRemovalsRate: number | null;
  stateMismatchTotal: number | null;
  synfloodsDetectedTotal: number | null;
}

/** Raw row shape of the log endpoint (only the fields we consume are typed). */
interface RawEventRow {
  __digest__?: string;
  __timestamp__?: string;
  action?: string;
  reason?: string;
  interface?: string;
  src?: string;
  dst?: string;
  protoname?: string;
  srcport?: string | number;
  dstport?: string | number;
  rid?: string;
  label?: string;
}

function numOrNull(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === 'string') {
    const n = Number(v);
    if (v.trim() !== '' && Number.isFinite(n)) return Math.trunc(n);
  }
  return null;
}

/** Parses an OPNsense "HH:MM:SS" duration (hours may exceed 24) into seconds. */
export function parseHhMmSs(v: unknown): number | null {
  if (typeof v !== 'string') return null;
  const parts = v.trim().split(':').map((p) => Number(p));
  if (parts.length !== 3 || parts.some((n) => !Number.isFinite(n))) return null;
  return ((parts[0] * 60 + parts[1]) * 60 + parts[2]);
}

/**
 * Fetches firewall events newer than (and including) the given digest cursor.
 * Returns [] on any failure — a dead endpoint must never break the poll, and
 * an empty result simply means "no new events this beat".
 */
export async function fetchFirewallEvents(
  client: AxiosInstance,
  opts: { digest?: string | null; limit?: number } = {}
): Promise<FirewallEventRow[]> {
  const query: Record<string, unknown> = { limit: opts.limit ?? 2000 };
  if (opts.digest) query['digest'] = opts.digest;
  let res;
  try {
    res = await get(client, '/api/diagnostics/firewall/log', query);
  } catch {
    return []; // transport failure — best-effort
  }
  if (!res.ok || !Array.isArray(res.data)) return [];
  const out: FirewallEventRow[] = [];
  for (const raw of res.data as RawEventRow[]) {
    if (!raw || typeof raw !== 'object') continue;
    const vendorEventId = typeof raw.__digest__ === 'string' ? raw.__digest__.trim() : '';
    const ts = typeof raw.__timestamp__ === 'string' ? raw.__timestamp__.trim() : '';
    if (!vendorEventId || !ts) continue; // unusable row — skip, don't fail the batch
    const action = typeof raw.action === 'string' && raw.action.trim() !== '' ? raw.action.trim().toLowerCase() : 'unknown';
    const rid = typeof raw.rid === 'string' ? raw.rid.trim() : '';
    out.push({
      vendorEventId,
      ts,
      action,
      reason: typeof raw.reason === 'string' && raw.reason.trim() !== '' ? raw.reason.trim() : null,
      interfaceName: typeof raw.interface === 'string' ? raw.interface.trim() : '',
      srcIp: typeof raw.src === 'string' ? raw.src.trim() : '',
      dstIp: typeof raw.dst === 'string' ? raw.dst.trim() : '',
      proto: typeof raw.protoname === 'string' && raw.protoname.trim() !== '' ? raw.protoname.trim().toLowerCase() : null,
      srcPort: numOrNull(raw.srcport),
      dstPort: numOrNull(raw.dstport),
      ruleId: rid !== '' && rid !== '0' ? rid : null,
      ruleName: typeof raw.label === 'string' && raw.label.trim() !== '' ? raw.label.trim() : null,
    });
  }
  return out;
}

/**
 * Aggregate state-table summary for one beat: total + capacity from pf_states
 * (two cheap GETs' worth of data in one call) plus the OLDEST session age from
 * a tiny sample sorted by age desc. Never pages through the full table — on a
 * busy firewall that is >200k rows and pointless for an aggregate metric.
 */
export async function fetchStateSummary(client: AxiosInstance): Promise<StateSummary | null> {
  let total = -1;
  let limit: number | null = null;
  try {
    const res = await get(client, '/api/diagnostics/firewall/pf_states');
    if (res.ok && res.data && typeof res.data === 'object') {
      const d = res.data as Record<string, unknown>;
      total = numOrNull(d['current']) ?? -1;
      limit = numOrNull(d['limit']);
    }
  } catch {
    /* best-effort */
  }

  let oldestAgeSec: number | null = null;
  try {
    const res = await post(client, '/api/diagnostics/firewall/query_states', { rowCount: 5, current: 1, sort: { age: 'desc' } });
    if (res.ok && res.data && typeof res.data === 'object') {
      const d = res.data as Record<string, unknown>;
      const rows = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
      for (const row of rows) {
        const age = parseHhMmSs(row?.['age']);
        if (age !== null && (oldestAgeSec === null || age > oldestAgeSec)) oldestAgeSec = age;
      }
    }
  } catch {
    /* best-effort */
  }

  if (total < 0) return null; // neither call worked — omit the metrics entirely
  return { totalSessions: total, stateLimit: limit, oldestAgeSec };
}

/** camelCase for a dotted pf key: `tcp.first` → `tcpFirst`, `adaptive.start` → `adaptiveStart`. */
function camelKey(dotted: string): string {
  const parts = dotted.split('.');
  return parts[0] + parts.slice(1).map((p) => p.charAt(0).toUpperCase() + p.slice(1)).join('');
}

/**
 * Live effective pf timeout values (inventory cadence — quasi-static). Returns
 * null when the endpoint is unavailable so the caller omits the keys entirely
 * (absent = no wipe on the API side).
 */
export async function fetchStateTimeouts(client: AxiosInstance): Promise<StateTimeouts | null> {
  try {
    const res = await get(client, '/api/diagnostics/firewall/pf_statistics/timeouts');
    if (!res.ok || !res.data || typeof res.data !== 'object') return null;
    const timeouts = (res.data as Record<string, unknown>)['timeouts'];
    if (!timeouts || typeof timeouts !== 'object') return null;
    const out: StateTimeouts = {};
    for (const [k, v] of Object.entries(timeouts as Record<string, unknown>)) {
      if (typeof v === 'string' && v.trim() !== '') out[camelKey(k)] = v.trim();
    }
    return Object.keys(out).length > 0 ? out : null;
  } catch {
    return null; // best-effort
  }
}

/** A few plot-friendly scalars from pf_statistics/info (inventory cadence). */
export async function fetchPfStats(client: AxiosInstance): Promise<PfStats | null> {
  try {
    const res = await get(client, '/api/diagnostics/firewall/pf_statistics/info');
    if (!res.ok || !res.data || typeof res.data !== 'object') return null;
    const infoRaw = (res.data as Record<string, unknown>)['info'];
    if (!infoRaw || typeof infoRaw !== 'object') return null;
    const info = infoRaw as Record<string, unknown>;

    const numAt = (obj: unknown, ...path: string[]): number | null => {
      let cur: unknown = obj;
      for (const p of path) {
        if (!cur || typeof cur !== 'object') return null;
        cur = (cur as Record<string, unknown>)[p];
      }
      return numOrNull(cur);
    };

    const table = info['state-table'];
    const counters = info['counters'];
    const limitCounters = info['limit-counters'];

    const out: PfStats = {
      stateTableSearchesRate: numAt(table, 'searches', 'rate'),
      stateTableInsertsRate: numAt(table, 'inserts', 'rate'),
      stateTableRemovalsRate: numAt(table, 'removals', 'rate'),
      stateMismatchTotal: numAt(counters, 'state-mismatch', 'total'),
      synfloodsDetectedTotal: numAt(limitCounters, 'synfloods-detected', 'total'),
    };
    return out;
  } catch {
    return null; // best-effort
  }
}
