/**
 * Reverse-DNS backfill worker (leader-gated, key 9024).
 *
 * The 5-min rollup (workers/flows.ts) already PTR-enriches NEW tuples as they
 * land — this worker covers what the rollup cannot:
 *   - pre-existing history rows rolled up before rDNS was enabled/configured,
 *   - overflow beyond the rollup's per-tick batch limit on high-churn networks.
 *
 * Each beat (60 s) selects up to `rdnsBatchLimit` DISTINCT unresolved endpoint
 * IPs from flow_agg_5m (per scope: 'external' uses the pending partial indexes
 * — index-only scan; 'all' falls back to a windowed BRIN scan over the last 7
 * days), resolves them through utils/reverseDns.ts (persistent per-ADDRESS
 * cache, so already-known IPs cost one indexed lookup and no wire traffic),
 * and writes the POSITIVE results back into the rows. Negative results are only
 * cached — a row whose IP has no PTR record stays hostname-less by design.
 *
 * The flow_agg_1h tier is NOT backfilled directly: new hours inherit hostnames
 * via MAX() from the 5m tier, and top-talkers falls back to one live (cached)
 * lookup for older hourly rows — keeping this worker's write volume bounded.
 */

import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
import { parseRdnsConfig, pruneRdnsCache, resolveHostnames } from '../utils/reverseDns';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

const BEAT_MS = 60_000; // fixed beat — the per-beat work is budget-capped in settings
/** 'all'-scope window bound (no partial index covers internal rows). */
const ALL_SCOPE_WINDOW_MS = 7 * 86_400_000;
/** Cache pruning cadence — far beyond any TTL, so growth stays bounded. */
const PRUNE_INTERVAL_MS = 3_600_000;

let lastPruneAt = 0;
/** Overlap guard — a slow beat must not pile up unbounded concurrent scans. */
let busy = false;

/** One beat: resolve + write back one budget-sized batch of pending IPs. */
async function reverseDnsBeat(): Promise<void> {
  if (busy) return; // previous beat still running — skip this tick
  busy = true;
  try {
    await runReverseDnsBeat();
  } finally {
    busy = false;
  }
}

async function runReverseDnsBeat(): Promise<void> {
  const values = await getEffectiveValues();
  if (values.rdnsEnabled !== true) return; // master switch off — no work at all

  const cfg = parseRdnsConfig(values);
  const budget = Math.min(Math.max(Number(values.rdnsBatchLimit) || 200, 10), 5_000);
  const scopeAll = String(values.rdnsScope ?? 'external') === 'all';

  // Hourly cache prune — keeps reverse_dns_cache bounded (4× max TTL retention).
  if (Date.now() - lastPruneAt >= PRUNE_INTERVAL_MS) {
    lastPruneAt = Date.now();
    try {
      const pruned = await pruneRdnsCache(cfg);
      if (pruned > 0) console.log(`[reverse-dns] pruned ${pruned} stale cache row(s)`);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn('[reverse-dns] cache prune failed:', (err as Error).message);
    }
  }

  const dirs = [
    { ipCol: 'srcIp', classCol: 'srcClass', hostCol: 'srcHostname', sourceCol: 'srcHostnameSource' },
    { ipCol: 'dstIp', classCol: 'dstClass', hostCol: 'dstHostname', sourceCol: 'dstHostnameSource' },
  ] as const;

  // external scope → the pending partial index; all scope → windowed BRIN scan
  // over the recent 7 days. NO DISTINCT / no ::text cast — both would force a
  // full pass over every matching row before LIMIT can apply (minutes on large
  // networks). Plain column select = index-only scan that stops at LIMIT;
  // duplicates are harmless (candidates is a Set, resolveHostnames dedupes and
  // the per-IP cache makes repeats one indexed lookup).
  const windowFromIso = new Date(Date.now() - ALL_SCOPE_WINDOW_MS).toISOString();
  const candidates = new Set<string>();
  for (const d of dirs) {
    const sql = scopeAll
      ? `SELECT "${d.ipCol}" AS ip FROM flow_agg_5m WHERE "${d.hostCol}" IS NULL AND bucket >= $1 LIMIT $2`
      : `SELECT "${d.ipCol}" AS ip FROM flow_agg_5m WHERE "${d.classCol}" = 'internet' AND "${d.hostCol}" IS NULL LIMIT $1`;
    let res;
    try {
      res = scopeAll
        ? await pool.query<{ ip: string }>(sql, [windowFromIso, budget])
        : await pool.query<{ ip: string }>(sql, [budget]);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[reverse-dns] pending scan failed for ${d.ipCol}:`, (err as Error).message);
      continue;
    }
    for (const r of res.rows) candidates.add(String(r.ip));
  }

  if (candidates.size === 0) return; // nothing pending — steady state

  const names = await resolveHostnames([...candidates], budget);
  const positives: Array<{ ip: string; hostname: string }> = [];
  for (const [ip, hostname] of names) {
    if (hostname) positives.push({ ip, hostname });
  }
  if (positives.length === 0) return; // all negatives — cached, rows stay nameless

  const ips = positives.map((p) => p.ip);
  const hostnames = positives.map((p) => p.hostname);
  let written = 0;
  for (const d of dirs) {
    const scopeClause = scopeAll ? '' : `AND "${d.classCol}" = 'internet'`;
    try {
      const res = await pool.query(
        `UPDATE flow_agg_5m f SET "${d.hostCol}" = u.hostname, "${d.sourceCol}" = 'reverse-dns'
         FROM (SELECT * FROM unnest($1::text[], $2::text[]) AS u(ip, hostname)) u
         WHERE f."${d.ipCol}" = u.ip::inet AND f."${d.hostCol}" IS NULL ${scopeClause}`,
        [ips, hostnames],
      );
      written += Number(res.rowCount ?? 0);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[reverse-dns] write-back failed for ${d.ipCol}:`, (err as Error).message);
    }
  }
  if (written > 0) {
    // eslint-disable-next-line no-console
    console.log(`[reverse-dns] backfilled ${written} row(s) from ${positives.length} resolved IP(s)`);
  }
}

/**
 * Starts the reverse-DNS backfill loop. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startReverseDnsWorker(): () => void {
  initWorker('reverseDns', LEADER_KEYS.reverseDns);
  // eslint-disable-next-line no-console
  console.log('[reverse-dns] worker started');

  void trackBeat('reverseDns', reverseDnsBeat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[reverse-dns] initial beat failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('reverseDns', reverseDnsBeat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[reverse-dns] backfill beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
