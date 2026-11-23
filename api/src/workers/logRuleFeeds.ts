/**
 * Log-rule feed sync worker (Phase 2). Leader-gated; every beat it finds the
 * enabled feeds whose interval has elapsed and runs one authoritative sync
 * cycle each (logRules/feeds.ts): fetch → upsert by name → disable missing.
 * Manual "sync now" requests run in-process via the same engine, so this worker
 * only drives the scheduled cadence (intervalMinutes > 0).
 */

import { pool } from '../db';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { isFeedSyncing, recordFeedSyncError, syncLogRuleFeed } from '../logRules/feeds';

const BEAT_MS = 60_000;
let busy = false;

async function beat(): Promise<void> {
  if (busy) return; // a previous sweep is still fetching — skip this tick
  busy = true;
  try {
    // Due-check in JS (ISO-8601 UTC strings compare lexicographically, but the
    // interval math is clearer here than in SQL).
    const all = await pool.query<{ id: string; name: string; "intervalMinutes": number; "lastSyncAt": string | null }>(
      `SELECT id, name, "intervalMinutes", "lastSyncAt" FROM log_rule_feeds WHERE enabled = true AND "intervalMinutes" > 0 ORDER BY name`
    );
    const nowMs = Date.now();
    for (const f of all.rows) {
      if (isFeedSyncing(f.id)) continue; // manual sync in flight — don't double-fetch
      const lastMs = f.lastSyncAt ? Date.parse(String(f.lastSyncAt)) : 0;
      if (nowMs - lastMs < Number(f.intervalMinutes) * 60_000) continue; // not due yet
      try {
        const r = await syncLogRuleFeed(f.id);
        // eslint-disable-next-line no-console
        console.log(`[log-rule-feeds] synced "${f.name}": ${r.created} created, ${r.updated} updated, ${r.disabled} disabled, ${r.skipped.length} skipped`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        // eslint-disable-next-line no-console
        console.error(`[log-rule-feeds] sync of "${f.name}" failed:`, msg);
        await recordFeedSyncError(f.id, msg).catch(() => undefined);
      }
    }
  } finally {
    busy = false;
  }
}

/** Starts the feed-sync worker (leader-gated by the caller via runAsLeader). */
export function startLogRuleFeedsWorker(): () => void {
  initWorker('logRuleFeeds', LEADER_KEYS.logRuleFeeds);
  // eslint-disable-next-line no-console
  console.log('[log-rule-feeds] worker started');

  const timer = setInterval(() => {
    void trackBeat('logRuleFeeds', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[log-rule-feeds] beat failed:', err);
    });
  }, BEAT_MS);
  // First sweep shortly after boot (feeds with lastSyncAt NULL are due immediately).
  void trackBeat('logRuleFeeds', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[log-rule-feeds] initial run failed:', err);
  });

  return () => clearInterval(timer);
}
