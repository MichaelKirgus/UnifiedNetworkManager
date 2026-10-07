import { lt } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Retention for per-host firewall state snapshots (see routes/internal.ts
 * POST /plugin/host-states). The table is append-only — one row per endpoint
 * address per walk on every stateful device, so without retention it grows
 * unbounded. This worker deletes rows older than hostStateRetentionDays on an
 * hourly sweep — the same cutoff-DELETE pattern as firewallEventRetention.ts.
 * Rows are cut by `walkedAtMs` (epoch ms stamped at ingest), which is always
 * set, so no NULL fallback is needed. The default of 7 days comfortably covers
 * the 24h churn window shown on the Hosts/Networks pages plus a week of
 * history for trend questions.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweepExpiredHostStates(): Promise<void> {
  const retentionDays = Number(await getEffectiveSettingValue('hostStateRetentionDays')) || 7;
  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  await db.delete(schema.hostStates).where(lt(schema.hostStates.walkedAtMs, cutoffMs));
}

/**
 * Starts the host-state retention sweep. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startHostStateRetentionWorker(): NodeJS.Timeout {
  initWorker('hostStateRetention', LEADER_KEYS.hostStateRetention);
  // eslint-disable-next-line no-console
  console.log('[host-state-retention] worker started (retention read live from Settings)');

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  void trackBeat('hostStateRetention', sweepExpiredHostStates).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[host-state-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('hostStateRetention', sweepExpiredHostStates).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[host-state-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
