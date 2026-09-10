import { lt } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Retention for raw telemetry snapshots (see workers/telemetry.ts).
 *
 * Telemetry is the fastest-growing table in the system — one row per plugin
 * assignment per poll beat (~10 KB each with metrics + descriptors). Without
 * retention, 200 devices × 2 plugins at a 30s beat writes ~1.15M rows/day and
 * tens of GB/month; VACUUM pressure, bloat and backup size all degrade over
 * months even though every READ stays fast (the per-device index serves the
 * history endpoint). This worker deletes raw snapshots older than
 * TELEMETRY_RETENTION_DAYS on an hourly sweep — the same cutoff-DELETE pattern
 * as logRetention.ts. ISO-8601 strings compare correctly lexicographically, so
 * a plain string comparison is safe against the TEXT timestamp column.
 *
 * The normalized inventory tables (networks/hosts/tunnels/routes/wifi) are NOT
 * touched here — they carry their own 24h stale sweep in workers/telemetry.ts
 * and hold only current-state rows, not history.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweepExpiredTelemetry(): Promise<void> {
  const retentionDays = Number(await getEffectiveSettingValue('telemetryRetentionDays')) || 7;
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  await db.delete(schema.telemetry).where(lt(schema.telemetry.collectedAt, cutoff));
}

/**
 * Starts the telemetry retention sweep. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startTelemetryRetentionWorker(): NodeJS.Timeout {
  initWorker('telemetryRetention', LEADER_KEYS.telemetryRetention);
  // eslint-disable-next-line no-console
  console.log('[telemetry-retention] worker started (retention read live from Settings)');

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  void trackBeat('telemetryRetention', sweepExpiredTelemetry).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[telemetry-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('telemetryRetention', sweepExpiredTelemetry).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[telemetry-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
