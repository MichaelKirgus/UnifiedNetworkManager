import { lt } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/**
 * Retention for plugin log entries (see routes/internal.ts POST /plugin/logs).
 * Rows older than LOG_RETENTION_DAYS are deleted on an hourly sweep — the same
 * cutoff-DELETE pattern as the telemetry worker's stale-inventory sweep. ISO-8601
 * strings compare correctly lexicographically, so a plain string comparison is
 * safe against the TEXT timestamp column.
 */

const RETENTION_DAYS = Math.max(1, Number(process.env.LOG_RETENTION_DAYS ?? 7));
const SWEEP_INTERVAL_MS = 3_600_000; // hourly — log volume makes this cheap enough to run often

async function sweepExpiredLogs(): Promise<void> {
  const cutoff = new Date(Date.now() - RETENTION_DAYS * 24 * 60 * 60 * 1000).toISOString();
  await db.delete(schema.pluginLogs).where(lt(schema.pluginLogs.timestamp, cutoff));
}

/**
 * Starts the log retention sweep. Must be called only after the API has bound
 * its port (same rule as every other worker — see index.ts app.listen callback).
 */
export function startLogRetentionWorker(): NodeJS.Timeout {
  // eslint-disable-next-line no-console
  console.log(`[log-retention] worker started, keeping ${RETENTION_DAYS} days of plugin logs`);

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  sweepExpiredLogs().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[log-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    sweepExpiredLogs().catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[log-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
