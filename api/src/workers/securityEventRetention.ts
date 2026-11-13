import { lt } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Retention for syslog security-event rows (see routes/internal.ts
 * POST /plugin/security-events). The table is an append-only log — a fleet of
 * devices forwarding their logs can push thousands of lines per minute, so
 * without retention it grows unbounded. This worker deletes rows older than
 * SECURITY_EVENT_RETENTION_DAYS on an hourly sweep — the same cutoff-DELETE
 * pattern as firewallEventRetention.ts. Rows are cut by `tsMs` (epoch ms of
 * the syslog timestamp); unlike firewall_events there is no NULL-ts fallback
 * because ingest drops lines without a parseable timestamp entirely.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweepExpiredSecurityEvents(): Promise<void> {
  const retentionDays = Number(await getEffectiveSettingValue('securityEventRetentionDays')) || 7;
  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  await db.delete(schema.securityEvents).where(lt(schema.securityEvents.tsMs, cutoffMs));
}

/**
 * Starts the security-event retention sweep. Must be called only after the API
 * has bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startSecurityEventRetentionWorker(): NodeJS.Timeout {
  initWorker('securityEventRetention', LEADER_KEYS.securityEventRetention);
  // eslint-disable-next-line no-console
  console.log('[security-event-retention] worker started (retention read live from Settings)');

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  void trackBeat('securityEventRetention', sweepExpiredSecurityEvents).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[security-event-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('securityEventRetention', sweepExpiredSecurityEvents).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[security-event-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
