import { and, isNull, lt, or } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Retention for firewall event-log rows (see routes/internal.ts
 * POST /plugin/firewall-events). The table is an append-only log — busy
 * firewalls can push thousands of events per minute, so without retention it
 * grows unbounded. This worker deletes rows older than
 * FIREWALL_EVENT_RETENTION_DAYS on an hourly sweep — the same cutoff-DELETE
 * pattern as telemetryRetention.ts. Rows are cut by `tsMs` (epoch ms resolved
 * at ingest from the appliance-local timestamp + the device's known UTC
 * offset); rows whose timestamp was unparseable (tsMs NULL) fall back to a
 * lexicographic compare on the raw `ts` string so they still age out.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweepExpiredFirewallEvents(): Promise<void> {
  const retentionDays = Number(await getEffectiveSettingValue('firewallEventRetentionDays')) || 7;
  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  await db.delete(schema.firewallEvents).where(
    or(
      lt(schema.firewallEvents.tsMs, cutoffMs),
      and(isNull(schema.firewallEvents.tsMs), lt(schema.firewallEvents.ts, new Date(cutoffMs).toISOString()))
    )
  );
}

/**
 * Starts the firewall-event retention sweep. Must be called only after the API
 * has bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startFirewallEventRetentionWorker(): NodeJS.Timeout {
  initWorker('firewallEventRetention', LEADER_KEYS.firewallEventRetention);
  // eslint-disable-next-line no-console
  console.log('[firewall-event-retention] worker started (retention read live from Settings)');

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  void trackBeat('firewallEventRetention', sweepExpiredFirewallEvents).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[firewall-event-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('firewallEventRetention', sweepExpiredFirewallEvents).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[firewall-event-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
