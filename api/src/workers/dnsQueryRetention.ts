import { lt } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';

/**
 * Retention for DNS query-event rows (see routes/internal.ts
 * POST /plugin/dns-queries). The table is an append-only per-query log — a busy
 * resolver can push thousands of rows per minute, so without retention it grows
 * unbounded. This worker deletes rows older than dnsQueryRetentionDays on an
 * hourly sweep — the same cutoff-DELETE pattern as firewallEventRetention.ts.
 * Rows are cut by `tsMs` (epoch ms; the appliance's unix seconds × 1000, always
 * UTC so no offset fallback is needed). The default of 7 days mirrors the
 * appliance-side retention of OPNsense's own query database.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweepExpiredDnsQueries(): Promise<void> {
  const retentionDays = Number(await getEffectiveSettingValue('dnsQueryRetentionDays')) || 7;
  const cutoffMs = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
  await db.delete(schema.dnsQueryEvents).where(lt(schema.dnsQueryEvents.tsMs, cutoffMs));
}

/**
 * Starts the DNS query-event retention sweep. Must be called only after the API
 * has bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startDnsQueryRetentionWorker(): NodeJS.Timeout {
  initWorker('dnsQueryRetention', LEADER_KEYS.dnsQueryRetention);
  // eslint-disable-next-line no-console
  console.log('[dns-query-retention] worker started (retention read live from Settings)');

  // First sweep runs immediately so stale rows from before the feature (or a
  // retention change) are cleaned up without waiting an hour.
  void trackBeat('dnsQueryRetention', sweepExpiredDnsQueries).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[dns-query-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('dnsQueryRetention', sweepExpiredDnsQueries).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[dns-query-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
