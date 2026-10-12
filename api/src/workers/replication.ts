/**
 * Replication scheduler — leader-gated worker that runs due replication syncs.
 *
 * Every BEAT_MS it asks the replication service for enabled targets whose
 * interval has elapsed and fires a sync for each (fire-and-forget: runTargetSync
 * already guards per-target concurrency, persists lastSyncAt/Status/Error on its
 * row, and never throws past this point). Manual "Sync now" requests go through
 * the same runTargetSync path, so scheduler + manual can't double-run a target.
 */

import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { findDueTargets, runTargetSync } from '../replication';

const BEAT_MS = 30_000; // scheduler granularity — per-target cadence comes from intervalMinutes

/**
 * Starts the replication scheduler loop. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startReplicationSchedulerWorker(): () => void {
  initWorker('replication', LEADER_KEYS.replication);
  // eslint-disable-next-line no-console
  console.log('[replication] scheduler started');

  const beat = async (): Promise<void> => {
    const due = await findDueTargets();
    if (due.length === 0) return;
    for (const target of due) {
      void runTargetSync(target.id).catch((err) => {
        // eslint-disable-next-line no-console
        console.error(`[replication] sync failed for target ${target.name} (${target.id}):`, err);
      });
    }
  };

  void trackBeat('replication', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[replication] initial scan failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('replication', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[replication] scheduler beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
