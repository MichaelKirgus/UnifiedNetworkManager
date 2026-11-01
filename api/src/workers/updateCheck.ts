import { getEffectiveSettingValue } from '../systemSettings';
import { syncStackUpdateNotification } from '../stackUpdates';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * Stack self-update checker — proactively tells the admin when a newer UNM
 * release is available.
 *
 * The Updates page already shows an "UNM itself" card (getStackUpdateInfo), but
 * that only updates when someone opens the page. This worker closes the gap: on
 * a configurable cadence (`updateFeedCheckIntervalMs` setting, default 15 min)
 * it re-checks the configured update feed and maintains a single deduplicated
 * "UnifiedNetworkManager <version> is available" notification — emitting it
 * while a newer version exists and RESOLVING it once the running version catches
 * up or the feed is disabled. The check itself is shared + short-cached with the
 * /updates route (see stackUpdates.checkFeed), so page views and worker beats
 * never double-fetch GitHub within the cache window.
 *
 * Leader-gated like every other worker: only one API replica runs it, and a
 * container restart simply clears the in-memory feed cache (the next beat
 * re-fetches).
 */

const BEAT_MS = 30_000; // fixed timer beat — the effective interval comes from settings

/**
 * Starts the update-check loop. Must be called only after the API has bound its
 * port (same rule as every other worker — see index.ts app.listen).
 */
export function startUpdateCheckWorker(): () => void {
  initWorker('stackUpdates', LEADER_KEYS.stackUpdates);
  // eslint-disable-next-line no-console
  console.log('[update-check] worker started');

  let lastCycleAt = 0;
  const beat = async (): Promise<void> => {
    const rawInterval = await getEffectiveSettingValue('updateFeedCheckIntervalMs');
    const intervalMs = Number(rawInterval) || 900_000;
    if (Date.now() - lastCycleAt < intervalMs) return; // not due yet — settings may have been raised mid-flight
    lastCycleAt = Date.now();
    await syncStackUpdateNotification();
  };

  void trackBeat('stackUpdates', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[update-check] initial cycle failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('stackUpdates', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[update-check] check cycle failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
