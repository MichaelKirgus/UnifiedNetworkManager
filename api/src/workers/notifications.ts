import { initWorker, trackBeat } from './stats';
import { LEADER_KEYS } from './leader';
import { getEffectiveSettingValue } from '../systemSettings';
import { autoResolveStaleCertificateNotifications, autoResolveStaleDeviceNotifications, pruneOldNotifications } from '../notifications';

/**
 * Notifications worker (leader-gated).
 *
 * The notification SERVICE (src/notifications.ts) is synchronous and cheap —
 * emitters call it inline. This worker owns the periodic maintenance that must
 * run exactly once across replicas:
 *   1. AUTO-RESOLVE: mirrored device-state notifications clear themselves when
 *      the device recovers (status no longer matches the dedupe key's state).
 *   2. RETENTION: terminal rows (resolved/closed) older than NOTIFICATION_RETENTION_DAYS
 *      are pruned so the table stays small even with a chatty fleet.
 *
 * Cadence is deliberately coarse (60s): resolution latency of one minute is
 * imperceptible for device recovery, and it keeps DB load negligible at scale.
 */

const SWEEP_INTERVAL_MS = 60_000;

export function startNotificationsWorker(): () => void {
  initWorker('notifications', LEADER_KEYS.notifications);
  // eslint-disable-next-line no-console
  console.log(
    `[notifications] worker started (sweep every ${SWEEP_INTERVAL_MS / 1000}s, retention read live from Settings)`
  );

  let stopped = false;
  const timer = setInterval(() => {
    if (stopped) return;
    void trackBeat('notifications', async () => {
      // 1. Auto-resolve recovered device-state conditions.
      const resolved = await autoResolveStaleDeviceNotifications();
      if (resolved > 0) {
        // eslint-disable-next-line no-console
        console.log(`[notifications] auto-resolved ${resolved} stale device notification(s)`);
      }

      // 2. Auto-resolve certificate expiry/invalidity conditions that cleared
      //    (renewed cert now valid + past the warn window, or endpoint removed).
      const warnDays = Number(await getEffectiveSettingValue('certExpiryWarnDays')) || 30;
      const resolvedCerts = await autoResolveStaleCertificateNotifications(warnDays);
      if (resolvedCerts > 0) {
        // eslint-disable-next-line no-console
        console.log(`[notifications] auto-resolved ${resolvedCerts} stale certificate notification(s)`);
      }

      // 3. Retention sweep for terminal rows.
      const retentionDays = Number(await getEffectiveSettingValue('notificationRetentionDays')) || 30;
      const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
      const pruned = await pruneOldNotifications(cutoff);
      if (pruned > 0) {
        // eslint-disable-next-line no-console
        console.log(`[notifications] pruned ${pruned} terminal notification(s)`);
      }
    }).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[notifications] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
