import { pool } from '../db';
import { getEffectiveSettingValue } from '../systemSettings';
import { emitNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { PROBE_USERNAME, probeRadius } from '../radius/probe';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * RADIUS self-monitoring worker (leader-gated).
 *
 * Two jobs on one coarse beat:
 *   1. PROBE — UNM checks its own FreeRADIUS sidecar the same way a device is
 *      checked: every cycle it sends ONE test Access-Request from the internal
 *      probe client (radius_probe_client, rendered into clients.conf by the API)
 *      and classifies the outcome. The EAP-only site answers PAP with
 *      Access-Reject — ANY well-formed reply proves radiusd is up, listening on
 *      1812, has loaded its config, and recognizes UNM's source IP (FreeRADIUS
 *      silently drops requests from unknown clients). Consecutive failures
 *      escalate to a notification (warning after WARN_STREAK, critical after
 *      CRIT_STREAK); recovery resolves it. The latest outcome is stored in
 *      radius_monitor_state for GET /radius/status + the webapp.
 *   2. AUTH-FAIL AUDIT — rlm_sql writes one radpostauth row per completed auth
 *      attempt (ACCEPT and REJECT). This worker scans NEW rows past its cursor:
 *      a reject emits a warning notification deduped per username (re-fires only
 *      after the re-fire window, so a chatty attacker doesn't flood the bell);
 *      an accept for that username resolves it. Rows older than the retention
 *      setting are pruned in batches.
 *
 * The worker is a no-op while `radiusEnabled` is off — nothing to monitor.
 */

const BEAT_MS = 60_000; // one probe + one scan per minute — coarse on purpose
const PROBE_TIMEOUT_MS = 5_000;
/** Consecutive failed probes before the condition escalates (warning / critical). */
const WARN_STREAK = 3;
const CRIT_STREAK = 6;
/** A reject re-notifies only after this long — dedupe in between. */
const AUTH_FAIL_REFIRE_MS = 15 * 60_000;
/** Max radpostauth rows fetched per scan (a burst of failures must not stall the beat). */
const SCAN_LIMIT = 200;

let failStreak = 0;
let probeConditionOpen = false;
/** username → last time a reject notification was emitted/refreshed. */
const lastFailNotifyAt = new Map<string, number>();

async function upsertState(patch: Record<string, unknown>): Promise<void> {
  // $1 = the fixed row id; $2..$N are the patch values (the DO UPDATE SET must
  // reference the SAME positions as the VALUES list).
  const sets = Object.keys(patch)
    .map((k, i) => `"${k}" = $${i + 2}`)
    .join(', ');
  await pool.query(
    `INSERT INTO radius_monitor_state (id, ${Object.keys(patch).map((k) => `"${k}"`).join(', ')})
     VALUES ($1, ${Object.keys(patch)
       .map((_, i) => `$${i + 2}`)
       .join(', ')})
     ON CONFLICT (id) DO UPDATE SET ${sets}`,
    ['unm', ...Object.values(patch)]
  );
}

/** Job 1 — the liveness probe. Never throws; every outcome is stored. */
async function runProbe(): Promise<void> {
  const rows = await pool.query(`SELECT ip, secret FROM radius_probe_client WHERE id = $1`, ['unm']);
  if (rows.rows.length === 0) return; // bootstrap not done yet — nothing to probe with

  const host = process.env.UNM_RADIUS_HOST ?? 'unm-radius';
  const port = Number(process.env.UNM_RADIUS_PORT ?? 1812);
  const result = await probeRadius(host, port, rows.rows[0].secret, PROBE_USERNAME, PROBE_TIMEOUT_MS);

  await upsertState({
    lastProbeAt: new Date().toISOString(),
    probeOutcome: result.outcome,
    packetType: result.packetType,
    latencyMs: result.latencyMs,
    detail: result.detail,
  });

  const dedupeKey = 'radius:probe-down';
  if (result.outcome === 'ok') {
    failStreak = 0;
    if (probeConditionOpen) {
      await resolveNotificationsByDedupeKeys([dedupeKey]);
      probeConditionOpen = false;
      console.log('[radius-monitor] RADIUS sidecar recovered — notification resolved');
    }
    return;
  }

  failStreak += 1;
  if (failStreak < WARN_STREAK) return; // grace period across restarts / transient blips
  const severity = failStreak >= CRIT_STREAK ? 'critical' : 'warning';
  probeConditionOpen = true;
  await emitNotification({
    severity,
    source: 'system',
    title: `RADIUS server ${failStreak >= CRIT_STREAK ? 'unreachable' : 'degraded'} (${failStreak} failed probes)`,
    message: `${result.detail}. WiFi EAP-TLS authentication is ${failStreak >= CRIT_STREAK ? 'NOT working — clients cannot authenticate.' : 'at risk; the probe has been failing repeatedly.'}`,
    dedupeKey,
    context: { outcome: result.outcome, host, port, failStreak },
  });
}

/** Job 2 — scan new radpostauth rows → notifications + retention. */
async function scanAuthLog(): Promise<void> {
  const state = await pool.query(`SELECT "lastAuthLogId" FROM radius_monitor_state WHERE id = $1`, ['unm']);
  let cursor: number = Number(state.rows[0]?.['lastAuthLogId'] ?? 0);

  // First run after an upgrade: start at the NEWEST row so historical rejects
  // (from before monitoring existed) don't flood the bell on boot.
  if (cursor === 0) {
    const max = await pool.query(`SELECT COALESCE(MAX(id), 0) AS m FROM radpostauth`);
    cursor = Number(max.rows[0]?.['m'] ?? 0);
    if (cursor > 0) await upsertState({ lastAuthLogId: cursor });
    return;
  }

  // NOTE: unquoted identifiers in the DDL folded to lowercase — reference them
  // as such (or quoted-lowercase) or Postgres rejects the query.
  const res = await pool.query(
    `SELECT id, username, reply, calledstationid AS "CalledStationId", callingstationid AS "CallingStationId", authdate
     FROM radpostauth WHERE id > $1 ORDER BY id ASC LIMIT $2`,
    [cursor, SCAN_LIMIT]
  );
  for (const row of res.rows) {
    const id = Number(row.id);
    cursor = Math.max(cursor, id);
    const username = String(row.username ?? '');
    // The probe's own test requests land here as rejects too — they are
    // UNM's heartbeat, not real login attempts: never notify about them.
    if (!username || username === PROBE_USERNAME) continue;

      if (String(row.reply).startsWith('Access-Reject')) {
        const now = Date.now();
        const last = lastFailNotifyAt.get(username) ?? 0;
        // In-memory re-fire window: a brand-new process has no memory, so the
        // first reject after ANY restart notifies once (correct — it's new info),
        // then dedupes until the window elapses.
        if (now - last < AUTH_FAIL_REFIRE_MS) continue;
        lastFailNotifyAt.set(username, now);
        await emitNotification({
          severity: 'warning',
          source: 'system',
          title: `Failed RADIUS login: ${username}`,
          message: `EAP-TLS authentication was REJECTED${row['CalledStationId'] ? ` from NAS ${row['CalledStationId']}` : ''}${row['CallingStationId'] ? ` (client ${row['CallingStationId']})` : ''} at ${new Date(row.authdate).toISOString()}. Repeated rejects for the same user are deduplicated.`,
          dedupeKey: `radius:auth-fail:${username}`,
          context: { username, calledStationId: row['CalledStationId'] ?? null, callingStationId: row['CallingStationId'] ?? null },
        });
      } else if (String(row.reply).startsWith('Access-Accept')) {
        // A successful auth clears the user's open failure condition.
        await resolveNotificationsByDedupeKeys([`radius:auth-fail:${username}`]);
        lastFailNotifyAt.delete(username);
      }
    }

  if (cursor > Number(state.rows[0]?.['lastAuthLogId'] ?? 0)) {
    await upsertState({ lastAuthLogId: cursor });
  }

  // Retention — batched DELETE so a large backlog never holds the table lock.
  const retentionDays = Math.max(1, Number(await getEffectiveSettingValue('radiusAuthLogRetentionDays')) || 30);
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  let deletedTotal = 0;
  for (let i = 0; i < 50; i++) {
    const del = await pool.query(`DELETE FROM radpostauth WHERE authdate < $1 LIMIT 10000`, [cutoff]);
    deletedTotal += del.rowCount ?? 0;
    if ((del.rowCount ?? 0) < 10000) break;
  }
  if (deletedTotal > 0) console.log(`[radius-monitor] pruned ${deletedTotal} radpostauth row(s) older than ${retentionDays}d`);
}

export function startRadiusMonitorWorker(): () => void {
  initWorker('radiusMonitor', LEADER_KEYS.radiusMonitor);
  // eslint-disable-next-line no-console
  console.log('[radius-monitor] worker started (probe + auth-fail audit every 60s, leader-gated)');

  let stopped = false;
  const timer = setInterval(() => {
    if (stopped) return;
    void trackBeat('radiusMonitor', async () => {
      // No-op while RADIUS is off — the sidecar isn't running and there is no
      // rendered probe client to speak of.
      const enabled = String(await getEffectiveSettingValue('radiusEnabled')) !== 'false';
      if (!enabled) return;

      await runProbe();
      try {
        await scanAuthLog();
      } catch (err) {
        // A DB hiccup in the audit job must not kill the probe cadence.
        console.error('[radius-monitor] auth-log scan failed:', err);
      }
    }).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[radius-monitor] cycle failed:', err);
    });
  }, BEAT_MS);

  return () => {
    stopped = true;
    clearInterval(timer);
  };
}
