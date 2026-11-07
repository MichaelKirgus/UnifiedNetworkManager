import { pool } from '../db';
import { getEffectiveSettingValue } from '../systemSettings';
import { emitNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { PROBE_USERNAME, probeRadius } from '../radius/probe';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * RADIUS self-monitoring worker (leader-gated).
 *
 * Three jobs on one coarse beat:
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
 *   3. SLAVE MONITORING (RADIUS failover) — every enabled PUSH replication
 *      target that carries the `radius` section is a potential failover slave.
 *      This job polls each one's GET /replication/slave-status with the same
 *      peer token used for inbound sync, stores probe outcome + 24h counters in
 *      radius_slave_monitor (for GET /radius/slaves + the webapp), and mirrors
 *      NEW auth attempts into radius_slave_auth_events — so a failed login on a
 *      failover slave alerts on the PRIMARY without any shared storage. The
 *      mirror is best-effort: the slave's own radpostauth stays authoritative.
 *      Consecutive poll failures escalate like the local probe; recovery
 *      resolves. Mirrored rows are pruned with the same retention setting.
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
/** Per-slave poll timeout — a hung peer must not stall the whole beat. */
const SLAVE_POLL_TIMEOUT_MS = 15_000;
/** Max mirrored events ingested per slave per beat (backlogs drain over beats). */
const SLAVE_EVENT_LIMIT = 500;

let failStreak = 0;
let probeConditionOpen = false;
/** username → last time a reject notification was emitted/refreshed. */
const lastFailNotifyAt = new Map<string, number>();
/** targetId → consecutive failed slave polls (in-memory, like failStreak). */
const slaveFailStreak = new Map<string, number>();
/** targetIds with an open "slave down" notification. */
const slaveDownOpen = new Set<string>();
/** `${targetId}:${username}` → last time a SLAVE reject was notified/refreshed. */
const lastSlaveFailNotifyAt = new Map<string, number>();

/** Shape of GET /replication/slave-status (served by the peer's API). */
interface SlaveStatusResponse {
  enabled?: boolean;
  probe?: {
    lastProbeAt: string | null;
    outcome: string | null; // ok | bad-auth | timeout
    packetType: string | null;
    latencyMs: number | null;
    detail: string | null;
  } | null;
  last24h?: { rejects: number; accepts: number; lastAttemptAt: string | null };
  events?: Array<{
    id: number;
    username: string;
    result: 'accept' | 'reject' | null;
    calledStationId: string | null;
    callingStationId: string | null;
    authdate: string; // ISO
  }>;
  /** Newest non-probe row on the peer — used to detect a radpostauth RESET. */
  latestEvent?: { id: number; authdate: string } | null;
}

/** If the peer's newest event is this far AHEAD of our cursor yet its id did not grow, the table was reset (ids restarted) → re-bootstrap. */
const SLAVE_RESET_MARGIN_MS = 10 * 60_000;

/** JSON string array → string[] (replication_targets.sections / excludeKeys). */
function parseStringArray(raw: unknown): string[] {
  if (typeof raw !== 'string' || !raw) return [];
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v.filter((s): s is string => typeof s === 'string') : [];
  } catch {
    return [];
  }
}

/** A replication target that carries the `radius` section (explicitly, or via all-portable). */
function carriesRadiusSection(sections: unknown): boolean {
  if (sections == null) return true; // NULL/empty = ALL portable sections (incl. radius)
  const list = parseStringArray(sections);
  return list.length === 0 || list.includes('radius');
}

async function upsertSlaveMonitor(id: string, patch: Record<string, unknown>): Promise<void> {
  const keys = Object.keys(patch);
  await pool.query(
    `INSERT INTO radius_slave_monitor (id, ${keys.map((k) => `"${k}"`).join(', ')})
     VALUES ($1, ${keys.map((_, i) => `$${i + 2}`).join(', ')})
     ON CONFLICT (id) DO UPDATE SET ${keys.map((k, i) => `"${k}" = $${i + 2}`).join(', ')}`,
    [id, ...Object.values(patch)]
  );
}

/** Record a failed slave poll; escalate after WARN_STREAK / CRIT_STREAK. Never throws. */
async function recordSlavePollFailure(target: { id: string; name: string }, detail: string): Promise<void> {
  const streak = (slaveFailStreak.get(target.id) ?? 0) + 1;
  slaveFailStreak.set(target.id, streak);
  await upsertSlaveMonitor(target.id, { lastCheckAt: new Date().toISOString(), reachable: false, error: detail });
  if (streak < WARN_STREAK) return; // grace period across restarts / transient blips
  const severity = streak >= CRIT_STREAK ? 'critical' : 'warning';
  slaveDownOpen.add(target.id);
  await emitNotification({
    severity,
    source: 'system',
    title: `RADIUS failover slave "${target.name}" ${streak >= CRIT_STREAK ? 'unreachable' : 'degraded'} (${streak} failed polls)`,
    message: `${detail}. If the primary is down this slave may be serving authentication WITHOUT monitoring — check it directly.`,
    dedupeKey: `radius:slave-down:${target.id}`,
    context: { targetId: target.id, name: target.name, streak },
  });
}

/** Poll ONE failover slave: status + counters → monitor row; new events → mirror table + alerts. */
async function pollOneSlave(target: { id: string; name: string; baseUrl: string; token: string }): Promise<void> {
  // Cursor = newest ingested event (authdate + the SLAVE's local radpostauth id,
  // for a same-second tie-break). Corrupt/missing cursor → bootstrap (newest N).
  let cursor: { authdate: string; id: number } | null = null;
  const curRes = await pool.query(`SELECT "eventsCursor" FROM radius_slave_monitor WHERE id = $1`, [target.id]);
  const rawCursor = curRes.rows[0]?.['eventsCursor'];
  if (typeof rawCursor === 'string' && rawCursor) {
    try {
      const parsed = JSON.parse(rawCursor) as Record<string, unknown>;
      if (typeof parsed.authdate === 'string' && Number.isFinite(Number(parsed.id))) {
        cursor = { authdate: parsed.authdate, id: Number(parsed.id) };
      }
    } catch {
      /* corrupt cursor — fall through to bootstrap */
    }
  }

  // Cursor = the SLAVE's local radpostauth id (monotonic bigserial) — an exact,
  // precision-proof "newer than this" marker. authdate rides along ONLY for
  // reset detection below. No cursor → bootstrap (peer returns its newest N).
  const qs = new URLSearchParams();
  if (cursor) qs.set('cursorId', String(cursor.id));
  qs.set('limit', String(SLAVE_EVENT_LIMIT));

  let res: Response;
  try {
    res = await fetch(`${target.baseUrl}/v1/replication/slave-status?${qs.toString()}`, {
      headers: { authorization: `Bearer ${target.token}` },
      signal: AbortSignal.timeout(SLAVE_POLL_TIMEOUT_MS),
    });
  } catch (err) {
    const e = err as Error & { name?: string };
    await recordSlavePollFailure(target, e.name === 'TimeoutError' ? `Peer did not answer within ${SLAVE_POLL_TIMEOUT_MS / 1000}s` : e.message);
    return;
  }

  if (!res.ok) {
    const text = (await res.text().catch(() => '')).slice(0, 200);
    await recordSlavePollFailure(target, `Peer answered HTTP ${res.status}${text ? `: ${text}` : ''}`);
    return;
  }

  let body: SlaveStatusResponse;
  try {
    body = (await res.json()) as SlaveStatusResponse;
  } catch {
    await recordSlavePollFailure(target, 'Peer returned a non-JSON response');
    return;
  }

  // Success — clear any open down condition.
  slaveFailStreak.set(target.id, 0);
  if (slaveDownOpen.has(target.id)) {
    slaveDownOpen.delete(target.id);
    await resolveNotificationsByDedupeKeys([`radius:slave-down:${target.id}`]);
    console.log(`[radius-monitor] failover slave "${target.name}" recovered — notification resolved`);
  }

  const probe = body.probe ?? null;
  await upsertSlaveMonitor(target.id, {
    lastCheckAt: new Date().toISOString(),
    reachable: true,
    radiusEnabled: body.enabled === true,
    error: null,
    probeOutcome: probe?.outcome ?? null,
    packetType: probe?.packetType ?? null,
    latencyMs: probe?.latencyMs ?? null,
    detail: probe?.detail ?? null,
    accepts24h: Number(body.last24h?.accepts ?? 0),
    rejects24h: Number(body.last24h?.rejects ?? 0),
    lastAttemptAt: body.last24h?.lastAttemptAt ?? null,
  });

  const events = Array.isArray(body.events) ? body.events : [];
  if (events.length === 0) {
    // RESET detection: no new rows, yet the peer's newest event is far AHEAD of
    // our cursor in time while its id did not grow → the peer's radpostauth was
    // wiped and ids restarted. Clear the cursor so we re-bootstrap next beat
    // instead of silently missing every new event until ids overtake ours.
    const latest = body.latestEvent ?? null;
    if (cursor && latest && latest.id <= cursor.id) {
      const latestAt = Date.parse(latest.authdate);
      const cursorAt = Date.parse(cursor.authdate);
      if (Number.isFinite(latestAt) && Number.isFinite(cursorAt) && latestAt > cursorAt + SLAVE_RESET_MARGIN_MS) {
        console.log(
          `[radius-monitor] failover slave "${target.name}" appears to have RESET its auth log ` +
            `(newest id ${latest.id} <= cursor ${cursor.id}, but ~${Math.round((latestAt - cursorAt) / 60_000)}min newer) — re-bootstrapping next beat`,
        );
        await upsertSlaveMonitor(target.id, { eventsCursor: null });
      }
    }
    return;
  }

  // Mirror the new rows — one parameterized multi-row INSERT (id is a BIGSERIAL).
  const values: unknown[] = [];
  const rowSql = events
    .map((e, i) => {
      values.push(
        target.id,
        String(e.username ?? ''),
        e.result === 'accept' || e.result === 'reject' ? e.result : null,
        e.calledStationId ?? null,
        e.callingStationId ?? null,
        new Date(e.authdate),
      );
      const b = i * 6;
      return `($${b + 1}, $${b + 2}, $${b + 3}, $${b + 4}, $${b + 5}, $${b + 6})`;
    })
    .join(', ');
  await pool.query(
    `INSERT INTO radius_slave_auth_events ("targetId", "username", "result", "calledStationId", "callingStationId", "authdate") VALUES ${rowSql}`,
    values,
  );

  // Advance the cursor past the newest ingested row (events arrive oldest-first).
  const last = events[events.length - 1];
  await upsertSlaveMonitor(target.id, {
    eventsCursor: JSON.stringify({ authdate: String(last.authdate), id: Number(last.id) }),
  });

  // Security-critical: a REJECT on the slave is a failed login attempt against
  // this network — alert on the primary (deduped per target+username, same
  // re-fire window as local rejects). An accept clears that user's condition.
  for (const e of events) {
    const username = String(e.username ?? '');
    if (!username || username === PROBE_USERNAME) continue; // heartbeat rows never alert
    const dedupeKey = `radius:slave-auth-fail:${target.id}:${username}`;
    if (e.result === 'reject') {
      const now = Date.now();
      const lastAt = lastSlaveFailNotifyAt.get(dedupeKey) ?? 0;
      if (now - lastAt < AUTH_FAIL_REFIRE_MS) continue;
      lastSlaveFailNotifyAt.set(dedupeKey, now);
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: `Failed RADIUS login on slave "${target.name}": ${username}`,
        message: `EAP-TLS authentication was REJECTED${e.calledStationId ? ` from NAS ${e.calledStationId}` : ''}${e.callingStationId ? ` (client ${e.callingStationId})` : ''} at ${String(e.authdate)} on failover slave "${target.name}". Repeated rejects for the same user are deduplicated.`,
        dedupeKey,
        context: { targetId: target.id, username, calledStationId: e.calledStationId ?? null, callingStationId: e.callingStationId ?? null },
      });
    } else if (e.result === 'accept') {
      lastSlaveFailNotifyAt.delete(dedupeKey);
      await resolveNotificationsByDedupeKeys([dedupeKey]);
    }
  }
}

/** Job 3 — poll every RADIUS failover slave + prune mirrored events. */
async function pollSlaveTargets(): Promise<void> {
  // NOTE: quoted camelCase — unquoted identifiers fold to lowercase and the
  // query fails with "column does not exist".
  const res = await pool.query(
    `SELECT id, name, "baseUrl", token, sections FROM replication_targets WHERE enabled = true AND direction = 'push'`
  );
  for (const t of res.rows) {
    if (!carriesRadiusSection(t.sections)) continue;
    try {
      await pollOneSlave({ id: String(t.id), name: String(t.name), baseUrl: String(t.baseUrl), token: String(t.token) });
    } catch (err) {
      // One bad slave must not stop the others.
      console.error(`[radius-monitor] slave poll failed for target ${t.id}:`, err);
    }
  }

  // Retention — mirror rows are pruned with the same window as local radpostauth.
  const retentionDays = Math.max(1, Number(await getEffectiveSettingValue('radiusAuthLogRetentionDays')) || 30);
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
  let deletedTotal = 0;
  for (let i = 0; i < 50; i++) {
    const del = await pool.query(
      `DELETE FROM radius_slave_auth_events WHERE id IN (SELECT id FROM radius_slave_auth_events WHERE "authdate" < $1 ORDER BY id ASC LIMIT 10000)`,
      [cutoff],
    );
    deletedTotal += del.rowCount ?? 0;
    if ((del.rowCount ?? 0) < 10000) break;
  }
  if (deletedTotal > 0) console.log(`[radius-monitor] pruned ${deletedTotal} mirrored slave auth event(s) older than ${retentionDays}d`);
}

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
    // Postgres has no DELETE … LIMIT — delete via a bounded id subquery instead.
    const del = await pool.query(
      `DELETE FROM radpostauth WHERE id IN (SELECT id FROM radpostauth WHERE authdate < $1 ORDER BY id ASC LIMIT 10000)`,
      [cutoff],
    );
    deletedTotal += del.rowCount ?? 0;
    if ((del.rowCount ?? 0) < 10000) break;
  }
  if (deletedTotal > 0) console.log(`[radius-monitor] pruned ${deletedTotal} radpostauth row(s) older than ${retentionDays}d`);
}

export function startRadiusMonitorWorker(): () => void {
  initWorker('radiusMonitor', LEADER_KEYS.radiusMonitor);
  // eslint-disable-next-line no-console
  console.log('[radius-monitor] worker started (probe + auth-fail audit + slave monitoring every 60s, leader-gated)');

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
      try {
        await pollSlaveTargets();
      } catch (err) {
        // Slave monitoring is best-effort — it must never kill the probe cadence.
        console.error('[radius-monitor] slave polling failed:', err);
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
