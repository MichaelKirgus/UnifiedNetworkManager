import { Router, Request, Response } from 'express';
import { and, asc, desc, eq, ilike, inArray, like, ne } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { PROBE_USERNAME } from '../radius/probe';
import { getEffectiveSettingValue } from '../systemSettings';
import { requireAuth, requirePermission } from '../auth/middleware';

/**
 * RADIUS NAS clients + user profiles (the unm-radius sidecar — FreeRADIUS EAP-TLS).
 *
 *   GET /radius/nas-clients      -> list NAS clients (+ resolved secret metadata)
 *   GET /radius/user-profiles    -> list per-user reply profiles (+ cert name)
 *   GET /radius/status           -> latest probe outcome + 24h accept/reject counters
 *   GET /radius/auth-log         -> recent radpostauth rows (the failed-login audit trail)
 *
 * All MUTATIONS (NAS-client and profile create/update/delete, incl. bulk) are
 * plan-gated: the webapp creates a system plan via POST /plans/system with an
 * intentActionId like radius.nas-client.create or radius.profile.bulk-delete and
 * executes it through the 2FA-gated plan workflow. The executor runs the shared
 * functions in api/src/radius/mutations.ts locally (no device, no plugin). This
 * makes every RADIUS change auditable, retryable, schedulable and automatable —
 * there is deliberately NO direct mutation route left that bypasses the 2FA gate.
 *
 * The shared secret is NEVER stored here — each row references a secrets.id
 * (same pattern as device_plugins.secretId). At render time api/src/radius/
 * resolves + decrypts it via the owning provider. Reading requires `radius:read`;
 * mutations require `radius:write` (checked on plan creation AND execution).
 */

const router = Router();

/** A NAS client row enriched with its secret's display metadata (no values). */
export interface RadiusNasClientView {
  id: string;
  name: string | null;
  ip: string;
  secretId: string | null;
  /** Display label of the referenced secret (metadata only — never the value). */
  secretLabel: string | null;
  /** The secret's type (e.g. 'apiKeyNoSecret', 'tunnelPsk') for the picker UI. */
  secretType: string | null;
  createdAt: string;
}

type Row = typeof schema.radiusNasClients.$inferSelect;

/** Resolves each row's secret label + type from the secrets table (one query). */
async function toViews(rows: Row[]): Promise<RadiusNasClientView[]> {
  const ids = rows.map((r) => r.secretId).filter((s): s is string => Boolean(s));
  const meta = new Map<string, { label: string | null; type: string }>();
  if (ids.length > 0) {
    const secrets = await db.query.secrets.findMany({ where: inArray(schema.secrets.id, ids) });
    for (const s of secrets) meta.set(s.id, { label: s.label, type: s.type });
  }
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    ip: r.ip,
    secretId: r.secretId,
    secretLabel: r.secretId && meta.has(r.secretId) ? (meta.get(r.secretId)?.label ?? null) : null,
    secretType: r.secretId && meta.has(r.secretId) ? (meta.get(r.secretId)?.type ?? null) : null,
    createdAt: r.createdAt,
  }));
}

// GET /radius/nas-clients — list all NAS clients with resolved secret metadata.
router.get(
  '/radius/nas-clients',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const rows = await db.query.radiusNasClients.findMany({ orderBy: [asc(schema.radiusNasClients.ip)] });
    res.status(200).json(await toViews(rows));
  }
);

// NOTE: NAS-client mutations (create/update/delete, incl. bulk) are NOT direct
// routes anymore — they flow through the plan workflow so every change is
// 2FA-gated, audited and automatable. The webapp creates a system plan via
// POST /plans/system with intentActionId radius.nas-client.{create|update|delete}
// (or .bulk-delete) and executes it; the executor runs the shared functions in
// radius/mutations.ts locally. See api/src/plans/systemActions.ts.

/**
 * Per-user RADIUS reply profiles (VLAN / static IP / session limits) keyed by
 * client cert serial. The exec script reads this table at auth time and prints
 * the set fields as reply attributes — see radiusConfig.renderUserProfileScript.
 *
 *   GET    /radius/user-profiles      -> list all (+ resolved cert name)
 *
 * Mutations (create/update/delete, incl. bulk) flow through the plan workflow
 * like NAS clients: POST /plans/system with intentActionId
 * radius.profile.{create|update|delete} (or .bulk-delete), executed by the
 * executor via radius/mutations.ts. See api/src/plans/systemActions.ts.
 */
export interface RadiusUserProfileView {
  id: string;
  serial: string;
  name: string | null;
  /** Display label of the matching wifi_client_certs row (metadata only). */
  certName: string | null;
  vlanId: number | null;
  framedIp: string | null;
  framedIpv6: string | null;
  sessionTimeoutSec: number | null;
  idleTimeoutSec: number | null;
  replyMessage: string | null;
  createdAt: string;
}

type ProfileRow = typeof schema.radiusUserProfiles.$inferSelect;

/** Resolves each row's cert name from wifi_client_certs (one query). */
async function toProfileViews(rows: ProfileRow[]): Promise<RadiusUserProfileView[]> {
  const serials = rows.map((r) => r.serial);
  const names = new Map<string, string>();
  if (serials.length > 0) {
    const certs = await db.query.wifiClientCerts.findMany({ where: inArray(schema.wifiClientCerts.serial, serials) });
    for (const c of certs) names.set(c.serial.toLowerCase(), c.name);
  }
  return rows.map((r) => ({
    id: r.id,
    serial: r.serial,
    name: r.name,
    certName: names.get(r.serial.toLowerCase()) ?? null,
    vlanId: r.vlanId,
    framedIp: r.framedIp,
    framedIpv6: r.framedIpv6,
    sessionTimeoutSec: r.sessionTimeoutSec,
    idleTimeoutSec: r.idleTimeoutSec,
    replyMessage: r.replyMessage,
    createdAt: r.createdAt,
  }));
}

// GET /radius/user-profiles — list all profiles with resolved cert names.
router.get(
  '/radius/user-profiles',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const rows = await db.query.radiusUserProfiles.findMany({ orderBy: [asc(schema.radiusUserProfiles.serial)] });
    res.status(200).json(await toProfileViews(rows));
  }
);

// NOTE: profile mutations are plan-gated like NAS clients — see the note above.

/**
 * RADIUS self-monitoring + auth log (unsuccessful-login audit trail).
 *
 *   GET /radius/status     -> latest probe outcome of the radiusMonitor worker
 *                             (+ whether RADIUS is enabled) — no secret material.
 *   GET /radius/auth-log   -> recent radpostauth rows (one per completed auth
 *                             attempt, accept AND reject), newest first, with
 *                             optional result/username filters + limit.
 *
 * Both are read-only and require `radius:read`. The probe client's shared
 * secret is NEVER exposed here — only the outcome of probing with it.
 */

// GET /radius/status — latest self-monitoring state (probe outcome + counters).
router.get(
  '/radius/status',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    const [stateRes] = await Promise.all([pool.query(`SELECT * FROM radius_monitor_state WHERE id = $1`, ['unm'])]);
    const s = stateRes.rows[0];

    // Recent auth-attempt counters for the last 24h (cheap — indexed by id/authdate).
    // The probe's own test requests are excluded: they are UNM's heartbeat, not
    // real login attempts (they would otherwise count as a reject every minute).
    const counts = await pool.query(
      `SELECT count(*) FILTER (WHERE reply LIKE 'Access-Reject%') AS rejects,
              count(*) FILTER (WHERE reply LIKE 'Access-Accept%') AS accepts,
              max(authdate) AS "lastAttemptAt"
       FROM radpostauth
       WHERE authdate > now() - interval '24 hours' AND username <> $1`,
      [PROBE_USERNAME]
    );
    const c = counts.rows[0];

    const enabled = String(await getEffectiveSettingValue('radiusEnabled')) !== 'false';
    res.status(200).json({
      enabled,
      probe: s
        ? {
            lastProbeAt: s['lastProbeAt'] as string | null,
            outcome: (s['probeOutcome'] as string | null) ?? null, // ok | bad-auth | timeout
            packetType: (s['packetType'] as string | null) ?? null,
            latencyMs: s['latencyMs'] != null ? Number(s['latencyMs']) : null,
            detail: (s['detail'] as string | null) ?? null,
          }
        : null, // worker has not run yet (or RADIUS was just enabled)
      last24h: {
        rejects: Number(c?.rejects ?? 0),
        accepts: Number(c?.accepts ?? 0),
        lastAttemptAt: c?.lastAttemptAt ? new Date(c.lastAttemptAt).toISOString() : null,
      },
    });
  }
);

// GET /radius/auth-log — recent auth attempts (the failed-login audit trail).
router.get(
  '/radius/auth-log',
  requireAuth,
  requirePermission('radius:read'),
  async (req: Request, res: Response) => {
    const limit = Math.min(500, Math.max(1, Number(req.query.limit ?? 100) || 100));
    const result = String(req.query.result ?? ''); // '' | 'reject' | 'accept'
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';

    const clauses: Array<ReturnType<typeof like>> = [ne(schema.radpostauth.username, PROBE_USERNAME)]; // heartbeat rows are not logins
    if (result === 'reject') clauses.push(like(schema.radpostauth.reply, 'Access-Reject%'));
    else if (result === 'accept') clauses.push(like(schema.radpostauth.reply, 'Access-Accept%'));
    if (search) clauses.push(ilike(schema.radpostauth.username, `%${search}%`));

    const rows = await db.query.radpostauth.findMany({
      where: clauses.length > 0 ? and(...clauses) : undefined,
      orderBy: [desc(schema.radpostauth.id)],
      limit,
    });
    res.status(200).json(
      rows.map((r) => ({
        id: Number(r.id),
        username: r.username,
        result: (r.reply ?? '').startsWith('Access-Reject') ? 'reject' : (r.reply ?? '').startsWith('Access-Accept') ? 'accept' : (r.reply ?? null),
        calledStationId: r.calledStationId,
        callingStationId: r.callingStationId,
        authdate: r.authdate instanceof Date ? r.authdate.toISOString() : String(r.authdate),
      }))
    );
  }
);

/**
 * RADIUS failover — slave monitoring (read-only).
 *
 *   GET /radius/slaves            -> every enabled PUSH replication target that
 *                                    carries the `radius` section, with its last
 *                                    sync state + the radiusMonitor worker's
 *                                    latest poll snapshot (probe outcome, 24h
 *                                    counters) from radius_slave_monitor.
 *   GET /radius/slaves/:id/events -> auth attempts MIRRORED from that slave
 *                                    (best-effort copy of its radpostauth),
 *                                    newest first — the failed-login audit trail
 *                                    for a failover slave, visible on the primary.
 *
 * Both require `radius:read`. Peer tokens / passphrases are never returned.
 */

// GET /radius/slaves — monitoring snapshot per failover slave (replication target).
router.get(
  '/radius/slaves',
  requireAuth,
  requirePermission('radius:read'),
  async (_req: Request, res: Response) => {
    // NOTE: quoted camelCase — unquoted identifiers fold to lowercase.
    const targets = await pool.query(
      `SELECT id, name, "baseUrl", direction, "intervalMinutes", "lastSyncAt", "lastSyncStatus", sections
       FROM replication_targets WHERE enabled = true AND direction = 'push'`
    );
    const monitors = await pool.query(`SELECT * FROM radius_slave_monitor`);
    const byId = new Map(monitors.rows.map((m) => [String(m.id), m]));

    res.status(200).json({
      slaves: targets.rows
        .filter((t) => {
          // NULL/empty sections = all portable sections (incl. radius); else explicit list.
          const raw = t.sections as string | null;
          if (raw == null || raw === '') return true;
          try {
            const list = JSON.parse(raw);
            return Array.isArray(list) && (list.length === 0 || list.includes('radius'));
          } catch {
            return false;
          }
        })
        .map((t) => {
          const m = byId.get(String(t.id));
          return {
            targetId: String(t.id),
            name: String(t.name),
            baseUrl: String(t.baseUrl),
            intervalMinutes: t['intervalMinutes'] != null ? Number(t['intervalMinutes']) : null,
            lastSyncAt: (t.lastSyncAt as string | null) ?? null,
            lastSyncStatus: (t.lastSyncStatus as string | null) ?? null, // ok | error | null (never synced yet)
            monitor: m
              ? {
                  lastCheckAt: (m['lastCheckAt'] as string | null) ?? null,
                  reachable: Boolean(m['reachable']),
                  radiusEnabled: m['radiusEnabled'] != null ? Boolean(m['radiusEnabled']) : null,
                  probeOutcome: (m['probeOutcome'] as string | null) ?? null, // ok | bad-auth | timeout | null
                  packetType: (m['packetType'] as string | null) ?? null,
                  latencyMs: m['latencyMs'] != null ? Number(m['latencyMs']) : null,
                  detail: (m['detail'] as string | null) ?? null,
                  accepts24h: m['accepts24h'] != null ? Number(m['accepts24h']) : 0,
                  rejects24h: m['rejects24h'] != null ? Number(m['rejects24h']) : 0,
                  lastAttemptAt: (m['lastAttemptAt'] as string | null) ?? null,
                  error: (m['error'] as string | null) ?? null,
                }
              : null, // worker has not polled this target yet
          };
        }),
    });
  }
);

// GET /radius/slaves/:id/events — mirrored auth attempts from one slave.
router.get(
  '/radius/slaves/:id/events',
  requireAuth,
  requirePermission('radius:read'),
  async (req: Request, res: Response) => {
    const targetId = String(req.params.id ?? '');
    const limit = Math.min(500, Math.max(1, Number(req.query.limit ?? 100) || 100));
    const result = String(req.query.result ?? ''); // '' | 'reject' | 'accept'

    // Verify the target exists (and is a push target — only those are slaves).
    const tRes = await pool.query(`SELECT id FROM replication_targets WHERE id = $1 AND direction = 'push'`, [targetId]);
    if (tRes.rows.length === 0) {
      res.status(404).json({ error: `No such RADIUS slave target "${targetId}"` });
      return;
    }

    const clauses: string[] = [`"targetId" = $1`];
    const params: unknown[] = [targetId];
    if (result === 'reject' || result === 'accept') {
      params.push(result);
      clauses.push(`"result" = $${params.length}`);
    }
    params.push(limit);

    const rows = await pool.query(
      `SELECT id, "targetId", username, "result", "calledStationId", "callingStationId", authdate
       FROM radius_slave_auth_events WHERE ${clauses.join(' AND ')}
       ORDER BY authdate DESC, id DESC LIMIT $${params.length}`,
      params
    );
    res.status(200).json({
      targetId,
      events: rows.rows.map((r) => ({
        id: Number(r.id),
        username: String(r.username),
        result: (r['result'] as string | null) ?? null,
        calledStationId: (r['calledStationId'] as string | null) ?? null,
        callingStationId: (r['callingStationId'] as string | null) ?? null,
        authdate: r.authdate instanceof Date ? r.authdate.toISOString() : String(r.authdate),
      })),
    });
  }
);

export default router;
