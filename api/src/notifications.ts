import { v4 as uuidv4 } from 'uuid';
import { and, eq, ilike, inArray, or, sql } from 'drizzle-orm';
import { db, pool } from './db';
import * as schema from './db/schema';

/**
 * Notification center — shared service used by the API workers (device status
 * transitions, plan/config-job failures), the plugin push endpoint and the
 * public read routes.
 *
 * Design goals:
 *   - SCALABLE: emitters never block on notification work beyond one small DB
 *     write; all heavy lifting (auto-resolve sweeps, retention) lives in the
 *     leader-gated notifications worker (workers/notifications.ts).
 *   - DEDUPLICATED: an ongoing condition carries a stable `dedupeKey` and is
 *     upserted while it persists (occurrences++ / lastSeenAt refresh) instead
 *     of flooding the bell. One-shot events use unique keys.
 *   - USER-SCOPED VIEW: per-user visibility prefs (notification_prefs) filter
 *     what counts toward the badge and shows in the panel; the full history is
 *     always available on the Notifications page with filters.
 */

export const NOTIFICATION_SEVERITIES = ['info', 'warning', 'critical'] as const;
export type NotificationSeverity = (typeof NOTIFICATION_SEVERITIES)[number];

export const NOTIFICATION_SOURCES = ['system', 'device', 'plugin'] as const;
export type NotificationSource = (typeof NOTIFICATION_SOURCES)[number];

export const NOTIFICATION_STATUSES = ['open', 'acknowledged', 'resolved', 'closed'] as const;
export type NotificationStatus = (typeof NOTIFICATION_STATUSES)[number];

const SEVERITY_RANK: Record<NotificationSeverity, number> = { info: 0, warning: 1, critical: 2 };

/** Default visibility: everything from every source is visible. */
export const DEFAULT_VISIBILITY: Record<string, string[]> = {
  system: [...NOTIFICATION_SEVERITIES],
  device: [...NOTIFICATION_SEVERITIES],
  plugin: [...NOTIFICATION_SEVERITIES],
};

export interface EmitNotificationInput {
  severity: NotificationSeverity;
  source: NotificationSource;
  title: string;
  message?: string;
  /** Stable identity of an ongoing condition — omit for one-shot events. */
  dedupeKey?: string | null;
  pluginId?: string | null;
  deviceId?: string | null;
  context?: Record<string, unknown> | null;
}

export interface NotificationRow {
  id: string;
  dedupeKey: string | null;
  severity: NotificationSeverity;
  source: NotificationSource;
  pluginId: string | null;
  deviceId: string | null;
  title: string;
  message: string;
  context: Record<string, unknown> | null;
  createdAt: string;
  lastSeenAt: string;
  occurrences: number;
  status: NotificationStatus;
  acknowledgedBy: string | null;
  acknowledgedAt: string | null;
  resolvedAt: string | null;
}

function safeParseContext(s: string | null): Record<string, unknown> | null {
  if (!s) return null;
  try {
    const v = JSON.parse(s);
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function serialize(row: typeof schema.notifications.$inferSelect): NotificationRow {
  return {
    id: row.id,
    dedupeKey: row.dedupeKey,
    severity: row.severity as NotificationSeverity,
    source: row.source as NotificationSource,
    pluginId: row.pluginId,
    deviceId: row.deviceId,
    title: row.title,
    message: row.message ?? '',
    context: safeParseContext(row.context),
    createdAt: row.createdAt,
    lastSeenAt: row.lastSeenAt,
    occurrences: row.occurrences ?? 1,
    status: row.status as NotificationStatus,
    acknowledgedBy: row.acknowledgedBy,
    acknowledgedAt: row.acknowledgedAt,
    resolvedAt: row.resolvedAt,
  };
}

/**
 * Emit a notification with dedupe semantics. NEVER throws — a notification
 * failure must not break the emitter (poll cycle, plan step, plugin push).
 * Returns the stored id (existing or new) for chaining, or null on failure.
 */
export async function emitNotification(input: EmitNotificationInput): Promise<string | null> {
  try {
    const now = new Date().toISOString();
    const severity = NOTIFICATION_SEVERITIES.includes(input.severity) ? input.severity : 'info';
    const source = NOTIFICATION_SOURCES.includes(input.source) ? input.source : 'system';
    const title = String(input.title ?? '').slice(0, 300);
    if (!title) return null;
    const message = String(input.message ?? '').slice(0, 2000);
    const contextJson = input.context && Object.keys(input.context).length > 0 ? JSON.stringify(input.context) : null;

    // Dedupe: an unresolved row with the same key is refreshed in place.
    if (input.dedupeKey) {
      const existing = await db.query.notifications.findFirst({
        where: and(
          eq(schema.notifications.dedupeKey, input.dedupeKey),
          inArray(schema.notifications.status, ['open', 'acknowledged'])
        ),
      });
      if (existing) {
        // Never downgrade the severity of a live condition.
        const newSeverity =
          SEVERITY_RANK[severity] > SEVERITY_RANK[(existing.severity as NotificationSeverity)] ? severity : existing.severity;
        await db.update(schema.notifications)
          .set({
            lastSeenAt: now,
            occurrences: sql`"occurrences" + 1`,
            severity: newSeverity,
            message,
            context: contextJson ?? existing.context,
          })
          .where(eq(schema.notifications.id, existing.id));
        return existing.id;
      }
    }

    try {
      const id = uuidv4();
      await db.insert(schema.notifications).values({
        id,
        dedupeKey: input.dedupeKey ?? null,
        severity,
        source,
        pluginId: input.pluginId ?? null,
        deviceId: input.deviceId ?? null,
        title,
        message,
        context: contextJson,
        createdAt: now,
        lastSeenAt: now,
        occurrences: 1,
        status: 'open',
      });
      return id;
    } catch (err) {
      // Lost a dedupe race (another replica inserted the same key first) —
      // fall back to refreshing whichever row won.
      if (!input.dedupeKey || !(err instanceof Error)) throw err;
      const winner = await db.query.notifications.findFirst({
        where: and(
          eq(schema.notifications.dedupeKey, input.dedupeKey),
          inArray(schema.notifications.status, ['open', 'acknowledged'])
        ),
      });
      if (winner) return winner.id;
      throw err;
    }
  } catch {
    // Notifications are best-effort by contract.
    return null;
  }
}

/** Resolve a notification (condition cleared). No-op when already terminal. */
export async function resolveNotification(id: string): Promise<void> {
  await db.update(schema.notifications)
    .set({ status: 'resolved', resolvedAt: new Date().toISOString() })
    .where(and(eq(schema.notifications.id, id), inArray(schema.notifications.status, ['open', 'acknowledged'])));
}

/** Resolve many notifications at once (bulk "condition fixed"). Returns the number of rows actually transitioned. */
export async function resolveNotifications(ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  const now = new Date().toISOString();
  const placeholders = ids.map((_, i) => `$${i + 2}`).join(', ');
  const result = await pool.query(
    `UPDATE notifications SET status = 'resolved', "resolvedAt" = $1
     WHERE id IN (${placeholders}) AND status IN ('open', 'acknowledged')`,
    [now, ...ids]
  );
  return result.rowCount ?? 0;
}

/**
 * Resolve every live row whose dedupeKey is in the list. Used by plugins that
 * track ongoing conditions themselves (e.g. TrueNAS alerts): when an alert
 * disappears from `alert.list`, the plugin reports it and the row resolves —
 * mirroring the appliance's own lifecycle into the notification center.
 */
export async function resolveNotificationsByDedupeKeys(keys: string[]): Promise<number> {
  if (keys.length === 0) return 0;
  const now = new Date().toISOString();
  const placeholders = keys.map((_, i) => `$${i + 2}`).join(', ');
  const result = await pool.query(
    `UPDATE notifications SET status = 'resolved', "resolvedAt" = $1
     WHERE "dedupeKey" IN (${placeholders}) AND "status" IN ('open', 'acknowledged')`,
    [now, ...keys]
  );
  return result.rowCount ?? 0;
}

/** Acknowledge (seen) — keeps the row visible but out of the badge count. */
export async function acknowledgeNotifications(ids: string[], userId: string): Promise<number> {
  if (ids.length === 0) return 0;
  const now = new Date().toISOString();
  // Raw UPDATE so we can report rowCount (drizzle's update doesn't expose it).
  const placeholders = ids.map((_, i) => `$${i + 3}`).join(', ');
  const result = await pool.query(
    `UPDATE notifications SET status = 'acknowledged', "acknowledgedBy" = $1, "acknowledgedAt" = $2
     WHERE id IN (${placeholders}) AND status = 'open'`,
    [userId, now, ...ids]
  );
  return result.rowCount ?? 0;
}

/** Close (dismiss from view entirely). */
export async function closeNotifications(ids: string[]): Promise<number> {
  if (ids.length === 0) return 0;
  const placeholders = ids.map((_, i) => `$${i + 1}`).join(', ');
  const result = await pool.query(
    `UPDATE notifications SET status = 'closed' WHERE id IN (${placeholders})`,
    [...ids]
  );
  return result.rowCount ?? 0;
}

/** Acknowledge every currently-open notification at once. */
export async function acknowledgeAllOpen(userId: string): Promise<number> {
  const rows = await db.query.notifications.findMany({ where: eq(schema.notifications.status, 'open') });
  if (rows.length === 0) return 0;
  const now = new Date().toISOString();
  await db.update(schema.notifications)
    .set({ status: 'acknowledged', acknowledgedBy: userId, acknowledgedAt: now })
    .where(eq(schema.notifications.status, 'open'));
  return rows.length;
}

/** Load (and normalize) a user's visibility prefs. Missing row = defaults. */
export async function getVisibilityPrefs(userId: string): Promise<Record<string, string[]>> {
  const row = await db.query.notificationPrefs.findFirst({ where: eq(schema.notificationPrefs.userId, userId) });
  if (!row) return structuredClone(DEFAULT_VISIBILITY);
  let parsed: unknown;
  try {
    parsed = JSON.parse(row.visibility);
  } catch {
    return structuredClone(DEFAULT_VISIBILITY);
  }
  const out: Record<string, string[]> = {};
  for (const source of NOTIFICATION_SOURCES) {
    const list = Array.isArray((parsed as Record<string, unknown>)?.[source])
      ? ((parsed as Record<string, unknown>)[source] as unknown[]).filter(
          (s): s is NotificationSeverity => typeof s === 'string' && NOTIFICATION_SEVERITIES.includes(s as NotificationSeverity)
        )
      : [...NOTIFICATION_SEVERITIES];
    out[source] = list;
  }
  return out;
}

/** Persist a user's visibility prefs (validated to known sources/severities). */
export async function setVisibilityPrefs(userId: string, visibility: Record<string, unknown>): Promise<Record<string, string[]>> {
  const clean: Record<string, string[]> = {};
  for (const source of NOTIFICATION_SOURCES) {
    const list = Array.isArray(visibility?.[source])
      ? (visibility[source] as unknown[]).filter(
          (s): s is NotificationSeverity => typeof s === 'string' && NOTIFICATION_SEVERITIES.includes(s as NotificationSeverity)
        )
      : [...NOTIFICATION_SEVERITIES]; // omitted source = show everything for it
    clean[source] = list;
  }
  const now = new Date().toISOString();
  await db.insert(schema.notificationPrefs)
    .values({ userId, visibility: JSON.stringify(clean), updatedAt: now })
    .onConflictDoUpdate({ target: [schema.notificationPrefs.userId], set: { visibility: JSON.stringify(clean), updatedAt: now } });
  return clean;
}

/** True when the user's prefs allow this notification to show. */
export function isVisibleFor(severity: NotificationSeverity, source: NotificationSource, prefs: Record<string, string[]>): boolean {
  const allowed = prefs[source] ?? NOTIFICATION_SEVERITIES;
  return allowed.includes(severity);
}

/** Count of OPEN notifications visible to the user (the bell badge). */
export async function countOpenForUser(userId: string): Promise<number> {
  const prefs = await getVisibilityPrefs(userId);
  const clauses = [];
  for (const source of NOTIFICATION_SOURCES) {
    const allowed = prefs[source];
    if (allowed.length === 0) continue; // hidden entirely
    clauses.push(and(eq(schema.notifications.source, source), inArray(schema.notifications.severity, allowed)));
  }
  if (clauses.length === 0) return 0;
  const rows = await db.query.notifications.findMany({
    where: and(eq(schema.notifications.status, 'open'), or(...clauses)),
    columns: { id: true },
  });
  return rows.length;
}

export interface ListNotificationsParams {
  status?: NotificationStatus | string; // comma list allowed
  severity?: string; // comma list allowed
  source?: string;
  deviceId?: string;
  pluginId?: string;
  search?: string;
  limit?: number;
  /** When true, only rows visible to the user's prefs are returned. */
  respectPrefs?: boolean;
}

/** List notifications (newest first) with optional filters + name enrichment. */
export async function listNotifications(
  params: ListNotificationsParams,
  userId?: string
): Promise<Array<NotificationRow & { deviceName?: string | null; pluginName?: string | null }>> {
  const limit = Math.min(500, Math.max(1, Number(params.limit ?? 200) || 200));

  const statuses = (params.status ?? 'open,acknowledged')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const severities = (params.severity ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  const sources = (params.source ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  let prefs: Record<string, string[]> | null = null;
  if (params.respectPrefs && userId) {
    prefs = await getVisibilityPrefs(userId);
  }

  const clauses = [];
  if (statuses.length > 0) clauses.push(inArray(schema.notifications.status, statuses));
  if (severities.length === 1) clauses.push(eq(schema.notifications.severity, severities[0]));
  else if (severities.length > 1) clauses.push(inArray(schema.notifications.severity, severities));
  if (sources.length === 1) clauses.push(eq(schema.notifications.source, sources[0]));
  else if (sources.length > 1) clauses.push(inArray(schema.notifications.source, sources));
  if (params.deviceId) clauses.push(eq(schema.notifications.deviceId, params.deviceId));
  if (params.pluginId) clauses.push(eq(schema.notifications.pluginId, params.pluginId));
  if (params.search) {
    const pattern = `%${params.search}%`;
    clauses.push(or(ilike(schema.notifications.title, pattern), ilike(schema.notifications.message, pattern)));
  }
  if (prefs) {
    // Visibility filter: per-source severity allow-lists.
    const visClauses = [];
    for (const source of NOTIFICATION_SOURCES) {
      const allowed = prefs[source];
      if (allowed.length === 0) continue;
      visClauses.push(and(eq(schema.notifications.source, source), inArray(schema.notifications.severity, allowed)));
    }
    if (visClauses.length > 0) clauses.push(or(...visClauses));
  }

  const rows = await db.query.notifications.findMany({
    ...(clauses.length > 0 ? { where: and(...clauses) } : {}),
    orderBy: [sql`"lastSeenAt" DESC`, sql`"createdAt" DESC`],
    limit,
  });

  // Enrich with display names (same batch pattern as routes/logs.ts).
  const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId).filter((d): d is string => !!d)));
  const pluginIds = Array.from(new Set(rows.map((r) => r.pluginId).filter((p): p is string => !!p)));
  const [devices, plugins] = await Promise.all([
    deviceIds.length > 0 ? db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }) : [],
    pluginIds.length > 0 ? db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }) : [],
  ]);
  const deviceNameById = new Map(devices.map((d) => [d.id, d.name] as const));
  const pluginNameById = new Map(plugins.map((p) => [p.id, p.name] as const));

  return rows.map((r) => ({
    ...serialize(r),
    deviceName: r.deviceId ? (deviceNameById.get(r.deviceId) ?? null) : null,
    pluginName: r.pluginId ? (pluginNameById.get(r.pluginId) ?? null) : null,
  }));
}

/**
 * Auto-resolve sweep for mirrored device-state notifications. A row whose
 * dedupeKey is `device-status:<deviceId>:<state>` stays live only while the
 * device's CURRENT status equals <state>; otherwise it resolves itself.
 * Returns the number of rows resolved (for worker stats).
 */
export async function autoResolveStaleDeviceNotifications(): Promise<number> {
  const candidates = await db.query.notifications.findMany({
    where: and(
      inArray(schema.notifications.status, ['open', 'acknowledged']),
      eq(schema.notifications.source, 'device'),
      sql`"dedupeKey" LIKE 'device-status:%'`
    ),
  });
  if (candidates.length === 0) return 0;

  const deviceIds = Array.from(new Set(candidates.map((c) => c.deviceId).filter((d): d is string => !!d)));
  const devices =
    deviceIds.length > 0 ? await db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }) : [];
  const statusById = new Map(devices.map((d) => [d.id, d.status] as const));

  let resolved = 0;
  for (const row of candidates) {
    if (!row.deviceId) continue;
    const state = row.dedupeKey?.split(':').pop() ?? '';
    const current = statusById.get(row.deviceId);
    // Device gone or no longer in the bad state → condition cleared.
    if (current === undefined || current !== state) {
      await resolveNotification(row.id);
      resolved++;
    }
  }
  return resolved;
}

/** Retention sweep: drop terminal rows older than the cutoff. */
export async function pruneOldNotifications(cutoffIso: string): Promise<number> {
  const result = await pool.query(
    `DELETE FROM notifications WHERE "status" IN ('resolved', 'closed') AND "createdAt" < $1`,
    [cutoffIso]
  );
  return result.rowCount ?? 0;
}

/** Convenience: is this severity worth mirroring a device status change for? */
export function statusToSeverity(status: string): NotificationSeverity | null {
  switch (status) {
    case 'offline':
      return 'critical';
    case 'critical':
      return 'critical';
    case 'degraded':
      return 'warning';
    default:
      return null; // online / unknown — no notification
  }
}

/** Convenience: the dedupe key for a device-status condition. */
export function deviceStatusDedupeKey(deviceId: string, status: string): string {
  return `device-status:${deviceId}:${status}`;
}
