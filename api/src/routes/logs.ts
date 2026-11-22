import { Router, Response } from 'express';
import { and, asc, desc, eq, gte, inArray, ilike, lt, or, sql } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { envelopePage, hasPaginationParams, limitOffset, parsePagination, type ParsedPagination } from '../utils/pagination';

/**
 * Public read side of the plugin log pipeline (ingest lives in routes/internal.ts).
 * Powers two webapp views: the global Logs page and the per-device Logs section
 * in DeviceDetail. Gated by `logs:read` — logs can carry critical details
 * (endpoints, error payloads), so they do not ride on devices:read.
 */

const router = Router();

const LOG_LEVELS = ['debug', 'info', 'warn', 'error'];
const DEFAULT_LIMIT = 500;
const MAX_LIMIT = 2000;

// GET /logs - plugin log entries, newest first.
// Query params: deviceId?, pluginId?, level? (comma list), search? (ILIKE on
// message + context), from?/to? (ISO timestamps), limit (default 500, max 2000).
// Paged mode — when page/pageSize/all is present the response becomes an
// envelope {rows,total,page,pageSize} (legacy callers keep the plain array);
// sort=emittedAt&dir=asc|desc flips the time order.
router.get(
  '/logs',
  requireAuth,
  requirePermission('logs:read'),
  async (_req, res: Response) => {
    try {
      const q = _req.query as Record<string, string | undefined>;

      // Paged mode — envelope response; legacy calls keep the plain array.
      const paged = hasPaginationParams(q);
      let pg: ParsedPagination | null = null;
      if (paged) {
        const parsed = parsePagination(q, { defaultPageSize: 50, maxPageSize: 200 });
        if ('error' in parsed) {
          res.status(400).json({ error: parsed.error });
          return;
        }
        pg = parsed;
      }

      // Time is the only meaningful sort axis for logs — anything else is a 400.
      let orderDir: 'asc' | 'desc' = 'desc';
      if (q.sort !== undefined) {
        if (q.sort !== 'emittedAt') {
          res.status(400).json({ error: `"sort" must be "emittedAt"` });
          return;
        }
        if (q.dir && !['asc', 'desc'].includes(q.dir)) {
          res.status(400).json({ error: '"dir" must be "asc" or "desc"' });
          return;
        }
        orderDir = q.dir === 'asc' ? 'asc' : 'desc';
      }

      const levels = (q.level ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      for (const l of levels) {
        if (!LOG_LEVELS.includes(l)) {
          res.status(400).json({ error: `"level" must be a comma list of: ${LOG_LEVELS.join(', ')}` });
          return;
        }
      }

      const limit = Math.min(MAX_LIMIT, Math.max(1, Number(q.limit ?? DEFAULT_LIMIT) || DEFAULT_LIMIT));

      const clauses = [];
      if (q.deviceId) clauses.push(eq(schema.pluginLogs.deviceId, q.deviceId));
      if (q.pluginId) clauses.push(eq(schema.pluginLogs.pluginId, q.pluginId));
      if (levels.length === 1) {
        clauses.push(eq(schema.pluginLogs.level, levels[0]));
      } else if (levels.length > 1) {
        clauses.push(inArray(schema.pluginLogs.level, levels));
      }
      if (q.search) {
        const pattern = `%${q.search}%`;
        clauses.push(or(ilike(schema.pluginLogs.message, pattern), ilike(schema.pluginLogs.context, pattern)));
      }
      if (q.from) clauses.push(gte(schema.pluginLogs.emittedAt, q.from));
      if (q.to) clauses.push(lt(schema.pluginLogs.emittedAt, q.to));

      // Device-level access control — scoped callers only see logs of their own
      // devices. Device-less plugin logs are excluded for them too (they may
      // reference any device); unrestricted callers keep the full view.
      const allowed = await allowedDeviceIds(_req);
      if (allowed !== null) {
        if (q.deviceId && !allowed.has(q.deviceId)) {
          res.status(200).json([]);
          return;
        }
        clauses.push(inArray(schema.pluginLogs.deviceId, [...allowed]));
      }

      // Paged: LIMIT/OFFSET from the parsed params (null = all-mode, unbounded);
      // legacy: the old limit cap. The total count only runs in paged mode.
      const lo = pg ? limitOffset(pg) : null;
      const where = clauses.length > 0 ? and(...clauses) : undefined;
      const [rows, countRow] = await Promise.all([
        db.query.pluginLogs.findMany({
          ...(where ? { where } : {}),
          orderBy: orderDir === 'asc' ? [asc(schema.pluginLogs.emittedAt)] : [desc(schema.pluginLogs.emittedAt)],
          ...(pg ? (lo ? { limit: lo.limit, offset: lo.offset } : {}) : { limit }),
        }),
        paged ? db.select({ n: sql<number>`count(*)::int` }).from(schema.pluginLogs).where(where) : null,
      ]);
      const total = countRow ? Number(countRow[0]?.n ?? 0) : null;

      // Batch-load display names so the webapp can render plugin/device chips
      // without extra round-trips (same pattern as routes/networks.ts).
      const deviceIds = Array.from(new Set(rows.map((r) => r.deviceId).filter((d): d is string => !!d)));
      const pluginIds = Array.from(new Set(rows.map((r) => r.pluginId)));
      const [devices, plugins] = await Promise.all([
        deviceIds.length > 0 ? db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }) : [],
        pluginIds.length > 0 ? db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }) : [],
      ]);
      const deviceNameById = new Map(devices.map((d) => [d.id, d.name] as const));
      const pluginNameById = new Map(plugins.map((p) => [p.id, p.name] as const));

      const mapped = rows.map((r) => ({
        id: r.id,
        pluginId: r.pluginId,
        pluginName: pluginNameById.get(r.pluginId) ?? null,
        deviceId: r.deviceId,
        deviceName: r.deviceId ? (deviceNameById.get(r.deviceId) ?? null) : null,
        level: r.level,
        message: r.message,
        context: r.context ? safeParseJson(r.context) : null,
        emittedAt: r.emittedAt,
      }));

      // Paged mode → envelope; legacy callers keep the plain array.
      if (pg && total !== null) {
        res.status(200).json({ rows: mapped, total, ...envelopePage(pg, total) });
      } else {
        res.status(200).json(mapped);
      }
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

// GET /logs/unified - ONE time-ordered table over BOTH log sources for the Logs
// page: plugin operational logs (plugin_logs, POST /plugin/logs) and device log
// lines (security_events — syslog ingestion + rotation-aware file tailing).
// Gated by `logs:read`; security_events rows are included ONLY when the caller
// also holds `security:read` (the two sources keep their separate gates).
// Query params: source? ('plugin'|'device'), level? (comma list), pluginId?,
// deviceId?, search? (ILIKE over message + context/appname/hostname/facility/IPs),
// from?/to? (ISO timestamps), page/pageSize/all, sort=emittedAt&dir. Paged mode
// only — the response is always the {rows,total,page,pageSize} envelope.
router.get(
  '/logs/unified',
  requireAuth,
  requirePermission('logs:read'),
  async (req, res: Response) => {
    try {
      const q = req.query as Record<string, string | undefined>;

      // Paged mode only — the webapp always sends page/pageSize or all=true.
      const pg = parsePagination(q, { defaultPageSize: 50, maxPageSize: 200 });
      if ('error' in pg) {
        res.status(400).json({ error: pg.error });
        return;
      }

      // Time is the only meaningful sort axis (same rule as /logs above).
      let orderDir: 'asc' | 'desc' = 'desc';
      if (q.sort !== undefined && q.sort !== 'emittedAt') {
        res.status(400).json({ error: `"sort" must be "emittedAt"` });
        return;
      }
      if (q.dir === 'asc') orderDir = 'asc';

      const levels = (q.level ?? '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean);
      for (const l of levels) {
        if (!LOG_LEVELS.includes(l)) {
          res.status(400).json({ error: `"level" must be a comma list of: ${LOG_LEVELS.join(', ')}` });
          return;
        }
      }

      const source = q.source?.trim();
      if (source && !['plugin', 'device'].includes(source)) {
        res.status(400).json({ error: `"source" must be "plugin" or "device"` });
        return;
      }

      // Time window — ISO text for plugin_logs (text column, lexicographic =
      // chronological), epoch ms for security_events.
      const fromIso = q.from?.trim() || null;
      const toIso = q.to?.trim() || null;
      if (fromIso && Number.isNaN(Date.parse(fromIso))) {
        res.status(400).json({ error: `"from" must be an ISO timestamp` });
        return;
      }
      if (toIso && Number.isNaN(Date.parse(toIso))) {
        res.status(400).json({ error: `"to" must be an ISO timestamp` });
        return;
      }

      // Device-level access control — same rules as both source routes.
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && q.deviceId && !allowed.has(q.deviceId)) {
        res.status(200).json({ rows: [], total: 0, ...envelopePage(pg, 0) });
        return;
      }

      // Device log lines keep their own gate — without security:read the caller
      // only ever sees plugin logs (source=device answers empty for them).
      const canSecurity = Array.isArray(req.user?.permissions) && req.user.permissions.includes('security:read');
      const wantPlugin = !source || source === 'plugin';
      const wantDevice = (!source || source === 'device') && canSecurity;

      if ((allowed !== null && allowed.size === 0) || (!wantPlugin && !wantDevice)) {
        res.status(200).json({ rows: [], total: 0, ...envelopePage(pg, 0) });
        return;
      }

      // --- Build the two UNION ALL sides (parameterized, per wanted side) -----
      const params: unknown[] = [];
      const ph = (v: unknown): string => {
        params.push(v);
        return `$${params.length}`;
      };
      const inList = (ids: string[]): string => `(${ids.map((id) => ph(id)).join(', ')})`;

      const search = q.search?.trim() ?? '';
      const pat = search ? `%${search.replace(/[%_]/g, '')}%` : null;

      const pluginClauses: string[] = [];
      if (wantPlugin) {
        if (fromIso) pluginClauses.push(`"emittedAt" >= ${ph(fromIso)}`);
        if (toIso) pluginClauses.push(`"emittedAt" < ${ph(toIso)}`);
        if (levels.length === 1) pluginClauses.push(`level = ${ph(levels[0])}`);
        else if (levels.length > 1) pluginClauses.push(`level IN ${inList(levels)}`);
        if (q.pluginId) pluginClauses.push(`"pluginId" = ${ph(q.pluginId)}`);
        if (q.deviceId) pluginClauses.push(`"deviceId" = ${ph(q.deviceId)}`);
        if (pat) pluginClauses.push(`("message" ILIKE ${ph(pat)} OR "context" ILIKE ${ph(pat)})`);
        if (allowed !== null) pluginClauses.push(`"deviceId" IN ${inList([...allowed])}`);
      }

      const deviceClauses: string[] = [];
      if (wantDevice) {
        if (fromIso) deviceClauses.push(`"tsMs" >= ${ph(Date.parse(fromIso))}`);
        if (toIso) deviceClauses.push(`"tsMs" < ${ph(Date.parse(toIso))}`);
        if (levels.length === 1) deviceClauses.push(`level = ${ph(levels[0])}`);
        else if (levels.length > 1) deviceClauses.push(`level IN ${inList(levels)}`);
        if (q.pluginId) deviceClauses.push(`"pluginId" = ${ph(q.pluginId)}`);
        if (q.deviceId) deviceClauses.push(`"deviceId" = ${ph(q.deviceId)}`);
        if (pat) {
          deviceClauses.push(
            `("message" ILIKE ${ph(pat)} OR "hostname" ILIKE ${ph(pat)} OR "appname" ILIKE ${ph(pat)} OR "facility" ILIKE ${ph(pat)} OR "srcIp" ILIKE ${ph(pat)} OR "dstIp" ILIKE ${ph(pat)})`
          );
        }
        if (allowed !== null) deviceClauses.push(`"deviceId" IN ${inList([...allowed])}`);
      }

      // Both sides normalize to the SAME ISO-8601 text format for sort_key, so a
      // single lexicographic ORDER BY is chronological across sources: plugin_logs
      // stores JS toISOString() verbatim; security_events tsMs (bigint ms) is
      // formatted into the identical shape (no parsing of untrusted text).
      const sides: string[] = [];
      if (wantPlugin) {
        sides.push(
          `SELECT 'plugin'::text AS source, id, level, message, context, "pluginId", "deviceId", NULL::text AS appname, NULL::text AS hostname, "emittedAt" AS sort_key FROM plugin_logs${pluginClauses.length ? ` WHERE ${pluginClauses.join(' AND ')}` : ''}`
        );
      }
      if (wantDevice) {
        sides.push(
          `SELECT 'device'::text AS source, id, level, message, NULL::text AS context, "pluginId", "deviceId", appname, hostname, to_char(to_timestamp("tsMs" / 1000.0) AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"') AS sort_key FROM security_events${deviceClauses.length ? ` WHERE ${deviceClauses.join(' AND ')}` : ''}`
        );
      }

      const union = sides.join(' UNION ALL ');
      // lo.limit/lo.offset are integers from parsePagination — safe to inline.
      const lo = limitOffset(pg); // null in all-mode (unbounded)
      const [rowsRes, countRes] = await Promise.all([
        pool.query(
          `SELECT * FROM (${union}) u ORDER BY sort_key ${orderDir.toUpperCase()}${lo ? ` LIMIT ${lo.limit} OFFSET ${lo.offset}` : ''}`,
          params
        ),
        pool.query(`SELECT count(*)::int AS n FROM (${union}) u`, params),
      ]);

      const raw = rowsRes.rows as Array<{
        source: string;
        id: string;
        level: string;
        message: string;
        context: string | null;
        pluginId: string;
        deviceId: string | null;
        appname: string | null;
        hostname: string | null;
        sort_key: string;
      }>;
      const total = Number(countRes.rows[0]?.n ?? 0);

      // Batch-load display names (same pattern as /logs above).
      const deviceIds = [...new Set(raw.map((r) => r.deviceId).filter((d): d is string => !!d))];
      const pluginIds = [...new Set(raw.map((r) => r.pluginId))];
      const [devicesQ, pluginsQ] = await Promise.all([
        deviceIds.length > 0 ? db.query.devices.findMany({ where: inArray(schema.devices.id, deviceIds) }) : [],
        pluginIds.length > 0 ? db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }) : [],
      ]);
      const deviceNameById = new Map(devicesQ.map((d) => [d.id, d.name] as const));
      const pluginNameById = new Map(pluginsQ.map((p2) => [p2.id, p2.name] as const));

      res.status(200).json({
        rows: raw.map((r) => ({
          id: `${r.source}:${r.id}`, // prefixed — unique across both tables
          source: r.source as 'plugin' | 'device',
          tsMs: Date.parse(r.sort_key),
          level: r.level,
          message: r.message,
          context: r.context ? safeParseJson(r.context) : null,
          pluginId: r.pluginId ?? null,
          pluginName: pluginNameById.get(r.pluginId) ?? null,
          deviceId: r.deviceId ?? null,
          deviceName: r.deviceId ? (deviceNameById.get(r.deviceId) ?? null) : null,
          appname: r.appname ?? null,
          hostname: r.hostname ?? null,
        })),
        total,
        ...envelopePage(pg, total),
      });
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
    }
  }
);

function safeParseJson(s: string): unknown {
  try {
    return JSON.parse(s);
  } catch {
    return s; // truncated context may be invalid JSON — surface the raw text
  }
}

export default router;
