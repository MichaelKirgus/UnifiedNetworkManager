import { Router, Request, Response } from 'express';
import { and, desc, eq, gte, inArray, like, lt, or, sql } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { loadDeviceViews, loadPluginNames } from '../utils/deviceViews';

/**
 * Security events (syslog ingestion) — read API for the append-only log filled
 * by the syslog-collector plugin via POST /plugin/security-events. Devices
 * forward their logs to the collector (UDP/TCP 514); this route serves the
 * windowed, filterable view (window pattern identical to GET /firewall-events).
 * The automation `log` trigger with source 'security' scans the same table by
 * tsMs watermark — this route is for humans/tooling. Gated on `security:read`.
 */

const router = Router();

/** Parse an ISO date param into epoch ms, or null when absent/invalid. */
function parseTimeParam(v: unknown): number | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

const LEVELS = ['debug', 'info', 'warn', 'error'] as const;

router.get('/security-events', requireAuth, requirePermission('security:read'), async (req: Request, res: Response) => {
  try {
    const q = req.query as Record<string, string | undefined>;

    // --- Window (same pattern as GET /firewall-events) -----------------------
    const now = Date.now();
    let toMs = parseTimeParam(q.to) ?? now;
    let fromMs = parseTimeParam(q.from) ?? toMs - 3600_000; // default: last hour
    if (fromMs >= toMs) fromMs = toMs - 3600_000;
    const MAX_RANGE_MS = 400 * 86_400_000;
    if (toMs - fromMs > MAX_RANGE_MS) fromMs = toMs - MAX_RANGE_MS;

    // --- Filters -------------------------------------------------------------
    let levelClause;
    if (q.level && q.level !== 'all') {
      if (!(LEVELS as readonly string[]).includes(q.level)) {
        res.status(400).json({ error: `"level" must be one of: ${LEVELS.join(', ')}, all` });
        return;
      }
      levelClause = eq(schema.securityEvents.level, q.level);
    }

    const search = typeof q.search === 'string' ? q.search.trim() : '';
    let searchClause;
    if (search) {
      // LIKE on the text fields — good enough at this volume.
      const pat = `%${search.replace(/[%_]/g, '')}%`;
      searchClause = or(
        like(schema.securityEvents.message, pat),
        like(schema.securityEvents.hostname, pat),
        like(schema.securityEvents.appname, pat),
        like(schema.securityEvents.facility, pat),
        like(schema.securityEvents.srcIp, pat),
        like(schema.securityEvents.dstIp, pat)
      );
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { total: 0, byLevel: { debug: 0, info: 0, warn: 0, error: 0 } } });
      return;
    }
    if (q.deviceId && allowed !== null && !allowed.has(q.deviceId)) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { total: 0, byLevel: { debug: 0, info: 0, warn: 0, error: 0 } } });
      return;
    }

    let deviceClause;
    if (q.deviceId) {
      deviceClause = eq(schema.securityEvents.deviceId, q.deviceId);
    } else if (allowed !== null) {
      // Scoped caller — restrict to their devices. Rows with NULL deviceId
      // (unresolved hostname) are excluded for scoped callers: they cannot be
      // attributed to any of the caller's devices.
      deviceClause = inArray(schema.securityEvents.deviceId, [...allowed]);
    }

    const limitParam = Number(q.limit);
    const limit = Math.max(1, Math.min(2000, Number.isFinite(limitParam) ? Math.floor(limitParam) : 500));

    const baseClauses = [gte(schema.securityEvents.tsMs, fromMs), lt(schema.securityEvents.tsMs, toMs)];
    if (deviceClause) baseClauses.push(deviceClause);
    if (levelClause) baseClauses.push(levelClause);
    if (searchClause) baseClauses.push(searchClause);

    const where = and(...baseClauses);
    // Rows + per-level counts over the SAME window/filters (SQL-side, cheap).
    const [rows, summaryAgg] = await Promise.all([
      db.query.securityEvents.findMany({ where, orderBy: [desc(schema.securityEvents.tsMs)], limit }),
      db.select({
        total: sql<number>`count(*)`,
        debug: sql<number>`count(*) filter (where ${schema.securityEvents.level} = 'debug')`,
        info: sql<number>`count(*) filter (where ${schema.securityEvents.level} = 'info')`,
        warn: sql<number>`count(*) filter (where ${schema.securityEvents.level} = 'warn')`,
        error: sql<number>`count(*) filter (where ${schema.securityEvents.level} = 'error')`,
      }).from(schema.securityEvents).where(where),
    ]);

    // Device + plugin display names for the rows.
    const deviceIds = [...new Set(rows.map((r) => r.deviceId).filter((d): d is string => !!d))];
    const deviceViews = await loadDeviceViews(deviceIds);
    const pluginNames = await loadPluginNames([...new Set(rows.map((r) => r.pluginId))]);

    res.status(200).json({
      fromMs,
      toMs,
      rows: rows.map((r) => ({
        id: r.id,
        deviceId: r.deviceId ?? null,
        deviceName: r.deviceId ? (deviceViews.get(r.deviceId)?.name ?? null) : null,
        pluginId: r.pluginId,
        pluginName: pluginNames.get(r.pluginId) ?? null,
        tsMs: Number(r.tsMs),
        level: r.level,
        severity: r.severity,
        facility: r.facility,
        hostname: r.hostname,
        appname: r.appname,
        srcIp: r.srcIp,
        dstIp: r.dstIp,
        message: r.message,
      })),
      summary: {
        total: Number(summaryAgg[0]?.total ?? 0),
        byLevel: {
          debug: Number(summaryAgg[0]?.debug ?? 0),
          info: Number(summaryAgg[0]?.info ?? 0),
          warn: Number(summaryAgg[0]?.warn ?? 0),
          error: Number(summaryAgg[0]?.error ?? 0),
        },
      },
    });
  } catch (error) {
    console.error('Error querying security events:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
