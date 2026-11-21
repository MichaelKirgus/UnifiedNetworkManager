import { Router, Request, Response } from 'express';
import { and, desc, eq, gte, inArray, like, or, sql } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { loadDeviceViews } from '../utils/deviceViews';

/**
 * DNS query events (Security page "DNS" tab) — read view of the append-only
 * per-query log pushed by plugins via POST /plugin/dns-queries (OPNsense
 * unbound qstats). Serves a windowed, filterable view plus SQL-side aggregates
 * (action counts + top blocked domains), so the UI can show both raw client
 * DNS activity and what the appliance's own blocklists are catching. Growth of
 * the table is bounded by the dnsQueryRetentionDays sweep
 * (workers/dnsQueryRetention.ts). Gated on `security:read`.
 */

const router = Router();

const ACTIONS = ['pass', 'block', 'drop'] as const;

/** Parse a positive integer param with fallback + cap. */
function parseCountParam(v: unknown, fallback: number, max: number): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

/** GET /v1/dns-queries — recent DNS query events + window aggregates. */
router.get('/dns-queries', requireAuth, requirePermission('security:read'), async (req: Request, res: Response) => {
  try {
    const q = req.query as Record<string, string | undefined>;

    // --- Window --------------------------------------------------------------
    // sinceHours — how far back to look; default 24 h, clamped to 1..7 days.
    // (The retention sweep bounds the table anyway.)
    const sinceHours = Math.min(Math.max(parseCountParam(q.sinceHours, 24, 7 * 24), 1), 7 * 24);
    const now = Date.now();
    const toMs = now;
    const fromMs = now - sinceHours * 3_600_000;

    // --- Filters -------------------------------------------------------------
    let actionClause;
    if (q.action && q.action !== 'all') {
      if (!(ACTIONS as readonly string[]).includes(q.action)) {
        res.status(400).json({ error: `"action" must be one of: ${[...ACTIONS, 'all'].join(', ')}` });
        return;
      }
      actionClause = eq(schema.dnsQueryEvents.action, q.action);
    }

    const search = typeof q.q === 'string' ? q.q.trim() : '';
    let searchClause;
    if (search) {
      // LIKE on domain AND client (IP or hostname) — good enough at this volume.
      const pat = `%${search.toLowerCase().replace(/[%_]/g, '')}%`;
      searchClause = or(like(schema.dnsQueryEvents.domain, pat), like(schema.dnsQueryEvents.client, pat));
    }

    // Device-level access control — scoped callers only see rows of their devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && allowed.size === 0) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { total: 0, passed: 0, blocked: 0, dropped: 0, topBlocked: [] } });
      return;
    }
    if (q.deviceId && allowed !== null && !allowed.has(q.deviceId)) {
      res.status(200).json({ fromMs, toMs, rows: [], summary: { total: 0, passed: 0, blocked: 0, dropped: 0, topBlocked: [] } });
      return;
    }

    let deviceClause;
    if (q.deviceId) {
      deviceClause = eq(schema.dnsQueryEvents.deviceId, q.deviceId);
    } else if (allowed !== null) {
      deviceClause = inArray(schema.dnsQueryEvents.deviceId, [...allowed]);
    }

    const limit = parseCountParam(q.limit, 200, 1_000);

    const baseClauses = [gte(schema.dnsQueryEvents.tsMs, fromMs), sql`${schema.dnsQueryEvents.tsMs} < ${toMs}`];
    if (deviceClause) baseClauses.push(deviceClause);
    if (actionClause) baseClauses.push(actionClause);
    if (searchClause) baseClauses.push(searchClause);

    const where = and(...baseClauses);
    // Rows + action counts over the SAME window/filters (SQL-side, cheap).
    const [rows, summaryAgg, topBlocked] = await Promise.all([
      db.query.dnsQueryEvents.findMany({ where, orderBy: [desc(schema.dnsQueryEvents.tsMs)], limit }),
      db.select({
        total: sql<number>`count(*)`,
        passed: sql<number>`count(*) filter (where ${schema.dnsQueryEvents.action} = 'pass')`,
        blocked: sql<number>`count(*) filter (where ${schema.dnsQueryEvents.action} = 'block')`,
        dropped: sql<number>`count(*) filter (where ${schema.dnsQueryEvents.action} = 'drop')`,
      }).from(schema.dnsQueryEvents).where(where),
      // Top blocked domains — what the appliance's own DNSBL is catching in this window.
      db.select({ domain: schema.dnsQueryEvents.domain, blocklist: schema.dnsQueryEvents.blocklist, n: sql<number>`count(*)` })
        .from(schema.dnsQueryEvents)
        .where(and(where, eq(schema.dnsQueryEvents.action, 'block')))
        .groupBy(schema.dnsQueryEvents.domain, schema.dnsQueryEvents.blocklist)
        .orderBy(desc(sql`count(*)`))
        .limit(5),
    ]);

    // Device display names for the rows.
    const deviceIds = [...new Set(rows.map((r) => r.deviceId).filter((d): d is string => !!d))];
    const deviceViews = await loadDeviceViews(deviceIds);

    res.status(200).json({
      fromMs,
      toMs,
      rows: rows.map((r) => ({
        id: r.id,
        deviceId: r.deviceId,
        deviceName: deviceViews.get(r.deviceId)?.name ?? null,
        tsMs: Number(r.tsMs),
        client: r.client,
        domain: r.domain,
        qtype: r.qtype ?? null,
        action: r.action,
        source: r.source ?? null,
        rcode: r.rcode ?? null,
        blocklist: r.blocklist ?? null,
        dnssecStatus: r.dnssecStatus ?? null,
        resolveTimeMs: r.resolveTimeMs ?? null,
        ttl: r.ttl ?? null,
      })),
      summary: {
        total: Number(summaryAgg[0]?.total ?? 0),
        passed: Number(summaryAgg[0]?.passed ?? 0),
        blocked: Number(summaryAgg[0]?.blocked ?? 0),
        dropped: Number(summaryAgg[0]?.dropped ?? 0),
        topBlocked: topBlocked.map((t) => ({ domain: t.domain, blocklist: t.blocklist ?? null, count: Number(t.n ?? 0) })),
      },
    });
  } catch (error) {
    console.error('Error querying dns queries:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
