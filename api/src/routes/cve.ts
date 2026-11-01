/**
 * CVE vulnerability tracking routes (Security page).
 *
 * GET  /cve/vulnerabilities — rows from device_cves: one row per (device ×
 *      vulnerable package) match, joined with device + plugin identity. Filters:
 *      deviceId, siteId, severityRank ('critical'|'high'|'medium'|'low'),
 *      ecosystem, q (case-insensitive substring on package name or CVE id).
 * GET  /cve/summary — page header: counts by severity rank, affected-device
 *      count, total matches, and the worker's last fetch outcome.
 * POST /cve/refresh — run one advisory fetch cycle NOW (bypasses the interval);
 *      match recomputation happens on the next beat automatically.
 *
 * All three are gated on `security:read` (the data feeds the Security page) and
 * honor device-level access control exactly like /security-checks: scoped
 * callers get 200 with an empty/zeroed payload for out-of-scope devices, never
 * a leak.
 */

import { Router, Response } from 'express';
import { and, asc, eq, inArray, sql } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { loadDeviceViews, loadPluginNames } from '../utils/deviceViews';
import { getEffectiveValues } from '../systemSettings';
import { cveFetchCycle } from '../cve/worker';

const router = Router();

const KNOWN_RANKS = ['critical', 'high', 'medium', 'low', 'unknown'];

/** Worker-managed status rows live in system_settings under cve* keys. */
async function readWorkerStatus(): Promise<{ lastAttemptAt: string | null; lastSuccessAt: string | null; lastError: string }> {
  const out = { lastAttemptAt: null as string | null, lastSuccessAt: null as string | null, lastError: '' };
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN ('cveLastAttemptAt','cveLastSuccessAt','cveLastError')`
    );
    for (const row of res.rows) {
      if (row.key === 'cveLastAttemptAt' && String(row.value)) out.lastAttemptAt = String(row.value);
      else if (row.key === 'cveLastSuccessAt' && String(row.value)) out.lastSuccessAt = String(row.value);
      else if (row.key === 'cveLastError') out.lastError = String(row.value);
    }
  } catch { /* table hiccup — report as fresh */ }
  return out;
}

/** Resolves the caller's device scope: null = unrestricted, Set = restricted. */
async function resolveScope(req: Parameters<typeof allowedDeviceIds>[0], deviceId?: string, siteId?: string): Promise<Set<string> | 'all' | 'none'> {
  const allowed = await allowedDeviceIds(req);
  if (allowed !== null && allowed.size === 0) return 'none';
  if (deviceId) {
    if (allowed !== null && !allowed.has(deviceId)) return 'none';
    return new Set([deviceId]);
  }
  if (siteId) {
    const siteIds = (await db.query.devices.findMany({ where: eq(schema.devices.siteId, siteId) })).map((d) => d.id);
    const ids = allowed !== null ? siteIds.filter((id) => allowed.has(id)) : siteIds;
    return new Set(ids); // may be empty → 'none' at the call site
  }
  if (allowed === null) return 'all';
  return allowed;
}

// GET /cve/vulnerabilities — per-device CVE matches (the Security page table).
router.get('/cve/vulnerabilities', requireAuth, requirePermission('security:read'), async (req, res: Response) => {
  try {
    const { deviceId, siteId, severityRank, ecosystem, q } = req.query as Record<string, string | undefined>;

    if (severityRank && !KNOWN_RANKS.includes(severityRank)) {
      res.status(400).json({ error: `"severityRank" must be one of: ${KNOWN_RANKS.join(', ')}` });
      return;
    }

    const scope = await resolveScope(req, deviceId, siteId);
    if (scope === 'none' || (scope instanceof Set && scope.size === 0)) {
      res.status(200).json({ rows: [] });
      return;
    }

    // Severity rank ordering — critical first, then high/medium/low/unknown.
    const severityOrder = sql`CASE "severityRank" WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`;
    const clauses: unknown[] = [];
    if (scope !== 'all') clauses.push(inArray(schema.deviceCves.deviceId, [...scope]));
    if (severityRank) clauses.push(eq(schema.deviceCves.severityRank, severityRank));
    if (ecosystem) clauses.push(eq(schema.deviceCves.ecosystem, ecosystem));
    if (q && q.trim()) {
      const like = `%${q.trim().replace(/[%_]/g, '')}%`; // strip wildcards — plain substring only
      clauses.push(sql`("packageName" ILIKE ${like} OR "cveId" ILIKE ${like})`);
    }

    const rows = await db.query.deviceCves.findMany({
      ...(clauses.length > 0 ? { where: and(...(clauses as never[])) } : {}),
      orderBy: [severityOrder, asc(schema.deviceCves.deviceId), asc(schema.deviceCves.packageName), asc(schema.deviceCves.cveId)],
    });

    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(rows.map((r) => r.deviceId)))),
      loadPluginNames(Array.from(new Set(rows.map((r) => r.pluginId)))),
    ]);

    res.status(200).json({
      rows: rows.map((r) => {
        const device = deviceViews.get(r.deviceId);
        return {
          ...r,
          extra: safeParseExtra(r.extra),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(r.pluginId) ?? null,
        };
      }),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /cve/summary — page header counts + worker fetch state.
router.get('/cve/summary', requireAuth, requirePermission('security:read'), async (req, res: Response) => {
  try {
    const scope = await resolveScope(req);
    if (scope === 'none') {
      res.status(200).json({ bySeverity: emptyBySeverity(), affectedDevices: 0, totalMatches: 0, ...(await readWorkerStatus()) });
      return;
    }

    const clauses: unknown[] = [];
    if (scope !== 'all') clauses.push(inArray(schema.deviceCves.deviceId, [...scope]));
    const where = clauses.length > 0 ? and(...(clauses as never[])) : undefined;

    // One pass for the per-rank counts + affected-device count.
    const [rankRows, deviceRow] = await Promise.all([
      db.select({ rank: schema.deviceCves.severityRank, n: sql<number>`count(*)::int` })
        .from(schema.deviceCves)
        .where(where)
        .groupBy(schema.deviceCves.severityRank),
      db.select({ n: sql<number>`count(DISTINCT "deviceId")::int` }).from(schema.deviceCves).where(where),
    ]);

    const bySeverity = emptyBySeverity();
    for (const r of rankRows) {
      if (r.rank in bySeverity) bySeverity[r.rank] += r.n;
    }

    res.status(200).json({
      bySeverity,
      affectedDevices: deviceRow[0]?.n ?? 0,
      totalMatches: Object.values(bySeverity).reduce((a, b) => a + b, 0),
      ...(await readWorkerStatus()),
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /cve/refresh — run one advisory fetch cycle now (bypasses the interval).
router.post('/cve/refresh', requireAuth, requirePermission('security:read'), async (_req, res: Response) => {
  try {
    const values = await getEffectiveValues();
    if (!values.cveEnabled) {
      res.status(409).json({ error: 'CVE tracking is disabled (cveEnabled)' });
      return;
    }
    await cveFetchCycle(); // never throws — failures land in the status rows
    const status = await readWorkerStatus();
    if (status.lastError && !status.lastSuccessAt) {
      res.status(502).json({ ...status, error: String(status.lastError) });
    } else {
      res.status(200).json(status);
    }
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

function emptyBySeverity(): Record<string, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
}

function safeParseExtra(raw: string): Record<string, unknown> {
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export default router;
