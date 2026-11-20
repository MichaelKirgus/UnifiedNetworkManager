/**
 * CVE vulnerability tracking routes (Security page).
 *
 * GET  /cve/vulnerabilities — rows from device_cves: one row per (device ×
 *      vulnerable package) match, joined with device + plugin identity. Filters:
 *      deviceId, siteId, severityRank ('critical'|'high'|'medium'|'low'),
 *      ecosystem, component ('host'|'container'), q (case-insensitive substring
 *      on package name or CVE id). SERVER-SIDE PAGINATED — page/pageSize
 *      (default 50, max 200); the response carries `total` for the pager.
 *      all=true returns EVERY matching row in one unpaginated response (opt-in
 *      escape hatch for exports / small filtered sets). Rows are ordered
 *      severity-first so page 1 is always the most urgent matches;
 *      an explicit sort/dir param (allowlisted per endpoint) overrides that.
 * GET  /cve/packages — the SMART DEFAULT view: one row per vulnerable package
 *      INSTANCE (device × component × package) with cveCount, worst severity
 *      and the top CVE ids. Same filters + pagination; here severityRank means
 *      "the group contains at least one CVE of this rank or worse" (HAVING on
 *      the group's worst rank). Collapses a 25k-row CVE table into ~1-2k
 *      actionable rows — what the Security page shows first.
 * GET  /cve/summary — page header: counts by severity rank, affected-device
 *      count, total matches, and the worker's last fetch outcome.
 * POST /cve/refresh — run one advisory fetch cycle NOW (bypasses the interval);
 *      match recomputation happens on the next beat automatically.
 *
 * All four are gated on `security:read` (the data feeds the Security page) and
 * honor device-level access control exactly like /security-checks: scoped
 * callers get 200 with an empty/zeroed payload for out-of-scope devices, never
 * a leak.
 */

import { Router, Response } from 'express';
import { and, asc, eq, inArray, sql, type SQL } from 'drizzle-orm';
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

// ── Shared filter/pagination helpers (both list endpoints) ───────────────────

const PAGE_SIZE_DEFAULT = 50;
const PAGE_SIZE_MAX = 200; // hard cap — unbounded pages are exactly what this exists to prevent

/** Parse + validate page/pageSize/all. Non-numeric → error; pageSize is CLAMPED to the max.
 * `all=true` disables pagination entirely (every matching row in one response) — an
 * opt-in escape hatch for exports and small filtered sets; it wins over any explicit
 * page/pageSize (the 200 cap exists precisely so nobody ships unbounded pages by accident). */
function parsePagination(query: Record<string, string | undefined>): { all: boolean; page: number; pageSize: number } | { error: string } {
  let page = 1;
  let pageSize = PAGE_SIZE_DEFAULT;
  if (query.page !== undefined) {
    const n = Number(query.page);
    if (!Number.isInteger(n) || n < 1) return { error: `"page" must be a positive integer` };
    page = n;
  }
  if (query.pageSize !== undefined) {
    const n = Number(query.pageSize);
    if (!Number.isInteger(n) || n < 1) return { error: `"pageSize" must be a positive integer` };
    pageSize = Math.min(n, PAGE_SIZE_MAX);
  }
  // The OpenAPI validator (express-openapi-validator v5 forces coerceTypes) converts
  // declared boolean params to REAL booleans before this handler runs — accept both.
  const allRaw = query.all as boolean | string | undefined;
  if (allRaw !== undefined && typeof allRaw !== 'boolean' && !['true', 'false'].includes(allRaw)) {
    return { error: `"all" must be "true" or "false"` };
  }
  const all = allRaw === true || allRaw === 'true';
  return { all, page, pageSize };
}

/** Severity rank ordering — critical first, then high/medium/low/unknown. */
const SEVERITY_ORDER = sql`CASE "severityRank" WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`;

// Sortable fields per endpoint — anything else is a 400 (same strictness as the
// other filters). Values are allowlisted, so quoted literals in ORDER BY are safe.
const VULN_SORT_FIELDS = ['severityRank', 'packageName', 'cveId', 'ecosystem', 'componentName'];
const PKG_SORT_FIELDS = ['worstRank', 'cveCount', 'packageName', 'componentName', 'ecosystem'];

/** ORDER BY expressions per endpoint. camelCase aliases MUST stay quoted — an
 * unquoted name folds to lowercase and the column "does not exist". */
const VULN_SORT_MAP: Record<string, SQL> = {
  severityRank: SEVERITY_ORDER,
  packageName: sql`"packageName"`,
  cveId: sql`"cveId"`,
  ecosystem: sql`ecosystem`,
  componentName: sql`"componentName"`,
};
const PKG_SORT_MAP: Record<string, SQL> = {
  worstRank: sql`"worstRankOrder"`, // the aggregate alias behind the rank
  cveCount: sql`"cveCount"`,
  packageName: sql`"packageName"`,
  componentName: sql`"componentName"`,
  ecosystem: sql`ecosystem`,
};

function validateSort(sort?: string, dir?: string, fields: string[] = VULN_SORT_FIELDS): string | null {
  if (sort && !fields.includes(sort)) return `"sort" must be one of: ${fields.join(', ')}`;
  if (dir && !['asc', 'desc'].includes(dir)) return '"dir" must be "asc" or "desc"';
  return null;}

/** ORDER BY for a validated sort param, with stable tiebreakers. Empty = caller's default order. */
function sortOrder(sort: string | undefined, dir: string | undefined, map: Record<string, SQL>, tiebreakers: SQL[]): SQL[] {
  if (!sort) return [];
  const direction = dir === 'desc' ? sql`DESC` : sql`ASC`;
  return [sql`${map[sort]} ${direction}`, ...tiebreakers];
}

interface CveListFilters {
  severityRank?: string;
  ecosystem?: string;
  component?: string;
  q?: string;
}

/** Validate the shared filter params — returns an error message or null. */
function validateCveFilters(f: CveListFilters): string | null {
  if (f.severityRank && !KNOWN_RANKS.includes(f.severityRank)) {
    return `"severityRank" must be one of: ${KNOWN_RANKS.join(', ')}`;
  }
  // BOM component filter — 'host' | 'container' (any other value = 400, same
  // strictness as severityRank so a typo can't silently empty the table).
  if (f.component && !['host', 'container'].includes(f.component)) {
    return `"component" must be one of: host, container`;
  }
  return null;
}

/** WHERE clauses shared by both list endpoints (severity is handled per-endpoint —
 * exact match on /cve/vulnerabilities, HAVING-worst-rank on /cve/packages). */
function buildCveWhere(scope: Set<string> | 'all', f: CveListFilters): unknown[] {
  const clauses: unknown[] = [];
  if (scope !== 'all') clauses.push(inArray(schema.deviceCves.deviceId, [...scope]));
  if (f.ecosystem) clauses.push(eq(schema.deviceCves.ecosystem, f.ecosystem));
  if (f.component) clauses.push(eq(schema.deviceCves.component, f.component));
  if (f.q && f.q.trim()) {
    const like = `%${f.q.trim().replace(/[%_]/g, '')}%`; // strip wildcards — plain substring only
    clauses.push(sql`("packageName" ILIKE ${like} OR "cveId" ILIKE ${like})`);
  }
  return clauses;
}

// GET /cve/vulnerabilities — per-component CVE matches (the Security page table).
router.get('/cve/vulnerabilities', requireAuth, requirePermission('security:read'), async (req, res: Response) => {
  try {
    const query = req.query as Record<string, string | undefined>;
    const { deviceId, siteId } = query;

    const filterError = validateCveFilters(query);
    if (filterError) { res.status(400).json({ error: filterError }); return; }
    const sortError = validateSort(query.sort, query.dir, VULN_SORT_FIELDS);
    if (sortError) { res.status(400).json({ error: sortError }); return; }
    const pg = parsePagination(query);
    if ('error' in pg) { res.status(400).json({ error: pg.error }); return; }

    const scope = await resolveScope(req, deviceId, siteId);
    if (scope === 'none' || (scope instanceof Set && scope.size === 0)) {
      res.status(200).json({ rows: [], total: 0, page: pg.page, pageSize: pg.pageSize });
      return;
    }

    const clauses = buildCveWhere(scope, query);
    if (query.severityRank) clauses.push(eq(schema.deviceCves.severityRank, query.severityRank)); // exact rank
    const where = clauses.length > 0 ? and(...(clauses as never[])) : undefined;

    // Default order is severity-first so page 1 is always the most urgent matches;
    // an explicit sort param wins (stable tiebreakers keep pages deterministic).
    const sorted = sortOrder(query.sort, query.dir, VULN_SORT_MAP, [asc(schema.deviceCves.deviceId), asc(schema.deviceCves.cveId)]);
    const orderBy: SQL[] = sorted.length > 0
      ? sorted
      : [SEVERITY_ORDER, asc(schema.deviceCves.deviceId), asc(schema.deviceCves.packageName), asc(schema.deviceCves.cveId)];

    // One page of rows + the filtered total in parallel (all=true → no LIMIT/OFFSET).
    const [rows, countRow] = await Promise.all([
      (() => {
        const q = db.select().from(schema.deviceCves)
          .where(where)
          .orderBy(...(orderBy as never[]));
        return pg.all ? q : q.limit(pg.pageSize).offset((pg.page - 1) * pg.pageSize);
      })(),
      db.select({ n: sql<number>`count(*)::int` }).from(schema.deviceCves).where(where),
    ]);

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
      total: countRow[0]?.n ?? 0,
      page: pg.all ? 1 : pg.page,
      pageSize: pg.all ? (countRow[0]?.n ?? 0) : pg.pageSize, // all=true → one page holding everything
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /cve/packages — grouped view: one row per vulnerable package INSTANCE.
// The "smart default" for the Security page — a fleet with tens of thousands of
// CVE matches collapses to a few thousand actionable rows (one per device ×
// component × package), each carrying its CVE count, worst severity and the top
// CVE ids. Same filters + pagination as /cve/vulnerabilities; severityRank here
// means "the group contains at least one CVE of this rank or worse".
router.get('/cve/packages', requireAuth, requirePermission('security:read'), async (req, res: Response) => {
  try {
    const query = req.query as Record<string, string | undefined>;
    const { deviceId, siteId } = query;

    const filterError = validateCveFilters(query);
    if (filterError) { res.status(400).json({ error: filterError }); return; }
    const sortError = validateSort(query.sort, query.dir, PKG_SORT_FIELDS);
    if (sortError) { res.status(400).json({ error: sortError }); return; }
    const pg = parsePagination(query);
    if ('error' in pg) { res.status(400).json({ error: pg.error }); return; }

    const scope = await resolveScope(req, deviceId, siteId);
    if (scope === 'none' || (scope instanceof Set && scope.size === 0)) {
      res.status(200).json({ rows: [], total: 0, page: pg.page, pageSize: pg.pageSize });
      return;
    }

    const where = buildCveWhere(scope, query);
    // Severity is a HAVING on the group's WORST rank — WHERE would only count
    // matching CVEs and understate cveCount for mixed-severity packages.
    let having: SQL | undefined;
    if (query.severityRank) {
      const order = KNOWN_RANKS.indexOf(query.severityRank); // critical=0 … unknown=4
      having = sql`min(${SEVERITY_ORDER}) <= ${order}`;
    }

    const whereClause = where.length > 0 ? and(...(where as never[])) : undefined;

    // Fresh builder per call — drizzle select builders share mutable state, so a
    // single instance reused for both the paged query and the count subquery
    // leaks orderBy/limit into whichever was derived second.
    const makeGroupBase = () =>
      db.select({
        deviceId: schema.deviceCves.deviceId,
        pluginId: schema.deviceCves.pluginId,
        component: schema.deviceCves.component,
        componentName: schema.deviceCves.componentName,
        ecosystem: schema.deviceCves.ecosystem,
        packageName: schema.deviceCves.packageName,
        // Explicit `as "<key>"` aliases are REQUIRED — drizzle does not alias raw
        // SQL chunks, so without them the driver names the columns by function
        // ("count", "") and ORDER BY <name> has nothing to reference.
        installedVersion: sql<string | null>`max("installedVersion") as "installedVersion"`,
        cveCount: sql<number>`count(*)::int as "cveCount"`,
        worstRankOrder: sql<number>`min(${SEVERITY_ORDER}) as "worstRankOrder"`,
        worstScore: sql<number | null>`max("severityScore") as "worstScore"`,
        // Most severe first — the API slices the top 5 for quick links.
        cveIds: sql<string[]>`array_agg("cveId" ORDER BY ${SEVERITY_ORDER}, "cveId") as "cveIds"`,
      })
        .from(schema.deviceCves)
        .where(whereClause)
        .groupBy(
          schema.deviceCves.deviceId,
          schema.deviceCves.pluginId,
          schema.deviceCves.component,
          schema.deviceCves.componentName,
          schema.deviceCves.ecosystem,
          schema.deviceCves.packageName
        );

    // Default order: worst severity first, then most CVEs (the triage view);
    // an explicit sort param wins with a stable tiebreaker.
    const pkgSorted = sortOrder(query.sort, query.dir, PKG_SORT_MAP, [asc(schema.deviceCves.packageName)]);
    const pkgOrderBy: SQL[] = pkgSorted.length > 0
      ? pkgSorted
      : [sql`"worstRankOrder" ASC`, sql`"cveCount" DESC`, asc(schema.deviceCves.packageName)];

    // Page of groups + group count in parallel (count over the SAME grouped
    // subquery — total is the number of package instances, not CVE rows).
    const [groups, countRow] = await Promise.all([
      (() => {
        const q = (having ? makeGroupBase().having(having) : makeGroupBase())
          .orderBy(...(pkgOrderBy as never[]));
        return pg.all ? q : q.limit(pg.pageSize).offset((pg.page - 1) * pg.pageSize);
      })(),
      db.select({ n: sql<number>`count(*)::int` })
        .from((having ? makeGroupBase().having(having) : makeGroupBase()).as('g')),
    ]);

    const RANK_BY_ORDER: Record<number, string> = { 0: 'critical', 1: 'high', 2: 'medium', 3: 'low', 4: 'unknown' };
    const [deviceViews, pluginNames] = await Promise.all([
      loadDeviceViews(Array.from(new Set(groups.map((g) => g.deviceId)))),
      loadPluginNames(Array.from(new Set(groups.map((g) => g.pluginId)))),
    ]);

    res.status(200).json({
      rows: groups.map((g) => {
        const device = deviceViews.get(g.deviceId);
        return {
          deviceId: g.deviceId,
          pluginId: g.pluginId,
          component: g.component || 'host',
          componentName: g.componentName ?? '',
          ecosystem: g.ecosystem,
          packageName: g.packageName,
          installedVersion: g.installedVersion ?? null,
          cveCount: g.cveCount,
          worstRank: RANK_BY_ORDER[g.worstRankOrder] ?? 'unknown',
          worstScore: g.worstScore ?? null,
          topCves: (g.cveIds ?? []).slice(0, 5),
          deviceName: device?.name ?? null,
          managementAddress: device?.managementAddress ?? null,
          siteName: device?.siteName ?? null,
          pluginName: pluginNames.get(g.pluginId) ?? null,
        };
      }),
      total: countRow[0]?.n ?? 0,
      page: pg.all ? 1 : pg.page,
      pageSize: pg.all ? (countRow[0]?.n ?? 0) : pg.pageSize, // all=true → one page holding everything
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

    // One pass for the per-rank counts + affected-device count + affected
    // container count (BOM — how many distinct containers carry a match).
    const [rankRows, deviceRow, containerRow] = await Promise.all([
      db.select({ rank: schema.deviceCves.severityRank, n: sql<number>`count(*)::int` })
        .from(schema.deviceCves)
        .where(where)
        .groupBy(schema.deviceCves.severityRank),
      db.select({ n: sql<number>`count(DISTINCT "deviceId")::int` }).from(schema.deviceCves).where(where),
      db.select({ n: sql<number>`count(DISTINCT "componentName") FILTER (WHERE component = 'container')::int` })
        .from(schema.deviceCves)
        .where(where),
    ]);

    const bySeverity = emptyBySeverity();
    for (const r of rankRows) {
      if (r.rank in bySeverity) bySeverity[r.rank] += r.n;
    }

    res.status(200).json({
      bySeverity,
      affectedDevices: deviceRow[0]?.n ?? 0,
      affectedContainers: containerRow[0]?.n ?? 0,
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
