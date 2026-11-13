/**
 * CVE vulnerability tracking — background worker (leader-gated).
 *
 * Two responsibilities, on the same 30 s beat:
 *   1. FETCH (interval-gated by `cveFetchIntervalHours`, default 24 h): query
 *      the advisory provider (OSV.dev today) for every DISTINCT (ecosystem,
 *      package, version) triple installed anywhere in the fleet — WITH versions,
 *      because OSV's Debian/Alpine sources only return advisory metadata
 *      (affected ranges + severity) for versioned queries. Results are upserted
 *      into cve_advisories; advisories for packages no longer in the fleet are
 *      pruned. Egress goes through the web-fetch plugin (same proxy/timeout
 *      settings as GeoIP).
 *   2. MATCH (every beat, cheap): recompute device_cves wholesale — join each
 *      device's installed versions against the stored advisories using the
 *      per-ecosystem comparators in cve/match.ts. Runs only when its inputs
 *      changed (max collectedAt of either table), so a steady fleet costs two
 *      max() scans per beat and nothing else. A package upgrade therefore
 *      clears its findings within one beat — no re-fetch needed.
 *
 * Status rows live in system_settings under cve* keys (same pattern as geoip);
 * fetch failures raise ONE deduped notification ('cve-fetch-failed').
 */

import { pool } from '../db';
import { getEffectiveValues } from '../systemSettings';
import { emitNotification, resolveNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { LEADER_KEYS } from '../workers/leader';
import { initWorker, trackBeat } from '../workers/stats';
import type { AdvisoryRow, PackageQuery } from './types';
import { dedupeAdvisoriesByPk } from './types';
import { matchesVersion } from './match';
import { osvProvider } from './osv';

const BEAT_MS = 30_000; // fixed timer beat — the effective interval comes from settings
/** Postgres bind-parameter budget per bulk statement (rows × ~12 fields). */
const BULK_ROWS_PER_STATEMENT = 400;

// ── Worker-managed status rows (system_settings, cve* keys) ─────────────────

interface CveStatus {
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string;
}

async function readStatus(): Promise<CveStatus> {
  const out: CveStatus = { lastAttemptAt: null, lastSuccessAt: null, lastError: '' };
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN ('cveLastAttemptAt','cveLastSuccessAt','cveLastError')`
    );
    for (const row of res.rows) {
      if (row.key === 'cveLastAttemptAt' && String(row.value)) out.lastAttemptAt = String(row.value);
      else if (row.key === 'cveLastSuccessAt' && String(row.value)) out.lastSuccessAt = String(row.value);
      else if (row.key === 'cveLastError') out.lastError = String(row.value);
    }
  } catch { /* table hiccup — treat as fresh */ }
  return out;
}

async function writeStatusKey(key: string, value: string): Promise<void> {
  await pool.query(
    `INSERT INTO system_settings ("key", value, "updatedAt") VALUES ($1, $2, $3)
     ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value, "updatedAt" = EXCLUDED."updatedAt"`,
    [key, value, new Date().toISOString()]
  );
}

// ── Fetch cycle (interval-gated) ─────────────────────────────────────────────

/**
 * Distinct (ecosystem, package, version) triples installed anywhere in the
 * fleet. OSV.dev's Debian/Alpine sources only return advisory metadata for
 * VERSIONED queries, so each distinct installed version is its own query unit;
 * unversioned packages are included with a null version — the provider skips
 * them (they still match locally once another device's version populated the
 * advisory).
 */
async function collectFleetPackages(): Promise<PackageQuery[]> {
  const res = await pool.query(
    `SELECT DISTINCT ecosystem, name, version FROM device_packages ORDER BY ecosystem, name, version`
  );
  return res.rows.map((r: { ecosystem: string; name: string; version: string | null }) => ({
    ecosystem: String(r.ecosystem),
    name: String(r.name),
    version: r.version === null ? null : String(r.version),
  }));
}

/** Bulk-upserts advisory rows (batches stay under the bind-parameter budget). */
async function upsertAdvisories(rows: AdvisoryRow[], nowIso: string): Promise<void> {
  // Dedupe by PK before batching — see dedupeAdvisoriesByPk for why a single
  // ON CONFLICT statement must not contain duplicate conflict targets.
  const deduped = dedupeAdvisoriesByPk(rows);
  for (let start = 0; start < deduped.length; start += BULK_ROWS_PER_STATEMENT) {
    const batch = deduped.slice(start, start + BULK_ROWS_PER_STATEMENT);
    const params: unknown[] = [];
    let p = 1;
    const valuesSql = batch.map((r) => {
      params.push(r.ecosystem, r.packageName, r.id, r.severityScore, r.severityRank, JSON.stringify(r.affectedRanges), r.summary ?? null, r.url ?? null, r.publishedAt ?? null, 'osv', nowIso);
      return `($${p++},$${p++},$${p++},$${p++},$${p++},$${p++}::jsonb,$${p++},$${p++},$${p++},$${p++},$${p++})`;
    }).join(', ');
    await pool.query(
      `INSERT INTO cve_advisories (ecosystem, "packageName", id, "severityScore", "severityRank", "affectedRanges", summary, url, "publishedAt", provider, "collectedAt")
       VALUES ${valuesSql}
       ON CONFLICT (ecosystem, "packageName", id) DO UPDATE SET
         "severityScore" = EXCLUDED."severityScore",
         "severityRank" = EXCLUDED."severityRank",
         "affectedRanges" = EXCLUDED."affectedRanges",
         summary = EXCLUDED.summary,
         url = EXCLUDED.url,
         "publishedAt" = EXCLUDED."publishedAt",
         provider = EXCLUDED.provider,
         "collectedAt" = EXCLUDED."collectedAt"`,
      params
    );
  }
}

/**
 * Prunes advisories for (ecosystem, package) pairs no longer installed in the
 * fleet, then removes empty-range rows for the remaining fleet packages. Both
 * DELETEs must see the FULL fleet-pair set in one predicate — so the pairs are
 * loaded into a session-scoped temp table on a dedicated connection and each
 * DELETE runs once against it (batching only the INSERT). The earlier per-batch
 * `NOT EXISTS (VALUES <slice>)` form was wrong: with disjoint slices, an
 * advisory survived only if its package appeared in EVERY slice — i.e. prune
 * deleted every row on any fleet larger than one batch. Returns { pruned, cleaned }.
 */
async function pruneAndCleanAdvisories(pkgs: PackageQuery[]): Promise<{ pruned: number; cleaned: number }> {
  if (pkgs.length === 0) return { pruned: 0, cleaned: 0 }; // empty fleet — keep the knowledge base intact

  const client = await pool.connect();
  try {
    const distinct = new Map<string, { ecosystem: string; name: string }>();
    for (const p of pkgs) distinct.set(`${p.ecosystem}|${p.name.toLowerCase()}`, { ecosystem: p.ecosystem, name: p.name });
    const set = Array.from(distinct.values());

    // Drop-first guards against a stale table left on this pooled connection by
    // an earlier interrupted cycle (temp tables survive until the session ends).
    await client.query(`DROP TABLE IF EXISTS cve_fleet_pairs`).catch(() => undefined);
    await client.query(`CREATE TEMP TABLE cve_fleet_pairs (ecosystem text NOT NULL, pkg text NOT NULL)`);
    for (let start = 0; start < set.length; start += BULK_ROWS_PER_STATEMENT) {
      const batch = set.slice(start, start + BULK_ROWS_PER_STATEMENT);
      const params: unknown[] = [];
      let p = 1;
      const valuesSql = batch.map((r) => {
        params.push(r.ecosystem, r.name.toLowerCase());
        return `($${p++},$${p++})`;
      }).join(', ');
      await client.query(`INSERT INTO cve_fleet_pairs VALUES ${valuesSql}`, params);
    }

    const pruneRes = await client.query(
      `DELETE FROM cve_advisories a WHERE NOT EXISTS (
         SELECT 1 FROM cve_fleet_pairs v
          WHERE v.ecosystem = a.ecosystem AND lower(v.pkg) = lower(a."packageName")
       )`
    );

    // Versioned OSV queries only return advisories that AFFECT the given version —
    // every such row carries at least one affected range, so an empty
    // `affectedRanges` marks a junk row (e.g. from a pre-versioning fetch).
    // Self-healing: if a legitimate advisory ever lacked ranges it is re-fetched
    // on the next cycle anyway.
    const cleanRes = await client.query(
      `DELETE FROM cve_advisories a WHERE a."affectedRanges" = '[]'::jsonb AND EXISTS (
         SELECT 1 FROM cve_fleet_pairs v
          WHERE v.ecosystem = a.ecosystem AND lower(v.pkg) = lower(a."packageName")
       )`
    );

    return { pruned: pruneRes.rowCount ?? 0, cleaned: cleanRes.rowCount ?? 0 };
  } finally {
    await client.query(`DROP TABLE IF EXISTS cve_fleet_pairs`).catch(() => undefined);
    client.release();
  }
}

/** One fetch cycle. Never throws — failures land in status + a notification. */
export async function cveFetchCycle(): Promise<void> {
  const values = await getEffectiveValues();
  if (!values.cveEnabled) return; // master switch off — no cycles, no noise

  const nowIso = new Date().toISOString();
  await writeStatusKey('cveLastAttemptAt', nowIso);

  const pkgs = await collectFleetPackages();
  if (pkgs.length === 0) {
    // No plugin reports installed packages yet — nothing to query. Not an error:
    // the feature simply has no input until a plugin emits `installedPackages`.
    await writeStatusKey('cveLastError', '');
    // eslint-disable-next-line no-console
    console.log('[cve] no installed packages reported by any device — skipping advisory fetch');
    return;
  }

  try {
    const rows = await osvProvider.fetchAdvisories(pkgs);
    if (rows.length > 0) await upsertAdvisories(rows, nowIso);
    // Prune + empty-range cleanup in one connection — both DELETEs must see the
    // full fleet-pair set (see pruneAndCleanAdvisories for why per-batch slices
    // were wrong).
    const { pruned, cleaned } = await pruneAndCleanAdvisories(pkgs);

    await writeStatusKey('cveLastSuccessAt', new Date().toISOString());
    await writeStatusKey('cveLastError', '');
    // eslint-disable-next-line no-console
    console.log(
      `[cve] advisory fetch done — ${rows.length} fetched (${rows.filter((r) => r.affectedRanges.length > 0).length} with ranges), ` +
        `${pruned} pruned, ${cleaned} empty-range row(s) cleaned, for ${pkgs.length} package(s)`
    );

    // Healthy — clear any live cve condition.
    await resolveNotificationsByDedupeKeys(['cve-fetch-failed']);
  } catch (err) {
    const msg = ((err as Error).message ?? String(err)).slice(0, 500);
    await writeStatusKey('cveLastError', msg);
    // eslint-disable-next-line no-console
    console.error(`[cve] advisory fetch failed:`, msg);

    // One live notification per failure condition (dedupe key keeps it stable).
    const status = await readStatus();
    if (!status.lastSuccessAt) {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'CVE advisories not available',
        message: `No advisory fetch has ever succeeded — the Security page shows no vulnerability data. Last error: ${msg}`,
        dedupeKey: 'cve-fetch-failed',
      });
    } else {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'CVE advisory refresh failed (serving last good data)',
        message: `The periodic advisory fetch failed — existing findings stay in place. Last error: ${msg}`,
        dedupeKey: 'cve-fetch-failed',
      });
    }
  }
}

// ── Match recomputation (every beat, input-gated) ───────────────────────────

/** One derived match row for device_cves. */
interface DeviceCveRow {
  deviceId: string;
  pluginId: string;
  ecosystem: string;
  packageName: string;
  cveId: string;
  installedVersion: string | null;
  severityScore: number | null;
  severityRank: string;
  summary: string | null;
  url: string | null;
}

/** Recomputes device_cves wholesale. Never throws — a failed beat retries next time. */
export async function recomputeDeviceCves(): Promise<void> {
  const [pkgRes, advRes] = await Promise.all([
    pool.query(`SELECT "deviceId", "pluginId", name, version, ecosystem FROM device_packages`),
    pool.query(
      `SELECT id, ecosystem, "packageName", "severityScore", "severityRank", "affectedRanges", summary, url
       FROM cve_advisories`
    ),
  ]);

  // Index advisories by (ecosystem, package) — the join key. Package names are
  // compared case-insensitively (OSV is exact per ecosystem; a tolerant match
  // here costs nothing and avoids tag-case drift between plugins).
  const advByPkg = new Map<string, typeof advRes.rows[number][]>();
  for (const a of advRes.rows) {
    const key = `${a.ecosystem}|${String(a.packageName).toLowerCase()}`;
    const list = advByPkg.get(key);
    if (list) list.push(a);
    else advByPkg.set(key, [a]);
  }

  const nowIso = new Date().toISOString();
  const matches: DeviceCveRow[] = [];
  for (const p of pkgRes.rows) {
    const key = `${p.ecosystem}|${String(p.name).toLowerCase()}`;
    const advisories = advByPkg.get(key);
    if (!advisories || advisories.length === 0) continue;
    for (const a of advisories) {
      const ranges: Array<{ type: '<' | '<=' | '>' | '>='; version: string }> =
        Array.isArray(a.affectedRanges) ? (a.affectedRanges as never[]) : [];
      if (!matchesVersion(ranges, p.version ?? null, p.ecosystem)) continue;
      matches.push({
        deviceId: String(p.deviceId),
        pluginId: String(p.pluginId),
        ecosystem: String(p.ecosystem),
        packageName: String(p.name),
        cveId: String(a.id),
        installedVersion: typeof p.version === 'string' && p.version.trim() !== '' ? p.version : null,
        severityScore: a.severityScore ?? null,
        severityRank: String(a.severityRank ?? 'unknown'),
        summary: a.summary ?? null,
        url: a.url ?? null,
      });
    }
  }

  // Previous match set (device|cve) — needed AFTER the wholesale recompute to
  // tell which findings are NEW (alert-worthy) vs. already known.
  const prevRes = await pool.query(`SELECT "deviceId", "cveId" FROM device_cves`);
  const prevKeys = new Set(prevRes.rows.map((r: { deviceId: string; cveId: string }) => `${String(r.deviceId)}|${String(r.cveId)}`));

  // Wholesale recompute in one transaction — the table is a pure derived view.
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`DELETE FROM device_cves`);
    for (let start = 0; start < matches.length; start += BULK_ROWS_PER_STATEMENT) {
      const batch = matches.slice(start, start + BULK_ROWS_PER_STATEMENT);
      const params: unknown[] = [];
      let p = 1;
      const valuesSql = batch.map((m) => {
        params.push(m.deviceId, m.pluginId, m.ecosystem, m.packageName, m.cveId, m.installedVersion, m.severityScore, m.severityRank, m.summary, m.url, '{}', nowIso);
        return `($${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++},$${p++})`;
      }).join(', ');
      await client.query(
        `INSERT INTO device_cves ("deviceId", "pluginId", ecosystem, "packageName", "cveId", "installedVersion", "severityScore", "severityRank", summary, url, extra, "collectedAt")
         VALUES ${valuesSql}`,
        params
      );
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }

  // Always log when a recompute actually ran (the caller only invokes it on
  // input change or after a fetch) — a zero-match result is meaningful too:
  // it means the advisory table no longer covers any installed version.
  // eslint-disable-next-line no-console
  console.log(`[cve] recomputed device_cves — ${matches.length} match(es) across ${pkgRes.rows.length} package row(s)`);

  // Alert on findings that APPEARED in this recompute (and resolve the ones
  // that disappeared). Best-effort — a notification failure never breaks the
  // recompute itself.
  await alertNewCveMatches(matches, prevKeys);
}

// ── Finding alerts (new matches → notifications) ───────────────────────────

/** CVSS rank ordering for alert filtering/sorting. */
const CVE_RANK_SCORE: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
/** Cap on individual notifications per recompute — beyond that one summary row. */
const MAX_INDIVIDUAL_CVE_ALERTS = 25;

/**
 * Raises one notification per NEW (device, CVE) match at or above the
 * configured minimum rank (`cveAlertMinRank`), and resolves notifications of
 * matches that disappeared (package upgraded / advisory withdrawn).
 *
 * First-time baseline: when the previous set was EMPTY (fresh install or first
 * successful fetch cycle), no alerts are raised — a fleet with hundreds of
 * historical matches would otherwise flood the bell on boot.
 */
async function alertNewCveMatches(matches: DeviceCveRow[], prevKeys: Set<string>): Promise<void> {
  try {
    const values = await getEffectiveValues();
    if (values.cveEnabled !== true) return;

    // Matches that disappeared in this recompute — resolve their stale rows.
    await resolveStaleCveFoundNotifications(matches);

    const fresh = matches.filter((m) => !prevKeys.has(`${m.deviceId}|${m.cveId}`));
    if (fresh.length === 0) return;
    if (prevKeys.size === 0) {
      // eslint-disable-next-line no-console
      console.log(`[cve] initial baseline established — ${fresh.length} finding(s), no notifications raised`);
      return;
    }

    const minRank = String(values.cveAlertMinRank ?? 'high');
    const minScore = CVE_RANK_SCORE[minRank] ?? 3;
    const alertable = fresh.filter((m) => (CVE_RANK_SCORE[m.severityRank] ?? 0) >= minScore);
    if (alertable.length === 0) return;

    // Device names for the titles — one batched query.
    const deviceIds = [...new Set(alertable.map((m) => m.deviceId))];
    const devRes = await pool.query(`SELECT id, name FROM devices WHERE id = ANY($1::text[])`, [deviceIds]);
    const names = new Map(devRes.rows.map((r: { id: string; name: string }) => [String(r.id), String(r.name)]));

    // Worst first — critical before high before medium.
    const sorted = [...alertable].sort(
      (a, b) => (CVE_RANK_SCORE[b.severityRank] ?? 0) - (CVE_RANK_SCORE[a.severityRank] ?? 0) || (b.severityScore ?? 0) - (a.severityScore ?? 0)
    );

    for (const m of sorted.slice(0, MAX_INDIVIDUAL_CVE_ALERTS)) {
      await emitNotification({
        severity: m.severityRank === 'critical' ? 'critical' : 'warning',
        source: 'device',
        deviceId: m.deviceId,
        title: `New CVE finding on ${names.get(m.deviceId) ?? m.deviceId}: ${m.cveId}`,
        message:
          `${m.packageName}${m.installedVersion ? ` @ ${m.installedVersion}` : ''} is affected by ${m.cveId} ` +
          `(${m.severityRank}${m.severityScore !== null ? `, CVSS ${m.severityScore}` : ''}).`,
        dedupeKey: `cve-found:${m.deviceId}:${m.cveId}`,
        context: { cveId: m.cveId, packageName: m.packageName, installedVersion: m.installedVersion, severityRank: m.severityRank, url: m.url },
      });
    }
    if (alertable.length > MAX_INDIVIDUAL_CVE_ALERTS) {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: `${alertable.length - MAX_INDIVIDUAL_CVE_ALERTS} additional new CVE findings`,
        message:
          `More than ${MAX_INDIVIDUAL_CVE_ALERTS} new vulnerability matches appeared in a single recompute — see the Security page for the full list.`,
        dedupeKey: 'cve-found-batch',
      });
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[cve] finding alerts failed:', (err as Error).message);
  }
}

/** Resolves cve-found:* notifications whose (device, CVE) pair no longer matches. */
async function resolveStaleCveFoundNotifications(matches: DeviceCveRow[]): Promise<void> {
  const current = new Set(matches.map((m) => `cve-found:${m.deviceId}:${m.cveId}`));
  // The batch-summary row (dedupeKey 'cve-found-batch') is not pair-scoped — it
  // never matches a `cve-found:<deviceId>:<cveId>` key and stays open for the user.
  const res = await pool.query(
    `SELECT id, "dedupeKey" FROM notifications
     WHERE status IN ('open', 'acknowledged') AND "dedupeKey" LIKE 'cve-found:%'`
  );
  for (const r of res.rows) {
    // Quoted DDL column names keep their case in pg result rows (r.dedupeKey, not r.dedupekey).
    if (!current.has(String(r.dedupeKey))) await resolveNotification(String(r.id));
  }
}

// ── Worker loop ──────────────────────────────────────────────────────────────

/** Per-process input-change gate for the (cheap) recompute step. */
let lastPkgMax: string | null = null;
let lastAdvMax: string | null = null;

async function maxCollectedAt(table: 'device_packages' | 'cve_advisories'): Promise<string | null> {
  const res = await pool.query(`SELECT max("collectedAt") AS m FROM ${table}`);
  return res.rows[0]?.m ? String(res.rows[0].m) : null;
}

/** One beat: fetch when due, then recompute matches if the inputs changed. */
async function cveBeat(): Promise<void> {
  const values = await getEffectiveValues();
  if (!values.cveEnabled) return; // master switch off — no beats, no noise

  let fetchRan = false;
  const intervalMs = (Number(values.cveFetchIntervalHours) || 24) * 3_600_000;
  const status = await readStatus();
  if (!status.lastAttemptAt || Date.now() - Date.parse(status.lastAttemptAt) >= intervalMs) {
    fetchRan = true; // never attempted, or the interval has elapsed (settings may have been raised mid-flight)
    await cveFetchCycle();
  }

  const [pkgMax, advMax] = await Promise.all([maxCollectedAt('device_packages'), maxCollectedAt('cve_advisories')]);
  if (fetchRan || pkgMax !== lastPkgMax || advMax !== lastAdvMax) {
    try {
      await recomputeDeviceCves();
      lastPkgMax = pkgMax;
      lastAdvMax = advMax;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[cve] match recomputation failed:', (err as Error).message);
    }
  }
}

/**
 * Starts the cve worker loop. Must be called only after the API has bound its
 * port (same rule as every other worker — see index.ts app.listen).
 */
export function startCveWorker(): () => void {
  initWorker('cve', LEADER_KEYS.cve);
  // eslint-disable-next-line no-console
  console.log('[cve] worker started');

  void trackBeat('cve', cveBeat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[cve] initial cycle failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('cve', cveBeat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[cve] beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
