import { pool } from '../db';
import { getEffectiveValues, invalidateSystemSettingsCache } from '../systemSettings';
import { addRepoFile, deleteRepoFile, getRepoFile, listRepoFiles, openRepoFile } from '../fileRepo';
import { resolveWebFetchProvider, fetchViaWebFetch, type WebFetchProvider } from '../webFetchBroker';
import { emitNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { COUNTRIES, type CountryEntry } from '../data/countries';
import { simplifyGeometry, countGeometryPoints } from '../utils/geoSimplify';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * Map basemap worker (leader-gated, key 9025) — keeps the world-map boundary
 * data for the Flows "Map" tab fresh in the central file repository.
 *
 * The API itself never opens an outbound internet connection: every download
 * goes THROUGH the web-fetch plugin (capability `webFetch`), exactly like the
 * GeoIP worker — so a firewalled deployment only needs egress on that one
 * service's network segment (or points mapBasemapCustomUrl at an internal
 * mirror).
 *
 * Two sources:
 *   - custom URL (mapBasemapCustomUrl): ONE direct file, expected to be a
 *     GeoJSON FeatureCollection of country polygons. Stored as-is (no
 *     simplification — the operator controls what they serve).
 *   - default = Nominatim (base URL configurable via mapBasemapNominatimUrl,
 *     public OpenStreetMap by default): one polygon_geojson request per
 *     country (≥1.1 s apart, well inside Nominatim's 1 req/s usage policy),
 *     name-verified against data/countries.ts so an ambiguous search can never
 *     store the wrong boundary, then simplified with Douglas-Peucker — full-res
 *     OSM polygons are ~3 MB per country (~700 MB for the world) and useless at
 *     world-map scale. The merged FeatureCollection is stored under category
 *     'map'; each feature carries properties.iso (the GeoIP code used by the
 *     flow aggregates).
 *
 * Builds are incremental: a cycle fetches only countries missing from the
 * current file, so an interrupted build resumes where it stopped and monthly
 * refreshes re-fetch everything once per mapBasemapRefreshDays.
 */

const BEAT_MS = 60_000; // fixed beat — build work is budgeted per cycle below
/** Countries fetched per cycle (≥1.1 s apart → ~15-30 s of wire time). */
const BATCH_PER_CYCLE = 8;
/** Pacing between Nominatim requests — the usage policy allows 1 req/s max. */
const NOMINATIM_PACING_MS = 1_100;
/** Simplification tolerances in degrees, coarsest first (~2 km world-map scale).
 * Tiny states (e.g. Vatican City) degenerate to nothing at the coarsest step —
 * retry finer before giving up on a country that DOES have a real polygon. */
const SIMPLIFY_TOLERANCES_DEG = [0.02, 0.01, 0.005, 0.001];
/** Consecutive deterministic failures (no matching polygon) before a country
 * is skipped for the rest of this build — keeps one permanently-unresolvable
 * lookup from head-of-line-blocking every cycle's batch. */
const MAX_CONSECUTIVE_FAILURES = 3;
/** Nominatim requires an identifying User-Agent (usage policy). */
const NOMINATIM_UA = 'UnifiedNetworkManager/1.0 (map basemap build; self-hosted network manager)';

/** Per-country consecutive failure counts (worker scope — reset on process
 * restart, manual "Fetch now", and periodic full rebuilds). */
const failCounts = new Map<string, number>();

interface BasemapStatus {
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string;
  /** "183/249" while a build is in flight, "" when idle. */
  progress: string;
  /** ISO codes skipped for the current build (no matching OSM boundary). */
  skipped: string[];
}

const STATUS_KEYS = ['mapBasemapLastAttemptAt', 'mapBasemapLastSuccessAt', 'mapBasemapLastError', 'mapBasemapProgress', 'mapBasemapSkipped'] as const;

/** Worker status (also served by GET /flows/map/basemap). */
export async function readMapBasemapStatus(): Promise<BasemapStatus> {
  const out: BasemapStatus = { lastAttemptAt: null, lastSuccessAt: null, lastError: '', progress: '', skipped: [] };
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN (${STATUS_KEYS.map((_, i) => `$${i + 1}`).join(', ')})`,
      [...STATUS_KEYS]
    );
    for (const row of res.rows) {
      if (row.key === 'mapBasemapLastAttemptAt') out.lastAttemptAt = String(row.value);
      else if (row.key === 'mapBasemapLastSuccessAt') out.lastSuccessAt = String(row.value);
      else if (row.key === 'mapBasemapLastError') out.lastError = String(row.value);
      else if (row.key === 'mapBasemapProgress') out.progress = String(row.value);
      else if (row.key === 'mapBasemapSkipped') out.skipped = String(row.value).split(',').filter(Boolean);
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

async function setActiveFileId(fileId: string): Promise<void> {
  await writeStatusKey('mapBasemapFileId', fileId);
  invalidateSystemSettingsCache(); // the pointer is a registry entry — bust its cache too
}

/** Loads the current basemap as an iso → feature map (empty when none stored). */
async function loadCurrentFeatures(): Promise<Map<string, unknown>> {
  const values = await getEffectiveValues();
  const fileId = String(values.mapBasemapFileId ?? '').trim();
  if (!fileId) return new Map();
  try {
    const entry = await getRepoFile(fileId);
    if (!entry) return new Map();
    const opened = await openRepoFile(entry.id);
    if (!opened) return new Map();
    const chunks: Buffer[] = [];
    for await (const chunk of opened.stream) chunks.push(chunk as Buffer);
    const fc = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { features?: Array<{ properties?: { iso?: string } }> };
    const byIso = new Map<string, unknown>();
    for (const f of fc.features ?? []) {
      const iso = String(f.properties?.iso ?? '').toUpperCase();
      if (iso) byIso.set(iso, f);
    }
    return byIso;
  } catch (err) {
    // Corrupt/unreadable file — rebuild from scratch rather than fail forever.
    console.warn('[map-basemap] could not read current basemap, rebuilding:', (err as Error).message);
    return new Map();
  }
}

/** Prunes superseded map files (keeps only the active one), like geoip does. */
async function pruneOldFiles(activeFileId: string): Promise<void> {
  const all = await listRepoFiles('map');
  for (const f of all) {
    if (f.id === activeFileId) continue;
    try {
      await deleteRepoFile(f.id);
    } catch (err) {
      console.warn(`[map-basemap] failed to prune old file ${f.name}:`, (err as Error).message);
    }
  }
}

/** True when the stored basemap is younger than the refresh interval. */
function isFresh(lastSuccessAt: string | null, refreshDays: number): boolean {
  if (!lastSuccessAt) return false;
  const ageMs = Date.now() - new Date(lastSuccessAt).getTime();
  return Number.isFinite(ageMs) && ageMs < refreshDays * 86_400_000;
}

/** Verifies a Nominatim response name against the entry's accepted names. */
function nameMatches(entry: CountryEntry, returnedName: string): boolean {
  const n = returnedName.trim().toLowerCase();
  if (!n) return false;
  const accepted = [entry.name, ...(entry.aliases ?? [])].map((a) => a.toLowerCase());
  return accepted.includes(n);
}

/** One Nominatim polygon fetch → simplified GeoJSON feature.
 * Returns null on DETERMINISTIC failure (no result / wrong name / degenerate
 * geometry) — the caller counts those toward skipping. THROWS on transient
 * failure (network error, HTTP 5xx/429) so it is retried next cycle WITHOUT
 * counting toward skip: an outage must not permanently drop countries. */
async function fetchCountryFeature(
  provider: WebFetchProvider,
  entry: CountryEntry,
  nominatimBase: string,
  proxyUrl?: string,
  timeoutMs = 120_000,
  maxBytes = 536_870_912
): Promise<{ feature: unknown; pointsBefore: number } | null> {
  let url = `${nominatimBase}/search?q=${encodeURIComponent(entry.name)}&format=geojson&polygon_geojson=1&limit=1&accept-language=en`;
  if (entry.viewbox) url += `&viewbox=${encodeURIComponent(entry.viewbox)}&bounded=1`; // disambiguate same-named places elsewhere
  const { bytes, result } = await fetchViaWebFetch(provider, {
    url,
    proxyUrl,
    timeoutMs,
    maxBytes,
    headers: { 'User-Agent': NOMINATIM_UA },
  });
  if (result.status >= 500 || result.status === 429) throw new Error(`Nominatim HTTP ${result.status} — transient, retry next cycle`);
  if (result.status < 200 || result.status >= 300) return null; // 4xx = deterministic no-result
  const fc = JSON.parse(bytes.toString('utf8')) as { features?: Array<{ properties?: Record<string, unknown>; geometry: { type: string; coordinates: unknown } }> };
  const f = fc.features?.[0];
  if (!f || !nameMatches(entry, String(f.properties?.name ?? ''))) return null; // wrong/ambiguous result — never store it
  let simplified: unknown = null;
  for (const tol of SIMPLIFY_TOLERANCES_DEG) { // tiny states degenerate at coarse tolerances — retry finer
    simplified = simplifyGeometry(f.geometry, tol);
    if (simplified) break;
  }
  if (!simplified) return null; // degenerate after simplification (e.g. a point/line)
  return {
    feature: { type: 'Feature', properties: { iso: entry.iso, name: entry.name }, geometry: simplified },
    pointsBefore: countGeometryPoints(f.geometry),
  };
}

/** Custom-URL source: one direct file, stored as-is. */
async function customUrlCycle(customUrl: string): Promise<void> {
  const values = await getEffectiveValues();
  const provider = await resolveWebFetchProvider();
  if (!provider) throw new Error('No web-fetch plugin is registered/online — start the web-fetch-plugin service (or another plugin with capability `webFetch`)');

  const proxyUrl = String(values.webFetchProxyUrl ?? '').trim() || undefined;
  const timeoutMs = Number(values.webFetchTimeoutMs) || 120_000;
  const maxBytes = Number(values.webFetchMaxBytes) || 536_870_912;

  console.log(`[map-basemap] fetching custom basemap ${customUrl} via ${provider.name}`);
  const { bytes, result } = await fetchViaWebFetch(provider, { url: customUrl, proxyUrl, timeoutMs, maxBytes, extract: 'auto' });
  // Sanity-check it is a GeoJSON FeatureCollection before publishing it.
  const fc = JSON.parse(bytes.toString('utf8')) as { type?: string; features?: unknown[] };
  if (fc.type !== 'FeatureCollection' || !Array.isArray(fc.features)) {
    throw new Error(`Custom basemap URL did not return a GeoJSON FeatureCollection (got ${String(fc.type ?? 'unknown')})`);
  }

  const name = `map-basemap-custom-${new Date().toISOString().slice(0, 10)}.geojson`;
  const { entry } = await addRepoFile({ data: bytes, name, category: 'map', uploadedBy: 'plugin' });
  await setActiveFileId(entry.id);
  await writeStatusKey('mapBasemapLastSuccessAt', new Date().toISOString());
  await writeStatusKey('mapBasemapLastError', '');
  await writeStatusKey('mapBasemapProgress', '');
  console.log(`[map-basemap] stored ${entry.name} (${result.sizeBytes} bytes, sha256 ${result.sha256.slice(0, 12)}…)`);
  await pruneOldFiles(entry.id);
  await resolveNotificationsByDedupeKeys(['map-basemap-fetch-failed']);
}

/** OSM source: fetch the missing countries for this cycle (incremental). */
async function osmCycle(current: Map<string, unknown>): Promise<void> {
  const values = await getEffectiveValues();
  const provider = await resolveWebFetchProvider();
  if (!provider) throw new Error('No web-fetch plugin is registered/online — start the web-fetch-plugin service (or another plugin with capability `webFetch`)');

  const proxyUrl = String(values.webFetchProxyUrl ?? '').trim() || undefined;
  const timeoutMs = Number(values.webFetchTimeoutMs) || 120_000;
  const maxBytes = Number(values.webFetchMaxBytes) || 536_870_912;
  // Configurable Nominatim base (self-hosted instances in firewalled deployments).
  const nominatimBase = String(values.mapBasemapNominatimUrl ?? '').trim().replace(/\/+$/, '') || 'https://nominatim.openstreetmap.org';

  const missing = COUNTRIES.filter((c) => !current.has(c.iso));
  if (missing.length === 0) {
    // Complete — just record success so the freshness check has a timestamp.
    await writeStatusKey('mapBasemapLastSuccessAt', new Date().toISOString());
    await writeStatusKey('mapBasemapLastError', '');
    await writeStatusKey('mapBasemapProgress', '');
    return;
  }

  // Skip countries that already failed MAX_CONSECUTIVE_FAILURES times — left
  // in the batch they would head-of-line-block it (the first missing in ISO
  // order are always tried first) and stall every other country behind them.
  const pending = missing.filter((c) => (failCounts.get(c.iso) ?? 0) < MAX_CONSECUTIVE_FAILURES);

  const batch = pending.slice(0, BATCH_PER_CYCLE);
  let fetched = 0;
  for (let i = 0; i < batch.length; i++) {
    const entry = batch[i];
    try {
      const res = await fetchCountryFeature(provider, entry, nominatimBase, proxyUrl, timeoutMs, maxBytes);
      if (res) {
        failCounts.delete(entry.iso); // success — clear any earlier failures
        current.set(entry.iso, res.feature);
        fetched++;
        console.log(`[map-basemap] ${entry.iso} (${entry.name}): simplified from ${res.pointsBefore.toLocaleString()} points`);
      } else {
        // Deterministic no-match (wrong/ambiguous name or degenerate geometry).
        const n = (failCounts.get(entry.iso) ?? 0) + 1;
        failCounts.set(entry.iso, n);
        if (n >= MAX_CONSECUTIVE_FAILURES) console.warn(`[map-basemap] ${entry.iso}: no matching polygon after ${n} attempts — skipping for this build`);
        else console.warn(`[map-basemap] ${entry.iso}: Nominatim returned no matching polygon (attempt ${n}/${MAX_CONSECUTIVE_FAILURES})`);
      }
    } catch (err) {
      // Transient failure (network / HTTP 5xx) — retry next beat, NOT counted toward skip.
      console.warn(`[map-basemap] ${entry.iso} fetch failed:`, (err as Error).message);
    }
    if (i < batch.length - 1) await new Promise((r) => setTimeout(r, NOMINATIM_PACING_MS)); // Nominatim usage policy
  }

  const stillMissing = COUNTRIES.filter((c) => !current.has(c.iso));
  const skippedIso = stillMissing
    .filter((c) => (failCounts.get(c.iso) ?? 0) >= MAX_CONSECUTIVE_FAILURES)
    .map((c) => c.iso)
    .sort();
  await writeStatusKey('mapBasemapSkipped', skippedIso.join(','));

  if (fetched === 0 && batch.length > 0) {
    const msg = 'No countries could be fetched this cycle (Nominatim unreachable or all lookups mismatched)';
    await writeStatusKey('mapBasemapLastError', msg);
    throw new Error(msg); // trackBeat records it; the build resumes next beat
  }

  // Done when nothing unskipped is left to fetch.
  const done = stillMissing.every((c) => (failCounts.get(c.iso) ?? 0) >= MAX_CONSECUTIVE_FAILURES);
  if (!done && fetched === 0) return; // nothing new to persist this cycle

  if (done && current.size === 0) {
    const msg = 'All country lookups failed — no basemap could be built';
    await writeStatusKey('mapBasemapLastError', msg);
    throw new Error(msg); // pathological: never publish an empty map as "success"
  }

  const fc = { type: 'FeatureCollection' as const, features: [...current.values()] };
  const name = `map-basemap-osm-${new Date().toISOString().slice(0, 10)}.geojson`;
  const { entry } = await addRepoFile({ data: Buffer.from(JSON.stringify(fc), 'utf8'), name, category: 'map', uploadedBy: 'plugin' });
  await setActiveFileId(entry.id);
  await writeStatusKey('mapBasemapProgress', done ? '' : `${current.size}/${COUNTRIES.length}`);
  if (done) {
    await writeStatusKey('mapBasemapLastSuccessAt', new Date().toISOString());
    await writeStatusKey('mapBasemapLastError', ''); // holes are reported via `skipped`, not as an error
    await resolveNotificationsByDedupeKeys(['map-basemap-fetch-failed']);
    if (skippedIso.length > 0) {
      // Build finished with holes — serve the partial map, note it once.
      console.log(`[map-basemap] build complete with ${skippedIso.length} skipped: ${skippedIso.join(', ')} (${current.size}/${COUNTRIES.length})`);
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'Map basemap built with missing countries',
        message: `${current.size}/${COUNTRIES.length} country polygons fetched — no matching OSM boundary for: ${skippedIso.join(', ')}. They are retried on the next full rebuild.`,
        dedupeKey: 'map-basemap-skipped',
      });
    } else {
      console.log(`[map-basemap] build complete — ${current.size} countries stored (${entry.name})`);
    }
  } else {
    // Still building — keep the last success timestamp (the map serves partial data).
    console.log(`[map-basemap] build in progress: ${current.size}/${COUNTRIES.length} countries`);
  }
  await pruneOldFiles(entry.id);
}

/** One cycle. Never throws to the timer — failures land in status + notification. */
export async function mapBasemapCycle(): Promise<void> {
  const values = await getEffectiveValues();
  if (!values.mapBasemapEnabled) return; // master switch off — no cycles, no noise

  const nowIso = new Date().toISOString();
  await writeStatusKey('mapBasemapLastAttemptAt', nowIso);

  try {
    const customUrl = String(values.mapBasemapCustomUrl ?? '').trim();
    const refreshDays = Number(values.mapBasemapRefreshDays) || 30;
    const status = await readMapBasemapStatus();
    const requested = String(values.mapBasemapBuildRequested ?? '') === 'true';

    if (customUrl) {
      // Single-file source: only re-fetch when stale or explicitly requested.
      if (!requested && isFresh(status.lastSuccessAt, refreshDays)) return;
      await customUrlCycle(customUrl);
    } else {
      const current = await loadCurrentFeatures();
      // Countries not yet stored and not skipped for this build. A build that
      // finished WITH skips has pending.length === 0 too — it goes idle like a
      // complete one (and gets a full rebuild when the refresh interval elapses).
      const pending = COUNTRIES.filter((c) => !current.has(c.iso) && (failCounts.get(c.iso) ?? 0) < MAX_CONSECUTIVE_FAILURES);
      if (!requested && pending.length === 0 && isFresh(status.lastSuccessAt, refreshDays)) return; // idle — nothing due
      if (pending.length === 0 && !isFresh(status.lastSuccessAt, refreshDays) && !requested) {
        // Periodic full rebuild: drop the stored file so every country re-fetches.
        const fileId = String(values.mapBasemapFileId ?? '').trim();
        if (fileId) await deleteRepoFile(fileId).catch(() => undefined);
        current.clear();
        failCounts.clear(); // fresh build — give previously skipped countries another chance
      }
      if (requested) failCounts.clear(); // manual "Fetch now" — retry everything, including skipped countries
      await osmCycle(current);
    }
  } catch (err) {
    const msg = ((err as Error).message ?? String(err)).slice(0, 500);
    await writeStatusKey('mapBasemapLastError', msg);
    console.error(`[map-basemap] cycle failed:`, msg);

    // One live notification per failure condition (dedupe key keeps it stable).
    const status = await readMapBasemapStatus();
    if (!status.lastSuccessAt) {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'Map basemap not available yet',
        message: `The world-map boundaries have never been fetched — the Flows Map tab shows no map. Last error: ${msg}`,
        dedupeKey: 'map-basemap-fetch-failed',
      });
    } else {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'Map basemap refresh failed (serving last good data)',
        message: `The map boundary download failed — the Flows Map tab keeps using the previously stored file. Last error: ${msg}`,
        dedupeKey: 'map-basemap-fetch-failed',
      });
    }
  } finally {
    // A manual "fetch now" is consumed by this cycle regardless of outcome.
    await writeStatusKey('mapBasemapBuildRequested', 'false').catch(() => undefined);
  }
}

/** Starts the map basemap worker loop (same rules as every other worker). */
export function startMapBasemapWorker(): () => void {
  initWorker('mapBasemap', LEADER_KEYS.mapBasemap);
  console.log('[map-basemap] worker started');

  // Overlap guard — a build cycle takes ~30 s and must not pile up.
  let busy = false;
  const beat = async (): Promise<void> => {
    if (busy) return; // previous cycle still running — skip this tick
    busy = true;
    try {
      await mapBasemapCycle();
    } finally {
      busy = false;
    }
  };

  void trackBeat('mapBasemap', beat).catch((err) => {
    console.error('[map-basemap] initial cycle failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('mapBasemap', beat).catch((err) => {
      console.error('[map-basemap] cycle failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
