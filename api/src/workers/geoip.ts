import { pool } from '../db';
import { getEffectiveValues, invalidateSystemSettingsCache } from '../systemSettings';
import { addRepoFile, deleteRepoFile, listRepoFiles } from '../fileRepo';
import { resolveWebFetchProvider, fetchViaWebFetch } from '../webFetchBroker';
import { emitNotification, resolveNotificationsByDedupeKeys } from '../notifications';
import { resetGeoIpCache } from '../utils/geoIp';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';

/**
 * GeoIP database worker — keeps the central file repository's active GeoIP
 * database fresh so the Flows page can enrich external IPs with country/city.
 *
 * Cadence mirrors ntpReferences: a fixed 30 s beat + a settings-driven due
 * check (`geoipFetchIntervalHours`, default 720 h = monthly — GeoLite2 ships
 * monthly updates). Each cycle:
 *   1. resolve the effective download URL (source preset or custom override),
 *   2. fetch it THROUGH the web-fetch plugin (capability `webFetch`) — the API
 *      itself never opens an outbound internet connection; proxies/egress live
 *      in that plugin's network segment,
 *   3. store the bytes in the central file repository under category 'geoip'
 *      (content-addressed dedupe: unchanged content = no new row),
 *   4. point `geoipActiveFileId` at the stored file and — when enabled — prune
 *      superseded GeoIP files from the repo.
 *
 * The lookup engine (utils/geoIp.ts) reads `geoipActiveFileId` on demand; a
 * failed cycle never clears it, so lookups keep working off the last good
 * database until the next success.
 */

const BEAT_MS = 30_000; // fixed timer beat — the effective interval comes from settings

/**
 * Download URL presets per source (customUrl always wins when set). Sources
 * that need credentials or a non-stable download link return null — the user
 * pastes their full URL into geoipCustomUrl; failing clearly beats a
 * guaranteed-403 fetch on every cycle.
 */
export function geoipPresetUrl(source: string): string | null {
  switch (source) {
    case 'maxmind':
      return null; // license key in the query string → must be provided via geoipCustomUrl
    case 'dpip':
      return null; // free CSV is linked from a download page, no stable direct URL → customUrl
    case 'ip2location-lite':
      return 'https://lite.ip2location.com/download/geoip-lite-ipv4.zip';
    case 'ipinfo':
      return 'https://mmdb.ipinfo.io/mmdb-lite-v1.mmdb';
    default:
      return null;
  }
}

interface GeoipStatus {
  lastAttemptAt: string | null;
  lastSuccessAt: string | null;
  lastError: string;
}

/** Reads the worker-managed status rows (plain key/value, not user settings). */
async function readStatus(): Promise<GeoipStatus> {
  const out: GeoipStatus = { lastAttemptAt: null, lastSuccessAt: null, lastError: '' };
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN ('geoipLastAttemptAt','geoipLastSuccessAt','geoipLastError')`
    );
    for (const row of res.rows) {
      if (row.key === 'geoipLastAttemptAt') out.lastAttemptAt = String(row.value);
      else if (row.key === 'geoipLastSuccessAt') out.lastSuccessAt = String(row.value);
      else if (row.key === 'geoipLastError') out.lastError = String(row.value);
    }
  } catch { /* table hiccup — treat as fresh */ }
  return out;
}

/** Persists one worker-managed status key (same upsert shape as settings writes). */
async function writeStatusKey(key: string, value: string): Promise<void> {
  await pool.query(
    `INSERT INTO system_settings ("key", value, "updatedAt") VALUES ($1, $2, $3)
     ON CONFLICT ("key") DO UPDATE SET value = EXCLUDED.value, "updatedAt" = EXCLUDED."updatedAt"`,
    [key, value, new Date().toISOString()]
  );
}

/** Persists the active-file pointer (the lookup engine reads this). */
async function setActiveFileId(fileId: string): Promise<void> {
  await writeStatusKey('geoipActiveFileId', fileId);
  invalidateSystemSettingsCache(); // the pointer is a registry entry — bust its cache too
}

/**
 * Resolves the effective download URL for the current settings. Returns null
 * when no usable source is configured (e.g. maxmind without a license key).
 */
export function resolveGeoipUrl(values: Record<string, string | number | boolean>): { url: string; name: string } | null {
  const custom = String(values.geoipCustomUrl ?? '').trim();
  if (custom) return { url: custom, name: 'custom' };

  const source = String(values.geoipSource ?? 'maxmind');
  const preset = geoipPresetUrl(source);
  if (!preset) return null; // needs credentials / no stable direct URL → customUrl required
  return { url: preset, name: source };
}

/** Derives a human-readable file name from the URL (+ extracted member). */
function fileNameFor(url: string, extractedFrom?: string): string {
  const base = extractedFrom ?? (() => {
    try {
      const u = new URL(url);
      const last = decodeURIComponent(u.pathname.split('/').filter(Boolean).pop() ?? 'geoip');
      return last.length > 0 ? last : 'geoip';
    } catch {
      return 'geoip';
    }
  })();
  // Strip query junk, keep it short + safe (addRepoFile sanitizes anyway).
  const clean = base.replace(/[^\w.\-]+/g, '-').slice(0, 120);
  const date = new Date().toISOString().slice(0, 10);
  return `geoip-${clean}-${date}`;
}

/** Prunes superseded GeoIP files (keeps only the active one). */
async function pruneOldFiles(activeFileId: string): Promise<void> {
  const all = await listRepoFiles('geoip');
  const stale = all.filter((f) => f.id !== activeFileId);
  for (const f of stale) {
    try {
      await deleteRepoFile(f.id);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[geoip] failed to prune old file ${f.name}:`, (err as Error).message);
    }
  }
}

/** One fetch cycle. Never throws — failures land in status + a notification. */
export async function geoipCycle(): Promise<void> {
  const values = await getEffectiveValues();
  if (!values.geoipEnabled) return; // master switch off — no cycles, no noise

  const nowIso = new Date().toISOString();
  await writeStatusKey('geoipLastAttemptAt', nowIso);

  const resolved = resolveGeoipUrl(values as Record<string, string | number | boolean>);
  if (!resolved) {
    const msg = 'No download URL configured — set a custom URL (e.g. the MaxMind link with your license key) or pick another source';
    await writeStatusKey('geoipLastError', msg);
    // eslint-disable-next-line no-console
    console.warn(`[geoip] ${msg}`);
    return;
  }

  const provider = await resolveWebFetchProvider();
  if (!provider) {
    const msg = 'No web-fetch plugin is registered/online — start the web-fetch-plugin service (or another plugin with capability `webFetch`)';
    await writeStatusKey('geoipLastError', msg);
    // eslint-disable-next-line no-console
    console.warn(`[geoip] ${msg}`);
    return;
  }

  try {
    const proxyUrl = String(values.webFetchProxyUrl ?? '').trim() || undefined;
    const timeoutMs = Number(values.webFetchTimeoutMs) || 120_000;
    const maxBytes = Number(values.webFetchMaxBytes) || 536_870_912;
    const authHeader = String(values.geoipAuthHeader ?? '').trim();

    // Parse "Name: value" into a header map (single header supported).
    const headers: Record<string, string> = {};
    if (authHeader) {
      const idx = authHeader.indexOf(':');
      if (idx > 0) headers[authHeader.slice(0, idx).trim()] = authHeader.slice(idx + 1).trim();
    }

    // eslint-disable-next-line no-console
    console.log(`[geoip] fetching ${resolved.url} via ${provider.name}`);
    const { bytes, result } = await fetchViaWebFetch(provider, {
      url: resolved.url,
      proxyUrl,
      timeoutMs,
      maxBytes,
      extract: 'auto',
      headers,
    });

    // Store in the central file repository (category 'geoip'). Identical
    // content dedupes to the existing row — a no-op refresh costs nothing.
    const name = fileNameFor(resolved.url, result.extractedFrom);
    const { entry } = await addRepoFile({ data: bytes, name, category: 'geoip', uploadedBy: 'plugin' });

    await setActiveFileId(entry.id);
    // This process's lookup engine must see the new pointer immediately — drop
    // its loaded DB + caches (other replicas follow within their snapshot TTL).
    resetGeoIpCache();
    await writeStatusKey('geoipLastSuccessAt', new Date().toISOString());
    await writeStatusKey('geoipLastError', '');
    // eslint-disable-next-line no-console
    console.log(`[geoip] stored ${entry.name} (${result.sizeBytes} bytes, sha256 ${result.sha256.slice(0, 12)}…)`);

    if (values.geoipDeleteOldFiles) await pruneOldFiles(entry.id);

    // Healthy — clear any live geoip condition.
    await resolveNotificationsByDedupeKeys(['geoip-fetch-failed']);
  } catch (err) {
    const msg = (err as Error).message?.slice(0, 500) ?? String(err);
    await writeStatusKey('geoipLastError', msg);
    // eslint-disable-next-line no-console
    console.error(`[geoip] fetch cycle failed:`, msg);

    // One live notification per failure condition (dedupe key keeps it stable).
    const status = await readStatus();
    if (!status.lastSuccessAt) {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'GeoIP database not available',
        message: `No GeoIP database has ever been fetched successfully — Flows location lookups are disabled. Last error: ${msg}`,
        dedupeKey: 'geoip-fetch-failed',
      });
    } else {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: 'GeoIP refresh failed (serving last good database)',
        message: `The periodic GeoIP download failed — lookups keep using the previously stored file. Last error: ${msg}`,
        dedupeKey: 'geoip-fetch-failed',
      });
    }
  }
}

/**
 * Starts the geoip worker loop. Must be called only after the API has bound its
 * port (same rule as every other worker — see index.ts app.listen).
 */
export function startGeoIpWorker(): () => void {
  initWorker('geoip', LEADER_KEYS.geoip);
  // eslint-disable-next-line no-console
  console.log('[geoip] worker started');

  let lastCycleAt = 0;
  const beat = async (): Promise<void> => {
    const values = await getEffectiveValues();
    if (!values.geoipEnabled) return;
    const intervalMs = (Number(values.geoipFetchIntervalHours) || 720) * 3_600_000;
    if (Date.now() - lastCycleAt < intervalMs) return; // not due yet — settings may have been raised mid-flight
    lastCycleAt = Date.now();
    await geoipCycle();
  };

  void trackBeat('geoip', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[geoip] initial cycle failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('geoip', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[geoip] fetch cycle failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
