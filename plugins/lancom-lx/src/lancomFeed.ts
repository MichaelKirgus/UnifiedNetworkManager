/**
 * LANCOM public release feed — the newest LCOS-LX firmware per model.
 *
 * LANCOM publishes each model's current release as a single .upx under
 * `https://ftp.lancom.de/LANCOM-Releases/LC-LX-<model>/` (Apache autoindex with
 * name + date + size; verified 2026-11-23 for LC-LX-6500/7400/6212 — one .upx
 * per folder, e.g. LC-LX-6500-7.20.0192-RU1.upx). The vendor's own WEBconfig
 * SPA has no online update check (bundle grepped), so this listing is the de
 * facto "update server endpoint". Only the LATEST release per model is exposed
 * — picking an older/specific build still goes through a manual upload.
 *
 * Egress invariant: the plugin never touches the internet directly — the
 * listing fetch goes through UNM's web-fetch broker (SDK `webFetchViaApi` →
 * API POST /plugin/webfetch → web-fetch plugin), the same path as WLED's
 * GitHub feed. A transport failure THROWS so the caller omits the feed row for
 * this cycle (never sinks the poll, never wipes a repo-file row). An empty or
 * 404 listing is authoritative ("checked — nothing published for this model")
 * and is cached like any other result.
 */

import { compareVersions, TtlCache, webFetchViaApi } from '@unm/plugin-sdk';
import { parseLxFwFileName } from './firmwareFiles';

/** One .upx entry in a LANCOM release listing. */
export interface LxFwFeedEntry {
  /** File name as published (e.g., "LC-LX-6500-7.20.0192-RU1.upx"). */
  fileName: string;
  /** Version parsed from the file name (e.g., "7.20.0192-RU1"). */
  version: string;
  /** Size in bytes as listed (null when the listing omits it). */
  sizeBytes: number | null;
  /** Absolute URL of the image on the release server. */
  url: string;
}

/** Base of LANCOM's public release server — overridable for mirrors/tests. */
export const FEED_BASE_URL = (process.env.LANCOM_FEED_BASE_URL ?? 'https://ftp.lancom.de/LANCOM-Releases').replace(/\/+$/, '');

/** Feed cache window — a listing changes at most a few times a year; 6 h is plenty for a fleet. */
const FEED_TTL_MS = 6 * 60 * 60_000;
/** Listing HTML is tiny (a few KB) — cap well below any image size. */
const LISTING_MAX_BYTES = 1024 * 1024;
/** Bounded so a first-poll feed check can't blow the API's poll budget by much (worst case once per 6 h). */
const LISTING_TIMEOUT_MS = 15_000;

type FeedCacheValue = { entry: LxFwFeedEntry | null };
const feedCache = new TtlCache<FeedCacheValue>({ isFresh: (v) => !!v && typeof v === 'object' });

/** Absolute URL of the release listing for one model. */
export function feedListingUrl(modelDigits: string): string {
  return `${FEED_BASE_URL}/LC-LX-${modelDigits}/`;
}

/**
 * Parses an Apache autoindex HTML listing into .upx entries (name + size).
 * Pure — unit-testable. Returns [] for non-listing content (404 pages, error
 * bodies) instead of throwing; the caller decides what "no entries" means.
 */
export function parseLxFwListing(html: string): Array<{ fileName: string; sizeBytes: number | null }> {
  const out: Array<{ fileName: string; sizeBytes: number | null }> = [];
  // Autoindex line shape (verified against ftp.lancom.de, 2026-11-23):
  //   <a href="LC-LX-6500-7.20.0192-RU1.upx">LC-LX-6500-7.20.0192-RU1.upx</a>
  //               13-Nov-2026 20:28            70288610
  const re = /<a\s+href="([^"]+\.upx)"[^>]*>[^<]*<\/a>\s*\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}\s+(\d+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    out.push({ fileName: m[1], sizeBytes: Number(m[2]) });
  }
  return out;
}

/**
 * Picks the newest .upx from a listing. LANCOM publishes exactly one per model
 * folder — the max-by-version is defensive against odd states (e.g. a pending
 * replacement during a vendor upload). Entries whose names don't follow the
 * LC-LX convention are skipped; null when nothing qualifies.
 */
export function pickNewestLxFw(
  entries: Array<{ fileName: string; sizeBytes: number | null }>,
  listingDir: string,
): LxFwFeedEntry | null {
  let best: LxFwFeedEntry | null = null;
  for (const e of entries) {
    const parsed = parseLxFwFileName(e.fileName);
    if (!parsed) continue;
    const entry: LxFwFeedEntry = {
      fileName: e.fileName,
      version: parsed.version,
      sizeBytes: Number.isFinite(e.sizeBytes) ? (e.sizeBytes as number) : null,
      url: `${listingDir}${encodeURIComponent(e.fileName)}`,
    };
    if (!best || compareVersions(best.version, entry.version) < 0) best = entry;
  }
  return best;
}

/**
 * Fetches the newest published firmware for one model through the web-fetch
 * broker. Returns null when LANCOM publishes nothing for this model (404 or an
 * empty listing). Throws on transport failure — callers must treat that as "no
 * data this cycle", never as "no updates".
 */
export async function fetchLxFwFeed(modelDigits: string): Promise<LxFwFeedEntry | null> {
  const key = `LC-LX-${modelDigits}`;
  const cached = feedCache.get(key, FEED_TTL_MS);
  if (cached) return cached.entry;

  const url = feedListingUrl(modelDigits);
  let res: Awaited<ReturnType<typeof webFetchViaApi>>;
  try {
    res = await webFetchViaApi({ url, timeoutMs: LISTING_TIMEOUT_MS, maxBytes: LISTING_MAX_BYTES });
  } catch (e) {
    // Broker/origin failure — NOT cached (transient); the caller skips this cycle.
    throw e;
  }
  if (res.status === 404) {
    feedCache.set(key, { entry: null });
    return null;
  }
  if (res.status !== 200) {
    // Don't cache other error statuses — they are usually transient too.
    throw new Error(`LANCOM release listing for ${key} returned HTTP ${res.status}`);
  }
  const entry = pickNewestLxFw(parseLxFwListing(res.bytes.toString('utf8')), url);
  feedCache.set(key, { entry });
  return entry;
}

/** Test hook. */
export function clearFeedCache(): void {
  feedCache.clear();
}
