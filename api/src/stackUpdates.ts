/**
 * Stack self-update info for the Updates page's "UNM itself" card.
 *
 * Combines the running API version (version.ts), the plugin versions already
 * stored in the `plugins` table by discovery, and — when the admin configured
 * an update feed URL (system setting `updateFeedUrl`) — a remote release
 * manifest check with a short cache so the page's 30 s refetch does not hammer
 * the feed. The download goes through a web-fetch plugin instance (the API
 * never opens outbound internet connections itself) — which instance is chosen
 * by the `updateFeedWebFetchProviderId` setting, empty = auto-resolve.
 * The feed is OPTIONAL: empty URL = versions shown without any latest-version
 * comparison and no update notification.
 */

import { asc } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getEffectiveSettingValue, getEffectiveValues } from './systemSettings';
import { emitNotification, resolveNotificationsByDedupeKeys } from './notifications';
import { apiVersion } from './version';
import { fetchViaWebFetch, resolveWebFetchProvider } from './webFetchBroker';

export interface StackPluginVersion {
  name: string;
  version: string;
}

/** Stable identity of the ongoing "UNM update available" condition. */
export const STACK_UPDATE_DEDUPE_KEY = 'unm-stack-update-available';

export interface StackUpdateInfo {
  /** Running API version (UNM_VERSION env or package.json). */
  apiVersion: string;
  /** Plugin instances + their discovered versions. */
  plugins: StackPluginVersion[];
  /** True when updateFeedUrl is configured. */
  feedConfigured: boolean;
  /** Latest version from the feed (null = not fetched / no feed). */
  latestApiVersion: string | null;
  /** True when the feed reports a newer version than the running one. */
  available: boolean;
  /** Release notes URL from the manifest, if present. */
  notesUrl: string | null;
  /** The release page itself (GitHub html_url) — where an admin actually updates. */
  releaseUrl: string | null;
}

const FEED_CACHE_TTL_MS = 10 * 60_000;
// Keyed by URL too, so changing updateFeedUrl at runtime takes effect on the
// next check instead of waiting out the TTL.
let feedCache: { url: string; at: number; latestVersion: string | null; notesUrl: string | null; releaseUrl: string | null } | null = null;

/** Minimal version compare (dotted numeric + alphanumeric segments) — good enough for stack releases. */
function newerThan(current: string, latest: string): boolean {
  const a = current.trim().match(/[0-9]+|[A-Za-z]+/g) ?? [];
  const b = latest.trim().match(/[0-9]+|[A-Za-z]+/g) ?? [];
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const sa = a[i];
    const sb = b[i];
    if (sa === undefined || sb === undefined) return sa !== undefined; // longer wins unless pre-release marker
    if (/^(rc|beta|alpha|pre|dev)/i.test(sa ?? '') && !/^(rc|beta|alpha|pre|dev)/i.test(sb ?? '')) return false;
    const na = /^\d+$/.test(sa) ? Number(sa) : null;
    const nb = /^\d+$/.test(sb) ? Number(sb) : null;
    if (na !== null && nb !== null) {
      if (na !== nb) return na > nb;
    } else if ((sa ?? '').toLowerCase() !== (sb ?? '').toLowerCase()) {
      return (sa ?? '').toLowerCase() > (sb ?? '').toLowerCase();
    }
  }
  return false;
}

/** Parsed feed result — one of three shapes is accepted (see fetchFeed). */
interface FeedResult {
  latestVersion: string | null;
  notesUrl: string | null;
  releaseUrl: string | null;
}

const EMPTY_FEED: FeedResult = { latestVersion: null, notesUrl: null, releaseUrl: null };

/**
 * Fetches + parses the update feed THROUGH A WEB-FETCH PLUGIN — the API never
 * opens outbound internet connections itself. The instance is resolved from the
 * `updateFeedWebFetchProviderId` setting (empty = auto-resolve: built-in web-
 * fetch plugin if online, else any registered online provider); proxy/timeout/
 * size come from the shared Web Fetch settings.
 *
 * Three body shapes are accepted so an admin can point at whatever is
 * convenient:
 *   1. a bare manifest — `{ "latestVersion": "1.2.3", "notesUrl": "…" }`
 *      (or `version` in place of `latestVersion`);
 *   2. a GitHub `/releases` ARRAY — the newest non-prerelease entry wins;
 *   3. a single GitHub release OBJECT (`/releases/latest`) — `tag_name`,
 *      `html_url` (the release page) and `body` (release notes).
 * Never throws: any failure degrades to an empty result (no latest version).
 */
async function fetchFeed(url: string): Promise<FeedResult> {
  try {
    const values = await getEffectiveValues();
    const providerId = String(values.updateFeedWebFetchProviderId ?? '').trim() || undefined;
    const provider = await resolveWebFetchProvider(providerId);
    if (!provider) {
      // eslint-disable-next-line no-console
      console.warn('[stack-updates] no web-fetch plugin available — update feed check skipped');
      return EMPTY_FEED;
    }
    const { bytes, result } = await fetchViaWebFetch(provider, {
      url,
      proxyUrl: String(values.webFetchProxyUrl ?? '').trim() || undefined,
      timeoutMs: Number(values.webFetchTimeoutMs) || 120_000,
      maxBytes: Number(values.webFetchMaxBytes) || 536_870_912,
      headers: { accept: 'application/json' },
    });
    if (result.status < 200 || result.status >= 300) return EMPTY_FEED;
    const body = JSON.parse(bytes.toString('utf8')) as unknown;

    // Shape 2 — a GitHub /releases array.
    if (Array.isArray(body)) {
      const arr = body as Record<string, unknown>[];
      const first = arr.find((r) => r && !String(r['prerelease'] ?? false)) ?? arr[0];
      if (!first) return EMPTY_FEED;
      const tag = typeof first['tag_name'] === 'string' ? first['tag_name'] : typeof first['name'] === 'string' ? (first['name'] as string) : null;
      return {
        latestVersion: tag && tag.trim() !== '' ? tag.replace(/^v/i, '').trim() : null,
        notesUrl: typeof first['html_url'] === 'string' ? (first['html_url'] as string) : null,
        releaseUrl: typeof first['html_url'] === 'string' ? (first['html_url'] as string) : null,
      };
    }

    if (!body || typeof body !== 'object') return EMPTY_FEED;
    const obj = body as Record<string, unknown>;

    // Shape 3 — a single GitHub release object (/releases/latest).
    if (typeof obj['tag_name'] === 'string' && obj['tag_name'].trim() !== '') {
      const tag = (obj['tag_name'] as string).replace(/^v/i, '').trim();
      const htmlUrl = typeof obj['html_url'] === 'string' ? (obj['html_url'] as string) : null;
      return { latestVersion: tag, notesUrl: htmlUrl, releaseUrl: htmlUrl };
    }

    // Shape 1 — a bare manifest.
    const latest = obj['latestVersion'] ?? obj['version'];
    return {
      latestVersion: typeof latest === 'string' && latest.trim() !== '' ? (latest as string).replace(/^v/i, '').trim() : null,
      notesUrl: typeof obj['notesUrl'] === 'string' ? (obj['notesUrl'] as string) : null,
      releaseUrl: typeof obj['releaseUrl'] === 'string' ? (obj['releaseUrl'] as string) : null,
    };
  } catch {
    return EMPTY_FEED;
  }
}

/**
 * Shared, short-cached feed check used by BOTH the /updates route and the
 * notification worker — so a page view and a worker beat never double-fetch
 * GitHub within the cache window. Returns null when no feed URL is configured.
 */
async function checkFeed(feedUrl: string): Promise<FeedResult | null> {
  if (!feedUrl) return null;
  if (!feedCache || feedCache.url !== feedUrl || Date.now() - feedCache.at > FEED_CACHE_TTL_MS) {
    const fetched = await fetchFeed(feedUrl);
    feedCache = { url: feedUrl, at: Date.now(), ...fetched };
  }
  return feedCache;
}

/**
 * Maintains the "UnifiedNetworkManager update available" notification for the
 * admin (bell + Updates badge). Called by the leader-gated stackUpdates worker
 * on its configured cadence. Emits a single deduplicated info notification while
 * a newer version is available, and RESOLVES it once the running version catches
 * up or the feed is disabled — so the condition self-clears after an update.
 */
export async function syncStackUpdateNotification(): Promise<{ available: boolean; latestVersion: string | null }> {
  const [feedRaw] = await Promise.all([getEffectiveSettingValue('updateFeedUrl')]);
  const feedUrl = typeof feedRaw === 'string' ? feedRaw.trim() : '';

  if (!feedUrl) {
    // Feed disabled — clear any stale "update available" notification.
    await resolveNotificationsByDedupeKeys([STACK_UPDATE_DEDUPE_KEY]);
    return { available: false, latestVersion: null };
  }

  const feed = await checkFeed(feedUrl);
  const latest = feed?.latestVersion ?? null;
  const current = apiVersion();
  // An update is available when the FEED's version is NEWER than what we run.
  const available = latest !== null && newerThan(latest, current);

  if (available) {
    const releaseUrl = feed?.releaseUrl ?? feed?.notesUrl ?? null;
    await emitNotification({
      severity: 'info',
      source: 'system',
      dedupeKey: STACK_UPDATE_DEDUPE_KEY,
      title: `UnifiedNetworkManager ${latest} is available`,
      message:
        releaseUrl
          ? `You are running ${current}. A newer version (${latest}) has been released — see the release page for notes and update instructions.`
          : `You are running ${current}. A newer version (${latest}) has been released.`,
      context: { current, latest, releaseUrl },
    });
  } else {
    await resolveNotificationsByDedupeKeys([STACK_UPDATE_DEDUPE_KEY]);
  }

  return { available, latestVersion: latest };
}

/** The full "UNM itself" card payload. Never throws — feed failures degrade to no-latest. */
export async function getStackUpdateInfo(): Promise<StackUpdateInfo> {
  const [feedRaw, plugins] = await Promise.all([
    getEffectiveSettingValue('updateFeedUrl'),
    db.query.plugins.findMany({ orderBy: [asc(schema.plugins.name)] }),
  ]);
  const feedUrl = typeof feedRaw === 'string' ? feedRaw.trim() : '';

  const feed = await checkFeed(feedUrl);
  const latestVersion = feed?.latestVersion ?? null;

  return {
    apiVersion: apiVersion(),
    plugins: plugins.map((p) => ({ name: p.name, version: p.version ?? 'unknown' })),
    feedConfigured: feedUrl !== '',
    latestApiVersion: latestVersion,
    // An update is available when the FEED's version is NEWER than what we run.
    available: latestVersion !== null && newerThan(latestVersion, apiVersion()),
    notesUrl: feed?.notesUrl ?? null,
    releaseUrl: feed?.releaseUrl ?? null,
  };
}
