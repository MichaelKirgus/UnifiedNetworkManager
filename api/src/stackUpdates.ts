/**
 * Stack self-update info for the Updates page's "UNM itself" card.
 *
 * Combines the running API version (version.ts), the plugin versions already
 * stored in the `plugins` table by discovery, and — when the admin configured
 * an update feed URL (system setting `updateFeedUrl`) — a remote release
 * manifest check with a short cache so the page's 30 s refetch does not hammer
 * the feed. The feed is OPTIONAL: empty URL = versions shown without any
 * latest-version comparison (the repo has no public releases yet; this is the
 * prepared hook for when it does).
 */

import { asc } from 'drizzle-orm';
import { db } from './db';
import * as schema from './db/schema';
import { getEffectiveSettingValue } from './systemSettings';
import { apiVersion } from './version';

export interface StackPluginVersion {
  name: string;
  version: string;
}

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
}

const FEED_CACHE_TTL_MS = 10 * 60_000;
let feedCache: { at: number; latestVersion: string | null; notesUrl: string | null } | null = null;

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

async function fetchFeed(url: string): Promise<{ latestVersion: string | null; notesUrl: string | null }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 8_000);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: 'application/json' } });
    if (!res.ok) return { latestVersion: null, notesUrl: null };
    const body = (await res.json()) as Record<string, unknown>;
    // Accept both a bare manifest and a GitHub-style releases array.
    let latest: unknown = body['latestVersion'] ?? body['version'];
    if (!latest && Array.isArray(body)) {
      const arr = body as Record<string, unknown>[];
      const first = arr.find((r) => !String(r['prerelease'] ?? false));
      latest = (first ?? arr[0])?.['tag_name'] ?? (first ?? arr[0])?.['name'];
    }
    return {
      latestVersion: typeof latest === 'string' && latest.trim() !== '' ? latest.replace(/^v/i, '').trim() : null,
      notesUrl: typeof body['notesUrl'] === 'string' ? (body['notesUrl'] as string) : null,
    };
  } catch {
    return { latestVersion: null, notesUrl: null };
  } finally {
    clearTimeout(timer);
  }
}

/** The full "UNM itself" card payload. Never throws — feed failures degrade to no-latest. */
export async function getStackUpdateInfo(): Promise<StackUpdateInfo> {
  const [feedRaw, plugins] = await Promise.all([
    getEffectiveSettingValue('updateFeedUrl'),
    db.query.plugins.findMany({ orderBy: [asc(schema.plugins.name)] }),
  ]);
  const feedUrl = typeof feedRaw === 'string' ? feedRaw.trim() : '';

  let latestVersion: string | null = null;
  let notesUrl: string | null = null;
  if (feedUrl) {
    if (!feedCache || Date.now() - feedCache.at > FEED_CACHE_TTL_MS) {
      const fetched = await fetchFeed(feedUrl);
      feedCache = { at: Date.now(), ...fetched };
    }
    latestVersion = feedCache.latestVersion;
    notesUrl = feedCache.notesUrl;
  }

  return {
    apiVersion: apiVersion(),
    plugins: plugins.map((p) => ({ name: p.name, version: p.version ?? 'unknown' })),
    feedConfigured: feedUrl !== '',
    latestApiVersion: latestVersion,
    available: latestVersion !== null && newerThan(apiVersion(), latestVersion),
    notesUrl,
  };
}
