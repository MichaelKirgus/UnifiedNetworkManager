/**
 * WLED firmware update rows — the Updates page integration.
 *
 * The device's own web UI resolves its firmware source from `info.repo`
 * (default "wled/WLED") and reads GitHub's `releases/latest`. We mirror that:
 * one release lookup per repo, cached for 6 h in memory so a 12-device fleet
 * costs ONE request per half-day instead of one per poll.
 *
 * Egress invariant: the plugin never queries the internet directly — the feed
 * download goes through UNM's web-fetch broker (SDK `webFetchViaApi` → API
 * POST /plugin/webfetch → web-fetch plugin). A transport failure (no provider
 * online, GitHub down) THROWS so the caller omits the `updates` metric key
 * entirely — never wiping previously stored rows on a transient outage. An
 * empty result is authoritative ("checked, nothing for this board").
 */

import { TtlCache, compareVersions, firmwareRow, webFetchViaApi } from '@unm/plugin-sdk';
import type { UpdateRow } from '@unm/plugin-sdk';

/** Feed cache window — GitHub rate limits are generous but 12 devices × 30 s polls is not polite. */
const FEED_TTL_MS = 6 * 60 * 60_000;

/** The parsed bits of a GitHub release we need (everything else is dropped). */
export interface WledRelease {
  /** Tag name, e.g. "v16.0.1". */
  tag: string;
  /** Release notes URL (the release page on GitHub). */
  htmlUrl: string | null;
  /** Matching asset for the device's board variant — null when none exists. */
  asset: { name: string; sizeBytes: number; downloadUrl: string } | null;
}

const feedCache = new TtlCache<Record<string, unknown>>({ isFresh: (v) => !!v && typeof v === 'object' });

/**
 * Fetches the latest release of `repo` through the web-fetch broker.
 * Throws on any transport failure — callers must treat that as "no data this
 * cycle" (omit), never as "no updates".
 */
export async function fetchLatestRelease(repo: string): Promise<Record<string, unknown>> {
  const key = repo.trim();
  const cached = feedCache.get(key, FEED_TTL_MS);
  if (cached) return cached;

  const url = `https://api.github.com/repos/${key}/releases/latest`;
  const { bytes } = await webFetchViaApi({ url, timeoutMs: 30_000, maxBytes: 2 * 1024 * 1024 });
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`GitHub feed for ${key} returned non-JSON`);
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    // GitHub answers 404 with a JSON error object — treat as "no release data".
    throw new Error(`GitHub feed for ${key} has no latest release (repo missing or empty?)`);
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj['tag_name'] !== 'string') {
    // GitHub's error envelope ({ message: "Not Found" }) — surface it clearly.
    throw new Error(`GitHub feed for ${key}: ${typeof obj['message'] === 'string' ? obj['message'] : 'no tag_name in response'}`);
  }
  feedCache.set(key, obj);
  return obj;
}

/**
 * Picks the firmware asset matching this device: release assets are named
 * `WLED_{version}_{releaseName}.bin` where releaseName is EXACTLY the device's
 * `info.release` (e.g. "ESP32") — no board database needed. The download host
 * is rewritten to download.wled.me, mirroring what WLED's own web UI does
 * (GitHub's redirect target). Returns null when the release ships no asset for
 * this board variant (custom firmware / unknown variant → nothing to offer).
 */
export function pickAsset(release: Record<string, unknown>, tag: string, deviceRelease?: string): { name: string; sizeBytes: number; downloadUrl: string } | null {
  const assets = Array.isArray(release['assets']) ? (release['assets'] as Record<string, unknown>[]) : [];
  if (!deviceRelease) return null;
  const suffix = `_${tag.replace(/^v/i, '')}_${deviceRelease}.bin`;
  for (const a of assets) {
    const name = typeof a['name'] === 'string' ? a['name'] : '';
    if (name.endsWith(suffix)) {
      let downloadUrl = typeof a['browser_download_url'] === 'string' ? a['browser_download_url'] : '';
      // Rewrite the host to WLED's own CDN — same as the official UI.
      try {
        const u = new URL(downloadUrl);
        if (u.hostname !== 'download.wled.me') {
          downloadUrl = `https://download.wled.me${u.pathname}${u.search}`;
        }
      } catch {
        /* keep as-is */
      }
      return { name, sizeBytes: typeof a['size'] === 'number' ? a['size'] : 0, downloadUrl };
    }
  }
  return null;
}

/**
 * Builds the Updates-page row for one WLED device. Returns [] when nothing is
 * available (authoritative wipe) — THROWS on feed transport failure so the
 * caller omits the key instead of wiping.
 */
export async function getWledUpdateRows(info: { ver?: string; release?: string; repo?: string }): Promise<UpdateRow[]> {
  const current = typeof info.ver === 'string' && info.ver.trim() !== '' ? info.ver.trim() : null;
  if (!current) return []; // no version reported — nothing to compare against

  const repo = (typeof info.repo === 'string' && info.repo.trim() !== '' ? info.repo.trim() : 'wled/WLED');
  const release = await fetchLatestRelease(repo);
  const tag = String(release['tag_name'] ?? '');
  if (!tag) return [];

  const asset = pickAsset(release, tag, typeof info.release === 'string' ? info.release : undefined);
  if (!asset || !asset.downloadUrl) {
    // No asset for this board variant — nothing we can offer (custom firmware).
    return [];
  }

  const latest = tag.replace(/^v/i, '');
  const available = compareVersions(current, latest) < 0;
  const row = firmwareRow(available ? current : null, available ? latest : null, {
    rebootRequired: true, // WLED reboots itself after a successful /update
    releaseNotesUrl: typeof release['html_url'] === 'string' ? release['html_url'] : null,
    applyActionId: 'wled.firmware.update',
    applyInput: { url: asset.downloadUrl, fileName: asset.name },
  });
  row.sizeBytes = asset.sizeBytes > 0 ? asset.sizeBytes : null;
  return available ? [row] : [];
}

/** Test hook. */
export function clearFeedCache(): void {
  feedCache.clear();
}
