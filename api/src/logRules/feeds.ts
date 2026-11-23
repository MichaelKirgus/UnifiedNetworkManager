/**
 * Sigma rule feeds (Phase 2) — URL sources of log rules, synced by the leader
 * worker (workers/logRuleFeeds.ts) and on demand via POST /v1/log-rule-feeds/:id/sync.
 *
 * Two kinds:
 *   - 'yaml-url'    one https/http URL serving a (multi-document) Sigma YAML file.
 *   - 'github-repo' owner/repo (+ optional pathPrefix) — files are listed via the
 *     GitHub trees API and fetched from raw.githubusercontent.com. A pasted
 *     github.com/…/tree/<branch>/<dir> folder URL is accepted and its directory
 *     becomes the pathPrefix.
 *
 * Sync semantics (per feed, authoritative snapshot):
 *   - every parseable document is UPSERTED by rule name: new → inserted with
 *     source='feed' + this feedId; owned-by-this-feed → sigmaYaml refreshed when
 *     it changed (user enabled/severityOverride choices are PRESERVED);
 *   - a rule already owned by another feed, a user or the builtin pack is NEVER
 *     touched — reported as a conflict;
 *   - rules owned by this feed that are absent from the latest sync are DISABLED
 *     (kept, never deleted) so they stop firing until re-added or re-enabled.
 */

import { randomUUID as cryptoRandomUuid } from 'node:crypto';
import { pool } from '../db';
import { addRepoFile, deleteRepoFile, sanitizeTags } from '../fileRepo';
import { getEffectiveValues } from '../systemSettings';
import { fetchViaWebFetch, resolveWebFetchProvider } from '../webFetchBroker';
import { importAllSigmaRules } from './sigma';

/** Cap for one fetched YAML document/file — multi-doc packs can be large, but not THIS large. */
const MAX_YAML_BYTES = 2 * 1024 * 1024; // 2 MiB
/** Per-feed fetch timeout (URL feeds) / per-file raw fetch (GitHub). */
const FETCH_TIMEOUT_MS = 30_000;
/** Hard cap on how many files one GitHub-repo sync will fetch. */
const MAX_GITHUB_FILES = 500;

export type FeedKind = 'yaml-url' | 'github-repo';

export interface LogRuleFeedRow {
  id: string;
  name: string;
  kind: string;
  url: string;
  pathPrefix: string | null;
  enabled: boolean;
  intervalMinutes: number;
  lastSyncAt: string | null;
  lastSuccessAt: string | null;
  lastError: string | null;
  ruleCount: number;
  repoFileId: string | null;
  createdAt: string;
  updatedAt: string;
}

/**
 * File name for the raw snapshot stored in the central file repository
 * (category 'log-rule-feeds'). Date-suffixed like the threat-intel worker:
 * unchanged content dedupes to the existing row by sha256, a changed feed on
 * the same day gets addRepoFile's numeric collision suffix.
 */
export function logRuleFeedFileName(feedName: string): string {
  const base = feedName.replace(/[^\w.\-]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'feed';
  return `log-rule-feed-${base}-${new Date().toISOString().slice(0, 10)}.yml`;
}

/** Per-sync outcome returned by syncLogRuleFeed (and the /sync route). */
export interface FeedSyncResult {
  syncedAt: string;
  /** Documents found in the source this cycle. */
  totalDocs: number;
  created: number;
  updated: number;
  unchanged: number;
  /** Rules owned by this feed that were missing from the sync → disabled. */
  disabled: number;
  /** Parse failures — skipped, last known good YAML stays in place. */
  skipped: Array<{ name: string | null; error: string }>;
  /** Name collisions with rules NOT owned by this feed (untouched). */
  conflicts: Array<{ name: string; owner: 'builtin' | 'user' | 'feed'; ownerId?: string }>;
  /** Central file-repo id of the raw snapshot stored for this cycle. */
  repoFileId: string | null;
}

// ── URL normalization (pure — unit-tested) ────────────────────────────────

export interface GithubRepoRef {
  owner: string;
  repo: string;
  /** Directory prefix inside the repo (from a /tree/<branch>/<dir> URL or explicit input). */
  pathPrefix?: string;
}

/**
 * Accepts github.com/owner/repo(.git), www. variants, raw.githubusercontent.com
 * URLs, bare owner/repo, and folder/file URLs like
 * https://github.com/owner/repo/tree/main/rules/linux or …/blob/main/path/rule.yml —
 * the directory after the branch segment becomes pathPrefix. Returns null when
 * not a recognizable GitHub repo reference.
 */
export function normalizeGithubRepo(input: string): GithubRepoRef | null {
  const raw = (input ?? '').trim();
  if (!raw) return null;

  let host = '';
  let path = raw;
  if (/^https?:\/\//i.test(raw)) {
    let u: URL;
    try {
      u = new URL(raw);
    } catch {
      return null; // malformed URL
    }
    host = u.hostname.toLowerCase();
    path = u.pathname.replace(/\/+$/, '');
  }

  // Only GitHub hosts (or a bare owner/repo with no scheme) are repo references.
  if (host !== '' && !/^(www\.)?github\.com$/.test(host) && host !== 'raw.githubusercontent.com') return null;

  // Folder/file URLs: the directory after the branch segment becomes pathPrefix.
  let pathPrefix: string | undefined;
  const treeMatch = path.match(/\/tree\/[^/]+\/(.+)$/);
  if (treeMatch) {
    pathPrefix = treeMatch[1];
    path = path.slice(0, path.length - treeMatch[0].length).replace(/\/+$/, '');
  } else {
    const blobMatch = path.match(/\/blob\/[^/]+\/(.+)$/);
    if (blobMatch) {
      const p = blobMatch[1];
      pathPrefix = p.includes('/') ? p.slice(0, p.lastIndexOf('/')) : undefined;
      path = path.slice(0, path.length - blobMatch[0].length).replace(/\/+$/, '');
    }
  }

  // github.com: /owner/repo… — raw.githubusercontent.com: /owner/repo/<branch>/<path…>.
  const segs = path.split('/').filter(Boolean);
  if (segs.length < 2) return null;
  // Bare references (no scheme) must be exactly owner/repo — anything else is prose, not a ref.
  if (host === '' && segs.length > 2) return null;
  // A raw URL names ONE file — its directory becomes the pathPrefix (folder semantics).
  if (host === 'raw.githubusercontent.com' && !pathPrefix && segs.length > 4) {
    pathPrefix = segs.slice(3, -1).join('/');
  }
  const owner = segs[0];
  const repo = segs[1].replace(/\.git$/i, '');
  if (!/^[A-Za-z0-9._-]{1,39}$/.test(owner)) return null;
  if (repo === '' || !/^[A-Za-z0-9._-]+$/.test(repo)) return null;
  // Remaining segments on raw URLs are <branch>/<path…> — ignored (default branch is used).
  return pathPrefix ? { owner, repo, pathPrefix } : { owner, repo };
}

// ── Fetching (via the web-fetch plugin — the API never opens egress itself) ──

/** One sync cycle's worth of brokered fetching (provider + settings resolved once). */
interface FeedFetchClient {
  providerName: string;
  text(url: string, headers?: Record<string, string>): Promise<string>;
}

const GITHUB_API_HEADERS: Record<string, string> = { accept: 'application/vnd.github+json' };

/** Optional GitHub token for private repos / higher rate limits (api container env). */
function githubAuthHeaders(): Record<string, string> {
  const tok = process.env.GITHUB_TOKEN ?? '';
  return tok ? { authorization: `Bearer ${tok}` } : {};
}

async function createFeedFetchClient(): Promise<FeedFetchClient> {
  const provider = await resolveWebFetchProvider();
  if (!provider) {
    throw new Error('No web-fetch plugin is registered/online — start the web-fetch-plugin service (or another plugin with capability `webFetch`)');
  }
  const values = await getEffectiveValues();
  const proxyUrl = String(values.webFetchProxyUrl ?? '').trim() || undefined;
  const timeoutMs = Number(values.webFetchTimeoutMs) || FETCH_TIMEOUT_MS;
  return {
    providerName: provider.name,
    async text(url, headers) {
      const { bytes } = await fetchViaWebFetch(provider, {
        url,
        proxyUrl,
        timeoutMs,
        maxBytes: MAX_YAML_BYTES,
        headers: { 'user-agent': 'unm-log-rule-feed', ...(headers ?? {}) },
      });
      return bytes.toString('utf8');
    },
  };
}

/** Resolves the repo's default branch via the GitHub API (brokered). */
async function resolveDefaultBranch(client: FeedFetchClient, owner: string, repo: string): Promise<string> {
  const body = await client.text(`https://api.github.com/repos/${owner}/${repo}`, { ...GITHUB_API_HEADERS, ...githubAuthHeaders() });
  let data: { default_branch?: string };
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error(`GitHub API returned non-JSON for repo ${owner}/${repo}`);
  }
  if (!data.default_branch) throw new Error(`no default branch reported for ${owner}/${repo} (private or missing — set GITHUB_TOKEN on the api container)`);
  return data.default_branch;
}

/** Lists .yml/.yaml blob paths under pathPrefix via the trees API (capped). */
async function listGithubSigmaFiles(client: FeedFetchClient, owner: string, repo: string, branch: string, pathPrefix?: string): Promise<string[]> {
  const prefix = (pathPrefix ?? '').replace(/^\/+|\/+$/g, '');
  const body = await client.text(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(branch)}?recursive=1`, { ...GITHUB_API_HEADERS, ...githubAuthHeaders() });
  let data: { tree?: Array<{ path: string; type: string }>; truncated?: boolean };
  try {
    data = JSON.parse(body);
  } catch {
    throw new Error(`GitHub trees API returned non-JSON for ${owner}/${repo}@${branch}`);
  }
  const files = (data.tree ?? [])
    .filter((t) => t.type === 'blob' && /\.ya?ml$/i.test(t.path))
    .filter((t) => !prefix || t.path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`))
    .map((t) => t.path)
    .sort();
  if (files.length > MAX_GITHUB_FILES) {
    throw new Error(`${files.length} YAML files under "${prefix || '(repo root)'}" exceed the ${MAX_GITHUB_FILES}-file sync cap — narrow the path prefix`);
  }
  return files;
}

/** Fetches every document of a feed as raw YAML text (one entry per source file). */
async function fetchFeedDocuments(client: FeedFetchClient, feed: LogRuleFeedRow): Promise<string[]> {
  if (feed.kind === 'github-repo') {
    const ref = normalizeGithubRepo(feed.url);
    if (!ref) throw new Error(`"${feed.url}" is not a recognizable GitHub repo reference`);
    const branch = await resolveDefaultBranch(client, ref.owner, ref.repo);
    const prefix = feed.pathPrefix ?? ref.pathPrefix;
    const files = await listGithubSigmaFiles(client, ref.owner, ref.repo, branch, prefix);
    const docs: string[] = [];
    for (const f of files) {
      docs.push(await client.text(`https://raw.githubusercontent.com/${ref.owner}/${ref.repo}/${branch}/${f}`));
    }
    return docs;
  }
  // yaml-url — one file, possibly multi-document.
  if (!/^https?:\/\//i.test(feed.url)) throw new Error('feed url must be http(s)://…');
  return [await client.text(feed.url)];
}

// ── Sync orchestration ─────────────────────────────────────────────────────

/** In-process guard — one sync per feed at a time (routes + worker share it). */
const syncingFeeds = new Set<string>();

export function isFeedSyncing(feedId: string): boolean {
  return syncingFeeds.has(feedId);
}

/**
 * Runs ONE authoritative sync cycle for the given feed. Updates log_rules and
 * the feed row; returns the outcome. Throws on fetch/infra errors (the caller
 * records lastError) — per-document parse failures never abort the cycle.
 */
export async function syncLogRuleFeed(feedId: string): Promise<FeedSyncResult> {
  if (syncingFeeds.has(feedId)) throw new Error('a sync for this feed is already in progress');
  syncingFeeds.add(feedId);
  const nowIso = new Date().toISOString();
  try {
    const res = await pool.query<LogRuleFeedRow>(
      `SELECT id, name, kind, url, "pathPrefix", enabled, "intervalMinutes", "lastSyncAt", "lastSuccessAt", "lastError", "ruleCount", "repoFileId", "createdAt", "updatedAt" FROM log_rule_feeds WHERE id = $1`,
      [feedId]
    );
    if (res.rows.length === 0) throw new Error('feed not found');
    const feed = res.rows[0];

    // 1. Fetch + parse every document (per-doc errors are collected, never fatal).
    // All egress goes through the web-fetch plugin — the API container itself
    // never opens outbound connections (enterprise proxy environments).
    const client = await createFeedFetchClient();
    const rawDocs = await fetchFeedDocuments(client, feed);
    const outcomes = rawDocs.flatMap((d) => importAllSigmaRules(d));
    const skipped: FeedSyncResult['skipped'] = [];
    for (const o of outcomes) {
      if (!o.rule || !o.yaml) skipped.push({ name: o.name, error: o.error ?? 'unparseable document' });
    }

    // 2. Upsert by name with ownership checks.
    let created = 0;
    let updated = 0;
    let unchanged = 0;
    const conflicts: FeedSyncResult['conflicts'] = [];
    for (const o of outcomes) {
      if (!o.rule || !o.yaml) continue;
      const existing = await pool.query<{ id: string; name: string; source: string; feedId: string | null; sigmaYaml: string }>(
        `SELECT id, name, source, "feedId", "sigmaYaml" FROM log_rules WHERE name = $1`,
        [o.rule.name]
      );
      if (existing.rows.length === 0) {
        await pool.query(
          `INSERT INTO log_rules (id, name, source, "sigmaYaml", enabled, "severityOverride", "lastError", "feedId", "createdAt", "updatedAt")
           VALUES ($1, $2, 'feed', $3, true, NULL, NULL, $4, $5, $5)`,
          [cryptoRandomUuid(), o.rule.name, o.yaml.trim(), feed.id, nowIso]
        );
        created++;
        continue;
      }
      const row = existing.rows[0];
      if (row.feedId === feed.id) {
        if (String(row.sigmaYaml) !== o.yaml.trim()) {
          // YAML follows the feed — user enabled/severityOverride are preserved.
          await pool.query(`UPDATE log_rules SET "sigmaYaml" = $1, "updatedAt" = $2 WHERE id = $3`, [o.yaml.trim(), nowIso, row.id]);
          updated++;
        } else {
          unchanged++;
        }
      } else {
        const owner: 'builtin' | 'user' | 'feed' = row.source === 'builtin' ? 'builtin' : row.feedId ? 'feed' : 'user';
        conflicts.push({ name: o.rule.name, owner, ...(row.feedId ? { ownerId: String(row.feedId) } : {}) });
      }
    }

    // 3. Prune — rules owned by THIS feed that are absent from the sync are
    // disabled (kept). Only currently-enabled rows count as "disabled".
    const mine = await pool.query<{ id: string; name: string; enabled: boolean }>(
      `SELECT id, name, enabled FROM log_rules WHERE "feedId" = $1`,
      [feed.id]
    );
    const presentNames = new Set(outcomes.filter((o) => o.rule).map((o) => o.rule!.name));
    let disabled = 0;
    for (const r of mine.rows) {
      if (!presentNames.has(String(r.name)) && r.enabled) {
        await pool.query(`UPDATE log_rules SET enabled = false, "updatedAt" = $1 WHERE id = $2`, [nowIso, r.id]);
        disabled++;
      }
    }

    // 4. Raw snapshot → central file repository (category 'log-rule-feeds'): the
    // exact feed content behind this sync stays auditable/downloadable in the
    // Files page — same pattern as threat-intel feeds. One current snapshot per
    // feed; a superseded file is pruned after the new one lands, and unchanged
    // content dedupes to the existing row by sha256 (no-op). log_rules above are
    // authoritative for matching, so a repo failure must never break the cycle.
    let repoFileId: string | null = feed.repoFileId;
    try {
      const snapshot = rawDocs.join('\n---\n');
      const { entry } = await addRepoFile({
        data: Buffer.from(snapshot, 'utf8'),
        name: logRuleFeedFileName(feed.name),
        category: 'log-rule-feeds',
        // Flat feature tags — group/filter these snapshots in the Files page
        // without any folder structure (portable across repo backends).
        tags: ['log-rules', ...sanitizeTags([feed.name])],
        uploadedBy: 'plugin',
      });
      if (feed.repoFileId && feed.repoFileId !== entry.id) {
        await deleteRepoFile(feed.repoFileId).catch(() => undefined); // superseded — keep only the current snapshot
      }
      repoFileId = entry.id;
    } catch (err) {
      // eslint-disable-next-line no-console
      console.warn(`[log-rule-feeds] raw snapshot for "${feed.name}" not stored in the file repo:`, (err as Error).message);
    }

    // 5. Feed bookkeeping — success state + managed-rule count + snapshot pointer.
    const countRes = await pool.query<{ n: number }>(`SELECT count(*)::int AS n FROM log_rules WHERE "feedId" = $1`, [feed.id]);
    await pool.query(
      `UPDATE log_rule_feeds SET "lastSyncAt" = $1, "lastSuccessAt" = $2, "lastError" = NULL, "ruleCount" = $3, "repoFileId" = $4, "updatedAt" = $5 WHERE id = $6`,
      [nowIso, nowIso, Number(countRes.rows[0]?.n ?? 0), repoFileId, nowIso, feed.id]
    );

    return { syncedAt: nowIso, totalDocs: outcomes.length, created, updated, unchanged, disabled, skipped, conflicts, repoFileId };
  } finally {
    syncingFeeds.delete(feedId);
  }
}

/** Records a failed sync attempt on the feed row (fetch/infra errors). */
export async function recordFeedSyncError(feedId: string, message: string): Promise<void> {
  await pool.query(
    `UPDATE log_rule_feeds SET "lastSyncAt" = $1, "lastError" = $2, "updatedAt" = $3 WHERE id = $4`,
    [new Date().toISOString(), message.slice(0, 500), new Date().toISOString(), feedId]
  );
}
