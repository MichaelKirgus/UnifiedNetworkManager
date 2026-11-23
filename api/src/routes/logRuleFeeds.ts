import { Router, Request, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { pool } from '../db';
import { requireAuth, requirePermission } from '../auth/middleware';
import { invalidateLogRuleCache } from '../workers/logRules';
import { FeedSyncResult, isFeedSyncing, normalizeGithubRepo, recordFeedSyncError, syncLogRuleFeed } from '../logRules/feeds';

/**
 * Sigma rule feeds (Phase 2) — named URL sources of log rules. The leader
 * worker syncs due feeds on their interval; POST /:id/sync runs a cycle now.
 * Synced rules land in log_rules with source='feed' + feedId (see
 * logRules/feeds.ts for the upsert/prune semantics). Reads gated on
 * `security:read`; writes on `system:write` — same as /v1/log-rules.
 */

const router = Router();

interface FeedRow {
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

const FEED_COLUMNS = `id, name, kind, url, "pathPrefix", enabled, "intervalMinutes", "lastSyncAt", "lastSuccessAt", "lastError", "ruleCount", "repoFileId", "createdAt", "updatedAt"`;
const FEED_SELECT = `SELECT ${FEED_COLUMNS} FROM log_rule_feeds`;

function feedToJson(f: FeedRow) {
  return {
    id: String(f.id),
    name: String(f.name),
    kind: f.kind === 'github-repo' ? 'github-repo' : 'yaml-url',
    url: String(f.url),
    pathPrefix: f.pathPrefix ? String(f.pathPrefix) : null,
    enabled: Boolean(f.enabled),
    intervalMinutes: Number(f.intervalMinutes),
    lastSyncAt: f.lastSyncAt ? String(f.lastSyncAt) : null,
    lastSuccessAt: f.lastSuccessAt ? String(f.lastSuccessAt) : null,
    lastError: f.lastError ? String(f.lastError) : null,
    ruleCount: Number(f.ruleCount),
    repoFileId: f.repoFileId ? String(f.repoFileId) : null,
    createdAt: String(f.createdAt),
    updatedAt: String(f.updatedAt),
  };
}

/** Validates a create/update payload; returns normalized fields or an error message. */
function validateFeedInput(body: Record<string, unknown>, partial: boolean): { ok: true; values: Partial<{ name: string; kind: 'yaml-url' | 'github-repo'; url: string; pathPrefix: string | null; intervalMinutes: number }> } | { ok: false; error: string } {
  const out: Record<string, unknown> = {};

  if (!partial || body.name !== undefined) {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (name.length < 1 || name.length > 200) return { ok: false, error: '"name" is required (1-200 chars)' };
    out.name = name;
  }

  const kindRaw = partial && body.kind === undefined ? 'yaml-url' : body.kind;
  if (kindRaw !== 'yaml-url' && kindRaw !== 'github-repo') {
    return { ok: false, error: '"kind" must be "yaml-url" or "github-repo"' };
  }
  const kind = kindRaw as 'yaml-url' | 'github-repo';

  if (!partial || body.url !== undefined) {
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    if (url.length < 8) return { ok: false, error: '"url" is required' };
    out.url = url;
  }

  let pathPrefix: string | null = null;
  if (!partial || body.pathPrefix !== undefined) {
    // Omitted on create = no prefix (undefined is NOT an error — only a wrong type is).
    if (body.pathPrefix === undefined || body.pathPrefix === null || body.pathPrefix === '') {
      pathPrefix = null;
    } else if (typeof body.pathPrefix === 'string') {
      pathPrefix = body.pathPrefix.trim().replace(/^\/+|\/+$/g, '');
    } else {
      return { ok: false, error: '"pathPrefix" must be a string or null' };
    }
  }

  let intervalMinutes = 60;
  if (!partial || body.intervalMinutes !== undefined) {
    const v = Number(body.intervalMinutes);
    if (!Number.isInteger(v) || v < 0 || v > 1440) return { ok: false, error: '"intervalMinutes" must be an integer between 0 (manual only) and 1440' };
    intervalMinutes = v;
  }

  // Cross-field validation needs both kind + url.
  const finalKind = (out.kind ?? kind) as 'yaml-url' | 'github-repo';
  const finalUrl = typeof out.url === 'string' ? out.url : undefined;
  if (finalUrl !== undefined) {
    if (finalKind === 'yaml-url') {
      if (!/^https?:\/\//i.test(finalUrl)) return { ok: false, error: '"url" must be an http(s):// URL for kind "yaml-url"' };
    } else {
      const ref = normalizeGithubRepo(finalUrl);
      if (!ref) return { ok: false, error: '"url" is not a recognizable GitHub repo reference (github.com/owner/repo or owner/repo)' };
      // A prefix extracted from a pasted tree/blob URL wins over an explicit one only when none was given.
      if (pathPrefix === null && ref.pathPrefix) pathPrefix = ref.pathPrefix;
    }
  }

  out.kind = finalKind;
  out.pathPrefix = pathPrefix;
  out.intervalMinutes = intervalMinutes;
  return { ok: true, values: out as { name?: string; kind: 'yaml-url' | 'github-repo'; url?: string; pathPrefix: string | null; intervalMinutes: number } };
}

/** GET /v1/log-rule-feeds — all feeds with sync state. */
router.get('/log-rule-feeds', requireAuth, requirePermission('security:read'), async (_req: Request, res: Response) => {
  try {
    const r = await pool.query<FeedRow>(`${FEED_SELECT} ORDER BY name`);
    res.status(200).json({ feeds: r.rows.map(feedToJson) });
  } catch (error) {
    console.error('Error querying log rule feeds:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** POST /v1/log-rule-feeds — create a feed. */
router.post('/log-rule-feeds', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const v = validateFeedInput(body, false);
    if (!v.ok) {
      res.status(400).json({ error: v.error });
      return;
    }
    const dup = await pool.query(`SELECT id FROM log_rule_feeds WHERE name = $1`, [v.values.name]);
    if (dup.rows.length > 0) {
      res.status(409).json({ error: `a feed named "${v.values.name}" already exists` });
      return;
    }
    const id = randomUUID();
    const nowIso = new Date().toISOString();
    await pool.query(
      `INSERT INTO log_rule_feeds (id, name, kind, url, "pathPrefix", enabled, "intervalMinutes", "ruleCount", "createdAt", "updatedAt")
       VALUES ($1, $2, $3, $4, $5, true, $6, 0, $7, $7)`,
      [id, v.values.name, v.values.kind, v.values.url, v.values.pathPrefix, v.values.intervalMinutes, nowIso]
    );
    const created = await pool.query<FeedRow>(`${FEED_SELECT} WHERE id = $1`, [id]);
    res.status(201).json(feedToJson(created.rows[0]));
  } catch (error) {
    console.error('Error creating log rule feed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** PATCH /v1/log-rule-feeds/:id — update name/kind/url/pathPrefix/intervalMinutes/enabled. */
router.patch('/log-rule-feeds/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const pre = await pool.query<FeedRow>(`${FEED_SELECT} WHERE id = $1`, [req.params.id]);
    if (pre.rows.length === 0) {
      res.status(404).json({ error: 'feed not found' });
      return;
    }
    const body = (req.body ?? {}) as Record<string, unknown>;

    // Merge current values so cross-field validation sees the full picture.
    const merged: Record<string, unknown> = { ...pre.rows[0], ...body };
    const v = validateFeedInput(merged, true);
    if (!v.ok) {
      res.status(400).json({ error: v.error });
      return;
    }

    const sets: string[] = [];
    const params: unknown[] = [];
    for (const key of ['name', 'kind', 'url', 'pathPrefix', 'intervalMinutes'] as const) {
      if (body[key] !== undefined || (key === 'pathPrefix' && body.pathPrefix === null)) {
        params.push(v.values[key]);
        sets.push(`"${key}" = $${params.length}`);
      }
    }
    if (body.enabled !== undefined) {
      if (typeof body.enabled !== 'boolean') {
        res.status(400).json({ error: '"enabled" must be a boolean' });
        return;
      }
      params.push(body.enabled);
      sets.push(`enabled = $${params.length}`);
    }
    if (sets.length === 0) {
      res.status(400).json({ error: 'no fields to update' });
      return;
    }

    // Name uniqueness when the name changes.
    if (body.name !== undefined && String(body.name).trim() !== pre.rows[0].name) {
      const dup = await pool.query(`SELECT id FROM log_rule_feeds WHERE name = $1 AND id <> $2`, [String(v.values.name), req.params.id]);
      if (dup.rows.length > 0) {
        res.status(409).json({ error: `a feed named "${v.values.name}" already exists` });
        return;
      }
    }

    params.push(new Date().toISOString());
    sets.push(`"updatedAt" = $${params.length}`);
    params.push(req.params.id);
    const updated = await pool.query<FeedRow>(`UPDATE log_rule_feeds SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING ${FEED_COLUMNS}`, params);
    res.status(200).json(feedToJson(updated.rows[0]));
  } catch (error) {
    console.error('Error updating log rule feed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** DELETE /v1/log-rule-feeds/:id — the feed's rules become ordinary user rules. */
router.delete('/log-rule-feeds/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const conv = await client.query(`UPDATE log_rules SET source = 'user', "feedId" = NULL, "updatedAt" = $1 WHERE "feedId" = $2`, [new Date().toISOString(), req.params.id]);
    const del = await client.query(`DELETE FROM log_rule_feeds WHERE id = $1`, [req.params.id]);
    await client.query('COMMIT');
    if (del.rowCount === 0) {
      res.status(404).json({ error: 'feed not found' });
      return;
    }
    invalidateLogRuleCache();
    res.status(200).json({ deleted: true, convertedRules: Number(conv.rowCount ?? 0) });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error deleting log rule feed:', error);
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

/** POST /v1/log-rule-feeds/:id/sync — run one sync cycle now (any replica). */
router.post('/log-rule-feeds/:id/sync', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const feedId = String(req.params.id); // Express 5 types params as string | string[]
    const pre = await pool.query<{ id: string }>(`SELECT id FROM log_rule_feeds WHERE id = $1`, [feedId]);
    if (pre.rows.length === 0) {
      res.status(404).json({ error: 'feed not found' });
      return;
    }
    if (isFeedSyncing(feedId)) {
      res.status(409).json({ error: 'a sync for this feed is already in progress' });
      return;
    }
    let result: FeedSyncResult;
    try {
      result = await syncLogRuleFeed(feedId);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      await recordFeedSyncError(feedId, msg).catch(() => undefined);
      res.status(502).json({ error: `feed sync failed: ${msg}` });
      return;
    }
    invalidateLogRuleCache();
    const feed = await pool.query<FeedRow>(`${FEED_SELECT} WHERE id = $1`, [feedId]);
    res.status(200).json({ ...result, feed: feedToJson(feed.rows[0]) });
  } catch (error) {
    console.error('Error syncing log rule feed:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
