import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { pool } from '../db';
import { getEffectiveSettingValue } from '../systemSettings';
import { requireAuth, requirePermission } from '../auth/middleware';
import { THREAT_INTEL_FORMATS, ThreatIntelFormat, computeSourceHealth, getThreatIntelStats, invalidateIocCache, triggerThreatIntelFetch } from '../workers/threatIntel';
import { THREAT_INTEL_SOURCE_TEMPLATES } from '../threatIntelTemplates';
import { deleteRepoFile } from '../fileRepo';

/**
 * Threat intelligence — source management + status (Security page).
 *
 * IOC feed sources are rows in threat_intel_sources; the worker
 * (workers/threatIntel.ts) fetches them through the web-fetch broker and
 * matches flow destinations + firewall-event IPs against the active set,
 * raising 'ioc-hit' findings into flow_security_findings. This route manages
 * the sources and surfaces per-source status + recent hits. Reads are gated on
 * `security:read`; writes on `system:write`.
 */

const router = Router();

function parseLimit(v: unknown, fallback: number, max: number): number {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return fallback;
  return Math.min(Math.floor(n), max);
}

/** Device display info for the recent-hits column (id → name). */
async function loadDeviceNames(deviceIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (deviceIds.length === 0) return map;
  const res = await pool.query(`SELECT id, name FROM devices WHERE id = ANY($1::text[])`, [deviceIds]);
  for (const r of res.rows) map.set(String(r.id), String(r.name));
  return map;
}

/** Notification severities a feed may raise (drives finding + notification severity). */
const THREAT_INTEL_SEVERITIES = ['info', 'warning', 'critical'] as const;
type ThreatIntelSeverity = (typeof THREAT_INTEL_SEVERITIES)[number];

interface SourceRow {
  id: string;
  name: string;
  url: string;
  format: ThreatIntelFormat;
  enabled: boolean;
  severity: string;
  iocCount: number | string;
  lastSuccessAt: string | null;
  lastError: string | null;
  /** Central file-repo row holding the raw snapshot of the last successful fetch (null = none yet). */
  repoFileId?: string | null;
  content?: string | null; // manual (pasted) source body — null for URL feeds
  authHeader?: string | null; // "Name: value" sent with URL fetches
  failCount?: number | string; // consecutive fetch failures (auto-pause input)
  createdAt: string;
}

function sourceToJson(r: SourceRow) {
  return {
    id: String(r.id),
    name: String(r.name),
    url: String(r.url),
    format: String(r.format) as ThreatIntelFormat,
    enabled: Boolean(r.enabled),
    severity: (THREAT_INTEL_SEVERITIES as readonly string[]).includes(String(r.severity)) ? r.severity : 'warning',
    iocCount: Number(r.iocCount ?? 0),
    lastSuccessAt: r.lastSuccessAt ? String(r.lastSuccessAt) : null,
    lastError: r.lastError ? String(r.lastError) : null,
    repoFileId: r.repoFileId ? String(r.repoFileId) : null,
    content: r.content !== undefined && r.content !== null ? String(r.content) : null,
    authHeader: r.authHeader !== undefined && r.authHeader !== null ? String(r.authHeader) : null,
    failCount: Number(r.failCount ?? 0),
    health: computeSourceHealth({ enabled: Boolean(r.enabled), failCount: Number(r.failCount ?? 0) }),
    createdAt: String(r.createdAt),
  };
}

/** Validates a source create/update body; returns the clean fields or an error string. */
function validateSourceBody(body: Record<string, unknown>, partial: boolean): { name?: string; url?: string; format?: ThreatIntelFormat; severity?: ThreatIntelSeverity; content?: string; authHeader?: string | null } | string {
  const out: { name?: string; url?: string; format?: ThreatIntelFormat; severity?: ThreatIntelSeverity; content?: string; authHeader?: string | null } = {};
  if (!partial || body.name !== undefined) {
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (name.length < 1 || name.length > 100) return '"name" is required (1-100 characters)';
    out.name = name;
  }
  if (!partial || body.url !== undefined) {
    const url = typeof body.url === 'string' ? body.url.trim() : '';
    if (url !== '') {
      let ok = false;
      try {
        const u = new URL(url);
        ok = u.protocol === 'http:' || u.protocol === 'https:';
      } catch {
        ok = false;
      }
      if (!ok) return '"url" must be an http(s) URL';
    }
    out.url = url; // '' marks a manual source — the body lives in "content"
  }
  if (!partial || body.content !== undefined) {
    const content = typeof body.content === 'string' ? body.content : '';
    if (content.length > 2_048_576) return '"content" is too large (max 1 MiB)';
    out.content = content;
  }
  if (!partial || body.authHeader !== undefined) {
    const authHeader = typeof body.authHeader === 'string' ? body.authHeader.trim() : '';
    if (authHeader.length > 512) return '"authHeader" is too large (max 512 characters)';
    out.authHeader = authHeader || null; // empty string clears the header
  }
  if (!partial && !out.url && !out.content) {
    return 'provide a feed "url" or pasted "content"';
  }
  if (partial && out.url === '' && out.content === undefined) {
    return 'clearing "url" requires pasted "content" in the same update';
  }
  if (!partial || body.format !== undefined) {
    const format = typeof body.format === 'string' ? body.format : '';
    if (!(THREAT_INTEL_FORMATS as readonly string[]).includes(format)) return `"format" must be one of: ${THREAT_INTEL_FORMATS.join(', ')}`;
    out.format = format as ThreatIntelFormat;
  }
  if (!partial || body.severity !== undefined) {
    const severity = typeof body.severity === 'string' ? body.severity : '';
    if (!(THREAT_INTEL_SEVERITIES as readonly string[]).includes(severity)) return `"severity" must be one of: ${THREAT_INTEL_SEVERITIES.join(', ')}`;
    out.severity = severity as ThreatIntelSeverity;
  }
  return out;
}

/** GET /v1/threat-intel — worker status, all sources with per-source state, recent hits. */
router.get('/threat-intel', requireAuth, requirePermission('security:read'), async (req: Request, res: Response) => {
  try {
    const q = req.query as Record<string, unknown>;
    const limit = parseLimit(q.limit, 50, 200);

    const [srcRes, hitRes] = await Promise.all([
      pool.query<SourceRow>(`SELECT id, name, url, format, enabled, severity, "iocCount", "lastSuccessAt", "lastError", "repoFileId", "content", "authHeader", "failCount", "createdAt" FROM threat_intel_sources ORDER BY name`),
      pool.query(
        `SELECT id, kind, severity, "srcIp", "dstIp", detail, context, "deviceId", "firstSeenAt", "lastSeenAt", occurrences, status
         FROM flow_security_findings WHERE kind IN ('ioc-hit', 'dns-ioc-hit') AND status = 'open'
         ORDER BY "lastSeenAt" DESC LIMIT $1`,
        [limit]
      ),
    ]);

    const deviceIds = [...new Set(hitRes.rows.map((r: { deviceId: string | null }) => r.deviceId).filter(Boolean))];
    const names = await loadDeviceNames(deviceIds as string[]);

    res.status(200).json({
      enabled: (await getEffectiveSettingValue('threatIntelEnabled')) === true,
      worker: getThreatIntelStats(),
      sources: srcRes.rows.map(sourceToJson),
      recentHits: hitRes.rows.map((r) => {
        // The listed domain rides in the finding context for dns-ioc-hit rows.
        let domain: string | null = null;
        try {
          const ctx = JSON.parse(String(r.context ?? '{}')) as { domain?: unknown };
          if (typeof ctx.domain === 'string' && ctx.domain) domain = ctx.domain;
        } catch { /* context is best-effort — never fail the listing on it */ }
        return {
          id: String(r.id),
          kind: String(r.kind) as 'ioc-hit' | 'dns-ioc-hit',
          severity: String(r.severity),
          // Quoted DDL column names keep their case in pg result rows (r.srcIp, not r.srcip).
          srcIp: String(r.srcIp),
          dstIp: r.dstIp === null ? null : String(r.dstIp),
          domain,
          detail: String(r.detail ?? ''),
          deviceId: r.deviceId ? String(r.deviceId) : null,
          deviceName: r.deviceId ? (names.get(String(r.deviceId)) ?? null) : null,
          firstSeenAt: String(r.firstSeenAt),
          lastSeenAt: String(r.lastSeenAt),
          occurrences: Number(r.occurrences ?? 1),
        };
      }),
    });
  } catch (error) {
    console.error('Error querying threat intel:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** GET /v1/threat-intel/source-templates — built-in feed catalog for the Security page. */
router.get('/threat-intel/source-templates', requireAuth, requirePermission('security:read'), (_req: Request, res: Response) => {
  res.status(200).json({ templates: THREAT_INTEL_SOURCE_TEMPLATES });
});

/** POST /v1/threat-intel/sources — add a feed; the first fetch starts immediately. */
router.post('/threat-intel/sources', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const validated = validateSourceBody(body, false);
    if (typeof validated === 'string') {
      res.status(400).json({ error: validated });
      return;
    }

    // Unique name — a friendly 409 instead of the constraint violation.
    const dup = await pool.query(`SELECT id FROM threat_intel_sources WHERE name = $1`, [validated.name]);
    if (dup.rows.length > 0) {
      res.status(409).json({ error: `a source named "${validated.name}" already exists` });
      return;
    }

    const id = uuidv4();
    const nowIso = new Date().toISOString();
    await pool.query(
      `INSERT INTO threat_intel_sources (id, name, url, format, severity, enabled, "iocCount", "lastSuccessAt", "lastError", "content", "authHeader", "createdAt")
       VALUES ($1, $2, $3, $4, $5, true, 0, NULL, NULL, $6, $7, $8)`,
      [id, validated.name, validated.url ?? '', validated.format ?? 'ip-list', validated.severity ?? 'warning', validated.content ?? null, validated.authHeader ?? null, nowIso]
    );

    // First fetch is immediate — the beat's interval logic would otherwise wait.
    void triggerThreatIntelFetch(id);

    const created = await pool.query<SourceRow>(`SELECT id, name, url, format, enabled, severity, "iocCount", "lastSuccessAt", "lastError", "repoFileId", "content", "authHeader", "failCount", "createdAt" FROM threat_intel_sources WHERE id = $1`, [id]);
    res.status(201).json(sourceToJson(created.rows[0]));
  } catch (error) {
    console.error('Error creating threat-intel source:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** PATCH /v1/threat-intel/sources/:id — update name/url/format/enabled/severity. */
router.patch('/threat-intel/sources/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const validated = validateSourceBody(body, true);
    if (typeof validated === 'string') {
      res.status(400).json({ error: validated });
      return;
    }

    const sets: string[] = [];
    const params: unknown[] = [];
    for (const [col, val] of Object.entries(validated)) {
      params.push(val);
      sets.push(`"${col}" = $${params.length}`);
    }
    if (body.enabled !== undefined) {
      if (typeof body.enabled !== 'boolean') {
        res.status(400).json({ error: '"enabled" must be a boolean' });
        return;
      }
      params.push(body.enabled);
      sets.push(`enabled = $${params.length}`);
    }
    // Re-enabling a (possibly auto-paused) source starts with a clean failure slate.
    if (body.enabled === true) {
      sets.push(`"failCount" = 0`);
    }
    if (sets.length === 0) {
      res.status(400).json({ error: 'no fields to update' });
      return;
    }

    // A changed feed definition invalidates the previous snapshot — force an
    // immediate re-fetch by clearing lastSuccessAt.
    const definitionChanged = validated.url !== undefined || validated.format !== undefined || validated.content !== undefined || validated.authHeader !== undefined;
    if (definitionChanged) {
      sets.push(`"lastSuccessAt" = NULL`);
    }

    params.push(req.params.id);
    const upd = await pool.query(
      `UPDATE threat_intel_sources SET ${sets.join(', ')} WHERE id = $${params.length} RETURNING id, name, url, format, enabled, severity, "iocCount", "lastSuccessAt", "lastError", "repoFileId", "content", "authHeader", "failCount", "createdAt`,
      params
    );
    if (upd.rows.length === 0) {
      res.status(404).json({ error: 'source not found' });
      return;
    }

    const row = upd.rows[0] as SourceRow;
    if (definitionChanged && row.enabled) {
      void triggerThreatIntelFetch(row.id);
    }
    // Any enabled-state change must take effect immediately — the worker's
    // in-memory cache would otherwise keep a disabled source's indicators
    // matching (or an enabled one excluded) until its TTL expires.
    if (body.enabled !== undefined) invalidateIocCache();
    res.status(200).json(sourceToJson(row));
  } catch (error) {
    console.error('Error updating threat-intel source:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** DELETE /v1/threat-intel/sources/:id — remove the feed + its indicators. */
router.delete('/threat-intel/sources/:id', requireAuth, requirePermission('system:write'), async (req: Request, res: Response) => {
  try {
    // The raw snapshot file is pruned with the source (best-effort — a repo
    // hiccup must not block deleting the feed itself).
    const pre = await pool.query<{ "repoFileId": string | null }>(`SELECT "repoFileId" FROM threat_intel_sources WHERE id = $1`, [req.params.id]);
    const del = await pool.query(`DELETE FROM threat_intel_sources WHERE id = $1`, [req.params.id]);
    if (del.rowCount === 0) {
      res.status(404).json({ error: 'source not found' });
      return;
    }
    const repoFileId = pre.rows[0]?.['repoFileId'];
    if (repoFileId) await deleteRepoFile(String(repoFileId)).catch(() => undefined);
    // Deleted indicators must stop matching immediately, not on the cache TTL.
    invalidateIocCache();
    res.status(200).json({ deleted: true });
  } catch (error) {
    console.error('Error deleting threat-intel source:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

/** POST /v1/threat-intel/fetch — run one fetch cycle for all enabled sources now. */
router.post('/threat-intel/fetch', requireAuth, requirePermission('system:write'), async (_req: Request, res: Response) => {
  try {
    const result = await triggerThreatIntelFetch();
    if (result.triggered === 0) {
      res.status(409).json({ error: 'no enabled sources to fetch' });
      return;
    }
    res.status(202).json(result);
  } catch (error) {
    console.error('Error triggering threat-intel fetch:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
