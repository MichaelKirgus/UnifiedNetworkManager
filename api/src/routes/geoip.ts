import { Router, Request, Response } from 'express';
import { pool } from '../db';
import { requireAuth, requirePermission } from '../auth/middleware';
import { getEffectiveValues } from '../systemSettings';
import { getRepoFile } from '../fileRepo';
import { geoipCycle } from '../workers/geoip';

/**
 * GeoIP status + manual refresh (the Settings page "GeoIP" category).
 *
 * GET  /v1/geoip/status   — current source config, the active database file
 *                           (name/size/sha256) and the last fetch outcome.
 * POST /v1/geoip/refresh  — run one fetch cycle NOW (bypasses the interval).
 *                           The worker's normal cadence is untouched; a manual
 *                           refresh just does what the next beat would do.
 */

const router = Router();

/** Worker-managed status rows live in system_settings under geoip* keys. */
async function readWorkerStatus(): Promise<{ lastAttemptAt: string | null; lastSuccessAt: string | null; lastError: string }> {
  const out = { lastAttemptAt: null as string | null, lastSuccessAt: null as string | null, lastError: '' };
  try {
    const res = await pool.query(
      `SELECT "key", value FROM system_settings WHERE "key" IN ('geoipLastAttemptAt','geoipLastSuccessAt','geoipLastError')`
    );
    for (const row of res.rows) {
      if (row.key === 'geoipLastAttemptAt' && String(row.value)) out.lastAttemptAt = String(row.value);
      else if (row.key === 'geoipLastSuccessAt' && String(row.value)) out.lastSuccessAt = String(row.value);
      else if (row.key === 'geoipLastError') out.lastError = String(row.value);
    }
  } catch { /* table hiccup — report as fresh */ }
  return out;
}

/** Builds the status payload shared by GET /status and POST /refresh. */
async function buildStatus(): Promise<Record<string, unknown>> {
  const values = await getEffectiveValues();
  const activeFileId = String(values.geoipActiveFileId ?? '').trim();
  const file = activeFileId ? await getRepoFile(activeFileId) : null;

  return {
    enabled: Boolean(values.geoipEnabled),
    source: String(values.geoipSource ?? ''),
    customUrlConfigured: String(values.geoipCustomUrl ?? '').length > 0,
    fetchIntervalHours: Number(values.geoipFetchIntervalHours ?? 720),
    deleteOldFiles: Boolean(values.geoipDeleteOldFiles),
    proxyConfigured: String(values.webFetchProxyUrl ?? '').length > 0,
    activeFileId: file ? file.id : null,
    activeFileName: file ? file.name : null,
    activeFileSizeBytes: file ? file.sizeBytes : null,
    activeFileSha256: file ? file.sha256 : null,
    activeFileCreatedAt: file ? file.createdAt : null,
    ...(await readWorkerStatus()),
  };
}

// GET /geoip/status — current GeoIP state (read permission: flows:read, since
// the data feeds the Flows page; system:read would also fit but flows:read is
// what every consumer of this feature already holds).
router.get('/geoip/status', requireAuth, requirePermission('flows:read'), async (_req: Request, res: Response) => {
  try {
    res.status(200).json(await buildStatus());
  } catch (error) {
    console.error('Error reading geoip status:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /geoip/refresh — run one fetch cycle now. system:write because it
// triggers an outbound download + file-repo writes (same class as settings).
router.post('/geoip/refresh', requireAuth, requirePermission('system:write'), async (_req: Request, res: Response) => {
  try {
    await geoipCycle(); // never throws — failures land in the status rows
    const status = await buildStatus();
    if (status.lastError && !status.activeFileId) {
      res.status(502).json({ ...status, error: String(status.lastError) });
    } else {
      res.status(200).json(status);
    }
  } catch (error) {
    console.error('Error refreshing geoip:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
