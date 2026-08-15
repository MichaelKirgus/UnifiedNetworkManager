import { Router } from 'express';
import { query, ConfigJobRow } from '../db';
import { requireAuth } from '../auth/middleware';

const router = Router();

function serializeConfigJob(row: ConfigJobRow) {
  return {
    id: row.id,
    deviceId: row.deviceId,
    action: row.action,
    status: row.status,
    result: row.result ? JSON.parse(row.result) : undefined,
    createdAt: row.createdAt,
    finishedAt: row.finishedAt ?? undefined,
  };
}

router.get('/config-jobs/:jobId', requireAuth, async (req, res) => {
  const { jobId } = req.params;
  const result = await query<ConfigJobRow>('SELECT * FROM config_jobs WHERE id = $1', [jobId]);
  const job = result.rows[0];
  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }
  res.status(200).json(serializeConfigJob(job));
});

/**
 * Not part of the formal OpenAPI contract (which only defines the
 * per-job GET), but useful for the web app's "recent config jobs" view
 * across all devices. Because express-openapi-validator 404s any path it
 * doesn't recognize from the spec, this router must be mounted *before*
 * the validator middleware in index.ts.
 */
export const configJobsListRouter = Router();
configJobsListRouter.get('/config-jobs', requireAuth, async (_req, res) => {
  const result = await query<ConfigJobRow>('SELECT * FROM config_jobs ORDER BY "createdAt" DESC LIMIT 100');
  res.status(200).json(result.rows.map(serializeConfigJob));
});

export default router;
