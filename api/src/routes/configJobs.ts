import { Router } from 'express';
import { db, ConfigJobRow } from '../db';
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

router.get('/config-jobs/:jobId', requireAuth, (req, res) => {
  const { jobId } = req.params;
  const job = db.prepare('SELECT * FROM config_jobs WHERE id = ?').get(jobId) as ConfigJobRow | undefined;
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
configJobsListRouter.get('/config-jobs', requireAuth, (_req, res) => {
  const rows = db.prepare('SELECT * FROM config_jobs ORDER BY createdAt DESC LIMIT 100').all() as ConfigJobRow[];
  res.status(200).json(rows.map(serializeConfigJob));
});

export default router;
