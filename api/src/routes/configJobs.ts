import { Router } from 'express';
import { db } from '../db';
import { eq, desc } from 'drizzle-orm';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';

const router = Router();

function serializeConfigJob(row: any) {
  return {
    id: row.id,
    deviceId: row.deviceId,
    pluginId: row.pluginId ?? undefined,
    action: row.action,
    status: row.status,
    result: row.result ? JSON.parse(row.result) : undefined,
    createdAt: row.createdAt,
    finishedAt: row.finishedAt ?? undefined,
  };
}

router.get('/config-jobs/:jobId', requireAuth, requirePermission('config-jobs:read'), async (req, res) => {
  const { jobId } = req.params;
  const job = await db.query.configJobs.findFirst({
    where: (configJobs, { eq }) => eq(configJobs.id, jobId),
  });
  if (!job) {
    res.status(404).json({ error: 'Job not found' });
    return;
  }
  // Device-level access control — a job on an out-of-scope device is invisible.
  const allowed = await allowedDeviceIds(req);
  if (allowed !== null && !allowed.has(job.deviceId)) {
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
configJobsListRouter.get('/config-jobs', requireAuth, requirePermission('config-jobs:read'), async (_req, res) => {
  const jobs = await db.query.configJobs.findMany({
    orderBy: [desc(schema.configJobs.createdAt)],
    limit: 100,
  });
  // Device-level access control — only jobs on the caller's devices are listed.
  const allowed = await allowedDeviceIds(_req);
  const visible = allowed !== null ? jobs.filter((j) => allowed.has(j.deviceId)) : jobs;
  res.status(200).json(visible.map(serializeConfigJob));
});

export default router;
