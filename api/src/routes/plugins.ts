import { Router } from 'express';
import { desc, eq } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';
import { getRequiredSecretType } from '../secretsProvider';

const router = Router();

function serializePlugin(row: any) {
  return {
    id: row.id,
    name: row.name,
    version: row.version,
    vendors: typeof row.vendors === 'string' ? JSON.parse(row.vendors) : row.vendors,
    capabilities: typeof row.capabilities === 'string' ? JSON.parse(row.capabilities) : row.capabilities,
    endpoint: row.endpoint,
    authType: row.authType,
    lastSeenAt: row.lastSeenAt ?? null,
  };
}

router.get('/plugins', requireAuth, async (_req, res) => {
  const result = await db.query.plugins.findMany({
    orderBy: [desc(schema.plugins.createdAt)],
  });
  res.status(200).json(result.map(serializePlugin));
});

// GET /plugins/:id/required-secret-type - The secret type a device plugin
// expects for its device credentials (read from the plugin's /discover).
router.get('/plugins/:id/required-secret-type', requireAuth, async (req, res) => {
  const { id } = req.params;
  const requiredSecretType = await getRequiredSecretType(id);
  res.status(200).json({ requiredSecretType });
});

// GET /plugins/:id/metrics - The metric descriptors a plugin declared in its
// /discover endpoint. The webapp renders device metrics generically from these
// (gauge/plot/text/table), so new plugins/metrics need no webapp changes.
router.get('/plugins/:id/metrics', requireAuth, async (req, res) => {
  const { id } = req.params;
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, id),
  });
  if (!row) {
    res.status(404).json({ error: 'Plugin not found' });
    return;
  }
  let metrics: unknown[] = [];
  if (row.metricDescriptors) {
    try {
      const parsed = JSON.parse(row.metricDescriptors);
      metrics = Array.isArray(parsed) ? parsed : [];
    } catch {
      metrics = [];
    }
  }
  res.status(200).json({ pluginId: id, metrics });
});

export default router;
