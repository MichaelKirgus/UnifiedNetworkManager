import { Router } from 'express';
import { desc } from 'drizzle-orm';
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

export default router;
