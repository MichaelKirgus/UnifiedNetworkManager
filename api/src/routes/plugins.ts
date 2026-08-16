import { Router } from 'express';
import { desc } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth } from '../auth/middleware';

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

export default router;
