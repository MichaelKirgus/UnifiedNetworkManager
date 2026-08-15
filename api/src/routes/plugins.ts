import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { query, PluginRow } from '../db';
import { requireAuth, requirePermission } from '../auth/middleware';

const router = Router();

function serializePlugin(row: PluginRow) {
  return {
    id: row.id,
    name: row.name,
    version: row.version,
    vendors: JSON.parse(row.vendors),
    capabilities: JSON.parse(row.capabilities),
    endpoint: row.endpoint,
    authType: row.authType,
  };
}

router.get('/plugins', requireAuth, async (_req, res) => {
  const result = await query<PluginRow>('SELECT * FROM plugins ORDER BY "createdAt" DESC');
  res.status(200).json(result.rows.map(serializePlugin));
});

router.post('/plugins', requireAuth, requirePermission('plugins:manage'), async (req, res) => {
  const { name, version, vendors, capabilities, endpoint, authType } = req.body ?? {};

  const id = uuidv4();
  const createdAt = new Date().toISOString();

  await query(
    `INSERT INTO plugins (id, name, version, vendors, capabilities, endpoint, "authType", "createdAt")
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      id,
      name,
      version,
      JSON.stringify(vendors ?? []),
      JSON.stringify(capabilities ?? []),
      endpoint,
      authType ?? 'none',
      createdAt,
    ]
  );

  const created = await query<PluginRow>('SELECT * FROM plugins WHERE id = $1', [id]);
  res.status(201).json(serializePlugin(created.rows[0]));
});

export default router;
