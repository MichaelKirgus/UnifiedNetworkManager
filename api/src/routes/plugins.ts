import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, PluginRow } from '../db';
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

router.get('/plugins', requireAuth, (_req, res) => {
  const rows = db.prepare('SELECT * FROM plugins ORDER BY createdAt DESC').all() as PluginRow[];
  res.status(200).json(rows.map(serializePlugin));
});

router.post('/plugins', requireAuth, requirePermission('plugins:manage'), (req, res) => {
  const { name, version, vendors, capabilities, endpoint, authType } = req.body ?? {};

  const id = uuidv4();
  const createdAt = new Date().toISOString();

  db.prepare(
    `INSERT INTO plugins (id, name, version, vendors, capabilities, endpoint, authType, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    id,
    name,
    version,
    JSON.stringify(vendors ?? []),
    JSON.stringify(capabilities ?? []),
    endpoint,
    authType ?? 'none',
    createdAt
  );

  const created = db.prepare('SELECT * FROM plugins WHERE id = ?').get(id) as PluginRow;
  res.status(201).json(serializePlugin(created));
});

export default router;
