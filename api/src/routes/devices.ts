import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, DeviceRow, PluginRow, TelemetryRow, ConfigJobRow } from '../db';
import { requireAuth, requirePermission, require2FA } from '../auth/middleware';
import { configJobQueue } from '../queue';

const router = Router();

function serializeDevice(row: DeviceRow) {
  return {
    id: row.id,
    name: row.name,
    vendor: row.vendor,
    deviceType: row.deviceType,
    pluginId: row.pluginId,
    managementAddress: row.managementAddress,
    site: row.site ?? undefined,
    status: row.status,
  };
}

router.get('/devices', requireAuth, (req, res) => {
  const { vendor, site } = req.query;

  const clauses: string[] = [];
  const params: string[] = [];
  if (typeof vendor === 'string' && vendor.length > 0) {
    clauses.push('vendor = ?');
    params.push(vendor);
  }
  if (typeof site === 'string' && site.length > 0) {
    clauses.push('site = ?');
    params.push(site);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const rows = db
    .prepare(`SELECT * FROM devices ${where} ORDER BY createdAt DESC`)
    .all(...params) as DeviceRow[];

  res.status(200).json(rows.map(serializeDevice));
});

router.post('/devices', requireAuth, requirePermission('devices:write'), (req, res) => {
  const { name, vendor, deviceType, pluginId, managementAddress, site } = req.body ?? {};

  const plugin = db.prepare('SELECT * FROM plugins WHERE id = ?').get(pluginId) as PluginRow | undefined;
  if (!plugin) {
    res.status(404).json({ error: 'Referenced plugin not found' });
    return;
  }

  const id = uuidv4();
  const createdAt = new Date().toISOString();
  const status = 'unknown';

  db.prepare(
    `INSERT INTO devices (id, name, vendor, deviceType, pluginId, managementAddress, site, status, createdAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(id, name, vendor, deviceType, pluginId, managementAddress, site ?? null, status, createdAt);

  const created = db.prepare('SELECT * FROM devices WHERE id = ?').get(id) as DeviceRow;
  res.status(201).json(serializeDevice(created));
});

router.get('/devices/:deviceId/monitoring', requireAuth, (req, res) => {
  const { deviceId } = req.params;

  const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as DeviceRow | undefined;
  if (!device) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  const telemetry = db
    .prepare('SELECT * FROM telemetry WHERE deviceId = ? ORDER BY collectedAt DESC LIMIT 1')
    .get(deviceId) as TelemetryRow | undefined;

  if (!telemetry) {
    res.status(200).json({
      deviceId,
      collectedAt: new Date().toISOString(),
      health: 'unknown',
      metrics: {},
    });
    return;
  }

  res.status(200).json({
    deviceId: telemetry.deviceId,
    collectedAt: telemetry.collectedAt,
    health: telemetry.health,
    metrics: JSON.parse(telemetry.metrics),
  });
});

router.post(
  '/devices/:deviceId/config-jobs',
  requireAuth,
  require2FA,
  requirePermission('configs:apply'),
  (req, res) => {
    const { deviceId } = req.params;
    const { action, payload } = req.body ?? {};

    const device = db.prepare('SELECT * FROM devices WHERE id = ?').get(deviceId) as DeviceRow | undefined;
    if (!device) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    const id = uuidv4();
    const createdAt = new Date().toISOString();

    db.prepare(
      `INSERT INTO config_jobs (id, deviceId, action, status, payload, result, createdAt, finishedAt)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, deviceId, action, 'queued', JSON.stringify(payload ?? {}), null, createdAt, null);

    configJobQueue.add(id, { jobId: id, deviceId });

    const created = db.prepare('SELECT * FROM config_jobs WHERE id = ?').get(id) as ConfigJobRow;
    res.status(202).json({
      id: created.id,
      deviceId: created.deviceId,
      action: created.action,
      status: created.status,
      result: created.result ? JSON.parse(created.result) : undefined,
      createdAt: created.createdAt,
      finishedAt: created.finishedAt ?? undefined,
    });
  }
);

export default router;
