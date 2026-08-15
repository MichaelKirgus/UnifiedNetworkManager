import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { query, DeviceRow, PluginRow, TelemetryRow, ConfigJobRow } from '../db';
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

router.get('/devices', requireAuth, async (req, res) => {
  const { vendor, site } = req.query;

  const clauses: string[] = [];
  const params: string[] = [];
  if (typeof vendor === 'string' && vendor.length > 0) {
    params.push(vendor);
    clauses.push(`vendor = $${params.length}`);
  }
  if (typeof site === 'string' && site.length > 0) {
    params.push(site);
    clauses.push(`site = $${params.length}`);
  }

  const where = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  const result = await query<DeviceRow>(
    `SELECT * FROM devices ${where} ORDER BY "createdAt" DESC`,
    params
  );

  res.status(200).json(result.rows.map(serializeDevice));
});

router.post('/devices', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { name, vendor, deviceType, pluginId, managementAddress, site } = req.body ?? {};

  const pluginResult = await query<PluginRow>('SELECT * FROM plugins WHERE id = $1', [pluginId]);
  if (!pluginResult.rows[0]) {
    res.status(404).json({ error: 'Referenced plugin not found' });
    return;
  }

  const id = uuidv4();
  const createdAt = new Date().toISOString();
  const status = 'unknown';

  await query(
    `INSERT INTO devices (id, name, vendor, "deviceType", "pluginId", "managementAddress", site, status, "createdAt")
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [id, name, vendor, deviceType, pluginId, managementAddress, site ?? null, status, createdAt]
  );

  const created = await query<DeviceRow>('SELECT * FROM devices WHERE id = $1', [id]);
  res.status(201).json(serializeDevice(created.rows[0]));
});

router.get('/devices/:deviceId/monitoring', requireAuth, async (req, res) => {
  const { deviceId } = req.params;

  const deviceResult = await query<DeviceRow>('SELECT * FROM devices WHERE id = $1', [deviceId]);
  if (!deviceResult.rows[0]) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  const telemetryResult = await query<TelemetryRow>(
    'SELECT * FROM telemetry WHERE "deviceId" = $1 ORDER BY "collectedAt" DESC LIMIT 1',
    [deviceId]
  );
  const telemetry = telemetryResult.rows[0];

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
  async (req, res) => {
    const { deviceId } = req.params;
    const { action, payload } = req.body ?? {};

    const deviceResult = await query<DeviceRow>('SELECT * FROM devices WHERE id = $1', [deviceId]);
    if (!deviceResult.rows[0]) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    const id = uuidv4();
    const createdAt = new Date().toISOString();

    await query(
      `INSERT INTO config_jobs (id, "deviceId", action, status, payload, result, "createdAt", "finishedAt")
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [id, deviceId, action, 'queued', JSON.stringify(payload ?? {}), null, createdAt, null]
    );

    configJobQueue.add(id, { jobId: id, deviceId });

    const createdResult = await query<ConfigJobRow>('SELECT * FROM config_jobs WHERE id = $1', [id]);
    const created = createdResult.rows[0];
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
