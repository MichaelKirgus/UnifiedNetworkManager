import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, Device, Plugin, Telemetry, ConfigJob } from '../db';
import { encrypt } from '../utils/crypto';
import { requireAuth, requirePermission, require2FA } from '../auth/middleware';
import { configJobQueue } from '../queue';
import { eq, and, desc } from 'drizzle-orm';
import * as schema from '../db/schema';

const router = Router();

function serializeDevice(row: Device) {
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

  const filters = [];
  if (typeof vendor === 'string' && vendor.length > 0) {
    filters.push(eq(schema.devices.vendor, vendor));
  }
  if (typeof site === 'string' && site.length > 0) {
    filters.push(eq(schema.devices.site, site));
  }

  const result = await db.query.devices.findMany({
    where: filters.length > 0 ? and(...filters) : undefined,
    orderBy: [desc(schema.devices.createdAt)],
  });

  res.status(200).json(result.map(serializeDevice));
});

router.post('/devices', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { name, vendor, deviceType, pluginId, managementAddress, site, credentialsRef } = req.body ?? {};

  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!plugin) {
    res.status(404).json({ error: 'Referenced plugin not found' });
    return;
  }

  // Verify that the provided credentials reference exists in the secret store
  const secret = await db.query.secrets.findFirst({
    where: (secrets, { eq }) => eq(secrets.id, credentialsRef),
  });
  if (!secret) {
    res.status(404).json({ error: 'Referenced credentials (credentialsRef) not found' });
    return;
  }

  const id = uuidv4();
  const createdAt = new Date().toISOString();
  const status = 'unknown';

  await db.insert(schema.devices).values({
    id,
    name,
    vendor,
    deviceType,
    pluginId,
    managementAddress,
    site: site ?? null,
    status,
    secretId: credentialsRef,
    createdAt,
  });

  const created = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, id),
  });
  if (!created) {
    res.status(500).json({ error: 'Failed to retrieve created device' });
    return;
  }
  res.status(201).json(serializeDevice(created));
});

router.get('/devices/:deviceId/monitoring', requireAuth, async (req, res) => {
  const { deviceId } = req.params;

  const device = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
  if (!device) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  const telemetry = await db.query.telemetry.findFirst({
    where: (telemetry, { eq }) => eq(telemetry.deviceId, deviceId),
    orderBy: [desc(schema.telemetry.collectedAt)],
  });

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
    metrics: typeof telemetry.metrics === 'string' ? JSON.parse(telemetry.metrics) : telemetry.metrics,
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

    const device = await db.query.devices.findFirst({
      where: (devices, { eq }) => eq(devices.id, deviceId),
    });
    if (!device) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    const id = uuidv4();
    const createdAt = new Date().toISOString();

    await db.insert(schema.configJobs).values({
      id,
      deviceId,
      action,
      status: 'queued',
      payload: JSON.stringify(payload ?? {}),
      result: null,
      createdAt,
      finishedAt: null,
    });

    configJobQueue.add(id, { jobId: id, deviceId });

    const created = await db.query.configJobs.findFirst({
      where: (configJobs, { eq }) => eq(configJobs.id, id),
    });
    if (!created) {
      res.status(500).json({ error: 'Failed to retrieve created config job' });
      return;
    }
    res.status(202).json({
      id: created.id,
      deviceId: created.deviceId,
      action: created.action,
      status: created.status,
      result: created.result ? (typeof created.result === 'string' ? JSON.parse(created.result) : created.result) : undefined,
      createdAt: created.createdAt,
      finishedAt: created.finishedAt ?? undefined,
    });
  }
);

export default router;
