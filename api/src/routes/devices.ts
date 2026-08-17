import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, Device, Plugin, Telemetry, ConfigJob } from '../db';
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

/**
 * Computes the "summary" metrics for a device from its latest telemetry row.
 * A plugin marks its headline metrics with `summary: true` in the descriptor
 * (e.g. CPU %, Memory %). Those are the values shown inline in the device
 * overview table — the flexible "most important metrics" hook. Returns an empty
 * array when the device has no telemetry or no summary metrics declared.
 */
function summaryMetricsFor(telemetry: { metrics: unknown; metricDescriptors: unknown } | undefined) {
  if (!telemetry) return [];
  const metrics =
    typeof telemetry.metrics === 'string' ? JSON.parse(telemetry.metrics) : (telemetry.metrics ?? {});
  const descriptors =
    typeof telemetry.metricDescriptors === 'string'
      ? JSON.parse(telemetry.metricDescriptors)
      : (telemetry.metricDescriptors ?? []);
  const out: {
    key: string;
    label: string;
    value: unknown;
    unit?: string;
    format?: string;
    visualization: string;
    min?: number;
    max?: number;
    color?: string;
  }[] = [];
  for (const d of descriptors) {
    if (!d || d.summary !== true) continue;
    out.push({
      key: d.key,
      label: d.label,
      value: metrics[d.key],
      unit: d.unit,
      format: d.format,
      visualization: d.visualization,
      min: d.min,
      max: d.max,
      color: d.color,
    });
  }
  return out;
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

  // Attach the latest telemetry's summary metrics to each device so the
  // overview table can render headline values (CPU, memory, ...) inline.
  const withMetrics = await Promise.all(
    result.map(async (device) => {
      const telemetry = await db.query.telemetry.findFirst({
        where: (t, { eq }) => eq(t.deviceId, device.id),
        orderBy: [desc(schema.telemetry.collectedAt)],
      });
      return { ...serializeDevice(device), summaryMetrics: summaryMetricsFor(telemetry) };
    })
  );

  res.status(200).json(withMetrics);
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
      metricDescriptors: [],
    });
    return;
  }

  const descriptors = telemetry.metricDescriptors
    ? (typeof telemetry.metricDescriptors === 'string'
        ? JSON.parse(telemetry.metricDescriptors)
        : telemetry.metricDescriptors)
    : [];

  res.status(200).json({
    deviceId: telemetry.deviceId,
    collectedAt: telemetry.collectedAt,
    health: telemetry.health,
    metrics: typeof telemetry.metrics === 'string' ? JSON.parse(telemetry.metrics) : telemetry.metrics,
    metricDescriptors: descriptors,
  });
});

// GET /devices/:deviceId/telemetry - Recent telemetry history (for plot metrics).
router.get('/devices/:deviceId/telemetry', requireAuth, async (req, res) => {
  const { deviceId } = req.params;
  const limit = Math.min(Number(req.query.limit ?? 30) || 30, 200);

  const device = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
  if (!device) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  const rows = await db.query.telemetry.findMany({
    where: (telemetry, { eq }) => eq(telemetry.deviceId, deviceId),
    orderBy: [desc(schema.telemetry.collectedAt)],
    limit,
  });

  // Oldest → newest for plotting.
  const history = rows
    .slice()
    .reverse()
    .map((r) => ({
      collectedAt: r.collectedAt,
      health: r.health,
      metrics: typeof r.metrics === 'string' ? JSON.parse(r.metrics) : r.metrics,
    }));

  res.status(200).json({ deviceId, history });
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
