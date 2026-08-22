import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, Device, Plugin, Telemetry, ConfigJob } from '../db';
import { requireAuth, requirePermission, require2FA } from '../auth/middleware';
import { configJobQueue } from '../queue';
import { eq, and, desc, inArray } from 'drizzle-orm';
import * as schema from '../db/schema';
import {
  AssignmentError,
  addAssignment,
  listAssignmentViews,
  removeAssignment,
  setPrimary,
  updateAssignment,
} from '../devicePlugins';
import {
  SettingsValidationError,
  getDevicePluginOptions,
  resetDevicePluginSettings,
  upsertDevicePluginSettings,
} from '../pluginSettings';
import {
  IpError,
  addDeviceIp,
  listDeviceAddresses,
  removeDeviceIp,
} from '../deviceIps';
import { isValidAddress, addressError } from '../utils/address';

const router = Router();

function serializeDevice(row: Device, siteName?: string | null) {
  return {
    id: row.id,
    name: row.name,
    vendor: row.vendor,
    deviceType: row.deviceType,
    managementAddress: row.managementAddress,
    siteId: row.siteId ?? undefined,
    siteName: siteName ?? null,
    status: row.status,
  };
}

/** Batch-loads the names of the sites referenced by a set of devices. */
async function siteNamesFor(devices: Device[]): Promise<Map<string, string>> {
  const ids = [...new Set(devices.map((d) => d.siteId).filter((v): v is string => !!v))];
  if (ids.length === 0) return new Map();
  const rows = await db.query.sites.findMany({ where: inArray(schema.sites.id, ids) });
  return new Map(rows.map((s) => [s.id, s.name]));
}

/** Validates a siteId reference; returns the id or an error message. */
async function validateSiteRef(siteId: unknown): Promise<{ value?: string | null; error?: string }> {
  if (siteId === undefined || siteId === null) return { value: null };
  if (typeof siteId !== 'string' || siteId.trim().length === 0) {
    return { error: '"siteId" must be a non-empty string or null' };
  }
  const found = await db.query.sites.findFirst({ where: eq(schema.sites.id, siteId.trim()) });
  if (!found) return { error: `Unknown site: ${siteId}` };
  return { value: siteId.trim() };
}

/** Maps AssignmentError (404/409) to an HTTP response; returns true when handled. */
function sendAssignmentError(res: any, err: unknown): boolean {
  if (err instanceof AssignmentError) {
    res.status(err.status).json({ error: err.message });
    return true;
  }
  return false;
}

/** Maps IpError (400/404/409) to an HTTP response; returns true when handled. */
function sendIpError(res: any, err: unknown): boolean {
  if (err instanceof IpError) {
    res.status(err.status).json({ error: err.message });
    return true;
  }
  return false;
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
  const { vendor, siteId } = req.query;

  const filters = [];
  if (typeof vendor === 'string' && vendor.length > 0) {
    filters.push(eq(schema.devices.vendor, vendor));
  }
  if (typeof siteId === 'string' && siteId.length > 0) {
    filters.push(eq(schema.devices.siteId, siteId));
  }

  const result = await db.query.devices.findMany({
    where: filters.length > 0 ? and(...filters) : undefined,
    orderBy: [desc(schema.devices.createdAt)],
  });
  const siteNames = await siteNamesFor(result);

  // Attach the plugin assignments + each assignment's latest summary metrics
  // so the overview table can render headline values (CPU, memory, ...) inline.
  const withPlugins = await Promise.all(
    result.map(async (device) => {
      const plugins = await listAssignmentViews(device.id);
      const perPluginTelemetry = await Promise.all(
        plugins.map((p) =>
          db.query.telemetry
            .findFirst({
              where: and(eq(schema.telemetry.deviceId, device.id), eq(schema.telemetry.pluginId, p.pluginId)),
              orderBy: [desc(schema.telemetry.collectedAt)],
            })
            .catch(() => undefined)
        )
      );
      const summaryMetrics = perPluginTelemetry.flatMap((t) => summaryMetricsFor(t));
      let ips: { address: string; isPrimary: boolean }[] = [];
      try {
        ips = await listDeviceAddresses(device.id);
      } catch {
        /* device exists — treat as no secondaries */
      }
      return {
        ...serializeDevice(device, siteNames.get(device.siteId ?? '') ?? null),
        plugins,
        summaryMetrics,
        ips,
      };
    })
  );

  res.status(200).json(withPlugins);
});

interface DevicePluginRef {
  pluginId?: string;
  secretId?: string | null;
  isPrimary?: boolean;
}

router.post('/devices', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { name, vendor, deviceType, managementAddress, siteId, plugins, ips } = req.body ?? {};

  if (!Array.isArray(plugins) || plugins.length === 0) {
    res.status(400).json({ error: 'At least one plugin assignment is required ("plugins": [{ "pluginId", ... }])' });
    return;
  }
  for (const ref of plugins as DevicePluginRef[]) {
    if (!ref || typeof ref.pluginId !== 'string') {
      res.status(400).json({ error: 'Each plugin assignment needs a "pluginId"' });
      return;
    }
  }

  // The primary address must be a bare IPv4/IPv6 literal or DNS name — the
  // transport scheme (https/http, self-signed) is each plugin's own decision.
  if (!isValidAddress(managementAddress)) {
    res.status(400).json({ error: `"managementAddress": ${addressError(managementAddress)}` });
    return;
  }

  // Optional site reference (must point at an existing site, or null/omitted).
  const siteRef = await validateSiteRef(siteId);
  if (siteRef.error) {
    res.status(400).json({ error: siteRef.error });
    return;
  }

  // Optional secondary IPs (validated here; addDeviceIp re-checks + dedupes).
  const secondaryIps: string[] = [];
  if (ips !== undefined) {
    if (!Array.isArray(ips)) {
      res.status(400).json({ error: '"ips" must be an array of address strings' });
      return;
    }
    for (const ip of ips as unknown[]) {
      if (!isValidAddress(ip)) {
        res.status(400).json({ error: `Invalid secondary IP: ${addressError(ip)}` });
        return;
      }
      secondaryIps.push((ip as string).trim());
    }
  }

  const id = uuidv4();
  await db.insert(schema.devices).values({
    id,
    name,
    vendor,
    deviceType,
    managementAddress,
    siteId: siteRef.value ?? null,
    status: 'unknown',
    createdAt: new Date().toISOString(),
  });

  // First assignment becomes primary automatically; an explicit isPrimary
  // demotes any earlier one (exactly-one invariant). If anything fails
  // validation, roll the device back so no orphan rows are left behind.
  try {
    for (const ref of plugins as DevicePluginRef[]) {
      await addAssignment({
        deviceId: id,
        pluginId: ref.pluginId!,
        secretId: ref.secretId ?? null,
        isPrimary: ref.isPrimary === true,
      });
    }
    for (const address of secondaryIps) {
      await addDeviceIp({ deviceId: id, address });
    }
  } catch (err) {
    await db.delete(schema.devicePlugins).where(eq(schema.devicePlugins.deviceId, id));
    await db.delete(schema.deviceIps).where(eq(schema.deviceIps.deviceId, id));
    await db.delete(schema.devices).where(eq(schema.devices.id, id));
    if (sendAssignmentError(res, err) || sendIpError(res, err)) return;
    throw err;
  }

  const created = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, id),
  });
  if (!created) {
    res.status(500).json({ error: 'Failed to retrieve created device' });
    return;
  }
  const pluginsView = await listAssignmentViews(id);
  let ipsView: { address: string; isPrimary: boolean }[] = [];
  try {
    ipsView = await listDeviceAddresses(id);
  } catch {
    /* device exists — treat as no secondaries */
  }
  const createdSiteNames = await siteNamesFor([created]);
  res.status(201).json({
    ...serializeDevice(created, createdSiteNames.get(created.siteId ?? '') ?? null),
    plugins: pluginsView,
    ips: ipsView,
  });
});

/** Identity fields that can be changed after creation (plugins are managed separately). */
const UPDATABLE_FIELDS = ['name', 'vendor', 'deviceType', 'managementAddress'] as const;

// PATCH /devices/:deviceId - rename a device, change its management address or site.
router.patch('/devices/:deviceId', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId } = req.params;
  const body = (req.body ?? {}) as Record<string, unknown>;

  const updates: Partial<typeof schema.devices.$inferInsert> = {};
  for (const field of UPDATABLE_FIELDS) {
    if (!(field in body)) continue;
    const value = body[field];
    if (value === null || value === undefined || typeof value !== 'string' || value.trim().length === 0) {
      res.status(400).json({ error: `"${field}" must be a non-empty string (omit it to keep the current value)` });
      return;
    }
    // The primary address is a bare IPv4/IPv6 literal or DNS name — plugins
    // own the transport scheme, so stored values never carry one.
    if (field === 'managementAddress' && !isValidAddress(value)) {
      res.status(400).json({ error: `"${field}": ${addressError(value)}` });
      return;
    }
    updates[field] = value.trim();
  }

  // siteId is handled separately: null clears the assignment, a string must
  // reference an existing site.
  if ('siteId' in body) {
    const ref = await validateSiteRef(body.siteId);
    if (ref.error) {
      res.status(400).json({ error: ref.error });
      return;
    }
    updates.siteId = ref.value ?? null;
  }

  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: `Provide at least one of: ${UPDATABLE_FIELDS.join(', ')}, siteId` });
    return;
  }

  const existing = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
  if (!existing) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  await db.update(schema.devices).set(updates).where(eq(schema.devices.id, deviceId));

  const updated = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
  if (!updated) {
    res.status(500).json({ error: 'Failed to retrieve updated device' });
    return;
  }
  const plugins = await listAssignmentViews(deviceId);
  let ips: { address: string; isPrimary: boolean }[] = [];
  try {
    ips = await listDeviceAddresses(deviceId);
  } catch {
    /* device exists — treat as no secondaries */
  }
  const updatedSiteNames = await siteNamesFor([updated]);
  res.status(200).json({
    ...serializeDevice(updated, updatedSiteNames.get(updated.siteId ?? '') ?? null),
    plugins,
    ips,
  });
});

// DELETE /devices/:deviceId - remove a device and everything that hangs off it.
// Refused (409) while any plan still references the device: plans are explicit
// multi-device intents and deleting one of their targets out from under them
// would leave dangling steps, so those must be deleted first.
router.delete('/devices/:deviceId', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId } = req.params;
  try {
    const existing = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    if (!existing) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    // Plans referencing this device block deletion (plan_steps.deviceId has no FK).
    const planRefs = await db.query.planSteps.findMany({ where: eq(schema.planSteps.deviceId, deviceId) });
    if (planRefs.length > 0) {
      res.status(409).json({ error: `Device is referenced by ${planRefs.length} plan step(s); delete those plans first` });
      return;
    }

    // No FK constraints in this schema — cascade manually, children first.
    await db.delete(schema.telemetry).where(eq(schema.telemetry.deviceId, deviceId));
    await db.delete(schema.configJobs).where(eq(schema.configJobs.deviceId, deviceId));
    await db.delete(schema.pluginSettings).where(eq(schema.pluginSettings.deviceId, deviceId));
    await db.delete(schema.networks).where(eq(schema.networks.deviceId, deviceId));
    await db.delete(schema.hosts).where(eq(schema.hosts.deviceId, deviceId));
    await db.delete(schema.deviceIps).where(eq(schema.deviceIps.deviceId, deviceId));
    await db.delete(schema.devicePlugins).where(eq(schema.devicePlugins.deviceId, deviceId));
    await db.delete(schema.devices).where(eq(schema.devices.id, deviceId));

    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// --- Device IP addresses (primary = managementAddress, secondaries here) --

// GET /devices/:deviceId/ips - primary address first, then secondary IPs.
router.get('/devices/:deviceId/ips', requireAuth, async (req, res) => {
  const { deviceId } = req.params;
  try {
    const ips = await listDeviceAddresses(deviceId);
    res.status(200).json({ deviceId, ips });
  } catch (err) {
    if (sendIpError(res, err)) return;
    throw err;
  }
});

// POST /devices/:deviceId/ips - add a secondary IP ({ "address": "10.0.0.5" }).
router.post('/devices/:deviceId/ips', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId } = req.params;
  const { address } = req.body ?? {};
  if (!isValidAddress(address)) {
    res.status(400).json({ error: `"address": ${addressError(address)}` });
    return;
  }
  try {
    const row = await addDeviceIp({ deviceId, address });
    res.status(201).json(row);
  } catch (err) {
    if (sendIpError(res, err)) return;
    throw err;
  }
});

// DELETE /devices/:deviceId/ips/:ipId - remove a secondary IP.
router.delete('/devices/:deviceId/ips/:ipId', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId, ipId } = req.params;
  try {
    await removeDeviceIp(deviceId, ipId);
    res.status(204).send();
  } catch (err) {
    if (sendIpError(res, err)) return;
    throw err;
  }
});

// --- Device ↔ plugin assignments -------------------------------------------

// GET /devices/:deviceId/plugins - all plugin assignments with identity + online state.
router.get('/devices/:deviceId/plugins', requireAuth, async (req, res) => {
  const { deviceId } = req.params;
  try {
    const plugins = await listAssignmentViews(deviceId);
    res.status(200).json({ deviceId, plugins });
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    throw err;
  }
});

// POST /devices/:deviceId/plugins - assign another plugin to this device.
router.post('/devices/:deviceId/plugins', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId } = req.params;
  const { pluginId, secretId, isPrimary } = req.body ?? {};
  if (!pluginId || typeof pluginId !== 'string') {
    res.status(400).json({ error: '"pluginId" is required' });
    return;
  }
  try {
    const assignment = await addAssignment({ deviceId, pluginId, secretId: secretId ?? null, isPrimary: isPrimary === true });
    res.status(201).json(assignment);
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    throw err;
  }
});

// PATCH /devices/:deviceId/plugins/:pluginId - update an assignment.
// Body is optional:
//   {}                          → promote to primary (legacy behavior)
//   { "isPrimary": true }       → promote to primary
//   { "secretId": "..." | null }→ change credential source (null clears it)
//   both                        → apply both in one call
router.patch('/devices/:deviceId/plugins/:pluginId', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId, pluginId } = req.params;
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    let assignment;
    if ('secretId' in body || 'isPrimary' in body) {
      assignment = await updateAssignment(deviceId, pluginId, {
        secretId: body.secretId === undefined ? undefined : (body.secretId as string | null),
        isPrimary: typeof body.isPrimary === 'boolean' ? body.isPrimary : undefined,
      });
    } else {
      // No fields provided → legacy "make primary" semantics.
      assignment = await setPrimary(deviceId, pluginId);
    }
    res.status(200).json(assignment);
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    throw err;
  }
});

// DELETE /devices/:deviceId/plugins/:pluginId - remove an assignment.
router.delete('/devices/:deviceId/plugins/:pluginId', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId, pluginId } = req.params;
  try {
    await removeAssignment(deviceId, pluginId);
    res.status(204).send();
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    throw err;
  }
});

// --- Per-device plugin settings (inherit global → override per device) ------

// GET /devices/:deviceId/plugins/:pluginId/options - descriptors + this device's overrides.
router.get('/devices/:deviceId/plugins/:pluginId/options', requireAuth, async (req, res) => {
  const { deviceId, pluginId } = req.params;
  try {
    const view = await getDevicePluginOptions(deviceId, pluginId);
    res.status(200).json(view);
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PUT /devices/:deviceId/plugins/:pluginId/settings - persist this device's overrides.
router.put('/devices/:deviceId/plugins/:pluginId/settings', requireAuth, requirePermission('plugins:manage'), async (req, res) => {
  const { deviceId, pluginId } = req.params;
  const settings = (req.body ?? {}).settings as Record<string, unknown> | undefined;
  if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
    res.status(400).json({ error: "Body must be { \"settings\": { [key]: value } }" });
    return;
  }
  try {
    await upsertDevicePluginSettings(deviceId, pluginId, settings);
    const view = await getDevicePluginOptions(deviceId, pluginId);
    res.status(200).json(view);
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    if (err instanceof SettingsValidationError) {
      res.status(400).json({ error: err.message, fieldErrors: err.fieldErrors });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /devices/:deviceId/plugins/:pluginId/settings - reset this device's overrides.
router.delete('/devices/:deviceId/plugins/:pluginId/settings', requireAuth, requirePermission('plugins:manage'), async (req, res) => {
  const { deviceId, pluginId } = req.params;
  try {
    await resetDevicePluginSettings(deviceId, pluginId);
    const view = await getDevicePluginOptions(deviceId, pluginId);
    res.status(200).json(view);
  } catch (err) {
    if (sendAssignmentError(res, err)) return;
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
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

  // One snapshot per assigned plugin — each plugin reports independently.
  const assignments = await db.query.devicePlugins.findMany({
    where: (rows, { eq }) => eq(rows.deviceId, deviceId),
    orderBy: [desc(schema.devicePlugins.createdAt)],
  });

  const snapshots = await Promise.all(
    assignments.map(async (a) => {
      const telemetry = await db.query.telemetry.findFirst({
        where: and(eq(schema.telemetry.deviceId, deviceId), eq(schema.telemetry.pluginId, a.pluginId)),
        orderBy: [desc(schema.telemetry.collectedAt)],
      });
      if (!telemetry) {
        return { pluginId: a.pluginId, collectedAt: null, health: 'unknown', metrics: {}, metricDescriptors: [] };
      }
      const descriptors = telemetry.metricDescriptors
        ? (typeof telemetry.metricDescriptors === 'string'
            ? JSON.parse(telemetry.metricDescriptors)
            : telemetry.metricDescriptors)
        : [];
      return {
        pluginId: a.pluginId,
        collectedAt: telemetry.collectedAt,
        health: telemetry.health,
        metrics: typeof telemetry.metrics === 'string' ? JSON.parse(telemetry.metrics) : telemetry.metrics,
        metricDescriptors: descriptors,
      };
    })
  );

  // Overall device health = worst-wins across assignments.
  const order: Record<string, number> = { ok: 0, degraded: 1, unknown: 2, critical: 3 };
  const health = snapshots.reduce(
    (worst, s) => ((order[s.health] ?? 2) > (order[worst] ?? 2) ? s.health : worst),
    'unknown'
  );

  res.status(200).json({ deviceId, health, snapshots });
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

  // Oldest → newest for plotting; each row carries its plugin so the webapp
  // can group history per assignment.
  const history = rows
    .slice()
    .reverse()
    .map((r) => ({
      collectedAt: r.collectedAt,
      health: r.health,
      metrics: typeof r.metrics === 'string' ? JSON.parse(r.metrics) : r.metrics,
      pluginId: r.pluginId ?? undefined,
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
    const { action, payload, pluginId } = req.body ?? {};

    if (!pluginId || typeof pluginId !== 'string') {
      res.status(400).json({ error: '"pluginId" is required — pick which assigned plugin applies the change' });
      return;
    }

    const device = await db.query.devices.findFirst({
      where: (devices, { eq }) => eq(devices.id, deviceId),
    });
    if (!device) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    const assignment = await db.query.devicePlugins.findFirst({
      where: and(eq(schema.devicePlugins.deviceId, deviceId), eq(schema.devicePlugins.pluginId, pluginId)),
    });
    if (!assignment) {
      res.status(400).json({ error: 'Plugin is not assigned to this device' });
      return;
    }

    const id = uuidv4();
    const createdAt = new Date().toISOString();

    await db.insert(schema.configJobs).values({
      id,
      deviceId,
      pluginId,
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
      pluginId: created.pluginId ?? undefined,
      action: created.action,
      status: created.status,
      result: created.result ? (typeof created.result === 'string' ? JSON.parse(created.result) : created.result) : undefined,
      createdAt: created.createdAt,
      finishedAt: created.finishedAt ?? undefined,
    });
  }
);

export default router;
