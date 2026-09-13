import { Router } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { db, Device, Plugin, Telemetry, ConfigJob } from '../db';
import { requireAuth, requirePermission, require2FA, requireDeviceAccess } from '../auth/middleware';
import { allowedDeviceIds, invalidateDeviceAccessCache } from '../deviceAccess';
import { mintConsoleTicket } from '../consoleTickets';
import { DeviceConsoleError, resolveConsoleTarget } from '../deviceConsole';
import { configJobQueue } from '../queue';
import { asc, eq, and, desc, inArray } from 'drizzle-orm';
import * as schema from '../db/schema';
import { DeviceStateError, fetchDeviceState } from '../deviceState';
import { DeviceProbeError, fetchDeviceProbe } from '../deviceProbe';
import { DeviceFilesystemError, performFilesystemOp, type FilesystemOp } from '../deviceFilesystem';
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
import { parseExtraCredentials } from '../types/credentialSlots';
import { isValidAddress, addressError } from '../utils/address';
import { forceRefreshDevices } from '../workers/telemetry';

const router = Router();

/** Parses a stored JSON string array defensively (bad data → []). */
function readStringArray(raw: unknown): string[] {
  let arr: unknown = raw;
  if (typeof raw === 'string') {
    try { arr = JSON.parse(raw); } catch { return []; }
  }
  if (!Array.isArray(arr)) return [];
  const out: string[] = [];
  for (const v of arr) {
    if (typeof v !== 'string') continue;
    const t = v.trim();
    if (t !== '' && !out.includes(t)) out.push(t);
  }
  return out;
}

/** Validates a request-body field as an array of non-empty strings; returns the deduped list or an error. */
function parseStringArrayField(raw: unknown, field: string): { value?: string[]; error?: string } {
  if (!Array.isArray(raw)) return { error: `"${field}" must be an array of strings` };
  for (const v of raw as unknown[]) {
    if (typeof v !== 'string' || v.trim() === '') return { error: `"${field}" entries must be non-empty strings` };
  }
  const out: string[] = [];
  for (const v of raw as string[]) {
    const t = v.trim();
    if (!out.includes(t)) out.push(t);
  }
  return { value: out };
}

function serializeDevice(row: Device, siteName?: string | null) {
  const deviceTypes = readStringArray(row.deviceTypes);
  return {
    id: row.id,
    name: row.name,
    vendor: row.vendor,
    // Legacy single type (first of the array) — kept for old clients.
    deviceType: row.deviceType ?? deviceTypes[0] ?? null,
    /** All roles this device fulfills, e.g. ["router", "firewall"]. */
    deviceTypes,
    /** User-assigned free-form tags (future filter/plan targeting). */
    tags: readStringArray(row.tags),
    managementAddress: row.managementAddress,
    siteId: row.siteId ?? undefined,
    siteName: siteName ?? null,
    status: row.status,
    model: row.model ?? null,
    firmwareVersion: row.firmwareVersion ?? null,
    // Manual topology-layer override (null = auto-classify).
    layerOverride: row.layerOverride ?? null,
    // Per-device metrics poll window in ms (null = inherit plugin/system setting).
    pollIntervalMs: row.pollIntervalMs ?? null,
    enabled: row.enabled !== false,
  };
}

/** Normalizes the per-device poll-window override. `undefined` = keep current
 * value; `null`/empty = clear (inherit); a number must be 5000–3600000 ms.
 */
function normalizePollIntervalMs(raw: unknown): { value?: number | null; error?: string } {
  if (raw === undefined) return {};
  if (raw === null || raw === '') return { value: null };
  const v = Number(raw);
  if (!Number.isFinite(v)) return { error: '"pollIntervalMs" must be a number of milliseconds or null' };
  const ms = Math.round(v);
  if (ms < 5_000 || ms > 3_600_000) {
    return { error: '"pollIntervalMs" must be between 5000 and 3600000 ms' };
  }
  return { value: ms };
}

/**
 * Normalizes an optional device-model field from a request body.
 * `undefined` = not provided (keep current value); `null`/empty string = clear;
 * anything else must be a non-empty string. Returns { error } or { value }.
 */
function normalizeOptionalModelField(field: 'model' | 'firmwareVersion', raw: unknown): { value?: string | null; error?: string } {
  if (raw === undefined) return {}; // omit → keep current value
  if (raw === null || raw === '') return { value: null };
  if (typeof raw !== 'string' || raw.trim().length === 0) {
    return { error: `"${field}" must be a string or null` };
  }
  const v = raw.trim();
  if (v.length > 200) return { error: `"${field}" is too long (max 200 chars)` };
  return { value: v };
}

/** Batch-loads the names of the sites referenced by a set of devices. */
async function siteNamesFor(devices: Device[]): Promise<Map<string, string>> {
  const ids = [...new Set(devices.map((d) => d.siteId).filter((v): v is string => !!v))];
  if (ids.length === 0) return new Map();
  const rows = await db.query.sites.findMany({ where: inArray(schema.sites.id, ids) });
  return new Map(rows.map((s) => [s.id, s.name]));
}

/** Validates a layerOverride reference: null/omitted = auto-classify, a
 * string must name an existing network_layers row. Returns the id or an error. */
async function validateLayerRef(layerId: unknown): Promise<{ value?: string | null; error?: string }> {
  if (layerId === undefined || layerId === null) return { value: null };
  if (typeof layerId !== 'string' || layerId.trim() === '') {
    return { error: '"layerOverride" must be a non-empty string or null' };
  }
  const found = await db.query.networkLayers.findFirst({ where: eq(schema.networkLayers.id, layerId.trim()) });
  if (!found) return { error: `Unknown layer: ${layerId}` };
  return { value: layerId.trim() };
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

// Firmware version + serial number for the overview table's at-a-glance columns.
// Plugins report these under different metric keys:
//   lancom-lx/lcos/sx → system.swVersion, mikrotik-swos → system.detectedFirmwareVersion,
//   opnsense → version. Serial is system.serialNumber (lancom-*, swos).
const FIRMWARE_METRIC_KEYS = ['system.swVersion', 'system.detectedFirmwareVersion', 'system.version', 'version'];
const SERIAL_METRIC_KEYS = ['system.serialNumber'];

function parseTelemetryMetrics(row: { metrics: unknown } | undefined): Record<string, unknown> {
  if (!row) return {};
  try {
    const m = typeof row.metrics === 'string' ? JSON.parse(row.metrics) : (row.metrics ?? {});
    return m && typeof m === 'object' ? (m as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

/** First non-empty value across the rows; callers order them (primary plugin first). */
function firstMetricValue(rows: ({ metrics: unknown } | undefined)[], keys: string[]): string | null {
  for (const row of rows) {
    const metrics = parseTelemetryMetrics(row);
    for (const k of keys) {
      const v = metrics[k];
      if (typeof v === 'string' && v.trim() !== '') return v;
    }
  }
  return null;
}

// All device read routes require devices:read.
router.get('/devices', requireAuth, requirePermission('devices:read'), async (req, res) => {
  const { vendor, siteId } = req.query;

  // Device-level access control: scoped callers only ever see their devices.
  // `null` = unrestricted (devices:all or no scope rules); an empty set means
  // the caller sees nothing — answer early instead of querying with inArray([])
  // (drizzle rejects empty arrays).
  const allowed = await allowedDeviceIds(req);
  if (allowed !== null && allowed.size === 0) {
    res.status(200).json([]);
    return;
  }

  const filters = [];
  if (typeof vendor === 'string' && vendor.length > 0) {
    filters.push(eq(schema.devices.vendor, vendor));
  }
  if (typeof siteId === 'string' && siteId.length > 0) {
    filters.push(eq(schema.devices.siteId, siteId));
  }
  if (allowed !== null) {
    filters.push(inArray(schema.devices.id, [...allowed]));
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
      // Firmware/serial come from the latest telemetry, primary plugin first.
      const primaryPluginId = plugins.find((p) => p.isPrimary)?.pluginId ?? plugins[0]?.pluginId;
      const orderedTelemetry = [...perPluginTelemetry].sort(
        (a, b) => Number(b?.pluginId === primaryPluginId) - Number(a?.pluginId === primaryPluginId)
      );
      return {
        ...serializeDevice(device, siteNames.get(device.siteId ?? '') ?? null),
        plugins,
        summaryMetrics,
        ips,
        detectedFirmwareVersion: firstMetricValue(orderedTelemetry, FIRMWARE_METRIC_KEYS),
        serialNumber: firstMetricValue(orderedTelemetry, SERIAL_METRIC_KEYS),
      };
    })
  );

  res.status(200).json(withPlugins);
});

interface DevicePluginRef {
  pluginId?: string;
  secretId?: string | null;
  isPrimary?: boolean;
  /** Extra credential slots to bind (slot name → secrets.id). */
  extraCredentials?: Record<string, string | null>;
}

router.post('/devices', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { name, vendor, managementAddress, siteId, plugins, ips } = req.body ?? {};

  if (!Array.isArray(plugins) || plugins.length === 0) {
    res.status(400).json({ error: 'At least one plugin assignment is required ("plugins": [{ "pluginId", ... }])' });
    return;
  }

  // Device roles: `deviceTypes` array (preferred, e.g. ["router","firewall"])
  // or the legacy single `deviceType` string.
  let deviceTypes: string[] | null = null;
  if ('deviceTypes' in (req.body ?? {})) {
    const ref = parseStringArrayField(req.body.deviceTypes, 'deviceTypes');
    if (ref.error) { res.status(400).json({ error: ref.error }); return; }
    deviceTypes = ref.value!;
  } else if (typeof req.body?.deviceType === 'string' && req.body.deviceType.trim() !== '') {
    deviceTypes = [req.body.deviceType.trim()];
  }
  if (!deviceTypes || deviceTypes.length === 0) {
    res.status(400).json({ error: '"deviceTypes" must be a non-empty array of strings (e.g. ["router", "firewall"])' });
    return;
  }

  // Free-form tags (optional; used later for filtering / plan targeting).
  let tags: string[] = [];
  if ('tags' in (req.body ?? {}) && req.body.tags !== undefined) {
    const ref = parseStringArrayField(req.body.tags, 'tags');
    if (ref.error) { res.status(400).json({ error: ref.error }); return; }
    tags = ref.value!;
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

  // Optional hardware model / firmware version — chosen from a plugin's
  // advertised catalog in the webapp form. Free-form here on purpose: the API
  // does not validate against catalogs (a device can outlive its plugin).
  const body = req.body ?? {};
  const modelRef = normalizeOptionalModelField('model', body.model);
  if (modelRef.error) {
    res.status(400).json({ error: modelRef.error });
    return;
  }
  const firmwareRef = normalizeOptionalModelField('firmwareVersion', body.firmwareVersion);
  if (firmwareRef.error) {
    res.status(400).json({ error: firmwareRef.error });
    return;
  }

  // Optional manual topology-layer override (null/omitted = auto-classify).
  const layerRef = await validateLayerRef(body.layerOverride);
  if (layerRef.error) {
    res.status(400).json({ error: layerRef.error });
    return;
  }

  // Optional per-device metrics poll window override (null/omitted = inherit).
  const pollIntervalRef = normalizePollIntervalMs(body.pollIntervalMs);
  if (pollIntervalRef.error) {
    res.status(400).json({ error: pollIntervalRef.error });
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
    deviceType: deviceTypes[0], // legacy mirror of the first role
    deviceTypes: JSON.stringify(deviceTypes),
    tags: JSON.stringify(tags),
    managementAddress,
    siteId: siteRef.value ?? null,
    status: 'unknown',
    model: modelRef.value ?? null,
    firmwareVersion: firmwareRef.value ?? null,
    layerOverride: layerRef.value ?? null,
    pollIntervalMs: pollIntervalRef.value ?? null,
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
        extraCredentials: ref.extraCredentials,
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
  // A new device may match a scoped caller's tag/site rules — refresh caches.
  invalidateDeviceAccessCache();
  res.status(201).json({
    ...serializeDevice(created, createdSiteNames.get(created.siteId ?? '') ?? null),
    plugins: pluginsView,
    ips: ipsView,
  });
});

/** Identity fields that can be changed after creation (plugins are managed separately).
 * `deviceTypes`/`tags` are arrays and handled separately below. */
const UPDATABLE_FIELDS = ['name', 'vendor', 'managementAddress'] as const;

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

  // Device roles: `deviceTypes` array (preferred) or the legacy single
  // `deviceType`. At least one role is always required.
  if ('deviceTypes' in body || 'deviceType' in body) {
    let types: string[] | null = null;
    if ('deviceTypes' in body) {
      const ref = parseStringArrayField(body.deviceTypes, 'deviceTypes');
      if (ref.error) { res.status(400).json({ error: ref.error }); return; }
      types = ref.value!;
    } else if (typeof body.deviceType === 'string' && body.deviceType.trim() !== '') {
      types = [body.deviceType.trim()];
    }
    if (!types || types.length === 0) {
      res.status(400).json({ error: '"deviceTypes" must contain at least one type (e.g. ["router", "firewall"])' });
      return;
    }
    updates.deviceTypes = JSON.stringify(types);
    updates.deviceType = types[0]; // legacy mirror
  }

  // Free-form tags — an array of strings; [] clears all.
  if ('tags' in body) {
    const ref = parseStringArrayField(body.tags, 'tags');
    if (ref.error) { res.status(400).json({ error: ref.error }); return; }
    updates.tags = JSON.stringify(ref.value!);
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

  // model / firmwareVersion are handled separately too: unlike the identity
  // fields above, they may be CLEARED with null (the device no longer matches
  // a plugin catalog) — omitting them keeps the current value.
  for (const field of ['model', 'firmwareVersion'] as const) {
    if (!(field in body)) continue;
    const ref = normalizeOptionalModelField(field, body[field]);
    if (ref.error) {
      res.status(400).json({ error: ref.error });
      return;
    }
    updates[field] = ref.value ?? null;
  }

  // Manual topology-layer override — null clears it back to auto-classify.
  if ('layerOverride' in body) {
    const ref = await validateLayerRef(body.layerOverride);
    if (ref.error) {
      res.status(400).json({ error: ref.error });
      return;
    }
    updates.layerOverride = ref.value ?? null;
  }

  // Per-device metrics poll window — null clears it back to the inherited value.
  if ('pollIntervalMs' in body) {
    const ref = normalizePollIntervalMs(body.pollIntervalMs);
    if (ref.error) {
      res.status(400).json({ error: ref.error });
      return;
    }
    updates.pollIntervalMs = ref.value ?? null;
  }

  // enabled toggles telemetry polling for the device. Disabled devices keep
  // their historical data + last metrics; re-enabling resumes polling.
  if ('enabled' in body) {
    if (typeof body.enabled !== 'boolean') {
      res.status(400).json({ error: '"enabled" must be a boolean' });
      return;
    }
    updates.enabled = body.enabled;
  }

  if (Object.keys(updates).length === 0) {
    res.status(400).json({ error: `Provide at least one of: ${UPDATABLE_FIELDS.join(', ')}, deviceTypes, tags, siteId, model, firmwareVersion, layerOverride, pollIntervalMs, enabled` });
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

  // tags/siteId changes shift which scoped callers may see this device.
  invalidateDeviceAccessCache();

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

// POST /devices/:deviceId/clone - create a copy of the device with all its
// settings (plugin assignments incl. credentials + extra slots, secondary IPs,
// per-device plugin setting overrides). The clone gets a fresh id, status
// 'unknown' and the name "<source> (copy)" — the webapp opens the edit form
// right away so the user can change the IP/name before saving.
router.post('/devices/:deviceId/clone', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const { deviceId } = req.params;
  try {
    const source = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    if (!source) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }

    // Unique clone name ("X (copy)", "X (copy 2)", ...).
    const existingNames = new Set(
      (await db.query.devices.findMany()).map((d) => d.name.toLowerCase())
    );
    let cloneName = `${source.name} (copy)`;
    for (let i = 2; existingNames.has(cloneName.toLowerCase()); i++) {
      cloneName = `${source.name} (copy ${i})`;
    }

    const id = uuidv4();
    await db.insert(schema.devices).values({
      id,
      name: cloneName,
      vendor: source.vendor,
      deviceType: source.deviceType ?? readStringArray(source.deviceTypes)[0] ?? null,
      deviceTypes: source.deviceTypes,
      tags: source.tags,
      managementAddress: source.managementAddress,
      siteId: source.siteId ?? null,
      status: 'unknown',
      model: source.model ?? null,
      firmwareVersion: source.firmwareVersion ?? null,
      pollIntervalMs: source.pollIntervalMs ?? null,
      enabled: source.enabled !== false,
      createdAt: new Date().toISOString(),
    });

    // Copy plugin assignments (same plugins, same credential sources — the user
    // typically changes only the address) + secondary IPs + per-device setting
    // overrides. Roll everything back on failure so no orphan rows remain.
    try {
      const sourceAssignments = await db.query.devicePlugins.findMany({
        where: eq(schema.devicePlugins.deviceId, deviceId),
      });
      for (const a of sourceAssignments) {
        await addAssignment({
          deviceId: id,
          pluginId: a.pluginId,
          secretId: a.secretId ?? null,
          isPrimary: a.isPrimary === true,
          extraCredentials: parseExtraCredentials(a.extraCredentials),
        });
      }
      const sourceIps = await db.query.deviceIps.findMany({
        where: eq(schema.deviceIps.deviceId, deviceId),
      });
      for (const ip of sourceIps) {
        await addDeviceIp({ deviceId: id, address: ip.address });
      }
      const sourceSettings = await db.query.pluginSettings.findMany({
        where: eq(schema.pluginSettings.deviceId, deviceId),
      });
      for (const s of sourceSettings) {
        await db.insert(schema.pluginSettings).values({
          id: uuidv4(),
          pluginId: s.pluginId,
          deviceId: id,
          optionKey: s.optionKey,
          value: s.value,
          updatedAt: new Date().toISOString(),
        });
      }
    } catch (err) {
      await db.delete(schema.devicePlugins).where(eq(schema.devicePlugins.deviceId, id));
      await db.delete(schema.deviceIps).where(eq(schema.deviceIps.deviceId, id));
      await db.delete(schema.pluginSettings).where(eq(schema.pluginSettings.deviceId, id));
      await db.delete(schema.devices).where(eq(schema.devices.id, id));
      if (sendAssignmentError(res, err) || sendIpError(res, err)) return;
      throw err;
    }

    const created = await db.query.devices.findFirst({ where: eq(schema.devices.id, id) });
    if (!created) {
      res.status(500).json({ error: 'Failed to retrieve cloned device' });
      return;
    }
    const pluginsView = await listAssignmentViews(id);
    let ipsView: { address: string; isPrimary: boolean }[] = [];
    try {
      ipsView = await listDeviceAddresses(id);
    } catch {
      /* device exists — treat as no secondaries */
    }
    const siteNames = await siteNamesFor([created]);
    // The clone inherits the source's tags/site — refresh access caches.
    invalidateDeviceAccessCache();
    res.status(201).json({
      ...serializeDevice(created, siteNames.get(created.siteId ?? '') ?? null),
      plugins: pluginsView,
      ips: ipsView,
    });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
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
    await db.delete(schema.deviceTimes).where(eq(schema.deviceTimes.deviceId, deviceId));
    await db.delete(schema.devicePorts).where(eq(schema.devicePorts.deviceId, deviceId));
    // Cross-device inventory rows (Containers/Storage pages) — without these a
    // deleted device leaves orphaned rows behind (they only carry deviceId +
    // pluginId, no FK to devices).
    await db.delete(schema.containers).where(eq(schema.containers.deviceId, deviceId));
    await db.delete(schema.dockerImages).where(eq(schema.dockerImages.deviceId, deviceId));
    await db.delete(schema.vms).where(eq(schema.vms.deviceId, deviceId));
    await db.delete(schema.certificates).where(eq(schema.certificates.deviceId, deviceId));
    await db.delete(schema.certificateHistory).where(eq(schema.certificateHistory.deviceId, deviceId));
    await db.delete(schema.storageFilesystems).where(eq(schema.storageFilesystems.deviceId, deviceId));
    await db.delete(schema.storageDisks).where(eq(schema.storageDisks.deviceId, deviceId));
    await db.delete(schema.deviceIps).where(eq(schema.deviceIps.deviceId, deviceId));
    await db.delete(schema.devicePlugins).where(eq(schema.devicePlugins.deviceId, deviceId));
    await db.delete(schema.devices).where(eq(schema.devices.id, deviceId));

    // The device set changed — drop the in-memory snapshot + per-user allowed-id
    // caches so tag/site-scoped callers see the change immediately.
    invalidateDeviceAccessCache();
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// --- Device IP addresses (primary = managementAddress, secondaries here) --

// GET /devices/:deviceId/ips - primary address first, then secondary IPs.
router.get('/devices/:deviceId/ips', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
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
router.post('/devices/:deviceId/ips', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
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
router.delete('/devices/:deviceId/ips/:ipId', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
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
router.get('/devices/:deviceId/plugins', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
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
router.post('/devices/:deviceId/plugins', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;
  const { pluginId, secretId, isPrimary, extraCredentials } = req.body ?? {};
  if (!pluginId || typeof pluginId !== 'string') {
    res.status(400).json({ error: '"pluginId" is required' });
    return;
  }
  try {
    const assignment = await addAssignment({
      deviceId,
      pluginId,
      secretId: secretId ?? null,
      isPrimary: isPrimary === true,
      extraCredentials,
    });
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
//   { "extraCredentials": {...} }→ replace bound slot secrets (validated per slot type)
//   any combination             → applied in one call
router.patch('/devices/:deviceId/plugins/:pluginId', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
  const { deviceId, pluginId } = req.params;
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    let assignment;
    if ('secretId' in body || 'isPrimary' in body || 'extraCredentials' in body) {
      assignment = await updateAssignment(deviceId, pluginId, {
        secretId: body.secretId === undefined ? undefined : (body.secretId as string | null),
        isPrimary: typeof body.isPrimary === 'boolean' ? body.isPrimary : undefined,
        extraCredentials:
          body.extraCredentials === undefined
            ? undefined
            : (body.extraCredentials as Record<string, string | null>),
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
router.delete('/devices/:deviceId/plugins/:pluginId', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
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
router.get('/devices/:deviceId/plugins/:pluginId/options', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
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
router.put('/devices/:deviceId/plugins/:pluginId/settings', requireAuth, requirePermission('plugins:manage'), requireDeviceAccess, async (req, res) => {
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
router.delete('/devices/:deviceId/plugins/:pluginId/settings', requireAuth, requirePermission('plugins:manage'), requireDeviceAccess, async (req, res) => {
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

router.get('/devices/:deviceId/monitoring', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
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

// GET /devices/:deviceId/state - LIVE device state from one assigned plugin's
// `GET /state` endpoint (capability 'deviceState'). The webapp's per-device
// Config page renders this verbatim: sections of items (ports with live states,
// interfaces, ZFS pools) + context-aware action references. The broker is
// generic — it only resolves credentials and validates advertised action ids
// against the plugin's persisted catalog (see deviceState.ts).
router.get('/devices/:deviceId/state', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;
  const pluginId = typeof req.query.pluginId === 'string' ? req.query.pluginId : '';

  try {
    // No explicit plugin → the device's primary assignment.
    let effectivePluginId = pluginId;
    if (!effectivePluginId) {
      const assignments = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.deviceId, deviceId) });
      const primary = assignments.find((a) => a.isPrimary) ?? assignments[0];
      if (!primary) {
        res.status(400).json({ error: 'Device has no plugin assignment' });
        return;
      }
      effectivePluginId = primary.pluginId;
    }

    const result = await fetchDeviceState(deviceId, effectivePluginId);
    res.status(200).json({ deviceId, ...result });
  } catch (err) {
    if (err instanceof DeviceStateError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /devices/:deviceId/probe - LIVE short-cycle telemetry from one assigned
// plugin's POST /probe endpoint (capability 'probe'). The webapp polls this on
// demand (1–5 s) for data too slow/heavy for the background /monitoring worker
// — e.g. per-container CPU/RAM/I-O. Query params: keys (comma-separated probe
// keys to collect; absent = plugin default), names (comma-separated container
// selection for state-style keys; absent = full collection), pluginId
// (default = primary). The broker is generic (see deviceProbe.ts) — it resolves
// credentials and forwards verbatim, never interpreting metric content or
// writing to the DB.
router.get('/devices/:deviceId/probe', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;
  const pluginId = typeof req.query.pluginId === 'string' ? req.query.pluginId : '';
  const keysRaw = typeof req.query.keys === 'string' ? req.query.keys : Array.isArray(req.query.keys) ? (req.query.keys as string[]).join(',') : '';
  const keys = keysRaw.split(',').map((k) => k.trim()).filter(Boolean);
  const namesRaw = typeof req.query.names === 'string' ? req.query.names : Array.isArray(req.query.names) ? (req.query.names as string[]).join(',') : '';
  const names = namesRaw.split(',').map((n) => n.trim()).filter(Boolean);

  try {
    // No explicit plugin → the device's primary assignment.
    let effectivePluginId = pluginId;
    if (!effectivePluginId) {
      const assignments = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.deviceId, deviceId) });
      const primary = assignments.find((a) => a.isPrimary) ?? assignments[0];
      if (!primary) {
        res.status(400).json({ error: 'Device has no plugin assignment' });
        return;
      }
      effectivePluginId = primary.pluginId;
    }

    const result = await fetchDeviceProbe(deviceId, effectivePluginId, keys, names.length > 0 ? names : undefined);
    res.status(200).json({ deviceId, ...result });
  } catch (err) {
    if (err instanceof DeviceProbeError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /devices/:deviceId/filesystem - one file operation on a device's filesystem,
// brokered to the assigned plugin's POST /filesystem endpoint (capability
// 'filesystem'). The webapp's Storage page browses dataset contents and the
// Containers page browses container volume mounts through this ONE route. Body:
//   { op, path?, targetPath?, contentBase64?, parents?, context? }
// `context` names WHAT to browse (a dataset or a container volume); the plugin maps
// it onto an SFTP root and confines every path to it. Gated on devices:write — file
// ops mutate device state (and reads are only useful alongside them). The broker is
// generic (see deviceFilesystem.ts) — it resolves credentials + forwards verbatim.
router.post('/devices/:deviceId/filesystem', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;
  const body = (req.body ?? {}) as Record<string, unknown>;

  // No explicit plugin → the device's primary assignment.
  let pluginId = typeof body.pluginId === 'string' ? body.pluginId : '';
  if (!pluginId) {
    const assignments = await db.query.devicePlugins.findMany({ where: eq(schema.devicePlugins.deviceId, deviceId) });
    const primary = assignments.find((a) => a.isPrimary) ?? assignments[0];
    if (!primary) {
      res.status(400).json({ error: 'Device has no plugin assignment' });
      return;
    }
    pluginId = primary.pluginId;
  }

  const op = typeof body.op === 'string' ? (body.op as FilesystemOp) : '';
  if (!op) {
    res.status(400).json({ error: 'Missing "op" in request body' });
    return;
  }

  try {
    const result = await performFilesystemOp(deviceId, pluginId, op, {
      path: typeof body.path === 'string' ? body.path : undefined,
      targetPath: typeof body.targetPath === 'string' ? body.targetPath : undefined,
      contentBase64: typeof body.contentBase64 === 'string' ? body.contentBase64 : undefined,
      parents: typeof body.parents === 'boolean' ? body.parents : undefined,
      context: body.context && typeof body.context === 'object' ? (body.context as Record<string, unknown>) : undefined,
    });
    res.status(200).json({ deviceId, ...result });
  } catch (err) {
    if (err instanceof DeviceFilesystemError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /devices/:deviceId/console - mint a short-lived, single-use CONSOLE TICKET
// for an interactive SSH terminal (capability 'sshConsole'). This is the ONLY
// authenticated step of the console flow — browsers cannot set headers on a
// WebSocket upgrade, so the ticket itself becomes the bearer credential for the
// WS path below. Authorization happens HERE: JWT + devices:write + the plugin's
// 'sshConsole' capability (resolveConsoleTarget throws 501 when absent). The webapp
// then opens GET /devices/:id/console/ws?ticket=… and gets a full xterm.js session.
router.post('/devices/:deviceId/console', requireAuth, requirePermission('devices:write'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;
  const body = (req.body ?? {}) as Record<string, unknown>;

  try {
    // Resolves the assignment + checks the capability BEFORE minting — a ticket is
    // only ever issued for a target that can actually serve a console.
    const pluginId = typeof body.pluginId === 'string' ? body.pluginId : undefined;
    await resolveConsoleTarget(deviceId, pluginId);

    const context = body.context && typeof body.context === 'object' ? (body.context as Record<string, unknown>) : undefined;
    const ticket = mintConsoleTicket(deviceId, pluginId, context);
    res.status(201).json({ deviceId, ticket });
  } catch (err) {
    if (err instanceof DeviceConsoleError) {
      res.status(err.status).json({ error: err.message });
      return;
    }
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// NOTE: the console WebSocket PROXY (GET /devices/:id/console/ws?ticket=…) is NOT an
// express route — WS upgrades bypass express entirely. It lives in consoleProxy.ts
// and is attached to the HTTP server's 'upgrade' event in index.ts. The single-use
// ticket minted above IS its credential: browsers cannot set headers on a WS upgrade,
// so the ticket proves "this user already passed JWT + devices:write + capability
// checks for exactly this device/assignment".

// GET /devices/:deviceId/ports - Normalized port inventory (device_ports table)
// for this device across all plugins. Fed by the telemetry worker from each
// plugin's `metrics['ports']` array — upserted per poll, deleted-on-absent.
router.get('/devices/:deviceId/ports', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
  const { deviceId } = req.params;

  const device = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
  if (!device) {
    res.status(404).json({ error: 'Device not found' });
    return;
  }

  const rows = await db.query.devicePorts.findMany({
    where: eq(schema.devicePorts.deviceId, deviceId),
    orderBy: [asc(schema.devicePorts.pluginId), asc(schema.devicePorts.name)],
  });

  res.status(200).json({
    deviceId,
    ports: rows.map((r) => ({
      pluginId: r.pluginId,
      name: r.name,
      status: r.status,
      speed: r.speed ?? undefined,
      duplex: r.duplex ?? undefined,
      vlanId: r.vlanId ?? undefined,
      poe: r.poe ?? undefined,
      extra: r.extra ? (typeof r.extra === 'string' ? JSON.parse(r.extra) : r.extra) : {},
      collectedAt: r.collectedAt,
    })),
  });
});

// GET /devices/:deviceId/telemetry - Recent telemetry history (for plot metrics).
router.get('/devices/:deviceId/telemetry', requireAuth, requirePermission('devices:read'), requireDeviceAccess, async (req, res) => {
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
  requireDeviceAccess,
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

// POST /devices/refresh - Force an immediate re-poll of one or more devices.
// Bypasses the staggered scheduling windows (metrics AND inventory), so both
// live metrics and the cross-device inventory tables refresh right away — the
// diagnostic path for "is this device reachable NOW?". Requires devices:write
// because it triggers real plugin calls with the device's credentials.
router.post('/devices/refresh', requireAuth, requirePermission('devices:write'), async (req, res) => {
  const body = req.body ?? {};
  // Accept { deviceIds: [...] } or a bare array of ids.
  let rawIds: unknown = Array.isArray(body) ? body : body.deviceIds;
  if (!Array.isArray(rawIds)) {
    res.status(400).json({ error: '"deviceIds" must be an array of device id strings' });
    return;
  }
  let ids = rawIds.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => v.trim());
  if (ids.length === 0) {
    res.status(400).json({ error: '"deviceIds" must contain at least one device id' });
    return;
  }

  // Device-level access control: scoped callers may only refresh their own
  // devices — out-of-scope ids are dropped silently (they would be "unknown"
  // to them anyway, and listing them would leak existence).
  const allowed = await allowedDeviceIds(req);
  if (allowed !== null) {
    ids = ids.filter((id) => allowed.has(id));
    if (ids.length === 0) {
      res.status(200).json({ results: [] });
      return;
    }
  }

  try {
    const results = await forceRefreshDevices(ids);
    res.status(200).json({ results });
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
