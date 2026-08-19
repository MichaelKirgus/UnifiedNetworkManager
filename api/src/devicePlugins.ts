import { and, asc, eq, inArray } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Device ↔ plugin assignment broker.
 *
 * `device_plugins` is the single source of truth for which plugins serve a
 * device (many-to-many). Each row carries its own credential source so every
 * plugin on a device can use a different secret. Exactly one assignment per
 * device is marked primary — the default target for config jobs and the UI's
 * "main" plugin.
 */

export interface DevicePluginAssignment {
  id: string;
  deviceId: string;
  pluginId: string;
  /** Credential source for this assignment (null = no credentials). */
  secretId: string | null;
  isPrimary: boolean;
  createdAt: string;
}

/** Assignment enriched with the plugin's identity + online state. */
export interface DevicePluginAssignmentView extends DevicePluginAssignment {
  pluginName?: string;
  pluginVersion?: string;
  pluginEndpoint?: string;
  /** True when the plugin was seen within the last 5 minutes. */
  pluginOnline?: boolean;
  secretLabel?: string | null;
}

/** Error carrying an HTTP status so routes can map it directly. */
export class AssignmentError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

const ONLINE_WINDOW_MS = 5 * 60_000;

async function assertDevice(deviceId: string): Promise<void> {
  const device = await db.query.devices.findFirst({
    where: (devices, { eq }) => eq(devices.id, deviceId),
  });
  if (!device) throw new AssignmentError(404, 'Device not found');
}

async function assertPlugin(pluginId: string): Promise<void> {
  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!plugin) throw new AssignmentError(404, 'Referenced plugin not found');
}

async function findAssignment(deviceId: string, pluginId: string) {
  return db.query.devicePlugins.findFirst({
    where: and(
      eq(schema.devicePlugins.deviceId, deviceId),
      eq(schema.devicePlugins.pluginId, pluginId)
    ),
  });
}

/** All assignments for a device (oldest first). */
export async function listAssignments(deviceId: string): Promise<DevicePluginAssignment[]> {
  await assertDevice(deviceId);
  return db.query.devicePlugins.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
    orderBy: [asc(schema.devicePlugins.createdAt)],
  });
}

/** Assignments enriched with plugin identity + online state for the UI. */
export async function listAssignmentViews(deviceId: string): Promise<DevicePluginAssignmentView[]> {
  const assignments = await listAssignments(deviceId);
  if (assignments.length === 0) return [];

  const pluginIds = Array.from(new Set(assignments.map((a) => a.pluginId)));
  const secretIds = Array.from(
    new Set(assignments.map((a) => a.secretId).filter((s): s is string => s !== null))
  );

  const [plugins, secrets] = await Promise.all([
    db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }),
    secretIds.length > 0
      ? db.query.secrets.findMany({ where: inArray(schema.secrets.id, secretIds) })
      : [],
  ]);

  const now = Date.now();
  return assignments.map((a) => {
    const plugin = plugins.find((p) => p.id === a.pluginId);
    const secret = secrets.find((s) => s.id === a.secretId);
    return {
      ...a,
      pluginName: plugin?.name,
      pluginVersion: plugin?.version,
      pluginEndpoint: plugin?.endpoint,
      pluginOnline:
        plugin?.lastSeenAt !== null &&
        plugin?.lastSeenAt !== undefined &&
        now - Date.parse(plugin.lastSeenAt) < ONLINE_WINDOW_MS,
      secretLabel: secret ? (secret.label ?? null) : null,
    };
  });
}

/**
 * Adds a plugin assignment to a device.
 * - Duplicate (device, plugin) → 409.
 * - First assignment on the device becomes primary automatically.
 * - `isPrimary: true` demotes any existing primary exactly-one invariant.
 */
export async function addAssignment(input: {
  deviceId: string;
  pluginId: string;
  secretId?: string | null;
  isPrimary?: boolean;
}): Promise<DevicePluginAssignment> {
  const { deviceId, pluginId } = input;
  await assertDevice(deviceId);
  await assertPlugin(pluginId);

  const secretId = input.secretId ?? null;
  if (secretId) {
    const secret = await db.query.secrets.findFirst({
      where: (secrets, { eq }) => eq(secrets.id, secretId),
    });
    if (!secret) throw new AssignmentError(404, 'Referenced credentials not found');
  }

  const existing = await findAssignment(deviceId, pluginId);
  if (existing) throw new AssignmentError(409, 'Plugin is already assigned to this device');

  const siblings = await db.query.devicePlugins.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
  });

  // Exactly-one-primary invariant: adding a primary demotes the old one.
  if (input.isPrimary === true) {
    for (const s of siblings) {
      if (s.isPrimary) {
        await db.update(schema.devicePlugins)
          .set({ isPrimary: false })
          .where(eq(schema.devicePlugins.id, s.id));
      }
    }
  }

  const now = new Date().toISOString();
  await db.insert(schema.devicePlugins).values({
    id: uuidv4(),
    deviceId,
    pluginId,
    secretId,
    isPrimary: input.isPrimary === true || siblings.length === 0,
    createdAt: now,
  });

  return (await findAssignment(deviceId, pluginId))!;
}

/**
 * Removes a plugin assignment from a device. If it was the primary and other
 * assignments remain, the oldest remaining one is promoted to keep exactly one
 * primary per device.
 */
export async function removeAssignment(deviceId: string, pluginId: string): Promise<void> {
  await assertDevice(deviceId);
  const assignment = await findAssignment(deviceId, pluginId);
  if (!assignment) throw new AssignmentError(404, 'Plugin is not assigned to this device');

  await db.delete(schema.devicePlugins).where(eq(schema.devicePlugins.id, assignment.id));

  if (assignment.isPrimary) {
    const remaining = await db.query.devicePlugins.findMany({
      where: (rows) => eq(rows.deviceId, deviceId),
      orderBy: [asc(schema.devicePlugins.createdAt)],
    });
    if (remaining.length > 0 && !remaining.some((r) => r.isPrimary)) {
      await db.update(schema.devicePlugins)
        .set({ isPrimary: true })
        .where(eq(schema.devicePlugins.id, remaining[0].id));
    }
  }
}

/** True when (device, plugin) has an assignment — used to validate config jobs. */
export async function hasAssignment(deviceId: string, pluginId: string): Promise<boolean> {
  const row = await findAssignment(deviceId, pluginId);
  return row !== undefined;
}
