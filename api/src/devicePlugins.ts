import { and, asc, desc, eq, inArray } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from './db';
import * as schema from './db/schema';
import {
  CredentialSlotDescriptor,
  ExtraCredentials,
  parseExtraCredentials,
  slotAcceptsType,
} from './types/credentialSlots';
import type { CapabilityEvaluation, DeviceSupport } from './types/deviceSupport';
import { evaluateDeviceSupport } from '@unm/plugin-sdk';

/**
 * Device ↔ plugin assignment broker.
 *
 * `device_plugins` is the single source of truth for which plugins serve a
 * device (many-to-many). Each row carries its own credential source so every
 * plugin on a device can use a different secret. Exactly one assignment per
 * device is marked primary — the default target for config jobs and the UI's
 * "main" plugin.
 */

/** One bound credential slot: descriptor + resolved label for UI display. */
export interface BoundCredentialSlot {
  name: string;
  /** Legacy single allowed type (first of `secretTypes`). */
  secretType: string;
  /** All allowed secret types for this slot (one or many). */
  secretTypes?: string[];
  required?: boolean;
  description?: string;
  /** secrets.id bound to this slot (null = unbound). */
  secretId: string | null;
  /** Label of the bound secret, when resolvable. */
  secretLabel?: string | null;
}

/** One quick action a plugin advertises for its devices (Devices page column). */
export interface QuickActionView {
  id: string;
  label: string;
  description?: string;
  kind: 'url' | 'shell' | 'files' | 'action';
  /** kind 'url': path the plugin appends to the resolved base URL. */
  url?: { path: string };
  /** kind 'action': id of a single-device entry in this plugin's action catalog. */
  actionId?: string;
  /** Pre-filled input values for kind 'action'. */
  prefill?: Record<string, unknown>;
}

export interface DevicePluginAssignment {
  id: string;
  deviceId: string;
  pluginId: string;
  /** Credential source for this assignment (null = no credentials). */
  secretId: string | null;
  /** Bound extra credential slots: slot name → secrets.id. */
  extraCredentials: ExtraCredentials;
  isPrimary: boolean;
  /** Position within the device's ordered plugin list (0-based, dense). The row at order 0 is primary. */
  order: number;
  createdAt: string;
}

/** Assignment enriched with the plugin's identity + online state. */
export interface DevicePluginAssignmentView extends DevicePluginAssignment {
  pluginName?: string;
  pluginVersion?: string;
  pluginEndpoint?: string;
  /** The assigned plugin's advertised capabilities (e.g. 'deviceState'). */
  pluginCapabilities?: string[];
  /** The assigned plugin's quick actions for the Devices page "Device Actions" column. */
  pluginQuickActions?: QuickActionView[];
  /** True when the plugin was seen within the last 5 minutes. */
  pluginOnline?: boolean;
  secretLabel?: string | null;
  /** The plugin's declared slots with their bound secrets resolved for display. */
  credentialSlots?: BoundCredentialSlot[];
  /** The plugin's device-support document (license/help/docs + support matrix). */
  deviceSupport?: DeviceSupport | null;
  /** Capabilities evaluated as effective for THIS device (feature/slot/firmware gating applied). */
  effectiveCapabilities?: CapabilityEvaluation[];
  /** Intents allowed on THIS device per the plugin's support matrix. */
  effectiveIntents?: CapabilityEvaluation[];
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

/** Maps a raw row to the public assignment shape (parses extraCredentials). */
function toAssignment(row: typeof schema.devicePlugins.$inferSelect): DevicePluginAssignment {
  return {
    id: row.id,
    deviceId: row.deviceId,
    pluginId: row.pluginId,
    secretId: row.secretId,
    extraCredentials: parseExtraCredentials(row.extraCredentials),
    isPrimary: row.isPrimary,
    order: row.order,
    createdAt: row.createdAt,
  };
}

/** All sibling rows for a device in their stored (dense) order. */
async function orderedSiblings(deviceId: string) {
  return db.query.devicePlugins.findMany({
    where: (rows) => eq(rows.deviceId, deviceId),
    orderBy: [asc(schema.devicePlugins.order), asc(schema.devicePlugins.createdAt)],
  });
}

/**
 * Rewrites the dense `order` values for a device so that the given plugin ids
 * occupy positions 0..n-1 in exactly this sequence (unknown/missing ids are
 * ignored). The row at position 0 becomes primary; all others are demoted.
 */
export async function reorderAssignments(deviceId: string, orderedPluginIds: string[]): Promise<DevicePluginAssignment[]> {
  await assertDevice(deviceId);
  const siblings = await orderedSiblings(deviceId);
  if (siblings.length === 0) return [];

  // Desired sequence: requested ids first (in order), then any not mentioned.
  const byId = new Map(siblings.map((s) => [s.pluginId, s]));
  const seen = new Set<string>();
  const sequence: string[] = [];
  for (const pluginId of orderedPluginIds) {
    if (!byId.has(pluginId) || seen.has(pluginId)) continue;
    seen.add(pluginId);
    sequence.push(pluginId);
  }
  for (const s of siblings) {
    if (!seen.has(s.pluginId)) sequence.push(s.pluginId);
  }

  const newPrimary = byId.get(sequence[0])!;
  await db.transaction(async (tx) => {
    for (let i = 0; i < sequence.length; i += 1) {
      const row = byId.get(sequence[i])!;
      const isPrimary = i === 0;
      if (row.order !== i || row.isPrimary !== isPrimary) {
        await tx.update(schema.devicePlugins)
          .set({ order: i, isPrimary })
          .where(eq(schema.devicePlugins.id, row.id));
      }
    }
  });

  return (await orderedSiblings(deviceId)).map(toAssignment);
}

/**
 * Validates a proposed extra-credentials map against the plugin's declared
 * slots. Throws AssignmentError(400) on unknown slot names or secret-type
 * mismatches; returns the validated map (empty object when nothing bound).
 */
async function validateExtraCredentials(
  pluginId: string,
  input: Record<string, string | null> | undefined
): Promise<ExtraCredentials> {
  if (!input || Object.keys(input).length === 0) return {};

  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  let slots: CredentialSlotDescriptor[] = [];
  if (plugin?.credentialSlots) {
    try {
      const parsed = JSON.parse(plugin.credentialSlots);
      if (Array.isArray(parsed)) slots = parsed as CredentialSlotDescriptor[];
    } catch {
      /* malformed cache — treat as no slots */
    }
  }

  const out: ExtraCredentials = {};
  for (const [name, secretId] of Object.entries(input)) {
    if (!secretId) continue; // explicit null/empty clears the slot
    const slot = slots.find((s) => s.name === name);
    if (!slot) {
      throw new AssignmentError(400, `Plugin does not declare a credential slot named "${name}"`);
    }
    const secret = await db.query.secrets.findFirst({
      where: (secrets, { eq }) => eq(secrets.id, secretId),
    });
    if (!secret) throw new AssignmentError(404, `Referenced credentials for slot "${name}" not found`);
    if (!slotAcceptsType(slot, secret.type)) {
      const allowed = (Array.isArray(slot.secretTypes) && slot.secretTypes.length > 0 ? slot.secretTypes : [slot.secretType]).join(' | ');
      throw new AssignmentError(
        400,
        `Credential slot "${name}" requires a secret of type ${allowed}, but the selected secret is of type "${secret.type}"`
      );
    }
    out[name] = secretId;
  }
  return out;
}

/** All assignments for a device in their stored order (primary first). */
export async function listAssignments(deviceId: string): Promise<DevicePluginAssignment[]> {
  await assertDevice(deviceId);
  const rows = await orderedSiblings(deviceId);
  return rows.map(toAssignment);
}

/** Assignments enriched with plugin identity + online state for the UI. */
export async function listAssignmentViews(deviceId: string): Promise<DevicePluginAssignmentView[]> {
  const assignments = await listAssignments(deviceId);
  if (assignments.length === 0) return [];

  const pluginIds = Array.from(new Set(assignments.map((a) => a.pluginId)));
  // Primary + every bound slot secret, resolved in one query.
  const secretIds = new Set<string>();
  for (const a of assignments) {
    if (a.secretId) secretIds.add(a.secretId);
    for (const id of Object.values(a.extraCredentials)) secretIds.add(id);
  }

  const [plugins, secrets, device] = await Promise.all([
    db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) }),
    secretIds.size > 0
      ? db.query.secrets.findMany({ where: inArray(schema.secrets.id, Array.from(secretIds)) })
      : [],
    // The device row itself — vendor/model/firmwareVersion feed the support-matrix evaluation.
    db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) }),
  ]);

  const now = Date.now();
  // Async per assignment: the support-matrix evaluation reads each device's
  // latest telemetry snapshot (detected features).
  return Promise.all(
    assignments.map(async (a) => {
      const plugin = plugins.find((p) => p.id === a.pluginId);
      const secret = secrets.find((s) => s.id === a.secretId);
    let credentialSlots: BoundCredentialSlot[] | undefined;
    if (plugin?.credentialSlots) {
      try {
        const declared = JSON.parse(plugin.credentialSlots) as CredentialSlotDescriptor[];
        if (Array.isArray(declared)) {
          credentialSlots = declared.map((slot) => {
            const boundId = a.extraCredentials[slot.name] ?? null;
            const boundSecret = secrets.find((s) => s.id === boundId);
            const types = Array.isArray(slot.secretTypes) && slot.secretTypes.length > 0 ? slot.secretTypes : undefined;
            return {
              name: slot.name,
              secretType: slot.secretType ?? (types?.[0] ?? ''),
              ...(types ? { secretTypes: types } : {}),
              required: slot.required,
              description: slot.description,
              secretId: boundId,
              secretLabel: boundSecret ? (boundSecret.label ?? null) : null,
            };
          });
        }
      } catch {
        /* malformed cache — skip slot display */
      }
    }
    let capabilities: string[] | undefined;
    if (plugin?.capabilities) {
      try {
        const parsed = JSON.parse(plugin.capabilities);
        capabilities = Array.isArray(parsed) ? parsed.filter((c): c is string => typeof c === 'string') : [];
      } catch {
        /* malformed cache — skip capability display */
      }
    }
    let quickActions: QuickActionView[] | undefined;
    if (plugin?.quickActions) {
      try {
        const parsed = JSON.parse(plugin.quickActions);
        if (Array.isArray(parsed)) {
          quickActions = parsed
            .filter((q): q is Record<string, unknown> => !!q && typeof q === 'object')
            .map((q) => ({
              id: String(q.id ?? ''),
              label: String(q.label ?? ''),
              ...(typeof q.description === 'string' ? { description: q.description } : {}),
              kind: (['url', 'shell', 'files', 'action'].includes(String(q.kind)) ? String(q.kind) : 'url') as QuickActionView['kind'],
              ...(q.url && typeof q.url === 'object' ? { url: { path: String((q.url as Record<string, unknown>).path ?? '') } } : {}),
              ...(typeof q.actionId === 'string' ? { actionId: q.actionId } : {}),
              ...(q.prefill && typeof q.prefill === 'object' ? { prefill: q.prefill as Record<string, unknown> } : {}),
            }))
            .filter((q) => q.id !== '' && q.label !== '');
        }
      } catch {
        /* malformed cache — skip quick-action display */
      }
    }
    // Device-support evaluation: which of the plugin's capabilities/intents are
    // EFFECTIVE for this specific device — gated by detected features (latest
    // telemetry snapshot), bound credential slots, and firmware version.
    let deviceSupport: DeviceSupport | null = null;
    if (typeof plugin?.deviceSupport === 'string' && plugin.deviceSupport.length > 0) {
      try {
        const parsed = JSON.parse(plugin.deviceSupport);
        deviceSupport = parsed && typeof parsed === 'object' ? (parsed as DeviceSupport) : null;
      } catch {
        /* malformed cache — skip support display */
      }
    }
    let effectiveCapabilities: CapabilityEvaluation[] | undefined;
    let effectiveIntents: CapabilityEvaluation[] | undefined;
    if (deviceSupport && device) {
      // Detected features from the newest telemetry snapshot of THIS assignment.
      const latest = await db.query.telemetry.findFirst({
        where: and(eq(schema.telemetry.deviceId, deviceId), eq(schema.telemetry.pluginId, a.pluginId)),
        orderBy: [desc(schema.telemetry.collectedAt)],
      });
      let detectedFeatures: string[] = [];
      if (latest?.metrics) {
        try {
          const m = typeof latest.metrics === 'string' ? JSON.parse(latest.metrics) : latest.metrics;
          const raw = Array.isArray(m['detectedFeatures']) ? (m['detectedFeatures'] as unknown[]) : [];
          detectedFeatures = raw.filter((f): f is string => typeof f === 'string');
        } catch {
          /* malformed snapshot — evaluate with no features */
        }
      }
      // A slot counts as bound when a secret id is set on it (type validity was
      // enforced at bind time by validateExtraCredentials).
      const boundSlots: Record<string, boolean> = {};
      for (const [slotName] of Object.entries(a.extraCredentials)) boundSlots[slotName] = true;
      const evaluation = evaluateDeviceSupport(deviceSupport, {
        vendor: device.vendor,
        model: device.model,
        firmwareVersion: device.firmwareVersion,
        detectedFeatures,
        boundSlots,
      });
      effectiveCapabilities = evaluation.capabilities;
      effectiveIntents = evaluation.intents;
    }

    return {
      ...a,
      pluginName: plugin?.name,
      pluginVersion: plugin?.version,
      pluginEndpoint: plugin?.endpoint,
      pluginCapabilities: capabilities,
      pluginQuickActions: quickActions,
      pluginOnline:
        plugin?.lastSeenAt !== null &&
        plugin?.lastSeenAt !== undefined &&
        now - Date.parse(plugin.lastSeenAt) < ONLINE_WINDOW_MS,
      secretLabel: secret ? (secret.label ?? null) : null,
      credentialSlots,
      deviceSupport,
      effectiveCapabilities,
      effectiveIntents,
    };
    }),
  );
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
  /** Extra credential slots to bind (slot name → secrets.id). Validated against the plugin's declared slots. */
  extraCredentials?: Record<string, string | null>;
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

  const extraCredentials = await validateExtraCredentials(pluginId, input.extraCredentials);

  const existing = await findAssignment(deviceId, pluginId);
  if (existing) throw new AssignmentError(409, 'Plugin is already assigned to this device');

  const siblings = await orderedSiblings(deviceId);
  const now = new Date().toISOString();
  const extraJson = Object.keys(extraCredentials).length > 0 ? JSON.stringify(extraCredentials) : null;

  // Placement: an explicit primary lands at position 0 (shifting the rest down,
  // which also demotes the old primary); anything else appends to the end. The
  // very first assignment on a device is always primary.
  if (input.isPrimary === true && siblings.length > 0) {
    await db.transaction(async (tx) => {
      for (const s of siblings) {
        await tx.update(schema.devicePlugins)
          .set({ order: s.order + 1, isPrimary: false })
          .where(eq(schema.devicePlugins.id, s.id));
      }
      await tx.insert(schema.devicePlugins).values({
        id: uuidv4(), deviceId, pluginId, secretId, extraCredentials: extraJson,
        isPrimary: true, order: 0, createdAt: now,
      });
    });
  } else {
    const isFirst = siblings.length === 0;
    await db.insert(schema.devicePlugins).values({
      id: uuidv4(), deviceId, pluginId, secretId, extraCredentials: extraJson,
      isPrimary: isFirst, order: siblings.length, createdAt: now,
    });
  }

  return toAssignment((await findAssignment(deviceId, pluginId))!);
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

  // Re-densify the remaining rows (0..n-1) and make sure position 0 is primary.
  const remaining = await orderedSiblings(deviceId);
  if (remaining.length > 0) {
    for (let i = 0; i < remaining.length; i += 1) {
      const row = remaining[i];
      const isPrimary = i === 0;
      if (row.order !== i || row.isPrimary !== isPrimary) {
        await db.update(schema.devicePlugins)
          .set({ order: i, isPrimary })
          .where(eq(schema.devicePlugins.id, row.id));
      }
    }
  }
}

/**
 * Promotes the given assignment to primary by moving it to position 0 (the row
 * at order 0 is always primary). No-op when it already leads — idempotent.
 */
export async function setPrimary(deviceId: string, pluginId: string): Promise<DevicePluginAssignment> {
  await assertDevice(deviceId);
  const assignment = await findAssignment(deviceId, pluginId);
  if (!assignment) throw new AssignmentError(404, 'Plugin is not assigned to this device');

  if (assignment.order !== 0 || !assignment.isPrimary) {
    // Move the row to the front and shift everything else down by one.
    const siblings = await orderedSiblings(deviceId);
    await db.transaction(async (tx) => {
      for (const s of siblings) {
        if (s.id === assignment.id) continue;
        const nextOrder = s.order >= assignment.order ? s.order + 1 : s.order;
        await tx.update(schema.devicePlugins)
          .set({ order: nextOrder, isPrimary: false })
          .where(eq(schema.devicePlugins.id, s.id));
      }
      await tx.update(schema.devicePlugins)
        .set({ order: 0, isPrimary: true })
        .where(eq(schema.devicePlugins.id, assignment.id));
    });
  }

  return toAssignment((await findAssignment(deviceId, pluginId))!);
}

/**
 * Updates an existing assignment's credential source and/or primary flag.
 * - `isPrimary: true` demotes the current primary (exactly-one invariant).
 * - `secretId` may be set to a new value or null (clear credentials).
 * At least one field must be provided; otherwise 400.
 */
export async function updateAssignment(
  deviceId: string,
  pluginId: string,
  input: { secretId?: string | null; isPrimary?: boolean; extraCredentials?: Record<string, string | null> }
): Promise<DevicePluginAssignment> {
  await assertDevice(deviceId);
  const assignment = await findAssignment(deviceId, pluginId);
  if (!assignment) throw new AssignmentError(404, 'Plugin is not assigned to this device');

  // Validate secret reference when provided.
  let newSecretId: string | null | undefined;
  if (input.secretId !== undefined) {
    if (input.secretId === null || input.secretId === '') {
      newSecretId = null;
    } else {
      // Capture to a local — closure over a narrowed prop loses narrowing.
      const secretId: string = input.secretId;
      const secret = await db.query.secrets.findFirst({
        where: (secrets, { eq }) => eq(secrets.id, secretId),
      });
      if (!secret) throw new AssignmentError(404, 'Referenced credentials not found');
      newSecretId = secretId;
    }
  }

  // Promote to primary (demoting the current one) when requested — moves the
  // row to position 0 and shifts everything else down by one.
  if (input.isPrimary === true && assignment.order !== 0) {
    const siblings = await orderedSiblings(deviceId);
    await db.transaction(async (tx) => {
      for (const s of siblings) {
        if (s.id === assignment.id) continue;
        const nextOrder = s.order >= assignment.order ? s.order + 1 : s.order;
        await tx.update(schema.devicePlugins)
          .set({ order: nextOrder, isPrimary: false })
          .where(eq(schema.devicePlugins.id, s.id));
      }
    });
  }

  // Extra credential slots: validated against the plugin's declared slots.
  // Omitted = unchanged; provided = full replacement of the slot map.
  let newExtraJson: string | null | undefined;
  if (input.extraCredentials !== undefined) {
    const extra = await validateExtraCredentials(pluginId, input.extraCredentials);
    newExtraJson = Object.keys(extra).length > 0 ? JSON.stringify(extra) : null;
  }

  const updates: Partial<typeof schema.devicePlugins.$inferInsert> = {};
  if (newSecretId !== undefined) updates.secretId = newSecretId;
  if (input.isPrimary === true) updates.isPrimary = true;
  if (newExtraJson !== undefined) updates.extraCredentials = newExtraJson;

  if (Object.keys(updates).length > 0) {
    await db.update(schema.devicePlugins)
      .set(updates)
      .where(eq(schema.devicePlugins.id, assignment.id));
  }

  return toAssignment((await findAssignment(deviceId, pluginId))!);
}

/** True when (device, plugin) has an assignment — used to validate config jobs. */
export async function hasAssignment(deviceId: string, pluginId: string): Promise<boolean> {
  const row = await findAssignment(deviceId, pluginId);
  return row !== undefined;
}
