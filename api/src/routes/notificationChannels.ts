import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { and, desc, eq, inArray, isNull, or } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { sendChannelTest } from '../notificationDispatch';

/**
 * Notification SENDER channels — configured delivery endpoints (SMTP account,
 * webhook URL, Telegram chat, …). The API owns all metadata here; the transport
 * is a notification-sender plugin resolved per channel. Config fields are
 * validated against the plugin-declared channel catalog at write time;
 * credentials live in the pluggable secrets provider (bound by secretId).
 */

const router = Router();

interface ChannelField {
  name: string;
  label: string;
  input: 'text' | 'number' | 'select' | 'boolean';
  required?: boolean;
  options?: string[];
}

interface ChannelDescriptor {
  type: string;
  label: string;
  description?: string;
  fields: ChannelField[];
  secretTypes?: string[];
}

/** Loads the sender plugin's channel catalog (null when not a sender / stale). */
async function loadCatalog(pluginId: string): Promise<ChannelDescriptor[] | null> {
  const row = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!row || !row.notificationChannels) return null;
  try {
    const parsed = JSON.parse(row.notificationChannels);
    return Array.isArray(parsed) ? (parsed as ChannelDescriptor[]) : null;
  } catch {
    return null;
  }
}

/** True when the plugin row exists, advertises notificationSender, and is online. */
async function isSenderPlugin(pluginId: string): Promise<boolean> {
  const row = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
  if (!row || !row.capabilities) return false;
  let caps: string[] = [];
  try {
    const parsed = JSON.parse(row.capabilities);
    caps = Array.isArray(parsed) ? (parsed as string[]) : [];
  } catch {
    return false;
  }
  if (!caps.includes('notificationSender')) return false;
  if (!row.lastSeenAt) return false;
  const t = Date.parse(row.lastSeenAt);
  return !Number.isNaN(t) && Date.now() - t <= 5 * 60 * 1000;
}

/**
 * Validates a channel config object against the descriptor's field schema:
 * required fields present + non-empty, select values within options, number
 * fields numeric. Unknown keys are dropped (forward-compatible with plugins
 * that add fields). Returns the cleaned config or an error string.
 */
function validateConfig(config: Record<string, unknown>, descriptor: ChannelDescriptor): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  const out: Record<string, unknown> = {};
  for (const field of descriptor.fields) {
    const raw = config[field.name];
    if (raw === undefined || raw === null || raw === '') {
      if (field.required) return { ok: false, error: `"${field.label}" is required` };
      continue;
    }
    switch (field.input) {
      case 'text':
        if (typeof raw !== 'string') return { ok: false, error: `"${field.label}" must be a string` };
        out[field.name] = raw.trim();
        break;
      case 'number': {
        const n = typeof raw === 'number' ? raw : Number(raw);
        if (!Number.isFinite(n)) return { ok: false, error: `"${field.label}" must be a number` };
        out[field.name] = n;
        break;
      }
      case 'boolean':
        out[field.name] = raw === true || raw === 'true' || raw === 1;
        break;
      case 'select': {
        if (typeof raw !== 'string') return { ok: false, error: `"${field.label}" must be a string` };
        if (field.options && !field.options.includes(raw)) {
          return { ok: false, error: `"${field.label}" must be one of: ${field.options.join(', ')}` };
        }
        out[field.name] = raw;
        break;
      }
    }
  }
  return { ok: true, value: out };
}

interface ChannelInput {
  name?: unknown;
  pluginId?: unknown;
  channelType?: unknown;
  enabled?: unknown;
  config?: unknown;
  secretId?: unknown;
  ownerId?: unknown;
}

/**
 * Resolves + validates the requested channel owner. null/absent = SHARED channel.
 * A user may create personal channels for themselves; creating one for ANOTHER
 * user requires users:write (admin setup on someone's behalf).
 */
async function resolveOwner(req: Request, input: unknown): Promise<{ ok: true; value: string | null } | { ok: false; status: number; error: string }> {
  if (input === undefined || input === null || input === '') return { ok: true, value: null };
  if (typeof input !== 'string') return { ok: false, status: 400, error: '"ownerId" must be a user id or null' };
  const me = req.user!.sub;
  if (input === me) return { ok: true, value: me };
  if (!(req.user?.permissions ?? []).includes('users:write')) {
    return { ok: false, status: 403, error: '"ownerId" may only be set to yourself (or null for a shared channel) without users:write' };
  }
  const u = await db.query.users.findFirst({ where: eq(schema.users.id, input) });
  if (!u) return { ok: false, status: 400, error: 'The selected owner user does not exist' };
  return { ok: true, value: u.id };
}

/** Shared channels are managed by any notifications:write holder; personal ones only by their owner (or users:write). */
function canManageChannel(req: Request, ownerId: string | null): boolean {
  if (!ownerId) return true;
  const perms = req.user?.permissions ?? [];
  return ownerId === req.user!.sub || perms.includes('users:write');
}

/** Validates a CREATE payload (all fields required except enabled/secretId). */
async function validateChannel(input: ChannelInput): Promise<{ values: Record<string, unknown> } | { error: string }> {
  const values: Record<string, unknown> = {};

  if (typeof input.name !== 'string' || input.name.trim().length === 0) return { error: '"name" must be a non-empty string' };
  if (input.name.trim().length > 200) return { error: '"name" must be at most 200 characters' };
  values.name = input.name.trim();

  const pluginId = typeof input.pluginId === 'string' ? input.pluginId : '';
  if (!pluginId) return { error: '"pluginId" is required' };
  const channelType = typeof input.channelType === 'string' ? input.channelType : '';
  if (!channelType) return { error: '"channelType" is required' };

  if (!(await isSenderPlugin(pluginId))) {
    return { error: 'The selected plugin does not advertise the notificationSender capability (or is offline)' };
  }
  const catalog = await loadCatalog(pluginId);
  const descriptor = catalog?.find((c) => c.type === channelType);
  if (!descriptor) return { error: `Channel type "${channelType}" is not in the selected plugin's catalog` };

  // Config — validated against the descriptor (unknown keys dropped).
  let configInput: Record<string, unknown> = {};
  if (input.config !== undefined) {
    if (!input.config || typeof input.config !== 'object' || Array.isArray(input.config)) return { error: '"config" must be an object' };
    configInput = input.config as Record<string, unknown>;
  }
  const cfg = validateConfig(configInput, descriptor);
  if (!cfg.ok) return { error: cfg.error };
  values.config = JSON.stringify(cfg.value);

  // Secret binding — must exist and match the descriptor's accepted types.
  let secretId: string | null = null;
  if (input.secretId !== undefined && input.secretId !== null && input.secretId !== '') {
    if (typeof input.secretId !== 'string') return { error: '"secretId" must be a string or null' };
    const sec = await db.query.secrets.findFirst({ where: eq(schema.secrets.id, input.secretId) });
    if (!sec) return { error: 'The selected secret does not exist' };
    const accepted = descriptor.secretTypes ?? [];
    if (accepted.length > 0 && !accepted.includes(sec.type)) {
      return { error: `This channel type accepts secrets of type: ${accepted.join(', ')} (selected is "${sec.type}")` };
    }
    secretId = sec.id;
  }
  values.secretId = secretId;

  if (input.enabled !== undefined) {
    if (typeof input.enabled !== 'boolean') return { error: '"enabled" must be a boolean' };
    values.enabled = input.enabled;
  }

  values.pluginId = pluginId;
  values.channelType = channelType;
  return { values };
}

function serializeChannel(row: typeof schema.notificationChannels.$inferSelect, extra?: { pluginName?: string | null; typeLabel?: string | null; lastDelivery?: { status: string; sentAt: string; error: string | null } | null; ownerName?: string | null }) {
  let config: Record<string, unknown> = {};
  try {
    const parsed = JSON.parse(row.config || '{}');
    if (parsed && typeof parsed === 'object') config = parsed;
  } catch { /* keep {} */ }
  return {
    id: row.id,
    name: row.name,
    pluginId: row.pluginId,
    channelType: row.channelType,
    enabled: row.enabled,
    config,
    secretId: row.secretId ?? null,
    ownerId: row.ownerId ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ...(extra?.pluginName !== undefined ? { pluginName: extra.pluginName } : {}),
    ...(extra?.typeLabel !== undefined ? { typeLabel: extra.typeLabel } : {}),
    ...(extra?.lastDelivery !== undefined ? { lastDelivery: extra.lastDelivery } : {}),
    ...(extra?.ownerName !== undefined ? { ownerName: extra.ownerName } : {}),
  };
}

// GET /notification-channels — channels with plugin name, catalog label and the
// most recent delivery attempt (drives the UI's status column). Personal
// channels are only visible to their owner (or users:write holders).
router.get('/notification-channels', requireAuth, requirePermission('notifications:read'), async (req: Request, res: Response) => {
  const me = req.user!.sub;
  const canSeeAll = (req.user?.permissions ?? []).includes('users:write');
  const rows = await db.query.notificationChannels.findMany({
    where: canSeeAll ? undefined : or(isNull(schema.notificationChannels.ownerId), eq(schema.notificationChannels.ownerId, me)),
    orderBy: [desc(schema.notificationChannels.createdAt)],
  });
  if (rows.length === 0) {
    res.status(200).json([]);
    return;
  }

  // Latest delivery per channel in one query.
  const ids = rows.map((r) => r.id);
  const deliveries = await db.query.notificationDeliveries.findMany({
    where: inArray(schema.notificationDeliveries.channelId, ids),
    orderBy: [desc(schema.notificationDeliveries.sentAt)],
  });
  const lastByChannel = new Map<string, { status: string; sentAt: string; error: string | null }>();
  for (const d of deliveries) {
    if (!lastByChannel.has(d.channelId)) lastByChannel.set(d.channelId, { status: d.status, sentAt: d.sentAt, error: d.error });
  }

  const pluginIds = [...new Set(rows.map((r) => r.pluginId))];
  const plugins = await db.query.plugins.findMany({ where: inArray(schema.plugins.id, pluginIds) });
  const pluginById = new Map(plugins.map((p) => [p.id, p]));

  const ownerIds = [...new Set(rows.map((r) => r.ownerId).filter((v): v is string => !!v))];
  const owners = ownerIds.length > 0 ? await db.query.users.findMany({ where: inArray(schema.users.id, ownerIds) }) : [];
  const ownerNameById = new Map(owners.map((u) => [u.id, u.username]));

  res.status(200).json(rows.map((row) => {
    const plugin = pluginById.get(row.pluginId);
    let typeLabel: string | null = null;
    if (plugin?.notificationChannels) {
      try {
        const catalog = JSON.parse(plugin.notificationChannels) as ChannelDescriptor[];
        typeLabel = Array.isArray(catalog) ? catalog.find((c) => c.type === row.channelType)?.label ?? null : null;
      } catch { /* keep null */ }
    }
    return serializeChannel(row, {
      pluginName: plugin?.name ?? null,
      typeLabel,
      lastDelivery: lastByChannel.get(row.id) ?? null,
      ownerName: row.ownerId ? (ownerNameById.get(row.ownerId) ?? null) : null,
    });
  }));
});

// POST /notification-channels — create a channel (validated against the catalog).
// Optional ownerId makes it a PERSONAL channel of that user (self, or anyone
// with users:write) — the fan-out target for rule audiences.
router.post('/notification-channels', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as ChannelInput;
  const v = await validateChannel(body);
  if ('error' in v) {
    res.status(400).json({ error: v.error });
    return;
  }
  const ownerRes = await resolveOwner(req, body.ownerId);
  if (!ownerRes.ok) {
    res.status(ownerRes.status).json({ error: ownerRes.error });
    return;
  }
  const now = new Date().toISOString();
  const id = uuidv4();
  await db.insert(schema.notificationChannels).values({
    id,
    name: String(v.values.name),
    pluginId: String(v.values.pluginId),
    channelType: String(v.values.channelType),
    enabled: v.values.enabled === false ? false : true,
    config: String(v.values.config),
    secretId: (v.values.secretId as string | null) ?? null,
    ownerId: ownerRes.value,
    createdAt: now,
    updatedAt: now,
  });
  const row = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  res.status(201).json(serializeChannel(row!));
});

// GET /notification-channels/:id — single channel (personal ones only to their owner).
router.get('/notification-channels/:id', requireAuth, requirePermission('notifications:read'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const row = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  if (!row || !canManageChannel(req, row.ownerId)) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }
  const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, row.pluginId) });
  let typeLabel: string | null = null;
  if (plugin?.notificationChannels) {
    try {
      const catalog = JSON.parse(plugin.notificationChannels) as ChannelDescriptor[];
      typeLabel = Array.isArray(catalog) ? catalog.find((c) => c.type === row.channelType)?.label ?? null : null;
    } catch { /* keep null */ }
  }
  res.status(200).json(serializeChannel(row, { pluginName: plugin?.name ?? null, typeLabel }));
});

// PUT /notification-channels/:id — partial update. ownerId is immutable.
router.put('/notification-channels/:id', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const existing = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  if (!existing || !canManageChannel(req, existing.ownerId)) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }
  const body = (req.body ?? {}) as ChannelInput;
  if (body.ownerId !== undefined) {
    res.status(400).json({ error: '"ownerId" cannot be changed after creation — delete and recreate the channel instead' });
    return;
  }
  const v = await validateChannelWithId(body, id);
  if ('error' in v) {
    res.status(400).json({ error: v.error });
    return;
  }
  await db.update(schema.notificationChannels)
    .set({ ...v.values, updatedAt: new Date().toISOString() })
    .where(eq(schema.notificationChannels.id, id));
  const row = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  res.status(200).json(serializeChannel(row!));
});

// DELETE /notification-channels/:id — remove the channel + its delivery history.
router.delete('/notification-channels/:id', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const existing = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  if (!existing || !canManageChannel(req, existing.ownerId)) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }
  await db.delete(schema.notificationDeliveries).where(eq(schema.notificationDeliveries.channelId, id));
  await db.delete(schema.notificationChannels).where(eq(schema.notificationChannels.id, id));
  res.status(204).send();
});

// POST /notification-channels/:id/test — send a fixed test message through this
// channel (records a delivery row with ruleId null for the audit trail).
router.post('/notification-channels/:id/test', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const existing = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  if (!existing || !canManageChannel(req, existing.ownerId)) {
    res.status(404).json({ error: 'Channel not found' });
    return;
  }
  const result = await sendChannelTest(id);
  if (result.error) {
    res.status(502).json({ error: result.error });
    return;
  }
  res.status(200).json({ sent: true });
});

export default router;

// ── Partial-update validation (needs the existing row for absent fields) ─────

async function validateChannelWithId(input: ChannelInput, id: string): Promise<{ values: Record<string, unknown> } | { error: string }> {
  const existing = await db.query.notificationChannels.findFirst({ where: eq(schema.notificationChannels.id, id) });
  if (!existing) return { error: 'Channel not found' };

  const name = input.name !== undefined ? input.name : existing.name;
  if (typeof name !== 'string' || name.trim().length === 0) return { error: '"name" must be a non-empty string' };
  if (name.trim().length > 200) return { error: '"name" must be at most 200 characters' };

  const pluginId = input.pluginId !== undefined ? String(input.pluginId ?? '') : existing.pluginId;
  if (!pluginId) return { error: '"pluginId" is required' };
  const channelType = input.channelType !== undefined ? String(input.channelType ?? '') : existing.channelType;
  if (!channelType) return { error: '"channelType" is required' };

  if (!(await isSenderPlugin(pluginId))) {
    return { error: 'The selected plugin does not advertise the notificationSender capability (or is offline)' };
  }
  const catalog = await loadCatalog(pluginId);
  const descriptor = catalog?.find((c) => c.type === channelType);
  if (!descriptor) return { error: `Channel type "${channelType}" is not in the selected plugin's catalog` };

  let configInput: Record<string, unknown> = {};
  if (input.config !== undefined) {
    if (!input.config || typeof input.config !== 'object' || Array.isArray(input.config)) return { error: '"config" must be an object' };
    configInput = input.config as Record<string, unknown>;
  } else {
    try {
      configInput = JSON.parse(existing.config || '{}');
    } catch {
      configInput = {};
    }
  }
  const cfg = validateConfig(configInput, descriptor);
  if (!cfg.ok) return { error: cfg.error };

  let secretId: string | null = existing.secretId ?? null;
  if (input.secretId !== undefined) {
    if (input.secretId === null || input.secretId === '') {
      secretId = null;
    } else if (typeof input.secretId === 'string' && input.secretId) {
      const sec = await db.query.secrets.findFirst({ where: eq(schema.secrets.id, input.secretId) });
      if (!sec) return { error: 'The selected secret does not exist' };
      const accepted = descriptor.secretTypes ?? [];
      if (accepted.length > 0 && !accepted.includes(sec.type)) {
        return { error: `This channel type accepts secrets of type: ${accepted.join(', ')} (selected is "${sec.type}")` };
      }
      secretId = sec.id;
    } else {
      return { error: '"secretId" must be a string or null' };
    }
  }

  const values: Record<string, unknown> = {
    name: name.trim(),
    pluginId,
    channelType,
    config: JSON.stringify(cfg.value),
    secretId,
  };
  if (input.enabled !== undefined) {
    if (typeof input.enabled !== 'boolean') return { error: '"enabled" must be a boolean' };
    values.enabled = input.enabled;
  }
  return { values };
}
