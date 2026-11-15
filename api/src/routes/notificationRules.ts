import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { and, desc, eq, inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import type { NotificationRuleAudience } from '../notificationDispatch';

/**
 * Notification RULES — "when a notification matches this filter, render the
 * templates and deliver to these channels" — plus the delivery audit trail.
 */

const router = Router();

const SEVERITIES = ['info', 'warning', 'critical'];
const SOURCES = ['system', 'device', 'plugin'];

interface RuleFilter {
  severities?: string[];
  sources?: string[];
  deviceTags?: string[];
  vendors?: string[];
  deviceTypes?: string[];
  titleRegex?: string | null;
  messageRegex?: string | null;
}

/** Validates a rule filter object. Returns the cleaned filter or an error. */
function validateFilter(filter: unknown): { ok: true; value: RuleFilter } | { ok: false; error: string } {
  if (filter === undefined || filter === null) return { ok: true, value: {} };
  if (!filter || typeof filter !== 'object' || Array.isArray(filter)) return { ok: false, error: '"filter" must be an object' };
  const f = filter as Record<string, unknown>;

  const out: RuleFilter = {};

  for (const key of ['severities', 'sources'] as const) {
    if (f[key] === undefined || f[key] === null) continue;
    if (!Array.isArray(f[key])) return { ok: false, error: `"filter.${key}" must be an array` };
    const allowed = key === 'severities' ? SEVERITIES : SOURCES;
    for (const v of f[key]) {
      if (typeof v !== 'string') return { ok: false, error: `"filter.${key}" entries must be strings` };
      if (!allowed.includes(v)) return { ok: false, error: `"filter.${key}" contains invalid value "${v}" (allowed: ${allowed.join(', ')})` };
    }
    out[key] = [...new Set(f[key] as string[])];
  }

  for (const key of ['deviceTags', 'vendors', 'deviceTypes'] as const) {
    if (f[key] === undefined || f[key] === null) continue;
    if (!Array.isArray(f[key])) return { ok: false, error: `"filter.${key}" must be an array` };
    for (const v of f[key]) {
      if (typeof v !== 'string' || !v.trim()) return { ok: false, error: `"filter.${key}" entries must be non-empty strings` };
    }
    out[key] = [...new Set((f[key] as string[]).map((s) => s.trim()))];
  }

  for (const key of ['titleRegex', 'messageRegex'] as const) {
    if (f[key] === undefined || f[key] === null || f[key] === '') continue;
    if (typeof f[key] !== 'string') return { ok: false, error: `"filter.${key}" must be a string` };
    try {
      new RegExp(f[key] as string, 'i');
    } catch (e) {
      return { ok: false, error: `"filter.${key}" is not a valid regular expression: ${(e as Error).message}` };
    }
    out[key] = f[key] as string;
  }

  return { ok: true, value: out };
}

interface RuleInput {
  name?: unknown;
  enabled?: unknown;
  filter?: unknown;
  channelIds?: unknown;
  audience?: unknown;
  titleTemplate?: unknown;
  bodyTemplate?: unknown;
  cooldownSec?: unknown;
}

/**
 * Validates an audience document. `type:'roles'` requires existing role names,
 * `type:'users'` requires existing user ids; fanOutTypes are free channel-type
 * strings (matched against personal channels at dispatch time). Returns the
 * cleaned, normalized document.
 */
async function validateAudience(input: unknown): Promise<{ ok: true; value: NotificationRuleAudience } | { ok: false; error: string }> {
  if (input === undefined || input === null) return { ok: true, value: { type: 'all' } };
  if (!input || typeof input !== 'object' || Array.isArray(input)) return { ok: false, error: '"audience" must be an object' };
  const a = input as Record<string, unknown>;

  const out: NotificationRuleAudience = { type: 'all' };
  if (a.type !== undefined && a.type !== null) {
    if (a.type !== 'all' && a.type !== 'roles' && a.type !== 'users') {
      return { ok: false, error: '"audience.type" must be one of all, roles, users' };
    }
    out.type = a.type;
  }

  if (out.type === 'roles') {
    if (!Array.isArray(a.roleNames) || a.roleNames.length === 0) return { ok: false, error: '"audience.roleNames" must be a non-empty array of role names' };
    for (const v of a.roleNames) {
      if (typeof v !== 'string' || !v.trim()) return { ok: false, error: '"audience.roleNames" entries must be non-empty strings' };
    }
    out.roleNames = [...new Set((a.roleNames as string[]).map((s) => s.trim()))];
    const existing = await db.query.roles.findMany({ where: inArray(schema.roles.name, out.roleNames) });
    const found = new Set(existing.map((r) => r.name));
    const missing = out.roleNames.filter((n) => !found.has(n));
    if (missing.length > 0) return { ok: false, error: `Unknown role name(s): ${missing.join(', ')}` };
  }

  if (out.type === 'users') {
    if (!Array.isArray(a.userIds) || a.userIds.length === 0) return { ok: false, error: '"audience.userIds" must be a non-empty array of user ids' };
    for (const v of a.userIds) {
      if (typeof v !== 'string' || !v.trim()) return { ok: false, error: '"audience.userIds" entries must be non-empty strings' };
    }
    out.userIds = [...new Set((a.userIds as string[]).map((s) => s.trim()))];
    const existing = await db.query.users.findMany({ where: inArray(schema.users.id, out.userIds) });
    const found = new Set(existing.map((u) => u.id));
    const missing = out.userIds.filter((id) => !found.has(id));
    if (missing.length > 0) return { ok: false, error: `Unknown user id(s): ${missing.join(', ')}` };
  }

  if (a.fanOutTypes !== undefined && a.fanOutTypes !== null) {
    if (!Array.isArray(a.fanOutTypes)) return { ok: false, error: '"audience.fanOutTypes" must be an array' };
    for (const v of a.fanOutTypes) {
      if (typeof v !== 'string' || !v.trim() || v.trim().length > 50) return { ok: false, error: '"audience.fanOutTypes" entries must be strings of at most 50 characters' };
    }
    out.fanOutTypes = [...new Set((a.fanOutTypes as string[]).map((s) => s.trim().toLowerCase()))];
  }

  return { ok: true, value: out };
}

/** Validates a CREATE payload. */
async function validateRule(input: RuleInput): Promise<{ values: Record<string, unknown> } | { error: string }> {
  const values: Record<string, unknown> = {};

  if (typeof input.name !== 'string' || input.name.trim().length === 0) return { error: '"name" must be a non-empty string' };
  if (input.name.trim().length > 200) return { error: '"name" must be at most 200 characters' };
  values.name = input.name.trim();

  const filterRes = validateFilter(input.filter);
  if (!filterRes.ok) return { error: filterRes.error };
  values.filter = JSON.stringify(filterRes.value);

  // Channel bindings — every id must exist.
  let channelIds: string[] = [];
  if (input.channelIds !== undefined && input.channelIds !== null) {
    if (!Array.isArray(input.channelIds)) return { error: '"channelIds" must be an array' };
    for (const v of input.channelIds) {
      if (typeof v !== 'string' || !v) return { error: '"channelIds" entries must be non-empty strings' };
    }
    channelIds = [...new Set(input.channelIds as string[])];
  }
  if (channelIds.length > 0) {
    const existing = await db.query.notificationChannels.findMany({ where: inArray(schema.notificationChannels.id, channelIds) });
    const found = new Set(existing.map((c) => c.id));
    const missing = channelIds.filter((id) => !found.has(id));
    if (missing.length > 0) return { error: `Unknown channel id(s): ${missing.join(', ')}` };
  }
  values.channelIds = JSON.stringify(channelIds);

  const audienceRes = await validateAudience(input.audience);
  if (!audienceRes.ok) return { error: audienceRes.error };
  values.audience = JSON.stringify(audienceRes.value);

  if (typeof input.titleTemplate !== 'string' || input.titleTemplate.trim().length === 0) {
    return { error: '"titleTemplate" must be a non-empty string' };
  }
  values.titleTemplate = input.titleTemplate;

  let bodyTemplate = '';
  if (input.bodyTemplate !== undefined && input.bodyTemplate !== null) {
    if (typeof input.bodyTemplate !== 'string') return { error: '"bodyTemplate" must be a string' };
    bodyTemplate = input.bodyTemplate;
  }
  values.bodyTemplate = bodyTemplate;

  let cooldownSec = 300;
  if (input.cooldownSec !== undefined && input.cooldownSec !== null) {
    const n = Number(input.cooldownSec);
    if (!Number.isInteger(n) || n < 0) return { error: '"cooldownSec" must be a non-negative integer' };
    cooldownSec = n;
  }
  values.cooldownSec = cooldownSec;

  if (input.enabled !== undefined) {
    if (typeof input.enabled !== 'boolean') return { error: '"enabled" must be a boolean' };
    values.enabled = input.enabled;
  }

  return { values };
}

/** Validates a PUT payload (absent fields keep their current value). */
async function validateRuleUpdate(input: RuleInput, existing: typeof schema.notificationRules.$inferSelect): Promise<{ values: Record<string, unknown> } | { error: string }> {
  const values: Record<string, unknown> = {};

  if (input.name !== undefined) {
    if (typeof input.name !== 'string' || input.name.trim().length === 0) return { error: '"name" must be a non-empty string' };
    if (input.name.trim().length > 200) return { error: '"name" must be at most 200 characters' };
    values.name = input.name.trim();
  }

  if (input.filter !== undefined) {
    const filterRes = validateFilter(input.filter);
    if (!filterRes.ok) return { error: filterRes.error };
    values.filter = JSON.stringify(filterRes.value);
  }

  if (input.channelIds !== undefined) {
    if (!Array.isArray(input.channelIds)) return { error: '"channelIds" must be an array' };
    for (const v of input.channelIds) {
      if (typeof v !== 'string' || !v) return { error: '"channelIds" entries must be non-empty strings' };
    }
    const channelIds = [...new Set(input.channelIds as string[])];
    if (channelIds.length > 0) {
      const existingChannels = await db.query.notificationChannels.findMany({ where: inArray(schema.notificationChannels.id, channelIds) });
      const found = new Set(existingChannels.map((c) => c.id));
      const missing = channelIds.filter((id) => !found.has(id));
      if (missing.length > 0) return { error: `Unknown channel id(s): ${missing.join(', ')}` };
    }
    values.channelIds = JSON.stringify(channelIds);
  }

  if (input.audience !== undefined) {
    const audienceRes = await validateAudience(input.audience);
    if (!audienceRes.ok) return { error: audienceRes.error };
    values.audience = JSON.stringify(audienceRes.value);
  }

  if (input.titleTemplate !== undefined) {
    if (typeof input.titleTemplate !== 'string' || input.titleTemplate.trim().length === 0) return { error: '"titleTemplate" must be a non-empty string' };
    values.titleTemplate = input.titleTemplate;
  }

  if (input.bodyTemplate !== undefined) {
    if (typeof input.bodyTemplate !== 'string') return { error: '"bodyTemplate" must be a string' };
    values.bodyTemplate = input.bodyTemplate;
  }

  if (input.cooldownSec !== undefined && input.cooldownSec !== null) {
    const n = Number(input.cooldownSec);
    if (!Number.isInteger(n) || n < 0) return { error: '"cooldownSec" must be a non-negative integer' };
    values.cooldownSec = n;
  }

  if (input.enabled !== undefined) {
    if (typeof input.enabled !== 'boolean') return { error: '"enabled" must be a boolean' };
    values.enabled = input.enabled;
  }

  return { values };
}

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}

function serializeRule(row: typeof schema.notificationRules.$inferSelect, extra?: { channelNames?: string[] }) {
  return {
    id: row.id,
    name: row.name,
    enabled: row.enabled,
    filter: parseJson<Record<string, unknown>>(row.filter, {}),
    channelIds: parseJson<string[]>(row.channelIds, []),
    audience: parseJson<NotificationRuleAudience>(row.audience ?? '{"type":"all"}', { type: 'all' }),
    titleTemplate: row.titleTemplate,
    bodyTemplate: row.bodyTemplate ?? '',
    cooldownSec: row.cooldownSec ?? 300,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    ...(extra?.channelNames !== undefined ? { channelNames: extra.channelNames } : {}),
  };
}

// GET /notification-rules — all rules with bound channel names.
router.get('/notification-rules', requireAuth, requirePermission('notifications:read'), async (_req: Request, res: Response) => {
  const rows = await db.query.notificationRules.findMany({ orderBy: [desc(schema.notificationRules.createdAt)] });
  if (rows.length === 0) {
    res.status(200).json([]);
    return;
  }
  const allChannelIds = [...new Set(rows.flatMap((r) => parseJson<string[]>(r.channelIds, [])))];
  const channels = allChannelIds.length > 0
    ? await db.query.notificationChannels.findMany({ where: inArray(schema.notificationChannels.id, allChannelIds) })
    : [];
  const channelNameById = new Map(channels.map((c) => [c.id, c.name]));

  res.status(200).json(rows.map((row) => serializeRule(row, {
    channelNames: parseJson<string[]>(row.channelIds, []).map((id) => channelNameById.get(id) ?? id),
  })));
});

// POST /notification-rules — create a rule.
router.post('/notification-rules', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as RuleInput;
  const v = await validateRule(body);
  if ('error' in v) {
    res.status(400).json({ error: v.error });
    return;
  }
  const now = new Date().toISOString();
  const id = uuidv4();
  await db.insert(schema.notificationRules).values({
    id,
    name: String(v.values.name),
    enabled: v.values.enabled === false ? false : true,
    filter: String(v.values.filter),
    channelIds: String(v.values.channelIds),
    audience: String(v.values.audience ?? '{"type":"all"}'),
    titleTemplate: String(v.values.titleTemplate),
    bodyTemplate: String(v.values.bodyTemplate ?? ''),
    cooldownSec: Number(v.values.cooldownSec ?? 300),
    createdAt: now,
    updatedAt: now,
  });
  const row = await db.query.notificationRules.findFirst({ where: eq(schema.notificationRules.id, id) });
  res.status(201).json(serializeRule(row!));
});

// PUT /notification-rules/:id — partial update.
router.put('/notification-rules/:id', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const existing = await db.query.notificationRules.findFirst({ where: eq(schema.notificationRules.id, id) });
  if (!existing) {
    res.status(404).json({ error: 'Rule not found' });
    return;
  }
  const body = (req.body ?? {}) as RuleInput;
  const v = await validateRuleUpdate(body, existing);
  if ('error' in v) {
    res.status(400).json({ error: v.error });
    return;
  }
  await db.update(schema.notificationRules)
    .set({ ...v.values, updatedAt: new Date().toISOString() })
    .where(eq(schema.notificationRules.id, id));
  const row = await db.query.notificationRules.findFirst({ where: eq(schema.notificationRules.id, id) });
  res.status(200).json(serializeRule(row!));
});

// DELETE /notification-rules/:id — remove the rule + its delivery history.
router.delete('/notification-rules/:id', requireAuth, requirePermission('notifications:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const existing = await db.query.notificationRules.findFirst({ where: eq(schema.notificationRules.id, id) });
  if (!existing) {
    res.status(404).json({ error: 'Rule not found' });
    return;
  }
  await db.delete(schema.notificationDeliveries).where(eq(schema.notificationDeliveries.ruleId, id));
  await db.delete(schema.notificationRules).where(eq(schema.notificationRules.id, id));
  res.status(204).send();
});

// GET /notification-deliveries — audit trail (newest first), filterable by
// rule and channel. limit defaults to 100, max 500.
router.get('/notification-deliveries', requireAuth, requirePermission('notifications:read'), async (req: Request, res: Response) => {
  const q = req.query;
  const conditions = [];
  if (typeof q.ruleId === 'string' && q.ruleId) conditions.push(eq(schema.notificationDeliveries.ruleId, q.ruleId));
  if (typeof q.channelId === 'string' && q.channelId) conditions.push(eq(schema.notificationDeliveries.channelId, q.channelId));

  const limitRaw = Number(q.limit);
  const limit = Math.min(Math.max(Number.isFinite(limitRaw) && limitRaw > 0 ? limitRaw : 100, 1), 500);

  const rows = await db.query.notificationDeliveries.findMany({
    where: conditions.length > 0 ? and(...conditions) : undefined,
    orderBy: [desc(schema.notificationDeliveries.sentAt)],
    limit,
  });
  if (rows.length === 0) {
    res.status(200).json([]);
    return;
  }

  const channelIds = [...new Set(rows.map((r) => r.channelId))];
  const ruleIds = [...new Set(rows.map((r) => r.ruleId).filter((v): v is string => !!v))];
  const channels = await db.query.notificationChannels.findMany({ where: inArray(schema.notificationChannels.id, channelIds) });
  const rules = ruleIds.length > 0 ? await db.query.notificationRules.findMany({ where: inArray(schema.notificationRules.id, ruleIds) }) : [];
  const channelById = new Map(channels.map((c) => [c.id, c]));
  const ruleById = new Map(rules.map((r) => [r.id, r]));

  res.status(200).json(rows.map((row) => {
    const channel = channelById.get(row.channelId);
    return {
      id: row.id,
      ruleId: row.ruleId ?? null,
      ruleName: row.ruleId ? (ruleById.get(row.ruleId)?.name ?? null) : null,
      channelId: row.channelId,
      channelName: channel?.name ?? null,
      channelType: channel?.channelType ?? null,
      notificationId: row.notificationId ?? null,
      status: row.status,
      error: row.error ?? null,
      sentAt: row.sentAt,
    };
  }));
});

export default router;
