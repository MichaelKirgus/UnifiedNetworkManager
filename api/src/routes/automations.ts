/**
 * Actions & Schedules — CRUD + test-run + run history for automation rules.
 *
 * All paths are mounted under /v1 (see index.ts) and MUST stay in the OpenAPI
 * spec — the API runs express-openapi-validator with validateRequests, so an
 * unknown path 404s even if this router defines it. Read routes gate on
 * `automations:read`, mutating ones on `automations:write`. The engine itself
 * (trigger evaluation + action execution) lives in workers/automations.ts —
 * these routes only manage rule definitions and inspect their runs.
 */

import { Router, Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { desc, eq } from 'drizzle-orm';
import { requireAuth, requirePermission } from '../auth/middleware';
import { db } from '../db';
import * as schema from '../db/schema';
import { nextScheduleRun, parseJsonField, previewSchedule, validateAutomationDraft } from '../automations/engine';
import { listAutomationTemplates } from '../automations/templates';
import type { ActionBlock, Automation, AutomationDraft, AutomationRun, LogTrigger, ScheduleSpec, TriggerBlock } from '../automations/types';
import { fireRule, manualTriggerRule, scanLogMatches, seedPendingUpdateWindows } from '../workers/automations';

const router = Router();

interface RuleRow {
  id: string;
  name: string;
  description: string | null;
  enabled: boolean;
  triggers: string; // JSON array of trigger blocks
  actions: string; // JSON array of action blocks
  cooldownSec: number;
  lastFiredAt: string | null;
  createdBy: string | null;
  createdAt: string;
  updatedAt: string;
}

/** Serializes a rule row for the API — parsed blocks + computed next runs. */
function serializeRule(row: RuleRow): Automation & { schedulePreviews: Record<string, string | null> } {
  const triggers = parseJsonField<TriggerBlock[]>(row.triggers, []);
  // Next occurrence per schedule trigger (anchor = lastFiredAt ?? createdAt).
  const anchor = row.lastFiredAt ?? row.createdAt;
  const schedulePreviews: Record<string, string | null> = {};
  for (const t of triggers) {
    if (t.type === 'schedule') {
      schedulePreviews[t.id] = nextScheduleRun(t.schedule, anchor)?.toISOString() ?? null;
    }
  }
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    enabled: !!row.enabled,
    triggers,
    actions: parseJsonField<ActionBlock[]>(row.actions, []),
    cooldownSec: Number.isFinite(row.cooldownSec) ? row.cooldownSec : 0,
    lastFiredAt: row.lastFiredAt ?? null,
    createdBy: row.createdBy ?? null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    schedulePreviews,
  };
}

function serializeRun(row: { id: string; automationId: string; firedAt: string; triggerType: string; context: string; status: string; error: string | null; planIds: string }): AutomationRun {
  return {
    id: row.id,
    automationId: row.automationId,
    firedAt: row.firedAt,
    triggerType: row.triggerType as AutomationRun['triggerType'],
    context: parseJsonField(row.context, {}),
    status: row.status as AutomationRun['status'],
    error: row.error ?? null,
    planIds: parseJsonField<string[]>(row.planIds, []),
  };
}

/** Loads one rule or null. */
async function loadRule(id: string): Promise<RuleRow | null> {
  const rows = await db.select().from(schema.automations).where(eq(schema.automations.id, id));
  return (rows[0] as unknown as RuleRow) ?? null;
}

/** Builds an in-memory Automation view of a validated draft — for post-save engine hooks (window seeding). */
function automationFromDraft(draft: AutomationDraft, id: string): Automation {
  return {
    id,
    name: draft.name.trim(),
    description: typeof draft.description === 'string' && draft.description.trim() ? draft.description.trim() : null,
    enabled: draft.enabled !== false,
    triggers: draft.triggers,
    actions: draft.actions,
    cooldownSec: Number.isInteger(draft.cooldownSec) && (draft.cooldownSec ?? 0) >= 0 ? (draft.cooldownSec as number) : 0,
    lastFiredAt: null,
    createdBy: null,
    createdAt: '',
    updatedAt: '',
  };
}

// GET /automations — list all rules with computed next-run previews.
router.get('/automations', requireAuth, requirePermission('automations:read'), async (_req: Request, res: Response) => {
  const rows = await db.select().from(schema.automations).orderBy(desc(schema.automations.createdAt));
  res.status(200).json({ automations: (rows as unknown as RuleRow[]).map(serializeRule) });
});

// GET /automations/templates — the template catalog (built-ins + plugin-
// advertised). Registered BEFORE /automations/:id so the static segment wins.
// Picking a template creates nothing — it only pre-fills the rule builder;
// saving goes through POST /automations as usual.
router.get('/automations/templates', requireAuth, requirePermission('automations:read'), async (_req: Request, res: Response) => {
  const templates = await listAutomationTemplates();
  res.status(200).json({ templates });
});

// GET /automations/preview-schedule — upcoming occurrences of a schedule spec
// (the builder's "next runs" hint). Registered BEFORE /automations/:id so the
// static segment wins.
router.get('/automations/preview-schedule', requireAuth, requirePermission('automations:read'), async (req: Request, res: Response) => {
  const expr = typeof req.query.expr === 'string' ? req.query.expr : '';
  const kindRaw = typeof req.query.kind === 'string' ? req.query.kind : 'cron';
  const count = Math.max(1, Math.min(Number(req.query.count ?? 5), 20));

  let spec: ScheduleSpec | null = null;
  if (kindRaw === 'cron') {
    if (!expr) { res.status(400).json({ error: 'expr is required for kind=cron' }); return; }
    spec = { kind: 'cron', expr };
  } else if (kindRaw === 'interval') {
    const everyMinutes = Number(expr);
    if (!Number.isInteger(everyMinutes) || everyMinutes < 1) { res.status(400).json({ error: 'expr must be an integer ≥ 1 for kind=interval' }); return; }
    spec = { kind: 'interval', everyMinutes };
  } else if (kindRaw === 'dailyAt') {
    if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(expr)) { res.status(400).json({ error: 'expr must be "HH:MM" for kind=dailyAt' }); return; }
    spec = { kind: 'dailyAt', time: expr };
  } else {
    res.status(400).json({ error: 'kind must be cron, interval or dailyAt' });
    return;
  }

  const runs = previewSchedule(spec, count);
  if (runs.length === 0) { res.status(400).json({ error: 'Invalid schedule — no upcoming occurrences could be computed' }); return; }
  res.status(200).json({ runs });
});

// POST /automations — create a rule. Body = AutomationDraft (validated).
router.post('/automations', requireAuth, requirePermission('automations:write'), async (req: Request, res: Response) => {
  const draft = (req.body ?? {}) as AutomationDraft;
  const errors = validateAutomationDraft(draft);
  if (errors.length > 0) {
    res.status(400).json({ error: 'Invalid automation', details: errors });
    return;
  }

  const now = new Date().toISOString();
  const id = uuidv4();
  await db.insert(schema.automations).values({
    id,
    name: draft.name.trim(),
    description: typeof draft.description === 'string' && draft.description.trim() ? draft.description.trim() : null,
    enabled: draft.enabled !== false,
    triggers: JSON.stringify(draft.triggers),
    actions: JSON.stringify(draft.actions),
    cooldownSec: Number.isInteger(draft.cooldownSec) && (draft.cooldownSec ?? 0) >= 0 ? (draft.cooldownSec as number) : 0,
    lastFiredAt: null,
    createdBy: req.user?.sub ?? null,
    createdAt: now,
    updatedAt: now,
  });

  // Seed deferral windows for updates that are already available — without this a
  // new rule would never pick up rows that predate it (no transition fires for them).
  // Awaited so the response is deterministic (an immediate manual trigger or state
  // read right after create sees the seeded windows; seeding is idempotent + cheap).
  if (draft.enabled !== false) await seedPendingUpdateWindows(automationFromDraft(draft, id));

  const row = await loadRule(id);
  res.status(201).json({ automation: serializeRule(row!) });
});

// PATCH /automations/:id — update a rule (full draft; partial fields keep current values).
router.patch('/automations/:id', requireAuth, requirePermission('automations:write'), async (req: Request, res: Response) => {
  const existing = await loadRule(String(req.params.id ?? ''));
  if (!existing) { res.status(404).json({ error: 'Automation not found' }); return; }

  const body = (req.body ?? {}) as Partial<AutomationDraft>;
  // Merge over the current values so partial updates work.
  const draft: AutomationDraft = {
    name: typeof body.name === 'string' ? body.name : existing.name,
    description: body.description !== undefined ? body.description : existing.description,
    enabled: body.enabled !== undefined ? body.enabled : !!existing.enabled,
    triggers: Array.isArray(body.triggers) ? body.triggers : parseJsonField<TriggerBlock[]>(existing.triggers, []),
    actions: Array.isArray(body.actions) ? body.actions : parseJsonField<ActionBlock[]>(existing.actions, []),
    cooldownSec: body.cooldownSec !== undefined ? body.cooldownSec : existing.cooldownSec,
  };

  const errors = validateAutomationDraft(draft);
  if (errors.length > 0) {
    res.status(400).json({ error: 'Invalid automation', details: errors });
    return;
  }

  await db.update(schema.automations)
    .set({
      name: draft.name.trim(),
      description: typeof draft.description === 'string' && draft.description.trim() ? draft.description.trim() : null,
      enabled: draft.enabled !== false,
      triggers: JSON.stringify(draft.triggers),
      actions: JSON.stringify(draft.actions),
      cooldownSec: Number.isInteger(draft.cooldownSec) && (draft.cooldownSec ?? 0) >= 0 ? (draft.cooldownSec as number) : 0,
      updatedAt: new Date().toISOString(),
    })
    .where(eq(schema.automations.id, existing.id));

  // Re-enabling (or editing) an enabled rule with deferred update triggers → make
  // sure currently-available rows have a window. Idempotent — open windows keep
  // their original anchor; only missing ones are seeded.
  if (draft.enabled !== false) await seedPendingUpdateWindows(automationFromDraft(draft, existing.id));

  const row = await loadRule(existing.id);
  res.status(200).json({ automation: serializeRule(row!) });
});

// DELETE /automations/:id — remove the rule (its run history is kept for audit).
router.delete('/automations/:id', requireAuth, requirePermission('automations:write'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  const rows = await db.select({ id: schema.automations.id }).from(schema.automations).where(eq(schema.automations.id, id));
  if (rows.length === 0) { res.status(404).json({ error: 'Automation not found' }); return; }
  await db.delete(schema.automations).where(eq(schema.automations.id, id));
  res.status(200).json({ deleted: true });
});

// POST /automations/:id/test — manually trigger the rule right now. Optional body:
//   { "mode": "apply" } → run for real: updateAvailable triggers resolve the
//     CURRENTLY available device_updates rows and fire once per row (defer
//     schedules are bypassed). This is what `resolveFromTrigger: "update"` actions
//     need — a bare test context has no update row to resolve against.
//   { "mode": "test" } or omitted → legacy wiring check: the first trigger block
//     fires once with a bare context (no live rows resolved).
router.post('/automations/:id/test', requireAuth, requirePermission('automations:write'), async (req: Request, res: Response) => {
  const existing = await loadRule(String(req.params.id ?? ''));
  if (!existing) { res.status(404).json({ error: 'Automation not found' }); return; }

  const triggers = parseJsonField<TriggerBlock[]>(existing.triggers, []);
  const actions = parseJsonField<ActionBlock[]>(existing.actions, []);
  if (triggers.length === 0 || actions.length === 0) {
    res.status(400).json({ error: 'Rule has no triggers or actions to test' });
    return;
  }

  const modeRaw = typeof req.body?.mode === 'string' ? req.body.mode : '';
  if (modeRaw !== '' && modeRaw !== 'test' && modeRaw !== 'apply') {
    res.status(400).json({ error: "mode must be 'test' or 'apply'" });
    return;
  }

  const rule: Automation = serializeRule(existing);
  try {
    if (modeRaw === 'apply') {
      await manualTriggerRule(rule);
    } else {
      await fireRule(rule, triggers[0], { kind: 'test', triggerType: triggers[0].type }, { trigger: triggers[0] });
    }
  } catch (err) {
    res.status(500).json({ error: `Test run failed: ${(err as Error).message}` });
    return;
  }

  // Return the run rows just written — apply mode with an updateAvailable trigger
  // writes one per live row, so list them (newest first) alongside the newest.
  const runs = await db.select().from(schema.automationRuns)
    .where(eq(schema.automationRuns.automationId, existing.id))
    .orderBy(desc(schema.automationRuns.firedAt))
    .limit(20);
  res.status(200).json({ run: serializeRun(runs[0]), runs: runs.map(serializeRun) });
});

// GET /automations/:id/runs — run history for one rule (newest first, capped).
router.get('/automations/:id/runs', requireAuth, requirePermission('automations:read'), async (req: Request, res: Response) => {
  const id = String(req.params.id ?? '');
  if (!(await loadRule(id))) { res.status(404).json({ error: 'Automation not found' }); return; }

  const limit = Math.max(1, Math.min(Number(req.query.limit ?? 50), 200));
  const rows = await db.select().from(schema.automationRuns)
    .where(eq(schema.automationRuns.automationId, id))
    .orderBy(desc(schema.automationRuns.firedAt))
    .limit(limit);
  res.status(200).json({ runs: rows.map(serializeRun) });
});

// POST /automations/test-pattern — dry-run a log trigger's pattern against the
// recent log history (no watermark, no firing, no state written). Lets the
// builder verify a regex before saving. Body = { source, pluginId?, levels?,
// pattern } — same fields as a LogTrigger block minus id/type/scope.
router.post('/automations/test-pattern', requireAuth, requirePermission('automations:read'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Partial<LogTrigger>;
  if (body.source !== 'plugin' && body.source !== 'firewall') {
    res.status(400).json({ error: "source must be 'plugin' or 'firewall'" });
    return;
  }
  if (!body.pattern || typeof body.pattern !== 'string') {
    res.status(400).json({ error: 'pattern is required' });
    return;
  }
  try {
    // eslint-disable-next-line no-new
    new RegExp(body.pattern);
  } catch (err) {
    res.status(400).json({ error: `Invalid regex: ${(err as Error).message}` });
    return;
  }

  const trigger: LogTrigger = {
    id: 'test',
    type: 'log',
    source: body.source,
    pluginId: typeof body.pluginId === 'string' && body.pluginId ? body.pluginId : undefined,
    levels: Array.isArray(body.levels) ? body.levels : undefined,
    pattern: body.pattern,
  };

  try {
    const { matches } = await scanLogMatches(trigger, null); // null watermark = most-recent window only
    res.status(200).json({ count: matches.length, matches: matches.slice(0, 50) });
  } catch (err) {
    res.status(500).json({ error: `Pattern scan failed: ${(err as Error).message}` });
  }
});

export default router;
