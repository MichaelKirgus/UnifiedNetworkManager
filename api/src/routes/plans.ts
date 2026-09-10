import { Router, Request, Response } from 'express';
import { and, asc, desc, eq, gte, inArray, like, ne } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission, require2FA } from '../auth/middleware';
import { allowedDeviceIds } from '../deviceAccess';
import { getSecret, generateSecret, regenerateSecret, deleteSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { planQueue } from '../queue';
import type { CatalogEntry as SdkCatalogEntry } from '@unm/plugin-sdk';
import { validateInput, type InputSchema } from '../utils/inputSchema';

const router = Router();

/**
 * Execution plans — the API-side consumer of a plugin's /plan endpoint.
 *
 * A plan is created by asking the plugin to plan an intent across selected
 * devices (POST /plans), which returns ordered steps + provisionRequests. The
 * API fulfils every provisionRequest via the secrets provider at creation time
 * (the ref→secretId map is persisted on the plan row) and persists each step.
 * Execution (POST /plans/:id/execute) enqueues the plan; workers/planExecutor
 * walks the steps in dependency order, merges per-step credentials, resolves
 * ${steps[N].result.details.*} tokens from prior results, and dispatches each
 * step to the plugin's /config endpoint.
 */

// --- Types ------------------------------------------------------------------

interface PlanRow {
  id: string;
  pluginId: string;
  intentActionId: string;
  intentInputs: string | null;
  status: string;
  provisionedSecrets: string | null;
  error: string | null;
  createdBy: string;
  executedBy: string | null;
  cancelledAt: string | null;
  createdAt: string;
  updatedAt: string;
  startedAt: string | null;
  finishedAt: string | null;
  recentlyFinishedAt: string | null;
  retriedFrom: string | null;
}

/**
 * Resolves user ids to display names for a batch of plan rows (createdBy +
 * executedBy). One query per list call; unknown ids (deleted users) fall back
 * to the raw id so the column never renders empty.
 */
async function resolveUsernames(rows: PlanRow[]): Promise<Map<string, string>> {
  const ids = new Set<string>();
  for (const r of rows) {
    if (r.createdBy) ids.add(r.createdBy);
    if (r.executedBy) ids.add(r.executedBy);
  }
  const map = new Map<string, string>();
  if (ids.size > 0) {
    const users = await db.query.users.findMany({ where: (u, { inArray }) => inArray(u.id, [...ids]) });
    for (const u of users) map.set(u.id, u.username);
  }
  return map;
}

/** Secret metadata shape as exposed on plan responses (never material). */
type PlanSecretMeta = { ref: string; secretId: string; label?: string | null; type?: string };

/**
 * Batch-resolves provisioned-secret metadata for many plan rows in ONE query
 * (label/type only — never material). Returns a map of planId → ordered meta.
 */
async function resolveSecretsMetadata(rows: PlanRow[]): Promise<Map<string, PlanSecretMeta[]>> {
  const byPlan = new Map<string, PlanSecretMeta[]>();
  const ids = new Set<string>();
  for (const r of rows) {
    const map = parseJson<Record<string, string>>(r.provisionedSecrets ?? '{}', {});
    for (const secretId of Object.values(map)) ids.add(secretId);
  }
  const meta = new Map<string, { label: string | null; type?: string }>();
  if (ids.size > 0) {
    const srows = await db.query.secrets.findMany({ where: (s, { inArray }) => inArray(s.id, [...ids]) });
    for (const s of srows) meta.set(s.id, { label: s.label ?? null, type: s.type });
  }
  for (const r of rows) {
    const map = parseJson<Record<string, string>>(r.provisionedSecrets ?? '{}', {});
    byPlan.set(
      r.id,
      Object.entries(map).map(([ref, secretId]) => ({ ref, secretId, label: meta.get(secretId)?.label ?? null, type: meta.get(secretId)?.type }))
    );
  }
  return byPlan;
}

interface StepRow {
  id: string;
  planId: string;
  stepIndex: number;
  deviceId: string;
  actionId: string;
  input: string | null;
  dependsOn: string | null;
  secretRefs: string | null;
  bestEffort: boolean;
  status: string;
  result: string | null;
  startedAt: string | null;
  finishedAt: string | null;
}

/**
 * The persisted catalog entry as stored on the plugin row. Looser than the
 * SDK's wire type: rows written before a field existed (or by older plugins)
 * may lack label/module/riskLevel/etc., so every field except `id` is optional.
 */
type CatalogEntry = Omit<SdkCatalogEntry, 'label' | 'module' | 'riskLevel' | 'deviceCount' | 'inputSchema'> & {
  label?: string;
  description?: string;
  module?: string;
  riskLevel?: string;
  deviceCount?: number | 'N';
  beOnly?: boolean;
  timeoutMs?: number;
  inputSchema?: InputSchema;
};

const EDITABLE_STATUSES = ['draft', 'ready'];

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function serializeStep(row: StepRow) {
  return {
    id: row.id,
    planId: row.planId,
    stepIndex: row.stepIndex,
    deviceId: row.deviceId,
    actionId: row.actionId,
    input: parseJson<Record<string, unknown>>(row.input, {}),
    dependsOn: parseJson<number[]>(row.dependsOn, []),
    secretRefs: parseJson<string[]>(row.secretRefs, []),
    bestEffort: !!row.bestEffort,
    status: row.status,
    result: row.result ? (parseJson<Record<string, unknown>>(row.result, {}) as Record<string, unknown>) : null,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
  };
}

async function loadPlan(planId: string): Promise<PlanRow | null> {
  return (await db.query.plans.findFirst({
    where: (plans, { eq }) => eq(plans.id, planId),
  })) as PlanRow | null;
}

async function loadSteps(planId: string): Promise<StepRow[]> {
  const rows = await db.query.planSteps.findMany({
    where: (steps, { eq }) => eq(steps.planId, planId),
    orderBy: [asc(schema.planSteps.stepIndex)],
  });
  return rows as StepRow[];
}

/**
 * Serializes one plan row; `usernames` (from resolveUsernames) maps ids →
 * display names. NOTE: does NOT include `provisionedSecrets` — callers must
 * add the resolved metadata array (resolveSecretsMetadata), never the raw map.
 */
function serializePlanRow(row: PlanRow, usernames: Map<string, string>): Record<string, unknown> & { id: string; pluginId: string } {
  return {
    id: row.id,
    pluginId: row.pluginId,
    intentActionId: row.intentActionId,
    // The raw intent inputs — the payload of every execution (re-runs and
    // retries carry the same values, so this is always what will be applied).
    intentInputs: parseJson<Record<string, unknown>>(row.intentInputs ?? '{}', {}),
    status: row.status,
    error: row.error,
    createdBy: row.createdBy,
    createdByName: usernames.get(row.createdBy) ?? row.createdBy,
    executedBy: row.executedBy,
    executedByName: row.executedBy ? (usernames.get(row.executedBy) ?? row.executedBy) : null,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    startedAt: row.startedAt,
    finishedAt: row.finishedAt,
    recentlyFinishedAt: row.recentlyFinishedAt,
    retriedFrom: row.retriedFrom,
  };
}

async function serializePlan(planId: string, withSteps = false) {
  const row = await loadPlan(planId);
  if (!row) return null;
  const usernames = await resolveUsernames([row]);
  const secretsMeta = await resolveSecretsMetadata([row]);
  const out = serializePlanRow(row, usernames);
  // Secret metadata (label/type only — never material).
  out.provisionedSecrets = secretsMeta.get(row.id) ?? [];
  if (withSteps) {
    const steps = await loadSteps(planId);
    out.steps = steps.map(serializeStep);
  }
  return out;
}

/** Loads the plugin's persisted action catalog (empty when never discovered). */
async function loadCatalog(pluginId: string): Promise<CatalogEntry[]> {
  const row = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, pluginId),
  });
  if (!row?.actionDescriptors) return [];
  const parsed = parseJson<unknown>(row.actionDescriptors, []);
  return Array.isArray(parsed) ? (parsed as CatalogEntry[]) : [];
}

/** Resolves the assignment of `pluginId` on a device (explicit or primary). */
async function resolveAssignment(deviceId: string, pluginId: string) {
  const rows = await db.query.devicePlugins.findMany({
    where: (rows2) => eq(rows2.deviceId, deviceId),
    orderBy: [asc(schema.devicePlugins.createdAt)],
  });
  return rows.find((a) => a.pluginId === pluginId && a.isPrimary) ?? rows.find((a) => a.pluginId === pluginId) ?? null;
}

/** DFS cycle check over a stepIndex → dependsOn(stepIndex[]) graph. */
function hasCycle(depsOf: Map<number, number[]>): boolean {
  const visiting = new Set<number>();
  const done = new Set<number>();
  const visit = (node: number): boolean => {
    if (done.has(node)) return false;
    if (visiting.has(node)) return true; // cycle
    visiting.add(node);
    for (const dep of depsOf.get(node) ?? []) {
      if (visit(dep)) return true;
    }
    visiting.delete(node);
    done.add(node);
    return false;
  };
  for (const node of depsOf.keys()) {
    if (visit(node)) return true;
  }
  return false;
}

/**
 * Re-indexes steps after an add/remove/reorder and remaps every dependsOn
 * array through the old→new index map. Throws on cycles (with `.status` 400).
 */
async function reindexSteps(planId: string, orderedIds: string[]): Promise<void> {
  const steps = await loadSteps(planId);
  const byId = new Map(steps.map((s) => [s.id, s]));
  const oldToNew = new Map<number, number>();
  orderedIds.forEach((id, i) => {
    const row = byId.get(id);
    if (row) oldToNew.set(row.stepIndex, i);
  });

  // Build the remapped graph and check for cycles before writing anything.
  const depsOf = new Map<number, number[]>();
  orderedIds.forEach((id, i) => {
    const row = byId.get(id)!;
    const oldDeps = parseJson<number[]>(row.dependsOn, []);
    depsOf.set(i, oldDeps.map((d) => oldToNew.get(d)).filter((n): n is number => typeof n === 'number'));
  });

  if (hasCycle(depsOf)) {
    throw Object.assign(new Error('Dependency cycle detected in plan steps'), { status: 400 });
  }

  for (let i = 0; i < orderedIds.length; i++) {
    const id = orderedIds[i];
    await db.update(schema.planSteps)
      .set({ stepIndex: i, dependsOn: JSON.stringify(depsOf.get(i) ?? []) })
      .where(eq(schema.planSteps.id, id));
  }
}

// --- Device-level access control --------------------------------------------

/**
 * A plan is visible to a caller only when EVERY device referenced by its steps
 * lies within their scope — list and detail stay consistent, and no mutation
 * can ever touch an out-of-scope device. Unrestricted callers (devices:all or
 * no scope rules) always pass; step-less plans have nothing to touch.
 */
async function planVisibleTo(req: Request, planId: string): Promise<boolean> {
  const allowed = await allowedDeviceIds(req);
  if (allowed === null) return true;
  for (const step of await loadSteps(planId)) {
    if (!allowed.has(step.deviceId)) return false;
  }
  return true;
}

/** Responds 404 "Plan not found" when the plan is outside the caller's device scope. */
async function assertPlanAccess(req: Request, res: Response, planId: string): Promise<boolean> {
  if (await planVisibleTo(req, planId)) return true;
  res.status(404).json({ error: 'Plan not found' });
  return false;
}

// --- Routes -----------------------------------------------------------------

// POST /plans — plan an intent across devices via the plugin's /plan endpoint,
// fulfil its provisionRequests (secrets are created NOW), persist everything.
router.post(
  '/plans',
  requireAuth,
  require2FA,
  requirePermission('configs:apply'),
  async (req, res) => {
    const body = req.body ?? {};
    const pluginId = typeof body.pluginId === 'string' ? body.pluginId : '';
    const intentActionId = typeof body.intentActionId === 'string' ? body.intentActionId : '';
    const inputs = isPlainObject(body.inputs) ? (body.inputs as Record<string, unknown>) : {};
    const devicesRaw = Array.isArray(body.devices) ? body.devices : [];

    if (!pluginId || !intentActionId) {
      res.status(400).json({ error: 'pluginId and intentActionId are required' });
      return;
    }
    if (devicesRaw.length === 0) {
      res.status(400).json({ error: 'At least one device is required' });
      return;
    }

    const plugin = await db.query.plugins.findFirst({
      where: (plugins, { eq }) => eq(plugins.id, pluginId),
    });
    if (!plugin) {
      res.status(404).json({ error: 'Plugin not found' });
      return;
    }

    const catalog = await loadCatalog(pluginId);
    const intent = catalog.find((c) => c.id === intentActionId);
    if (intent && typeof intent.deviceCount === 'number') {
      // Multi-device intents name an exact device count (e.g. 2 for tunnels).
      if (devicesRaw.length !== intent.deviceCount) {
        res.status(400).json({
          error: `Intent ${intentActionId} requires exactly ${intent.deviceCount} devices, got ${devicesRaw.length}`,
        });
        return;
      }
    }

    // Resolve each device's assignment + credentials for THIS plugin.
    const planDevices: Array<{ deviceId: string; managementAddress: string; credentials: Record<string, unknown> }> = [];
    for (const d of devicesRaw) {
      if (!d || typeof d.deviceId !== 'string') {
        res.status(400).json({ error: 'Each device entry must be { deviceId }' });
        return;
      }
      const device = await db.query.devices.findFirst({
        where: (devices, { eq }) => eq(devices.id, d.deviceId),
      });
      if (!device) {
        res.status(404).json({ error: `Device not found: ${d.deviceId}` });
        return;
      }
      // Device-level access control — a plan may only be created for the
      // caller's own devices (out-of-scope ids are indistinguishable from unknown).
      const allowed = await allowedDeviceIds(req);
      if (allowed !== null && !allowed.has(device.id)) {
        res.status(404).json({ error: `Device not found: ${d.deviceId}` });
        return;
      }
      const assignment = await resolveAssignment(device.id, pluginId);
      if (!assignment) {
        res.status(400).json({ error: `Plugin is not assigned to device "${device.name}"` });
        return;
      }
      let credentials: Record<string, unknown> = {};
      if (assignment.secretId) {
        try {
          const decrypted = await getSecret(assignment.secretId);
          credentials = { ...decrypted.fields };
        } catch (err) {
          res.status(502).json({ error: `Could not load device credentials: ${(err as Error).message}` });
          return;
        }
      } else if (intent && intent.deviceCount !== 1) {
        // Multi-device intents always need appliance credentials.
        res.status(400).json({
          error: `Device "${device.name}" has no secret assigned for this plugin — multi-device intents require credentials`,
        });
        return;
      }
      planDevices.push({ deviceId: device.id, managementAddress: device.managementAddress, credentials });
    }

    // Ask the plugin to build the plan. Settings (transport/edition/backend)
    // ride in x-unm-settings exactly like /config calls do.
    const headers = await settingsHeaders(pluginId, planDevices[0].deviceId).catch(() => ({}));
    let plan: {
      id: string;
      createdAt: string;
      intentActionId: string;
      provisionRequests: Array<{ ref: string; type: string; fields?: Record<string, unknown>; label?: string }>;
      steps: Array<{
        stepIndex: number;
        deviceId: string;
        actionId: string;
        input: Record<string, unknown>;
        dependsOn?: number[];
        secretRefs?: string[];
        bestEffort?: boolean;
      }>;
    };
    try {
      const response = await axios.post(
        `${plugin.endpoint.replace(/\/$/, '')}/plan`,
        { intent: { actionId: intentActionId, inputs }, devices: planDevices },
        { timeout: 20_000, headers }
      );
      plan = response.data?.plan;
      if (!plan || !Array.isArray(plan.steps)) throw new Error('Plugin did not return a valid plan');
    } catch (err) {
      const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
      if (e.response?.status === 400) {
        res.status(400).json({ error: e.response.data?.error ?? 'Planning failed' });
        return;
      }
      res.status(502).json({ error: `Plugin planning failed: ${e.message ?? 'unreachable'}` });
      return;
    }

    // Fulfil provisionRequests NOW (user decision: provisioning at creation).
    const userId = req.user?.sub ?? '';
    const provisionedSecrets: Record<string, string> = {};
    try {
      for (const pr of plan.provisionRequests ?? []) {
        if (!pr || typeof pr.ref !== 'string' || typeof pr.type !== 'string') continue;
        const created = await generateSecret({
          type: pr.type,
          fields: pr.fields,
          label: pr.label ?? `Plan ${plan.id.slice(0, 8)} — ${pr.ref}`,
          userId,
        });
        provisionedSecrets[pr.ref] = created.id;
      }
    } catch (err) {
      // Roll back anything we already created for this plan.
      for (const secretId of Object.values(provisionedSecrets)) {
        await deleteSecret(secretId).catch(() => undefined);
      }
      res.status(502).json({ error: `Provisioning failed: ${(err as Error).message}` });
      return;
    }

    const now = new Date().toISOString();
    const planRowId = uuidv4();
    await db.insert(schema.plans).values({
      id: planRowId,
      pluginId,
      intentActionId,
      // Persist the raw intent inputs so every execution of this plan (and any
      // retry that duplicates it) is fully transparent about what was applied.
      intentInputs: JSON.stringify(inputs),
      status: 'ready',
      provisionedSecrets: JSON.stringify(provisionedSecrets),
      error: null,
      createdBy: userId,
      executedBy: null,
      cancelledAt: null,
      createdAt: now,
      updatedAt: now,
      startedAt: null,
      finishedAt: null,
    });
    for (const step of plan.steps) {
      await db.insert(schema.planSteps).values({
        id: uuidv4(),
        planId: planRowId,
        stepIndex: step.stepIndex,
        deviceId: step.deviceId,
        actionId: step.actionId,
        input: JSON.stringify(step.input ?? {}),
        dependsOn: JSON.stringify(step.dependsOn ?? []),
        secretRefs: JSON.stringify(step.secretRefs ?? []),
        bestEffort: !!step.bestEffort,
        status: 'pending',
        result: null,
        startedAt: null,
        finishedAt: null,
      });
    }

    res.status(201).json(await serializePlan(planRowId, true));
  }
);

// GET /plans/activity — compact feed for the top-bar plans icon. Returns
// every executing + queued (ready/draft) plan plus recently-finished ones
// (terminal status within `windowMs`, default 5 min), newest activity first,
// with step progress.
router.get('/plans/activity', requireAuth, requirePermission('plans:read'), async (req, res) => {
  const windowMs = Math.min(Math.max(Number(req.query.windowMs ?? 300_000), 10_000), 3_600_000);
  const cutoff = new Date(Date.now() - windowMs).toISOString();
  const rows = await db.query.plans.findMany({
    where: (plans, { or }) =>
      or(
        eq(plans.status, 'executing'),
        eq(plans.status, 'ready'),
        eq(plans.status, 'draft'),
        gte(plans.recentlyFinishedAt, cutoff),
      ),
    orderBy: [desc(schema.plans.updatedAt)],
    limit: 50,
  });
  // Device-level access control — a plan is only listed when every device its
  // steps reference is within the caller's scope.
  const visibleRows = (await Promise.all(
    (rows as PlanRow[]).map(async (row) => ((await planVisibleTo(req, row.id)) ? row : null))
  )).filter((r): r is PlanRow => r !== null);
  if (visibleRows.length === 0) {
    res.status(200).json([]);
    return;
  }
  const planRows = visibleRows;
  const usernames = await resolveUsernames(planRows);
  const secretsMeta = await resolveSecretsMetadata(planRows);
  const out: unknown[] = [];
  for (const row of planRows) {
    const steps = await loadSteps(row.id);
    const done = steps.filter((s) => s.status === 'succeeded').length;
    out.push({ ...serializePlanRow(row, usernames), provisionedSecrets: secretsMeta.get(row.id) ?? [], stepCount: steps.length, stepsDone: done });
  }
  res.status(200).json(out);
});

// GET /plans — most recent plans (no steps; use the detail route for those).
router.get('/plans', requireAuth, requirePermission('plans:read'), async (_req, res) => {
  const rows = await db.query.plans.findMany({
    orderBy: [desc(schema.plans.createdAt)],
    limit: 100,
  });
  // Device-level access control — same visibility rule as /plans/activity.
  const visibleRows = (await Promise.all(
    (rows as PlanRow[]).map(async (row) => ((await planVisibleTo(_req, row.id)) ? row : null))
  )).filter((r): r is PlanRow => r !== null);
  if (visibleRows.length === 0) {
    res.status(200).json([]);
    return;
  }
  const planRows = visibleRows;
  const usernames = await resolveUsernames(planRows);
  const secretsMeta = await resolveSecretsMetadata(planRows);
  const out: unknown[] = [];
  for (const row of planRows) {
    const steps = await loadSteps(row.id);
    const done = steps.filter((s) => s.status === 'succeeded').length;
    out.push({ ...serializePlanRow(row, usernames), provisionedSecrets: secretsMeta.get(row.id) ?? [], stepCount: steps.length, stepsDone: done });
  }
  res.status(200).json(out);
});

// GET /plans/:id — full plan with ordered steps + provisioned secret metadata.
router.get('/plans/:id', requireAuth, requirePermission('plans:read'), async (req, res) => {
  if (!(await assertPlanAccess(req, res, req.params.id))) return;
  const out = await serializePlan(req.params.id, true);
  if (!out) {
    res.status(404).json({ error: 'Plan not found' });
    return;
  }
  res.status(200).json(out);
});

// PATCH /plans/:id/steps/:stepId — edit a step (draft/ready plans only).
router.patch(
  '/plans/:id/steps/:stepId',
  requireAuth,
  requirePermission('configs:apply'),
  async (req, res) => {
    if (!(await assertPlanAccess(req, res, req.params.id))) return;
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be edited` });
      return;
    }
    const steps = await loadSteps(plan.id);
    const step = steps.find((s) => s.id === req.params.stepId);
    if (!step) {
      res.status(404).json({ error: 'Step not found' });
      return;
    }

    const body = req.body ?? {};
    const updates: Record<string, unknown> = {};

    if (typeof body.actionId === 'string') {
      const catalog = await loadCatalog(plan.pluginId);
      const entry = catalog.find((c) => c.id === body.actionId);
      if (!entry || entry.deviceCount !== 1) {
        res.status(400).json({ error: `Unknown single-device action: ${body.actionId}` });
        return;
      }
      updates.actionId = body.actionId;
    }
    if (isPlainObject(body.input)) {
      const catalog = await loadCatalog(plan.pluginId);
      const targetActionId = typeof updates.actionId === 'string' ? updates.actionId : step.actionId;
      const entry = catalog.find((c) => c.id === targetActionId);
      if (entry?.inputSchema) {
        const issues = validateInput(entry.inputSchema, body.input as Record<string, unknown>);
        if (issues.length > 0) {
          res.status(400).json({ error: 'Invalid step input', fieldErrors: Object.fromEntries(issues.map((i) => [i.path, i.message])) });
          return;
        }
      }
      updates.input = JSON.stringify(body.input);
    }
    if (body.secretRefs !== undefined) {
      const refs: unknown[] = Array.isArray(body.secretRefs) ? body.secretRefs : [];
      if (!refs.every((r) => typeof r === 'string')) {
        res.status(400).json({ error: 'secretRefs must be an array of strings' });
        return;
      }
      const provisioned = parseJson<Record<string, string>>(plan.provisionedSecrets, {});
      for (const r of refs) {
        if (!(r in provisioned)) {
          res.status(400).json({ error: `Unknown secretRef "${r}" — not a provisioned secret on this plan` });
          return;
        }
      }
      updates.secretRefs = JSON.stringify(refs);
    }
    if (body.dependsOn !== undefined) {
      const deps: unknown[] = Array.isArray(body.dependsOn) ? body.dependsOn : [];
      if (!deps.every((d) => Number.isInteger(d))) {
        res.status(400).json({ error: 'dependsOn must be an array of step indices' });
        return;
      }
      const intDeps = deps as number[];
      for (const d of intDeps) {
        if (!steps.some((s) => s.stepIndex === d)) {
          res.status(400).json({ error: `dependsOn references unknown step index ${d}` });
          return;
        }
      }
      // Cycle check over the graph with this step's deps replaced.
      const depsOf = new Map<number, number[]>();
      for (const s of steps) {
        depsOf.set(s.stepIndex, s.id === step.id ? intDeps : parseJson<number[]>(s.dependsOn, []));
      }
      if (hasCycle(depsOf)) {
        res.status(400).json({ error: 'Dependency cycle detected in plan steps' });
        return;
      }
      updates.dependsOn = JSON.stringify(intDeps);
    }
    if (body.bestEffort !== undefined) {
      if (typeof body.bestEffort !== 'boolean') {
        res.status(400).json({ error: 'bestEffort must be a boolean' });
        return;
      }
      updates.bestEffort = body.bestEffort;
    }

    await db.update(schema.planSteps)
      .set(updates as never)
      .where(eq(schema.planSteps.id, step.id));
    res.status(200).json((await serializePlan(plan.id, true))!);
  }
);

// POST /plans/:id/steps — append a new single-device step (draft/ready only).
router.post(
  '/plans/:id/steps',
  requireAuth,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be edited` });
      return;
    }

    const body = req.body ?? {};
    // Device-level access control — a new step may only target the caller's devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && !allowed.has(typeof body.deviceId === 'string' ? body.deviceId : '')) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }

    const deviceId = typeof body.deviceId === 'string' ? body.deviceId : '';
    const actionId = typeof body.actionId === 'string' ? body.actionId : '';
    if (!deviceId || !actionId) {
      res.status(400).json({ error: 'deviceId and actionId are required' });
      return;
    }
    const device = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.id, deviceId) });
    if (!device) {
      res.status(404).json({ error: 'Device not found' });
      return;
    }
    const assignment = await resolveAssignment(deviceId, plan.pluginId);
    if (!assignment) {
      res.status(400).json({ error: `Plugin is not assigned to device "${device.name}"` });
      return;
    }
    const catalog = await loadCatalog(plan.pluginId);
    const entry = catalog.find((c) => c.id === actionId);
    if (!entry || entry.deviceCount !== 1) {
      res.status(400).json({ error: `Unknown single-device action: ${actionId}` });
      return;
    }

    const input = isPlainObject(body.input) ? (body.input as Record<string, unknown>) : {};
    if (entry.inputSchema) {
      const issues = validateInput(entry.inputSchema, input);
      if (issues.length > 0) {
        res.status(400).json({ error: 'Invalid step input', fieldErrors: Object.fromEntries(issues.map((i) => [i.path, i.message])) });
        return;
      }
    }
    const secretRefs: unknown[] = Array.isArray(body.secretRefs) ? body.secretRefs : [];
    if (!secretRefs.every((r) => typeof r === 'string')) {
      res.status(400).json({ error: 'secretRefs must be an array of strings' });
      return;
    }
    const provisioned = parseJson<Record<string, string>>(plan.provisionedSecrets, {});
    for (const r of secretRefs) {
      if (!(r in provisioned)) {
        res.status(400).json({ error: `Unknown secretRef "${r}" — not a provisioned secret on this plan` });
        return;
      }
    }

    const steps = await loadSteps(plan.id);
    const newId = uuidv4();
    await db.insert(schema.planSteps).values({
      id: newId,
      planId: plan.id,
      stepIndex: steps.length, // temporary — reindex below
      deviceId,
      actionId,
      input: JSON.stringify(input),
      dependsOn: '[]',
      secretRefs: JSON.stringify(secretRefs),
      bestEffort: typeof body.bestEffort === 'boolean' ? body.bestEffort : false,
      status: 'pending',
      result: null,
      startedAt: null,
      finishedAt: null,
    });

    try {
      await reindexSteps(plan.id, [...steps.map((s) => s.id), newId]);
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to add step' });
      return;
    }
    res.status(201).json((await serializePlan(plan.id, true))!);
  }
);

// POST /plans/:id/steps/bulk — append MANY single-device steps in one round-trip.
// Used by the Containers page's bulk actions (stop/start/update/delete N apps or
// images): instead of N sequential add-step calls, the webapp sends every step
// at once. Each step is validated against the plan plugin's catalog inputSchema
// exactly like the single-step route; all-or-nothing (any invalid step → 400).
router.post(
  '/plans/:id/steps/bulk',
  requireAuth,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be edited` });
      return;
    }

    const body = req.body ?? {};
    // Device-level access control — every new step must target the caller's devices.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null) {
      for (const s of Array.isArray(body.steps) ? body.steps : []) {
        const deviceId = typeof (s as Record<string, unknown>)?.deviceId === 'string' ? ((s as Record<string, unknown>).deviceId as string) : '';
        if (!allowed.has(deviceId)) {
          res.status(404).json({ error: 'Plan not found' });
          return;
        }
      }
    }

    const stepsRaw = Array.isArray(body.steps) ? body.steps : [];
    if (stepsRaw.length === 0) {
      res.status(400).json({ error: 'At least one step is required' });
      return;
    }

    const catalog = await loadCatalog(plan.pluginId);
    // Validate every step BEFORE writing anything (all-or-nothing).
    for (let i = 0; i < stepsRaw.length; i++) {
      const s = stepsRaw[i];
      if (!s || typeof s !== 'object') {
        res.status(400).json({ error: `Step ${i} must be an object` });
        return;
      }
      const deviceId = typeof (s as Record<string, unknown>).deviceId === 'string' ? ((s as Record<string, unknown>).deviceId as string) : '';
      const actionId = typeof (s as Record<string, unknown>).actionId === 'string' ? ((s as Record<string, unknown>).actionId as string) : '';
      if (!deviceId || !actionId) {
        res.status(400).json({ error: `Step ${i}: deviceId and actionId are required` });
        return;
      }
      const device = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.id, deviceId) });
      if (!device) {
        res.status(404).json({ error: `Step ${i}: device not found: ${deviceId}` });
        return;
      }
      const assignment = await resolveAssignment(deviceId, plan.pluginId);
      if (!assignment) {
        res.status(400).json({ error: `Step ${i}: plugin is not assigned to device "${device.name}"` });
        return;
      }
      const entry = catalog.find((c) => c.id === actionId);
      if (!entry || entry.deviceCount !== 1) {
        res.status(400).json({ error: `Step ${i}: unknown single-device action: ${actionId}` });
        return;
      }
      const input = isPlainObject((s as Record<string, unknown>).input) ? ((s as Record<string, unknown>).input as Record<string, unknown>) : {};
      if (entry.inputSchema) {
        const issues = validateInput(entry.inputSchema, input);
        if (issues.length > 0) {
          res.status(400).json({ error: `Step ${i}: invalid input`, fieldErrors: Object.fromEntries(issues.map((x) => [x.path, x.message])) });
          return;
        }
      }
    }

    const steps = await loadSteps(plan.id);
    const newIds: string[] = [];
    for (const s of stepsRaw as Array<Record<string, unknown>>) {
      const id = uuidv4();
      newIds.push(id);
      await db.insert(schema.planSteps).values({
        id,
        planId: plan.id,
        stepIndex: 0, // temporary — reindex below
        deviceId: s.deviceId as string,
        actionId: s.actionId as string,
        input: JSON.stringify(isPlainObject(s.input) ? (s.input as Record<string, unknown>) : {}),
        dependsOn: '[]',
        secretRefs: '[]',
        bestEffort: typeof s.bestEffort === 'boolean' ? (s.bestEffort as boolean) : false,
        status: 'pending',
        result: null,
        startedAt: null,
        finishedAt: null,
      });
    }

    try {
      await reindexSteps(plan.id, [...steps.map((x) => x.id), ...newIds]);
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to add steps' });
      return;
    }
    res.status(201).json((await serializePlan(plan.id, true))!);
  }
);

// DELETE /plans/:id/steps/:stepId — remove a step (draft/ready only).
router.delete(
  '/plans/:id/steps/:stepId',
  requireAuth,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be edited` });
      return;
    }
    const steps = await loadSteps(plan.id);
    const step = steps.find((s) => s.id === req.params.stepId);
    if (!step) {
      res.status(404).json({ error: 'Step not found' });
      return;
    }

    // Device-level access control — the removed step's device must be in scope.
    const allowed = await allowedDeviceIds(req);
    if (allowed !== null && !allowed.has(step.deviceId)) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }

    await db.delete(schema.planSteps).where(eq(schema.planSteps.id, step.id));
    try {
      await reindexSteps(plan.id, steps.filter((s) => s.id !== step.id).map((s) => s.id));
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to remove step' });
      return;
    }
    res.status(200).json((await serializePlan(plan.id, true))!);
  }
);

// PATCH /plans/:id/steps/reorder — move a step (draft/ready only).
router.patch(
  '/plans/:id/steps/reorder',
  requireAuth,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be edited` });
      return;
    }
    // Device-level access control (reorder touches every step's device).
    if (!(await assertPlanAccess(req, res, req.params.id))) return;

    const body = req.body ?? {};
    const from = typeof body.from === 'number' ? body.from : -1;
    const to = typeof body.to === 'number' ? body.to : -1;
    const steps = await loadSteps(plan.id);
    if (from < 0 || from >= steps.length || to < 0 || to >= steps.length) {
      res.status(400).json({ error: `from/to must be step indices in [0, ${steps.length - 1}]` });
      return;
    }

    const ids = steps.map((s) => s.id);
    const [moved] = ids.splice(from, 1);
    ids.splice(to, 0, moved);
    try {
      await reindexSteps(plan.id, ids);
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 500).json({ error: e.message ?? 'Failed to reorder steps' });
      return;
    }
    res.status(200).json((await serializePlan(plan.id, true))!);
  }
);

// POST /plans/:id/execute — start execution (2FA-gated like config jobs).
router.post(
  '/plans/:id/execute',
  requireAuth,
  require2FA,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (!EDITABLE_STATUSES.includes(plan.status)) {
      res.status(409).json({ error: `Plan is ${plan.status} — only draft/ready plans can be executed` });
      return;
    }
    // Device-level access control — executing applies changes to every step's device.
    if (!(await assertPlanAccess(req, res, req.params.id))) return;

    const now = new Date().toISOString();
    await db.update(schema.plans)
      // Re-execution clears the "recently done" tick so it re-appears on finish,
      // and resets every step to pending (a re-run re-applies ALL steps — the
      // executor resolves ${steps[N].result...} tokens from THIS run's results).
      .set({
        status: 'executing',
        executedBy: req.user?.sub ?? null,
        error: null,
        startedAt: null,
        finishedAt: null,
        recentlyFinishedAt: null,
        updatedAt: now,
      })
      .where(eq(schema.plans.id, plan.id));
    await db.update(schema.planSteps)
      .set({ status: 'pending', result: null, startedAt: null, finishedAt: null })
      .where(eq(schema.planSteps.planId, plan.id));
    planQueue.add(plan.id, { planId: plan.id });
    res.status(202).json((await serializePlan(plan.id, true))!);
  }
);

// POST /plans/:id/retry — duplicate this plan and execute the copy. The new
// plan carries the SAME intent inputs, steps and provisioned secrets (no
// re-provisioning), so a retry is exactly "run it again" with full payload
// transparency on both rows (`retriedFrom` links them). 2FA-gated like execute.
router.post(
  '/plans/:id/retry',
  requireAuth,
  require2FA,
  requirePermission('configs:apply'),
  async (req, res) => {
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    if (plan.status === 'executing') {
      res.status(409).json({ error: 'This plan is still executing — cancel it or wait for completion before retrying' });
      return;
    }
    // Device-level access control — a retry re-applies every step's device.
    if (!(await assertPlanAccess(req, res, req.params.id))) return;

    const steps = await loadSteps(plan.id);
    if (steps.length === 0) {
      res.status(400).json({ error: 'Plan has no steps to retry' });
      return;
    }

    const now = new Date().toISOString();
    const userId = req.user?.sub ?? '';
    const newId = uuidv4();
    await db.insert(schema.plans).values({
      id: newId,
      pluginId: plan.pluginId,
      intentActionId: plan.intentActionId,
      // Same payload as the original — a retry re-applies exactly what was planned.
      intentInputs: plan.intentInputs ?? '{}',
      status: 'ready',
      provisionedSecrets: plan.provisionedSecrets ?? '{}',
      error: null,
      createdBy: userId,
      executedBy: null,
      cancelledAt: null,
      createdAt: now,
      updatedAt: now,
      startedAt: null,
      finishedAt: null,
      retriedFrom: plan.id,
    });
    for (const step of steps) {
      await db.insert(schema.planSteps).values({
        id: uuidv4(),
        planId: newId,
        stepIndex: step.stepIndex,
        deviceId: step.deviceId,
        actionId: step.actionId,
        input: step.input ?? '{}',
        dependsOn: step.dependsOn ?? '[]',
        secretRefs: step.secretRefs ?? '[]',
        bestEffort: !!step.bestEffort,
        status: 'pending',
        result: null,
        startedAt: null,
        finishedAt: null,
      });
    }

    // Execute the duplicate immediately (same path as a manual execute).
    await db.update(schema.plans)
      .set({ status: 'executing', executedBy: userId, updatedAt: now })
      .where(eq(schema.plans.id, newId));
    planQueue.add(newId, { planId: newId });

    res.status(201).json((await serializePlan(newId, true))!);
  }
);

// POST /plans/:id/cancel — cooperative cancel; the executor checks between steps.
router.post('/plans/:id/cancel', requireAuth, requirePermission('configs:apply'), async (req, res) => {
  const plan = await loadPlan(req.params.id);
  if (!plan) {
    res.status(404).json({ error: 'Plan not found' });
    return;
  }
  if (!(await assertPlanAccess(req, res, req.params.id))) return;
  if (plan.status !== 'executing') {
    res.status(409).json({ error: `Plan is ${plan.status} — only executing plans can be cancelled` });
    return;
  }
  const now = new Date().toISOString();
  await db.update(schema.plans)
    .set({ cancelledAt: now, updatedAt: now })
    .where(eq(schema.plans.id, plan.id));
  res.status(200).json((await serializePlan(plan.id, true))!);
});

// POST /plans/:id/secrets/:ref/regenerate — re-roll a provisioned secret (same id).
router.post(
  '/plans/:id/secrets/:ref/regenerate',
  requireAuth,
  requirePermission('secrets:write'),
  async (req, res) => {
    if (!(await assertPlanAccess(req, res, req.params.id))) return;
    const plan = await loadPlan(req.params.id);
    if (!plan) {
      res.status(404).json({ error: 'Plan not found' });
      return;
    }
    const provisioned = parseJson<Record<string, string>>(plan.provisionedSecrets, {});
    const secretId = provisioned[req.params.ref];
    if (!secretId) {
      res.status(404).json({ error: `No provisioned secret with ref "${req.params.ref}"` });
      return;
    }
    try {
      const out = await regenerateSecret(secretId);
      res.status(200).json(out);
    } catch (err) {
      const e = err as { status?: number; message?: string };
      res.status(e.status ?? 502).json({ error: e.message ?? 'Regeneration failed' });
    }
  }
);

// DELETE /plans/:id — delete a non-executing plan + its steps + provisioned secrets.
router.delete('/plans/:id', requireAuth, requirePermission('configs:apply'), async (req, res) => {
  const plan = await loadPlan(req.params.id);
  if (!plan) {
    res.status(404).json({ error: 'Plan not found' });
    return;
  }
  if (!(await assertPlanAccess(req, res, req.params.id))) return;
  if (plan.status === 'executing') {
    res.status(409).json({ error: 'Cancel the plan before deleting it' });
    return;
  }
  const provisioned = parseJson<Record<string, string>>(plan.provisionedSecrets ?? '{}', {});
  for (const secretId of Object.values(provisioned)) {
    // Retried plans share the original's secrets — never delete one that
    // another plan row still references.
    const others = await db.query.plans.findMany({
      where: and(ne(schema.plans.id, plan.id), like(schema.plans.provisionedSecrets, `%${secretId}%`)),
    });
    if (others.length > 0) continue;
    await deleteSecret(secretId).catch((err) => {
      // eslint-disable-next-line no-console
      console.warn(`[plans] failed to delete provisioned secret ${secretId}:`, (err as Error).message);
    });
  }
  await db.delete(schema.planSteps).where(eq(schema.planSteps.planId, plan.id));
  await db.delete(schema.plans).where(eq(schema.plans.id, plan.id));
  res.status(204).send();
});

export default router;
