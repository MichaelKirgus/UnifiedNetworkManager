import { Router } from 'express';
import { desc, eq, asc } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import axios from 'axios';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission, require2FA } from '../auth/middleware';
import { getSecret, generateSecret, regenerateSecret, deleteSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { planQueue } from '../queue';
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
  status: string;
  provisionedSecrets: string | null;
  error: string | null;
  createdBy: string;
  cancelledAt: string | null;
  createdAt: string;
  updatedAt: string;
  finishedAt: string | null;
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

interface CatalogEntry {
  id: string;
  label?: string;
  description?: string;
  module?: string;
  riskLevel?: string;
  deviceCount?: number | 'N';
  beOnly?: boolean;
  timeoutMs?: number;
  inputSchema?: InputSchema;
}

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

async function serializePlan(planId: string, withSteps = false) {
  const row = await loadPlan(planId);
  if (!row) return null;
  const provisionedSecrets = parseJson<Record<string, string>>(row.provisionedSecrets, {});
  // Secret metadata (label/type/createdAt only — never material).
  let secrets: Array<{ ref: string; secretId: string; label?: string | null; type?: string }> = [];
  for (const [ref, secretId] of Object.entries(provisionedSecrets)) {
    const srow = await db.query.secrets.findFirst({
      where: (secretsTable, { eq }) => eq(secretsTable.id, secretId),
    });
    secrets.push({ ref, secretId, label: srow?.label ?? null, type: srow?.type ?? undefined });
  }
  const out: Record<string, unknown> & { id: string; pluginId: string } = {
    id: row.id,
    pluginId: row.pluginId,
    intentActionId: row.intentActionId,
    status: row.status,
    provisionedSecrets: secrets,
    error: row.error,
    createdBy: row.createdBy,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    finishedAt: row.finishedAt,
  };
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
      status: 'ready',
      provisionedSecrets: JSON.stringify(provisionedSecrets),
      error: null,
      createdBy: userId,
      cancelledAt: null,
      createdAt: now,
      updatedAt: now,
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

// GET /plans — most recent plans (no steps; use the detail route for those).
router.get('/plans', requireAuth, async (_req, res) => {
  const rows = await db.query.plans.findMany({
    orderBy: [desc(schema.plans.createdAt)],
    limit: 100,
  });
  const out: unknown[] = [];
  for (const row of rows as PlanRow[]) {
    const steps = await loadSteps(row.id);
    const done = steps.filter((s) => s.status === 'succeeded').length;
    out.push({ ...(await serializePlan(row.id)), stepCount: steps.length, stepsDone: done });
  }
  res.status(200).json(out);
});

// GET /plans/:id — full plan with ordered steps + provisioned secret metadata.
router.get('/plans/:id', requireAuth, async (req, res) => {
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
    const now = new Date().toISOString();
    await db.update(schema.plans)
      .set({ status: 'executing', updatedAt: now })
      .where(eq(schema.plans.id, plan.id));
    planQueue.add(plan.id, { planId: plan.id });
    res.status(202).json((await serializePlan(plan.id, true))!);
  }
);

// POST /plans/:id/cancel — cooperative cancel; the executor checks between steps.
router.post('/plans/:id/cancel', requireAuth, requirePermission('configs:apply'), async (req, res) => {
  const plan = await loadPlan(req.params.id);
  if (!plan) {
    res.status(404).json({ error: 'Plan not found' });
    return;
  }
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
  if (plan.status === 'executing') {
    res.status(409).json({ error: 'Cancel the plan before deleting it' });
    return;
  }
  const provisioned = parseJson<Record<string, string>>(plan.provisionedSecrets, {});
  for (const secretId of Object.values(provisioned)) {
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
