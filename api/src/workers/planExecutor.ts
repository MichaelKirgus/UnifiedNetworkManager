import axios from 'axios';
import { db } from '../db';
import { asc, eq } from 'drizzle-orm';
import * as schema from '../db/schema';
import { planQueue } from '../queue';
import { getSecretFresh } from '../secretsProvider';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { settingsHeaders } from '../pluginSettings';
import { emitNotification } from '../notifications';
import { parseExtraCredentials } from '../types/credentialSlots';
import { decryptCredentialSlots, withSlots } from '../utils/slotCredentials';

const PROCESS_INTERVAL_MS = 5_000;
/** Default per-step dispatch timeout (ms); catalog entries may override via timeoutMs. */
const DEFAULT_STEP_TIMEOUT_MS = 60_000;

interface StepRecord {
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
}

interface PlanRecord {
  id: string;
  pluginId: string;
  intentActionId: string;
  status: string;
  provisionedSecrets: string | null;
  error: string | null;
  cancelledAt: string | null;
}

/** The ActionResult a plugin /config call returns, as stored on plan_steps.result. */
interface StoredStepResult {
  success: boolean;
  result?: Record<string, unknown>;
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

/**
 * Resolves `${steps[N].result.details.<key>}` tokens in a step's input using
 * the stored results of earlier steps. The plugin's planner emits these literal
 * tokens (e.g. a peer step binding to its server step's created uuid); NO code
 * in the plugin resolves them — that is the executor's job here. Tokens whose
 * referenced value is missing are left intact so the plugin surfaces an explicit
 * error instead of silently applying wrong config.
 */
function substituteTokens(
  value: unknown,
  results: Map<number, StoredStepResult>
): unknown {
  if (typeof value === 'string') {
    return value.replace(/\$\{steps\[(\d+)\]\.result\.details\.([A-Za-z0-9_.]+)\}/g, (_m, idxRaw, key) => {
      const stored = results.get(Number(idxRaw));
      const details = (stored?.result?.['details'] ?? null) as Record<string, unknown> | null;
      const v = details ? details[key] : undefined;
      if (v === undefined || v === null) return _m; // leave token intact → plugin errors clearly
      return String(v);
    });
  }
  if (Array.isArray(value)) {
    return value.map((item) => substituteTokens(item, results));
  }
  if (typeof value === 'object' && value !== null) {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = substituteTokens(v, results);
    }
    return out;
  }
  return value;
}

async function markStep(stepId: string, status: string, result?: StoredStepResult | null): Promise<void> {
  const now = new Date().toISOString();
  await db.update(schema.planSteps)
    .set({
      status,
      ...(result !== undefined ? { result: JSON.stringify(result) } : {}),
      // startedAt is only meaningful once the step actually ran; a step that
      // fails during credential resolution never starts. finishedAt is only set
      // for terminal statuses — a 'running' row must not look already-finished.
      ...(status === 'running' ? { startedAt: now } : { finishedAt: now }),
    })
    .where(eq(schema.planSteps.id, stepId));
}

async function finishPlan(planId: string, status: string, error?: string | null): Promise<void> {
  const now = new Date().toISOString();
  await db.update(schema.plans)
    .set({ status, error: error ?? null, updatedAt: now, finishedAt: now })
    .where(eq(schema.plans.id, planId));

  // Mirror failures into the notification center (one-shot per plan).
  if (status === 'failed') {
    try {
      const plan = await db.query.plans.findFirst({ where: eq(schema.plans.id, planId) });
      const plugin = plan ? await db.query.plugins.findFirst({ where: eq(schema.plugins.id, plan.pluginId) }) : null;
      await emitNotification({
        severity: 'critical',
        source: 'system',
        title: `Plan execution failed${plugin ? ` (${plugin.name})` : ''}`,
        message: error ?? 'Unknown error',
        dedupeKey: `plan-failed:${planId}`,
        pluginId: plan?.pluginId ?? null,
        context: { planId, intentActionId: plan?.intentActionId ?? null },
      });
    } catch {
      // Best-effort by contract.
    }
  }
}

/** Marks every not-yet-run step of a plan as skipped (used on abort/cancel). */
async function skipRemainingSteps(planId: string): Promise<void> {
  const steps = await db.query.planSteps.findMany({
    where: (s) => eq(s.planId, planId),
  });
  for (const step of steps as StepRecord[]) {
    if (step.status === 'pending' || step.status === 'running') {
      await markStep(step.id, 'skipped');
    }
  }
}

async function processPlan(planId: string): Promise<void> {
  const plan = (await db.query.plans.findFirst({
    where: (plans, { eq }) => eq(plans.id, planId),
  })) as PlanRecord | null;
  if (!plan || plan.status !== 'executing') return;

  const plugin = await db.query.plugins.findFirst({
    where: (plugins, { eq }) => eq(plugins.id, plan.pluginId),
  });
  if (!plugin) {
    await finishPlan(planId, 'failed', 'Plugin no longer registered');
    await skipRemainingSteps(planId);
    return;
  }

  // Catalog for per-action timeout overrides.
  const catalogRaw = parseJson<unknown>(plugin.actionDescriptors ?? null, []);
  const catalog: Array<{ id?: string; timeoutMs?: number }> = Array.isArray(catalogRaw) ? (catalogRaw as never[]) : [];

  const steps = (await db.query.planSteps.findMany({
    where: (s) => eq(s.planId, planId),
    orderBy: [asc(schema.planSteps.stepIndex)],
  })) as StepRecord[];

  const provisionedSecrets = parseJson<Record<string, string>>(plan.provisionedSecrets, {});
  const results = new Map<number, StoredStepResult>();

  for (const step of steps) {
    // Cooperative cancel: the route sets cancelledAt; we honor it between steps.
    const fresh = await db.query.plans.findFirst({ where: (p, { eq }) => eq(p.id, planId) });
    if ((fresh as PlanRecord | null)?.cancelledAt) {
      await markStep(step.id, 'skipped');
      await skipRemainingSteps(planId);
      await finishPlan(planId, 'cancelled', 'Cancelled by user before completion');
      return;
    }

    // Dependency gate: every dependsOn index must have succeeded. (A failed
    // non-bestEffort dependency already aborted the loop, so anything missing
    // here means an inconsistent plan — skip rather than guess.)
    const deps = parseJson<number[]>(step.dependsOn, []);
    const unsatisfied = deps.filter((d) => !results.has(d));
    if (unsatisfied.length > 0) {
      await markStep(step.id, 'skipped');
      await skipRemainingSteps(planId);
      await finishPlan(planId, 'failed', `Step ${step.stepIndex} has unsatisfied dependencies [${unsatisfied.join(', ')}]`);
      return;
    }

    const device = await db.query.devices.findFirst({
      where: (devices, { eq }) => eq(devices.id, step.deviceId),
    });
    if (!device) {
      await markStep(step.id, 'failed', { success: false, result: { error: 'Device not found' } });
      if (step.bestEffort) continue;
      await skipRemainingSteps(planId);
      await finishPlan(planId, 'failed', `Step ${step.stepIndex}: device not found`);
      return;
    }

    // The assignment bound to THIS plan's plugin (primary preferred).
    const assignments = await db.query.devicePlugins.findMany({
      where: (rows) => eq(rows.deviceId, step.deviceId),
    });
    const assignment =
      assignments.find((a) => a.pluginId === plan.pluginId && a.isPrimary) ??
      assignments.find((a) => a.pluginId === plan.pluginId) ??
      null;
    if (!assignment) {
      await markStep(step.id, 'failed', { success: false, result: { error: `No ${plugin.name} assignment on device` } });
      if (step.bestEffort) continue;
      await skipRemainingSteps(planId);
      await finishPlan(planId, 'failed', `Step ${step.stepIndex}: no plugin assignment on device`);
      return;
    }

    // Build this step's credentials: the device's base secret plus every
    // provisioned secret merged in under its ref name (the plugin reads them via
    // input.credentialRef → ctx.credentials[ref]).
    let credentials: Record<string, unknown> = {};
    try {
      // FRESH (uncached) — plan steps apply config and must use current credentials.
      if (assignment.secretId) {
        const decrypted = await getSecretFresh(assignment.secretId);
        credentials = { ...decrypted.fields };
      }
      for (const ref of parseJson<string[]>(step.secretRefs, [])) {
        const secretId = provisionedSecrets[ref];
        if (!secretId) throw new Error(`No provisioned secret for ref "${ref}"`);
        const material = await getSecretFresh(secretId);
        credentials[ref] = material.fields;
      }
      // The assignment's bound credential slots (e.g. a web-UI login distinct
      // from the primary SNMP secret) are passed under credentials.slots.<name>.
      credentials = withSlots(
        credentials,
        await decryptCredentialSlots(parseExtraCredentials(assignment.extraCredentials), { fresh: true })
      );
    } catch (err) {
      await markStep(step.id, 'failed', { success: false, result: { error: `Credential resolution failed: ${(err as Error).message}` } });
      if (step.bestEffort) continue;
      await skipRemainingSteps(planId);
      await finishPlan(planId, 'failed', `Step ${step.stepIndex}: credential resolution failed`);
      return;
    }

    const input = substituteTokens(parseJson<Record<string, unknown>>(step.input, {}), results) as Record<string, unknown>;

    // Persist the RESOLVED input so GET /plans/:id shows exactly what was
    // dispatched (tokens replaced with real values). Unresolved tokens stay
    // literal — they are a bug signal, not something to hide.
    await db.update(schema.planSteps)
      .set({ input: JSON.stringify(input) })
      .where(eq(schema.planSteps.id, step.id));

    await markStep(step.id, 'running');

    // Traceability: mirror each dispatched step as a config job row (terminal
    // status set here — the legacy configJob worker only picks up 'queued' rows).
    const jobId = crypto.randomUUID();
    const nowStart = new Date().toISOString();
    await db.insert(schema.configJobs).values({
      id: jobId,
      deviceId: step.deviceId,
      pluginId: plan.pluginId,
      action: step.actionId,
      status: 'running',
      payload: JSON.stringify(input),
      result: null,
      planId: plan.id,
      createdAt: nowStart,
      finishedAt: null,
    });

    const entry = catalog.find((c) => c.id === step.actionId);
    const timeoutMs = typeof entry?.timeoutMs === 'number' ? entry.timeoutMs : DEFAULT_STEP_TIMEOUT_MS;
    const headers = await settingsHeaders(plan.pluginId, step.deviceId).catch(() => ({}));

    let stored: StoredStepResult;
    try {
      const response = await axios.post(
        `${plugin.endpoint.replace(/\/$/, '')}/config`,
        {
          deviceId: device.id,
          managementAddress: device.managementAddress,
          credentials,
          actionId: step.actionId,
          input,
        },
        { timeout: timeoutMs, headers }
      );
      const body = response.data ?? {};
      stored = { success: body.success !== false, result: (body.result ?? {}) as Record<string, unknown> };
    } catch (err) {
      const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
      if (e.response?.status === 400 && e.response.data?.error) {
        stored = { success: false, result: { error: e.response.data.error } };
      } else {
        stored = { success: false, result: { error: `Dispatch failed: ${e.message ?? 'unreachable'}` } };
      }
    }

    const stepStatus = stored.success ? 'succeeded' : 'failed';
    await markStep(step.id, stepStatus, stored);
    await db.update(schema.configJobs)
      .set({ status: stored.success ? 'succeeded' : 'failed', result: JSON.stringify(stored.result ?? {}), finishedAt: new Date().toISOString() })
      .where(eq(schema.configJobs.id, jobId));

    if (stored.success) {
      results.set(step.stepIndex, stored);
      continue;
    }

    // Failure policy: bestEffort steps (e.g. snapshot.create on appliances
    // without snapshots) are recorded but do NOT abort the plan.
    if (step.bestEffort) {
      // eslint-disable-next-line no-console
      console.warn(`[planExecutor] best-effort step ${step.stepIndex} (${step.actionId}) failed:`, stored.result?.error);
      continue;
    }

    await skipRemainingSteps(planId);
    await finishPlan(planId, 'failed', `Step ${step.stepIndex} (${step.actionId}) failed: ${(stored.result as { error?: string })?.error ?? 'unknown error'}`);
    return;
  }

  await finishPlan(planId, 'succeeded');
}

/**
 * Crash recovery (user decision: fail, don't resume). If the API restarted
 * while a plan was executing, its steps may be half-applied to firewalls —
 * auto-resuming risks double-applying staged config. Mark such plans failed so
 * the user re-plans deliberately.
 */
async function sweepInterruptedPlans(): Promise<void> {
  const rows = await db.query.plans.findMany({ where: (p) => eq(p.status, 'executing') });
  for (const row of rows as PlanRecord[]) {
    // eslint-disable-next-line no-console
    console.warn(`[planExecutor] marking interrupted plan ${row.id} failed (API restarted mid-execution)`);
    await skipRemainingSteps(row.id);
    await finishPlan(row.id, 'failed', 'Interrupted by API restart — re-plan to retry');
  }
}

/**
 * Starts the plan execution loop. Plans are processed STRICTLY SEQUENTIALLY
 * (one at a time) so two plans never write to the same appliance concurrently.
 * Returns a stop function (leader step-down / graceful shutdown).
 */
export function startPlanExecutorWorker(): () => void {
  initWorker('planExecutor', LEADER_KEYS.planExecutor);
  // eslint-disable-next-line no-console
  console.log(`[planExecutor] worker started, processing every ${PROCESS_INTERVAL_MS / 1000}s`);

  void sweepInterruptedPlans().catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[planExecutor] startup sweep failed:', err);
  });

  let chain: Promise<void> = Promise.resolve();
  const timer = setInterval(() => {
    const messages = planQueue.drain();
    for (const message of messages) {
      chain = chain
        .then(() => trackBeat('planExecutor', () => processPlan(message.data.planId)))
        .catch((err) => {
          // eslint-disable-next-line no-console
          console.error(`[planExecutor] failed processing plan ${message.data.planId}:`, err);
        });
    }
  }, PROCESS_INTERVAL_MS);

  return () => clearInterval(timer);
}
