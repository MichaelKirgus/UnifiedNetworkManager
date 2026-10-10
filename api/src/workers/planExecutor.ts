import { pluginAxios } from '../utils/pluginHttp';
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
import { getEffectiveSettingValue } from '../systemSettings';

const PROCESS_INTERVAL_MS = 5_000;

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
  startedAt: string | null;
  /** JSON per-plan retry override ({ maxAttempts?, waitMs? }) or null = global defaults. */
  retryPolicy?: string | null;
}

/** The ActionResult a plugin /config call returns, as stored on plan_steps.result. */
interface StoredStepResult {
  success: boolean;
  result?: Record<string, unknown>;
  /** How many dispatch attempts this step took (omitted when it succeeded first try). */
  attempts?: number;
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
    // recentlyFinishedAt drives the top-bar plans icon's "recently done" tick;
    // it is distinct from finishedAt (cleared on re-execution).
    .set({ status, error: error ?? null, updatedAt: now, finishedAt: now, recentlyFinishedAt: now })
    .where(eq(schema.plans.id, planId));

  // Mirror terminal outcomes into the notification center (one-shot per plan):
  // 'failed' is critical; 'unverified' (applied but not confirmed) is a warning.
  if (status === 'failed' || status === 'unverified') {
    try {
      const plan = await db.query.plans.findFirst({ where: eq(schema.plans.id, planId) });
      const plugin = plan ? await db.query.plugins.findFirst({ where: eq(schema.plugins.id, plan.pluginId) }) : null;
      await emitNotification(
        status === 'failed'
          ? {
              severity: 'critical',
              source: 'system',
              title: `Plan execution failed${plugin ? ` (${plugin.name})` : ''}`,
              message: error ?? 'Unknown error',
              dedupeKey: `plan-failed:${planId}`,
              pluginId: plan?.pluginId ?? null,
              context: { planId, intentActionId: plan?.intentActionId ?? null },
            }
          : {
              severity: 'warning',
              source: 'system',
              title: `Plan applied but not verified${plugin ? ` (${plugin.name})` : ''}`,
              message: error ?? 'The device acknowledged the change, but UNM could not confirm the resulting state.',
              dedupeKey: `plan-unverified:${planId}`,
              pluginId: plan?.pluginId ?? null,
              context: { planId, intentActionId: plan?.intentActionId ?? null },
            }
      );
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

/**
 * Effective per-step retry policy for one plan: the global settings
 * (planStepRetryMaxAttempts / planStepRetryWaitMs) overridden by whatever the
 * plan row carries in `retryPolicy` — a partial object ({ maxAttempts?, waitMs? })
 * where missing keys inherit, or null/absent = pure global defaults. A plugin
 * may set this on the plan it returns from /plan (e.g. { maxAttempts: 0 } to
 * DISABLE retries for a critical intent), and users can edit it before execution.
 */
async function resolveStepRetryPolicy(planRow: PlanRecord): Promise<{ maxAttempts: number; waitMs: number }> {
  const gMax = Number(await getEffectiveSettingValue('planStepRetryMaxAttempts'));
  const gWait = Number(await getEffectiveSettingValue('planStepRetryWaitMs'));
  let maxAttempts = Number.isFinite(gMax) ? Math.trunc(gMax) : 2;
  let waitMs = Number.isFinite(gWait) ? Math.round(gWait) : 15_000;
  const override = parseJson<Record<string, unknown> | null>(planRow.retryPolicy ?? null, null);
  if (override && typeof override === 'object') {
    const m = Number(override['maxAttempts']);
    if (Number.isFinite(m)) maxAttempts = Math.trunc(m);
    const w = Number(override['waitMs']);
    if (Number.isFinite(w)) waitMs = Math.round(w);
  }
  return {
    maxAttempts: Math.min(Math.max(maxAttempts, 0), 10),
    waitMs: Math.min(Math.max(waitMs, 1_000), 3_600_000),
  };
}

/**
 * Sleeps up to `ms` in 2 s chunks so a cancel can interrupt the wait. Resolves
 * true when a cancel landed mid-sleep (the caller must then stop and finalize).
 */
async function sleepCancellable(planId: string, ms: number): Promise<boolean> {
  const end = Date.now() + Math.max(0, ms);
  for (;;) {
    if (Date.now() >= end) return false;
    await new Promise((r) => setTimeout(r, Math.min(2_000, end - Date.now())));
    const fresh = await db.query.plans.findFirst({ where: (p, { eq }) => eq(p.id, planId) });
    if ((fresh as PlanRecord | null)?.cancelledAt) return true;
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

  // Catalog for per-action timeout overrides + riskLevel (read-only actions
  // are exempt from post-apply verification — a read IS its own confirmation).
  // retryOnDispatchFailure=false is the plugin's flapping guard: power /
  // firmware-flash / config-restore actions that must never be re-dispatched.
  const catalogRaw = parseJson<unknown>(plugin.actionDescriptors ?? null, []);
  const catalog: Array<{ id?: string; timeoutMs?: number; riskLevel?: 'read' | 'write' | 'dangerous'; retryOnDispatchFailure?: boolean }> = Array.isArray(catalogRaw)
    ? (catalogRaw as never[])
    : [];

  const steps = (await db.query.planSteps.findMany({
    where: (s) => eq(s.planId, planId),
    orderBy: [asc(schema.planSteps.stepIndex)],
  })) as StepRecord[];

  // Stamp when this execution actually started (the route only flips the
  // status; the worker may pick it up seconds later). Guarded so a re-run of
  // an already-stamped row never moves the timestamp backwards.
  if (!plan.startedAt) {
    await db.update(schema.plans)
      .set({ startedAt: new Date().toISOString() })
      .where(eq(schema.plans.id, planId));
  }

  const provisionedSecrets = parseJson<Record<string, string>>(plan.provisionedSecrets ?? '{}', {});
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

    const entry = catalog.find((c) => c.id === step.actionId);
    // Default per-step timeout is a system setting; catalog entries may override via timeoutMs.
    const defaultStepTimeoutMs = Number(await getEffectiveSettingValue('planStepTimeoutMs')) || 60_000;
    const timeoutMs = typeof entry?.timeoutMs === 'number' ? entry.timeoutMs : defaultStepTimeoutMs;
    const headers = await settingsHeaders(plan.pluginId, step.deviceId).catch(() => ({}));

    // --- Retry loop -----------------------------------------------------------
    // A FAILED step is re-dispatched only when the failure is TRANSIENT:
    //   - dispatch-level: the plugin was unreachable or the round-trip timed out
    //     (the appliance may simply not be ready yet — reboot, update in flight);
    //   - action-level: the plugin explicitly reports `retryable: true` on its
    //     ActionResult (e.g. "service not started", "container still starting").
    // A hard failure (validation error, missing object, wrong state that will
    // NOT fix itself) is final — it fails the plan immediately, no matter what
    // the retry policy says. The wait between attempts is the plugin's per-failure
    // hint (`waitMs`) when present, else the policy default. Each attempt gets its
    // own config_jobs row for full traceability of every dispatch.
    const retryPolicy = await resolveStepRetryPolicy(plan);

    let stored: StoredStepResult;
    let transient = false;
    let waitHintMs: number | null = null;
    let attempts = 0;
    for (;;) {
      // Traceability: mirror each dispatched attempt as a config_jobs row for
      // full audit history of every dispatch — status is set to its terminal
      // value below, so no worker ever picks these rows up.
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

      attempts++;
      transient = false;
      waitHintMs = null;
      try {
        const response = await pluginAxios(plugin.endpoint).post(
          '/config',
          {
            deviceId: device.id,
            // The UNM display name — plugins use it to label artifacts they create
            // (e.g. config backups stored in the central file repo).
            deviceName: device.name,
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
          // A plugin-side validation/contract error — deterministic, never retryable.
          stored = { success: false, result: { error: e.response.data.error } };
        } else {
          // Unreachable / timeout — the appliance or plugin may simply not be ready yet.
          transient = true;
          stored = { success: false, result: { error: `Dispatch failed: ${e.message ?? 'unreachable'}` } };
        }
      }

      const resObj = (stored.result ?? {}) as Record<string, unknown>;
      if (!stored.success) {
        // The plugin's EXPLICIT classification wins; when it stays silent the
        // dispatch-level guess stands (device not ready yet → retry). A missing
        // `retryable` key must NOT downgrade a transient dispatch failure to hard.
        if (resObj['retryable'] === true || resObj['retryable'] === false) transient = resObj['retryable'];
        const hint = Number(resObj['waitMs']);
        if (Number.isFinite(hint) && hint > 0) waitHintMs = Math.min(Math.round(hint), 3_600_000);
      }

      // Flapping guard: the action's catalog entry may declare that a failed
      // attempt is ALWAYS final — re-dispatching would flap the device (e.g.
      // reboot it twice, flash firmware twice). Overrides any transient signal.
      if (!stored.success && entry?.retryOnDispatchFailure === false) transient = false;

      await db.update(schema.configJobs)
        .set({ status: stored.success ? 'succeeded' : 'failed', result: JSON.stringify(resObj), finishedAt: new Date().toISOString() })
        .where(eq(schema.configJobs.id, jobId));

      if (stored.success || !transient || attempts >= retryPolicy.maxAttempts) break;

      // Cooperative cancel before + during the wait.
      const fresh = await db.query.plans.findFirst({ where: (p, { eq }) => eq(p.id, planId) });
      if ((fresh as PlanRecord | null)?.cancelledAt) {
        stored.attempts = attempts;
        await markStep(step.id, 'failed', stored);
        await skipRemainingSteps(planId);
        await finishPlan(planId, 'cancelled', 'Cancelled by user before completion');
        return;
      }
      const waitMs = waitHintMs ?? retryPolicy.waitMs;
      // eslint-disable-next-line no-console
      console.warn(`[planExecutor] step ${step.stepIndex} (${step.actionId}) attempt ${attempts}/${retryPolicy.maxAttempts} failed (transient) — retrying in ${Math.round(waitMs / 1000)}s:`, resObj['error']);
      const cancelled = await sleepCancellable(planId, waitMs);
      if (cancelled) {
        stored.attempts = attempts;
        await markStep(step.id, 'failed', stored);
        await skipRemainingSteps(planId);
        await finishPlan(planId, 'cancelled', 'Cancelled by user before completion');
        return;
      }
    }

    if (attempts > 1) stored.attempts = attempts;

    const stepStatus = stored.success ? 'succeeded' : 'failed';
    await markStep(step.id, stepStatus, stored);

    if (stored.success) {
      results.set(step.stepIndex, stored);
      continue;
    }

    // Failure policy: bestEffort steps (e.g. snapshot.create on appliances
    // without snapshots) are recorded but do NOT abort the plan.
    if (step.bestEffort) {
      // eslint-disable-next-line no-console
      console.warn(`[planExecutor] best-effort step ${step.stepIndex} (${step.actionId}) failed after ${attempts} attempt(s):`, stored.result?.error);
      continue;
    }

    const errText = (stored.result as { error?: string })?.error ?? 'unknown error';
    await skipRemainingSteps(planId);
    await finishPlan(
      planId,
      'failed',
      attempts > 1
        ? `Step ${step.stepIndex} (${step.actionId}) failed after ${attempts} attempt(s): ${errText}`
        : `Step ${step.stepIndex} (${step.actionId}) failed: ${errText}`
    );
    return;
  }

  // --- Outcome aggregation -------------------------------------------------
  // A step that the plugin ACKNOWLEDGED is not necessarily VERIFIED: plugins
  // re-read device state post-apply and report it via ActionResult.verified
  // (persisted on plan_steps.result). The plan's terminal status reflects the
  // strongest claim we can make:
  //   succeeded  — every non-best-effort step was verified, or is a read-only
  //                action (riskLevel 'read'), which needs no verification;
  //   unverified — everything applied without error, but at least one
  //                non-best-effort write step could not be confirmed. The user
  //                can retry to re-apply + re-check; the per-step result JSON
  //                shows exactly what was and wasn't verified.
  // NOTE: `results` is the success signal here — it only contains steps whose
  // dispatch succeeded (the in-memory step.status rows are stale after markStep).
  const needsVerification = steps.filter((s) => {
    if (s.bestEffort) return false;
    const res = results.get(s.stepIndex);
    if (!res) return false;
    const entry = catalog.find((c) => c.id === s.actionId);
    if (entry?.riskLevel === 'read') return false; // reads are self-evident
    return res.result?.['verified'] !== true;
  });

  if (needsVerification.length === 0) {
    await finishPlan(planId, 'succeeded');
    return;
  }

  const names = needsVerification.map((s) => s.actionId).join(', ');
  await finishPlan(
    planId,
    'unverified',
    `All steps applied without error, but ${needsVerification.length} step${needsVerification.length === 1 ? '' : 's'} could not be verified against device state: ${names}`
  );
}

/**
 * Flips a startable plan (draft/ready/scheduled) to 'executing' and enqueues it
 * for the worker loop — ONE place owns "reset every step + flip status", shared
 * by POST /plans/:id/execute, POST /plans/:id/retry (the duplicate), and the
 * scheduler worker. Consumes any pending schedule (its fields are cleared).
 */
export async function enqueuePlanExecution(planId: string, executedBy: string | null): Promise<void> {
  const now = new Date().toISOString();
  await db.update(schema.plans)
    // Re-execution clears the "recently done" tick so it re-appears on finish,
    // and resets every step to pending (a re-run re-applies ALL steps — the
    // executor resolves ${steps[N].result...} tokens from THIS run's results).
    .set({
      status: 'executing',
      executedBy,
      error: null,
      startedAt: null,
      finishedAt: null,
      recentlyFinishedAt: null,
      scheduledAt: null,
      schedulePolicy: null,
      preScheduleStatus: null,
      scheduleAttempts: 0,
      updatedAt: now,
    })
    .where(eq(schema.plans.id, planId));
  await db.update(schema.planSteps)
    .set({ status: 'pending', result: null, startedAt: null, finishedAt: null })
    .where(eq(schema.planSteps.planId, planId));
  planQueue.add(planId, { planId });
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
