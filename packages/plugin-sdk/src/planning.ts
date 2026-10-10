/**
 * Planning core — shared by all config-capable plugins (previously copy-pasted
 * into 4: opnsense, swos, lancom-sx, lancom-lcos).
 */

import { randomUUID } from 'crypto';
import { Plan, PlanStep, ProvisionRequest } from './types';

/** Raised for invalid plan requests (mapped to HTTP 400 by the /plan endpoint). */
export class PlanningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PlanningError';
  }
}

/** Pattern matching `${steps[N].result...}` substitution tokens in step inputs. */
export const STEP_TOKEN_PATTERN = /\$\{steps\[(\d+)\]\./g;

/** Shifts every ${steps[N]...} token in a step input by `offset` indices (deep, non-mutating). */
export function shiftStepTokens(input: Record<string, unknown>, offset: number): Record<string, unknown> {
  if (offset === 0) return input;
  const shift = (v: unknown): unknown => {
    if (typeof v === 'string') {
      return v.replace(STEP_TOKEN_PATTERN, (_m, n: string) => `\${steps[${Number(n) + offset}].`);
    }
    if (Array.isArray(v)) return v.map(shift);
    if (v !== null && typeof v === 'object') {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v as Record<string, unknown>)) out[k] = shift(val);
      return out;
    }
    return v;
  };
  const result: Record<string, unknown> = {};
  for (const [k, val] of Object.entries(input)) result[k] = shift(val);
  return result;
}

export interface FinalizePlanOptions {
  /**
   * Returns the best-effort rollback step to prepend for a device that receives
   * at least one non-read step (e.g. snapshot.create / config.backup.download).
   * Omit when the plugin has no rollback mechanism (lancom-sx v1 style).
   */
  rollbackStep?: (deviceId: string) => Pick<PlanStep, 'actionId' | 'input'>;
}

/**
 * Post-processes raw steps into a final Plan: assigns indices and prepends one
 * best-effort rollback step per dirty device.
 *
 * CRITICAL RULE (a real bug was hit here): the dependsOn re-indexing AND the
 * ${steps[N]} token shift use `snapshotCount = steps.length` captured BEFORE
 * appending raw steps — a live steps.length would drift as we push and produce
 * negative/shifted indices. The emitted plan must carry FINAL indices everywhere.
 */
export function finalizePlan(
  intentActionId: string,
  devices: { deviceId: string }[],
  provisionRequests: ProvisionRequest[],
  rawSteps: Omit<PlanStep, 'stepIndex'>[],
  isDirty: (actionId: string) => boolean,
  opts: FinalizePlanOptions = {}
): Plan {
  const steps: PlanStep[] = [];

  if (opts.rollbackStep) {
    const dirtyDevices = new Set<string>();
    for (const s of rawSteps) if (isDirty(s.actionId)) dirtyDevices.add(s.deviceId);
    let nextIndex = 0;
    for (const device of devices) {
      if (!dirtyDevices.has(device.deviceId)) continue;
      const rb = opts.rollbackStep(device.deviceId);
      steps.push({ stepIndex: nextIndex++, deviceId: device.deviceId, ...rb, bestEffort: true });
    }
  }

  // Re-index dependencies AND ${steps[N].result...} tokens (see CRITICAL RULE).
  const snapshotCount = steps.length;
  let nextIndex = steps.length;
  for (const s of rawSteps) {
    const deps = s.dependsOn?.map((d) => d + snapshotCount);
    steps.push({ ...s, stepIndex: nextIndex++, input: shiftStepTokens(s.input, snapshotCount), ...(deps && deps.length > 0 ? { dependsOn: deps } : {}) });
  }

  return {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    intentActionId,
    provisionRequests,
    steps,
  };
}

// ---------------------------------------------------------------------------
// Reserved system steps — executed by the UNM plan executor ITSELF, never
// dispatched to a plugin's /config endpoint. A plugin appends them to its plan
// (via appendSettleAndRefresh) whenever an applied action invalidates data the
// API caches (e.g. the updates inventory after an OS package or image update).
// The PLUGIN decides whether they are needed and how long to wait — the API is
// a dumb runner, which keeps this reusable across every plugin + intent.
// ---------------------------------------------------------------------------

/** Reserved action id: sleep `input.ms` before dependent steps run (visible in
 * the plan as its own step). Executor-side; never dispatched to a plugin. */
export const SYSTEM_STEP_WAIT = 'unm.wait';
/** Reserved action id: force an immediate inventory re-poll of the step's device
 * after the update has settled. Executor-side; never dispatched to a plugin. */
export const SYSTEM_STEP_INVENTORY_REFRESH = 'unm.inventory.refresh';

/** True for reserved system-step action ids (executor runs them locally). */
export function isSystemStepAction(actionId: string): boolean {
  return actionId === SYSTEM_STEP_WAIT || actionId === SYSTEM_STEP_INVENTORY_REFRESH;
}

/**
 * Appends a transparent "settle + refresh" tail to a finalized plan, per device
 * that received at least one step in `invalidateActions`:
 *   … update steps → unm.wait { ms } (best-effort) → unm.inventory.refresh {} (best-effort)
 * The wait gives the device time to finish applying (a package install settles
 * fast; an OS upgrade needs minutes — the plugin picks the value). Both steps
 * are bestEffort: a rebooted/updated appliance may be unreachable for the
 * refresh, and that must NOT fail an otherwise successful plan. Returns the
 * same Plan object with the tail appended (indices continue after `plan.steps`).
 */
export function appendSettleAndRefresh(
  plan: Plan,
  invalidateActions: string[],
  waitMs: number,
): Plan {
  const invalidating = new Set(invalidateActions);
  if (invalidating.size === 0) return plan;

  // Devices that actually received an invalidating step — in first-seen order.
  const devices: string[] = [];
  for (const s of plan.steps) {
    if (invalidating.has(s.actionId) && !devices.includes(s.deviceId)) devices.push(s.deviceId);
  }

  let nextIndex = plan.steps.length;
  for (const deviceId of devices) {
    const waitIdx = nextIndex++;
    plan.steps.push({ stepIndex: waitIdx, deviceId, actionId: SYSTEM_STEP_WAIT, input: { ms: Math.max(0, Math.round(waitMs)) }, bestEffort: true });
    plan.steps.push({ stepIndex: nextIndex++, deviceId, actionId: SYSTEM_STEP_INVENTORY_REFRESH, input: {}, dependsOn: [waitIdx], bestEffort: true });
  }
  return plan;
}
