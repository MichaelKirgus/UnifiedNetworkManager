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
