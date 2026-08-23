/**
 * The SwOS planner: turns an intent (one action + inputs) into an ordered,
 * dependency-aware execution plan. v1 is single-device only — every catalog
 * action fans out to one step per device; there are no multi-device intents
 * (switch config is inherently per-device).
 *
 * Like the OPNsense planner this module is pure with respect to writes: it may
 * issue read-only probes but never mutates a switch, and it never generates
 * key material — SwOS v1 needs no provisioned secrets at all.
 */

import { randomUUID } from 'crypto';
import { getAction, listActions } from './actions/registry';
import { Plan, PlanStep, validateInput } from './actions/types';

export interface PlanDevice {
  deviceId: string;
  managementAddress: string;
  /** This device's username/password (resolved by the API from its assignment). */
  credentials: { username?: string; password?: string };
}

export interface PlanRequest {
  intent: { actionId: string; inputs: Record<string, unknown> };
  devices: PlanDevice[];
}

/** Raised for invalid plan requests (mapped to HTTP 400 by the /plan endpoint). */
export class PlanningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PlanningError';
  }
}

/** Shifts every ${steps[N]...} token in a step input by `offset` indices. */
function shiftStepTokens(input: Record<string, unknown>, offset: number): Record<string, unknown> {
  if (offset === 0) return input;
  const shift = (v: unknown): unknown => {
    if (typeof v === 'string') {
      return v.replace(/\$\{steps\[(\d+)\]\./g, (_m, n: string) => `\${steps[${Number(n) + offset}].`);
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

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid
 * requests. No device probes are needed: SwOS actions validate their inputs
 * against the live switch at execution time, so planning is purely structural.
 */
export function buildPlan(req: PlanRequest): Plan {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${listActions().map((a) => a.id).join(', ')}`);
  }

  const issues = validateInput(action.inputSchema, inputs ?? {});
  if (issues.length > 0) {
    throw new PlanningError(`Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`);
  }

  // Fan-out: one step per device with the same inputs.
  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}) },
  }));

  return finalizePlan(actionId, devices, rawSteps);
}

/**
 * Post-processes raw steps: assigns indices and prepends a best-effort backup
 * snapshot per device that receives any write/dangerous step — the .swb file is
 * the rollback point (restoring it is a manual operation; see action docs).
 */
function finalizePlan(intentActionId: string, devices: PlanDevice[], rawSteps: Omit<PlanStep, 'stepIndex'>[]): Plan {
  const dirtyDevices = new Set<string>();
  for (const s of rawSteps) {
    const a = getAction(s.actionId);
    if (a && a.riskLevel !== 'read') dirtyDevices.add(s.deviceId);
  }

  const steps: PlanStep[] = [];
  let nextIndex = 0;
  for (const device of devices) {
    if (!dirtyDevices.has(device.deviceId)) continue;
    steps.push({ stepIndex: nextIndex++, deviceId: device.deviceId, actionId: 'swos.backup.download', input: {}, bestEffort: true });
  }

  // Re-index dependencies AND ${steps[N].result...} tokens. The offset is the
  // number of prepended snapshot steps — captured BEFORE appending raw steps
  // (a live steps.length here would drift as we push).
  const snapshotCount = steps.length;
  for (const s of rawSteps) {
    const deps = s.dependsOn?.map((d) => d + snapshotCount);
    steps.push({ ...s, stepIndex: nextIndex++, input: shiftStepTokens(s.input, snapshotCount), ...(deps && deps.length > 0 ? { dependsOn: deps } : {}) });
  }

  return {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    intentActionId,
    provisionRequests: [], // SwOS v1 never provisions secrets.
    steps,
  };
}
