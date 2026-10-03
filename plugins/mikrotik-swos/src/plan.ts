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

import { finalizePlan, PlanningError } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep } from '@unm/plugin-sdk';
import { getAction, listActions } from './actions/registry';
import { validateInput } from './actions/types';

/** This device's username/password (resolved by the API from its assignment). */
type SwosCredentials = { username?: string; password?: string };

export type PlanDevice = SdkPlanDevice<SwosCredentials>;

export interface PlanRequest extends SdkPlanRequest<SwosCredentials> {}

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanStep };
export { PlanningError };

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

  // Fan-out: one step per device. Per-device overrides (PlanRequest.deviceInputs
  // — the rollout wizard's confirmed preflight values, e.g. different member
  // ports per switch) merge on top of the shared inputs for that device only.
  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}), ...((req.deviceInputs ?? {})[d.deviceId] ?? {}) },
  }));

  // The SDK finalizer assigns indices and prepends a best-effort backup snapshot
  // per device that receives any write/dangerous step — the .swb file is the
  // rollback point (restoring it is a manual operation; see action docs).
  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep, {
    rollbackStep: () => ({ actionId: 'swos.backup.download', input: {} }),
  });
}

/** True when a step's action mutates the switch (write/dangerous). */
function isDirtyStep(stepActionId: string): boolean {
  const a = getAction(stepActionId);
  return !!a && a.riskLevel !== 'read';
}
