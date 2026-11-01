/**
 * The generic IPMI planner: turns an intent (one action + inputs) into an ordered
 * execution plan. Every catalog action fans out to one step per device; there are
 * no multi-device intents (IPMI actions target exactly the BMC bound to the device).
 *
 * No rollback snapshot is possible for bare-metal power operations — a pre-change
 * "snapshot" of chassis state has no restore semantics, so dirty steps simply get
 * the plan workflow's confirm dialogs + audit trail instead.
 */

import { finalizePlan, PlanningError, validateInput } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep } from '@unm/plugin-sdk';
import { registry } from './actions';

/** This device's BMC credentials (resolved by the API from its assignment). */
type IpmiCredentials = { username?: string; password?: string };

export type PlanDevice = SdkPlanDevice<IpmiCredentials>;

export interface PlanRequest extends SdkPlanRequest<IpmiCredentials> {}

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanStep };
export { PlanningError };

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid requests.
 * No device probes are needed: IPMI actions validate their inputs against the live
 * BMC at execution time, so planning is purely structural.
 */
export function buildPlan(req: PlanRequest): Plan {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = registry.getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${registry.listActions().map((a) => a.id).join(', ')}`);
  }

  const issues = validateInput(action.inputSchema, inputs ?? {});
  if (issues.length > 0) {
    throw new PlanningError(`Invalid input for ${actionId}: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`);
  }

  // Fan-out: one step per device. Per-device overrides (PlanRequest.deviceInputs)
  // merge on top of the shared inputs for that device only.
  const rawSteps: Omit<PlanStep, 'stepIndex'>[] = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}), ...((req.deviceInputs ?? {})[d.deviceId] ?? {}) },
  }));

  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep);
}

/** True when a step's action mutates the BMC (write/dangerous). */
function isDirtyStep(stepActionId: string): boolean {
  const a = registry.getAction(stepActionId);
  return !!a && a.riskLevel !== 'read';
}
