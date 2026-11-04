/**
 * The WLED planner: turns an intent (one action + inputs) into an ordered
 * execution plan. Every catalog action targets exactly one device
 * (deviceCount 1), so planning is a pure fan-out — no multi-device intents,
 * no dependencies between steps.
 *
 * No rollback snapshot exists for WLED (there is no config backup to restore):
 * the plan workflow's confirm dialogs + audit trail are the safety net. The one
 * extra tail we append: after `wled.firmware.update` succeeds the device has
 * already rebooted into the new firmware (the action verifies it), so a short
 * settle wait + forced inventory re-poll refreshes the Updates page row to the
 * new version without waiting for the next poll cycle.
 */

import { PlanningError, appendSettleAndRefresh, finalizePlan, validateInput } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep } from '@unm/plugin-sdk';
import { wledActions } from './actions';

/** Credentials resolved by the API for this device (primary secret fields; slots ride under `slots`). */
type WledCredentials = Record<string, unknown>;

export type PlanDevice = SdkPlanDevice<WledCredentials>;

export interface PlanRequest extends SdkPlanRequest<WledCredentials> {}

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanStep };
export { PlanningError };

/** How long to let the device settle after a verified flash before re-polling inventory. */
const POST_FLASH_SETTLE_MS = 5_000;

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid requests.
 * No device probes are needed: WLED actions validate their inputs against the live
 * controller at execution time, so planning is purely structural.
 */
export function buildPlan(req: PlanRequest): Plan {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = wledActions.getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${wledActions.listCatalog().map((a) => a.id).join(', ')}`);
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

  const plan = finalizePlan(actionId, devices, [], rawSteps, isDirtyStep);

  // After a verified flash the device already reports the new version — refresh
  // the cached updates inventory so the Updates page clears the row immediately.
  return appendSettleAndRefresh(plan, ['wled.firmware.update'], POST_FLASH_SETTLE_MS);
}

/** True when a step's action mutates the controller (write/dangerous). */
function isDirtyStep(stepActionId: string): boolean {
  const a = wledActions.getAction(stepActionId);
  return !!a && a.riskLevel !== 'read';
}
