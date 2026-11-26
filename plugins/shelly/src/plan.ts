/**
 * The Shelly planner: turns an intent (one action + inputs) into an ordered
 * execution plan. Every catalog action targets exactly one device
 * (deviceCount 1), so planning is a pure fan-out — no multi-device intents,
 * no dependencies between steps.
 *
 * The one structural tail: after `shelly.firmware.update` the device reboots
 * mid-flight and is unreachable for ~1–2 minutes, so the plan appends a settle
 * wait (unm.wait, 120 s) + a forced inventory refresh (unm.inventory.refresh)
 * per updated device — the Updates page row and firmware metrics clear to the
 * new version without waiting for the next poll cycle. Both are best-effort
 * system steps executed by the API's plan runner, never dispatched here.
 */

import { PlanningError, appendSettleAndRefresh, finalizePlan, validateInput } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep } from '@unm/plugin-sdk';
import { shellyActions } from './actions';

/** Credentials resolved by the API for this device (primary secret fields; slots ride under `slots`). */
type ShellyCredentials = Record<string, unknown>;

export type PlanDevice = SdkPlanDevice<ShellyCredentials>;

export interface PlanRequest extends SdkPlanRequest<ShellyCredentials> {}

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanStep };
export { PlanningError };

/** The device flashes + reboots during an update — let it settle before re-polling inventory. */
const POST_UPDATE_SETTLE_MS = 120_000;

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid requests.
 * No device probes are needed: Shelly actions validate against the live device
 * at execution time, so planning is purely structural.
 */
export function buildPlan(req: PlanRequest): Plan {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = shellyActions.getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${shellyActions.listCatalog().map((a) => a.id).join(', ')}`);
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

  // No rollback mechanism in v1 (config backup is out of scope) — no prepend.
  const plan = finalizePlan(actionId, devices, [], rawSteps, () => false);

  // After an update the device reboots into the new firmware — settle, then
  // refresh the cached inventory so the Updates page clears the row immediately.
  return appendSettleAndRefresh(plan, ['shelly.firmware.update'], POST_UPDATE_SETTLE_MS);
}
