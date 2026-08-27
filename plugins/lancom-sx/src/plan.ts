/**
 * The LANCOM SX-Series switch planner: turns an intent (one action + inputs)
 * into an ordered, dependency-aware execution plan. v1 is single-device only —
 * every catalog action fans out to one step per device; there are no
 * multi-device intents (switch config changes are inherently per-device).
 *
 * Like the other planners this module is pure with respect to writes: it never
 * mutates a switch and never generates key material — SX v1 needs no
 * provisioned secrets at all. Unlike the LCOS router planner there is NO
 * auto-prepended config backup step (v1 has no web-UI credential slot); risky
 * actions are gated by their `dangerous` risk level instead.
 */

import { finalizePlan, PlanningError } from '@unm/plugin-sdk';
import type { Plan, PlanDevice, PlanRequest } from '@unm/plugin-sdk';
import { getAction, listActions } from './actions/registry';
import { validateInput } from './actions/types';

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanDevice, PlanRequest };
export { PlanningError };

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid
 * requests. No device probes are needed: SX actions validate their inputs
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
    throw new PlanningError(`Invalid action input: ${issues.map((i) => `${i.path}: ${i.message}`).join('; ')}`);
  }

  // Fan-out: one step per device with the same inputs. finalizePlan without a
  // rollbackStep — SX v1 has no snapshot/backup mechanism, so there is nothing
  // to prepend and no index shifting happens (snapshotCount stays 0).
  const rawSteps = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}) },
  }));

  return finalizePlan(actionId, devices, [], rawSteps, () => false); // SX v1 never provisions secrets.
}
