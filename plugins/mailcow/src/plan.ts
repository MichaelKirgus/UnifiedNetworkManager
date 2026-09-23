/**
 * The mailcow planner — turns an intent into an ordered execution plan. v1 has
 * NO multi-device intents: every catalog action is single-device (deviceCount 1)
 * and simply FANS OUT to one independent step per device in the batch. This is
 * what makes the Mail page's "execute directly" flow work — a 1-step plan for
 * one mail server, created + executed immediately by the webapp.
 *
 * No rollback step: mailcow has no lightweight config-backup endpoint that fits
 * the finalizePlan contract (a full backup is a heavyweight job). Failed writes
 * are surfaced per step; deletes are idempotent so re-runs are safe.
 */

import { PlanningError, Plan, PlanRequest, finalizePlan } from '@unm/plugin-sdk';
import { registry as actionRegistry } from './actions';

// Re-exported so index.ts keeps a single import source for the plan contract.
export { PlanningError };

/** True when a step's action mutates the appliance (write/dangerous). */
function isDirtyStep(actionId: string): boolean {
  const a = actionRegistry.getAction(actionId);
  return !!a && a.riskLevel !== 'read';
}

export async function buildPlan(req: PlanRequest): Promise<Plan> {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = actionRegistry.getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${actionRegistry.listActions().map((a) => a.id).join(', ')}`);
  }

  // Single-device fan-out — one step per device, same input.
  const rawSteps = devices.map((d) => ({ deviceId: d.deviceId, actionId, input: { ...(inputs ?? {}) } }));

  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep);
}
