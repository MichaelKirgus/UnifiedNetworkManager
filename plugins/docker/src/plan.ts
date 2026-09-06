/**
 * The Docker planner — turns an intent into an ordered execution plan. Every
 * catalog action is single-device (deviceCount 1) and simply FANS OUT to one
 * independent step per device in the batch, so a bulk selection across several
 * bare-metal hosts becomes N steps sharing the same input shape. This is what
 * makes the Containers page's "execute directly" flow work — a 1-step plan for
 * one host, created + executed immediately by the webapp (2FA-gated).
 */

import { finalizePlan, PlanningError, Plan, PlanRequest } from '@unm/plugin-sdk';
import { registry as actionRegistry } from './actions';

// Re-exported so index.ts keeps a single import source for the plan contract.
export { PlanningError };

/** True when a step's action mutates the host (write/dangerous). */
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

  // No rollback mechanism (no snapshot/backup action for a bare Docker host).
  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep);
}
