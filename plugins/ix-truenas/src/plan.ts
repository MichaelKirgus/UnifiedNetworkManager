/**
 * The TrueNAS planner — turns an intent into an ordered execution plan. v1 has
 * NO multi-device intents: every catalog action is single-device (deviceCount 1)
 * and simply FANS OUT to one independent step per device in the batch. This is
 * what makes the Config page's "execute directly" flow work — a 1-step plan for
 * one appliance, created + executed immediately by the webapp.
 */

import { finalizePlan, PlanningError, Plan, PlanRequest } from '@unm/plugin-sdk';
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

  // Rollback point: every plan that mutates the appliance gets a best-effort
  // configuration backup (config.backup.download — read-only on the device)
  // prepended per dirty device. A failed backup never blocks the plan; the
  // step result carries the base64 file for later config.restore.
  return finalizePlan(actionId, devices, [], rawSteps, isDirtyStep, {
    rollbackStep: () => ({ actionId: 'config.backup.download', input: {} }),
  });
}
