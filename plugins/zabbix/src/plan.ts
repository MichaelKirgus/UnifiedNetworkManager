/**
 * The zabbix planner — turns an intent into an ordered execution plan. Every
 * catalog action is single-device (deviceCount 1) and simply FANS OUT to one
 * independent step per device in the batch: each Zabbix server assigned this
 * plugin gets its own sync/create step. No rollback step — host.create/sync are
 * idempotent, so a re-run never hard-fails and there is no lightweight backup
 * that fits the finalizePlan contract.
 */

import { PlanningError, Plan, PlanRequest, finalizePlan } from '@unm/plugin-sdk';
import { registry as actionRegistry } from './actions';

// Re-exported so index.ts keeps a single import source for the plan contract.
export { PlanningError };

/** True when a step's action mutates the Zabbix server (write/dangerous). */
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
