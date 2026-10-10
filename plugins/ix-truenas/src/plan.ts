/**
 * The TrueNAS planner — turns an intent into an ordered execution plan. v1 has
 * NO multi-device intents: every catalog action is single-device (deviceCount 1)
 * and simply FANS OUT to one independent step per device in the batch. This is
 * what makes the Config page's "execute directly" flow work — a 1-step plan for
 * one appliance, created + executed immediately by the webapp.
 */

import { appendSettleAndRefresh, finalizePlan, PlanningError, Plan, PlanRequest } from '@unm/plugin-sdk';
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

  // Single-device fan-out — one step per device. Per-device overrides (the
  // rollout wizard's confirmed preflight values, e.g. a different L3 address or
  // an explicit null to clear the shared CIDR for an L2-only appliance) merge
  // over the shared inputs for that device only.
  const overrides = req.deviceInputs ?? {};
  const rawSteps = devices.map((d) => ({ deviceId: d.deviceId, actionId, input: { ...(inputs ?? {}), ...(overrides[d.deviceId] ?? {}) } }));

  // Rollback point: every plan that mutates the appliance gets a best-effort
  // configuration backup (config.backup.download — read-only on the device)
  // prepended per dirty device. A failed backup never blocks the plan; the
  // step result carries the base64 file for later config.restore.
  return withSettleTail(
    finalizePlan(actionId, devices, [], rawSteps, isDirtyStep, {
      rollbackStep: () => ({ actionId: 'config.backup.download', input: {} }),
    }),
    actionId,
  );
}

// --- Settle + inventory-refresh tail ---------------------------------------------
// Applying an update invalidates the updates inventory the API caches. The plugin
// appends reserved SYSTEM steps — executed by the UNM plan executor itself, never
// dispatched here: a visible settle wait, then a forced inventory re-poll so
// applied updates disappear from the Updates page instead of dangling. The PLUGIN
// owns both decisions (which intents need it and how long to wait).
const UPDATE_SETTLE_MS: Record<string, number> = {
  // App upgrades redeploy containers server-side; image pulls refresh the store.
  'containers.upgrade': 60_000,
  'images.update': 30_000,
  // A firmware update installs a new boot environment and REBOOTS — give it
  // time to come back before the re-poll (best-effort: unreachable is fine).
  'system.firmware.update': 600_000,
};

/** Appends the settle+refresh tail for update intents; passes other plans through. */
function withSettleTail(plan: Plan, intentId: string): Plan {
  const waitMs = UPDATE_SETTLE_MS[intentId];
  if (waitMs === undefined) return plan;
  return appendSettleAndRefresh(plan, Object.keys(UPDATE_SETTLE_MS), waitMs);
}
