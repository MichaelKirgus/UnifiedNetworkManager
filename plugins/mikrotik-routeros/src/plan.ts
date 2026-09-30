/**
 * The MikroTik RouterOS router planner: turns an intent (one action + inputs)
 * into an ordered execution plan. Every catalog action fans out to one step per
 * device; there are no multi-device intents (router config changes are
 * inherently per-device).
 *
 * Like the LCOS/OPNsense planners this module is pure with respect to writes:
 * it never mutates a router and never generates key material — RouterOS v1
 * needs no provisioned secrets at all. No rollback step is prepended: RouterOS
 * has no config-backup action in v1 (the web-UI backup is manual), so the plan
 * carries only the intent steps themselves.
 */

import { finalizePlan, PlanningError } from '@unm/plugin-sdk';
import type { Plan, PlanRequest } from '@unm/plugin-sdk';
import { getAction, listActions } from './actions/registry';
import { validateInput } from './actions/types';

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanRequest };
export { PlanningError };

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid
 * requests. No device probes are needed: RouterOS actions validate their
 * inputs against the live router at execution time, so planning is purely
 * structural. Per-device overrides (PlanRequest.deviceInputs — the rollout
 * wizard's confirmed preflight values, e.g. a different attach point or L3
 * address per router) merge on top of the shared inputs for that device only.
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

  // Fan-out: one step per device. Shared inputs are the base; optional
  // per-device overrides merge on top for that device only.
  const overrides = req.deviceInputs ?? {};
  const rawSteps = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}), ...(overrides[d.deviceId] ?? {}) },
  }));

  return finalizePlan(
    actionId,
    devices,
    [], // RouterOS v1 never provisions secrets.
    rawSteps,
    (stepActionId) => {
      const a = getAction(stepActionId);
      return !!a && a.riskLevel !== 'read';
    },
    // No rollbackStep — RouterOS has no config-backup action in v1.
  );
}
