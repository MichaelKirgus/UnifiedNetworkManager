/**
 * The LANCOM LCOS router planner: turns an intent (one action + inputs) into an
 * ordered, dependency-aware execution plan. v1 is single-device only — every
 * catalog action fans out to one step per device; there are no multi-device
 * intents (router config changes are inherently per-device).
 *
 * Like the OPNsense/SwOS planners this module is pure with respect to writes:
 * it never mutates a router and never generates key material — LCOS v1 needs
 * no provisioned secrets at all. For every device that receives a write step,
 * a best-effort `config.backup.download` rollback point is prepended (it fails
 * harmlessly when the assignment has no `web` slot bound).
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
 * requests. No device probes are needed: LCOS actions validate their inputs
 * against the live router at execution time, so planning is purely structural.
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
  // per-device overrides (PlanRequest.deviceInputs — the rollout wizard's
  // confirmed preflight values, e.g. a different interface or L3 address per
  // router) merge on top for that device only. The shared finalizePlan
  // (@unm/plugin-sdk) prepends a best-effort config backup per dirty device —
  // the downloaded config is the rollback point (restoring it is a manual
  // web-UI operation; the step fails harmlessly when no `web` slot is bound).
  const overrides = req.deviceInputs ?? {};
  const rawSteps = devices.map((d) => ({
    deviceId: d.deviceId,
    actionId: action.id,
    input: { ...(inputs ?? {}), ...(overrides[d.deviceId] ?? {}) },
  }));

  return finalizePlan(
    actionId,
    devices,
    [], // LCOS v1 never provisions secrets.
    rawSteps,
    (stepActionId) => {
      const a = getAction(stepActionId);
      return !!a && a.riskLevel !== 'read';
    },
    { rollbackStep: () => ({ actionId: 'config.backup.download', input: {} }) }
  );
}
