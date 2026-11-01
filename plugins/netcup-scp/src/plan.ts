/**
 * The netcup SCP planner: turns an intent (one action + inputs) into an ordered
 * execution plan. v1 is single-device only — every catalog action fans out to
 * one step per device; there are no multi-device intents (SCP actions target
 * exactly the account bound to the device).
 *
 * Rollback point: when the intent targets a concrete server (its schema has a
 * `serverId`), a best-effort `snapshot.create` is PREPENDED for every dirty
 * device — the snapshot is the rollback point for dangerous operations (image
 * setup, snapshot revert, power cycles). Account-scoped actions (firewall
 * policy CRUD) have nothing to snapshot and get no rollback step.
 */

import { finalizePlan, PlanningError, validateInput } from '@unm/plugin-sdk';
import type { Plan, PlanDevice as SdkPlanDevice, PlanRequest as SdkPlanRequest, PlanStep } from '@unm/plugin-sdk';
import { registry } from './actions';

/** This device's SCP token (resolved by the API from its assignment). */
type ScpCredentials = { apiKey?: string };

export type PlanDevice = SdkPlanDevice<ScpCredentials>;

export interface PlanRequest extends SdkPlanRequest<ScpCredentials> {}

// Shared plan contract types + error (re-exported so index.ts keeps its imports).
export type { Plan, PlanStep };
export { PlanningError };

/**
 * Builds an execution plan. Throws PlanningError (→ HTTP 400) on invalid
 * requests. No device probes are needed: SCP actions validate their inputs
 * against the live API at execution time, so planning is purely structural.
 */
export function buildPlan(req: PlanRequest): Plan {
  const { actionId, inputs } = req.intent;
  const devices = req.devices ?? [];
  if (devices.length === 0) throw new PlanningError('At least one device is required');

  const action = registry.getAction(actionId);
  if (!action) {
    throw new PlanningError(`Unknown action "${actionId}". Available: ${registry.listActions().map((a) => a.id).join(', ')}`);
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

  // Rollback snapshot only makes sense when the intent targets a concrete server.
  const hasServerTarget = !!action.inputSchema['serverId'];
  return finalizePlan(
    actionId,
    devices,
    [],
    rawSteps,
    isDirtyStep,
    hasServerTarget
      ? {
          rollbackStep: (deviceId) => {
            const step = rawSteps.find((s) => s.deviceId === deviceId);
            const serverId = typeof step?.input['serverId'] === 'number' ? (step.input['serverId'] as number) : 0;
            return {
              actionId: 'snapshot.create',
              input: {
                serverId,
                name: `unm-rollback-${Date.now().toString(36)}`,
                description: 'Pre-change rollback snapshot created by UNM plan execution',
                onlineSnapshot: true,
              },
            };
          },
        }
      : {},
  );
}

/** True when a step's action mutates the account (write/dangerous). */
function isDirtyStep(stepActionId: string): boolean {
  const a = registry.getAction(stepActionId);
  return !!a && a.riskLevel !== 'read';
}
