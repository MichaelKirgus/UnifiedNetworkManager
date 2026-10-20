/**
 * Shared plan-building core — the device-agnostic heart of POST /plans.
 *
 * Given a plugin, an intent action id and a list of ALREADY-AUTHORIZED device
 * ids (the caller is responsible for existence + device-scope checks), this:
 *   1. resolves each device's assignment + credentials for the plugin,
 *   2. asks the plugin to build the plan (/plan endpoint),
 *   3. fulfils every provisionRequest NOW (secrets created at creation time,
 *      rolled back on failure — same contract as the interactive route), and
 *   4. persists the plans + plan_steps rows.
 *
 * It is used by BOTH the interactive POST /plans route (which keeps auth/2FA/
 * device-scope) and the automation engine's intent actions (which run in-process
 * as system). Failures throw an Error with a `.status` so callers map to their
 * own response shape. No HTTP, no req/res — pure orchestration over the DB +
 * plugin transport.
 */

import { v4 as uuidv4 } from 'uuid';
import { asc } from 'drizzle-orm';
import { pluginAxios } from './pluginHttp';
import { db } from '../db';
import * as schema from '../db/schema';
import { getSecret, generateSecret, deleteSecret } from '../secretsProvider';
import { settingsHeaders } from '../pluginSettings';
import { parseExtraCredentials } from '../types/credentialSlots';
import { isCanonicalIntent, type CatalogEntry } from '@unm/plugin-sdk';

export interface CreatePlanCoreInput {
  pluginId: string;
  intentActionId: string;
  /** Shared intent inputs (validated against the catalog schema by the caller). */
  inputs?: Record<string, unknown>;
  /** Device ids to plan across — must be non-empty and already authorized. */
  deviceIds: string[];
  /** Per-device input overrides for fan-out intents (deviceCount 'N'). */
  deviceInputs?: Record<string, Record<string, unknown>>;
  /** User id that created the plan; 'system' (or omitted) for automation-driven plans. */
  createdBy?: string | null;
  /** Explicit per-plan retry override; else the plugin's suggestion; else global defaults. */
  retryPolicy?: { maxAttempts?: number; waitMs?: number } | null;
}

export interface CreatePlanCoreResult {
  planId: string;
  steps: Array<{ stepIndex: number; deviceId: string; actionId: string }>;
}

/** Error carrying an HTTP status so callers can map to a response. */
export class PlanBuildError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function parseJson<T>(raw: string | null, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}

/** Loads the plugin's persisted action catalog (empty when never discovered). */
async function loadCatalog(pluginId: string): Promise<CatalogEntry[]> {
  const row = await db.query.plugins.findFirst({ where: (p, { eq }) => eq(p.id, pluginId) });
  if (!row?.actionDescriptors) return [];
  const parsed = parseJson<unknown>(row.actionDescriptors, []);
  return Array.isArray(parsed) ? (parsed as CatalogEntry[]) : [];
}

/** Resolves the assignment of `pluginId` on a device (explicit or primary). */
async function resolveAssignment(deviceId: string, pluginId: string) {
  const rows = await db.query.devicePlugins.findMany({
    where: (rows2, { eq }) => eq(rows2.deviceId, deviceId),
    orderBy: [asc(schema.devicePlugins.createdAt)],
  });
  return rows.find((a) => a.pluginId === pluginId && a.isPrimary) ?? rows.find((a) => a.pluginId === pluginId) ?? null;
}

/**
 * Builds + persists a plan for an intent across the given (authorized) devices.
 * Throws PlanBuildError on any failure; provisioned secrets are rolled back if
 * persistence fails partway through provisioning.
 */
export async function createPlanCore(input: CreatePlanCoreInput): Promise<CreatePlanCoreResult> {
  const { pluginId, intentActionId } = input;
  const inputs = input.inputs ?? {};
  const deviceInputs = input.deviceInputs ?? {};

  if (!pluginId || !intentActionId) throw new PlanBuildError(400, 'pluginId and intentActionId are required');
  if (input.deviceIds.length === 0) throw new PlanBuildError(400, 'At least one device is required');

  const plugin = await db.query.plugins.findFirst({ where: (p, { eq }) => eq(p.id, pluginId) });
  if (!plugin) throw new PlanBuildError(404, 'Plugin not found');

  const catalog = await loadCatalog(pluginId);
  const intent = catalog.find((c) => c.id === intentActionId);
  // Canonical fleet intents FAN OUT (one step per device). Older persisted
  // catalogs may carry a numeric deviceCount for them; the 'N' contract wins.
  if (intent && typeof intent.deviceCount === 'number' && !isCanonicalIntent(intentActionId)) {
    if (input.deviceIds.length !== intent.deviceCount) {
      throw new PlanBuildError(400, `Intent ${intentActionId} requires exactly ${intent.deviceCount} devices, got ${input.deviceIds.length}`);
    }
  }

  // Resolve each device's assignment + credentials for THIS plugin.
  const planDevices: Array<{ deviceId: string; managementAddress: string; credentials: Record<string, unknown> }> = [];
  for (const deviceId of input.deviceIds) {
    const device = await db.query.devices.findFirst({ where: (d, { eq }) => eq(d.id, deviceId) });
    if (!device) throw new PlanBuildError(404, `Device not found: ${deviceId}`);

    const assignment = await resolveAssignment(deviceId, pluginId);
    if (!assignment) {
      throw new PlanBuildError(400, `Plugin is not assigned to device "${device.name}"`);
    }

    let credentials: Record<string, unknown> = {};
    if (assignment.secretId) {
      try {
        const decrypted = await getSecret(assignment.secretId);
        credentials = { ...decrypted.fields };
      } catch (err) {
        throw new PlanBuildError(502, `Could not load device credentials: ${(err as Error).message}`);
      }
    } else if (intent && intent.deviceCount !== 1) {
      // Multi-device intents always need appliance credentials — a bound primary
      // secret OR any credential slot counts. Slot-only assignments are usable;
      // devices with NO credential at all are rejected here.
      const slots = parseExtraCredentials(assignment.extraCredentials);
      if (Object.keys(slots).length === 0) {
        throw new PlanBuildError(400, `Device "${device.name}" has no secret assigned for this plugin — multi-device intents require credentials`);
      }
    }
    planDevices.push({ deviceId: device.id, managementAddress: device.managementAddress, credentials });
  }

  // Ask the plugin to build the plan. Settings ride in x-unm-settings like /config.
  const headers = await settingsHeaders(pluginId, planDevices[0].deviceId).catch(() => ({}));
  let plan: {
    id: string;
    createdAt: string;
    intentActionId: string;
    provisionRequests: Array<{ ref: string; type: string; fields?: Record<string, unknown>; label?: string }>;
    steps: Array<{
      stepIndex: number;
      deviceId: string;
      actionId: string;
      input: Record<string, unknown>;
      dependsOn?: number[];
      secretRefs?: string[];
      bestEffort?: boolean;
    }>;
    retryPolicy?: { maxAttempts?: number; waitMs?: number } | null;
  };
  try {
    const response = await pluginAxios(plugin.endpoint).post(
      '/plan',
      { intent: { actionId: intentActionId, inputs }, devices: planDevices, ...(Object.keys(deviceInputs).length > 0 ? { deviceInputs } : {}) },
      { timeout: 20_000, headers }
    );
    plan = response.data?.plan;
    if (!plan || !Array.isArray(plan.steps)) throw new Error('Plugin did not return a valid plan');
  } catch (err) {
    const e = err as { response?: { status?: number; data?: { error?: string } }; message?: string };
    if (e.response?.status === 400) throw new PlanBuildError(400, e.response.data?.error ?? 'Planning failed');
    throw new PlanBuildError(502, `Plugin planning failed: ${e.message ?? 'unreachable'}`);
  }

  // Fulfil provisionRequests NOW (provisioning at creation). Roll back on failure.
  // createdBy is NOT NULL — automation-driven plans are attributed to 'system'.
  const userId = input.createdBy && input.createdBy.length > 0 ? input.createdBy : 'system';
  const provisionedSecrets: Record<string, string> = {};
  try {
    for (const pr of plan.provisionRequests ?? []) {
      if (!pr || typeof pr.ref !== 'string' || typeof pr.type !== 'string') continue;
      const created = await generateSecret({
        type: pr.type,
        fields: pr.fields,
        label: pr.label ?? `Plan ${plan.id.slice(0, 8)} — ${pr.ref}`,
        userId,
      });
      provisionedSecrets[pr.ref] = created.id;
    }
  } catch (err) {
    for (const secretId of Object.values(provisionedSecrets)) {
      await deleteSecret(secretId).catch(() => undefined);
    }
    throw new PlanBuildError(502, `Provisioning failed: ${(err as Error).message}`);
  }

  // Per-plan retry policy: explicit choice wins; else the plugin's suggestion; else null.
  let retryPolicyJson: string | null = null;
  if (input.retryPolicy !== undefined && input.retryPolicy !== null) {
    retryPolicyJson = JSON.stringify({
      ...(typeof input.retryPolicy.maxAttempts === 'number' ? { maxAttempts: Math.trunc(input.retryPolicy.maxAttempts) } : {}),
      ...(typeof input.retryPolicy.waitMs === 'number' ? { waitMs: Math.round(input.retryPolicy.waitMs) } : {}),
    });
  } else if (plan.retryPolicy && typeof plan.retryPolicy === 'object') {
    retryPolicyJson = JSON.stringify({
      ...(typeof plan.retryPolicy.maxAttempts === 'number' ? { maxAttempts: Math.trunc(plan.retryPolicy.maxAttempts) } : {}),
      ...(typeof plan.retryPolicy.waitMs === 'number' ? { waitMs: Math.round(plan.retryPolicy.waitMs) } : {}),
    });
  }

  const now = new Date().toISOString();
  const planRowId = uuidv4();
  await db.insert(schema.plans).values({
    id: planRowId,
    pluginId,
    intentActionId,
    intentInputs: JSON.stringify(inputs),
    status: 'ready',
    provisionedSecrets: JSON.stringify(provisionedSecrets),
    error: null,
    createdBy: userId ?? undefined,
    executedBy: null,
    cancelledAt: null,
    createdAt: now,
    updatedAt: now,
    startedAt: null,
    finishedAt: null,
    retryPolicy: retryPolicyJson,
  });
  for (const step of plan.steps) {
    await db.insert(schema.planSteps).values({
      id: uuidv4(),
      planId: planRowId,
      stepIndex: step.stepIndex,
      deviceId: step.deviceId,
      actionId: step.actionId,
      input: JSON.stringify(step.input ?? {}),
      dependsOn: JSON.stringify(step.dependsOn ?? []),
      secretRefs: JSON.stringify(step.secretRefs ?? []),
      bestEffort: !!step.bestEffort,
      status: 'pending',
      result: null,
      startedAt: null,
      finishedAt: null,
    });
  }

  return { planId: planRowId, steps: plan.steps.map((s) => ({ stepIndex: s.stepIndex, deviceId: s.deviceId, actionId: s.actionId })) };
}
