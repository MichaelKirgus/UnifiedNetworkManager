/**
 * Actions & Schedules — action execution.
 *
 * Runs one action block to completion and reports success/failure + any plan ids
 * it created. The worker calls `executeAction()` for each of a rule's actions,
 * sequentially, after a trigger fires. Each action type is self-contained:
 *   - intent       → createPlanCore (shared with POST /plans) + enqueue execution
 *   - webhook      → http(s) request to an external endpoint (10 s timeout)
 *   - notification → emitNotification (dedupeKey per rule+action)
 *   - internal     → backup of this instance, or a replication-target sync
 */

import axios from 'axios';
import { randomUUID } from 'crypto';
import { and, eq, like, ne } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { emitNotification } from '../notifications';
import { createPlanCore, PlanBuildError } from '../utils/createPlanCore';
import { enqueuePlanExecution } from '../workers/planExecutor';
import { PRESETS, buildArchive, gzipArchive, scopeForSections, storeLocalBackup } from '../backup';
import { runTargetSync } from '../replication';
import { deleteSecret } from '../secretsProvider';
import { parseJsonField, renderTemplate, templateVarsFor } from './engine';
import type { ActionBlock, IntentAction, TriggerContext } from './types';

/** Outcome of running one action block. */
export interface ActionResult {
  ok: boolean;
  error?: string;
  /** Set when the action was deliberately skipped (e.g. requireNoReboot guard) — not a failure. */
  skipped?: string | null;
  /** Plan ids created by an intent action (empty for other types). */
  planIds: string[];
}

const WEBHOOK_TIMEOUT_MS = 10_000;

/** Resolves the device ids a scope refers to (all devices when empty/absent). */
async function resolveScopeDeviceIds(scope?: { siteIds?: string[]; tags?: string[]; deviceIds?: string[] }): Promise<string[]> {
  const rows = await db.query.devices.findMany();
  return rows
    .filter((d) => {
      if (!scope) return true;
      const siteIds = scope.siteIds ?? [];
      const tags = scope.tags ?? [];
      const deviceIds = scope.deviceIds ?? [];
      if (siteIds.length === 0 && tags.length === 0 && deviceIds.length === 0) return true; // empty = all
      if (deviceIds.includes(d.id)) return true;
      if (d.siteId && siteIds.includes(d.siteId)) return true;
      // tags is a TEXT JSON column — parse defensively.
      let dTags: string[] = [];
      try {
        const parsed = JSON.parse(d.tags);
        if (Array.isArray(parsed)) dTags = parsed.filter((t): t is string => typeof t === 'string');
      } catch { /* malformed → no tags */ }
      if (tags.some((t) => dTags.includes(t))) return true;
      return false;
    })
    .map((d) => d.id);
}

/** Runs one action block. Never throws — failures are reported in the result. */
export async function executeAction(automationId: string, automationName: string, action: ActionBlock, ctx: TriggerContext): Promise<ActionResult> {
  const firedAtIso = new Date().toISOString();
  const vars = templateVarsFor(automationName, {
    triggerType: ctx.trigger.type,
    device: ctx.device ?? null,
    metricKey: ctx.metric?.key ?? null,
    metricValue: ctx.metric?.value ?? null,
    logMessage: ctx.logMessage ?? null,
    flowIp: ctx.flow?.ip ?? null,
    flowBytes: ctx.flow?.estBytes ?? null,
    updateKind: ctx.update?.kind ?? null,
    updateName: ctx.update?.name ?? null,
    updateCurrentVersion: ctx.update?.currentVersion ?? null,
    updateLatestVersion: ctx.update?.latestVersion ?? null,
    firedAtIso,
  });

  try {
    switch (action.type) {
      case 'intent': {
        // Shared with simulateAction so a dry run resolves the exact same target.
        const res = await resolveIntentTargets(action, ctx);
        if (res.skipped) return { ok: true, skipped: res.skipped, planIds: [] };
        if (!res.ok || !res.pluginId || !res.intentActionId) return { ok: false, error: res.error ?? 'unresolvable intent target', planIds: [] };
        try {
          const { planId } = await createPlanCore({
            pluginId: res.pluginId,
            intentActionId: res.intentActionId,
            inputs: res.inputs,
            deviceIds: res.deviceIds,
            createdBy: 'system',
          });
          // Fire-and-forget execution — the plan executor runs it sequentially.
          await enqueuePlanExecution(planId, null);
          return { ok: true, planIds: [planId] };
        } catch (err) {
          const e = err as PlanBuildError;
          return { ok: false, error: e.message ?? 'Failed to create plan', planIds: [] };
        }
      }

      case 'webhook': {
        const method = (action.method ?? 'POST').toUpperCase();
        const headers: Record<string, string> = { ...(action.headers ?? {}) };
        let body: unknown;
        if (action.bodyTemplate) {
          const rendered = renderTemplate(action.bodyTemplate, vars);
          // Try to parse as JSON object; fall back to raw string.
          try {
            body = JSON.parse(rendered);
          } catch {
            body = rendered;
          }
        }
        await axios({ method: method.toLowerCase(), url: action.url, headers, data: body, timeout: WEBHOOK_TIMEOUT_MS });
        return { ok: true, planIds: [] };
      }

      case 'notification': {
        const title = renderTemplate(action.titleTemplate, vars).slice(0, 300);
        const message = renderTemplate(action.messageTemplate, vars).slice(0, 2000);
        await emitNotification({
          severity: action.severity,
          source: 'system',
          title,
          message,
          dedupeKey: `automation:${automationId}:${action.id}`,
          deviceId: ctx.device?.id ?? null,
          context: { automationId, triggerType: ctx.trigger.type },
        });
        return { ok: true, planIds: [] };
      }

      case 'internal': {
        if (action.kind === 'backup') {
          // v1 stores to the local volume only — repo destinations need a bound
          // file-repo provider id which the action block does not carry yet.
          const preset = action.preset ?? 'config';
          const sections = action.sections?.length ? action.sections : [...(PRESETS[preset] ?? PRESETS['config'])];
          const archive = await buildArchive(sections);
          const { buffer, sha256, sizeBytes } = gzipArchive(archive);
          const id = randomUUID();
          const name = `automation-backup-${preset}-${new Date().toISOString().slice(0, 10)}`;

          await storeLocalBackup(id, buffer);
          await db.insert(schema.backups).values({
            id,
            name,
            scope: scopeForSections(sections),
            sections: JSON.stringify(sections),
            sizeBytes,
            sha256,
            source: 'local',
            providerId: null,
            createdAt: new Date().toISOString(),
          });
          return { ok: true, planIds: [] };
        }

        if (action.kind === 'replicationSync') {
          if (!action.targetId) return { ok: false, error: 'targetId is required for replicationSync', planIds: [] };
          const report = await runTargetSync(action.targetId);
          if (report.status !== 'ok') return { ok: false, error: report.error ?? 'Replication sync failed', planIds: [] };
          return { ok: true, planIds: [] };
        }

        return { ok: false, error: `Unknown internal kind`, planIds: [] };
      }

      default:
        return { ok: false, error: `Unknown action type ${(action as ActionBlock).type}`, planIds: [] };
    }
  } catch (err) {
    const e = err as { response?: { status?: number; data?: unknown }; message?: string };
    let msg = e.message ?? 'Action failed';
    if (e.response?.data && typeof e.response.data === 'object') {
      try {
        const d = e.response.data as { error?: string };
        if (d.error) msg = d.error;
      } catch { /* keep default */ }
    }
    return { ok: false, error: msg.slice(0, 500), planIds: [] };
  }
}

// ── Dry-run (simulation) support ─────────────────────────────────────────────
// A dry run must predict EXACTLY what a real apply would do. For intent actions
// that means calling the SAME createPlanCore() a real firing uses — same device
// resolution, same plugin /plan call, same secret provisioning — and then simply
// NOT enqueuing execution (and tearing the built plan down). Everything below is
// side-effect-free except for the transient plan rows it creates and removes.

/** Resolved target of an intent action: which plugin/action/inputs/devices a real firing would plan against. */
export interface IntentResolution {
  /** Set when the action resolves cleanly to a plannable target. */
  ok?: boolean;
  /** Deliberate skip reason (requireNoReboot guard, or no apply path on the row). */
  skipped?: string | null;
  /** Hard error (missing pluginId/actionId, no devices matched, …). */
  error?: string;
  pluginId: string;
  intentActionId: string;
  inputs: Record<string, unknown>;
  deviceIds: string[];
}

/**
 * Resolves an intent action's target WITHOUT building or executing anything.
 * Shared by executeAction (real) and simulateAction (dry run) so both resolve
 * identically — the dry run can never drift from what would actually be applied.
 */
export async function resolveIntentTargets(action: IntentAction, ctx: TriggerContext): Promise<IntentResolution> {
  // Guard — an update row that needs a reboot is never auto-applied (real or simulated).
  if (action.requireNoReboot && ctx.update?.rebootRequired === true) {
    return { ok: false, skipped: `update "${ctx.update.name}" requires a reboot`, pluginId: action.pluginId ?? '', intentActionId: action.actionId ?? '', inputs: {}, deviceIds: [] };
  }

  let pluginId: string | undefined = action.pluginId;
  let intentActionId: string | null = action.actionId ?? null;
  let inputs: Record<string, unknown> = action.input ?? {};
  let deviceIds: string[];

  if (action.resolveFromTrigger === 'update') {
    const u = ctx.update;
    if (!u) return { ok: false, error: 'resolveFromTrigger=update but the trigger did not fire from an update row', pluginId: '', intentActionId: '', inputs: {}, deviceIds: [] };
    pluginId = u.pluginId;
    intentActionId = u.applyActionId ?? null;
    // The row's prefill first — explicit action input overrides it.
    inputs = { ...(u.applyInput ?? {}), ...inputs };
    if (!intentActionId) return { ok: false, skipped: `update "${u.name}" has no apply path (manual on device)`, pluginId, intentActionId: '', inputs, deviceIds: [] };
    // The firing row's own assignment is the target — never a broader scope.
    deviceIds = [u.deviceId];
  } else {
    if (!pluginId || !intentActionId) return { ok: false, error: 'pluginId and actionId are required (or use resolveFromTrigger)', pluginId: '', intentActionId: '', inputs: {}, deviceIds: [] };
    const scoped = await resolveScopeDeviceIds(action.devices.scope);
    // Explicit device ids narrow/override the scope.
    deviceIds = action.devices.deviceIds?.length ? action.devices.deviceIds : scoped;
  }

  if (deviceIds.length === 0) return { ok: false, error: 'No devices matched the intent scope', pluginId: pluginId ?? '', intentActionId: intentActionId ?? '', inputs, deviceIds: [] };
  return { ok: true, skipped: null, pluginId: pluginId!, intentActionId: intentActionId!, inputs, deviceIds };
}

/** One simulated action outcome (dry run). */
export interface SimulatedAction {
  id: string;
  type: ActionBlock['type'];
  /** 'would-run' | 'skipped' | 'error'. */
  status: 'would-run' | 'skipped' | 'error';
  /** Human-readable one-line description of what would happen. */
  summary: string;
  /** For intent actions that resolve cleanly — the plan a real apply would build (built then torn down). */
  plan?: {
    pluginId: string;
    actionId: string;
    deviceIds: string[];
    steps: Array<{ stepIndex: number; deviceId: string; actionId: string }>;
  };
  /** Skip reason or error message. */
  detail?: string | null;
}

/**
 * Simulates one action block — predicts the outcome WITHOUT executing it. Intent
 * actions build a real plan via createPlanCore (the deterministic plugin /plan
 * call) and return its steps, then tear the plan down so nothing is left behind
 * and nothing can be executed. Non-intent actions are described without running.
 */
export async function simulateAction(automationId: string, automationName: string, action: ActionBlock, ctx: TriggerContext): Promise<SimulatedAction> {
  const vars = templateVarsFor(automationName, {
    triggerType: ctx.trigger.type,
    device: ctx.device ?? null,
    metricKey: ctx.metric?.key ?? null,
    metricValue: ctx.metric?.value ?? null,
    logMessage: ctx.logMessage ?? null,
    flowIp: ctx.flow?.ip ?? null,
    flowBytes: ctx.flow?.estBytes ?? null,
    updateKind: ctx.update?.kind ?? null,
    updateName: ctx.update?.name ?? null,
    updateCurrentVersion: ctx.update?.currentVersion ?? null,
    updateLatestVersion: ctx.update?.latestVersion ?? null,
    firedAtIso: new Date().toISOString(),
  });

  switch (action.type) {
    case 'intent': {
      const res = await resolveIntentTargets(action, ctx);
      if (res.skipped) return { id: action.id, type: 'intent', status: 'skipped', summary: `skip — ${res.skipped}`, detail: res.skipped };
      if (!res.ok || !res.pluginId || !res.intentActionId) return { id: action.id, type: 'intent', status: 'error', summary: res.error ?? 'unresolvable intent target', detail: res.error ?? null };

      // Build the REAL plan (same call a real apply makes), then tear it down.
      try {
        const built = await createPlanCore({ pluginId: res.pluginId, intentActionId: res.intentActionId, inputs: res.inputs, deviceIds: res.deviceIds, createdBy: 'system' });
        // Do NOT enqueue — a plan that is never enqueued stays inert (status 'ready').
        const teardown = await deletePlanWithSecrets(built.planId).catch((err) => ({ ok: false as const, error: (err as Error).message }));
        return {
          id: action.id, type: 'intent', status: 'would-run',
          summary: `apply ${res.intentActionId} on ${res.deviceIds.length} device(s)`,
          plan: { pluginId: res.pluginId, actionId: res.intentActionId, deviceIds: res.deviceIds, steps: built.steps },
          detail: teardown.ok ? null : `plan previewed but cleanup failed: ${teardown.error}`,
        };
      } catch (err) {
        const e = err as PlanBuildError;
        return { id: action.id, type: 'intent', status: 'error', summary: `would fail to build plan`, detail: e.message ?? 'Failed to create plan' };
      }
    }

    case 'webhook': {
      const method = (action.method ?? 'POST').toUpperCase();
      let bodyPreview: string | null = null;
      if (action.bodyTemplate) {
        try { bodyPreview = JSON.stringify(JSON.parse(renderTemplate(action.bodyTemplate, vars))); } catch { bodyPreview = renderTemplate(action.bodyTemplate, vars); }
      }
      return { id: action.id, type: 'webhook', status: 'would-run', summary: `${method} ${action.url}${bodyPreview ? ` (body previewed)` : ''}`, detail: bodyPreview };
    }

    case 'notification': {
      const title = renderTemplate(action.titleTemplate, vars).slice(0, 300);
      return { id: action.id, type: 'notification', status: 'would-run', summary: `notify ${action.severity}: "${title}"` };
    }

    case 'internal': {
      if (action.kind === 'backup') return { id: action.id, type: 'internal', status: 'would-run', summary: `local backup (${action.preset ?? 'config'})` };
      if (action.kind === 'replicationSync') return { id: action.id, type: 'internal', status: 'would-run', summary: `replication sync → target ${action.targetId ?? '?'}` };
      return { id: action.id, type: 'internal', status: 'error', summary: 'unknown internal kind', detail: String(action.kind) };
    }

    default:
      return { id: (action as ActionBlock).id, type: (action as ActionBlock).type, status: 'error', summary: `unknown action type ${(action as ActionBlock).type}` };
  }
}

/**
 * Deletes a plan + its steps + any provisioned secrets it owns — the same cleanup
 * DELETE /plans/:id performs. Used to tear down dry-run plans so a simulation leaves
 * zero residue (no executable plan, no orphan secrets). Never throws.
 */
export async function deletePlanWithSecrets(planId: string): Promise<{ ok: boolean; error?: string }> {
  try {
    const rows = await db.query.plans.findMany({ where: (p) => eq(p.id, planId) });
    const plan = rows[0] as { id: string; provisionedSecrets: string | null } | undefined;
    if (!plan) return { ok: true };

    const provisioned = parseJsonField<Record<string, string>>(plan.provisionedSecrets ?? '{}', {});
    for (const secretId of Object.values(provisioned)) {
      // Retried plans share the original's secrets — never delete one another plan still references.
      const others = await db.query.plans.findMany({
        where: and(ne(schema.plans.id, planId), like(schema.plans.provisionedSecrets, `%${secretId}%`)),
      });
      if (others.length > 0) continue;
      await deleteSecret(secretId).catch(() => undefined);
    }
    await db.delete(schema.planSteps).where(eq(schema.planSteps.planId, planId));
    await db.delete(schema.plans).where(eq(schema.plans.id, planId));
    return { ok: true };
  } catch (err) {
    return { ok: false, error: (err as Error).message };
  }
}
