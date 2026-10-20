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
import { db } from '../db';
import * as schema from '../db/schema';
import { emitNotification } from '../notifications';
import { createPlanCore, PlanBuildError } from '../utils/createPlanCore';
import { enqueuePlanExecution } from '../workers/planExecutor';
import { PRESETS, buildArchive, gzipArchive, scopeForSections, storeLocalBackup } from '../backup';
import { runTargetSync } from '../replication';
import { renderTemplate, templateVarsFor } from './engine';
import type { ActionBlock, TriggerContext } from './types';

/** Outcome of running one action block. */
export interface ActionResult {
  ok: boolean;
  error?: string;
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
    firedAtIso,
  });

  try {
    switch (action.type) {
      case 'intent': {
        const deviceIds = await resolveScopeDeviceIds(action.devices.scope);
        // Explicit device ids narrow/override the scope.
        const finalIds = action.devices.deviceIds?.length ? action.devices.deviceIds : deviceIds;
        if (finalIds.length === 0) return { ok: false, error: 'No devices matched the intent scope', planIds: [] };
        try {
          const { planId } = await createPlanCore({
            pluginId: action.pluginId,
            intentActionId: action.actionId,
            inputs: action.input ?? {},
            deviceIds: finalIds,
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
