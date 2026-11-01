/**
 * Actions & Schedules — automation evaluator (leader-gated worker).
 *
 * Every tick the leader loads all enabled rules and evaluates their triggers:
 *   - schedule     → pure due-check via engine.evaluateSchedules (cron/interval/dailyAt)
 *   - metric       → latest-telemetry condition check (+ sustained window in automation_state)
 *   - log          → new-rows-since-watermark scan (Phase 3)
 *   - deviceStatus → direct hook from the telemetry worker's commit point (onDeviceStatusTransition)
 * When a trigger fires, ALL of the rule's actions run sequentially and ONE
 * automation_runs row records the outcome (succeeded / failed / partial). The
 * whole feature is gated by the `automationsEnabled` system setting.
 */

import { v4 as uuidv4 } from 'uuid';
import { and, eq, lt } from 'drizzle-orm';
import { db, pool } from '../db';
import * as schema from '../db/schema';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { getEffectiveSettingValue } from '../systemSettings';
import { emitNotification } from '../notifications';
import { evaluateFlowCondition, evaluateMetricCondition, evaluateSchedules, hashLogLine, parseJsonField, pendingWindowState, scopeMatchesDevice, splitLogLines, updatePendingStateKey, updateRowMatches } from '../automations/engine';
import type { UpdateTransition } from '../automations/engine';
import type { Automation, ContainerLogTrigger, DeviceStatus, FlowTrigger, LogTrigger, MetricTrigger, ScheduleTrigger, TriggerBlock, TriggerContext, UpdateTrigger } from '../automations/types';
import { executeAction, simulateAction } from '../automations/actions';
import type { SimulatedAction } from '../automations/actions';
import { dispatchPluginAction } from '../utils/pluginDispatch';

const TICK_INTERVAL_MS = 15_000; // how often the leader scans for due triggers
/** Run history retention — rows older than this are swept (hourly). */
const RUN_RETENTION_DAYS = 30;
const SWEEP_INTERVAL_MS = 60 * 60_000;

interface RuleRow {
  id: string;
  name: string;
  enabled: boolean;
  triggers: string; // JSON array of trigger blocks
  actions: string; // JSON array of action blocks
  cooldownSec: number;
  lastFiredAt: string | null;
  createdAt: string;
}

/** Loads every rule (the tick filters by `enabled` — cheap at this scale). */
async function loadRules(): Promise<Automation[]> {
  const rows = await db.query.automations.findMany();
  return (rows as unknown as RuleRow[]).map((r) => ({
    id: r.id,
    name: r.name,
    description: null,
    enabled: !!r.enabled,
    triggers: parseJsonField(r.triggers, []),
    actions: parseJsonField(r.actions, []),
    cooldownSec: Number.isFinite(r.cooldownSec) ? r.cooldownSec : 0,
    lastFiredAt: r.lastFiredAt ?? null,
    createdBy: null,
    createdAt: r.createdAt,
    updatedAt: '',
  }));
}

/**
 * Fires a rule for one trigger block: runs every action sequentially and writes
 * ONE automation_runs row. Never throws — engine failures are recorded on the
 * run row + surfaced as a warning notification (dedupeKey per rule).
 */
export async function fireRule(automation: Automation, trigger: TriggerBlock, context: Record<string, unknown>, ctx: TriggerContext): Promise<void> {
  const nowIso = new Date().toISOString();
  let okCount = 0;
  let failCount = 0;
  let skipCount = 0;
  const errors: string[] = [];
  const planIds: string[] = [];

  for (const action of automation.actions) {
    try {
      const res = await executeAction(automation.id, automation.name, action, ctx);
      if (res.skipped) {
        // Deliberate skip (e.g. requireNoReboot guard) — not a failure.
        skipCount++;
        errors.push(`${action.type}: skipped (${res.skipped})`);
      } else if (res.ok) okCount++;
      else {
        failCount++;
        errors.push(`${action.type}: ${res.error ?? 'failed'}`);
      }
      planIds.push(...res.planIds);
    } catch (err) {
      // executeAction is contractually non-throwing — this is a safety net.
      failCount++;
      errors.push(`${action.type}: ${(err as Error).message ?? 'unexpected error'}`);
    }
  }

  const status = failCount === 0 ? (skipCount > 0 && okCount === 0 ? 'skipped' : 'succeeded') : okCount === 0 ? 'failed' : 'partial';
  try {
    await db.insert(schema.automationRuns).values({
      id: uuidv4(),
      automationId: automation.id,
      firedAt: nowIso,
      triggerType: trigger.type,
      context: JSON.stringify(context),
      status,
      error: errors.length > 0 ? errors.join('; ').slice(0, 2000) : null,
      planIds: JSON.stringify(planIds),
    });
    await db.update(schema.automations).set({ lastFiredAt: nowIso }).where(eq(schema.automations.id, automation.id));
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[automations] failed to record run for rule ${automation.id}:`, err);
  }

  if (failCount > 0) {
    try {
      await emitNotification({
        severity: 'warning',
        source: 'system',
        title: `Automation "${automation.name}" had failing actions`,
        message: errors.join('; ').slice(0, 2000),
        dedupeKey: `automation-failed:${automation.id}`,
        context: { automationId: automation.id, triggerType: trigger.type },
      });
    } catch {
      // Best-effort by contract.
    }
  }

  // eslint-disable-next-line no-console
  console.log(`[automations] rule "${automation.name}" fired (${trigger.type}) — ${status}${planIds.length ? `, plans: ${planIds.join(', ')}` : ''}`);
}

// ── Metric triggers (latest-telemetry condition check) ───────────────────────

/** One latest telemetry snapshot per device/plugin assignment. */
interface LatestTelemetry {
  deviceId: string;
  pluginId: string | null;
  collectedAt: string;
  metrics: Record<string, unknown>;
}

/**
 * Loads the newest telemetry row for every (device, plugin) assignment that has
 * ever reported — DISTINCT ON over the (deviceId, pluginId, collectedAt) index.
 * Bounded by fleet size × assignments-per-device, which is small at this scale.
 */
async function loadLatestTelemetry(): Promise<LatestTelemetry[]> {
  const { rows } = await pool.query<{ deviceId: string; pluginId: string | null; collectedAt: string; metrics: string }>(
    `SELECT t."deviceId", t."pluginId", t."collectedAt", t."metrics"
       FROM telemetry t
      WHERE t.id IN (
        SELECT DISTINCT ON ("deviceId", "pluginId") id
          FROM telemetry
         ORDER BY "deviceId", "pluginId", "collectedAt" DESC
      )`
  );
  const out: LatestTelemetry[] = [];
  for (const r of rows) {
    let metrics: Record<string, unknown> = {};
    try {
      const parsed = JSON.parse(r.metrics);
      if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) metrics = parsed as Record<string, unknown>;
    } catch { /* malformed snapshot — treat as empty */ }
    out.push({ deviceId: r.deviceId, pluginId: r.pluginId, collectedAt: r.collectedAt, metrics });
  }
  return out;
}

const METRIC_WINDOW_KEY = 'metricWindowStart';

/** Reads the sustained-window start (epoch ms) for a metric trigger, or null. */
async function readMetricWindowStart(automationId: string, triggerId: string): Promise<number | null> {
  const row = await db.query.automationState.findFirst({
    where: and(
      eq(schema.automationState.automationId, automationId),
      eq(schema.automationState.triggerId, triggerId),
      eq(schema.automationState.stateKey, METRIC_WINDOW_KEY)
    ),
  });
  if (!row) return null;
  const v = Number(row.value);
  return Number.isFinite(v) ? v : null;
}

/** Sets (or clears with null) the sustained-window start for a metric trigger. */
async function setMetricWindowStart(automationId: string, triggerId: string, valueMs: number | null): Promise<void> {
  const where = and(
    eq(schema.automationState.automationId, automationId),
    eq(schema.automationState.triggerId, triggerId),
    eq(schema.automationState.stateKey, METRIC_WINDOW_KEY)
  );
  if (valueMs === null) {
    await db.delete(schema.automationState).where(where);
    return;
  }
  const nowIso = new Date().toISOString();
  const existing = await db.query.automationState.findFirst({ where });
  if (existing) {
    await db.update(schema.automationState).set({ value: String(valueMs), updatedAt: nowIso }).where(where);
  } else {
    await db.insert(schema.automationState).values({ automationId, triggerId, stateKey: METRIC_WINDOW_KEY, value: String(valueMs), updatedAt: nowIso });
  }
}

/** One evaluator tick: due-check every enabled rule's schedule + metric triggers. */
async function tick(): Promise<void> {
  const enabled = await getEffectiveSettingValue('automationsEnabled');
  if (enabled !== true) return; // master switch off — no evaluation at all

  const rules = await loadRules();
  if (rules.length === 0) return;

  const nowMs = Date.now();

  // Schedule triggers — pure due-check.
  const due = evaluateSchedules(rules, nowMs);
  for (const d of due) {
    const rule = rules.find((r) => r.id === d.ruleId);
    if (!rule || !rule.enabled) continue; // may have been disabled mid-tick
    try {
      await fireRule(
        rule,
        d.trigger,
        { kind: 'schedule', schedule: d.trigger.schedule },
        { trigger: d.trigger }
      );
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error(`[automations] firing rule ${rule.id} failed:`, err);
    }
  }

  // Metric triggers — latest-telemetry condition check (+ sustained window).
  const metricRules = rules.filter((r) => r.enabled && r.triggers.some((t) => t.type === 'metric'));
  if (metricRules.length > 0) {
    try {
      await evaluateMetricTriggers(metricRules, nowMs);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[automations] metric trigger evaluation failed:', err);
    }
  }

  // Log triggers — new-rows-since-watermark scan.
  const logRules = rules.filter((r) => r.enabled && r.triggers.some((t) => t.type === 'log'));
  if (logRules.length > 0) {
    try {
      await evaluateLogTriggers(logRules, nowMs);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[automations] log trigger evaluation failed:', err);
    }
  }

  // Flow triggers — sliding-window aggregation over the flow_agg_* tables.
  const flowRules = rules.filter((r) => r.enabled && r.triggers.some((t) => t.type === 'flow'));
  if (flowRules.length > 0) {
    try {
      await evaluateFlowTriggers(flowRules, nowMs);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[automations] flow trigger evaluation failed:', err);
    }
  }

  // Container-log triggers — tail the app's containers via the plugin read action.
  const containerLogRules = rules.filter((r) => r.enabled && r.triggers.some((t) => t.type === 'containerLog'));
  if (containerLogRules.length > 0) {
    try {
      await evaluateContainerLogTriggers(containerLogRules, nowMs);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[automations] container-log trigger evaluation failed:', err);
    }
  }

  // Update triggers — due-check the pending deferral windows opened by transitions.
  const updateRules = rules.filter((r) => r.enabled && r.triggers.some((t) => t.type === 'updateAvailable' && (t as UpdateTrigger).defer));
  if (updateRules.length > 0) {
    try {
      await evaluatePendingUpdateWindows(updateRules, nowMs);
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[automations] pending update window evaluation failed:', err);
    }
  }

  await sweepOldRuns();
}

/**
 * Evaluates every metric trigger of the given rules against the latest telemetry
 * snapshot per assignment. A trigger fires when ANY in-scope assignment's value
 * meets its condition; `durationSec` > 0 requires the condition to hold for that
 * long (window start persisted in automation_state, cleared on recovery).
 */
async function evaluateMetricTriggers(rules: Automation[], nowMs: number): Promise<void> {
  const latest = await loadLatestTelemetry();
  if (latest.length === 0) return;

  // Device lookup for scope matching + template context.
  const deviceRows = await db.query.devices.findMany();
  const devicesById = new Map(deviceRows.map((d) => [d.id, toScopeDevice(d)]));

  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cooldown — same semantics as schedule triggers (any recent firing throttles).
    if (rule.cooldownSec > 0 && rule.lastFiredAt) {
      const last = new Date(rule.lastFiredAt).getTime();
      if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
    }

    for (const t of rule.triggers) {
      if (t.type !== 'metric') continue;
      try {
        await evaluateOneMetricTrigger(rule, t, latest, devicesById, nowMs);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[automations] metric trigger ${t.id} of rule ${rule.id} failed:`, err);
      }
    }
  }
}

/** Evaluates one metric trigger; at most ONE firing per tick. */
async function evaluateOneMetricTrigger(
  rule: Automation,
  t: MetricTrigger,
  latest: LatestTelemetry[],
  devicesById: Map<string, ScopeDeviceRow>,
  nowMs: number
): Promise<void> {
  const rawDuration = t.durationSec;
  const durationSec = typeof rawDuration === 'number' && Number.isFinite(rawDuration) && rawDuration > 0 ? rawDuration : 0;

  // Candidate assignments whose LATEST value meets the condition.
  let firstMatch: { snap: LatestTelemetry; value: number | string | boolean } | null = null;
  for (const snap of latest) {
    if (t.pluginId && snap.pluginId !== t.pluginId) continue;
    const dev = devicesById.get(snap.deviceId);
    if (!dev) continue; // deleted device — no telemetry to act on
    if (!scopeMatchesDevice(t.scope, dev)) continue;

    const value: unknown = lookupDotted(snap.metrics, t.metricKey);
    if (typeof value !== 'number' && typeof value !== 'string' && typeof value !== 'boolean') continue;
    if (!evaluateMetricCondition(t, value)) continue;
    firstMatch = { snap, value };
    break; // one representative match is enough to fire (and to hold the window)
  }

  if (!firstMatch) {
    // Condition not met anywhere — clear any open sustained window so a future
    // breach starts accumulating from scratch.
    const startMs = await readMetricWindowStart(rule.id, t.id);
    if (startMs !== null) await setMetricWindowStart(rule.id, t.id, null);
    return;
  }

  if (durationSec > 0) {
    // Sustained-condition window: accumulate until the condition has held for
    // durationSec continuously, then fire and re-arm.
    const startMs = await readMetricWindowStart(rule.id, t.id);
    if (startMs === null) {
      await setMetricWindowStart(rule.id, t.id, nowMs); // first observation — start the window
      return;
    }
    if (nowMs - startMs < durationSec * 1000) return; // still accumulating

    await fireRule(
      rule,
      t,
      { kind: 'metric', metricKey: t.metricKey, value: firstMatch.value, deviceId: firstMatch.snap.deviceId },
      {
        trigger: t,
        device: { id: firstMatch.snap.deviceId, name: devicesById.get(firstMatch.snap.deviceId)!.name, address: devicesById.get(firstMatch.snap.deviceId)?.managementAddress ?? null },
        metric: { key: t.metricKey, value: firstMatch.value },
      }
    );
    await setMetricWindowStart(rule.id, t.id, null); // re-arm — next breach accumulates fresh
  } else {
    // Immediate mode (no window). Cooldown/lastFiredAt throttle re-fires.
    const dev = devicesById.get(firstMatch.snap.deviceId)!;
    await fireRule(
      rule,
      t,
      { kind: 'metric', metricKey: t.metricKey, value: firstMatch.value, deviceId: firstMatch.snap.deviceId },
      {
        trigger: t,
        device: { id: dev.id, name: dev.name, address: dev.managementAddress ?? null },
        metric: { key: t.metricKey, value: firstMatch.value },
      }
    );
  }
}

/** Resolves a dotted metric key ("a.b.c") against the flat metrics blob. */
function lookupDotted(metrics: Record<string, unknown>, key: string): unknown {
  // The telemetry metrics blob is FLAT (dot-notation keys are literal), so an
  // exact hit wins; fall back to nested traversal for plugins that nest objects.
  if (key in metrics) return metrics[key];
  const parts = key.split('.');
  let cur: unknown = metrics;
  for (const p of parts) {
    if (!cur || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[p];
  }
  return cur;
}

/** Device row shape the trigger evaluators need (tags parsed to an array). */
interface ScopeDeviceRow {
  id: string;
  name: string;
  siteId?: string | null;
  tags: string[];
  managementAddress?: string | null;
}

/** Parses a device row's JSON `tags` column into the shape scopeMatchesDevice expects. */
function toScopeDevice(row: { id: string; name: string; siteId?: string | null; tags?: unknown; managementAddress?: string | null }): ScopeDeviceRow {
  let tags: string[] = [];
  if (Array.isArray(row.tags)) {
    tags = row.tags.filter((t): t is string => typeof t === 'string');
  } else if (typeof row.tags === 'string') {
    try {
      const parsed = JSON.parse(row.tags);
      if (Array.isArray(parsed)) tags = parsed.filter((t): t is string => typeof t === 'string');
    } catch { /* malformed → no tags */ }
  }
  return { id: row.id, name: row.name, siteId: row.siteId ?? null, tags, managementAddress: row.managementAddress ?? null };
}

// ── Log triggers (new-rows-since-watermark scan) ─────────────────────────────

const LOG_SCAN_LIMIT = 5000; // max rows scanned per trigger per tick (bounded work)
const LOG_WATERMARK_KEY = 'logWatermark';

/** One matching log row, normalized across both sources. */
export interface LogMatch {
  deviceId: string | null;
  message: string;
  /** The time-axis value of the row (ISO for plugin logs, epoch ms for firewall). */
  axisValue: string | number;
}

/** Reads a log trigger's watermark from automation_state. */
async function readLogWatermark(automationId: string, triggerId: string): Promise<string | null> {
  const row = await db.query.automationState.findFirst({
    where: and(
      eq(schema.automationState.automationId, automationId),
      eq(schema.automationState.triggerId, triggerId),
      eq(schema.automationState.stateKey, LOG_WATERMARK_KEY)
    ),
  });
  return row ? row.value : null;
}

/** Sets (or clears with null) a log trigger's watermark. */
async function setLogWatermark(automationId: string, triggerId: string, value: string | number | null): Promise<void> {
  const where = and(
    eq(schema.automationState.automationId, automationId),
    eq(schema.automationState.triggerId, triggerId),
    eq(schema.automationState.stateKey, LOG_WATERMARK_KEY)
  );
  if (value === null) {
    await db.delete(schema.automationState).where(where);
    return;
  }
  const nowIso = new Date().toISOString();
  const existing = await db.query.automationState.findFirst({ where });
  if (existing) {
    await db.update(schema.automationState).set({ value: String(value), updatedAt: nowIso }).where(where);
  } else {
    await db.insert(schema.automationState).values({ automationId, triggerId, stateKey: LOG_WATERMARK_KEY, value: String(value), updatedAt: nowIso });
  }
}

/**
 * Scans NEW rows since the trigger's watermark (plugin_logs by emittedAt ISO,
 * firewall_events by tsMs epoch) and returns up to LOG_SCAN_LIMIT matches of
 * `pattern` (JS regex search on the message). A null watermark = first run:
 * scans only the most recent window so a freshly created rule doesn't fire on
 * months of history. Exported for POST /automations/test-pattern (dry-run with
 * a null watermark — never advances any stored state).
 */
export async function scanLogMatches(t: LogTrigger, watermark: string | null): Promise<{ matches: LogMatch[]; newWatermark: string | number | null }> {
  const levels = t.levels && t.levels.length > 0 ? t.levels : null;

  if (t.source === 'plugin') {
    // emittedAt is ISO-8601 TEXT — lexicographic comparison == chronological.
    const firstRunFloor = new Date(Date.now() - 24 * 3600_000).toISOString();
    const since = watermark ?? firstRunFloor;
    // Build the WHERE clause + params with a running index (optional filters shift numbering).
    let n = 1;
    const conds: string[] = [`"emittedAt" > $${n++}`];
    const params: unknown[] = [since];
    if (t.pluginId) { conds.push(`"pluginId" = $${n++}`); params.push(t.pluginId); }
    if (levels) { conds.push(`"level" = ANY($${n})`); params.push(levels); }
    const { rows } = await pool.query<{ deviceId: string | null; message: string; emittedAt: string; level: string }>(
      `SELECT "deviceId", "message", "emittedAt", "level"
         FROM plugin_logs
        WHERE ${conds.join(' AND ')}
        ORDER BY "emittedAt" ASC
        LIMIT ${LOG_SCAN_LIMIT}`,
      params
    );
    const matches: LogMatch[] = [];
    let newWatermark: string | null = watermark;
    for (const r of rows) {
      if (!newWatermark || r.emittedAt > newWatermark) newWatermark = r.emittedAt;
      try {
        if (new RegExp(t.pattern).test(r.message)) matches.push({ deviceId: r.deviceId, message: r.message, axisValue: r.emittedAt });
      } catch { /* invalid pattern — validation should have caught it at write time */ }
    }
    return { matches, newWatermark };
  }

  // firewall_events — tsMs epoch-ms axis (NULL rows are skipped by the > filter).
  const firstRunFloor = Date.now() - 24 * 3600_000;
  const since = watermark !== null ? Number(watermark) : firstRunFloor;
  let n2 = 1;
  const conds2: string[] = [`"tsMs" > $${n2++}`];
  const params2: unknown[] = [since];
  if (t.pluginId) { conds2.push(`"pluginId" = $${n2++}`); params2.push(t.pluginId); }
  const { rows } = await pool.query<{ deviceId: string; message: string; tsMs: number | null }>(
    `SELECT "deviceId",
            COALESCE("reason", '') || ' ' || "action" || ': ' || "srcIp" || ':' || COALESCE("srcPort", 0) || ' -> ' || "dstIp" || ':' || COALESCE("dstPort", 0) AS message,
            "tsMs"
       FROM firewall_events
      WHERE ${conds2.join(' AND ')}
      ORDER BY "tsMs" ASC
      LIMIT ${LOG_SCAN_LIMIT}`,
    params2
  );
  const matches: LogMatch[] = [];
  let newWatermark: number | null = watermark !== null ? Number(watermark) : null;
  for (const r of rows) {
    if (r.tsMs === null) continue; // unparseable ts — no axis position to advance past
    if (newWatermark === null || r.tsMs > newWatermark) newWatermark = r.tsMs;
    try {
      if (new RegExp(t.pattern).test(r.message)) matches.push({ deviceId: r.deviceId, message: r.message, axisValue: r.tsMs });
    } catch { /* invalid pattern — validation should have caught it at write time */ }
  }
  return { matches, newWatermark };
}

/** Evaluates every log trigger of the given rules (watermark scan per tick). */
async function evaluateLogTriggers(rules: Automation[], nowMs: number): Promise<void> {
  const deviceRows = await db.query.devices.findMany();
  const devicesById = new Map(deviceRows.map((d) => [d.id, toScopeDevice(d)]));

  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cooldown — same semantics as the other trigger types.
    if (rule.cooldownSec > 0 && rule.lastFiredAt) {
      const last = new Date(rule.lastFiredAt).getTime();
      if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
    }

    for (const t of rule.triggers) {
      if (t.type !== 'log') continue;
      try {
        const watermark = await readLogWatermark(rule.id, t.id);
        const { matches, newWatermark } = await scanLogMatches(t, watermark);

        // Advance the watermark past everything scanned — even non-matching rows —
        // so each row is examined exactly once.
        if (newWatermark !== null && newWatermark !== watermark) {
          await setLogWatermark(rule.id, t.id, newWatermark);
        }

        // At most ONE firing per trigger per tick: the NEWEST in-scope match is
        // the representative context (a burst of matching rows — e.g. a failing
        // device logging every poll — must not write one run row per line).
        const inScope = matches.filter((m) => {
          if (!t.scope) return true;
          const dev = m.deviceId ? devicesById.get(m.deviceId) : undefined;
          return scopeMatchesDevice(t.scope, dev ?? { id: '', siteId: null, tags: [] });
        });
        if (inScope.length === 0) continue;
        const newest = inScope[inScope.length - 1]; // scan is ordered by time ASC
        const dev = newest.deviceId ? devicesById.get(newest.deviceId) : undefined;
        await fireRule(
          rule,
          t,
          { kind: 'log', source: t.source, deviceId: newest.deviceId, message: newest.message.slice(0, 500), matchCount: inScope.length },
          {
            trigger: t,
            device: dev ? { id: dev.id, name: dev.name, address: dev.managementAddress ?? null } : null,
            logMessage: newest.message,
          }
        );
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[automations] log trigger ${t.id} of rule ${rule.id} failed:`, err);
      }
    }
  }
}

// ── Generic per-trigger state helpers ───────────────────────────────────────

/** Reads an automation_state value for (rule, trigger, key), or null. */
async function readState(automationId: string, triggerId: string, key: string): Promise<string | null> {
  const row = await db.query.automationState.findFirst({
    where: and(
      eq(schema.automationState.automationId, automationId),
      eq(schema.automationState.triggerId, triggerId),
      eq(schema.automationState.stateKey, key)
    ),
  });
  return row ? row.value : null;
}

/** Sets (or clears with null) an automation_state value for (rule, trigger, key). */
async function writeState(automationId: string, triggerId: string, key: string, value: string | null): Promise<void> {
  const where = and(
    eq(schema.automationState.automationId, automationId),
    eq(schema.automationState.triggerId, triggerId),
    eq(schema.automationState.stateKey, key)
  );
  if (value === null) {
    await db.delete(schema.automationState).where(where);
    return;
  }
  const nowIso = new Date().toISOString();
  const existing = await db.query.automationState.findFirst({ where });
  if (existing) {
    await db.update(schema.automationState).set({ value, updatedAt: nowIso }).where(where);
  } else {
    await db.insert(schema.automationState).values({ automationId, triggerId, stateKey: key, value, updatedAt: nowIso });
  }
}

// ── Flow triggers (sliding-window aggregation over flow_agg_5m) ──────────────

const FLOW_WINDOW_KEY = 'flowWindowStart';
/** Max endpoint tuples considered per trigger per tick (bounded work). */
const FLOW_TUPLE_LIMIT = 200;

interface FlowTuple {
  ip: string;
  estBytes: number;
  deviceId: string | null;
}

/**
 * Aggregates estimated bytes over the last `windowSec` seconds per endpoint IP,
 * for one flow trigger. 'any' direction unions both endpoints of each tuple;
 * 'src'/'dst' measure only that side. The class filter applies to the MEASURED
 * endpoint (a src-side row with an internal dst is not filtered out when
 * endpointClass=internal and direction=src). Returns at most FLOW_TUPLE_LIMIT
 * tuples, highest traffic first.
 */
async function queryFlowWindow(t: FlowTrigger, nowMs: number): Promise<FlowTuple[]> {
  const windowSec = typeof t.windowSec === 'number' && Number.isFinite(t.windowSec) && t.windowSec >= 60 ? Math.min(t.windowSec, 3_600_000) : 300;
  const fromIso = new Date(nowMs - windowSec * 1000).toISOString();
  const toIso = new Date(nowMs).toISOString();

  // direction 'any' → both endpoints as separate subqueries (UNION ALL); else one side.
  const sides: Array<'src' | 'dst'> = t.direction === 'dst' ? ['dst'] : t.direction === 'src' ? ['src'] : ['src', 'dst'];
  const parts: string[] = [];
  for (const s of sides) {
    const ipCol = s === 'src' ? '"srcIp"' : '"dstIp"';
    const clsCol = s === 'src' ? '"srcClass"' : '"dstClass"';
    const devCol = s === 'src' ? '"srcDeviceId"' : '"dstDeviceId"';
    let conds = `bucket >= $1 AND bucket < $2`; // enum values — safe to inline
    if (t.endpointClass) conds += ` AND ${clsCol} = '${t.endpointClass}'`;
    if (t.ip) conds += ` AND ${ipCol} = '${String(t.ip).replace(/'/g, "''")}'`;
    parts.push(
      `(SELECT ${ipCol} AS ip, SUM("estBytes")::bigint AS est_bytes, MAX(${devCol}) AS device_id
          FROM flow_agg_5m WHERE ${conds} GROUP BY ${ipCol})`
    );
  }
  const { rows } = await pool.query<{ ip: string; est_bytes: string | number; device_id: string | null }>(
    `SELECT w.ip, SUM(w.est_bytes)::bigint AS est_bytes, MAX(w.device_id) AS device_id
       FROM (${parts.join(' UNION ALL ')}) w
      GROUP BY w.ip ORDER BY est_bytes DESC LIMIT ${FLOW_TUPLE_LIMIT}`,
    [fromIso, toIso]
  );
  return rows.map((r) => ({ ip: String(r.ip), estBytes: Number(r.est_bytes), deviceId: r.device_id ? String(r.device_id) : null }));
}

/** Evaluates every flow trigger of the given rules (sliding window per tick). */
async function evaluateFlowTriggers(rules: Automation[], nowMs: number): Promise<void> {
  const deviceRows = await db.query.devices.findMany();
  const devicesById = new Map(deviceRows.map((d) => [d.id, toScopeDevice(d)]));

  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cooldown — same semantics as the other trigger types.
    if (rule.cooldownSec > 0 && rule.lastFiredAt) {
      const last = new Date(rule.lastFiredAt).getTime();
      if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
    }

    for (const t of rule.triggers) {
      if (t.type !== 'flow') continue;
      try {
        const tuples = await queryFlowWindow(t, nowMs);
        // In-scope tuple: the endpoint's device matches the scope. A tuple with
        // no known device only matches an EMPTY scope (nothing to match against).
        let firstMatch: FlowTuple | null = null;
        for (const tup of tuples) {
          const dev = tup.deviceId ? devicesById.get(tup.deviceId) : undefined;
          if (!dev) continue; // unknown endpoint — can't verify scope
          if (!scopeMatchesDevice(t.scope, dev)) continue;
          if (!evaluateFlowCondition(t, tup.estBytes)) continue;
          firstMatch = tup;
          break; // tuples are ordered by traffic DESC — the biggest breach wins
        }

        const durationSec = typeof t.durationSec === 'number' && Number.isFinite(t.durationSec) && t.durationSec > 0 ? t.durationSec : 0;
        if (!firstMatch) {
          const startMsRaw = await readState(rule.id, t.id, FLOW_WINDOW_KEY);
          if (startMsRaw !== null) await writeState(rule.id, t.id, FLOW_WINDOW_KEY, null); // clear open window
          continue;
        }

        const fire = async () => {
          const dev = firstMatch!.deviceId ? devicesById.get(firstMatch!.deviceId!) : undefined;
          await fireRule(
            rule,
            t,
            { kind: 'flow', ip: firstMatch!.ip, estBytes: firstMatch!.estBytes, windowSec: typeof t.windowSec === 'number' ? t.windowSec : 300, direction: t.direction ?? 'any' },
            { trigger: t, device: dev ? { id: dev.id, name: dev.name, address: dev.managementAddress ?? null } : null, flow: { ip: firstMatch!.ip, estBytes: firstMatch!.estBytes, windowSec: typeof t.windowSec === 'number' ? t.windowSec : 300, direction: t.direction ?? 'any' } }
          );
        };

        if (durationSec > 0) {
          const startMsRaw = await readState(rule.id, t.id, FLOW_WINDOW_KEY);
          const startMs = startMsRaw !== null ? Number(startMsRaw) : null;
          if (startMs === null || !Number.isFinite(startMs)) {
            await writeState(rule.id, t.id, FLOW_WINDOW_KEY, String(nowMs)); // first observation — start window
            return;
          }
          if (nowMs - startMs < durationSec * 1000) return; // still accumulating
          await fire();
          await writeState(rule.id, t.id, FLOW_WINDOW_KEY, null); // re-arm
        } else {
          await fire();
        }
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[automations] flow trigger ${t.id} of rule ${rule.id} failed:`, err);
      }
    }
  }
}

// ── Container-log triggers (tail via the plugin's containers.logs.read) ──────

const CONTAINER_LOG_SEEN_KEY = 'seenLines';
/** Ring-buffer cap for the seen-line hash set (bounded state size). */
const SEEN_LINES_CAP = 2000;

/** Evaluates every container-log trigger of the given rules. */
async function evaluateContainerLogTriggers(rules: Automation[], nowMs: number): Promise<void> {
  const deviceRows = await db.query.devices.findMany();
  // Plain findMany() does NOT populate relational joins — load assignments explicitly.
  const assignments = await db.query.devicePlugins.findMany();
  const pluginIdsByDevice = new Map<string, string[]>();
  for (const a of assignments) {
    const list = pluginIdsByDevice.get(a.deviceId) ?? [];
    list.push(a.pluginId);
    pluginIdsByDevice.set(a.deviceId, list);
  }

  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cooldown — same semantics as the other trigger types.
    if (rule.cooldownSec > 0 && rule.lastFiredAt) {
      const last = new Date(rule.lastFiredAt).getTime();
      if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
    }

    for (const t of rule.triggers) {
      if (t.type !== 'containerLog') continue;
      try {
        // Devices that have this plugin assigned AND match the scope.
        const candidates = deviceRows.filter((d) => (pluginIdsByDevice.get(d.id) ?? []).includes(t.pluginId));
        const inScope = candidates.filter((d) => scopeMatchesDevice(t.scope, toScopeDevice(d)));
        if (inScope.length === 0) continue; // nothing to tail

        let pattern: RegExp | null = null;
        try { pattern = new RegExp(t.pattern); } catch { pattern = null; }
        if (!pattern) continue; // invalid — validation should have caught it at write time

        const tail = typeof t.tail === 'number' && Number.isInteger(t.tail) ? Math.min(5000, Math.max(20, t.tail)) : 300;

        // Tail each in-scope device (bounded — a scope should rarely span many).
        const perDeviceLines = new Map<string, string[]>();
        for (const dev of inScope.slice(0, 10)) {
          const out = await dispatchPluginAction(dev.id, t.pluginId, 'containers.logs.read', { name: t.appName, tail });
          if (!out.ok) continue; // unreachable / no SSH slot — skip this device
          const details = (out.result?.details ?? {}) as Record<string, unknown>;
          const containers = Array.isArray(details.containers) ? details.containers : [];
          let lines: string[] = [];
          for (const c of containers) {
            const logs = typeof (c as { logs?: unknown }).logs === 'string' ? (c as { logs: string }).logs : '';
            lines.push(...splitLogLines(logs));
          }
          if (lines.length > 0) perDeviceLines.set(dev.id, lines);
        }
        if (perDeviceLines.size === 0) continue;

        // New-line dedup against the persisted seen-set. First run seeds it so a
        // fresh rule doesn't fire on the whole tail history.
        const rawSeen = await readState(rule.id, t.id, CONTAINER_LOG_SEEN_KEY);
        let seen: Set<string>;
        let firstRun = false;
        if (rawSeen === null) {
          seen = new Set();
          firstRun = true;
        } else {
          try {
            const parsed = JSON.parse(rawSeen);
            seen = new Set(Array.isArray(parsed) ? parsed.filter((x): x is string => typeof x === 'string') : []);
          } catch { seen = new Set(); }
        }

        let matchedLine: string | null = null;
        let matchDeviceId: string | null = null;
        let freshCount = 0;
        for (const [deviceId, lines] of perDeviceLines) {
          for (const line of lines) {
            const h = hashLogLine(line);
            if (seen.has(h)) continue; // already reported — skip
            seen.add(h);
            freshCount++;
            if (!firstRun && pattern.test(line)) { matchedLine = line; matchDeviceId = deviceId; }
          }
        }

        // Persist the updated ring buffer (newest last, capped).
        const nextSeen = [...seen].slice(-SEEN_LINES_CAP);
        await writeState(rule.id, t.id, CONTAINER_LOG_SEEN_KEY, JSON.stringify(nextSeen));

        if (!firstRun && matchedLine !== null && matchDeviceId) {
          const devRow = deviceRows.find((d) => d.id === matchDeviceId);
          const scopeDev = devRow ? toScopeDevice(devRow) : undefined;
          await fireRule(
            rule,
            t,
            { kind: 'containerLog', pluginId: t.pluginId, appName: t.appName, deviceId: matchDeviceId, line: matchedLine.slice(0, 500), newLines: freshCount },
            { trigger: t, device: scopeDev ? { id: scopeDev.id, name: scopeDev.name, address: scopeDev.managementAddress ?? null } : null, logMessage: matchedLine }
          );
        }
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[automations] containerLog trigger ${t.id} of rule ${rule.id} failed:`, err);
      }
    }
  }
}

// ── Device-status trigger hook ───────────────────────────────────────────────

/**
 * Called from the telemetry worker's updateDeviceStatus() commit point — AFTER
 * hysteresis has settled a transition (prev → next). Fires every enabled rule
 * whose deviceStatus trigger lists `next` in toStatuses and whose scope matches.
 * Never throws: automation failures must not disturb telemetry bookkeeping.
 */
export async function onDeviceStatusTransition(deviceId: string, prev: DeviceStatus, next: DeviceStatus): Promise<void> {
  try {
    const enabled = await getEffectiveSettingValue('automationsEnabled');
    if (enabled !== true) return;

    const rules = await loadRules();
    const devRow = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    if (!devRow) return; // deleted mid-flight — nothing to fire for
    const scopeDev = toScopeDevice(devRow);

    const nowMs = Date.now();
    for (const rule of rules) {
      if (!rule.enabled) continue;
      if (rule.cooldownSec > 0 && rule.lastFiredAt) {
        const last = new Date(rule.lastFiredAt).getTime();
        if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
      }
      for (const t of rule.triggers) {
        if (t.type !== 'deviceStatus') continue;
        if (!t.toStatuses.includes(next)) continue;
        if (!scopeMatchesDevice(t.scope, scopeDev)) continue;
        try {
          await fireRule(
            rule,
            t,
            { kind: 'deviceStatus', deviceId, from: prev, to: next },
            { trigger: t, device: { id: scopeDev.id, name: scopeDev.name, address: scopeDev.managementAddress ?? null } }
          );
        } catch (err) {
          // eslint-disable-next-line no-console
          console.error(`[automations] deviceStatus firing for rule ${rule.id} failed:`, err);
        }
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[automations] onDeviceStatusTransition failed:', err);
  }
}

// ── Update triggers (device_updates transitions + deferral windows) ─────────

/** Row snapshot carried by a pending deferral window (automation_state JSON). */
interface PendingUpdateSnapshot {
  deviceId: string;
  pluginId: string;
  kind: string;
  name: string;
  currentVersion: string | null;
  latestVersion: string | null;
  rebootRequired: boolean | null;
  applyActionId?: string | null;
  applyInput?: Record<string, unknown>;
}

/** One pending deferral window: when the transition was first seen + its row snapshot. */
interface PendingUpdateWindow {
  sinceIso: string; // anchor for the defer schedule (does NOT move on version advances)
  snapshot: PendingUpdateSnapshot;
}

/** Builds the TriggerContext for an updateAvailable firing from a row snapshot. */
function buildUpdateTriggerContext(t: UpdateTrigger, deviceName: string | null, snap: PendingUpdateSnapshot): TriggerContext {
  return {
    trigger: t,
    device: { id: snap.deviceId, name: deviceName ?? snap.deviceId, address: null },
    update: {
      kind: snap.kind,
      name: snap.name,
      currentVersion: snap.currentVersion,
      latestVersion: snap.latestVersion,
      rebootRequired: snap.rebootRequired,
      deviceId: snap.deviceId,
      pluginId: snap.pluginId,
      applyActionId: snap.applyActionId ?? null,
      applyInput: snap.applyInput,
    },
  };
}

/** automation_runs context for an updateAvailable firing. */
function updateRunContext(deviceId: string, pluginId: string, tr: UpdateTransition): Record<string, unknown> {
  return {
    kind: 'updateAvailable',
    deviceId,
    pluginId,
    transition: tr.transition,
    update: { kind: tr.kind, name: tr.name, currentVersion: tr.currentVersion, latestVersion: tr.latestVersion, rebootRequired: tr.rebootRequired },
  };
}

/** True when the rule is inside its cooldown window at `nowMs`. */
function inCooldown(rule: Automation, nowMs: number): boolean {
  if (rule.cooldownSec <= 0 || !rule.lastFiredAt) return false;
  const last = new Date(rule.lastFiredAt).getTime();
  return Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000;
}

/**
 * Called from the telemetry worker's ingestUpdates() commit point with the
 * TRANSITIONS between this poll's device_updates rows and the previous ones.
 * Fires every enabled rule whose updateAvailable trigger matches (condition,
 * pluginId, scope, kinds/names/namePattern/rebootRequired) — immediately when
 * no `defer` is set, or by opening/refreshing a pending deferral window in
 * automation_state otherwise. Never throws: automation failures must not
 * disturb telemetry bookkeeping.
 */
export async function onUpdateTransitions(deviceId: string, pluginId: string, transitions: UpdateTransition[]): Promise<void> {
  try {
    const enabled = await getEffectiveSettingValue('automationsEnabled');
    if (enabled !== true) return;

    const rules = await loadRules();
    const devRow = await db.query.devices.findFirst({ where: eq(schema.devices.id, deviceId) });
    if (!devRow) return; // deleted mid-flight — nothing to fire for
    const scopeDev = toScopeDevice(devRow);

    const nowMs = Date.now();
    for (const rule of rules) {
      if (!rule.enabled) continue;
      for (const t of rule.triggers) {
        if (t.type !== 'updateAvailable') continue;
        if (t.pluginId && t.pluginId !== pluginId) continue;
        if (!scopeMatchesDevice(t.scope, scopeDev)) continue;
        for (const tr of transitions) {
          // `condition` selects which TRANSITIONS fire: available = appeared/advanced, resolved = disappeared.
          const fires = t.condition === 'available' ? (tr.transition === 'appeared' || tr.transition === 'advanced') : tr.transition === 'disappeared';
          if (!fires) continue;
          if (!updateRowMatches(t, tr)) continue;
          try {
            await handleUpdateTransition(rule, t, deviceId, pluginId, tr, scopeDev.name, nowMs);
          } catch (err) {
            // eslint-disable-next-line no-console
            console.error(`[automations] updateAvailable handling for rule ${rule.id} failed:`, err);
          }
        }
      }
    }
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[automations] onUpdateTransitions failed:', err);
  }
}

/** Fires immediately or opens/refreshes/cancels the pending deferral window for one transition. */
async function handleUpdateTransition(
  rule: Automation,
  t: UpdateTrigger,
  deviceId: string,
  pluginId: string,
  tr: UpdateTransition,
  deviceName: string,
  nowMs: number
): Promise<void> {
  const snapshot: PendingUpdateSnapshot = {
    deviceId,
    pluginId,
    kind: tr.kind,
    name: tr.name,
    currentVersion: tr.currentVersion,
    latestVersion: tr.latestVersion,
    rebootRequired: tr.rebootRequired,
    applyActionId: tr.applyActionId ?? null,
    applyInput: tr.applyInput,
  };

  if (!t.defer) {
    // Immediate firing — cooldown has the same semantics as other event triggers.
    if (inCooldown(rule, nowMs)) return;
    await fireRule(rule, t, updateRunContext(deviceId, pluginId, tr), buildUpdateTriggerContext(t, deviceName, snapshot));
    return;
  }

  // Deferred — one pending window per (rule, trigger, update row).
  const key = updatePendingStateKey(deviceId, pluginId, tr.kind, tr.name);
  const existingRaw = await readState(rule.id, t.id, key);
  if (existingRaw) {
    let win: PendingUpdateWindow | null = null;
    try {
      const parsed = JSON.parse(existingRaw) as Partial<PendingUpdateWindow>;
      if (parsed && typeof parsed.sinceIso === 'string' && parsed.snapshot && typeof parsed.snapshot === 'object') win = parsed as PendingUpdateWindow;
    } catch { /* corrupt — replaced below */ }

    if (!win) {
      await writeState(rule.id, t.id, key, JSON.stringify({ sinceIso: new Date(nowMs).toISOString(), snapshot } satisfies PendingUpdateWindow));
      return;
    }

    if (tr.transition === 'disappeared') {
      if (t.condition === 'available') {
        // The update vanished while we waited — cancel the window silently.
        await writeState(rule.id, t.id, key, null);
        return;
      }
      win.snapshot = snapshot; // resolved + defer: refresh with last known state
    } else if (t.condition === 'resolved') {
      // The update came back while a "resolved" window was pending — stale, cancel.
      await writeState(rule.id, t.id, key, null);
      return;
    } else {
      win.snapshot = snapshot; // version advance: refresh snapshot, keep sinceIso (slot doesn't move)
    }
    await writeState(rule.id, t.id, key, JSON.stringify(win));
  } else {
    await writeState(rule.id, t.id, key, JSON.stringify({ sinceIso: new Date(nowMs).toISOString(), snapshot } satisfies PendingUpdateWindow));
  }
}

// ── Manual trigger + seeding (pre-existing updates) ───────────────────────────
// updateAvailable triggers fire only on TRANSITIONS (appeared/advanced) detected at
// telemetry ingest. Two consequences this section addresses:
//   1. A rule created/enabled AFTER an update row already exists never sees a
//      transition for it — seedPendingUpdateWindows() opens the deferral windows
//      for currently-available rows so the schedule picks them up.
//   2. The manual trigger (POST /automations/:id/test) has no transition event at
//      all — manualTriggerRule() resolves CURRENTLY available rows and fires once
//      per row, which is what `resolveFromTrigger: "update"` actions need.

/** Parses a device_updates.applyInput JSON column into an object, or undefined. */
function parseApplyInputColumn(raw: string | null): Record<string, unknown> | undefined {
  if (!raw) return undefined;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Resolves the CURRENTLY available device_updates rows that match this rule's
 * updateAvailable trigger (pluginId, scope, kinds/names/namePattern/rebootRequired).
 * `condition` is not part of the match — it selects transitions, not rows.
 */
async function resolveLiveUpdateRows(rule: Automation, t: UpdateTrigger): Promise<PendingUpdateSnapshot[]> {
  const [rows, deviceRows] = await Promise.all([
    db.query.deviceUpdates.findMany(),
    db.query.devices.findMany(),
  ]);
  const devicesById = new Map(deviceRows.map((d) => [d.id, toScopeDevice(d)]));
  const out: PendingUpdateSnapshot[] = [];
  for (const r of rows) {
    if (t.pluginId && r.pluginId !== t.pluginId) continue;
    const dev = devicesById.get(r.deviceId);
    if (!dev || !scopeMatchesDevice(t.scope, dev)) continue;
    if (!updateRowMatches(t, { kind: r.kind, name: r.name, currentVersion: r.currentVersion, latestVersion: r.latestVersion, rebootRequired: r.rebootRequired })) continue;
    out.push({
      deviceId: r.deviceId,
      pluginId: r.pluginId,
      kind: r.kind,
      name: r.name,
      currentVersion: r.currentVersion,
      latestVersion: r.latestVersion,
      rebootRequired: r.rebootRequired,
      applyActionId: r.applyActionId ?? null,
      applyInput: parseApplyInputColumn(r.applyInput),
    });
  }
  return out;
}

/**
 * Manually runs a rule's actions once (POST /automations/:id/test). A manual run is
 * an explicit "do it now" intent — defer schedules are bypassed. updateAvailable
 * triggers resolve the currently available rows and fire the rule ONCE PER ROW
 * (the row becomes ctx.update, which `resolveFromTrigger: "update"` actions need);
 * with no matching rows the rule runs once with a bare context so non-update
 * actions can still be verified and the run row records what happened. Other
 * trigger types run once each as before. Never throws — failures land on the run rows.
 */
export async function manualTriggerRule(rule: Automation): Promise<void> {
  const deviceRows = await db.query.devices.findMany();
  const namesById = new Map(deviceRows.map((d) => [d.id, d.name]));

  for (const t of rule.triggers) {
    if (t.type !== 'updateAvailable') {
      await fireRule(rule, t, { kind: 'test', triggerType: t.type }, { trigger: t });
      continue;
    }
    const snaps = await resolveLiveUpdateRows(rule, t);
    if (snaps.length === 0) {
      // Nothing available right now — bare context so update actions fail with the
      // clear "no update row" error instead of silently doing nothing.
      await fireRule(rule, t, { kind: 'test', triggerType: t.type }, { trigger: t });
      continue;
    }
    for (const snap of snaps) {
      // A manual apply supersedes any pending deferral window for this row — clear it
      // so the scheduled slot doesn't double-apply later.
      await writeState(rule.id, t.id, updatePendingStateKey(snap.deviceId, snap.pluginId, snap.kind, snap.name), null);
      await fireRule(
        rule,
        t,
        updateRunContext(snap.deviceId, snap.pluginId, { kind: snap.kind, name: snap.name, transition: 'appeared', currentVersion: snap.currentVersion, latestVersion: snap.latestVersion, rebootRequired: snap.rebootRequired }),
        buildUpdateTriggerContext(t, namesById.get(snap.deviceId) ?? null, snap),
      );
    }
  }
}

/** One simulated firing (dry run): the trigger context + every action's predicted outcome. */
export interface SimulatedFiring {
  /** The trigger block this firing is for. */
  trigger: TriggerBlock;
  /** Human label — e.g. "update web09" or "schedule". */
  label: string;
  actions: SimulatedAction[];
}

/**
 * Dry-runs a rule WITHOUT executing anything (POST /automations/:id/dry-run).
 * Mirrors manualTriggerRule's context construction exactly — updateAvailable
 * triggers resolve the CURRENTLY available rows and produce one simulated firing
 * per row, other triggers produce one bare-context firing each — but every action
 * goes through simulateAction() instead of executeAction(). Intent actions build a
 * real plan (the deterministic plugin /plan call) to report its exact steps, then
 * tear it down. No run rows are written, no windows touched, nothing enqueued.
 */
export async function dryRunRule(rule: Automation): Promise<SimulatedFiring[]> {
  const deviceRows = await db.query.devices.findMany();
  const namesById = new Map(deviceRows.map((d) => [d.id, d.name]));

  const out: SimulatedFiring[] = [];
  for (const t of rule.triggers) {
    if (t.type !== 'updateAvailable') {
      const ctx: TriggerContext = { trigger: t };
      out.push({
        trigger: t,
        label: t.type === 'schedule' ? `schedule (${(t as ScheduleTrigger).schedule.kind})` : t.type,
        actions: await Promise.all(rule.actions.map((a) => simulateAction(rule.id, rule.name, a, ctx))),
      });
      continue;
    }

    const snaps = await resolveLiveUpdateRows(rule, t);
    if (snaps.length === 0) {
      // Nothing available right now — one bare firing so the UI can show what would
      // happen to non-update actions and that update actions have no row to apply.
      out.push({
        trigger: t,
        label: 'updateAvailable (no updates currently available)',
        actions: await Promise.all(rule.actions.map((a) => simulateAction(rule.id, rule.name, a, { trigger: t }))),
      });
      continue;
    }

    for (const snap of snaps) {
      const ctx = buildUpdateTriggerContext(t, namesById.get(snap.deviceId) ?? null, snap);
      out.push({
        trigger: t,
        label: `update ${snap.name} (${namesById.get(snap.deviceId) ?? snap.deviceId})`,
        actions: await Promise.all(rule.actions.map((a) => simulateAction(rule.id, rule.name, a, ctx))),
      });
    }
  }
  return out;
}

/**
 * Seeds deferral windows for updates that are ALREADY available when a rule is
 * created or enabled. Without this, a new rule would never pick up rows that predate it
 * (no transition fires for them) and its defer schedule would have nothing to fire
 * against. Idempotent — existing windows keep their original anchor (sinceIso). Only
 * deferred triggers are seeded: immediate triggers fire on the next transition as
 * before, and firing every currently-available row instantly at create time would be
 * surprising. Never throws — seeding is best-effort by contract.
 */
export async function seedPendingUpdateWindows(rule: Automation): Promise<void> {
  for (const t of rule.triggers) {
    if (t.type !== 'updateAvailable' || !t.defer) continue;
    try {
      const snaps = await resolveLiveUpdateRows(rule, t);
      // One anchor per seeding event — all windows opened here share sinceIso so a
      // single schedule slot covers the whole batch.
      const sinceIso = new Date().toISOString();
      for (const snap of snaps) {
        const key = updatePendingStateKey(snap.deviceId, snap.pluginId, snap.kind, snap.name);
        if (await readState(rule.id, t.id, key)) continue; // window already open — keep its anchor
        await writeState(rule.id, t.id, key, JSON.stringify({ sinceIso, snapshot: snap } satisfies PendingUpdateWindow));
      }
    } catch (err) {
      console.error(`[automations] seeding pending update windows for rule ${rule.id} failed:`, err);
    }
  }
}

/** One evaluator tick over all pending deferral windows of the given rules. */
async function evaluatePendingUpdateWindows(rules: Automation[], nowMs: number): Promise<void> {
  const deviceRows = await db.query.devices.findMany();
  const namesById = new Map(deviceRows.map((d) => [d.id, d.name]));

  for (const rule of rules) {
    if (!rule.enabled) continue;
    for (const t of rule.triggers) {
      if (t.type !== 'updateAvailable' || !t.defer) continue;
      try {
        await evaluateOnePendingUpdateTrigger(rule, t, namesById, nowMs);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error(`[automations] pending update window evaluation for rule ${rule.id} failed:`, err);
      }
    }
  }
}

/** Checks every pending window of one deferred trigger; fires the due ones. */
async function evaluateOnePendingUpdateTrigger(
  rule: Automation,
  t: UpdateTrigger,
  namesById: Map<string, string>,
  nowMs: number
): Promise<void> {
  if (!t.defer) return; // only deferred triggers keep pending windows
  const rows = await db.query.automationState.findMany({
    where: and(eq(schema.automationState.automationId, rule.id), eq(schema.automationState.triggerId, t.id)),
  });

  for (const row of rows) {
    if (!row.stateKey.startsWith('pending:')) continue;
    let win: PendingUpdateWindow | null = null;
    try {
      const parsed = JSON.parse(row.value) as Partial<PendingUpdateWindow>;
      if (parsed && typeof parsed.sinceIso === 'string' && parsed.snapshot && typeof parsed.snapshot === 'object') win = parsed as PendingUpdateWindow;
    } catch { /* corrupt row — drop it */ }
    if (!win) {
      await writeState(rule.id, t.id, row.stateKey, null);
      continue;
    }

    // An 'available' window whose update row vanished (applied/withdrawn) is cancelled silently.
    if (t.condition === 'available') {
      const stillThere = await db.query.deviceUpdates.findFirst({
        where: and(
          eq(schema.deviceUpdates.deviceId, win.snapshot.deviceId),
          eq(schema.deviceUpdates.pluginId, win.snapshot.pluginId),
          eq(schema.deviceUpdates.kind, win.snapshot.kind),
          eq(schema.deviceUpdates.name, win.snapshot.name)
        ),
      });
      if (!stillThere) {
        await writeState(rule.id, t.id, row.stateKey, null);
        continue;
      }
    }

    const state = pendingWindowState(t.defer, win.sinceIso, nowMs);
    if (state === 'pending') continue; // not due yet — keep waiting

    // Due (or max-wait exceeded) but the rule is in cooldown: keep the window and
    // retry next tick — the slot anchor (sinceIso) doesn't move.
    if (inCooldown(rule, nowMs)) continue;

    await fireRule(
      rule,
      t,
      updateRunContext(win.snapshot.deviceId, win.snapshot.pluginId, { kind: win.snapshot.kind, name: win.snapshot.name, transition: 'appeared', currentVersion: win.snapshot.currentVersion, latestVersion: win.snapshot.latestVersion, rebootRequired: win.snapshot.rebootRequired }),
      buildUpdateTriggerContext(t, namesById.get(win.snapshot.deviceId) ?? null, win.snapshot)
    );
    await writeState(rule.id, t.id, row.stateKey, null); // fired — clear the window
  }
}

/** Deletes run rows older than the retention window (hourly, index-served). */
async function sweepOldRuns(): Promise<void> {
  const cutoff = new Date(Date.now() - RUN_RETENTION_DAYS * 86_400_000).toISOString();
  await db.delete(schema.automationRuns).where(lt(schema.automationRuns.firedAt, cutoff));
}

/**
 * Starts the automation evaluator loop (leader-gated like every other worker).
 * Returns a stop function for graceful shutdown / step-down.
 */
export function startAutomationEvaluatorWorker(): () => void {
  initWorker('automationEvaluator', LEADER_KEYS.automationEvaluator);
  // eslint-disable-next-line no-console
  console.log(`[automations] evaluator started, scanning every ${TICK_INTERVAL_MS / 1000}s`);

  let chain: Promise<void> = Promise.resolve();
  const timer = setInterval(() => {
    chain = chain.then(() => trackBeat('automationEvaluator', () => tick())).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[automations] tick failed:', err);
    });
  }, TICK_INTERVAL_MS);

  return () => clearInterval(timer);
}
