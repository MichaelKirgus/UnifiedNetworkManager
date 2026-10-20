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
import { evaluateMetricCondition, evaluateSchedules, parseJsonField, scopeMatchesDevice } from '../automations/engine';
import type { Automation, DeviceStatus, LogTrigger, MetricTrigger, TriggerBlock, TriggerContext } from '../automations/types';
import { executeAction } from '../automations/actions';

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
  const errors: string[] = [];
  const planIds: string[] = [];

  for (const action of automation.actions) {
    try {
      const res = await executeAction(automation.id, automation.name, action, ctx);
      if (res.ok) okCount++;
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

  const status = failCount === 0 ? 'succeeded' : okCount === 0 ? 'failed' : 'partial';
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
