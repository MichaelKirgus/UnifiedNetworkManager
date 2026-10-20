/**
 * Actions & Schedules — pure evaluation helpers (no DB, no I/O).
 *
 * Everything the automation worker needs to DECIDE is here and unit-tested:
 * draft validation, schedule due-checks / next-run math, metric condition
 * evaluation, device-scope matching and {{…}} template rendering. The worker
 * (workers/automations.ts) owns the I/O — reading rows, writing runs/state —
 * and delegates every judgment to these functions so the logic stays testable
 * without a database.
 */

import { CronExpressionParser } from 'cron-parser';
import type {
  ActionBlock,
  AutomationDraft,
  DeviceScope,
  MetricTrigger,
  ScheduleSpec,
  TriggerBlock,
} from './types';
import { DEVICE_STATUSES, LOG_LEVELS, METRIC_COMPARATORS, NOTIFICATION_SEVERITIES, BACKUP_PRESETS } from './types';

// ── Draft validation ─────────────────────────────────────────────────────────

/** Returns a list of human-readable problems (empty = valid draft). */
export function validateAutomationDraft(draft: AutomationDraft): string[] {
  const errors: string[] = [];

  if (!draft || typeof draft.name !== 'string' || !draft.name.trim()) {
    errors.push('name is required');
  } else if (draft.name.length > 200) {
    errors.push('name must be at most 200 characters');
  }

  if (typeof draft.cooldownSec === 'number' && (!Number.isInteger(draft.cooldownSec) || draft.cooldownSec < 0)) {
    errors.push('cooldownSec must be a non-negative integer');
  }

  const triggerIds = new Set<string>();
  if (!Array.isArray(draft.triggers) || draft.triggers.length === 0) {
    errors.push('at least one trigger is required');
  } else {
    for (const [i, t] of draft.triggers.entries()) {
      const where = `triggers[${i}]`;
      if (!t || typeof t.id !== 'string' || !t.id) {
        errors.push(`${where}: id is required`);
        continue;
      }
      if (triggerIds.has(t.id)) errors.push(`${where}: duplicate trigger id "${t.id}"`);
      triggerIds.add(t.id);
      errors.push(...validateTrigger(t, where));
    }
  }

  const actionIds = new Set<string>();
  if (!Array.isArray(draft.actions) || draft.actions.length === 0) {
    errors.push('at least one action is required');
  } else {
    for (const [i, a] of draft.actions.entries()) {
      const where = `actions[${i}]`;
      if (!a || typeof a.id !== 'string' || !a.id) {
        errors.push(`${where}: id is required`);
        continue;
      }
      if (actionIds.has(a.id)) errors.push(`${where}: duplicate action id "${a.id}"`);
      actionIds.add(a.id);
      errors.push(...validateAction(a, where));
    }
  }

  return errors;
}

function validateTrigger(t: TriggerBlock, where: string): string[] {
  const e: string[] = [];
  switch (t.type) {
    case 'schedule': {
      const s = t.schedule;
      if (!s || typeof s !== 'object') return [`${where}: schedule is required`];
      if (s.kind === 'cron') {
        if (typeof s.expr !== 'string' || !s.expr.trim()) e.push(`${where}: cron expr is required`);
        else if (!isValidCronExpr(s.expr)) e.push(`${where}: invalid cron expression "${s.expr}"`);
      } else if (s.kind === 'interval') {
        if (!Number.isInteger(s.everyMinutes) || s.everyMinutes < 1) e.push(`${where}: everyMinutes must be an integer ≥ 1`);
        else if (s.everyMinutes > 525_600) e.push(`${where}: everyMinutes is capped at one year (525600)`);
      } else if (s.kind === 'dailyAt') {
        if (typeof s.time !== 'string' || !/^([01]\d|2[0-3]):[0-5]\d$/.test(s.time)) e.push(`${where}: dailyAt time must be "HH:MM" (24h)`);
      } else {
        e.push(`${where}: unknown schedule kind`);
      }
      break;
    }
    case 'metric': {
      if (!t.metricKey || typeof t.metricKey !== 'string') e.push(`${where}: metricKey is required`);
      if (t.mode === 'compare') {
        if (!METRIC_COMPARATORS.includes(t.comparator as never)) e.push(`${where}: comparator must be one of ${METRIC_COMPARATORS.join(', ')}`);
        if (t.value === undefined || t.value === null) e.push(`${where}: value is required for compare mode`);
      } else if (t.mode === 'regex') {
        if (!t.pattern || typeof t.pattern !== 'string') e.push(`${where}: pattern is required for regex mode`);
        else if (!isValidRegex(t.pattern)) e.push(`${where}: invalid regex "${t.pattern}"`);
      } else {
        e.push(`${where}: mode must be "compare" or "regex"`);
      }
      if (t.durationSec !== undefined && (!Number.isFinite(t.durationSec) || t.durationSec < 0)) e.push(`${where}: durationSec must be ≥ 0`);
      break;
    }
    case 'log': {
      if (t.source !== 'plugin' && t.source !== 'firewall') e.push(`${where}: source must be "plugin" or "firewall"`);
      if (!t.pattern || typeof t.pattern !== 'string') e.push(`${where}: pattern is required`);
      else if (!isValidRegex(t.pattern)) e.push(`${where}: invalid regex "${t.pattern}"`);
      if (t.levels && !Array.isArray(t.levels)) e.push(`${where}: levels must be an array`);
      else if (t.levels?.some((l) => !LOG_LEVELS.includes(l))) e.push(`${where}: unknown log level in levels`);
      break;
    }
    case 'deviceStatus': {
      if (!Array.isArray(t.toStatuses) || t.toStatuses.length === 0) e.push(`${where}: toStatuses must be a non-empty array`);
      else if (t.toStatuses.some((s) => !DEVICE_STATUSES.includes(s))) e.push(`${where}: unknown device status in toStatuses`);
      break;
    }
    default:
      e.push(`${where}: unknown trigger type`);
  }
  return e;
}

function validateAction(a: ActionBlock, where: string): string[] {
  const e: string[] = [];
  switch (a.type) {
    case 'intent': {
      if (!a.pluginId || typeof a.pluginId !== 'string') e.push(`${where}: pluginId is required`);
      if (!a.actionId || typeof a.actionId !== 'string') e.push(`${where}: actionId is required`);
      if (a.input !== undefined && (typeof a.input !== 'object' || Array.isArray(a.input) || a.input === null)) e.push(`${where}: input must be an object`);
      break;
    }
    case 'webhook': {
      if (!a.url || typeof a.url !== 'string') e.push(`${where}: url is required`);
      else if (!/^https?:\/\//i.test(a.url)) e.push(`${where}: url must be http(s)`);
      if (a.method && !['GET', 'POST', 'PUT', 'PATCH'].includes(a.method)) e.push(`${where}: method must be GET, POST, PUT or PATCH`);
      break;
    }
    case 'notification': {
      if (!NOTIFICATION_SEVERITIES.includes(a.severity)) e.push(`${where}: severity must be one of ${NOTIFICATION_SEVERITIES.join(', ')}`);
      if (typeof a.titleTemplate !== 'string' || !a.titleTemplate.trim()) e.push(`${where}: titleTemplate is required`);
      else if (a.titleTemplate.length > 300) e.push(`${where}: titleTemplate must be at most 300 characters`);
      if (typeof a.messageTemplate !== 'string') e.push(`${where}: messageTemplate is required`);
      else if (a.messageTemplate.length > 2000) e.push(`${where}: messageTemplate must be at most 2000 characters`);
      break;
    }
    case 'internal': {
      if (a.kind === 'backup') {
        if (a.preset !== undefined && !BACKUP_PRESETS.includes(a.preset)) e.push(`${where}: preset must be one of ${BACKUP_PRESETS.join(', ')}`);
        if (a.sections !== undefined && (!Array.isArray(a.sections) || a.sections.length === 0)) e.push(`${where}: sections must be a non-empty array`);
      } else if (a.kind === 'replicationSync') {
        if (!a.targetId || typeof a.targetId !== 'string') e.push(`${where}: targetId is required for replicationSync`);
      } else {
        e.push(`${where}: kind must be "backup" or "replicationSync"`);
      }
      break;
    }
    default:
      e.push(`${where}: unknown action type`);
  }
  return e;
}

function isValidCronExpr(expr: string): boolean {
  try {
    CronExpressionParser.parse(expr);
    return true;
  } catch {
    return false;
  }
}

function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

// ── Schedule math ────────────────────────────────────────────────────────────

/** Next occurrence of a schedule spec strictly after `afterIso` (or null). */
export function nextScheduleRun(spec: ScheduleSpec, afterIso: string): Date | null {
  const after = new Date(afterIso);
  if (Number.isNaN(after.getTime())) return null;
  switch (spec.kind) {
    case 'cron': {
      try {
        const it = CronExpressionParser.parse(spec.expr, { currentDate: after });
        return it.next().toDate();
      } catch {
        return null; // invalid expr — validation should have caught this at write time
      }
    }
    case 'interval':
      return new Date(after.getTime() + spec.everyMinutes * 60_000);
    case 'dailyAt': {
      const [h, m] = spec.time.split(':').map(Number);
      // Next local-time HH:MM strictly after `after`.
      const candidate = new Date(after);
      candidate.setHours(h, m, 0, 0);
      if (candidate.getTime() <= after.getTime()) candidate.setDate(candidate.getDate() + 1);
      return candidate;
    }
  }
}

/**
 * Is a schedule trigger due now? Anchor = lastFiredAt when the rule has fired
 * before, otherwise createdAt — so a freshly created interval rule fires on its
 * first tick, and a cron/daily rule that was missed while UNM was down fires on
 * the next tick (run-asap semantics, same as planScheduler). At most ONE firing
 * per scheduled slot: after firing, lastFiredAt moves past the slot.
 */
export function isScheduleDue(trigger: Extract<TriggerBlock, { type: 'schedule' }>, anchorIso: string | null, nowMs: number): boolean {
  const next = nextScheduleRun(trigger.schedule, anchorIso ?? new Date(0).toISOString());
  return next !== null && next.getTime() <= nowMs;
}

/** Upcoming occurrences for the UI's "next runs" preview. */
export function previewSchedule(spec: ScheduleSpec, count: number, fromIso?: string): string[] {
  const out: string[] = [];
  let cursor = fromIso ?? new Date().toISOString();
  for (let i = 0; i < Math.max(1, Math.min(count, 20)); i++) {
    const next = nextScheduleRun(spec, cursor);
    if (!next) break;
    out.push(next.toISOString());
    cursor = next.toISOString();
  }
  return out;
}

/** A rule row as the worker sees it (parsed triggers, raw schedule anchor). */
export interface ScheduleRule {
  id: string;
  name: string;
  enabled: boolean;
  cooldownSec: number;
  lastFiredAt: string | null; // ISO or null = never fired
  createdAt: string;
  triggers: TriggerBlock[];
}

/** A schedule trigger that is due to fire now. */
export interface DueSchedule {
  ruleId: string;
  ruleName: string;
  trigger: Extract<TriggerBlock, { type: 'schedule' }>;
}

/**
 * Which enabled rules have a schedule trigger due at `nowMs`? Anchor =
 * lastFiredAt (any trigger) when the rule has fired before, else createdAt —
 * so a fresh interval rule fires on its first tick and a cron/daily slot missed
 * while UNM was down fires run-asap. Cooldown is applied here too: a rule that
 * fired within `cooldownSec` of now is not due again (event-trigger throttle).
 */
export function evaluateSchedules(rules: ScheduleRule[], nowMs: number): DueSchedule[] {
  const out: DueSchedule[] = [];
  for (const rule of rules) {
    if (!rule.enabled) continue;
    // Cooldown — measured against the most recent firing of ANY trigger.
    if (rule.cooldownSec > 0 && rule.lastFiredAt) {
      const last = new Date(rule.lastFiredAt).getTime();
      if (Number.isFinite(last) && nowMs - last < rule.cooldownSec * 1000) continue;
    }
    for (const t of rule.triggers) {
      if (t.type !== 'schedule') continue;
      const anchor = rule.lastFiredAt ?? rule.createdAt;
      if (isScheduleDue(t, anchor, nowMs)) out.push({ ruleId: rule.id, ruleName: rule.name, trigger: t });
    }
  }
  return out;
}

// ── Metric condition evaluation ──────────────────────────────────────────────

/** Evaluates a metric trigger's condition against one observed value. */
export function evaluateMetricCondition(trigger: MetricTrigger, value: number | string | boolean | null): boolean {
  if (value === null || value === undefined) return false;
  if (trigger.mode === 'regex') {
    if (typeof value !== 'string' || !trigger.pattern) return false;
    try {
      return new RegExp(trigger.pattern).test(value);
    } catch {
      return false; // invalid pattern — validation should have caught it at write time
    }
  }
  // compare mode
  if (typeof value !== 'number' || !Number.isFinite(value)) return false;
  const target = typeof trigger.value === 'string' ? Number(trigger.value) : trigger.value;
  if (target === undefined || !Number.isFinite(target)) return false;
  switch (trigger.comparator) {
    case '>': return value > target;
    case '>=': return value >= target;
    case '<': return value < target;
    case '<=': return value <= target;
    case '=': return value === target;
    case '!=': return value !== target;
    default: return false;
  }
}

// ── Device scope matching ────────────────────────────────────────────────────

/** Minimal device shape the engine needs (avoids importing the DB schema). */
export interface ScopeDevice {
  id: string;
  siteId?: string | null;
  tags?: string[] | null;
}

/**
 * Does a device match a scope? "Any rule matches" semantics — same as user
 * deviceScope: empty/absent scope = every device. A device qualifies when it
 * matches ANY provided list (site, tag or explicit id).
 */
export function scopeMatchesDevice(scope: DeviceScope | undefined, device: ScopeDevice): boolean {
  if (!scope) return true;
  const siteIds = scope.siteIds ?? [];
  const tags = scope.tags ?? [];
  const deviceIds = scope.deviceIds ?? [];
  if (siteIds.length === 0 && tags.length === 0 && deviceIds.length === 0) return true; // empty scope = all
  if (deviceIds.includes(device.id)) return true;
  if (device.siteId && siteIds.includes(device.siteId)) return true;
  const deviceTags: string[] = Array.isArray(device.tags) ? device.tags : [];
  if (tags.some((t) => deviceTags.includes(t))) return true;
  return false;
}

// ── Template rendering ───────────────────────────────────────────────────────

/**
 * Renders {{…}} tokens in a template. Known keys are substituted; UNKNOWN or
 * missing values are left as the literal token (never throws, never blanks).
 * Keys: automation.name, trigger.type, device.name, device.address,
 * metric.key, metric.value, log.message, run.at — see TriggerContext.
 */
export function renderTemplate(template: string, vars: Record<string, string | number | boolean | null | undefined>): string {
  if (typeof template !== 'string') return '';
  return template.replace(/\{\{([\w.]+)\}\}/g, (match, key: string) => {
    const v = vars[key];
    if (v === undefined || v === null) return match; // leave literal
    return String(v);
  });
}

/** Builds the flat token map for a firing from its context. */
export function templateVarsFor(automationName: string, ctx: { triggerType: TriggerBlock['type']; device?: { name: string; address?: string | null } | null; metricKey?: string | null; metricValue?: number | string | boolean | null; logMessage?: string | null; firedAtIso: string }): Record<string, string> {
  const vars: Record<string, string> = {
    'automation.name': automationName,
    'trigger.type': ctx.triggerType,
    'run.at': ctx.firedAtIso,
  };
  if (ctx.device) {
    vars['device.name'] = ctx.device.name;
    if (ctx.device.address) vars['device.address'] = ctx.device.address;
  }
  if (ctx.metricKey !== undefined && ctx.metricKey !== null) {
    vars['metric.key'] = String(ctx.metricKey);
    if (ctx.metricValue !== undefined && ctx.metricValue !== null) vars['metric.value'] = String(ctx.metricValue);
  }
  if (ctx.logMessage) vars['log.message'] = ctx.logMessage;
  return vars;
}

// ── Row parsing ──────────────────────────────────────────────────────────────

/** Safely parses a stored JSON column (triggers/actions/context/planIds). */
export function parseJsonField<T>(raw: string | null | undefined, fallback: T): T {
  if (!raw) return fallback;
  try {
    const parsed = JSON.parse(raw);
    return (parsed ?? fallback) as T;
  } catch {
    return fallback;
  }
}
