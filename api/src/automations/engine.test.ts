/**
 * Unit tests for the automation engine's pure helpers (validation, schedule
 * math, metric conditions, scope matching, template rendering).
 */

import {
  evaluateMetricCondition,
  evaluateSchedules,
  isScheduleDue,
  nextScheduleRun,
  parseJsonField,
  previewSchedule,
  renderTemplate,
  scopeMatchesDevice,
  templateVarsFor,
  validateAutomationDraft,
} from './engine';
import type { AutomationDraft, MetricTrigger, ScheduleTrigger } from './types';

// ── Draft validation ─────────────────────────────────────────────────────────

const validDraft: AutomationDraft = {
  name: 'Test rule',
  triggers: [{ id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 5 } }],
  actions: [
    {
      id: 'a1',
      type: 'notification',
      severity: 'info',
      titleTemplate: 'Hello {{automation.name}}',
      messageTemplate: 'Fired at {{run.at}}',
    },
  ],
};

describe('validateAutomationDraft', () => {
  it('accepts a minimal valid draft', () => {
    expect(validateAutomationDraft(validDraft)).toEqual([]);
  });

  it('requires a name (≤200 chars)', () => {
    expect(validateAutomationDraft({ ...validDraft, name: '' })).toContain('name is required');
    expect(validateAutomationDraft({ ...validDraft, name: 'x'.repeat(201) })).toContain('name must be at most 200 characters');
  });

  it('requires at least one trigger and one action', () => {
    expect(validateAutomationDraft({ ...validDraft, triggers: [] })).toContain('at least one trigger is required');
    expect(validateAutomationDraft({ ...validDraft, actions: [] })).toContain('at least one action is required');
  });

  it('rejects invalid cron expressions but accepts valid ones', () => {
    const bad = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'schedule', schedule: { kind: 'cron', expr: 'not a cron' } }],
    });
    expect(bad.some((e) => e.includes('invalid cron'))).toBe(true);

    const good = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'schedule', schedule: { kind: 'cron', expr: '*/5 * * * *' } }],
    });
    expect(good).toEqual([]);
  });

  it('rejects interval < 1 and dailyAt with malformed time', () => {
    const badInterval = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 0 } }],
    });
    expect(badInterval.some((e) => e.includes('everyMinutes'))).toBe(true);

    const badDaily = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'schedule', schedule: { kind: 'dailyAt', time: '25:99' } }],
    });
    expect(badDaily.some((e) => e.includes('HH:MM'))).toBe(true);
  });

  it('validates metric triggers per mode', () => {
    const missingValue = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'metric', metricKey: 'cpu.load', mode: 'compare' } as never],
    });
    expect(missingValue.some((e) => e.includes('comparator'))).toBe(true);

    const badRegex = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'metric', metricKey: 'k', mode: 'regex', pattern: '[' } as never],
    });
    expect(badRegex.some((e) => e.includes('invalid regex'))).toBe(true);

    const good = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'metric', metricKey: 'cpu.load', mode: 'compare', comparator: '>', value: 80 } as never],
    });
    expect(good).toEqual([]);
  });

  it('validates log and deviceStatus triggers', () => {
    const badLog = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'log', source: 'plugin', pattern: '[', levels: ['nope'] } as never],
    });
    expect(badLog.some((e) => e.includes('invalid regex'))).toBe(true);
    expect(badLog.some((e) => e.includes('unknown log level'))).toBe(true);

    const badStatus = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'deviceStatus', toStatuses: ['asleep'] } as never],
    });
    expect(badStatus.some((e) => e.includes('unknown device status'))).toBe(true);

    const good = validateAutomationDraft({
      ...validDraft,
      triggers: [{ id: 't1', type: 'deviceStatus', toStatuses: ['offline'] } as never],
    });
    expect(good).toEqual([]);
  });

  it('validates action blocks per type', () => {
    const badWebhook = validateAutomationDraft({
      ...validDraft,
      actions: [{ id: 'a1', type: 'webhook', url: 'ftp://x' } as never],
    });
    expect(badWebhook.some((e) => e.includes('http(s)'))).toBe(true);

    const badIntent = validateAutomationDraft({
      ...validDraft,
      actions: [{ id: 'a1', type: 'intent', pluginId: '' } as never],
    });
    expect(badIntent.some((e) => e.includes('pluginId is required'))).toBe(true);

    const badInternal = validateAutomationDraft({
      ...validDraft,
      actions: [{ id: 'a1', type: 'internal', kind: 'replicationSync' } as never],
    });
    expect(badInternal.some((e) => e.includes('targetId is required'))).toBe(true);

    const good = validateAutomationDraft({
      ...validDraft,
      actions: [{ id: 'a1', type: 'internal', kind: 'backup', preset: 'config' } as never],
    });
    expect(good).toEqual([]);
  });

  it('rejects duplicate trigger/action ids and bad cooldownSec', () => {
    const dup = validateAutomationDraft({
      ...validDraft,
      triggers: [
        { id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 5 } },
        { id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 6 } },
      ],
    });
    expect(dup.some((e) => e.includes('duplicate trigger id'))).toBe(true);

    const badCooldown = validateAutomationDraft({ ...validDraft, cooldownSec: -1 });
    expect(badCooldown.some((e) => e.includes('cooldownSec'))).toBe(true);
  });
});

// ── Schedule math ────────────────────────────────────────────────────────────

describe('nextScheduleRun / isScheduleDue', () => {
  const T0 = '2026-10-18T12:00:30.000Z';

  it('computes the next cron occurrence after the anchor', () => {
    expect(nextScheduleRun({ kind: 'cron', expr: '*/5 * * * *' }, T0)?.toISOString()).toBe('2026-10-18T12:05:00.000Z');
  });

  it('computes interval runs as anchor + everyMinutes', () => {
    expect(nextScheduleRun({ kind: 'interval', everyMinutes: 5 }, T0)?.toISOString()).toBe('2026-10-18T12:05:30.000Z');
  });

  it('computes dailyAt in local time, rolling to the next day when passed (TZ-independent)', () => {
    const anchor = new Date(T0); // 12:00:30 UTC — wall-clock hour depends on TZ, so assert properties

    // Anchor's LOCAL wall-clock time decides same-day vs next-day.
    const localHour = anchor.getHours();
    const afterNoon = localHour >= 15; // is the anchor past 15:00 local?

    const at15 = nextScheduleRun({ kind: 'dailyAt', time: '15:00' }, T0)!;
    expect(at15.getHours()).toBe(15);
    expect(at15.getMinutes()).toBe(0);
    expect(at15.getTime()).toBeGreaterThan(anchor.getTime()); // strictly after the anchor
    expect(at15.getTime()).toBeLessThanOrEqual(anchor.getTime() + 24 * 3600_000); // within one day
    if (afterNoon) {
      expect(at15.getDate()).toBe(new Date(anchor.getTime() + 86_400_000).getDate()); // rolled to next local day
    } else {
      expect(at15.getDate()).toBe(anchor.getDate()); // same local day
    }

    const at0930 = nextScheduleRun({ kind: 'dailyAt', time: '09:30' }, T0)!;
    expect(at0930.getHours()).toBe(9);
    expect(at0930.getMinutes()).toBe(30);
    expect(at0930.getTime()).toBeGreaterThan(anchor.getTime());
  });

  it('returns null for invalid cron expressions', () => {
    expect(nextScheduleRun({ kind: 'cron', expr: 'garbage' }, T0)).toBeNull();
  });

  it('is due when the next run is at or before now (run-asap after downtime)', () => {
    const trigger: ScheduleTrigger = { id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 5 } };
    // anchor 12:00:30 → next 12:05:30; now 12:06 → due
    expect(isScheduleDue(trigger, T0, new Date('2026-10-18T12:06:00Z').getTime())).toBe(true);
    // now 12:04 → not yet
    expect(isScheduleDue(trigger, T0, new Date('2026-10-18T12:04:00Z').getTime())).toBe(false);
  });

  it('uses createdAt as anchor when the rule never fired', () => {
    const trigger: ScheduleTrigger = { id: 't1', type: 'schedule', schedule: { kind: 'interval', everyMinutes: 5 } };
    // created at 12:00:30, now 12:06 → due on first tick after the interval elapsed
    expect(isScheduleDue(trigger, null, new Date('2026-10-18T12:06:00Z').getTime())).toBe(true);
  });

  it('previewSchedule returns consecutive occurrences', () => {
    const runs = previewSchedule({ kind: 'cron', expr: '*/5 * * * *' }, 3, T0);
    expect(runs).toEqual(['2026-10-18T12:05:00.000Z', '2026-10-18T12:10:00.000Z', '2026-10-18T12:15:00.000Z']);
  });
});
describe('evaluateSchedules', () => {
  const rule = (over: Partial<{ id: string; name: string; enabled: boolean; cooldownSec: number; lastFiredAt: string | null; createdAt: string }> = {}) => ({
    id: over.id ?? 'r1',
    name: over.name ?? 'Rule',
    enabled: over.enabled ?? true,
    cooldownSec: over.cooldownSec ?? 0,
    lastFiredAt: over.lastFiredAt !== undefined ? over.lastFiredAt : null,
    createdAt: over.createdAt ?? '2026-10-18T12:00:30.000Z',
    triggers: [{ id: 't1', type: 'schedule' as const, schedule: { kind: 'interval' as const, everyMinutes: 5 } }],
  });

  it('fires a fresh interval rule once its first interval has elapsed (anchor = createdAt)', () => {
    const due = evaluateSchedules([rule()], new Date('2026-10-18T12:06:00Z').getTime());
    expect(due).toHaveLength(1);
    expect(due[0].ruleId).toBe('r1');
  });

  it('does not fire before the first interval elapsed', () => {
    expect(evaluateSchedules([rule()], new Date('2026-10-18T12:04:00Z').getTime())).toHaveLength(0);
  });

  it('re-fires on subsequent intervals after lastFiredAt advances (anchor = lastFiredAt)', () => {
    const fired = rule({ lastFiredAt: '2026-10-18T12:05:30.000Z' }); // next due 12:10:30
    expect(evaluateSchedules([fired], new Date('2026-10-18T12:09:00Z').getTime())).toHaveLength(0);
    expect(evaluateSchedules([fired], new Date('2026-10-18T12:11:00Z').getTime())).toHaveLength(1);
  });

  it('skips disabled rules', () => {
    expect(evaluateSchedules([rule({ enabled: false })], new Date('2026-10-18T12:30:00Z').getTime())).toHaveLength(0);
  });

  it('respects cooldownSec against the last firing of any trigger', () => {
    const r = rule({ lastFiredAt: '2026-10-18T12:05:30.000Z', cooldownSec: 600 }); // next due 12:10:30, but cooldown until 12:15:30
    expect(evaluateSchedules([r], new Date('2026-10-18T12:11:00Z').getTime())).toHaveLength(0); // due but cooling down
    expect(evaluateSchedules([r], new Date('2026-10-18T12:16:00Z').getTime())).toHaveLength(1); // cooldown over, still due (run-asap)
  });

  it('ignores non-schedule triggers', () => {
    const r = rule();
    r.triggers.push({ id: 't2', type: 'deviceStatus', toStatuses: ['offline'] } as never);
    expect(evaluateSchedules([r], new Date('2026-10-18T12:30:00Z').getTime())).toHaveLength(1); // only the schedule one
  });
});
// ── Metric conditions ────────────────────────────────────────────────────────

describe('evaluateMetricCondition', () => {
  const cmp = (comparator: string, value: number | string): MetricTrigger =>
    ({ id: 't1', type: 'metric', metricKey: 'k', mode: 'compare', comparator, value } as never);

  it('evaluates numeric comparators', () => {
    expect(evaluateMetricCondition(cmp('>', 80), 90)).toBe(true);
    expect(evaluateMetricCondition(cmp('>', 80), 80)).toBe(false);
    expect(evaluateMetricCondition(cmp('>=', 80), 80)).toBe(true);
    expect(evaluateMetricCondition(cmp('<', 10), 5)).toBe(true);
    expect(evaluateMetricCondition(cmp('<=', 10), 10)).toBe(true);
    expect(evaluateMetricCondition(cmp('=', 42), 42)).toBe(true);
    expect(evaluateMetricCondition(cmp('!=', 42), 43)).toBe(true);
  });

  it('accepts numeric strings as the target value', () => {
    const t = cmp('>', '80');
    expect(evaluateMetricCondition(t, 90)).toBe(true);
  });

  it('never matches null/undefined or non-numeric values in compare mode', () => {
    expect(evaluateMetricCondition(cmp('>', 0), null)).toBe(false);
    expect(evaluateMetricCondition(cmp('>', 0), 'high')).toBe(false);
  });

  it('evaluates regex mode with search semantics on strings only', () => {
    const re = (pattern: string): MetricTrigger => ({ id: 't1', type: 'metric', metricKey: 'k', mode: 'regex', pattern } as never);
    expect(evaluateMetricCondition(re('^error'), 'error: disk full')).toBe(true);
    expect(evaluateMetricCondition(re('warn|crit'), 'CRIT is uppercase — no lowercase match here')).toBe(false);
    expect(evaluateMetricCondition(re('disk'), 'disk full')).toBe(true); // search, not match-all
    expect(evaluateMetricCondition(re('.*'), 42)).toBe(false); // numbers don't match in regex mode
    expect(evaluateMetricCondition(re('['), 'x')).toBe(false); // invalid pattern → false, no throw
  });
});

// ── Scope matching ───────────────────────────────────────────────────────────

describe('scopeMatchesDevice', () => {
  const dev = (over: Partial<{ id: string; siteId: string | null; tags: string[] | null }> = {}) => ({
    id: over.id ?? 'd1',
    siteId: over.siteId !== undefined ? over.siteId : 's1',
    tags: over.tags !== undefined ? over.tags : ['edge'],
  });

  it('empty or absent scope matches everything', () => {
    expect(scopeMatchesDevice(undefined, dev())).toBe(true);
    expect(scopeMatchesDevice({}, dev())).toBe(true);
    expect(scopeMatchesDevice({ siteIds: [], tags: [], deviceIds: [] }, dev())).toBe(true);
  });

  it('matches by any of the provided lists (OR semantics)', () => {
    expect(scopeMatchesDevice({ siteIds: ['s1'] }, dev())).toBe(true);
    expect(scopeMatchesDevice({ tags: ['edge'] }, dev())).toBe(true);
    expect(scopeMatchesDevice({ deviceIds: ['d1'] }, dev())).toBe(true);
    // one list matches even though the others do not
    expect(scopeMatchesDevice({ siteIds: ['other'], tags: ['edge'] }, dev())).toBe(true);
  });

  it('does not match when no list matches', () => {
    expect(scopeMatchesDevice({ siteIds: ['s2'], tags: ['core'], deviceIds: ['d9'] }, dev())).toBe(false);
  });

  it('handles null siteId/tags gracefully', () => {
    const bare = dev({ id: 'd2', siteId: null, tags: null });
    expect(scopeMatchesDevice({ siteIds: ['s1'], tags: ['edge'] }, bare)).toBe(false);
    expect(scopeMatchesDevice({ deviceIds: ['d2'] }, bare)).toBe(true);
  });
});

// ── Template rendering ───────────────────────────────────────────────────────

describe('renderTemplate / templateVarsFor', () => {
  it('substitutes known tokens and leaves unknown ones literal', () => {
    const vars = templateVarsFor('Nightly check', {
      triggerType: 'metric',
      device: { name: 'GWBN01', address: '192.168.1.1' },
      metricKey: 'cpu.load',
      metricValue: 97,
      firedAtIso: '2026-10-18T12:00:00Z',
    });
    const out = renderTemplate('{{device.name}} at {{metric.value}}% ({{automation.name}}, {{trigger.type}}) — {{run.at}} [{{unknown.token}}]', vars);
    expect(out).toBe('GWBN01 at 97% (Nightly check, metric) — 2026-10-18T12:00:00Z [{{unknown.token}}]');
  });

  it('omits device/metric/log tokens when the context has none', () => {
    const vars = templateVarsFor('X', { triggerType: 'schedule', firedAtIso: 't' });
    expect(renderTemplate('{{device.name}}|{{log.message}}', vars)).toBe('{{device.name}}|{{log.message}}');
  });

  it('renders log message tokens for log triggers', () => {
    const vars = templateVarsFor('X', { triggerType: 'log', logMessage: 'auth failure from 10.0.0.5', firedAtIso: 't' });
    expect(renderTemplate('{{log.message}}', vars)).toBe('auth failure from 10.0.0.5');
  });

  it('returns empty string for non-string templates and never throws', () => {
    expect(renderTemplate(undefined as never, {})).toBe('');
    expect(renderTemplate('', {})).toBe('');
  });
});

// ── Row parsing ──────────────────────────────────────────────────────────────

describe('parseJsonField', () => {
  it('parses valid JSON and falls back on null/garbage', () => {
    expect(parseJsonField('[1,2]', [])).toEqual([1, 2]);
    expect(parseJsonField(null, 'fallback')).toBe('fallback');
    expect(parseJsonField('{oops', 'fallback')).toBe('fallback');
    // JSON "null" → fallback (the ?? guard)
    expect(parseJsonField('null', 'fallback')).toBe('fallback');
  });
});
