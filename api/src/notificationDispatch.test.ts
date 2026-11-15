/**
 * Unit tests for the notification dispatch pure functions (rule filter
 * matching + template variable building). No database access — these are the
 * decision core of rule evaluation; delivery/cooldown paths need a live stack
 * and are covered by scripts/e2e-notification-dispatch.ts.
 */

// uuid v13+ ships ESM-only dist — jest (CJS) can't require it; the functions
// under test never call it, so a static stub is enough.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import { buildNotificationVars, NotificationRuleFilter, ruleMatches } from './notificationDispatch';

const ROW = { severity: 'warning', source: 'device', title: 'WAN link down', message: 'wan0 lost carrier since 12:03' };

const DEVICE = {
  name: 'OPNSENSE01',
  address: '192.168.1.1',
  vendor: 'opnsense',
  tags: ['edge', 'wan'],
  deviceTypes: ['router', 'firewall'],
  siteName: 'HQ',
  status: 'down',
};

describe('ruleMatches', () => {
  it('matches everything with an empty filter (no device)', () => {
    expect(ruleMatches({}, ROW, null)).toBe(true);
  });

  it('applies the severity allow-list', () => {
    expect(ruleMatches({ severities: ['warning'] }, ROW, null)).toBe(true);
    expect(ruleMatches({ severities: ['critical'] }, ROW, null)).toBe(false);
    expect(ruleMatches({ severities: ['info', 'warning'] }, ROW, null)).toBe(true);
  });

  it('applies the source allow-list', () => {
    expect(ruleMatches({ sources: ['device'] }, ROW, null)).toBe(true);
    expect(ruleMatches({ sources: ['system'] }, ROW, null)).toBe(false);
  });

  it('treats empty/whitespace list entries as unconstrained', () => {
    const filter: NotificationRuleFilter = { severities: ['', '   '] };
    expect(ruleMatches(filter, ROW, null)).toBe(true);
  });

  it('deviceTags are any-match and require a device row', () => {
    expect(ruleMatches({ deviceTags: ['edge'] }, ROW, DEVICE)).toBe(true);
    expect(ruleMatches({ deviceTags: ['lab'] }, ROW, DEVICE)).toBe(false);
    expect(ruleMatches({ deviceTags: ['edge'] }, ROW, null)).toBe(false);
  });

  it('vendors match case-insensitively and exactly', () => {
    expect(ruleMatches({ vendors: ['OPNsense'] }, ROW, DEVICE)).toBe(true);
    expect(ruleMatches({ vendors: ['opnsense'] }, ROW, DEVICE)).toBe(true);
    expect(ruleMatches({ vendors: ['mikrotik'] }, ROW, DEVICE)).toBe(false);
  });

  it('deviceTypes are any-match and case-insensitive', () => {
    expect(ruleMatches({ deviceTypes: ['Router'] }, ROW, DEVICE)).toBe(true);
    expect(ruleMatches({ deviceTypes: ['switch'] }, ROW, DEVICE)).toBe(false);
  });

  it('title/message regexes are case-insensitive', () => {
    expect(ruleMatches({ titleRegex: 'LINK DOWN' }, ROW, null)).toBe(true);
    expect(ruleMatches({ messageRegex: 'carrier' }, ROW, null)).toBe(true);
    expect(ruleMatches({ messageRegex: 'CARRIER' }, ROW, null)).toBe(true);
    expect(ruleMatches({ messageRegex: 'never-mentioned' }, ROW, null)).toBe(false);
    expect(ruleMatches({ titleRegex: '^never-matches$' }, ROW, null)).toBe(false);
  });

  it('treats an invalid regex as unconstrained (warn + pass)', () => {
    const warn = jest.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect(ruleMatches({ titleRegex: '[unclosed' }, ROW, null)).toBe(true);
    warn.mockRestore();
  });

  it('ANDs all dimensions together', () => {
    const ok: NotificationRuleFilter = { severities: ['warning'], sources: ['device'], vendors: ['opnsense'], deviceTags: ['wan'] };
    expect(ruleMatches(ok, ROW, DEVICE)).toBe(true);
    // Same filter, wrong vendor → no match.
    expect(ruleMatches(ok, ROW, { ...DEVICE, vendor: 'mikrotik' })).toBe(false);
  });
});

describe('buildNotificationVars', () => {
  const NROW = {
    title: 'WAN link down',
    message: 'wan0 lost carrier since 12:03',
    severity: 'critical',
    source: 'device',
    status: 'open',
    createdAt: '2026-01-01T12:04:00Z',
    lastSeenAt: '2026-01-01T12:30:00Z',
    occurrences: 5,
  };

  it('exposes all notification tokens (occurrences stringified)', () => {
    const vars = buildNotificationVars(NROW, null, null, null);
    expect(vars['notification.title']).toBe('WAN link down');
    expect(vars['notification.message']).toBe('wan0 lost carrier since 12:03');
    expect(vars['notification.severity']).toBe('critical');
    expect(vars['notification.source']).toBe('device');
    expect(vars['notification.status']).toBe('open');
    expect(vars['notification.createdAt']).toBe('2026-01-01T12:04:00Z');
    expect(vars['notification.lastSeenAt']).toBe('2026-01-01T12:30:00Z');
    expect(vars['notification.occurrences']).toBe('5');
  });

  it('adds device tokens only when a device is present', () => {
    const withDevice = buildNotificationVars(NROW, DEVICE, null, null);
    expect(withDevice['device.name']).toBe('OPNSENSE01');
    expect(withDevice['device.address']).toBe('192.168.1.1');
    expect(withDevice['device.vendor']).toBe('opnsense');
    expect(withDevice['device.tags']).toBe('edge, wan');
    expect(withDevice['device.types']).toBe('router, firewall');
    expect(withDevice['device.site']).toBe('HQ');
    expect(withDevice['device.status']).toBe('down');

    const without = buildNotificationVars(NROW, null, null, null);
    expect(without['device.name']).toBeUndefined();
  });

  it('omits empty device sub-fields (no address/tags/site)', () => {
    const sparse = buildNotificationVars(
      NROW,
      { name: 'X', address: null, vendor: 'generic', tags: [], deviceTypes: ['host'], siteName: null, status: 'ok' },
      null,
      null,
    );
    expect(sparse['device.address']).toBeUndefined();
    expect(sparse['device.tags']).toBeUndefined();
    expect(sparse['device.site']).toBeUndefined();
    expect(sparse['device.types']).toBe('host');
  });

  it('adds plugin.name only when known', () => {
    expect(buildNotificationVars(NROW, null, 'opnsense-plugin', null)['plugin.name']).toBe('opnsense-plugin');
    expect(buildNotificationVars(NROW, null, null, null)['plugin.name']).toBeUndefined();
  });

  it('flattens scalar context values under context.* and skips objects/nulls', () => {
    const vars = buildNotificationVars(NROW, null, null, { from: '10.0.0.1', to: '10.0.0.2', nested: { a: 1 }, nothing: null });
    expect(vars['context.from']).toBe('10.0.0.1');
    expect(vars['context.to']).toBe('10.0.0.2');
    expect(vars['context.nested']).toBeUndefined();
    expect(vars['context.nothing']).toBeUndefined();
  });
});
