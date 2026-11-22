/**
 * Unit tests for the netfilter jail-log parser (pure logic — no HTTP).
 * Patterns are taken from a live 2026-11b instance (MAIL04).
 */

import {
  netfilterVendorEventId,
  newestNetfilterTimeSec,
  parseNetfilterEntry,
  selectFreshNetfilterEntries,
  toFirewallEventRows,
} from './netfilter';
import type { MailcowNetfilterLogEntry } from './client/mailcowClient';

const entry = (time: number, message: string): MailcowNetfilterLogEntry => ({ time, priority: 'warn', message });

describe('parseNetfilterEntry', () => {
  it('classifies brute-force pre-ban warnings and strips the CIDR suffix', () => {
    const p = parseNetfilterEntry(entry(1795362580, '9 more attempts in the next 600 seconds until 139.59.10.109/32 is banned'));
    expect(p).toEqual({
      reason: 'brute-force-pre-ban',
      srcIp: '139.59.10.109',
      ruleName: '9 more attempts in the next 600 seconds until 139.59.10.109/32 is banned',
    });
  });

  it('classifies pre-ban warnings without a CIDR suffix', () => {
    const p = parseNetfilterEntry(entry(1, '1 more attempt in the next 60 seconds until 10.0.0.5 is banned'));
    expect(p?.reason).toBe('brute-force-pre-ban');
    expect(p?.srcIp).toBe('10.0.0.5');
  });

  it('classifies MAILCOWAUTH login failures with the offending IP', () => {
    const p = parseNetfilterEntry(
      entry(2, '139.59.10.109 matched rule id 1 (MAILCOWAUTH: Login failed for user info@kirgus.net with service imap from IP 139.59.10.109)'),
    );
    expect(p).toEqual({
      reason: 'auth-failed',
      srcIp: '139.59.10.109',
      ruleName: 'MAILCOWAUTH: Login failed for user info@kirgus.net with service imap from IP 139.59.10.109',
    });
  });

  it('classifies SASL auth failures using the leading address', () => {
    const p = parseNetfilterEntry(
      entry(3, '203.0.113.7 matched rule id 4 (warning: unknown[203.0.113.7]: SASL PLAIN authentication failed: (reason unavailable), sasl_username=)'),
    );
    expect(p?.reason).toBe('auth-failed');
    expect(p?.srcIp).toBe('203.0.113.7');
  });

  it('classifies non-SMTP commands as port scans', () => {
    const p = parseNetfilterEntry(
      entry(4, '198.51.100.9 matched rule id 2 (warning: non-SMTP command from scan.visionheight.com[198.51.100.9]: GET _ HTTP/1.1)'),
    );
    expect(p?.reason).toBe('port-scan');
    expect(p?.srcIp).toBe('198.51.100.9');
  });

  it('truncates garbage scanner payloads in the rule description', () => {
    const p = parseNetfilterEntry(
      entry(5, `203.0.113.8 matched rule id 2 (warning: non-SMTP command from unknown[203.0.113.8]: ${'A'.repeat(400)})`),
    );
    expect(p?.reason).toBe('port-scan');
    expect((p?.ruleName ?? '').length).toBeLessThanOrEqual(200);
  });

  it('returns null for chain-setup / allowlist bookkeeping lines', () => {
    expect(parseNetfilterEntry(entry(6, 'MAILCOW ip4 chain created successfully.'))).toBeNull();
    expect(parseNetfilterEntry(entry(7, 'Allowlist was changed, it has 3 entries'))).toBeNull();
    expect(parseNetfilterEntry(entry(8, 'Watching Redis channel FNB_CHANNEL'))).toBeNull();
    expect(parseNetfilterEntry(entry(9, 'Initializing mailcow netfilter chain'))).toBeNull();
    expect(parseNetfilterEntry(entry(10, 'Setting MAILCOW isolation'))).toBeNull();
  });
});

describe('netfilterVendorEventId', () => {
  it('is deterministic across re-parses of the same entry', () => {
    const a = netfilterVendorEventId(1795362580, 'some message');
    expect(a).toBe(netfilterVendorEventId(1795362580, 'some message'));
  });

  it('differs for different messages or times', () => {
    const a = netfilterVendorEventId(1, 'x');
    expect(a).not.toBe(netfilterVendorEventId(1, 'y'));
    expect(a).not.toBe(netfilterVendorEventId(2, 'x'));
  });

  it('fits the 128-char vendorEventId column', () => {
    expect(netfilterVendorEventId(9_999_999_999, 'a'.repeat(500)).length).toBeLessThanOrEqual(128);
  });
});

describe('selectFreshNetfilterEntries / newestNetfilterTimeSec', () => {
  const entries = [entry(100, 'a'), entry(200, 'b'), entry(300, 'c')];

  it('returns all entries on first run (null cursor)', () => {
    expect(selectFreshNetfilterEntries(entries, null)).toHaveLength(3);
  });

  it('keeps only entries strictly newer than the cursor', () => {
    expect(selectFreshNetfilterEntries(entries, 200).map((e) => e.time)).toEqual([300]);
  });

  it('computes the newest time (null for empty)', () => {
    expect(newestNetfilterTimeSec(entries)).toBe(300);
    expect(newestNetfilterTimeSec([])).toBeNull();
  });
});

describe('toFirewallEventRows', () => {
  it('builds wire rows with ISO ts, warn action and classified fields', () => {
    const rows = toFirewallEventRows([entry(1795362580, '9 more attempts in the next 600 seconds until 139.59.10.109/32 is banned')]);
    expect(rows).toHaveLength(1);
    const r = rows[0];
    expect(r.ts).toBe(new Date(1795362580 * 1000).toISOString());
    expect(r.action).toBe('warn');
    expect(r.reason).toBe('brute-force-pre-ban');
    expect(r.srcIp).toBe('139.59.10.109');
    expect(typeof r.vendorEventId).toBe('string');
  });

  it('skips non-event lines', () => {
    const rows = toFirewallEventRows([entry(1, 'MAILCOW ip4 chain created successfully.')]);
    expect(rows).toHaveLength(0);
  });
});
