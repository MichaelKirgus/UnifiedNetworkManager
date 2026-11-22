/**
 * Unit tests for the rspamd + SASL auth-activity check builders (pure logic —
 * no HTTP). The fail2ban/DKIM checks predate this file and are covered by the
 * plugin-test-kit smoke config.
 */

import { buildRspamdRow, CREDENTIAL_STUFFING_THRESHOLD, isPrivateIp, saslAuthRows } from './security';
import type { MailcowRspamdStats, MailcowSaslLogin } from './client/mailcowClient';

describe('buildRspamdRow', () => {
  it('returns null when the endpoint yielded no data (not verifiable)', () => {
    expect(buildRspamdRow({ actions: {} })).toBeNull();
  });

  it('returns null when nothing has ever been blocked', () => {
    const row = buildRspamdRow({ version: '4.2.3', scanned: 100, actions: { 'no action': 95, greylist: 5 } });
    expect(row).toBeNull();
  });

  it('emits an info row with counts once the filter has blocked mail', () => {
    const row = buildRspamdRow({
      version: '4.2.3',
      uptimeSec: 100,
      scanned: 181543,
      actions: { reject: 702, 'soft reject': 5, greylist: 1050, 'no action': 179203 },
    });
    expect(row).not.toBeNull();
    expect(row!.name).toBe('rspamd');
    expect(row!.kind).toBe('spam-filtering');
    expect(row!.status).toBe('info');
    expect(row!.count).toBe(707); // reject + soft reject
    expect(row!.detail).toContain('4.2.3');
    expect(row!.extra).toMatchObject({ version: '4.2.3', scanned: 181543 });
  });

  it('handles a missing version string gracefully', () => {
    const row = buildRspamdRow({ actions: { reject: 3 } });
    expect(row).not.toBeNull();
    expect(row!.detail).toContain('(unknown version)');
  });
});

describe('isPrivateIp', () => {
  it('treats RFC1918/loopback/link-local as private', () => {
    expect(isPrivateIp('10.110.0.20')).toBe(true);
    expect(isPrivateIp('172.16.0.1')).toBe(true);
    expect(isPrivateIp('172.31.255.254')).toBe(true);
    expect(isPrivateIp('192.168.1.5')).toBe(true);
    expect(isPrivateIp('127.0.0.1')).toBe(true);
    expect(isPrivateIp('169.254.1.1')).toBe(true);
  });

  it('treats public IPv4 as external', () => {
    expect(isPrivateIp('79.193.103.177')).toBe(false);
    expect(isPrivateIp('172.32.0.1')).toBe(false); // outside 172.16/12
    expect(isPrivateIp('11.0.0.1')).toBe(false);
  });

  it('handles basic IPv6 forms and IPv4-mapped addresses', () => {
    expect(isPrivateIp('::1')).toBe(true);
    expect(isPrivateIp('fe80::1')).toBe(true);
    expect(isPrivateIp('fd12:3456::1')).toBe(true);
    expect(isPrivateIp('fc00::1')).toBe(true);
    expect(isPrivateIp('2001:db8::1')).toBe(false);
    expect(isPrivateIp('::ffff:192.168.1.5')).toBe(true);
    expect(isPrivateIp('::ffff:79.193.103.177')).toBe(false);
  });
});

describe('saslAuthRows', () => {
  const login = (ip: string, username: string): MailcowSaslLogin => ({ service: 'imap', username, ip, appPassword: false });

  it('returns [] with no data or only internal activity', () => {
    expect(saslAuthRows([])).toEqual([]);
    expect(
      saslAuthRows([login('192.168.178.131', 'michael@kirgus.net'), login('10.110.0.20', 'ralf@kirgus.net')]),
    ).toEqual([]);
  });

  it('emits an info row for normal external login activity', () => {
    const rows = saslAuthRows([
      login('79.193.103.177', 'michael@kirgus.net'),
      login('79.193.103.177', 'michael@kirgus.net'),
      login('203.0.113.5', 'ralf@kirgus.net'),
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].name).toBe('sasl-auth');
    expect(rows[0].kind).toBe('auth-activity');
    expect(rows[0].status).toBe('info');
    expect(rows[0].count).toBe(3);
  });

  it('emits a warning when one external IP authenticates as >= threshold users', () => {
    const rows = saslAuthRows([
      login('203.0.113.99', 'a@kirgus.net'),
      login('203.0.113.99', 'b@kirgus.net'),
      login('203.0.113.99', 'c@kirgus.net'), // 3 distinct users = threshold
    ]);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('warning');
    expect(rows[0].detail).toContain('203.0.113.99');
    const offenders = (rows[0].extra as { offenders: Array<{ ip: string; usernames: string[] }> }).offenders;
    expect(offenders[0].ip).toBe('203.0.113.99');
    expect(offenders[0].usernames).toHaveLength(CREDENTIAL_STUFFING_THRESHOLD);
  });

  it('stays info below the threshold (2 distinct users)', () => {
    const rows = saslAuthRows([login('203.0.113.99', 'a@kirgus.net'), login('203.0.113.99', 'b@kirgus.net')]);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('info');
  });

  it('counts usernames case-insensitively', () => {
    const rows = saslAuthRows([login('203.0.113.99', 'A@kirgus.net'), login('203.0.113.99', 'a@kirgus.net')]);
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('info'); // the same user twice, not two users
  });

  it('ranks offenders by distinct-user count in the warning row', () => {
    const rows = saslAuthRows([
      login('203.0.113.1', 'a@x'),
      login('203.0.113.1', 'b@x'),
      login('203.0.113.1', 'c@x'), // 3 users
      login('203.0.113.2', 'a@x'),
      login('203.0.113.2', 'b@x'),
      login('203.0.113.2', 'c@x'),
      login('203.0.113.2', 'd@x'), // 4 users → ranked first
    ]);
    const offenders = (rows[0].extra as { offenders: Array<{ ip: string; usernames: string[] }> }).offenders;
    expect(offenders[0].ip).toBe('203.0.113.2');
    expect(offenders[0].usernames).toHaveLength(4);
  });
});
