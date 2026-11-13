/**
 * Unit tests for workers/threatIntel.ts — the threat-intel feed parsers and
 * cache matching. The underlying IP/CIDR math lives in @unm/plugin-sdk (ip.ts)
 * and is covered by scripts/verify-ip-math.ts, including the wordsContain v4-
 * offset regression (a /24 that matched EVERY IPv4 address, flooding 3,500+
 * false-positive findings on live traffic).
 */

// uuid v14 ships an ESM node entry that jest cannot require — the worker only
// needs it for row ids, which these tests never assert on.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import { matchIoc, parseIpList, parseIocValue, parseStix } from './threatIntel';
import type { IocCache } from './threatIntel';

/** Builds a cache the same way ensureIocCache does from parsed entries. */
function makeCache(entries: Array<{ value: string; sources: string[] }>): IocCache {
  const exact = new Map<string, string[]>();
  const cidrs: IocCache['cidrs'] = [];
  for (const e of entries) {
    const p = parseIocValue(e.value);
    if (!p) throw new Error(`test helper: bad entry ${e.value}`);
    if (p.prefix === null) exact.set(p.key, [...(exact.get(p.key) ?? []), ...e.sources]);
    else cidrs.push({ words: p.words, prefix: p.prefix, family: p.family, sources: e.sources });
  }
  return { exact, cidrs, loadedAt: Date.now(), total: entries.length };
}

describe('parseIocValue', () => {
  it('parses bare IPv4 as an exact host entry', () => {
    const p = parseIocValue('198.51.100.66');
    expect(p).toMatchObject({ key: '198.51.100.66', prefix: null, family: 'v4' });
  });

  it('parses CIDRs and keeps the prefix', () => {
    expect(parseIocValue('203.0.113.0/24')).toMatchObject({ key: '203.0.113.0', prefix: 24, family: 'v4' });
    expect(parseIocValue('2001:db8::/64')).toMatchObject({ prefix: 64, family: 'v6' });
  });

  it('treats /32 and /128 as exact host entries (prefix null)', () => {
    expect(parseIocValue('10.0.0.1/32')).toMatchObject({ key: '10.0.0.1', prefix: null });
    expect(parseIocValue('::1/128')).toMatchObject({ key: '::1', prefix: null, family: 'v6' }); // RFC 5952 compressed key
  });

  it('normalizes case and zone scoping into the canonical key', () => {
    expect(parseIocValue(' 2001:DB8::66 ')).toMatchObject({ key: '2001:db8::66', family: 'v6' });
    expect(parseIocValue('fe80::1%eth0')).toMatchObject({ key: 'fe80::1', prefix: null });
  });

  it('rejects out-of-range prefixes and garbage without throwing', () => {
    for (const bad of ['', 'not-an-ip', 'http://example.com/junk', '10.0.0.0/33', '2001:db8::/129', '10.0.0.1/-1']) {
      expect(parseIocValue(bad)).toBeNull();
    }
  });
});

describe('matchIoc', () => {
  it('matches exact host entries and returns their sources', () => {
    const cache = makeCache([{ value: '198.51.100.66', sources: ['feed-a'] }]);
    expect(matchIoc('198.51.100.66', cache)).toEqual({ ip: '198.51.100.66', sources: ['feed-a'] });
  });

  it('matches CIDR containment (dst-side hit)', () => {
    const cache = makeCache([{ value: '203.0.113.0/24', sources: ['feed-b'] }]);
    expect(matchIoc('203.0.113.77', cache)).toEqual({ ip: '203.0.113.77', sources: ['feed-b'] });
  });

  it('never crosses address families (v4 IP vs v6 CIDR and vice versa)', () => {
    const v6Cache = makeCache([{ value: '2001:db8::/64', sources: ['v6-feed'] }]);
    expect(matchIoc('198.51.100.66', v6Cache)).toBeNull();
    const v4Cache = makeCache([{ value: '203.0.113.0/24', sources: ['v4-feed'] }]);
    expect(matchIoc('2001:db8::77', v4Cache)).toBeNull();
  });

  it('unions and dedupes sources across multiple matching CIDRs', () => {
    const cache = makeCache([
      { value: '203.0.113.0/24', sources: ['feed-a'] },
      { value: '203.0.0.0/8', sources: ['feed-a', 'feed-b'] },
    ]);
    expect(matchIoc('203.0.113.77', cache)?.sources).toEqual(['feed-a', 'feed-b']);
  });

  it('returns null for unlisted IPs and empty input', () => {
    const cache = makeCache([{ value: '203.0.113.0/24', sources: ['feed-b'] }]);
    expect(matchIoc('198.51.100.66', cache)).toBeNull();
    expect(matchIoc(null, cache)).toBeNull();
    expect(matchIoc('', cache)).toBeNull();
  });
});

describe('parseIpList', () => {
  it('collects valid entries and skips comments/URLs silently but counts garbage', () => {
    const body = [
      '# comment line',
      '; semicolon comment line',
      '',
      'http://example.com/junk',
      '198.51.100.66',
      '203.0.113.0/24',
      'not-an-ip',
      '2001:db8::66',
    ].join('\n');
    const r = parseIpList(Buffer.from(body), 10_000);
    expect(r.values).toEqual(['198.51.100.66', '203.0.113.0/24', '2001:db8::66']);
    expect(r.skipped).toBe(1); // only "not-an-ip" — comments/URLs/blanks are not counted
  });

  it('handles CRLF line endings and trailing commas, dedupes repeats', () => {
    const r = parseIpList(Buffer.from('1.2.3.4,\r\n5.6.7.8\r\n1.2.3.4\r\n'), 10_000);
    expect(r.values).toEqual(['1.2.3.4', '5.6.7.8']);
    expect(r.skipped).toBe(0);
  });

  it('enforces the per-source cap and counts the remainder as skipped', () => {
    const body = ['1.1.1.1', '2.2.2.2', '3.3.3.3', '4.4.4.4'].join('\n');
    const r = parseIpList(Buffer.from(body), 2);
    expect(r.values).toEqual(['1.1.1.1', '2.2.2.2']);
    expect(r.skipped).toBe(2);
  });
});

describe('parseStix', () => {
  const bundle = (objects: unknown[]): Buffer => Buffer.from(JSON.stringify({ type: 'bundle', objects }));
  const indicator = (pattern: string): Record<string, unknown> => ({ type: 'indicator', pattern });

  it('extracts equality patterns from indicators (object and array bundles)', () => {
    expect(parseStix(bundle([indicator("[ipv4-addr:value = '198.51.100.66']")]), 10_000).values)
      .toEqual(['198.51.100.66']);
    expect(parseStix(Buffer.from(JSON.stringify([indicator("[ipv6-addr:value = '2001:db8::66']")])), 10_000).values)
      .toEqual(['2001:db8::66']);
  });

  it('extracts every address from OR patterns and dedupes', () => {
    const r = parseStix(
      bundle([indicator("[ipv4-addr:value = '1.2.3.4' OR ipv4-addr:value = '5.6.7.8' OR ipv4-addr:value = '1.2.3.4']")]),
      10_000
    );
    expect(r.values).toEqual(['1.2.3.4', '5.6.7.8']);
    expect(r.skipped).toBe(0);
  });

  it('ignores non-indicator objects and indicators without string patterns, counts unparseable values', () => {
    const r = parseStix(
      bundle([
        { type: 'relationship', pattern: "[ipv4-addr:value = '9.9.9.9']" }, // not an indicator — ignored entirely
        { type: 'indicator' }, // no pattern — ignored
        indicator("[ipv4-addr:value = '999.1.1.1']"), // unparseable value — counted as skipped
      ]),
      10_000
    );
    expect(r.values).toEqual([]);
    expect(r.skipped).toBe(1);
  });

  it('throws descriptive errors for non-JSON or object-less bundles', () => {
    expect(() => parseStix(Buffer.from('not json'), 10_000)).toThrow(/not valid JSON/);
    expect(() => parseStix(Buffer.from(JSON.stringify({ type: 'bundle' })), 10_000)).toThrow(/no objects array/);
  });
});
