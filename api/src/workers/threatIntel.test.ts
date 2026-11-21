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

import { matchDomain, matchIoc, normalizeDomain, normalizeDomainLine, parseDomainList, parseIpList, parseIocValue, parseStix, threatIntelFileName, worstSeverity } from './threatIntel';
import type { IocCache } from './threatIntel';

describe('threatIntelFileName', () => {
  it('builds a date-suffixed name with the format extension', () => {
    const today = new Date().toISOString().slice(0, 10);
    expect(threatIntelFileName('My Feed', 'ip-list')).toBe(`threat-intel-My-Feed-${today}.txt`);
    expect(threatIntelFileName('My Feed', 'domain-list')).toBe(`threat-intel-My-Feed-${today}.txt`);
    expect(threatIntelFileName('My Feed', 'stix')).toBe(`threat-intel-My-Feed-${today}.json`);
  });

  it('sanitizes unsafe characters and bounds the length', () => {
    const name = threatIntelFileName('a/b\\c:d "quoted" feed', 'ip-list');
    expect(name).toMatch(/^threat-intel-a-b-c-d-quoted-feed-\d{4}-\d{2}-\d{2}\.txt$/);
    // 80-char cap on the source-name part + fixed suffix.
    const long = threatIntelFileName('x'.repeat(500), 'stix');
    expect(long.length).toBeLessThanOrEqual('threat-intel-'.length + 80 + '-YYYY-MM-DD.json'.length);
  });

  it('falls back to "feed" when the name sanitizes to nothing', () => {
    expect(threatIntelFileName('///', 'ip-list')).toMatch(/^threat-intel-feed-\d{4}-\d{2}-\d{2}\.txt$/);
  });
});

/** Builds a cache the same way ensureIocCache does from parsed entries. */
function makeCache(
  entries: Array<{ value: string; sources: string[] }>,
  domains?: Array<{ domain: string; sources: string[] }>,
  severities?: Map<string, string>
): IocCache {
  const exact = new Map<string, string[]>();
  const cidrs: IocCache['cidrs'] = [];
  for (const e of entries) {
    const p = parseIocValue(e.value);
    if (!p) throw new Error(`test helper: bad entry ${e.value}`);
    if (p.prefix === null) exact.set(p.key, [...(exact.get(p.key) ?? []), ...e.sources]);
    else cidrs.push({ words: p.words, prefix: p.prefix, family: p.family, sources: e.sources });
  }
  const domainMap = new Map<string, string[]>();
  for (const d of domains ?? []) {
    domainMap.set(d.domain, [...(domainMap.get(d.domain) ?? []), ...d.sources]);
  }
  return { exact, cidrs, domains: domainMap, severities: severities ?? new Map(), loadedAt: Date.now(), total: entries.length + (domains?.length ?? 0) };
}

describe('worstSeverity', () => {
  it('escalates to the highest severity among the matched sources', () => {
    const sev = new Map([['feed-a', 'info'], ['feed-b', 'critical']]);
    expect(worstSeverity(['feed-a', 'feed-b'], sev)).toBe('critical');
    expect(worstSeverity(['feed-a'], sev)).toBe('info');
  });

  it('defaults to warning for unknown sources and empty input', () => {
    expect(worstSeverity(['unknown-feed'], new Map())).toBe('warning');
    expect(worstSeverity([], new Map([['feed-a', 'critical']]))).toBe('warning');
  });
});

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

describe('normalizeDomain', () => {
  it('lowercases and strips trailing FQDN dots', () => {
    expect(normalizeDomain('Evil.Example.COM.')).toBe('evil.example.com');
    expect(normalizeDomain('  bad-domain.net ')).toBe('bad-domain.net');
  });

  it('strips leading wildcard labels (they add nothing — subdomains match anyway)', () => {
    expect(normalizeDomain('*.c2-malware.org')).toBe('c2-malware.org');
  });

  it('rejects bare labels, IP literals, single-letter TLDs and garbage', () => {
    for (const bad of ['', 'localhost', '198.51.100.66', 'http://example.com/x', 'a.b.c.', '-bad.com', 'bad-.com', 'evil.x']) {
      expect(normalizeDomain(bad)).toBeNull();
    }
  });
});

describe('parseDomainList', () => {
  it('collects valid domains and skips comments/URLs silently but counts garbage (Pi-hole format)', () => {
    const body = [
      '! Pi-hole style comment',
      '# hash comment line',
      '; semicolon comment line',
      '',
      'http://example.com/junk',
      'evil.example.com.',
      '*.tracker.adware.net',
      'not a domain',
      'c2-malware.org',
    ].join('\n');
    const r = parseDomainList(Buffer.from(body), 10_000);
    expect(r.values).toEqual(['evil.example.com', 'tracker.adware.net', 'c2-malware.org']);
    expect(r.skipped).toBe(1); // only "not a domain" — comments/URLs/blanks are not counted
  });

  it('dedupes repeats (case + trailing-dot variants collapse)', () => {
    const r = parseDomainList(Buffer.from('evil.com\nEVIL.COM.\nevil.com\n'), 10_000);
    expect(r.values).toEqual(['evil.com']);
    expect(r.skipped).toBe(0); // duplicates are valid entries, just not new ones
  });

  it('enforces the per-source cap and counts the remainder as skipped', () => {
    const r = parseDomainList(Buffer.from(['evil.com', 'ok.net', 'cap.org', 'extra.org'].join('\n')), 3);
    expect(r.values).toEqual(['evil.com', 'ok.net', 'cap.org']);
    expect(r.skipped).toBe(1); // the line after the cap
  });

  it('parses Adblock/EasyList filter rules alongside bare domains', () => {
    const body = [
      '[Adblock Plus]',
      '! adblock comment',
      '||evil.example.com^',
      '|tracker.adware.net',
      '*.popup.serve.net$third-party',
      '||ads.vendor.org/path/to/thing^$script',
      '@@||allowed.example.com^',
      '/regex\\.filter\\.com/',
    ].join('\n');
    const r = parseDomainList(Buffer.from(body), 10_000);
    expect(r.values).toEqual(['evil.example.com', 'tracker.adware.net', 'popup.serve.net', 'ads.vendor.org']);
    expect(r.skipped).toBe(2); // unblock rule + regex filter — section headers/comments are not counted
  });
});

describe('normalizeDomainLine', () => {
  it('strips adblock anchors, boundaries and $options before domain validation', () => {
    expect(normalizeDomainLine('||Evil.Example.COM^')).toBe('evil.example.com');
    expect(normalizeDomainLine('|bare-anchor.net')).toBe('bare-anchor.net');
    expect(normalizeDomainLine('plain-domain.org.')).toBe('plain-domain.org'); // bare Pi-hole style passes through
    expect(normalizeDomainLine('||sub.host.io/deep/path^$document')).toBe('sub.host.io');
  });

  it('returns null for regex filters and domain-less rules', () => {
    expect(normalizeDomainLine('/evil\\.com/')).toBeNull();
    expect(normalizeDomainLine('$document')).toBeNull();
  });
});

describe('matchDomain', () => {
  it('matches exact domains and returns their sources', () => {
    const cache = makeCache([], [{ domain: 'evil.example.com', sources: ['feed-a'] }]);
    expect(matchDomain('evil.example.com', cache)).toEqual({ domain: 'evil.example.com', sources: ['feed-a'] });
  });

  it('matches subdomains of listed domains (Pi-hole semantics)', () => {
    const cache = makeCache([], [{ domain: 'c2-malware.org', sources: ['feed-b'] }]);
    expect(matchDomain('a.b.c2-malware.org.', cache)).toEqual({ domain: 'c2-malware.org', sources: ['feed-b'] });
  });

  it('does NOT match sibling or parent domains of a listed name', () => {
    const cache = makeCache([], [{ domain: 'evil.example.com', sources: ['feed-a'] }]);
    expect(matchDomain('not-evil.example.com', cache)).toBeNull(); // different label, same parent
    expect(matchDomain('example.com', cache)).toBeNull(); // the parent itself is not listed
  });

  it('reports the most specific match and unions sources across depths', () => {
    const cache = makeCache([], [
      { domain: 'evil.example.com', sources: ['feed-a'] },
      { domain: 'example.com', sources: ['feed-b'] },
    ]);
    expect(matchDomain('deep.evil.example.com', cache)).toEqual({ domain: 'evil.example.com', sources: ['feed-a', 'feed-b'] });
  });

  it('returns null for unlisted names, empty input and an empty domain set', () => {
    const cache = makeCache([], [{ domain: 'evil.example.com', sources: ['feed-a'] }]);
    expect(matchDomain('clean.example.org', cache)).toBeNull();
    expect(matchDomain(null, cache)).toBeNull();
    expect(matchDomain('', cache)).toBeNull();
    const empty = makeCache([]);
    expect(matchDomain('evil.example.com', empty)).toBeNull();
  });
});
