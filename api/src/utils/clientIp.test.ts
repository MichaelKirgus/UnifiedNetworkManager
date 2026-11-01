/**
 * Unit tests for client-IP resolution behind a reverse proxy (see clientIp.ts).
 * The functions read process.env at call time, so each case sets/unsets the
 * relevant vars around the assertion.
 */
import type { Request } from 'express';
import { resolveClientIp, parseTrustProxy, clientIpKeyGenerator } from './clientIp';

/** Minimal Request-shaped object — only the fields under test are populated. */
function fakeReq(overrides: Partial<Request> & { headers?: Record<string, string | string[]> }): Request {
  return {
    ip: '127.0.0.1',
    socket: { remoteAddress: '127.0.0.1' },
    ...overrides,
  } as unknown as Request;
}

const CLIENT_IP_HEADER = 'UNM_CLIENT_IP_HEADER';

afterEach(() => {
  delete process.env[CLIENT_IP_HEADER];
});

describe('resolveClientIp', () => {
  test('falls back to req.ip when no client-IP header is configured', () => {
    expect(resolveClientIp(fakeReq({ ip: '203.0.113.7' }))).toBe('203.0.113.7');
  });

  test('strips a :port suffix from req.ip (IPv4)', () => {
    expect(resolveClientIp(fakeReq({ ip: '203.0.113.7:54321' }))).toBe('203.0.113.7');
  });

  test('strips a :port suffix from req.ip (bracketed IPv6)', () => {
    expect(resolveClientIp(fakeReq({ ip: '[2001:db8::5]:443' }))).toBe('[2001:db8::5]');
  });

  test('keeps a bracketless IPv6 address intact (no numeric-suffix false positive)', () => {
    expect(resolveClientIp(fakeReq({ ip: '2001:db8::5' }))).toBe('2001:db8::5');
  });

  test('falls back to socket.remoteAddress when req.ip is empty', () => {
    const req = fakeReq({});
    (req as unknown as { ip: string }).ip = '';
    expect(resolveClientIp(req)).toBe('127.0.0.1');
  });

  test('uses the configured header value when present (case-insensitive name)', () => {
    process.env[CLIENT_IP_HEADER] = 'CF-Connecting-IP';
    const req = fakeReq({ ip: '198.51.100.1', headers: { 'cf-connecting-ip': '203.0.113.42' } });
    expect(resolveClientIp(req)).toBe('203.0.113.42');
  });

  test('header value wins over req.ip (proxy address)', () => {
    process.env[CLIENT_IP_HEADER] = 'X-Real-Client';
    const req = fakeReq({ ip: '198.51.100.1', headers: { 'x-real-client': '203.0.113.42' } });
    expect(resolveClientIp(req)).toBe('203.0.113.42');
  });

  test('strips a :port from the header value too', () => {
    process.env[CLIENT_IP_HEADER] = 'X-Real-Client';
    const req = fakeReq({ headers: { 'x-real-client': '203.0.113.42:9999' } });
    expect(resolveClientIp(req)).toBe('203.0.113.42');
  });

  test('ignores an empty header value and falls back to req.ip', () => {
    process.env[CLIENT_IP_HEADER] = 'X-Real-Client';
    const req = fakeReq({ ip: '203.0.113.7', headers: { 'x-real-client': '   ' } });
    expect(resolveClientIp(req)).toBe('203.0.113.7');
  });

  test('takes the first non-empty entry of a multi-value header', () => {
    process.env[CLIENT_IP_HEADER] = 'X-Real-Client';
    const req = fakeReq({ headers: { 'x-real-client': ['', '203.0.113.42'] } });
    expect(resolveClientIp(req)).toBe('203.0.113.42');
  });

  test('supports multiple configured header names (first present wins)', () => {
    process.env[CLIENT_IP_HEADER] = 'X-Real-Client, CF-Connecting-IP';
    const req = fakeReq({ headers: { 'cf-connecting-ip': '198.51.100.9' } });
    expect(resolveClientIp(req)).toBe('198.51.100.9');
  });

  test('whitespace around configured names is tolerated', () => {
    process.env[CLIENT_IP_HEADER] = '  X-Real-Client , ';
    const req = fakeReq({ headers: { 'x-real-client': '203.0.113.42' } });
    expect(resolveClientIp(req)).toBe('203.0.113.42');
  });
});

describe('clientIpKeyGenerator', () => {
  test('returns undefined when no header is configured (library default applies)', () => {
    expect(clientIpKeyGenerator()).toBeUndefined();
  });

  test('returns a function that buckets by the header value, IPv6 /56-style', () => {
    process.env[CLIENT_IP_HEADER] = 'CF-Connecting-IP';
    const gen = clientIpKeyGenerator();
    expect(typeof gen).toBe('function');
    if (!gen) throw new Error('expected a key generator');

    // Two IPv4 clients → distinct keys.
    const a = gen(fakeReq({ headers: { 'cf-connecting-ip': '203.0.113.1' } }));
    const b = gen(fakeReq({ headers: { 'cf-connecting-ip': '203.0.113.2' } }));
    expect(a).not.toBe(b);

    // Same client with/without port → same key (port stripped before bucketing).
    const c = gen(fakeReq({ headers: { 'cf-connecting-ip': '203.0.113.1:40000' } }));
    expect(c).toBe(a);

    // IPv6 addresses are subnetted (/56) by ipKeyGenerator — two addresses in
    // the same /56 share a key, different /56s do not.
    const v6a = gen(fakeReq({ headers: { 'cf-connecting-ip': '2001:db8:1::1' } }));
    const v6b = gen(fakeReq({ headers: { 'cf-connecting-ip': '2001:db8:1::99' } }));
    expect(v6a).toBe(v6b);
    const v6c = gen(fakeReq({ headers: { 'cf-connecting-ip': '2001:db8:2::1' } }));
    expect(v6c).not.toBe(v6a);
  });
});

describe('parseTrustProxy', () => {
  test.each([
    [undefined, false],
    ['', false],
    ['   ', false],
    ['0', 0],
    ['1', 1],
    ['3', 3],
    ['loopback', 'loopback'],
    ['link-local', 'link-local'],
    ['10.0.0.0/8, 172.16.0.0/12', '10.0.0.0/8, 172.16.0.0/12'],
  ] as const)('parses %p → %p', (input, expected) => {
    expect(parseTrustProxy(input)).toEqual(expected);
  });
});
