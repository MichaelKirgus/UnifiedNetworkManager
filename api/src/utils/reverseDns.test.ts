/**
 * Unit tests for utils/reverseDns.ts — the PTR resolution engine. Covers the
 * pure parts: arpa naming (SDK-fed), DNS wire encoding/parsing (incl. name
 * compression pointers), settings parsing, server selection strategies and the
 * DOH answer handling (fetch mocked). The DB-backed batch pipeline is covered
 * by the dev E2E scripts instead.
 */

// uuid v14 ships an ESM node entry that jest cannot require — importing this
// module pulls in ../db for the pool; these tests never touch it.
jest.mock('uuid', () => ({ v4: () => '00000000-0000-4000-8000-000000000000' }));

import {
  arpaName,
  buildPtrQuery,
  decodeDnsName,
  encodeQname,
  noteServerSuccess,
  parsePtrAnswer,
  parseRdnsConfig,
  pickServerOrder,
  resetReverseDnsEngine,
  resolveIpOnce,
} from './reverseDns';

// ── arpa naming ──────────────────────────────────────────────────────────────

describe('arpaName', () => {
  it('builds in-addr.arpa names for IPv4 (octets reversed)', () => {
    expect(arpaName('192.0.2.1')).toBe('1.2.0.192.in-addr.arpa');
    expect(arpaName('10.37.1.5')).toBe('5.1.37.10.in-addr.arpa');
  });

  it('builds ip6.arpa names for IPv6 (nibbles reversed)', () => {
    // 2001:db8::1 → words [2001, 0db8, 0×5, 0001] → 32 nibbles reversed:
    // leading "1", then 23 zero nibbles (rest of word7 + five zero words),
    // then "8.b.d.0" (word1 reversed) and "1.0.0.2" (word0 reversed).
    const expected = ['1', ...Array(23).fill('0'), '8', 'b', 'd', '0', '1', '0', '0', '2'].join('.') + '.ip6.arpa';
    expect(arpaName('2001:db8::1')).toBe(expected);
  });

  it('strips zone ids and rejects non-IP input', () => {
    expect(arpaName('fe80::1%eth0')).toBe(arpaName('fe80::1'));
    expect(arpaName('not-an-ip')).toBeNull();
    expect(arpaName('300.1.2.3')).toBeNull(); // octet > 255 — SDK rejects
    expect(arpaName('')).toBeNull();
  });
});

// ── DNS wire format ──────────────────────────────────────────────────────────

describe('encodeQname / buildPtrQuery', () => {
  it('encodes labels with length prefixes + root terminator', () => {
    expect(encodeQname('a.b')).toEqual(Buffer.from([1, 97, 1, 98, 0]));
    expect(encodeQname('host.example.com')).toEqual(
      Buffer.concat([Buffer.from([4]), Buffer.from('host'), Buffer.from([7]), Buffer.from('example'), Buffer.from([3]), Buffer.from('com'), Buffer.from([0])]),
    );
  });

  it('builds a PTR query with RD flag, one question and QTYPE=12/QCLASS=IN', () => {
    const q = buildPtrQuery(0x1234, 'a.b');
    expect(q.length).toBe(12 + 5 + 4); // header + qname + type/class
    expect(q.readUInt16BE(0)).toBe(0x1234); // id
    expect(q.readUInt16BE(2)).toBe(0x0100); // RD set, standard query
    expect(q.readUInt16BE(4)).toBe(1);      // qdcount
    expect(q.subarray(17, 21)).toEqual(Buffer.from([0, 12, 0, 1])); // PTR / IN
  });

  it('rejects labels longer than 63 chars', () => {
    expect(() => encodeQname(`${'x'.repeat(64)}.arpa`)).toThrow(/63/);
  });
});

describe('decodeDnsName', () => {
  it('decodes a plain (uncompressed) name and reports the end offset', () => {
    const buf = Buffer.concat([Buffer.from([3]), Buffer.from('abc'), Buffer.from([0])]);
    expect(decodeDnsName(buf, 0)).toEqual({ name: 'abc', next: 5 });
  });

  it('follows a compression pointer to the target offset', () => {
    const buf = Buffer.alloc(17);
    buf[0] = 0xc0; buf[1] = 0x0c; // pointer → offset 12
    buf[12] = 3; buf.write('abc', 13, 'utf8'); buf[16] = 0;
    expect(decodeDnsName(buf, 0)).toEqual({ name: 'abc', next: 2 }); // past the 2-byte pointer
  });

  it('follows a MID-NAME pointer (shared suffix compression)', () => {
    // Labels are atomic — compression happens at label boundaries:
    // "a" + "b" + pointer to the stored "example.com" at offset 6.
    const suffix = encodeQname('example.com'); // [7,'example',3,'com',0]
    const buf = Buffer.alloc(6 + suffix.length);
    buf[0] = 1; buf.write('a', 1, 'utf8');
    buf[2] = 1; buf.write('b', 3, 'utf8');
    buf[4] = 0xc0; buf[5] = 0x06; // pointer → offset 6
    buf.set(suffix, 6);
    expect(decodeDnsName(buf, 0)).toEqual({ name: 'a.b.example.com', next: 6 });
  });

  it('throws on a pointer cycle instead of looping forever', () => {
    const buf = Buffer.from([0xc0, 0x00]); // points at itself (offset 0)
    expect(() => decodeDnsName(buf, 0)).toThrow(/pointer/);
  });
});

/** Builds a synthetic DNS response: header + question + the given answers. */
function dnsResponse(id: number, qname: string, answers: Array<{ type: number; rdata: Buffer; name?: Buffer }>): Buffer {
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x8180, 2); // QR + RA
  header.writeUInt16BE(1, 4);      // qdcount
  header.writeUInt16BE(answers.length, 6); // ancount
  const question = Buffer.concat([encodeQname(qname), Buffer.from([0, 12, 0, 1])]);
  const records = answers.map((a) => {
    const meta = Buffer.alloc(10);
    meta.writeUInt16BE(a.type, 0);
    meta.writeUInt16BE(1, 2);      // class IN
    meta.writeUInt32BE(300, 4);    // ttl
    meta.writeUInt16BE(a.rdata.length, 8);
    return Buffer.concat([a.name ?? Buffer.from([0xc0, 0x0c]), meta, a.rdata]); // default: pointer to qname @12
  });
  return Buffer.concat([header, question, ...records]);
}

describe('parsePtrAnswer', () => {
  it('extracts the PTR target (pointer-compressed name + inline rdata)', () => {
    const buf = dnsResponse(0xabcd, '1.2.3.in-addr.arpa', [
      { type: 12, rdata: encodeQname('host.example.com') },
    ]);
    expect(parsePtrAnswer(buf)).toBe('host.example.com');
  });

  it('skips non-PTR records and returns the first PTR', () => {
    const buf = dnsResponse(0xabcd, '1.2.3.in-addr.arpa', [
      { type: 1, rdata: Buffer.from([93, 184, 216, 34]) }, // A record first
      { type: 12, rdata: encodeQname('ptr.example.net') },
    ]);
    expect(parsePtrAnswer(buf)).toBe('ptr.example.net');
  });

  it('returns null when there are no answers (NXDOMAIN-style)', () => {
    const buf = dnsResponse(0xabcd, '1.2.3.in-addr.arpa', []);
    expect(parsePtrAnswer(buf)).toBeNull();
  });

  it('throws on a truncated packet', () => {
    expect(() => parsePtrAnswer(Buffer.alloc(4))).toThrow(/too short/);
  });
});

// ── settings parsing ─────────────────────────────────────────────────────────

describe('parseRdnsConfig', () => {
  it('applies safe defaults for empty settings', () => {
    const cfg = parseRdnsConfig({});
    expect(cfg.enabled).toBe(false); // master switch off unless explicitly true
    expect(cfg.mode).toBe('system');
    expect(cfg.strategy).toBe('failover');
    expect(cfg.servers).toEqual([]);
    expect(cfg.dohUrl).toBe('https://dns.google/resolve');
    expect(cfg.timeoutMs).toBe(2_000);
    expect(cfg.positiveTtlMs).toBe(24 * 3_600_000);
    expect(cfg.negativeTtlMs).toBe(15 * 60_000);
  });

  it('parses the custom nameserver list (host and host:port)', () => {
    const cfg = parseRdnsConfig({ rdnsMode: 'custom', rdnsServers: ' resolver-a , resolver-b:5353' });
    expect(cfg.servers).toEqual([
      { host: 'resolver-a', port: 53 },
      { host: 'resolver-b', port: 5353 },
    ]);
  });

  it('clamps timeout and TTLs into their configured ranges', () => {
    // (0/NaN means "unset" → the default applies; out-of-range values clamp.)
    const cfg = parseRdnsConfig({ rdnsTimeoutMs: 10, rdnsPositiveTtlHours: 9999, rdnsNegativeTtlMinutes: -5 });
    expect(cfg.timeoutMs).toBe(500);
    expect(cfg.positiveTtlMs).toBe(720 * 3_600_000);
    expect(cfg.negativeTtlMs).toBe(1 * 60_000);
    expect(parseRdnsConfig({ rdnsNegativeTtlMinutes: 0 }).negativeTtlMs).toBe(15 * 60_000); // unset → default
  });

  it('falls back to system mode for an unknown mode value', () => {
    expect(parseRdnsConfig({ rdnsMode: 'bogus' }).mode).toBe('system');
    expect(parseRdnsConfig({ rdnsDohUrl: 'https://doh.example/' }).dohUrl).toBe('https://doh.example'); // trailing slash stripped
  });
});

// ── server selection strategies ──────────────────────────────────────────────

describe('pickServerOrder / noteServerSuccess', () => {
  beforeEach(() => resetReverseDnsEngine());

  const servers = [
    { host: 'a', port: 53 },
    { host: 'b', port: 53 },
    { host: 'c', port: 53 },
  ];

  it('failover keeps the configured order until a success moves the start point', () => {
    const cfg = parseRdnsConfig({ rdnsMode: 'custom', rdnsStrategy: 'failover' });
    cfg.servers = servers;
    expect(pickServerOrder(cfg).map((s) => s.host)).toEqual(['a', 'b', 'c']);
    noteServerSuccess(cfg, 'c'); // c answered last — stick to it
    expect(pickServerOrder(cfg).map((s) => s.host)).toEqual(['c', 'a', 'b']);
  });

  it('round-robin rotates the start point on every call', () => {
    const cfg = parseRdnsConfig({ rdnsMode: 'custom', rdnsStrategy: 'round-robin' });
    cfg.servers = servers;
    expect(pickServerOrder(cfg).map((s) => s.host)).toEqual(['a', 'b', 'c']);
    expect(pickServerOrder(cfg).map((s) => s.host)).toEqual(['b', 'c', 'a']);
    expect(pickServerOrder(cfg).map((s) => s.host)).toEqual(['c', 'a', 'b']);
  });

  it('returns an empty order when no servers are configured', () => {
    const cfg = parseRdnsConfig({ rdnsMode: 'custom' });
    expect(pickServerOrder(cfg)).toEqual([]);
  });
});

// ── DOH answer handling (fetch mocked) ───────────────────────────────────────

describe('resolveIpOnce — doh mode', () => {
  const originalFetch = globalThis.fetch;
  afterEach(() => { globalThis.fetch = originalFetch; });

  function mockDoh(body: unknown): void {
    globalThis.fetch = (async (_url: string | URL | Request, _init?: RequestInit) => ({
      ok: true,
      json: async () => body,
    })) as unknown as typeof fetch;
  }

  it('parses an RFC 8484 PTR answer and strips the trailing dot', async () => {
    mockDoh({ Status: 0, Answer: [{ type: 12, data: 'host.example.com.' }] });
    const cfg = parseRdnsConfig({ rdnsEnabled: true, rdnsMode: 'doh' });
    await expect(resolveIpOnce('93.184.216.34', cfg)).resolves.toBe('host.example.com');
  });

  it('treats NXDOMAIN (Status 3) as "no PTR" instead of an error', async () => {
    mockDoh({ Status: 3, Answer: [] });
    const cfg = parseRdnsConfig({ rdnsEnabled: true, rdnsMode: 'doh' });
    await expect(resolveIpOnce('93.184.216.34', cfg)).resolves.toBeNull();
  });

  it('surfaces real resolver errors (Status 2 = SERVFAIL)', async () => {
    mockDoh({ Status: 2, Answer: [] });
    const cfg = parseRdnsConfig({ rdnsEnabled: true, rdnsMode: 'doh' });
    await expect(resolveIpOnce('93.184.216.34', cfg)).rejects.toThrow(/status 2/);
  });

  it('never queries for non-IP input (returns null without touching fetch)', async () => {
    let called = false;
    globalThis.fetch = (async () => { called = true; return { ok: true, json: async () => ({}) }; }) as unknown as typeof fetch;
    const cfg = parseRdnsConfig({ rdnsEnabled: true, rdnsMode: 'doh' });
    await expect(resolveIpOnce('not-an-ip', cfg)).resolves.toBeNull();
    expect(called).toBe(false);
  });
});
