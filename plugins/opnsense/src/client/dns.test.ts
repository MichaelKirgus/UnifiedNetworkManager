/**
 * Unit tests for the unbound qstats row parser (parseUnboundQueryRows). Pure
 * logic — no appliance, no network. The parser normalizes the JSON rows from
 * GET /api/unbound/overview/search_queries into UnboundQueryRow and must skip
 * feed noise without throwing.
 */
import { createHash } from 'node:crypto';
import { parseUnboundQueryRows, dnsVendorEventId } from './dns';

const key = (uuid: string | null, timeSec: number, client: string, domain: string, type: string | null): string =>
  createHash('sha1').update([uuid ?? '', String(timeSec), client, domain, type ?? ''].join('|')).digest('hex');

describe('parseUnboundQueryRows', () => {
  it('normalizes a full row (bare-array response shape)', () => {
    const rows = parseUnboundQueryRows([
      {
        uuid: 'abc-123',
        time: 1_700_000_042,
        client: '192.168.1.50',
        family: 'IN',
        type: 'A',
        domain: 'evil.example.com.',
        action: 'Block',
        source: 'Recursion',
        blocklist: 'blocklist_name_1',
        rcode: 'NOERROR',
        resolve_time_ms: 12,
        dnssec_status: 'Insecure',
        ttl: 300,
      },
    ]);
    expect(rows).toEqual([
      {
        uuid: 'abc-123',
        vendorEventId: key('abc-123', 1_700_000_042, '192.168.1.50', 'evil.example.com.', 'A'),
        time: 1_700_000_042,
        client: '192.168.1.50',
        family: 'IN',
        type: 'A',
        domain: 'evil.example.com.',
        action: 'Block',
        source: 'Recursion',
        blocklist: 'blocklist_name_1',
        rcode: 'NOERROR',
        resolveTimeMs: 12,
        dnssecStatus: 'Insecure',
        ttl: 300,
      },
    ]);
  });

  it('accepts the {rows:[...]} wrapper shape and keeps hostname clients verbatim', () => {
    const rows = parseUnboundQueryRows({
      rows: [
        // The appliance substitutes a reverse-resolved HOSTNAME for the client IP.
        { uuid: 'u2', time: 1_700_000_100, client: 'synapse04-master', domain: 'clean.example.org', action: 'Pass' },
      ],
    });
    expect(rows).toHaveLength(1);
    expect(rows[0].client).toBe('synapse04-master');
    // Absent optional fields normalize to null (action defaults to Pass).
    expect(rows[0]).toMatchObject({ blocklist: null, rcode: null, resolveTimeMs: null, dnssecStatus: null, ttl: null, action: 'Pass' });
  });

  it('skips rows missing time/client/domain and non-object entries (uuid is OPTIONAL)', () => {
    const rows = parseUnboundQueryRows([
      { uuid: 'u', client: '192.168.1.50', domain: 'x.com' }, // no time
      { uuid: 'u', time: 1_700_000_042, domain: 'x.com' }, // no client
      { uuid: 'u', time: 1_700_000_042, client: '192.168.1.50' }, // no domain
      { time: -5, client: '192.168.1.50', domain: 'x.com' }, // non-positive time
      'garbage',
      null,
    ]);
    expect(rows).toEqual([]);
  });

  it('accepts rows with uuid=null (every unblocked query) and synthesizes a deterministic vendorEventId', () => {
    const raw = { uuid: null, time: 1_700_000_042, client: '192.168.1.50', type: 'A', domain: 'x.com.', action: 'Pass' };
    // Parse the SAME row twice — re-sent batches must yield the identical dedupe key.
    const first = parseUnboundQueryRows([raw])[0];
    const second = parseUnboundQueryRows([raw])[0];
    expect(first.uuid).toBeNull();
    expect(first.vendorEventId).toMatch(/^[0-9a-f]{40}$/);
    expect(second.vendorEventId).toBe(first.vendorEventId);
    // Distinct queries differ in at least one field → distinct keys.
    expect(parseUnboundQueryRows([{ ...raw, domain: 'y.com.' }])[0].vendorEventId).not.toBe(first.vendorEventId);
    expect(parseUnboundQueryRows([{ ...raw, time: 1_700_000_043 }])[0].vendorEventId).not.toBe(first.vendorEventId);
    // A present uuid (DNSBL rule id on blocked rows) feeds the key too.
    const blocked = parseUnboundQueryRows([{ ...raw, uuid: 'rule-1', action: 'Block' }])[0];
    expect(blocked.uuid).toBe('rule-1');
    expect(blocked.vendorEventId).not.toBe(first.vendorEventId);
  });

  it('returns [] for empty/absent bodies (endpoint without data)', () => {
    expect(parseUnboundQueryRows(undefined)).toEqual([]);
    expect(parseUnboundQueryRows(null)).toEqual([]);
    expect(parseUnboundQueryRows({})).toEqual([]);
    expect(parseUnboundQueryRows([])).toEqual([]);
  });

  it('truncates fractional times and tolerates numeric strings', () => {
    const rows = parseUnboundQueryRows([
      { uuid: 'u1', time: 1_700_000_042.9, client: '10.0.0.5', domain: 'a.b.c', resolve_time_ms: '37' },
    ]);
    expect(rows[0].time).toBe(1_700_000_042);
    expect(rows[0].resolveTimeMs).toBe(37);
  });

  it('dnsVendorEventId is deterministic and fits the 128-char vendorEventId column', () => {
    const a = dnsVendorEventId(null, 1_700_000_042, '192.168.1.50', 'x.com.', null);
    expect(a).toBe(dnsVendorEventId(null, 1_700_000_042, '192.168.1.50', 'x.com.', null));
    expect(a.length).toBeLessThanOrEqual(128);
  });
});
