/**
 * Unit tests for the unbound qstats row parser (parseUnboundQueryRows). Pure
 * logic — no appliance, no network. The parser normalizes the JSON rows from
 * GET /api/unbound/overview/search_queries into UnboundQueryRow and must skip
 * feed noise without throwing.
 */
import { parseUnboundQueryRows } from './dns';

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

  it('skips rows missing uuid/time/client/domain and non-object entries', () => {
    const rows = parseUnboundQueryRows([
      { time: 1_700_000_042, client: '192.168.1.50', domain: 'x.com' }, // no uuid
      { uuid: 'u', client: '192.168.1.50', domain: 'x.com' }, // no time
      { uuid: 'u', time: 1_700_000_042, domain: 'x.com' }, // no client
      { uuid: 'u', time: 1_700_000_042, client: '192.168.1.50' }, // no domain
      'garbage',
      null,
    ]);
    expect(rows).toEqual([]);
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
});
