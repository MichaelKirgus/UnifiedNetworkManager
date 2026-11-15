/**
 * Unit tests for the FRR/OSPF monitoring module (frrOspf.ts).
 * Pure logic — no appliance, no network. The vtysh fixtures are REAL captured
 * output from an OPNsense 26.x box running FRR (GWST03), including FRR's own
 * log-noise lines that vtysh prints into every call and must be filtered.
 */
import {
  splitFrrSections,
  parseFrrDuration,
  parseOspfV4Neighbors,
  parseOspfV6Neighbors,
  parseRouterId,
  parseRouteCount,
  splitRouteSection,
  parseOspfRouteTable,
  decideFrrCollection,
  deriveFrrConditions,
  DEFAULT_FRR_MONITOR_INTERVAL_SEC,
  type FrrOspfResult,
} from './frrOspf';

// --- Real captured vtysh fixtures (OPNsense 26.1 / FRR on GWST03) -------------

/** Every vtysh call starts with FRR's own log noise — must never become a row. */
const NOISE = '2026-11-15 17:05:02 [H0DHT-S9KF2][EC 100663299] setsockopt_so_recvbuf: fd 8: Operation not permitted';

/** `show ip ospf neighbor` — one Full adjacency on wg0 (10 tokens per row). */
const V4_NEIGH_FULL = [
  NOISE,
  'Neighbor ID     Pri State           Up Time         Dead Time Address         Interface',
  '10.25.0.1       1   Full/-          43m16s          29.153s  10.1.1.93       wg0:10.1.1.94                        0     0     0',
].join('\n');

/** `show ip ospf neighbor` — one Full + one Down adjacency (the flap case). */
const V4_NEIGH_MIXED = [
  NOISE,
  'Neighbor ID     Pri State           Up Time         Dead Time Address         Interface',
  '10.25.0.1       1   Full/-          43m16s          29.153s  10.1.1.93       wg0:10.1.1.94                        0     0     0',
  '10.25.0.9       1   Down/WaitingInfo -              30s      10.1.1.97       wg1:10.1.1.98                        0     0     0',
].join('\n');

/** `show ip ospf neighbor` with zero neighbors — header only (still reachable). */
const V4_NEIGH_EMPTY = [NOISE, 'Neighbor ID     Pri State           Up Time         Dead Time Address         Interface'].join('\n');

/** `show ipv6 ospf6 neighbor` — one Full adjacency on wg4 (6 tokens per row). */
const V6_NEIGH_FULL = [
  NOISE,
  'Neighbor ID     Pri   DeadTime      State/IfState    Duration   I/F',
  '10.25.0.2       1     00:00:09      Full/PointToPoint 00:43:11  wg4[PointToPoint]',
].join('\n');

/** `show ip ospf` head — carries the router ID line. */
const ROUTER_ID_SECTION = [
  NOISE,
  'OSPF process running as',
  ' OSPF Routing Process, Router ID: 10.1.1.94',
].join('\n');

/** `show ip route ospf` — real table layout: flag chars (">", "*"), [dist/metric],
 * "via <gw>, <iface>, <age>" with trailing commas, plus a summary row without next hop. */
const V4_ROUTE_TABLE = [
  NOISE,
  'Codes: C - connected, S - static, R - RIP, O - OSPF, B - BGP,',
  'O>* 10.25.10.0/24 [110/2] via 10.1.1.78, wg0, 00:43:11',
  'O>* 10.25.20.0/24 [110/4] via 10.1.1.98, wg2, 01:12:05',
  'O    10.25.0.0/16 [110/1] is a summary, 02:00:00',
].join('\n');

/** `show ipv6 route ospf6` — same shape with v6 addresses. */
const V6_ROUTE_TABLE = [
  NOISE,
  'O>* fe80::/64 [110/1] via fe80::1, wg4, 00:43:11',
].join('\n');

/** The full combined script output for a healthy box (all sections). */
const HEALTHY_COMBINED = [
  '__FRR_INSTALLED__',
  'dir-present',
  'daemons.conf',
  'frr.conf',
  '__OSPF_CONFIGURED__',
  '/usr/local/etc/frr/frr.conf',
  '__V4_NEIGH__',
  V4_NEIGH_FULL,
  '__V6_NEIGH__',
  V6_NEIGH_FULL,
  // Route sections carry the awk count line FIRST, then the (capped) table.
  '__V4_ROUTES__',
  '3',
  V4_ROUTE_TABLE,
  '__V6_ROUTES__',
  '1',
  V6_ROUTE_TABLE,
  '__ROUTER_ID__',
  ROUTER_ID_SECTION,
].join('\n');

/** The full combined script output when FRR is DOWN (vtysh errors, no tables). */
const FRR_DOWN_COMBINED = [
  '__FRR_INSTALLED__',
  'dir-present',
  'daemons.conf',
  'frr.conf',
  '__OSPF_CONFIGURED__',
  '/usr/local/etc/frr/frr.conf',
  '__V4_NEIGH__',
  "Can't open /var/run/frr/vtysh: No such file or directory",
  '__V6_NEIGH__',
  "Can't open /var/run/frr/vtysh: No such file or directory",
  '__V4_ROUTES__',
  '',
  '__V6_ROUTES__',
  '',
  '__ROUTER_ID__',
  "Can't open /var/run/frr/vtysh: No such file or directory",
].join('\n');

// --- splitFrrSections ----------------------------------------------------------

describe('splitFrrSections', () => {
  it('splits the combined output into its seven sections', () => {
    const s = splitFrrSections(HEALTHY_COMBINED);
    expect(s.frrInstalled).toContain('frr.conf');
    expect(s.ospfConfigured).toContain('/usr/local/etc/frr/frr.conf');
    expect(s.v4Neigh).toContain('10.25.0.1');
    expect(s.v6Neigh).toContain('10.25.0.2');
    // Route sections = awk count line + table rows (the new layout).
    expect(s.v4Routes.split('\n')[0]).toBe('3');
    expect(s.v4Routes).toContain('O>* 10.25.10.0/24 [110/2] via 10.1.1.78, wg0, 00:43:11');
    expect(s.v6Routes.split('\n')[0]).toBe('1');
    expect(s.routerId).toContain('Router ID: 10.1.1.94');
  });

  it('leaves sections empty when their marker is absent', () => {
    const s = splitFrrSections('__V4_NEIGH__\nsome output');
    expect(s.v4Neigh).toBe('some output\n');
    expect(s.frrInstalled).toBe('');
    expect(s.routerId).toBe('');
  });

  it('returns all-empty sections for empty input', () => {
    expect(splitFrrSections('')).toEqual({
      frrInstalled: '',
      ospfConfigured: '',
      v4Neigh: '',
      v6Neigh: '',
      v4Routes: '',
      v6Routes: '',
      routerId: '',
    });
  });
});

// --- parseFrrDuration ----------------------------------------------------------

describe('parseFrrDuration', () => {
  it('parses FRR "XmYs" up-time strings', () => {
    expect(parseFrrDuration('43m16s')).toBe(2596);
    expect(parseFrrDuration('0m5s')).toBe(5);
  });

  it('parses clock-style durations (hh:mm:ss and mm:ss)', () => {
    expect(parseFrrDuration('00:43:11')).toBe(2591); // hh:mm:ss
    expect(parseFrrDuration('43:16')).toBe(2596); // mm:ss
  });

  it('parses w/d/h/m/s part strings in any order', () => {
    expect(parseFrrDuration('1h2m3s')).toBe(3723);
    expect(parseFrrDuration('2d5h')).toBe(2 * 86400 + 5 * 3600);
    expect(parseFrrDuration('90s')).toBe(90);
    expect(parseFrrDuration('1w')).toBe(604800);
  });

  it('returns null for "-", empty and unparseable values', () => {
    expect(parseFrrDuration('-')).toBeNull();
    expect(parseFrrDuration('')).toBeNull();
    expect(parseFrrDuration(undefined)).toBeNull();
    expect(parseFrrDuration('abc')).toBeNull();
  });
});

// --- neighbor parsers ----------------------------------------------------------

describe('parseOspfV4Neighbors', () => {
  it('parses a Full adjacency (state, up-time, address, interface suffix stripped)', () => {
    const rows = parseOspfV4Neighbors(V4_NEIGH_FULL);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      version: 'ospf',
      neighborId: '10.25.0.1',
      interfaceName: 'wg0', // "wg0:10.1.1.94" → local-ip suffix stripped
      state: 'Full/-',
      full: true,
      upTimeSeconds: 2596,
      address: '10.1.1.93',
    });
  });

  it('parses mixed Full/Down adjacencies and keeps the Down row non-full', () => {
    const rows = parseOspfV4Neighbors(V4_NEIGH_MIXED);
    expect(rows).toHaveLength(2);
    expect(rows[0].full).toBe(true);
    expect(rows[1]).toMatchObject({
      neighborId: '10.25.0.9',
      interfaceName: 'wg1',
      state: 'Down/WaitingInfo',
      full: false,
      upTimeSeconds: null, // "-" is not a duration
    });
  });

  it('returns no rows for a header-only (zero-neighbor) table', () => {
    expect(parseOspfV4Neighbors(V4_NEIGH_EMPTY)).toEqual([]);
  });

  it('skips FRR log-noise lines and non-IP first tokens', () => {
    const section = [NOISE, 'Neighbor ID Pri State Up Time Dead Time Address Interface', 'garbage line here'].join('\n');
    expect(parseOspfV4Neighbors(section)).toEqual([]);
  });
});

describe('parseOspfV6Neighbors', () => {
  it('parses a Full/PointToPoint adjacency (duration hh:mm:ss, bracket suffix stripped)', () => {
    const rows = parseOspfV6Neighbors(V6_NEIGH_FULL);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      version: 'ospfv6',
      neighborId: '10.25.0.2',
      interfaceName: 'wg4', // "wg4[PointToPoint]" → bracket state stripped
      state: 'Full/PointToPoint',
      full: true,
      upTimeSeconds: 2591,
    });
  });

  it('returns no rows for a header-only table or noise', () => {
    expect(parseOspfV6Neighbors([NOISE, 'Neighbor ID Pri DeadTime State/IfState Duration I/F'].join('\n'))).toEqual([]);
  });
});

// --- router id + route count ---------------------------------------------------

describe('parseRouterId / parseRouteCount', () => {
  it('extracts the router ID from a show ip ospf head', () => {
    expect(parseRouterId(ROUTER_ID_SECTION)).toBe('10.1.1.94');
    expect(parseRouterId("Can't open /var/run/frr/vtysh: No such file or directory")).toBeNull();
  });

  it('parses a single-integer route count and rejects anything else', () => {
    expect(parseRouteCount('128\n')).toBe(128);
    expect(parseRouteCount('0\n')).toBe(0);
    expect(parseRouteCount('\n')).toBeNull();
    expect(parseRouteCount('abc')).toBeNull();
  });
});

// --- OSPF route-table parsing (Routes page rows) --------------------------------

describe('splitRouteSection', () => {
  it('splits the awk count line from the remaining table rows', () => {
    const s = splitRouteSection(`3\n${V4_ROUTE_TABLE}`);
    expect(s.countLine).toBe('3');
    expect(s.table).toBe(V4_ROUTE_TABLE);
  });

  it('returns empty parts for an empty section', () => {
    expect(splitRouteSection('')).toEqual({ countLine: '', table: '' });
  });
});

describe('parseOspfRouteTable', () => {
  it('parses v4 route rows (flag chars, [dist/metric], via gw + interface with trailing commas)', () => {
    const rows = parseOspfRouteTable(V4_ROUTE_TABLE, 'ospf');
    expect(rows).toHaveLength(3);
    expect(rows[0]).toEqual({
      destination: '10.25.10.0/24',
      gateway: '10.1.1.78',
      protocol: 'ospf',
      distance: 110,
      metric: 2,
      status: 'active',
      extra: { version: 'ospf', interfaceName: 'wg0' },
    });
    expect(rows[1]).toMatchObject({
      destination: '10.25.20.0/24',
      gateway: '10.1.1.98',
      metric: 4,
      extra: { version: 'ospf', interfaceName: 'wg2' },
    });
  });

  it('parses summary routes (no next hop) and does NOT mistake the age token for an interface', () => {
    const rows = parseOspfRouteTable(V4_ROUTE_TABLE, 'ospf');
    expect(rows[2]).toEqual({
      destination: '10.25.0.0/16',
      gateway: '',
      protocol: 'ospf',
      distance: 110,
      metric: 1,
      status: 'active',
      extra: { version: 'ospf' }, // "is a summary, 02:00:00" — age rejected as interface
    });
  });

  it('parses v6 route rows with the ospfv6 version tag', () => {
    const rows = parseOspfRouteTable(V6_ROUTE_TABLE, 'ospfv6');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      destination: 'fe80::/64',
      gateway: 'fe80::1',
      protocol: 'ospf',
      distance: 110,
      metric: 1,
      status: 'active',
      extra: { version: 'ospfv6', interfaceName: 'wg4' },
    });
  });

  it('skips noise lines and the Codes header (non-O first tokens)', () => {
    const rows = parseOspfRouteTable([NOISE, 'Codes: C - connected, S - static, O - OSPF', 'garbage line'].join('\n'), 'ospf');
    expect(rows).toEqual([]);
  });

  it('omits distance/metric when the [d/m] token is absent', () => {
    const rows = parseOspfRouteTable('O>* 10.9.9.0/24 via 10.1.1.78, wg0, 00:01:00\n', 'ospf');
    expect(rows).toHaveLength(1);
    expect(rows[0]).toEqual({
      destination: '10.9.9.0/24',
      gateway: '10.1.1.78',
      protocol: 'ospf',
      status: 'active',
      extra: { version: 'ospf', interfaceName: 'wg0' },
    });
  });
});

// --- decideFrrCollection (cadence gate) ----------------------------------------

describe('decideFrrCollection', () => {
  const NOW = 1_700_000_000_000;
  const FIVE_MIN_MS = DEFAULT_FRR_MONITOR_INTERVAL_SEC * 1000; // 300 s

  it('runs on first sight (no entry yet) when an interval is configured', () => {
    expect(decideFrrCollection(undefined, NOW, FIVE_MIN_MS)).toBe('run');
  });

  it('never runs when the interval is 0 (disabled by setting)', () => {
    expect(decideFrrCollection(undefined, NOW, 0)).toBe('skip-disabled');
    // …even with a stale entry from before the user set 0.
    expect(decideFrrCollection({ lastRunAt: NOW - 3_600_000, inFlight: false }, NOW, 0)).toBe('skip-disabled');
  });

  it('skips while a collection is already in flight (no overlapping SSH execs)', () => {
    expect(decideFrrCollection({ lastRunAt: 0, inFlight: true }, NOW, FIVE_MIN_MS)).toBe('skip-inflight');
    // In-flight wins over cadence — a due run must not stack on the running one.
    expect(
      decideFrrCollection({ lastRunAt: NOW - 2 * FIVE_MIN_MS, inFlight: true }, NOW, FIVE_MIN_MS)
    ).toBe('skip-inflight');
  });

  it('skips when the cadence has not elapsed since the last successful run', () => {
    const entry = { lastRunAt: NOW - 60_000, inFlight: false }; // ran a minute ago
    expect(decideFrrCollection(entry, NOW, FIVE_MIN_MS)).toBe('skip-cadence');
  });

  it('runs again once the cadence has elapsed (exactly due counts)', () => {
    const due = { lastRunAt: NOW - FIVE_MIN_MS, inFlight: false };
    expect(decideFrrCollection(due, NOW, FIVE_MIN_MS)).toBe('run');
    const overdue = { lastRunAt: NOW - 10 * FIVE_MIN_MS, inFlight: false };
    expect(decideFrrCollection(overdue, NOW, FIVE_MIN_MS)).toBe('run');
  });

  it('re-runs once due after SSH-level failures (a null result never advanced lastRunAt)', () => {
    // The caller only advances lastRunAt for non-null results. A host whose
    // entry still shows the OLD successful run time is due again as soon as the
    // cadence elapses — no matter how many failed beats happened in between.
    const stale = { lastRunAt: NOW - 301_000, inFlight: false }; // last SUCCESS just over a minute+ ago…
    expect(decideFrrCollection(stale, NOW, FIVE_MIN_MS)).toBe('run');
    // …and it does NOT run early just because recent beats failed.
    const notDue = { lastRunAt: NOW - 60_000, inFlight: false };
    expect(decideFrrCollection(notDue, NOW, FIVE_MIN_MS)).toBe('skip-cadence');
  });
});

// --- deriveFrrConditions (condition matrix) ------------------------------------

describe('deriveFrrConditions', () => {
  const base: FrrOspfResult = {
    frrInstalled: true,
    frrInspectable: true,
    ospfConfigured: true,
    frrReachable: true,
    routerId: '10.1.1.94',
    neighbors: [
      { version: 'ospf', neighborId: '10.25.0.1', interfaceName: 'wg0', state: 'Full/-', full: true, upTimeSeconds: 2596, address: '10.1.1.93' },
    ],
    v4RoutesLearned: 128,
    v6RoutesLearned: 0,
    routes: [],
  };

  it('returns [] for no fresh data (caller must not touch known-sets)', () => {
    expect(deriveFrrConditions(null)).toEqual([]);
  });

  it('stays silent when FRR is not installed at all', () => {
    expect(deriveFrrConditions({ ...base, frrInstalled: false })).toEqual([]);
  });

  it('stays silent when OSPF was never configured (box outside the routing domain)', () => {
    expect(deriveFrrConditions({ ...base, ospfConfigured: false })).toEqual([]);
  });

  it('still evaluates BGP conditions on a box with NO OSPF (v0.11.0 restructure)', () => {
    const conds = deriveFrrConditions(
      {
        ...base,
        ospfConfigured: false,
        neighbors: [],
        bgp: { configured: true, peers: [{ neighborId: '10.1.1.97', state: 'Active', established: false }] },
      },
      'GWST04'
    );
    // Per-peer warning + the all-down critical — none of this ran before v0.11
    // because !ospfConfigured short-circuited the function.
    expect(conds).toHaveLength(2);
    expect(conds.map((c) => c.dedupeKey)).toEqual(['bgp-peer:10.1.1.97', 'bgp-all-down:GWST04']);
  });

  it('raises a permission warning when FRR is installed but not inspectable by the bound user', () => {
    const conds = deriveFrrConditions(
      { ...base, frrInspectable: false, frrReachable: false, neighbors: [], routerId: null },
      'OPNSENSE01'
    );
    expect(conds).toHaveLength(1);
    expect(conds[0]).toMatchObject({ severity: 'warning', dedupeKey: 'frr-permissions:OPNSENSE01' });
    expect(conds[0].message).toContain('not inspectable');
  });

  it('does NOT raise the permission warning when FRR is absent at all (silent skip)', () => {
    expect(deriveFrrConditions({ ...base, frrInstalled: false, frrInspectable: false })).toEqual([]);
  });

  it('raises a critical condition when vtysh does not answer (the blackhole case)', () => {
    const conds = deriveFrrConditions({ ...base, frrReachable: false, neighbors: [], routerId: null }, 'GWST03');
    expect(conds).toHaveLength(1);
    expect(conds[0]).toMatchObject({ severity: 'critical', dedupeKey: 'frr-ospf:GWST03' });
    // Protocol-neutral since v0.11.0 — the box may run BGP instead of (or in
    // addition to) OSPF, and a stopped FRR takes both down at once.
    expect(conds[0].message).toBe('GWST03: FRR routing daemons not responding (down?)');
    expect(conds[0].detail).toBeTruthy();
  });

  it('falls back to "appliance" as the label when no hostname is known', () => {
    const conds = deriveFrrConditions({ ...base, frrReachable: false, neighbors: [] });
    expect(conds[0]?.dedupeKey).toBe('frr-ospf:appliance');
  });

  it('returns [] when everything is Full and routes are learned', () => {
    expect(deriveFrrConditions(base)).toEqual([]);
  });

  it('raises a per-neighbor warning for every non-Full adjacency (stable dedupe key)', () => {
    const conds = deriveFrrConditions({
      ...base,
      neighbors: [
        base.neighbors[0],
        { version: 'ospf', neighborId: '10.25.0.9', interfaceName: 'wg1', state: 'Down/WaitingInfo', full: false },
        { version: 'ospfv6', neighborId: '10.25.0.3', interfaceName: 'wg4', state: 'PointToPoint/Down', full: false },
      ],
    }, 'GWST03');
    expect(conds).toHaveLength(2);
    expect(conds[0]).toMatchObject({ severity: 'warning', dedupeKey: 'ospf-neighbor:ospf:wg1:10.25.0.9' });
    expect(conds[0].message).toContain('GWST03'); // label-prefixed by the caller's hostname
    expect(conds[1]).toMatchObject({ severity: 'warning', dedupeKey: 'ospf-neighbor:ospfv6:wg4:10.25.0.3' });
  });

  it('raises a zero-routes warning when adjacencies are Full but nothing was learned', () => {
    const conds = deriveFrrConditions({ ...base, v4RoutesLearned: 0, v6RoutesLearned: null }, 'GWST03');
    expect(conds).toHaveLength(1);
    expect(conds[0]).toMatchObject({ severity: 'warning', dedupeKey: 'ospf-routes-zero:GWST03' });
  });

  it('does NOT raise the zero-routes warning when v4 routes exist (v6 may legitimately be 0)', () => {
    expect(deriveFrrConditions(base)).toEqual([]); // base has v4=128, v6=0
  });
});
