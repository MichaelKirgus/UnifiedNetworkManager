/**
 * Unit tests for the REST-first FRR/OSPF collection (frrRest.ts).
 * Pure logic — no appliance, no network. The fixtures are REAL captured data
 * from OPNSENSE01's configd quagga diagnostics (26.10 BE): ospfoverview,
 * searchOspfneighbor rows, searchOspfroute rows and the multi-path
 * searchOspfv3route recordset.
 */
import type { AxiosInstance } from 'axios';
import { collectFrrViaRest } from './frrRest';
import { deriveFrrConditions } from './frrOspf';

// --- Fake client ---------------------------------------------------------------

/** Builds a fake axios instance serving canned bodies per path (404 when absent). */
function makeClient(routes: Record<string, unknown>): AxiosInstance {
  return {
    get: async (path: string) => {
      const body = routes[path];
      if (body === undefined) return { status: 404, data: {} };
      return { status: 200, data: body };
    },
  } as unknown as AxiosInstance;
}

// --- Real captured fixtures (OPNSENSE01, configd quagga diagnostics) ------------

const V4_OVERVIEW = {
  response: {
    routerId: '10.25.0.1',
    tosRoutesOnly: true,
    maximumPaths: 64,
    preference: 110,
    attachedAreaCounter: 1,
    areas: {
      '0.0.0.0': { backbone: true, areaIfTotalCounter: 33, areaIfActiveCounter: 33, nbrFullAdjacentCounter: 16 },
    },
  },
};

const V4_NEIGHBORS = {
  response: {
    rows: [
      { neighborid: '10.1.1.98', nbrState: 'Full/-', role: 'DROther', upTimeInMsec: 9710877, ifaceAddress: '10.1.1.98', ifaceName: 'wg0:10.1.1.97' },
      { neighborid: '10.1.1.102', nbrState: 'Full/-', role: 'DROther', upTimeInMsec: 9710854, ifaceAddress: '10.1.1.102', ifaceName: 'wg1:10.1.1.101' },
      { neighborid: '10.1.1.106', nbrState: 'Down/WaitingInfo', role: 'DROther', upTimeInMsec: 0, ifaceAddress: '10.1.1.105', ifaceName: 'wg2:10.1.1.104' },
    ],
    total: 3,
  },
};

const V4_ROUTES = {
  response: {
    rows: [
      // Point-to-point /30s — the "via" field is a bare space (PHP !empty(' ') = true).
      { type: 'N', network: '10.1.1.32/30', cost: 20, area: '0.0.0.0', via: ' ', viainterface: 'wg35' },
      // A learned external route with a real next hop.
      { type: 'E2', network: '10.9.8.0/24', cost: 100, area: '', via: '10.1.1.97', viainterface: 'wg0' },
    ],
    total: 2,
  },
};

const V6_OVERVIEW = {
  response: { routerId: '10.25.0.2', running: '18:28:08', numberOfAreaInRouter: 1 },
};

/** Multi-path recordset: the /127 prefix appears TWICE (best + non-best path). */
const V6_ROUTES = {
  response: {
    rows: [
      { network: 'fd42:1:1:1::/127', isBestRoute: true, destinationType: 'N', pathType: 'IA', duration: '18:28:00', nextHop: '::', interfaceName: 'wg7' },
      { network: 'fd42:1:1:1::/127', isBestRoute: false, destinationType: 'N', pathType: 'IA', duration: '00:23:00', nextHop: 'fe80:0:1:2::1', interfaceName: 'wg6' },
      { network: 'fd42:1:1:1::1/128', isBestRoute: true, destinationType: 'N', pathType: 'INTRA', duration: '00:23:00', nextHop: 'fe80:0:1:2::1', interfaceName: 'wg6' },
    ],
    total: 3,
  },
};

const RUNNING_ROUTES = {
  '/api/quagga/service/status': { status: 'running', widget: {} },
  '/api/quagga/diagnostics/ospfoverview': V4_OVERVIEW,
  '/api/quagga/diagnostics/searchOspfneighbor': V4_NEIGHBORS,
  '/api/quagga/diagnostics/searchOspfroute': V4_ROUTES,
  '/api/quagga/diagnostics/ospfv3overview': V6_OVERVIEW,
  '/api/quagga/diagnostics/searchOspfv3route': V6_ROUTES,
};

// --- State machine ---------------------------------------------------------------

describe('collectFrrViaRest — service-state machine', () => {
  it('returns null when the quagga REST surface is unavailable (404)', async () => {
    const client = makeClient({}); // every path → 404
    expect(await collectFrrViaRest(client)).toBeNull();
  });

  it('treats a non-2xx service-status as unavailable', async () => {
    const client = { get: async () => ({ status: 503, data: {} }) } as unknown as AxiosInstance;
    expect(await collectFrrViaRest(client)).toBeNull();
  });

  it('treats an unrecognized status string as unavailable', async () => {
    const client = makeClient({ '/api/quagga/service/status': { status: 'unknown' } });
    expect(await collectFrrViaRest(client)).toBeNull();
  });

  it('maps "disabled" to out-of-scope (no FRR / intentionally off → silent)', async () => {
    const client = makeClient({ '/api/quagga/service/status': { status: 'disabled' } });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrInstalled).toBe(false);
    expect(r!.frrReachable).toBe(false);
  });

  it('maps "stopped" to installed-but-down (the CRITICAL alert case)', async () => {
    const client = makeClient({ '/api/quagga/service/status': { status: 'stopped' } });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrInstalled).toBe(true);
    expect(r!.ospfConfigured).toBe(true);
    expect(r!.frrReachable).toBe(false);
    // And deriveFrrConditions turns that into the critical condition.
    const conds = deriveFrrConditions(r, 'GWST03');
    expect(conds).toHaveLength(1);
    expect(conds[0].severity).toBe('critical');
    expect(conds[0].dedupeKey).toBe('frr-ospf:GWST03');
  });

  it('maps "running" with empty overviews to OSPF-not-configured (silent)', async () => {
    const client = makeClient({
      '/api/quagga/service/status': { status: 'running' },
      // configd returned nothing → the controller's json_decode fallback `[]`.
      '/api/quagga/diagnostics/ospfoverview': { response: [] },
      '/api/quagga/diagnostics/ospfv3overview': { response: [] },
    });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrInstalled).toBe(true);
    expect(r!.ospfConfigured).toBe(false);
    expect(r!.frrReachable).toBe(false);
    // No conditions — a box running FRR without OSPF is out of scope.
    expect(deriveFrrConditions(r, 'BOX')).toEqual([]);
  });
});

// --- Full collection (real OPNSENSE01 data) --------------------------------------

describe('collectFrrViaRest — full collection', () => {
  it('parses neighbors, routes and router ID from the real fixtures', async () => {
    const r = await collectFrrViaRest(makeClient(RUNNING_ROUTES));
    expect(r).not.toBeNull();
    expect(r!.frrInstalled).toBe(true);
    expect(r!.frrInspectable).toBe(true);
    expect(r!.ospfConfigured).toBe(true);
    expect(r!.frrReachable).toBe(true);
    expect(r!.routerId).toBe('10.25.0.1'); // v4 overview wins

    // Neighbors: ifaceName suffix stripped, Full detection, uptime in seconds.
    expect(r!.neighbors).toHaveLength(3);
    const [a, b, c] = r!.neighbors;
    expect(a).toMatchObject({ version: 'ospf', neighborId: '10.1.1.98', interfaceName: 'wg0', state: 'Full/-', full: true, upTimeSeconds: 9711, address: '10.1.1.98' });
    expect(b.interfaceName).toBe('wg1');
    expect(c).toMatchObject({ neighborId: '10.1.1.106', interfaceName: 'wg2', state: 'Down/WaitingInfo', full: false, upTimeSeconds: 0 });

    // v4 routes: the bare-space "via" becomes '' (directly attached), cost → metric.
    const v4 = r!.routes.filter((x) => x.destination.startsWith('10.'));
    expect(v4).toHaveLength(2);
    expect(v4[0]).toMatchObject({ destination: '10.1.1.32/30', gateway: '', protocol: 'ospf', metric: 20, status: 'active' });
    expect(v4[0].extra).toEqual({ area: '0.0.0.0', routeType: 'N' });
    expect(v4[1]).toMatchObject({ destination: '10.9.8.0/24', gateway: '10.1.1.97', metric: 100 });

    // v6 routes: multi-path deduped per destination, best route wins ('::' → '').
    const v6 = r!.routes.filter((x) => x.destination.startsWith('fd42'));
    expect(v6).toHaveLength(2);
    const p127 = v6.find((x) => x.destination === 'fd42:1:1:1::/127')!;
    expect(p127.gateway).toBe(''); // best path's nextHop was '::'
    expect(p127.extra).toEqual({ interfaceName: 'wg7', pathType: 'IA' });
    const p128 = v6.find((x) => x.destination === 'fd42:1:1:1::1/128')!;
    expect(p128.gateway).toBe('fe80:0:1:2::1');

    // Learned-route counts drive the zero-routes alerting.
    expect(r!.v4RoutesLearned).toBe(2);
    expect(r!.v6RoutesLearned).toBe(2);

    // Healthy box → no conditions (all Full neighbors counted, routes > 0).
    const conds = deriveFrrConditions(r, 'OPNSENSE01');
    // The one Down neighbor IS reported.
    expect(conds).toHaveLength(1);
    expect(conds[0].severity).toBe('warning');
    expect(conds[0].dedupeKey).toBe('ospf-neighbor:ospf:wg2:10.1.1.106');
  });

  it('accepts top-level (unwrapped) response envelopes', async () => {
    const client = makeClient({
      '/api/quagga/service/status': { status: 'running' },
      '/api/quagga/diagnostics/ospfoverview': V4_OVERVIEW.response, // no `response` wrapper
      '/api/quagga/diagnostics/searchOspfneighbor': V4_NEIGHBORS.response,
      '/api/quagga/diagnostics/searchOspfroute': V4_ROUTES.response,
    });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrReachable).toBe(true);
    expect(r!.routerId).toBe('10.25.0.1');
    expect(r!.neighbors).toHaveLength(3);
    expect(r!.v4RoutesLearned).toBe(2);
  });

  it('collects v6-only boxes (no v4 OSPF) and takes the router ID from v6', async () => {
    const client = makeClient({
      '/api/quagga/service/status': { status: 'running' },
      '/api/quagga/diagnostics/ospfoverview': { response: [] }, // no v4 OSPF
      '/api/quagga/diagnostics/ospfv3overview': V6_OVERVIEW,
      '/api/quagga/diagnostics/searchOspfv3route': V6_ROUTES,
    });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrReachable).toBe(true);
    expect(r!.routerId).toBe('10.25.0.2');
    expect(r!.neighbors).toHaveLength(0); // no v6 neighbor endpoint exists
    expect(r!.v4RoutesLearned).toBe(0);
    expect(r!.v6RoutesLearned).toBe(2);
  });

  it('survives individual endpoint failures (best-effort per call)', async () => {
    const client = makeClient({
      '/api/quagga/service/status': { status: 'running' },
      '/api/quagga/diagnostics/ospfoverview': V4_OVERVIEW,
      // neighbor + route endpoints missing → 404s must not sink the collection.
    });
    const r = await collectFrrViaRest(client);
    expect(r).not.toBeNull();
    expect(r!.frrReachable).toBe(true);
    expect(r!.routerId).toBe('10.25.0.1');
    expect(r!.neighbors).toHaveLength(0);
    expect(r!.v4RoutesLearned).toBe(0);
  });
});
