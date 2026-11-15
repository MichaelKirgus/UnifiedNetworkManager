/**
 * FRR/OSPF monitoring — routing-protocol state over the appliance's REST API.
 *
 * v0.10.0 made this the PRIMARY data path (replacing SSH-first). It is the same
 * pipeline OPNsense's own Diagnostics → Routing screen uses: the REST controllers
 * call configd's `quagga` plugin, which runs vtysh as root on the appliance — so
 * NO SSH slot and NO frr group membership are required (OPNsense locks all FRR
 * state to user/group `frr`; a non-root remote user can never read it). The
 * Quagga API area is core code in both Community and Business Edition; FRR itself
 * is the optional os-frr package, whose installed/running state the service-status
 * endpoint reflects. See client/quagga.ts for the endpoint inventory.
 *
 * State machine (from GET /api/quagga/service/status):
 *   'disabled'  → os-frr absent or intentionally off → out of scope (silent skip)
 *   'stopped'   → installed + enabled but NOT running = the blackhole case →
 *                 frrReachable=false → CRITICAL condition (GWST03 scenario)
 *   'running'   → collect OSPF overview/neighbors/routes for both families AND
 *                 BGP summary/peers/route tables in one parallel batch. "No data"
 *                 means the protocol is not configured on this box: ALL of them
 *                 empty (no OSPF overviews, no BGP peers/localAS) → silent skip;
 *                 any one with data → frrReachable=true and that protocol's
 *                 section is populated.
 *
 * Contract: returns null ONLY when the quagga REST surface is unavailable
 * (older firmware without the API area, ACL-blocked) — callers then fall back to
 * the legacy vtysh-over-SSH path (frrOspf.ts) if a slot is bound. A FRR that is
 * DOWN still yields a RESULT (frrReachable=false): THAT is the data point we
 * alert on. BEST-EFFORT: never throws into /monitoring.
 */

import type { AxiosInstance } from 'axios';
import * as quagga from './client/quagga';
import type { OpnsenseApiResult } from './client/http';
import { type BgpPeerRow, type FrrBgpSection, type FrrOspfResult, type OspfNeighborRow, type OspfRouteRow } from './frrOspf';

/** Reads a string field, trimmed; '' when absent/non-string. */
function str(row: Record<string, unknown>, key: string): string {
  const v = row[key];
  return typeof v === 'string' ? v.trim() : '';
}

/** Reads a numeric field (number or numeric string); null when absent/unparseable. */
function num(row: Record<string, unknown>, key: string): number | null {
  const v = row[key];
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '') {
    const n = Number(v);
    if (Number.isFinite(n)) return n;
  }
  return null;
}

/** Strips the ':address' suffix configd appends to ifaceName ("wg0:10.1.1.97" → "wg0"). */
function cleanIface(name: string): string {
  const i = name.indexOf(':');
  return (i >= 0 ? name.slice(0, i) : name).trim();
}

/** True when an overview payload carries real OSPF state (not the empty `[]` fallback). */
function overviewHasData(ov: Record<string, unknown> | null): boolean {
  if (!ov) return false;
  return typeof ov['routerId'] === 'string' || (ov['areas'] !== undefined && ov['areas'] !== null);
}

/** True for a plain object (not an array / null). */
function isObj(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

/**
 * Extracts BGP peer rows from a /api/quagga/diagnostics/bgpsummary payload.
 * Tolerates both FRR layouts (envelope differences across versions):
 *   - `show bgp summary json`:  { ipv4Unicast: {peers: {...}}, ipv6Unicast: {...} }
 *   - flat per-AFI:             { as|localAS, routerId, peers: {...}, totalPeers }
 * Returns [] for empty payloads — when bgpd is not running configd returns
 * nothing and the PHP controller's `json_decode(...) ?? []` fallback yields an
 * array (verified live on a box with FRR up but no BGP). Peers appearing in
 * several AFI sections are deduped by address, preferring the more informative
 * entry (established / non-empty state wins).
 */
export function parseBgpSummary(payload: Record<string, unknown> | null): BgpPeerRow[] {
  if (!isObj(payload)) return []; // `[]` fallback or garbage → no BGP data
  const peerMaps: Record<string, unknown>[] = [];
  if (isObj(payload['peers'])) peerMaps.push(payload['peers']);
  for (const v of Object.values(payload)) {
    // One level down: AFI sections (ipv4Unicast/ipv6Unicast) or a vrf wrapper.
    if (isObj(v) && isObj(v['peers'])) peerMaps.push(v['peers']);
  }
  const byId = new Map<string, BgpPeerRow>();
  for (const map of peerMaps) {
    for (const [id, raw] of Object.entries(map)) {
      if (!isObj(raw)) continue;
      const state = str(raw, 'state');
      const pfxRcd = num(raw, 'pfxRcd');
      const row: BgpPeerRow = {
        neighborId: id,
        remoteAs: num(raw, 'remoteAs'),
        state,
        // Established when FRR says so — or (older layouts) when it reports a
        // prefix count without a state string.
        established: /^established/i.test(state) || (state === '' && pfxRcd !== null),
        ...(pfxRcd !== null ? { prefixesReceived: pfxRcd } : {}),
      };
      const existing = byId.get(id);
      if (!existing || (!existing.established && row.established)) byId.set(id, row);
    }
  }
  return [...byId.values()];
}

/** Reads the local AS from a bgpsummary payload (top level or one AFI down). */
export function parseBgpLocalAs(payload: Record<string, unknown> | null): number | null {
  if (!isObj(payload)) return null;
  const candidates = [payload, ...Object.values(payload).filter(isObj)];
  for (const c of candidates) {
    const v = num(c, 'localAS') ?? num(c, 'as');
    if (v !== null && v > 0) return v;
  }
  return null;
}

/** Reads the router ID from a bgpsummary payload (top level or one AFI down). */
export function parseBgpRouterId(payload: Record<string, unknown> | null): string | null {
  if (!isObj(payload)) return null;
  const candidates = [payload, ...Object.values(payload).filter(isObj)];
  for (const c of candidates) {
    const v = str(c, 'routerId');
    if (v !== '') return v;
  }
  return null;
}

/**
 * Fallback peer source from /api/quagga/diagnostics/bgpneighbors — used only
 * when the summary carried no peers. The payload is an object keyed by peer
 * address (possibly under a `neighbors` key); entries without a usable state
 * are still kept (state '' → treated as not established).
 */
export function parseBgpNeighborsFallback(payload: Record<string, unknown> | null): BgpPeerRow[] {
  if (!isObj(payload)) return [];
  const map = isObj(payload['neighbors']) ? payload['neighbors'] : payload;
  const rows: BgpPeerRow[] = [];
  for (const [id, raw] of Object.entries(map)) {
    if (!isObj(raw)) continue; // skip scalar metadata keys (routerId, localAS, ...)
    const state = str(raw, 'state');
    rows.push({
      neighborId: id,
      remoteAs: num(raw, 'remoteAs'),
      state,
      established: /^established/i.test(state),
      ...(num(raw, 'pfxRcd') !== null ? { prefixesReceived: num(raw, 'pfxRcd') } : {}),
    });
  }
  return rows;
}

/**
 * Parses one BGP learned-route recordset (searchBgproute4/6) into route rows.
 * Each row is a route merged with ONE of its nexthops by the PHP controller:
 * destination under `network` (defensively also `destination`), next-hop IP in
 * `ip`, egress interface in `interfaceName`, iBGP/eBGP origin in `pathFrom`.
 * Multi-path prefixes appear once per path — deduped to one row per destination.
 */
export function parseBgpRouteRows(res: OpnsenseApiResult | undefined): OspfRouteRow[] {
  const rows: OspfRouteRow[] = [];
  if (!res) return rows;
  const seen = new Set<string>();
  for (const row of quagga.rowsOf(res)) {
    // FRR's per-path JSON carries the prefix as "network"; keep fallbacks in
    // case a firmware version renames it. Rows without ANY parseable
    // destination are skipped — peer monitoring is unaffected either way.
    const dest = str(row, 'network') || str(row, 'destination') || str(row, 'prefix');
    if (!dest || seen.has(dest)) continue;
    seen.add(dest);
    const gw = str(row, 'ip') || str(row, 'via');
    rows.push({
      destination: dest,
      gateway: gw === '' || /^directly attached/i.test(gw) ? '' : gw,
      protocol: 'bgp',
      status: 'active',
      extra: {
        // The webapp Routes page renders extra.peer for non-OSPF rows (the egress
        // interface — which tunnel carries that prefix).
        ...(str(row, 'interfaceName') ? { peer: str(row, 'interfaceName') } : {}),
        ...(str(row, 'pathFrom') ? { pathFrom: str(row, 'pathFrom') } : {}),
      },
    });
  }
  return rows;
}

/**
 * Collects FRR routing-protocol state (OSPF + BGP) via REST. Returns null when
 * the quagga REST surface is unavailable (caller falls back to SSH); otherwise a
 * full result — including frrReachable=false for a stopped FRR, which IS the alert case.
 */
export async function collectFrrViaRest(client: AxiosInstance): Promise<FrrOspfResult | null> {
  // 1) Service state — the single source of truth for installed/running.
  let statusRes;
  try {
    statusRes = await quagga.getQuaggaServiceStatus(client);
  } catch {
    return null; // transport failure — best-effort, fall back to SSH
  }
  const status = quagga.quaggaStatusOf(statusRes);
  if (status === null) return null; // endpoint missing/failed → REST surface unavailable

  if (status === 'disabled') {
    // os-frr not installed, or intentionally disabled → out of scope (silent).
    return { frrInstalled: false, frrInspectable: true, ospfConfigured: false, frrReachable: false, neighbors: [], routes: [] };
  }

  if (status === 'stopped') {
    // Installed + enabled but not running = the blackhole case. REST cannot read
    // the config file to check whether OSPF was configured, so we assume it was:
    // a firewall whose FRR service is stopped has lost its routing-protocol state —
    // exactly what this feature exists to catch (GWST03). deriveFrrConditions turns
    // frrReachable=false into the CRITICAL condition.
    return { frrInstalled: true, frrInspectable: true, ospfConfigured: true, frrReachable: false, neighbors: [], routes: [] };
  }

  // 2) status === 'running' → collect OSPF (both families) + BGP in ONE parallel
  // batch — all best-effort; a single failing endpoint must not sink the rest.
  const [v4ovRes, v6ovRes, v4neighRes, v4routeRes, v6routeRes, bgpSumRes, bgpNeighRes, bgpRoute4Res, bgpRoute6Res] = await Promise.all([
    quagga.getOspfOverview(client).catch(() => undefined),
    quagga.getOspfv3Overview(client).catch(() => undefined),
    quagga.searchOspfNeighbors(client).catch(() => undefined),
    quagga.searchOspfRoutes(client).catch(() => undefined),
    quagga.searchOspfv3Routes(client).catch(() => undefined),
    quagga.getBgpSummary(client).catch(() => undefined),
    quagga.getBgpNeighbors(client).catch(() => undefined),
    quagga.searchBgpRoutesV4(client).catch(() => undefined),
    quagga.searchBgpRoutesV6(client).catch(() => undefined),
  ]);

  const v4ov = v4ovRes ? quagga.responseOf(v4ovRes) : null;
  const v6ov = v6ovRes ? quagga.responseOf(v6ovRes) : null;
  const v4HasData = overviewHasData(v4ov);
  const v6HasData = overviewHasData(v6ov);

  // BGP (v0.11.0): the summary is the source of truth for "does this box run
  // BGP" — peers reported, or at least a local AS / router ID present. The
  // neighbors endpoint is only a fallback peer source when the summary is empty.
  const bgpSummaryPayload = bgpSumRes ? quagga.responseOf(bgpSumRes) : null;
  let bgpPeers = parseBgpSummary(bgpSummaryPayload);
  if (bgpPeers.length === 0 && bgpNeighRes) {
    bgpPeers = parseBgpNeighborsFallback(quagga.responseOf(bgpNeighRes));
  }
  const bgpLocalAs = parseBgpLocalAs(bgpSummaryPayload);
  const bgpConfigured = bgpPeers.length > 0 || bgpLocalAs !== null;

  if (!v4HasData && !v6HasData && !bgpConfigured) {
    // FRR is running but reports NO routing-protocol state at all (no OSPF
    // overviews, no BGP peers/localAS) → nothing configured on this box. Out of
    // scope — stay silent rather than raise a false "FRR down" critical.
    return { frrInstalled: true, frrInspectable: true, ospfConfigured: false, frrReachable: false, neighbors: [], routes: [] };
  }

  // 3) v4 neighbors (no per-neighbor endpoint exists for OSPFv6).
  const neighbors: OspfNeighborRow[] = [];
  if (v4HasData && v4neighRes) {
    for (const row of quagga.rowsOf(v4neighRes)) {
      const state = str(row, 'nbrState');
      if (!state) continue;
      const upMs = num(row, 'upTimeInMsec');
      neighbors.push({
        version: 'ospf',
        neighborId: str(row, 'neighborid'),
        interfaceName: cleanIface(str(row, 'ifaceName')),
        state,
        full: /^full/i.test(state),
        upTimeSeconds: upMs === null ? null : Math.round(upMs / 1000),
        address: str(row, 'ifaceAddress') || null,
      });
    }
  }

  // 4) v4 learned routes — one row per destination (dedupe; first hop wins).
  const routes: OspfRouteRow[] = [];
  const seenV4 = new Set<string>();
  if (v4HasData && v4routeRes) {
    for (const row of quagga.rowsOf(v4routeRes)) {
      const dest = str(row, 'network');
      if (!dest || seenV4.has(dest)) continue;
      seenV4.add(dest);
      const via = str(row, 'via');
      routes.push({
        destination: dest,
        gateway: via === '' || /^directly attached/i.test(via) ? '' : via,
        protocol: 'ospf',
        metric: num(row, 'cost'),
        status: 'active',
        extra: { area: str(row, 'area') || undefined, routeType: str(row, 'type') || undefined },
      });
    }
  }

  // 5) v6 learned routes — the recordset carries one row per (destination × path);
  // keep ONE row per destination, preferring the best route's first next hop.
  const seenV6 = new Map<string, OspfRouteRow>();
  if (v6HasData && v6routeRes) {
    for (const row of quagga.rowsOf(v6routeRes)) {
      const dest = str(row, 'network');
      if (!dest) continue;
      const isBest = row['isBestRoute'] === true || row['isBestRoute'] === 1 || row['isBestRoute'] === '1';
      const existing = seenV6.get(dest);
      if (existing && !isBest) continue; // a best route replaces any earlier non-best one
      const nextHop = str(row, 'nextHop');
      seenV6.set(dest, {
        destination: dest,
        gateway: nextHop === '' || nextHop === '::' ? '' : nextHop,
        protocol: 'ospf',
        status: 'active',
        extra: { interfaceName: str(row, 'interfaceName') || undefined, pathType: str(row, 'pathType') || undefined },
      });
    }
  }

  // 6) BGP learned routes (v0.11.0) — one row per destination per family.
  const bgpRoutesV4 = parseBgpRouteRows(bgpRoute4Res);
  const bgpRoutesV6 = parseBgpRouteRows(bgpRoute6Res);

  // Router ID: OSPF overviews first, BGP summary as fallback (BGP-only boxes).
  const routerId = (v4ov && typeof v4ov['routerId'] === 'string' ? v4ov['routerId'] : '') ||
    (v6ov && typeof v6ov['routerId'] === 'string' ? v6ov['routerId'] : '') ||
    parseBgpRouterId(bgpSummaryPayload) || null;

  const bgp: FrrBgpSection = {
    configured: bgpConfigured,
    peers: bgpPeers,
    ...(bgpLocalAs !== null ? { localAs: bgpLocalAs } : {}),
    v4RoutesLearned: bgpRoutesV4.length,
    v6RoutesLearned: bgpRoutesV6.length,
  };

  return {
    frrInstalled: true,
    frrInspectable: true, // configd runs vtysh as root server-side — no permission lockout possible
    ospfConfigured: v4HasData || v6HasData,
    frrReachable: true,
    routerId,
    neighbors,
    v4RoutesLearned: seenV4.size,
    v6RoutesLearned: seenV6.size,
    routes: [...routes, ...seenV6.values(), ...bgpRoutesV4, ...bgpRoutesV6],
    bgp,
  };
}
