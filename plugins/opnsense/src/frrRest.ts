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
 *   'running'   → collect overview/neighbors/routes for both families; empty
 *                 overviews mean "FRR up, OSPF not configured" → silent skip
 *
 * Contract: returns null ONLY when the quagga REST surface is unavailable
 * (older firmware without the API area, ACL-blocked) — callers then fall back to
 * the legacy vtysh-over-SSH path (frrOspf.ts) if a slot is bound. A FRR that is
 * DOWN still yields a RESULT (frrReachable=false): THAT is the data point we
 * alert on. BEST-EFFORT: never throws into /monitoring.
 */

import type { AxiosInstance } from 'axios';
import * as quagga from './client/quagga';
import { type FrrOspfResult, type OspfNeighborRow, type OspfRouteRow } from './frrOspf';

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

/**
 * Collects FRR/OSPF state via REST. Returns null when the quagga REST surface is
 * unavailable (caller falls back to SSH); otherwise a full result — including
 * frrReachable=false for a stopped FRR, which IS the alert case.
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

  // 2) status === 'running' → collect both families in parallel (all best-effort).
  const [v4ovRes, v6ovRes, v4neighRes, v4routeRes, v6routeRes] = await Promise.all([
    quagga.getOspfOverview(client).catch(() => undefined),
    quagga.getOspfv3Overview(client).catch(() => undefined),
    quagga.searchOspfNeighbors(client).catch(() => undefined),
    quagga.searchOspfRoutes(client).catch(() => undefined),
    quagga.searchOspfv3Routes(client).catch(() => undefined),
  ]);

  const v4ov = v4ovRes ? quagga.responseOf(v4ovRes) : null;
  const v6ov = v6ovRes ? quagga.responseOf(v6ovRes) : null;
  const v4HasData = overviewHasData(v4ov);
  const v6HasData = overviewHasData(v6ov);

  if (!v4HasData && !v6HasData) {
    // FRR is running but reports no OSPF state at all → OSPF not configured on
    // this box (or the diagnostics plugin itself is broken). Out of scope — stay
    // silent rather than raise a false "FRR down" critical.
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

  const routerId = (v4ov && typeof v4ov['routerId'] === 'string' ? v4ov['routerId'] : '') ||
    (v6ov && typeof v6ov['routerId'] === 'string' ? v6ov['routerId'] : null);

  return {
    frrInstalled: true,
    frrInspectable: true, // configd runs vtysh as root server-side — no permission lockout possible
    ospfConfigured: true,
    frrReachable: true,
    routerId: routerId || null,
    neighbors,
    v4RoutesLearned: seenV4.size,
    v6RoutesLearned: seenV6.size,
    routes: [...routes, ...seenV6.values()],
  };
}
