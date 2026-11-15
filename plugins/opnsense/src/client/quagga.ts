import type { AxiosInstance } from 'axios';
import { get, OpnsenseApiResult } from './http';

/**
 * Quagga/FRR module — routing-protocol state over REST (NO SSH required).
 *
 * This is the SAME data path OPNsense's own Diagnostics → Routing screen uses:
 * the REST controllers call configd's `quagga` plugin, which runs vtysh as root
 * ON THE APPLIANCE. That is why it works without an SSH slot and without frr
 * group membership — the box queries FRR server-side (OPNsense locks all FRR
 * state to user/group `frr`, so a non-root remote user can never read it).
 *
 * The Quagga API area + configd plugin are CORE OPNsense code — present in both
 * Community and Business Edition (verified on 26.10 BE). FRR itself is the
 * optional `os-frr` package: when it is not installed or intentionally disabled,
 * `/api/quagga/service/status` reports 'disabled'/'unknown' and the diagnostics
 * endpoints come back empty — so this module works uniformly across editions
 * and its state machine reflects installation/running state.
 *
 * Endpoints (live-verified on OPNsense 26.10 BE):
 *   GET /api/quagga/service/status                    → {status: running|stopped|disabled}
 *   GET /api/quagga/diagnostics/ospfoverview          → v4 overview (routerId, per-area counters)
 *   GET /api/quagga/diagnostics/searchOspfneighbor    → v4 neighbor recordset rows[]
 *   GET /api/quagga/diagnostics/searchOspfroute       → v4 learned-route recordset rows[]
 *   GET /api/quagga/diagnostics/ospfv3overview        → v6 overview (routerId, running time)
 *   GET /api/quagga/diagnostics/searchOspfv3route     → v6 learned-route recordset rows[]
 *
 * There is NO per-neighbor-state endpoint for OSPFv6 — v6 adjacency detail comes
 * from the route nextHops (interfaceName) and the overview's area interfaces.
 */

/** Page size for the search endpoints — far above any realistic neighbor/route count on one appliance. */
const SEARCH_ROW_COUNT = 2000;

/**
 * Unwraps a plain-action payload: most versions return `{response: <payload>}`;
 * some areas/versions put the payload at top level. Returns null when the call
 * failed or carried no object payload (e.g. configd returned nothing → `[]`).
 */
export function responseOf(res: OpnsenseApiResult): Record<string, unknown> | null {
  if (!res.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const r = d['response'];
  if (r && typeof r === 'object' && !Array.isArray(r)) return r as Record<string, unknown>;
  // Top-level payload shape — but an empty object is NOT a usable overview.
  if (Object.keys(d).length > 0) return d;
  return null;
}

/** Extracts `rows[]` from a searchRecordsetBase response (top level or under `response`). */
export function rowsOf(res: OpnsenseApiResult): Record<string, unknown>[] {
  if (!res.ok || !res.data || typeof res.data !== 'object') return [];
  const d = res.data as Record<string, unknown>;
  if (Array.isArray(d['rows'])) return d['rows'] as Record<string, unknown>[];
  const r = d['response'];
  if (r && typeof r === 'object' && !Array.isArray(r)) {
    const rows = (r as Record<string, unknown>)['rows'];
    if (Array.isArray(rows)) return rows as Record<string, unknown>[];
  }
  return [];
}

/** GET /api/quagga/service/status — FRR service state. */
export function getQuaggaServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/service/status');
}

/** GET /api/quagga/diagnostics/ospfoverview — v4 OSPF overview (routerId + per-area counters). */
export function getOspfOverview(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/diagnostics/ospfoverview');
}

/** GET /api/quagga/diagnostics/searchOspfneighbor — v4 OSPF neighbor recordset. */
export function searchOspfNeighbors(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/diagnostics/searchOspfneighbor', { current: 1, rowCount: SEARCH_ROW_COUNT });
}

/** GET /api/quagga/diagnostics/searchOspfroute — v4 OSPF learned-route recordset. */
export function searchOspfRoutes(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/diagnostics/searchOspfroute', { current: 1, rowCount: SEARCH_ROW_COUNT });
}

/** GET /api/quagga/diagnostics/ospfv3overview — v6 OSPF overview. */
export function getOspfv3Overview(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/diagnostics/ospfv3overview');
}

/** GET /api/quagga/diagnostics/searchOspfv3route — v6 OSPF learned-route recordset. */
export function searchOspfv3Routes(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/quagga/diagnostics/searchOspfv3route', { current: 1, rowCount: SEARCH_ROW_COUNT });
}

/**
 * Extracts the usable service state from a /api/quagga/service/status response.
 * null = endpoint missing/failed or unrecognized status → REST surface unusable
 * (callers fall back to the SSH vtysh path when a slot is bound).
 */
export function quaggaStatusOf(res: OpnsenseApiResult): 'running' | 'stopped' | 'disabled' | null {
  if (!res.ok || !res.data || typeof res.data !== 'object') return null;
  const s = (res.data as Record<string, unknown>)['status'];
  if (s === 'running' || s === 'stopped' || s === 'disabled') return s;
  // 'unknown' and anything else is not a usable signal.
  return null;
}
