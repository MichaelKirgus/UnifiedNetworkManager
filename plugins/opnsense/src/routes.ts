import { AxiosInstance } from 'axios';
import { subnetOf } from '@unm/plugin-sdk';
import { searchRoutes, getGatewayStatus, searchGateways } from './client/routes';

/**
 * Route inventory collection for the Routes page.
 *
 * Emits one normalized row per configured static route:
 *   { destination (CIDR), gateway?, protocol ('static'), distance?, metric?,
 *     mtu?, status ('active'|'inactive'), extra? }
 *
 * The API's telemetry worker normalizes `metrics['routes']` into the cross-
 * device `routes` table. Field names in OPNsense REST responses vary by
 * version, so every parser below tries a list of candidate keys and degrades
 * to empty values instead of failing — one unrecognized row must never sink
 * the whole inventory (same defensive style as tunnels.ts).
 */

export interface RouteRow {
  /** Destination network as CIDR ("10.25.0.0/16", "0.0.0.0/0" for default). */
  destination: string;
  /** Next-hop gateway name or address ('' = unknown / directly connected). */
  gateway?: string;
  protocol: 'static' | 'connected';
  distance?: number | null;
  metric?: number | null;
  mtu?: number | null;
  status: 'active' | 'inactive';
  extra?: Record<string, unknown>;
}

// --- small tolerant-parsing helpers (local copies — tunnels.ts keeps its own) --

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Extracts item rows from an OPNsense API payload ({rows:[...]}, bare array, or object keyed by id). */
function extractRows(data: unknown): Record<string, unknown>[] {
  if (!data) return [];
  if (Array.isArray(data)) return data.filter(isObj);
  if (typeof data === 'object') {
    const d = data as Record<string, unknown>;
    if (Array.isArray(d['rows'])) return (d['rows'] as unknown[]).filter(isObj);
    // Some controllers double-wrap the list — unwrap one level.
    for (const v of Object.values(d)) {
      if (isObj(v) && Array.isArray(Object.values(v).find(Array.isArray))) {
        const arr = Object.values(v).find(Array.isArray);
        return (arr as unknown[]).filter(isObj);
      }
    }
    // Object keyed by uuid/name — the values are the items.
    return Object.values(d).filter(isObj);
  }
  return [];
}

function str(r: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return undefined;
}

function num(r: Record<string, unknown>, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  }
  return undefined;
}

/** OPNsense encodes booleans as true/false, '1'/'0', or 1/0. */
function bool(r: Record<string, unknown>, keys: string[]): boolean | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'boolean') return v;
    if (v === 1 || v === '1' || v === true) return true;
    if (v === 0 || v === '0' || v === false) return false;
    if (typeof v === 'string') {
      const s = v.trim().toLowerCase();
      if (s === 'true' || s === 'yes' || s === 'on') return true;
      if (s === 'false' || s === 'no' || s === 'off') return false;
    }
  }
  return undefined;
}

/**
 * A destination field may arrive as a plain CIDR string, an object carrying it
 * ({ value }), or a bare network address without prefix (→ "/32" for v4).
 */
function normalizeDestination(v: unknown): string | undefined {
  let s = '';
  if (typeof v === 'string') s = v.trim();
  else if (isObj(v)) s = str(v, ['value', 'cidr', 'network', 'address']) ?? '';
  if (s === '') return undefined;
  // Bare address without prefix — assume host route.
  if (!s.includes('/')) {
    s += s.includes(':') ? '/128' : '/32';
  }
  return s;
}

/**
 * Collects all configured static routes from the appliance (slow-changing,
 * cached with the rest of the inventory). Best-effort: a failing endpoint
 * yields an empty list, never throws.
 */
export async function collectRoutes(client: AxiosInstance): Promise<RouteRow[]> {
  const res = await searchRoutes(client);
  if (!res?.ok || !res.data) return [];

  const rows = extractRows(res.data);
  const out: RouteRow[] = [];
  for (const r of rows) {
    const destination = normalizeDestination(r['network'] ?? r['destination']);
    if (!destination) continue; // no usable destination — skip, don't fail

    const disabled = bool(r, ['disabled', 'inactive']) === true;
    out.push({
      destination,
      gateway: str(r, ['gateway', 'next_hop', 'nexthop']),
      protocol: 'static',
      distance: num(r, ['distance', 'admin_distance']),
      metric: num(r, ['metric', 'cost']),
      mtu: num(r, ['mtu']),
      status: disabled ? 'inactive' : 'active',
      extra: {
        ...(str(r, ['uuid']) ? { uuid: str(r, ['uuid']) } : {}),
        ...(str(r, ['description', 'comment']) ? { description: str(r, ['description', 'comment']) } : {}),
      },
    });
  }
  return out;
}

/**
 * Computes the network address (CIDR) for an interface IP + prefix — i.e. what
 * OPNsense installs as a "connected" route in its kernel table. Delegates to
 * the canonical SDK implementation (@unm/plugin-sdk ip.ts, v4 + v6).
 */
function networkAddress(ip: string, prefix: number): string | null {
  const p = Math.max(0, Math.min(ip.includes(':') ? 128 : 32, prefix));
  return subnetOf(ip, p);
}

/**
 * Derives route rows that OPNsense installs but does NOT list in the static-
 * routes module, so hosts without explicit static routes still appear on the
 * Routes page:
 *   - one 'connected' row per interface subnet (from the networks inventory),
 *   - ONE 'static' 0.0.0.0/0 row via the first enabled gateway — only when no
 *     explicit static default route exists (the routes table PK is
 *     destination+protocol, so multiple derived defaults would collide).
 */
export function deriveConnectedAndDefaultRoutes(
  networks: Record<string, unknown>[],
  gateways: Record<string, unknown>[],
  existingStaticRoutes: RouteRow[]
): RouteRow[] {
  const out: RouteRow[] = [];
  const seen = new Set<string>(existingStaticRoutes.map((r) => r.destination));

  for (const n of networks) {
    const ip = typeof n['ip'] === 'string' ? (n['ip'] as string).trim() : '';
    const prefixRaw = n['prefix'];
    if (!ip || typeof prefixRaw !== 'number' || !Number.isFinite(prefixRaw)) continue;
    const cidr = networkAddress(ip, Math.round(prefixRaw));
    if (!cidr || seen.has(cidr)) continue;
    seen.add(cidr);
    out.push({
      destination: cidr,
      gateway: '', // directly connected — no next hop
      protocol: 'connected',
      status: 'active',
      extra: { interface: typeof n['name'] === 'string' ? (n['name'] as string) : undefined },
    });
  }

  // Skip the derived default when an explicit static default already exists
  // (the routes table PK is destination+protocol — a second 'static' 0.0.0.0/0
  // row would silently overwrite the configured one).
  if (!seen.has('0.0.0.0/0')) {
    for (const g of gateways) {
      const enabled = bool(g, ['enabled']) !== false && bool(g, ['disabled']) !== true;
      if (!enabled) continue;
      const name = str(g, ['name']);
      if (!name || seen.has('0.0.0.0/0')) break; // first enabled gateway wins (PK collision guard)
      out.push({
        destination: '0.0.0.0/0',
        gateway: name,
        protocol: 'static',
        status: 'active',
        extra: { derivedDefaultViaGateway: true },
      });
      break;
    }
  }

  return out;
}

/** Live gateway state as reported by /api/routes/gateway/status. */
interface GatewayLiveState {
  status: 'online' | 'offline' | 'unknown';
  latencyMs: number | null;
}

// Logs the raw payload shape at most once per process when enrichment yields
// nothing — keeps a genuinely empty appliance from spamming every poll.
let gatewayStatusShapeLogged = false;

/**
 * Enriches route rows with LIVE gateway reachability (one extra endpoint call,
 * made on every poll by the caller — NOT cached with inventory). Strictly
 * additive: each row's `extra` gains `gatewayStatus` ('online'|'offline'|
 * 'unknown') and `gatewayLatencyMs`. Unknown response shapes degrade to
 * 'unknown' rather than failing.
 */
/** Optional structured-log sink for enrichment failures (wired to the plugin logger). */
export interface EnrichLogSink {
  log(level: 'warn' | 'error', message: string, context?: Record<string, unknown>): void;
}

export async function enrichRoutesWithGatewayStatus(
  client: AxiosInstance,
  routes: RouteRow[],
  log?: EnrichLogSink
): Promise<RouteRow[]> {
  if (routes.length === 0) return routes;

  let byName = new Map<string, GatewayLiveState>();
  try {
    const res = await getGatewayStatus(client);
    if (res?.ok && isObj(res.data)) {
      // Real appliance shape (verified live): `{ items: [ { name, address,
      // status, loss, delay ("9.2 ms"), stddev, monitor, status_translated
      // ("Online") }, … ] }`. Also accept a plain array or an object keyed by
      // gateway name / wrapped in `gateways` for other versions.
      const data = res.data as Record<string, unknown>;
      let entries: Array<Record<string, unknown>> = [];
      if (Array.isArray(data['items'])) {
        entries = (data['items'] as unknown[]).filter(isObj) as Array<Record<string, unknown>>;
      } else if (Array.isArray(res.data)) {
        entries = (res.data as unknown[]).filter(isObj) as Array<Record<string, unknown>>;
      } else if (isObj(data['gateways'])) {
        entries = Object.values(data['gateways'] as Record<string, unknown>).filter(isObj) as Array<Record<string, unknown>>;
      } else {
        // object keyed directly by gateway name — synthesize the name field
        entries = Object.entries(data).filter(([, v]) => isObj(v)).map(([name, v]) => ({ name, ...(v as Record<string, unknown>) }));
      }
      for (const v of entries) {
        const name = str(v, ['name']);
        if (!name) continue;
        // status_translated ("Online"/"Offline") is the human-facing verdict;
        // `status` carries machine codes that vary by version.
        const rawStatus = str(v, ['status_translated']) || str(v, ['status', 'state']);
        let status: GatewayLiveState['status'] = 'unknown';
        if (rawStatus) {
          const s = rawStatus.toLowerCase();
          if (s.includes('online') || s === 'up' || s === 'reachable') status = 'online';
          else if (s.includes('offline') || s === 'down' || s === 'unreachable') status = 'offline';
        }
        // delay is a display string ("9.2 ms") — extract the number; also
        // accept plain numeric fields from other versions.
        const delayRaw = str(v, ['delay', 'latency_ms', 'latency', 'rtt']);
        let latencyMs: number | null = num(v, ['latency_ms', 'latency', 'rtt']) ?? null;
        if (latencyMs === null && delayRaw) {
          const m = delayRaw.match(/(-?\d+(?:\.\d+)?)/);
          if (m) latencyMs = Number(m[1]);
        }
        byName.set(name, { status, latencyMs });
      }
    } else if (res && !res.ok) {
      console.error(`[opnsense] gateway/status returned HTTP ${res.status} — enrichment skipped`);
      log?.log('warn', `gateway/status returned HTTP ${res.status} — route enrichment skipped`, { endpoint: 'gateway/status', httpStatus: res.status });
    }
  } catch (err) {
    // best-effort — a failing status endpoint must not sink the route rows
    console.error('[opnsense] gateway/status call failed:', err instanceof Error ? err.message : String(err));
    log?.log('warn', 'gateway/status call failed — route enrichment skipped', { endpoint: 'gateway/status', error: err instanceof Error ? err.message : String(err) });
  }

  if (byName.size === 0 && routes.length > 0) {
    // One-time visibility into an unrecognized/empty payload shape so the
    // parser can be extended; logged at most once per process.
    if (!gatewayStatusShapeLogged) {
      gatewayStatusShapeLogged = true;
      try {
        const res = await getGatewayStatus(client);
        console.error('[opnsense] gateway/status payload (first 600 chars):', JSON.stringify(res?.data ?? null)?.slice(0, 600));
      } catch { /* already logged above */ }
    }
  }

  return routes.map((route) => {
    if (!route.gateway) return route;
    const live = byName.get(route.gateway);
    if (!live) return route;
    return {
      ...route,
      extra: {
        ...(route.extra ?? {}),
        gatewayStatus: live.status,
        ...(live.latencyMs !== null ? { gatewayLatencyMs: live.latencyMs } : {}),
      },
    };
  });
}
