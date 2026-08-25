import { AxiosInstance } from 'axios';
import { OpnsenseApiResult } from './client/http';
import { listServers, searchServers, getPeers, getServiceShow } from './client/wireguard';
import { searchInstances, searchSessions } from './client/openvpn';
import { searchConnections, searchPhase1Sessions, searchPhase2Sessions } from './client/ipsec';
import { gres } from './client/interfaces';

/**
 * Tunnel inventory collection for the Tunnels page.
 *
 * Emits one normalized row per configured tunnel:
 *   { name, type ('wireguard'|'openvpn'|'ipsec'|'pppoe'|'gre'), peerAddress?,
 *     localAddress?, subnet?, status ('up'|'down'|'enabled'|'disabled'),
 *     uptimeSeconds?, interfaceName?, extra? }
 *
 * The API's telemetry worker normalizes `metrics['tunnels']` into the cross-
 * device `tunnels` table. Field names in OPNsense REST responses vary by
 * version, so every parser below tries a list of candidate keys and degrades
 * to empty values instead of failing — one unrecognized row must never sink
 * the whole inventory (same defensive style as parseNetworkRows).
 */

export interface TunnelRow {
  name: string;
  type: 'wireguard' | 'openvpn' | 'ipsec' | 'pppoe' | 'gre';
  peerAddress?: string;
  localAddress?: string;
  subnet?: string;
  status: 'up' | 'down' | 'enabled' | 'disabled';
  uptimeSeconds?: number;
  // Seconds since the last handshake (WireGuard peers). null/undefined = no live data.
  lastHandshakeSeconds?: number | null;
  interfaceName?: string;
  extra?: Record<string, unknown>;
}

/** A WireGuard peer's LIVE runtime state from /api/wireguard/service/show. */
interface WgPeerRuntime {
  endpoint: string | undefined;
  status: 'up' | 'down';
  lastHandshakeSeconds: number | null;
  transferRx: number | null;
  transferTx: number | null;
}

/** An IPsec connection's LIVE state derived from phase-1/phase-2 session rows. */
interface IpsecRuntime {
  status: 'up' | 'down';
  peerAddress?: string;
  localAddress?: string;
  extra?: Record<string, unknown>;
}

// --- small tolerant-parsing helpers -------------------------------------------

function isObj(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Extracts item rows from an OPNsense API payload ({rows:[...]}, bare array, or object keyed by id). */
export function extractRows(data: unknown): Record<string, unknown>[] {
  if (!data) return [];
  if (Array.isArray(data)) return data.filter(isObj);
  if (typeof data === 'object') {
    const d = data as Record<string, unknown>;
    if (Array.isArray(d['rows'])) return (d['rows'] as unknown[]).filter(isObj);
    // Some controllers double-wrap the list ({ gre: { gre: [...] } }) — unwrap one level.
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

/**
 * A CIDR field may arrive three ways: a plain string ("10.1.1.62/30"), an object
 * ({ value, selected }), or a map keyed by the CIDR itself (the wireguard client
 * shape { "0.0.0.0/0": { value, selected } }). Strings may be comma-joined
 * ("fd42::1/127,fe80::1/64" — v4+v6 tunnel addresses) and are split apart.
 * Returns all candidate strings.
 */
function cidrCandidates(v: unknown): string[] {
  if (typeof v === 'string' && v.trim() !== '') {
    return v.split(',').map((s) => s.trim()).filter((s) => s !== '');
  }
  if (!isObj(v)) return [];
  const out: string[] = [];
  for (const item of Object.values(v)) {
    if (typeof item === 'string' && item.trim() !== '') out.push(item.trim());
    else if (isObj(item)) {
      const val = str(item, ['value', 'cidr', 'address']);
      if (val) out.push(val);
    }
  }
  return Array.from(new Set(out));
}

/** First CIDR-looking candidate (contains '/'), or the first string when none do. */
function firstCidr(v: unknown): string | undefined {
  const c = cidrCandidates(v);
  if (c.length === 0) return undefined;
  return c.find((x) => x.includes('/')) ?? c[0];
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

/** A field may be a plain string OR an object carrying the address in one of `addrKeys`. */
function endpoint(r: Record<string, unknown>, keys: string[], addrKeys = ['address', 'ip', 'value']): string | undefined {
  for (const k of keys) {
    const v = r[k];
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
    if (isObj(v)) {
      const a = str(v, addrKeys);
      if (a) return a;
    }
  }
  return undefined;
}

/** Allowed-IPs / network fields arrive as arrays or comma-separated strings. */
function networks(r: Record<string, unknown>, keys: string[]): string[] {
  const out: string[] = [];
  for (const k of keys) {
    const v = r[k];
    if (Array.isArray(v)) {
      for (const item of v) {
        if (typeof item === 'string' && item.trim() !== '') out.push(item.trim());
        else if (isObj(item)) {
          const a = str(item, ['cidr', 'network', 'address', 'value']);
          if (a) out.push(a);
        }
      }
    } else if (typeof v === 'string' && v.trim() !== '') {
      for (const part of v.split(',')) if (part.trim() !== '') out.push(part.trim());
    }
  }
  return Array.from(new Set(out));
}

// --- per-technology collectors --------------------------------------------------

/** WireGuard: one row per PEER (a peer IS the tunnel); servers without peers get a server-level row. */
async function collectWireguard(client: AxiosInstance): Promise<TunnelRow[]> {
  const rows: TunnelRow[] = [];
  // Servers — `list_servers` is missing on some OPNsense versions (404), so fall
  // back to the recordset search endpoint that always exists.
  let servers: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await listServers(client);
    if (res.ok) servers = extractRows(res.data);
  } catch { /* best-effort */ }
  if (servers.length === 0) {
    try {
      const res: OpnsenseApiResult = await searchServers(client);
      if (res.ok) servers = extractRows(res.data);
    } catch { /* best-effort */ }
  }

  // Server lookup by uuid so peers can inherit the server's IP/subnet/interface.
  const serverByUuid = new Map<string, Record<string, unknown>>();
  for (const s of servers) {
    const id = str(s, ['uuid', 'id']);
    if (id) serverByUuid.set(id, s);
  }

  /**
   * Resolves a peer's parent server uuid. The `servers` field is a map of ALL
   * servers keyed by uuid with `{ value: <serverName>, selected: 0|1 }` — the
   * peer belongs to the one marked `selected`. Taking the first key (the old
   * behavior) linked most peers to the wrong server. Falls back to an explicit
   * uuid field, then the first key (best effort).
   */
  const resolveServerId = (p: Record<string, unknown>): string | undefined => {
    const explicit = str(p, ['server_uuid', 'serverUuid', 'server_id', 'server']);
    if (explicit) return explicit;
    const serversMap = p['servers'];
    if (isObj(serversMap)) {
      for (const [uuid, v] of Object.entries(serversMap)) {
        if (isObj(v) && bool(v, ['selected']) === true) return uuid;
      }
      // No explicit selection — first key as a last resort.
      const keys = Object.keys(serversMap);
      if (keys.length > 0) return keys[0];
    }
    return undefined;
  };

  // Peers — `client/get` returns a NESTED map: { client: { clients: { client:
  // { <peer-uuid>: {...}, ... } } } }. Unwrap to the innermost object and treat
  // its values as peer rows (a bare array/rows shape is tolerated too).
  let peers: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await getPeers(client);
    if (res.ok) {
      let node: unknown = res.data;
      for (let depth = 0; depth < 4 && isObj(node); depth++) {
        const vals = Object.values(node).filter(isObj);
        // Stop unwrapping once the values look like peer rows (they carry name/pubkey).
        if (vals.length > 0 && vals.every((v) => v['name'] !== undefined || v['pubkey'] !== undefined)) {
          peers = vals;
          break;
        }
        // Otherwise descend into the single nested object.
        const next = Object.values(node).find(isObj);
        if (!next) break;
        node = next;
      }
      if (peers.length === 0) peers = extractRows(res.data);
    }
  } catch { /* best-effort */ }

  for (const p of peers) {
    const name = str(p, ['name', 'description', 'descr']) ?? `peer-${str(p, ['uuid', 'id']) ?? '?'}`;
    const enabled = bool(p, ['enabled', 'enable']);
    // The peer's parent server carries the local IP/subnet/interface.
    const serverId = resolveServerId(p);
    const server = serverId ? serverByUuid.get(serverId) : undefined;

    // Allowed IPs: a map keyed by CIDR ({"10.99.0.0/24": {value, selected}}),
    // an array of strings, or a plain string — firstCidr handles all three.
    const allowed = firstCidr(p['tunneladdress']) ?? firstCidr(p['allowed_ips']) ?? firstCidr(p['allowedIps']);

    rows.push({
      name,
      type: 'wireguard',
      peerAddress: endpoint(p, ['endpoint', 'remote_endpoint', 'remote', 'serveraddress']),
      localAddress: server ? str(server, ['tunneladdress', 'ip', 'server_ip', 'address']) : undefined,
      subnet: allowed,
      status: enabled === false ? 'disabled' : 'enabled',
      interfaceName: server ? str(server, ['interface', 'ifname', 'iface']) : str(p, ['interface', 'ifname', 'iface']),
      // The peer's public key is the stable join to the LIVE runtime rows from
      // /api/wireguard/service/show (which carry no uuid — only pubkey + if).
      extra: { uuid: str(p, ['uuid', 'id']), pubkey: str(p, ['pubkey']) },
    });
  }

  // Servers with no peers still deserve a row (the tunnel endpoint exists).
  const peerServerIds = new Set(peers.map((p) => resolveServerId(p)));
  for (const s of servers) {
    const id = str(s, ['uuid', 'id']);
    if (id && peerServerIds.has(id)) continue;
    rows.push({
      name: str(s, ['name', 'description', 'descr']) ?? `server-${id ?? '?'}`,
      type: 'wireguard',
      localAddress: firstCidr(str(s, ['tunneladdress'])),
      subnet: networks(s, ['subnet'])[0],
      status: bool(s, ['enabled', 'enable']) === false ? 'disabled' : 'enabled',
      interfaceName: str(s, ['interface', 'ifname', 'iface']),
      extra: { uuid: id },
    });
  }
  return rows;
}

/** OpenVPN: one row per instance (server or client profile); active sessions upgrade status to up. */
async function collectOpenvpn(client: AxiosInstance): Promise<TunnelRow[]> {
  const rows: TunnelRow[] = [];
  let instances: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await searchInstances(client);
    if (res.ok) instances = extractRows(res.data);
  } catch { /* best-effort */ }

  // Active sessions — matched to instances by remote address or common name.
  let sessions: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await searchSessions(client);
    if (res.ok) sessions = extractRows(res.data);
  } catch { /* best-effort */ }

  for (const i of instances) {
    const name = str(i, ['description', 'descr', 'name']) ?? `openvpn-${str(i, ['uuid', 'id']) ?? '?'}`;
    const enabled = bool(i, ['enabled', 'enable']);
    const mode = str(i, ['mode']); // 'server' | 'client'
    const remote = endpoint(i, ['remote', 'remote_address', 'gateway', 'peer']);
    const local = str(i, ['local_ip', 'ip', 'address', 'local_address']);
    const devicename = str(i, ['devicename', 'deviceName', 'interface', 'ifname']);

    // Best-effort session match: same remote address or common name == instance name.
    let matched: Record<string, unknown> | undefined;
    for (const s of sessions) {
      const real = str(s, ['real_address', 'address', 'ip']);
      const cn = str(s, ['common_name', 'peer', 'name']);
      if ((remote && real && (real.includes(remote.split(':')[0]) || remote.includes(real))) || (cn && cn === name)) {
        matched = s;
        break;
      }
    }

    rows.push({
      name,
      type: 'openvpn',
      peerAddress: mode === 'server' ? undefined : remote, // servers don't have a single remote
      localAddress: local,
      subnet: networks(i, ['subnet', 'local_subnet', 'remote_network'])[0],
      status: matched ? 'up' : enabled === false ? 'disabled' : 'enabled',
      uptimeSeconds: matched ? num(matched, ['uptime']) : undefined,
      interfaceName: devicename,
      extra: { uuid: str(i, ['uuid', 'id']), ...(mode ? { mode } : {}) },
    });
  }
  return rows;
}

/** IPsec (strongSwan): one row per connection. Config-level only — the REST API does not expose live SA state. */
async function collectIpsec(client: AxiosInstance): Promise<TunnelRow[]> {
  const rows: TunnelRow[] = [];
  let conns: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await searchConnections(client);
    if (res.ok) conns = extractRows(res.data);
  } catch { /* best-effort */ }

  for (const c of conns) {
    rows.push({
      name: str(c, ['name']) ?? `ipsec-${str(c, ['uuid', 'id']) ?? '?'}`,
      type: 'ipsec',
      peerAddress: endpoint(c, ['remote', 'remote_address', 'gateway', 'peer']),
      localAddress: endpoint(c, ['local', 'local_address', 'address']),
      subnet: networks(c, ['remote_network', 'local_network', 'subnet'])[0],
      status: bool(c, ['enabled', 'enable']) === false ? 'disabled' : 'enabled',
      extra: { uuid: str(c, ['uuid', 'id']) },
    });
  }
  return rows;
}

/** GRE tunnels from the gre_settings controller (same item shape as vlan/lagg/bridge). */
async function collectGre(client: AxiosInstance): Promise<TunnelRow[]> {
  const rows: TunnelRow[] = [];
  let items: Record<string, unknown>[] = [];
  try {
    const res: OpnsenseApiResult = await gres.get(client);
    if (res.ok) items = extractRows(res.data);
  } catch { /* best-effort — endpoint may not exist on older versions */ }

  for (const g of items) {
    rows.push({
      name: str(g, ['description', 'descr', 'name']) ?? `gre-${str(g, ['uuid', 'id']) ?? '?'}`,
      type: 'gre',
      peerAddress: endpoint(g, ['destination', 'dest', 'remote_address']),
      localAddress: endpoint(g, ['source', 'src', 'local_address']),
      status: bool(g, ['enabled', 'enable']) === false ? 'disabled' : 'enabled',
      interfaceName: str(g, ['interface', 'ifname', 'iface']),
      extra: { uuid: str(g, ['uuid', 'id']) },
    });
  }
  return rows;
}

/**
 * PPPoE WAN links — detected from the interfaces_info recordset already fetched
 * for the Networks page (no extra API call). An interface counts as PPPoE when
 * its type field says so or its config carries a pppoe flag.
 */
function collectPppoe(interfaceEntries: Record<string, unknown>[]): TunnelRow[] {
  const rows: TunnelRow[] = [];
  for (const e of interfaceEntries) {
    const config = isObj(e['config']) ? e['config'] : {};
    const typeHint = str(e, ['if_type', 'type']) ?? str(config, ['if_type', 'type']);
    const pppoeFlag = bool(config, ['pppoe', 'pppoe_enable']) ?? (typeHint !== undefined && /ppp/i.test(typeHint));
    if (!pppoeFlag) continue;

    const id = str(e, ['identifier']) ?? '';
    const name = id || str(e, ['description', 'descr']);
    if (!name) continue;
    // Assigned address (CIDR string in recordset rows).
    let local: string | undefined;
    for (const fam of ['ipv4', 'ipv6'] as const) {
      const v = e[fam];
      if (Array.isArray(v)) {
        for (const item of v) {
          if (isObj(item)) {
            const cidr = str(item, ['ipaddr']);
            if (cidr && !local) local = cidr.split('/')[0];
          }
        }
      }
    }
    rows.push({
      name,
      type: 'pppoe',
      peerAddress: undefined, // the ISP side is not exposed by this endpoint
      localAddress: local,
      status: str(e, ['status']) === 'up' && local ? 'up' : local ? 'enabled' : 'down',
      interfaceName: str(e, ['device']) ?? id,
    });
  }
  return rows;
}

/** Collects every tunnel type from one appliance. Each section is independent — a failing endpoint yields no rows for that type only. */
export async function collectTunnels(
  client: AxiosInstance,
  interfaceEntries: Record<string, unknown>[] = []
): Promise<TunnelRow[]> {
  const [wireguard, openvpn, ipsec, gre] = await Promise.all([
    collectWireguard(client),
    collectOpenvpn(client),
    collectIpsec(client),
    collectGre(client),
  ]);
  return [...wireguard, ...openvpn, ...ipsec, ...gre, ...collectPppoe(interfaceEntries)];
}

// --- live runtime enrichment -----------------------------------------------------
//
// The config endpoints above only know what is CONFIGURED. OPNsense also exposes
// the LIVE kernel state (the data behind VPN → WireGuard → Status / IPsec →
// Status Overview) through plain API-key-authenticated recordsets:
//   - /api/wireguard/service/show        per-peer endpoint, last handshake, rx/tx
//   - /api/ipsec/sessions/search_phase1  live IKE SAs (peer + local addresses)
//   - /api/ipsec/sessions/search_phase2  live child SAs (tunnel networks)
// These are polled on the LIVE cadence (not cached with inventory) and merged
// into the config rows below. A missing/empty recordset simply leaves a row at
// its config-level state — enrichment is strictly additive and best-effort.

/** Parses /api/wireguard/service/show rows into per-peer runtime, keyed by public key. */
async function fetchWgRuntime(client: AxiosInstance): Promise<Map<string, WgPeerRuntime>> {
  const out = new Map<string, WgPeerRuntime>();
  try {
    const res: OpnsenseApiResult = await getServiceShow(client);
    if (!res.ok) return out;
    for (const row of extractRows(res.data)) {
      // Only `peer` rows carry runtime state (`interface` rows are the local side).
      if (str(row, ['type']) !== 'peer') continue;
      const key = str(row, ['public-key']);
      if (!key) continue;
      const age = num(row, ['latest-handshake-age', 'latest_handshake_age']);
      out.set(key, {
        endpoint: str(row, ['endpoint']),
        status: /online|up/i.test(str(row, ['peer-status']) ?? '') ? 'up' : 'down',
        lastHandshakeSeconds: age !== undefined && Number.isFinite(age) ? Math.max(0, Math.round(age)) : null,
        transferRx: num(row, ['transfer-rx']) ?? null,
        transferTx: num(row, ['transfer-tx']) ?? null,
      });
    }
  } catch { /* best-effort */ }
  return out;
}

/** Parses IPsec phase-1/phase-2 session rows into per-connection runtime. */
async function fetchIpsecRuntime(client: AxiosInstance): Promise<Map<string, IpsecRuntime>> {
  const byName = new Map<string, IpsecRuntime>();
  try {
    const [p1, p2] = await Promise.all([searchPhase1Sessions(client), searchPhase2Sessions(client)]);
    // Phase-1 rows establish the tunnel (peer + local addresses).
    for (const row of extractRows(p1.ok ? p1.data : undefined)) {
      const name = str(row, ['name', 'connection', 'conn']);
      if (!name) continue;
      byName.set(name, {
        status: 'up',
        peerAddress: endpoint(row, ['peer', 'remote', 'rmt_address', 'remote_address']),
        localAddress: endpoint(row, ['local', 'lcl_address', 'local_address']),
      });
    }
    // Phase-2 rows confirm active child SAs (and may carry tunnel networks).
    for (const row of extractRows(p2.ok ? p2.data : undefined)) {
      const name = str(row, ['name', 'connection', 'conn']);
      if (!name) continue;
      const existing = byName.get(name);
      if (existing) {
        const net = networks(row, ['local_network', 'remote_network', 'subnet'])[0];
        if (net && !existing.extra?.['tunnelNetwork']) existing.extra = { ...existing.extra, tunnelNetwork: net };
      } else {
        byName.set(name, { status: 'up' });
      }
    }
  } catch { /* best-effort */ }
  return byName;
}

/**
 * Merges live runtime state into config-level tunnel rows. WireGuard peers are
 * matched by public key (the only stable id the runtime exposes); IPsec
 * connections by name. Rows without a matching live entry keep their
 * config-level status/addresses unchanged. Returns new row objects.
 */
export async function enrichTunnelsWithLiveState(
  client: AxiosInstance,
  tunnels: TunnelRow[]
): Promise<TunnelRow[]> {
  const hasWg = tunnels.some((t) => t.type === 'wireguard');
  const hasIpsec = tunnels.some((t) => t.type === 'ipsec');
  if (!hasWg && !hasIpsec) return tunnels;

  const [wgRuntime, ipsecRuntime] = await Promise.all([
    hasWg ? fetchWgRuntime(client) : Promise.resolve(new Map<string, WgPeerRuntime>()),
    hasIpsec ? fetchIpsecRuntime(client) : Promise.resolve(new Map<string, IpsecRuntime>()),
  ]);

  return tunnels.map((t) => {
    if (t.type === 'wireguard') {
      const key = typeof t.extra?.['pubkey'] === 'string' ? (t.extra['pubkey'] as string) : undefined;
      const rt = key ? wgRuntime.get(key) : undefined;
      if (!rt) return t; // no live entry → peer never connected / runtime unavailable
      return {
        ...t,
        // The configured endpoint is usually empty on servers — the LIVE
        // endpoint (the client's actual address:port) is what we want to show.
        peerAddress: rt.endpoint || t.peerAddress,
        status: rt.status,
        lastHandshakeSeconds: rt.lastHandshakeSeconds,
        // Cumulative per-peer byte counters — attachTunnelRates turns them into
        // bytes/s deltas (per-peer rates are more precise than the interface's).
        extra: { ...t.extra, transferRx: rt.transferRx ?? undefined, transferTx: rt.transferTx ?? undefined },
      };
    }
    if (t.type === 'ipsec') {
      const rt = ipsecRuntime.get(t.name);
      if (!rt) return t; // no live SA → stays at config-level enabled/disabled
      return {
        ...t,
        status: rt.status,
        peerAddress: rt.peerAddress || t.peerAddress,
        localAddress: rt.localAddress || t.localAddress,
        extra: rt.extra ? { ...t.extra, ...rt.extra } : t.extra,
      };
    }
    return t;
  });
}

// --- per-tunnel traffic rates ----------------------------------------------------
//
// The appliance reports CUMULATIVE byte counters per interface; tunnel rows
// reference their kernel/logical interface via `interfaceName`. We keep the
// previous sample per host in memory and emit bytes/s deltas. First sample
// after (re)start has no delta → null rates, which is expected.

interface CounterSample {
  at: number;
  counters: Map<string, { rx: number; tx: number }>;
  // Per-peer WireGuard cumulative byte counters (keyed by peer public key).
  peers: Map<string, { rx: number; tx: number }>;
}

const rateSamples = new Map<string, CounterSample>();
const SAMPLE_STALE_MS = 2 * 60 * 60 * 1000; // drop hosts unseen for 2h (device deleted/offline)

/**
 * Attaches rxRate/txRate (bytes/s) to tunnel rows. Two sources, most-specific
 * wins:
 *   1. Per-peer WireGuard counters — rows whose extra carries transferRx/Tx
 *      (cumulative bytes from /api/wireguard/service/show), keyed by pubkey.
 *   2. Interface-level counters — rows whose interfaceName matches a counter in
 *      `counters` (same keys as the plugin's `traffic` metric).
 * The previous sample per host is kept in memory; first poll after (re)start has
 * no delta → null rates, which is expected warm-up behavior. Input not mutated.
 */
export function attachTunnelRates(
  host: string,
  tunnels: TunnelRow[],
  counters: Record<string, { rx?: number; tx?: number }>
): (TunnelRow & { rxRate?: number | null; txRate?: number | null })[] {
  const now = Date.now();

  // Housekeeping: drop stale hosts so the map can't grow unbounded.
  for (const [h, s] of rateSamples) {
    if (now - s.at > SAMPLE_STALE_MS) rateSamples.delete(h);
  }

  const prev = rateSamples.get(host);
  const cur = new Map<string, { rx: number; tx: number }>();
  for (const [iface, c] of Object.entries(counters)) {
    if (typeof c?.rx === 'number' && typeof c?.tx === 'number') cur.set(iface, { rx: c.rx, tx: c.tx });
  }
  const curPeers = new Map<string, { rx: number; tx: number }>();
  for (const t of tunnels) {
    if (t.type !== 'wireguard' || !t.extra) continue;
    const key = typeof t.extra['pubkey'] === 'string' ? (t.extra['pubkey'] as string) : undefined;
    const rx = typeof t.extra['transferRx'] === 'number' ? (t.extra['transferRx'] as number) : null;
    const tx = typeof t.extra['transferTx'] === 'number' ? (t.extra['transferTx'] as number) : null;
    if (key && rx !== null && tx !== null) curPeers.set(key, { rx, tx });
  }

  // Delta helper with counter-reset guard.
  const delta = (c: { rx: number; tx: number }, p: { rx: number; tx: number }, dtSec: number): { rxRate: number; txRate: number } | undefined => {
    if (c.rx < p.rx || c.tx < p.tx) return undefined; // reset → skip this cycle
    return { rxRate: (c.rx - p.rx) / dtSec, txRate: (c.tx - p.tx) / dtSec };
  };

  const rates = new Map<string, { rxRate: number; txRate: number }>();
  const peerRates = new Map<string, { rxRate: number; txRate: number }>();
  if (prev) {
    const dtSec = (now - prev.at) / 1000;
    if (dtSec > 0.5) { // ignore sub-second re-polls (would produce garbage rates)
      for (const [iface, c] of cur) {
        const p = prev.counters.get(iface);
        if (!p) continue;
        const d = delta(c, p, dtSec);
        if (d) rates.set(iface, d);
      }
      for (const [key, c] of curPeers) {
        const p = prev.peers.get(key);
        if (!p) continue;
        const d = delta(c, p, dtSec);
        if (d) peerRates.set(key, d);
      }
    }
  }
  rateSamples.set(host, { at: now, counters: cur, peers: curPeers });

  return tunnels.map((t) => {
    // Per-peer rates win over interface-level ones for WireGuard rows.
    if (t.type === 'wireguard' && t.extra?.['pubkey']) {
      const r = peerRates.get(t.extra['pubkey'] as string);
      if (r) return { ...t, rxRate: r.rxRate, txRate: r.txRate };
    }
    if (!t.interfaceName) return t;
    const r = rates.get(t.interfaceName);
    return r ? { ...t, rxRate: r.rxRate, txRate: r.txRate } : t;
  });
}
