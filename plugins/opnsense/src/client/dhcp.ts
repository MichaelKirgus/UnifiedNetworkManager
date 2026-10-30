import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * DHCP module — DUAL BACKEND. Older appliances run dnsmasq for DHCP (static
 * mappings live in the `services/dhcp` controller); newer ones use Kea
 * (`kea/dhcpv4|dhcpv6`). This client exposes one logical surface and dispatches
 * to the active backend, auto-detected per appliance with an optional override.
 */

export type DhcpBackend = 'dnsmasq' | 'kea';

/**
 * Detects which DHCP backend the appliance uses: Kea when its service reports
 * a running/enabled state (`GET /api/kea/service/status`), otherwise dnsmasq
 * (the historical default). Best-effort — firmware status shapes vary, so an
 * explicit `dhcpBackend` override option exists for appliances where auto-detect
 * is inconclusive. A failing probe falls back to dnsmasq.
 */
export async function detectDhcpBackend(client: AxiosInstance): Promise<DhcpBackend> {
  try {
    const res = await get<Record<string, unknown>>(client, '/api/kea/service/status');
    if (res.ok && res.data) {
      const d = res.data;
      // Kea status shapes vary by version — accept any positive running/enabled signal.
      const running = d['running'] ?? d['enabled'] ?? d['status'];
      if (running === true || running === 'true' || running === 1) return 'kea';
      if (typeof running === 'string' && /run|enab/i.test(running)) return 'kea';
    }
  } catch {
    /* fall through to dnsmasq */
  }
  return 'dnsmasq';
}

// --- Static mappings / reservations (logical surface) ------------------------------

export interface DhcpStaticMapping {
  /** Interface the mapping applies to (e.g. `lan`). */
  interface: string;
  /** MAC address of the client. */
  mac: string;
  /** Fixed IP to assign. */
  ip: string;
  /** Optional hostname. */
  hostname?: string;
}

/** Adds a static DHCP mapping (dnsmasq) or reservation (Kea). Staged; call reconfigureDhcp to activate. */
export async function addStaticMapping(
  client: AxiosInstance,
  backend: DhcpBackend,
  mapping: DhcpStaticMapping
): Promise<OpnsenseApiResult> {
  if (backend === 'kea') {
    // Kea reservation model fields (KeaDhcpv4.xml): `subnet` is a REQUIRED
    // relation to the subnet recordset row — resolved here from the IP's CIDR
    // containment against search_subnet. The old `{interface, mac, ip}` payload
    // used non-model field names and failed validation on real firmware.
    const item: Record<string, unknown> = {
      hw_address: mapping.mac,
      ip_address: mapping.ip,
    };
    if (mapping.hostname) item['hostname'] = mapping.hostname;
    const subnetUuid = await resolveKeaSubnetForIp(client, mapping.ip);
    if (subnetUuid) item['subnet'] = subnetUuid;
    // The controller reads POST['reservation'] (addBase("reservation", ...)) —
    // wrapping in `item` makes hasPost() false and the call silently no-ops.
    return post(client, '/api/kea/dhcpv4/add_reservation', { reservation: item });
  }
  // Legacy dnsmasq static map (services plugin controller).
  return post(client, '/api/services/dhcp/staticmap/add', {
    interface: mapping.interface,
    mac: mapping.mac,
    ipaddr: mapping.ip,
    hostname: mapping.hostname ?? '',
  });
}

/** Updates a Kea reservation in place (`set_reservation/$uuid`) or emulates an
 * update on dnsmasq (del + add — the services/dhcp staticmap API has no set).
 * Staged; call reconfigureDhcp to activate. */
export async function setStaticMapping(
  client: AxiosInstance,
  backend: DhcpBackend,
  uuid: string,
  mapping: DhcpStaticMapping
): Promise<OpnsenseApiResult> {
  if (backend === 'kea') {
    const item: Record<string, unknown> = {
      hw_address: mapping.mac,
      ip_address: mapping.ip,
    };
    if (mapping.hostname) item['hostname'] = mapping.hostname;
    // The reservation's subnet relation is REQUIRED by the model — keep it when
    // the IP still fits the original subnet, otherwise re-resolve from the new IP.
    const currentSubnet = await getKeaReservationSubnet(client, uuid);
    if (currentSubnet) {
      const currentCidr = await cidrOfKeaSubnet(client, currentSubnet);
      if (currentCidr && ipInCidr(mapping.ip, currentCidr)) {
        item['subnet'] = currentSubnet;
      } else {
        const subnetUuid = await resolveKeaSubnetForIp(client, mapping.ip);
        if (subnetUuid) item['subnet'] = subnetUuid;
      }
    } else {
      const subnetUuid = await resolveKeaSubnetForIp(client, mapping.ip);
      if (subnetUuid) item['subnet'] = subnetUuid;
    }
    // The controller reads POST['reservation'] (setBase("reservation", ...)) —
    // wrapping in `item` makes hasPost() false and the call silently no-ops.
    return post(client, `/api/kea/dhcpv4/set_reservation/${encodeURIComponent(uuid)}`, { reservation: item });
  }
  // dnsmasq: no set endpoint — delete then re-add within this one call. The
  // staticmap is per-interface, so keep the original interface (resolved from
  // the existing row when the caller didn't supply one).
  let iface: string | undefined = mapping.interface;
  if (!iface) {
    const searchRes = await searchStaticMappings(client, 'dnsmasq').catch(() => null);
    if (searchRes?.ok && searchRes.data && typeof searchRes.data === 'object') {
      const d = searchRes.data as Record<string, unknown>;
      const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
      const row = rows.find((r) => r['uuid'] === uuid);
      iface = typeof row?.['interface'] === 'string' && row['interface'].trim() !== '' ? row['interface'] : undefined;
    }
  }
  if (!iface) return { ok: false, status: 0, data: { error: 'could not resolve the staticmap interface for update' } };
  const delRes = await post(client, `/api/services/dhcp/staticmap/del/${encodeURIComponent(uuid)}`, {});
  if (!delRes.ok) return delRes;
  return addStaticMapping(client, 'dnsmasq', { ...mapping, interface: iface });
}

/** Removes a static DHCP mapping/reservation by uuid. Staged. */
export async function deleteStaticMapping(
  client: AxiosInstance,
  backend: DhcpBackend,
  uuid: string
): Promise<OpnsenseApiResult> {
  if (backend === 'kea') {
    return post(client, `/api/kea/dhcpv4/del_reservation/${encodeURIComponent(uuid)}`, {});
  }
  return post(client, `/api/services/dhcp/staticmap/del/${encodeURIComponent(uuid)}`, {});
}

// --- Kea reservation helpers ---------------------------------------------------------

/** Parses an IPv4 dotted quad into a 32-bit integer (null when malformed). */
function ipv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value >>> 0;
}

/** True when `ip` falls inside the CIDR block (e.g. "192.168.1.0/24"). */
export function ipInCidr(ip: string, cidr: string): boolean {
  const slash = cidr.lastIndexOf('/');
  if (slash < 0) return false;
  const base = ipv4ToUint32(cidr.slice(0, slash));
  const addr = ipv4ToUint32(ip);
  if (base === null || addr === null) return false;
  let prefix = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  return (base & mask) === (addr & mask);
}

/** Finds the Kea subnet whose CIDR contains `ip` and returns its recordset uuid. */
export async function resolveKeaSubnetForIp(client: AxiosInstance, ip: string): Promise<string | null> {
  const res = await searchKeaSubnets(client).catch(() => null);
  if (!res?.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
  for (const row of rows) {
    const cidr = typeof row['subnet'] === 'string' && /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(row['subnet']) ? (row['subnet'] as string) : null;
    if (!cidr || !ipInCidr(ip, cidr)) continue;
    const uuid = typeof row['uuid'] === 'string' && row['uuid'].trim() !== '' ? row['uuid'] : null;
    if (uuid) return uuid;
  }
  return null;
}

/** Reads one Kea reservation's `subnet` relation value (the subnet recordset uuid). */
async function getKeaReservationSubnet(client: AxiosInstance, uuid: string): Promise<string | null> {
  const res = await get<Record<string, unknown>>(client, `/api/kea/dhcpv4/get_reservation/${encodeURIComponent(uuid)}`).catch(() => null);
  if (!res?.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const reservation = (d['reservation'] ?? d['item']) as Record<string, unknown> | undefined;
  const subnet = reservation ? reservation['subnet'] : undefined;
  if (typeof subnet === 'string' && subnet.trim() !== '') return subnet;
  // Real firmware returns the relation as a map { <subnetUuid>: { value, selected } }
  // — pick the entry flagged selected. Also accept an object carrying a direct uuid.
  if (subnet && typeof subnet === 'object' && !Array.isArray(subnet)) {
    const obj = subnet as Record<string, unknown>;
    if (typeof obj['uuid'] === 'string' && obj['uuid'].trim() !== '') return obj['uuid'];
    for (const [key, val] of Object.entries(obj)) {
      if (typeof key !== 'string' || key.trim() === '') continue;
      const v = val as { selected?: number | boolean } | undefined;
      if (v && typeof v === 'object' && (v.selected === 1 || v.selected === true)) return key;
    }
  }
  return null;
}

/** Resolves a Kea subnet recordset uuid back to its CIDR string. */
async function cidrOfKeaSubnet(client: AxiosInstance, uuid: string): Promise<string | null> {
  const res = await searchKeaSubnets(client).catch(() => null);
  if (!res?.ok || !res.data || typeof res.data !== 'object') return null;
  const d = res.data as Record<string, unknown>;
  const rows: Record<string, unknown>[] = Array.isArray(d['rows']) ? (d['rows'] as Record<string, unknown>[]) : [];
  for (const row of rows) {
    if (row['uuid'] === uuid && typeof row['subnet'] === 'string' && /^\d{1,3}(?:\.\d{1,3}){3}\/\d{1,2}$/.test(row['subnet'])) {
      return row['subnet'] as string;
    }
  }
  return null;
}

/** Lists static DHCP mappings/reservations (rows[]). */
export async function searchStaticMappings(
  client: AxiosInstance,
  backend: DhcpBackend,
  query?: Record<string, unknown>
): Promise<OpnsenseApiResult> {
  if (backend === 'kea') {
    return get(client, '/api/kea/dhcpv4/search_reservation', query);
  }
  return get(client, '/api/services/dhcp/staticmap/search', query);
}

/** Activates staged DHCP changes on the active backend. */
export async function reconfigureDhcp(client: AxiosInstance, backend: DhcpBackend): Promise<OpnsenseApiResult> {
  if (backend === 'kea') {
    return post(client, '/api/kea/service/reconfigure', {});
  }
  return post(client, '/api/dnsmasq/service/reconfigure', {});
}

// --- Kea-specific (exposed for completeness) ------------------------------------------

/** GET /api/kea/dhcpv4/get — full Kea DHCPv4 configuration. */
export function getKeaDhcpv4Config(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/kea/dhcpv4/get');
}

/** GET /api/kea/dhcpv4/search_subnet — Kea subnet recordset (rows[]). */
export function searchKeaSubnets(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/kea/dhcpv4/search_subnet', query);
}

/** POST /api/kea/dhcpv4/add_subnet — add a Kea subnet (staged). */
export function addKeaSubnet(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/kea/dhcpv4/add_subnet', { item });
}

/** POST /api/kea/dhcpv4/set_subnet/$uuid — update a Kea subnet (staged). */
export function setKeaSubnet(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/kea/dhcpv4/set_subnet/${encodeURIComponent(uuid)}`, { item });
}

/** POST /api/kea/dhcpv4/del_subnet/$uuid — delete a Kea subnet (staged). */
export function deleteKeaSubnet(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/kea/dhcpv4/del_subnet/${encodeURIComponent(uuid)}`, {});
}

/** GET /api/kea/leases/search — current Kea leases. */
export function searchKeaLeases(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/kea/leases/search', query);
}

// --- dnsmasq-specific (exposed for completeness) ------------------------------------------

/** GET /api/dnsmasq/leases/search — current dnsmasq leases. */
export function searchDnsmasqLeases(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/dnsmasq/leases/search', query);
}
