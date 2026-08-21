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
    // Kea reservation: { interface, mac, ip, hostname }.
    return post(client, '/api/kea/dhcpv4/add_reservation', { item: mapping });
  }
  // Legacy dnsmasq static map (services plugin controller).
  return post(client, '/api/services/dhcp/staticmap/add', {
    interface: mapping.interface,
    mac: mapping.mac,
    ipaddr: mapping.ip,
    hostname: mapping.hostname ?? '',
  });
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
