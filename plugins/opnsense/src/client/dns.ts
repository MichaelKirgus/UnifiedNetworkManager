import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * DNS module — DUAL BACKEND. Older OPNsense appliances run dnsmasq for DNS;
 * newer ones use Unbound (the user's fleet note: "in newer installations
 * unbound is used for DNS"). This client exposes one logical surface and
 * dispatches to the active backend, auto-detected per appliance with an
 * optional override.
 */

export type DnsBackend = 'dnsmasq' | 'unbound';

/**
 * Detects which DNS backend the appliance uses: Unbound when its service is
 * enabled (`GET /api/unbound/overview/is_enabled`), otherwise dnsmasq (the
 * historical default). Best-effort — a failing probe falls back to dnsmasq.
 */
export async function detectDnsBackend(client: AxiosInstance): Promise<DnsBackend> {
  try {
    const res = await get<{ enabled?: boolean }>(client, '/api/unbound/overview/is_enabled');
    if (res.ok && res.data?.enabled === true) return 'unbound';
  } catch {
    /* fall through to dnsmasq */
  }
  return 'dnsmasq';
}

// --- Host records (logical surface: add/remove/read a DNS host entry) ---------------

/** Adds a static DNS host record on the active backend. Staged; call reconfigureDns to activate. */
export async function addHostRecord(
  client: AxiosInstance,
  backend: DnsBackend,
  record: { name: string; ip: string }
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    // Unbound host override: { hostname, address }.
    return post(client, '/api/unbound/settings/add_host_override', { item: { hostname: record.name, address: record.ip } });
  }
  // dnsmasq host entry: { name, ip }.
  return post(client, '/api/dnsmasq/settings/add_host', { name: record.name, ip: record.ip });
}

/** Removes a static DNS host record by uuid on the active backend. Staged. */
export async function deleteHostRecord(
  client: AxiosInstance,
  backend: DnsBackend,
  uuid: string
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return post(client, `/api/unbound/settings/del_host_override/${encodeURIComponent(uuid)}`, {});
  }
  return post(client, `/api/dnsmasq/settings/del_host/${encodeURIComponent(uuid)}`, {});
}

/** Lists static DNS host records on the active backend (rows[]). */
export async function searchHostRecords(
  client: AxiosInstance,
  backend: DnsBackend,
  query?: Record<string, unknown>
): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return get(client, '/api/unbound/settings/search_host_override', query);
  }
  return get(client, '/api/dnsmasq/settings/search_host', query);
}

/** Activates staged DNS changes on the active backend. */
export async function reconfigureDns(client: AxiosInstance, backend: DnsBackend): Promise<OpnsenseApiResult> {
  if (backend === 'unbound') {
    return post(client, '/api/unbound/service/reconfigure', {});
  }
  return post(client, '/api/dnsmasq/service/reconfigure', {});
}

// --- dnsmasq-specific (exposed for completeness) --------------------------------------

/** GET /api/dnsmasq/settings/get — full dnsmasq settings. */
export function getDnsmasqSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/dnsmasq/settings/get');
}

/** POST /api/dnsmasq/service/restart — restart dnsmasq. */
export function restartDnsmasq(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/dnsmasq/service/restart', {});
}

// --- Unbound-specific (exposed for completeness) -----------------------------------------

/** GET /api/unbound/settings/get — full unbound settings. */
export function getUnboundSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/unbound/settings/get');
}

/** POST /api/unbound/service/restart — restart unbound. */
export function restartUnbound(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/unbound/service/restart', {});
}
