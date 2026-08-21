import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * OpenVPN module: instances (server/client profiles), static keys and the
 * openvpn service. Docs: development/api/core/openvpn.html. Writes are staged;
 * `service.reconfigure` activates them. Certificate/key material arrives as
 * step credentials (provisioned by the secrets provider) — this client only
 * writes it to the appliance.
 */

// --- Instances ---------------------------------------------------------------------

/** GET /api/openvpn/instances/search — all instances (rows[]). */
export function searchInstances(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/openvpn/instances/search', query);
}

/** GET /api/openvpn/instances/get/$uuid — one instance. */
export function getInstance(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/openvpn/instances/get${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** POST /api/openvpn/instances/add — add an instance (staged). Body: the instance object. */
export function addInstance(client: AxiosInstance, instance: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/openvpn/instances/add', instance);
}

/** POST /api/openvpn/instances/set/$uuid — update an instance (staged). Body: the instance object. */
export function setInstance(client: AxiosInstance, uuid: string, instance: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/openvpn/instances/set/${encodeURIComponent(uuid)}`, instance);
}

/** POST /api/openvpn/instances/del/$uuid — delete an instance (staged). */
export function deleteInstance(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/openvpn/instances/del/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/openvpn/instances/toggle/$uuid/$enabled — enable/disable (staged). */
export function toggleInstance(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/openvpn/instances/toggle/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

// --- Static keys ------------------------------------------------------------------------

/** GET /api/openvpn/instances/search_static_key — static (tun2socks-style) keys. */
export function searchStaticKeys(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/openvpn/instances/search_static_key', query);
}

/** POST /api/openvpn/instances/add_static_key — add a static key (staged). */
export function addStaticKey(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/openvpn/instances/add_static_key', item);
}

/** POST /api/openvpn/instances/set_static_key/$uuid — update a static key (staged). */
export function setStaticKey(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/openvpn/instances/set_static_key/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/openvpn/instances/del_static_key/$uuid — delete a static key (staged). */
export function deleteStaticKey(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/openvpn/instances/del_static_key/${encodeURIComponent(uuid)}`, {});
}

// --- Service -------------------------------------------------------------------------------

/** GET /api/openvpn/service/search_sessions — active openvpn sessions. */
export function searchSessions(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/openvpn/service/search_sessions');
}

/** POST /api/openvpn/service/reconfigure — ACTIVATE staged openvpn changes (reload the service). */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/openvpn/service/reconfigure', {});
}
