import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * IPsec module (swanctl-based): connections (phase1/phase2), local/remote
 * definitions, pre-shared keys, key pairs and the ipsec service.
 * Docs: development/api/core/ipsec.html. Writes are staged; `service.reconfigure`
 * activates them. PSKs arrive as step credentials (provisioned by the secrets
 * provider) — this client only writes them to the appliance.
 */

// --- Connections -----------------------------------------------------------------

/** GET /api/ipsec/connections/search_connection — search connections (rows[]). */
export function searchConnections(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/ipsec/connections/search_connection', query);
}

/** GET /api/ipsec/connections/get_connection/$uuid — one connection. */
export function getConnection(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/ipsec/connections/get_connection${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** POST /api/ipsec/connections/add_connection — add a connection (staged). Body: the connection object. */
export function addConnection(client: AxiosInstance, conn: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/ipsec/connections/add_connection', conn);
}

/** POST /api/ipsec/connections/set_connection/$uuid — update a connection (staged). Body: the connection object. */
export function setConnection(client: AxiosInstance, uuid: string, conn: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/set_connection/${encodeURIComponent(uuid)}`, conn);
}

/** POST /api/ipsec/connections/del_connection/$uuid — delete a connection (staged). */
export function deleteConnection(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/del_connection/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/ipsec/connections/toggle_connection/$uuid/$enabled — enable/disable (staged). */
export function toggleConnection(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/toggle_connection/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

// --- Local / remote definitions ------------------------------------------------------

/** GET /api/ipsec/connections/search_local — local (own-side) definitions. */
export function searchLocal(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/ipsec/connections/search_local', query);
}

/** POST /api/ipsec/connections/add_local — add a local definition (staged). */
export function addLocal(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/ipsec/connections/add_local', item);
}

/** POST /api/ipsec/connections/set_local/$uuid — update a local definition (staged). */
export function setLocal(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/set_local/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/ipsec/connections/del_local/$uuid — delete a local definition (staged). */
export function deleteLocal(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/del_local/${encodeURIComponent(uuid)}`, {});
}

/** GET /api/ipsec/connections/search_remote — remote (peer-side) definitions. */
export function searchRemote(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/ipsec/connections/search_remote', query);
}

/** POST /api/ipsec/connections/add_remote — add a remote definition (staged). */
export function addRemote(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/ipsec/connections/add_remote', item);
}

/** POST /api/ipsec/connections/set_remote/$uuid — update a remote definition (staged). */
export function setRemote(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/set_remote/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/ipsec/connections/del_remote/$uuid — delete a remote definition (staged). */
export function deleteRemote(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/connections/del_remote/${encodeURIComponent(uuid)}`, {});
}

// --- Pre-shared keys -------------------------------------------------------------------

/** GET /api/ipsec/pre_shared_keys/search_item — PSKs (rows[]). */
export function searchPresharedKeys(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/ipsec/pre_shared_keys/search_item', query);
}

/** POST /api/ipsec/pre_shared_keys/add_item — add a PSK (staged). Body: the item. */
export function addPresharedKey(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/ipsec/pre_shared_keys/add_item', item);
}

/** POST /api/ipsec/pre_shared_keys/set_item/$uuid — update a PSK (staged). Body: the item. */
export function setPresharedKey(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/pre_shared_keys/set_item/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/ipsec/pre_shared_keys/del_item/$uuid — delete a PSK (staged). */
export function deletePresharedKey(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/ipsec/pre_shared_keys/del_item/${encodeURIComponent(uuid)}`, {});
}

// --- Service ------------------------------------------------------------------------------

/** GET /api/ipsec/service/status — ipsec service status. */
export function getServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/ipsec/service/status');
}

/** POST /api/ipsec/service/reconfigure — ACTIVATE staged ipsec changes (reload swanctl). */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/ipsec/service/reconfigure', {});
}
