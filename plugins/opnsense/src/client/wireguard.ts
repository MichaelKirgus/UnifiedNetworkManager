import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * WireGuard module: servers (tunnels), peers/clients, general settings and the
 * wireguard service. Docs: development/api/core/wireguard.html.
 *
 * Key material is NOT generated here — key pairs are provisioned by the
 * secrets provider plugin and arrive as step credentials; this client only
 * writes them to the appliance (server.set / peer.add). The appliance's own
 * `key_pair` endpoint exists but is intentionally unused so all key material
 * stays in the UNM backend.
 */

// --- Servers -------------------------------------------------------------------

/** GET /api/wireguard/server/list_servers — all wireguard servers. */
export function listServers(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/server/list_servers');
}

/** GET /api/wireguard/server/get_server/$uuid — one server (or the first when uuid omitted). */
export function getServer(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/wireguard/server/get_server${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** GET /api/wireguard/server/search_server — search servers (rows[]). */
export function searchServers(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/server/search_server', query);
}

/** POST /api/wireguard/server/add_server — add a server (staged). Body: the server object. */
export function addServer(client: AxiosInstance, server: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/wireguard/server/add_server', server);
}

/** POST /api/wireguard/server/set_server/$uuid — update a server (staged). Body: the server object. */
export function setServer(client: AxiosInstance, uuid: string, server: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/server/set_server/${encodeURIComponent(uuid)}`, server);
}

/** POST /api/wireguard/server/del_server/$uuid — delete a server (staged). */
export function deleteServer(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/server/del_server/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/wireguard/server/toggle_server/$uuid — enable/disable a server (staged). */
export function toggleServer(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/server/toggle_server/${encodeURIComponent(uuid)}`, {});
}

// --- Peers / clients ---------------------------------------------------------------

/** GET /api/wireguard/client/get — all peers across servers. */
export function getPeers(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/client/get');
}

/** GET /api/wireguard/client/get_client/$uuid — one peer (or the first when uuid omitted). */
export function getPeer(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/wireguard/client/get_client${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** GET /api/wireguard/client/search_client — search peers (rows[]). */
export function searchPeers(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/client/search_client', query);
}

/** POST /api/wireguard/client/add_client_builder — add a peer (staged). Body: the peer object. */
export function addPeer(client: AxiosInstance, peer: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/wireguard/client/add_client_builder', peer);
}

/** POST /api/wireguard/client/set_client/$uuid — update a peer (staged). Body: the peer object. */
export function setPeer(client: AxiosInstance, uuid: string, peer: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/client/set_client/${encodeURIComponent(uuid)}`, peer);
}

/** POST /api/wireguard/client/del_client/$uuid — delete a peer (staged). */
export function deletePeer(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/client/del_client/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/wireguard/client/toggle_client/$uuid — enable/disable a peer (staged). */
export function togglePeer(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/wireguard/client/toggle_client/${encodeURIComponent(uuid)}`, {});
}

/** GET /api/wireguard/client/get_server_info/$uuid — server info incl. its public key (for peer wiring). */
export function getServerInfo(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/wireguard/client/get_server_info${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

// --- General + service -----------------------------------------------------------------

/** GET /api/wireguard/general/get — general wireguard settings. */
export function getGeneralSettings(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/general/get');
}

/** POST /api/wireguard/general/set — update general settings (staged). Body: the settings object. */
export function setGeneralSettings(client: AxiosInstance, settings: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/wireguard/general/set', settings);
}

/** GET /api/wireguard/service/status — wireguard service status. */
export function getServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/wireguard/service/status');
}

/** POST /api/wireguard/service/reconfigure — ACTIVATE staged wireguard changes (reload the service). */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/wireguard/service/reconfigure', {});
}
