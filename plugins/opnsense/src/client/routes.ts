import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Routing: static routes (routes/routes) and gateways (routing/settings).
 * Docs: development/api/core/routes.html + core/routing.html. Both are staged;
 * each module has its own reconfigure to activate.
 *
 * The back-route use case (SD-LAN/WAN): a forward route on firewall A toward
 * the remote subnet via a new gateway, plus a BACK-ROUTE on firewall B toward
 * the origin LAN so return traffic is routed correctly — both are plain static
 * routes + gateways expressed through these calls.
 */

// --- Static routes (routes/routes) -------------------------------------------

/** GET /api/routes/routes/searchroute — search static routes (rows[]). */
export function searchRoutes(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/routes/routes/searchroute', query);
}

/** GET /api/routes/routes/getroute/$uuid — one static route. */
export function getRoute(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/routes/routes/getroute/${encodeURIComponent(uuid)}`);
}

/** POST /api/routes/routes/addroute — add a static route (staged). Body: the route object. */
export function addRoute(client: AxiosInstance, route: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/routes/routes/addroute', route);
}

/** POST /api/routes/routes/setroute/$uuid — update a static route (staged). Body: the route object. */
export function setRoute(client: AxiosInstance, uuid: string, route: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/routes/routes/setroute/${encodeURIComponent(uuid)}`, route);
}

/** POST /api/routes/routes/toggleroute/$uuid/$disabled — enable/disable a route (staged). */
export function toggleRoute(client: AxiosInstance, uuid: string, disabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/routes/routes/toggleroute/${encodeURIComponent(uuid)}/${disabled ? '1' : '0'}`, {});
}

/** POST /api/routes/routes/delroute/$uuid — delete a static route (staged). */
export function deleteRoute(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/routes/routes/delroute/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/routes/routes/reconfigure — ACTIVATE staged static-route changes. */
export function reconfigureRoutes(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/routes/routes/reconfigure', {});
}

// --- Gateways (routing/settings) ----------------------------------------------

/** GET /api/routing/settings/search_gateway — search gateways (rows[]). */
export function searchGateways(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/routing/settings/search_gateway', query);
}

/** GET /api/routing/settings/get_gateway/$uuid — one gateway. */
export function getGateway(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/routing/settings/get_gateway/${encodeURIComponent(uuid)}`);
}

/** POST /api/routing/settings/add_gateway — add a gateway (staged). Body: the gateway object. */
export function addGateway(client: AxiosInstance, gateway: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/routing/settings/add_gateway', gateway);
}

/** POST /api/routing/settings/set_gateway/$uuid — update a gateway (staged). Body: the gateway object. */
export function setGateway(client: AxiosInstance, uuid: string, gateway: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/routing/settings/set_gateway/${encodeURIComponent(uuid)}`, gateway);
}

/** POST /api/routing/settings/toggle_gateway/$uuid/$enabled — enable/disable a gateway (staged). */
export function toggleGateway(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/routing/settings/toggle_gateway/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/routing/settings/del_gateway/$uuid — delete a gateway (staged). */
export function deleteGateway(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/routing/settings/del_gateway/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/routing/settings/reconfigure — ACTIVATE staged gateway changes. */
export function reconfigureGateways(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/routing/settings/reconfigure', {});
}

// --- Gateway status -------------------------------------------------------------

/** GET /api/routes/gateway/status — live gateway reachability/latency. */
export function getGatewayStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/routes/gateway/status');
}
