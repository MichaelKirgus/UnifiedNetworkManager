import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Syslog module: remote log destinations + service control.
 * Docs: development/api/core/syslog.html. Writes are staged; `service.reconfigure` activates.
 */

// --- Destinations ------------------------------------------------------------------

/** GET /api/syslog/settings/search_destinations — search syslog destinations (rows[]). */
export function searchDestinations(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/syslog/settings/search_destinations', query);
}

/** GET /api/syslog/settings/get_destination/$uuid — one destination. */
export function getDestination(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/syslog/settings/get_destination${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** POST /api/syslog/settings/add_destination — add a destination (staged). Body: the item. */
export function addDestination(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/syslog/settings/add_destination', item);
}

/** POST /api/syslog/settings/set_destination/$uuid — update a destination (staged). Body: the item. */
export function setDestination(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/syslog/settings/set_destination/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/syslog/settings/toggle_destination/$uuid/$enabled — enable/disable (staged). */
export function toggleDestination(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/syslog/settings/toggle_destination/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/syslog/settings/del_destination/$uuid — delete a destination (staged). */
export function deleteDestination(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/syslog/settings/del_destination/${encodeURIComponent(uuid)}`, {});
}

// --- Service ---------------------------------------------------------------------------

/** GET /api/syslog/service/status — syslog service status. */
export function getServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/syslog/service/status');
}

/** POST /api/syslog/service/reconfigure — ACTIVATE staged syslog changes. */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/syslog/service/reconfigure', {});
}
