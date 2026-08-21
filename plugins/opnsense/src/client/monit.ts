import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Monit module: monitored services + alerts. Docs: development/api/core/monit.html.
 * Writes are staged; `service.reconfigure` activates them.
 */

// --- Services ------------------------------------------------------------------------

/** GET /api/monit/settings/search_service — search monitored services (rows[]). */
export function searchServices(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/monit/settings/search_service', query);
}

/** GET /api/monit/settings/get_service/$uuid — one monitored service. */
export function getService(client: AxiosInstance, uuid?: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/monit/settings/get_service${uuid ? `/${encodeURIComponent(uuid)}` : ''}`);
}

/** POST /api/monit/settings/add_service — add a monitored service (staged). Body: the item. */
export function addService(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/monit/settings/add_service', item);
}

/** POST /api/monit/settings/set_service/$uuid — update a monitored service (staged). Body: the item. */
export function setService(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/monit/settings/set_service/${encodeURIComponent(uuid)}`, item);
}

/** POST /api/monit/settings/toggle_service/$uuid/$enabled — enable/disable (staged). */
export function toggleService(client: AxiosInstance, uuid: string, enabled: boolean): Promise<OpnsenseApiResult> {
  return post(client, `/api/monit/settings/toggle_service/${encodeURIComponent(uuid)}/${enabled ? '1' : '0'}`, {});
}

/** POST /api/monit/settings/del_service/$uuid — delete a monitored service (staged). */
export function deleteService(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/monit/settings/del_service/${encodeURIComponent(uuid)}`, {});
}

// --- Alerts ------------------------------------------------------------------------------

/** GET /api/monit/settings/search_alert — search alerts (rows[]). */
export function searchAlerts(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/monit/settings/search_alert', query);
}

/** POST /api/monit/settings/add_alert — add an alert (staged). Body: the item. */
export function addAlert(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/monit/settings/add_alert', item);
}

/** POST /api/monit/settings/del_alert/$uuid — delete an alert (staged). */
export function deleteAlert(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/monit/settings/del_alert/${encodeURIComponent(uuid)}`, {});
}

// --- Service control ------------------------------------------------------------------------

/** GET /api/monit/service/status — monit service status. */
export function getServiceStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/monit/service/status');
}

/** POST /api/monit/service/reconfigure — ACTIVATE staged monit changes. */
export function reconfigureService(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/monit/service/reconfigure', {});
}
