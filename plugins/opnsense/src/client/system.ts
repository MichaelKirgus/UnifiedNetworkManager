import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Core/system module: status, information, power actions, service control,
 * tunables and defaults. Docs: development/api/core/core.html + core/system.
 */

export interface SystemStatus {
  metadata?: { system?: { status?: number; uptime?: string; version?: string } };
}

/** GET /api/core/system/status — appliance health (0=critical,1=warning,2=ok) + uptime. */
export function getSystemStatus(client: AxiosInstance): Promise<OpnsenseApiResult<SystemStatus>> {
  return get(client, '/api/core/system/status');
}

/** POST /api/core/system/reboot — DANGEROUS: reboots the appliance. */
export function reboot(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/system/reboot', {});
}

/** POST /api/core/system/halt — DANGEROUS: powers off the appliance. */
export function halt(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/system/halt', {});
}

/** GET /api/diagnostics/system/system_information — hostname + version list. */
export function getSystemInformation(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_information');
}

/** GET /api/diagnostics/system/system_resources — memory/cpu/uptime details. */
export function getSystemResources(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_resources');
}

// --- Service control (core/service) ---------------------------------------

/** GET /api/core/service/search — all services + running state. */
export function searchServices(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/service/search', query);
}

/** POST /api/core/service/start/$name — start one service (e.g. `pf`, `unbound`). */
export function startService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/start/${encodeURIComponent(name)}`, {});
}

/** POST /api/core/service/stop/$name — stop one service. */
export function stopService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/stop/${encodeURIComponent(name)}`, {});
}

/** POST /api/core/service/restart/$name — restart one service. */
export function restartService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/restart/${encodeURIComponent(name)}`, {});
}

// --- Tunables (core/tunables) ---------------------------------------------

/** GET /api/core/tunables/get — all tunable items. */
export function getTunables(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/tunables/get');
}

/** POST /api/core/tunables/add_item — add a kernel tunable (staged). */
export function addTunable(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/tunables/add_item', { item });
}

/** POST /api/core/tunables/set_item/$uuid — update a tunable (staged). */
export function setTunable(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/tunables/set_item/${encodeURIComponent(uuid)}`, { item });
}

/** POST /api/core/tunables/del_item/$uuid — remove a tunable (staged). */
export function deleteTunable(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/tunables/del_item/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/core/tunables/reconfigure — activate staged tunable changes. */
export function reconfigureTunables(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/tunables/reconfigure', {});
}

// --- Defaults (core/defaults) ---------------------------------------------

/** GET /api/core/defaults/get — current default values. */
export function getDefaults(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/defaults/get');
}
