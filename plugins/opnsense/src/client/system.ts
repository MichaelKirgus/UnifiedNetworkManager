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

/**
 * GET /api/diagnostics/system/system_time — the appliance's CURRENT date/time
 * (device-local wall clock) + uptime + loadavg. This is the source for the Time
 * page's `system.deviceTime` metric: OPNsense has no separate "clock" endpoint,
 * and this one returns the live local time string directly.
 */
export function getSystemTime(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_time');
}

/**
 * GET /api/system/timezone/get_timezone — the appliance's configured IANA
 * timezone (e.g. "Europe/Berlin"). Combined with `system_time`'s local wall
 * clock this lets the Time page resolve an absolute instant and compute drift.
 */
export function getSystemTimezone(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/system/timezone/get_timezone');
}

/** POST /api/system/timezone/set_timezone — set the appliance IANA timezone.
 * Body: `{ timezone: 'Europe/Berlin' }`. Applies immediately (no staging). */
export function setSystemTimezone(client: AxiosInstance, timezone: string): Promise<OpnsenseApiResult> {
  return post(client, '/api/system/timezone/set_timezone', { timezone });
}

/** GET /api/diagnostics/system/system_resources — memory/cpu/uptime details. */
export function getSystemResources(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_resources');
}

// --- Storage (best-effort) --------------------------------------------------
// OPNsense exposes NO ZFS pool/dataset listing API — the only storage data is
// the mounted-filesystem overview below. Callers treat a missing endpoint as
// "no data" — never an error (see collectStorage in index.ts).

/** GET /api/diagnostics/system/system_disk/ — mounted filesystems.
 * Returns `{ devices: [{ device, type, blocks, used, available, used_pct,
 * mountpoint }] }` where the size fields are BASE-10 human strings ("5.2G")
 * exactly as OPNsense's own Disk widget consumes them (`_convertToBytes`). */
export function getSystemDisk(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_disk/');
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
