import { AxiosInstance } from 'axios';
import * as http from './client/http';
import * as system from './client/system';
import * as diagnostics from './client/diagnostics';

/**
 * Legacy transport + monitoring helpers, kept for backward compatibility.
 *
 * The real implementation now lives in `./client/` (one module file per
 * OPNsense API area). This shim re-exports the same names with the SAME legacy
 * signatures — `(host, apiKey, apiSecret, transport)` — so existing callers
 * keep compiling unchanged. New code should use `createClient()` from
 * `./client/http` and pass the bound client instead of repeating credentials
 * on every call.
 */

export type { OpnsenseApiResult, OpnsenseTransport } from './client/http';
export const resolveBase = http.resolveBase;

function clientFor(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): AxiosInstance {
  return http.createClient(host, { apiKey, apiSecret }, transport);
}

/**
 * Fetches high-level system status (uptime, version, load) from OPNsense.
 * GET /api/core/system/status
 */
export function getSystemStatus(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return system.getSystemStatus(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches system resource usage (memory total/used in bytes).
 * GET /api/diagnostics/system/system_resources
 */
export function getSystemResources(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return system.getSystemResources(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches system information (hostname, versions).
 * GET /api/diagnostics/system/system_information
 */
export function getSystemInformation(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return system.getSystemInformation(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches the configured interface names/details.
 * GET /api/diagnostics/interface/get_interface_names
 */
export function getInterfaces(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return diagnostics.getInterfaces(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches per-interface traffic statistics (byte counters).
 * GET /api/diagnostics/interface/get_interface_statistics
 */
export function getInterfaceStats(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return diagnostics.getInterfaceStats(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches the ARP table (IPv4 neighbors). The web UI uses a POST "search" endpoint
 * (GET /getArp returns 403). Shape:
 *   { total, rowCount, current, rows: [{ mac, ip, intf, manufacturer, intf_description, ... }] }
 * POST /api/diagnostics/interface/search_arp/
 */
export function getArpTable(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return diagnostics.getArpTable(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Fetches the NDP table (IPv6 neighbors).
 *   { total, rowCount, current, rows: [{ mac, ip, intf, manufacturer, ... }] }
 * POST /api/diagnostics/interface/search_ndp/
 */
export function getNdpTable(host: string, apiKey: string, apiSecret: string, transport?: http.OpnsenseTransport): Promise<http.OpnsenseApiResult> {
  return diagnostics.getNdpTable(clientFor(host, apiKey, apiSecret, transport));
}

/**
 * Reads a single CPU-usage sample from OPNsense's Server-Sent Events stream.
 *
 * The dashboard's CPU graph polls `GET /api/diagnostics/cpu_usage/stream`,
 * which emits one `event: message` frame per second with a shape like:
 *   { "total": 11, "user": 3, "nice": 0, "sys": 7, "intr": 1, "idle": 88 }
 * where `total` is the percentage of CPU in use (100 - idle).
 *
 * This helper opens the stream, captures the first complete sample, and closes
 * the connection — so a poll takes ~1s and never hangs. Returns `undefined`
 * when the appliance doesn't expose the endpoint (older firmware).
 */
/**
 * Reads a single CPU-usage sample from OPNsense's Server-Sent Events stream.
 * Best-effort — returns undefined when the appliance doesn't expose it.
 */
export function getCpuUsage(
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: http.OpnsenseTransport
): Promise<{ total: number; user: number; sys: number; intr: number; idle: number } | undefined> {
  return diagnostics.getCpuUsage(host, { apiKey, apiSecret }, transport);
}

/**
 * Legacy "apply config" stub. Kept so old job payloads still execute something
 * harmless (a firmware status read) instead of erroring — the real configuration
 * surface is now the action registry dispatched by /config (see index.ts).
 */
export function applyConfig(
  payload: unknown,
  host: string,
  apiKey: string,
  apiSecret: string,
  transport?: http.OpnsenseTransport
): Promise<http.OpnsenseApiResult> {
  return http.post(clientFor(host, apiKey, apiSecret, transport), '/api/core/firmware/status', payload);
}
