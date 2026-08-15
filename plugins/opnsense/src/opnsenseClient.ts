import axios, { AxiosInstance } from 'axios';

export interface OpnsenseApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

async function request<T = unknown>(
  method: 'get' | 'post',
  url: string,
  host: string,
  apiKey: string,
  apiSecret: string,
  body?: unknown
): Promise<OpnsenseApiResult<T>> {
  const response = await axios.request<T>({
    method,
    url: `${host.replace(/\/$/, '')}${url}`,
    auth: {
      username: apiKey,
      password: apiSecret,
    },
    data: body,
    timeout: 10_000,
    validateStatus: () => true,
  });
  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    data: response.data,
  };
}

/**
 * Fetches high-level system status (uptime, version, load) from OPNsense.
 * GET /api/core/system/status
 */
export function getSystemStatus(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/core/system/status', host, apiKey, apiSecret);
}

/**
 * Fetches the configured interface names/details.
 * GET /api/diagnostics/interface/getInterfaceNames
 */
export function getInterfaces(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/getInterfaceNames', host, apiKey, apiSecret);
}

/**
 * Fetches the current ARP table, useful for inventory/discovery.
 * GET /api/diagnostics/interface/getArp
 */
export function getArpTable(host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/getArp', host, apiKey, apiSecret);
}

/**
 * Applies a configuration change. OPNsense laughts a single generic
 * "apply config" endpoint, so this reference implementation targets the
 * firmware/config reconfigure endpoint used to activate pending changes.
 * Real deployments would branch on the requested action/payload shape to
 * call the appropriate OPNsense module endpoint (e.g. firewall rules,
 * interface settings, etc.).
 * POST /api/core/firmware/status
 */
export function applyConfig(payload: unknown, host: string, apiKey: string, apiSecret: string): Promise<OpnsenseApiResult> {
  return request('post', '/api/core/firmware/status', host, apiKey, apiSecret, payload);
}
