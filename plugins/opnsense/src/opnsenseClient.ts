import axios, { AxiosInstance } from 'axios';

const OPNSENSE_HOST = process.env.OPNSENSE_HOST ?? 'https://opnsense.local';
const OPNSENSE_KEY = process.env.OPNSENSE_KEY ?? '';
const OPNSENSE_SECRET = process.env.OPNSENSE_SECRET ?? '';

/**
 * Thin axios wrapper around the OPNsense REST API. Uses HTTP basic auth with
 * the API key/secret pair generated in OPNsense's System > Access > Users UI.
 * `validateStatus` is relaxed so callers can inspect non-2xx responses
 * themselves instead of having axios throw.
 */
export const opnsenseHttp: AxiosInstance = axios.create({
  baseURL: OPNSENSE_HOST,
  auth: {
    username: OPNSENSE_KEY,
    password: OPNSENSE_SECRET,
  },
  timeout: 10_000,
  validateStatus: () => true,
});

export interface OpnsenseApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

async function request<T = unknown>(method: 'get' | 'post', url: string, body?: unknown): Promise<OpnsenseApiResult<T>> {
  const response = await opnsenseHttp.request<T>({ method, url, data: body });
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
export function getSystemStatus(): Promise<OpnsenseApiResult> {
  return request('get', '/api/core/system/status');
}

/**
 * Fetches the configured interface names/details.
 * GET /api/diagnostics/interface/getInterfaceNames
 */
export function getInterfaces(): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/getInterfaceNames');
}

/**
 * Fetches the current ARP table, useful for inventory/discovery.
 * GET /api/diagnostics/interface/getArp
 */
export function getArpTable(): Promise<OpnsenseApiResult> {
  return request('get', '/api/diagnostics/interface/getArp');
}

/**
 * Applies a configuration change. OPNsense doesn't have a single generic
 * "apply config" endpoint, so this reference implementation targets the
 * firmware/config reconfigure endpoint used to activate pending changes.
 * Real deployments would branch on the requested action/payload shape to
 * call the appropriate OPNsense module endpoint (e.g. firewall rules,
 * interface settings, etc.).
 * POST /api/core/firmware/status
 */
export function applyConfig(payload: unknown): Promise<OpnsenseApiResult> {
  return request('post', '/api/core/firmware/status', payload);
}
