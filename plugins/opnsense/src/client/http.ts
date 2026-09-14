import axios, { AxiosInstance } from 'axios';
import { resolveEndpointCandidates, insecureHttpsAgent } from '@unm/plugin-sdk';

/**
 * Core transport for the OPNsense API client library.
 *
 * The OPNsense REST API (docs.opnsense.org/development/api.html) is addressed
 * as `https://host/api/<module>/<controller>/<command>/[param1/[param2...]]`
 * using exactly two verbs: GET retrieves data, POST creates/updates/executes.
 * Credentials are the API key + secret pair sent as HTTP Basic auth (username =
 * key, password = secret). Appliances almost always present a self-signed TLS
 * certificate, so the https agent accepts it unless the caller forces plain
 * http via the transport option.
 */

/**
 * Result of one OPNsense API call. Stricter than the SDK's `DeviceApiResult`:
 * `data` is ALWAYS present (the transport fills it with whatever body came back,
 * even on non-2xx) so callers can inspect error payloads without narrowing.
 */
export interface OpnsenseApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

/** Transport choice owned by this plugin via its `transport` option. */
export type OpnsenseTransport = 'auto' | 'http' | 'https';

/** Configurable endpoint ports (plugin options httpsPort/httpPort, defaults 443/80). */
export interface OpnsensePorts {
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80). */
  httpPort?: number;
}

/** Default per-request timeout; long-running actions may override per call. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Resolves the absolute base URL for a device address given the transport
 * option — shared SDK resolver (explicit scheme in the address wins, configured
 * default ports applied, HTTPS preferred in auto mode). OPNsense appliances
 * almost always present a self-signed TLS certificate, so https candidates are
 * used with an agent that accepts it (see createClient below).
 */
export function resolveBase(host: string, transport?: OpnsenseTransport, ports?: OpnsensePorts): string {
  return resolveEndpointCandidates(host, { transport, ports })[0] ?? '';
}

/** Credentials for one appliance: the API key/secret pair (Basic auth). */
export interface OpnsenseCredentials {
  apiKey: string;
  apiSecret: string;
}

export interface RequestOptions {
  /** Per-call timeout override (ms). Defaults to DEFAULT_TIMEOUT_MS. */
  timeoutMs?: number;
  /** Query parameters for GET requests (stringified into the URL). */
  query?: Record<string, unknown>;
}

/**
 * Builds a bound client for one appliance. All module clients receive this so
 * credentials/transport stay out of every individual call signature. `ports`
 * carries the configured https/http ports (defaults 443/80) — an explicit port
 * in the management address always wins.
 */
export function createClient(
  host: string,
  credentials: OpnsenseCredentials,
  transport?: OpnsenseTransport,
  ports?: OpnsensePorts
): AxiosInstance {
  const base = resolveBase(host, transport, ports);
  return axios.create({
    baseURL: base,
    auth: { username: credentials.apiKey, password: credentials.apiSecret },
    timeout: DEFAULT_TIMEOUT_MS,
    validateStatus: () => true, // we surface non-2xx as ok:false results, not exceptions
    ...(base.startsWith('https://') ? { httpsAgent: insecureHttpsAgent() } : {}),
  });
}

/**
 * Executes one OPNsense API call. `path` is the full `/api/...` path (path
 * params already interpolated). GET sends `query`; POST sends a JSON body.
 * Never throws for HTTP-level failures — those come back as `{ ok:false }`.
 */
export async function request<T = unknown>(
  client: AxiosInstance,
  method: 'get' | 'post',
  path: string,
  bodyOrQuery?: unknown,
  options: RequestOptions = {}
): Promise<OpnsenseApiResult<T>> {
  const config: Record<string, unknown> = {};
  if (options.timeoutMs) config.timeout = options.timeoutMs;

  let response;
  if (method === 'get') {
    // OPNsense search endpoints accept query params (current/rowCount/sort/searchPhrase).
    const cleanQuery: Record<string, string | number> = {};
    for (const [k, v] of Object.entries((bodyOrQuery as Record<string, unknown>) ?? {})) {
      if (v === undefined || v === null) continue;
      cleanQuery[k] = String(v);
    }
    response = await client.get<T>(path, { params: cleanQuery, ...config });
  } else {
    response = await client.post<T>(path, bodyOrQuery ?? {}, config);
  }

  return {
    ok: response.status >= 200 && response.status < 300,
    status: response.status,
    data: response.data as T,
  };
}

/** Convenience wrapper for GET calls. */
export function get<T = unknown>(client: AxiosInstance, path: string, query?: Record<string, unknown>, options?: RequestOptions): Promise<OpnsenseApiResult<T>> {
  return request(client, 'get', path, query, options);
}

/** Convenience wrapper for POST calls (JSON body). */
export function post<T = unknown>(client: AxiosInstance, path: string, body?: unknown, options?: RequestOptions): Promise<OpnsenseApiResult<T>> {
  return request(client, 'post', path, body, options);
}
