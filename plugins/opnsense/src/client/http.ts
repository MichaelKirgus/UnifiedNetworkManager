import axios, { AxiosInstance } from 'axios';
import { Agent as HttpsAgent } from 'https';

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

export interface OpnsenseApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data: T;
}

/** Transport choice owned by this plugin via its `transport` option. */
export type OpnsenseTransport = 'auto' | 'http' | 'https';

// OPNsense appliances almost always present a self-signed TLS certificate.
// Rejecting it (axios default) makes every poll fail with "self-signed
// certificate" and the device stays offline. Use an agent that accepts it.
const httpsAgent = new HttpsAgent({ rejectUnauthorized: false });

/** Default per-request timeout; long-running actions may override per call. */
export const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * Resolves the absolute base URL for a device address given the transport
 * option:
 *  - host already carries a scheme (legacy full-URL managementAddress) → kept.
 *  - `transport: 'http'` / `'https'` → that scheme is forced onto bare hosts.
 *  - `auto` (default, preserves historical behavior) → https with self-signed
 *    certificates accepted — OPNsense appliances almost always present one.
 */
export function resolveBase(host: string, transport?: OpnsenseTransport): string {
  const h = (host ?? '').trim().replace(/\/$/, '');
  if (!h) return '';
  if (/^https?:\/\//i.test(h)) return h; // explicit scheme wins
  const t = transport ?? 'auto';
  const scheme = t === 'http' ? 'http://' : 'https://';
  return `${scheme}${h}`;
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
 * credentials/transport stay out of every individual call signature.
 */
export function createClient(host: string, credentials: OpnsenseCredentials, transport?: OpnsenseTransport): AxiosInstance {
  const base = resolveBase(host, transport);
  return axios.create({
    baseURL: base,
    auth: { username: credentials.apiKey, password: credentials.apiSecret },
    timeout: DEFAULT_TIMEOUT_MS,
    validateStatus: () => true, // we surface non-2xx as ok:false results, not exceptions
    ...(base.startsWith('https://') ? { httpsAgent } : {}),
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
