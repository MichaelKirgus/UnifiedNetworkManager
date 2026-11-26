/**
 * Core transport for the Shelly device client.
 *
 * Shelly devices speak two protocols depending on generation, both plain HTTP:
 *   - Gen1 (ESP8266, fw 3.x–4.x): legacy REST — GET /shelly, GET /status,
 *     GET /settings/sta, GET /ota[?update=true], POST /reboot.
 *   - Gen2+ (Plus/Pro/Wave/Gen3/Gen4, fw 1.x & 2.x+): JSON-RPC 2.0 over a
 *     single POST /rpc endpoint. The device accepts request ARRAYS (batches),
 *     so one round-trip can collect everything — the plugin polls with exactly
 *     one batched request per device per poll.
 *
 * This module is transport-only: it resolves the base URL (shared SDK resolver,
 * explicit scheme in the address wins), sends requests with a hard timeout cap
 * below the ~10 s poll budget, and never throws for HTTP-level failures —
 * those come back as typed `{ ok:false }` results so callers can distinguish
 * "device unreachable" from "authentication rejected" (both are critical
 * health, but with different messages).
 */

import axios, { AxiosError } from 'axios';
import { insecureHttpsAgent, resolveEndpointCandidates } from '@unm/plugin-sdk';

/** Transport choice owned by this plugin via its `transport` option. */
export type ShellyTransport = 'auto' | 'http' | 'https';

/** Everything the transport needs to reach one device. */
export interface ShellyClientOptions {
  /** Device address: `host`, `host:port`, or an explicit `http(s)://...` URL. */
  address: string;
  /** Endpoint scheme selection (default: plain http — Shelly serves HTTP). */
  transport?: ShellyTransport;
  /** Plain-HTTP management port when the address has no explicit port (default 80). */
  httpPort?: number;
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Per-request timeout in ms (clamped to [100, MAX_TIMEOUT_MS]). */
  timeoutMs?: number;
}

export const DEFAULT_HTTP_PORT = 80;
export const DEFAULT_HTTPS_PORT = 443;
export const DEFAULT_TIMEOUT_MS = 5_000;
/** Hard cap — must stay below the ~10 s per-poll budget. */
export const MAX_TIMEOUT_MS = 9_000;

/** Failure classes callers can branch on (health verdicts, retry logic). */
export type ShellyErrorKind = 'unreachable' | 'auth-rejected';

/** Result of one Gen1 REST call. On non-2xx the raw body (if any) is still
 *  surfaced in `data` so callers can inspect error payloads; on transport
 *  failure it is null. */
export interface ShellyResult<T = unknown> {
  ok: boolean;
  /** HTTP status, or 0 for transport-level failure (no response at all). */
  status: number;
  data: T | null;
  errorKind?: ShellyErrorKind;
  error?: string;
}

/** Structural auth interface — implemented by AuthSession in auth.ts. */
export interface ShellyAuth {
  /** Headers for an outbound request (Basic and/or captured cookie). */
  headers(): Record<string, string>;
  /** Feed the response back so sessions can capture/expire cookies. */
  onResponse(status: number, setCookies: string[]): void;
}

/** Resolves the absolute base URL — shared SDK resolver. Explicit scheme in
 *  the address wins; configured default ports applied; HTTPS preferred in auto. */
export function resolveBase(
  opts: Pick<ShellyClientOptions, 'address' | 'transport' | 'httpPort' | 'httpsPort'>,
): string {
  return (
    resolveEndpointCandidates(opts.address, {
      transport: opts.transport ?? 'auto',
      ports: {
        httpPort: opts.httpPort ?? DEFAULT_HTTP_PORT,
        httpsPort: opts.httpsPort ?? DEFAULT_HTTPS_PORT,
      },
    })[0] ?? ''
  );
}

function timeoutOf(opts: ShellyClientOptions): number {
  const t = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  return Math.max(100, Math.min(Math.floor(t), MAX_TIMEOUT_MS));
}

/** One raw HTTP exchange. `setCookies` is surfaced for session capture. */
async function doRequest<T>(
  opts: ShellyClientOptions,
  method: 'get' | 'post',
  path: string,
  body?: unknown,
  auth?: ShellyAuth,
): Promise<ShellyResult<T> & { setCookies: string[] }> {
  const base = resolveBase(opts);
  if (!base) {
    return {
      ok: false,
      status: 0,
      data: null,
      errorKind: 'unreachable',
      error: `no endpoint candidates for address "${opts.address}"`,
      setCookies: [],
    };
  }

  try {
    const response = await axios.request<T>({
      method,
      url: `${base}${path}`,
      data: body,
      headers: auth?.headers() ?? {},
      timeout: timeoutOf(opts),
      validateStatus: () => true, // non-2xx becomes ok:false, never an exception
      ...(base.startsWith('https://') ? { httpsAgent: insecureHttpsAgent() } : {}),
    });
    const setCookies = (response.headers['set-cookie'] as string[] | undefined) ?? [];
    auth?.onResponse(response.status, setCookies);

    const result: ShellyResult<T> = {
      ok: response.status >= 200 && response.status < 300,
      status: response.status,
      data: (response.data as T) ?? null,
    };
    if (response.status === 401 || response.status === 403) {
      result.errorKind = 'auth-rejected';
      result.error = `authentication rejected by device (HTTP ${response.status})`;
    } else if (!result.ok) {
      result.error = `device answered HTTP ${response.status}`;
    }
    return { ...result, setCookies };
  } catch (err) {
    const msg = err instanceof AxiosError ? err.message : String(err);
    return {
      ok: false,
      status: 0,
      data: null,
      errorKind: 'unreachable',
      error: `device unreachable (${msg})`,
      setCookies: [],
    };
  }
}

/** One Gen1 REST GET (e.g. `/status`, `/ota`, `/settings/sta`). */
export async function gen1Get<T = unknown>(
  opts: ShellyClientOptions,
  path: string,
  auth?: ShellyAuth,
): Promise<ShellyResult<T>> {
  const r = await doRequest<T>(opts, 'get', path, undefined, auth);
  const { setCookies: _cookies, ...rest } = r;
  return rest;
}

/** One Gen1 REST POST (e.g. `/reboot`). */
export async function gen1Post<T = unknown>(
  opts: ShellyClientOptions,
  path: string,
  auth?: ShellyAuth,
): Promise<ShellyResult<T>> {
  const r = await doRequest<T>(opts, 'post', path, undefined, auth);
  const { setCookies: _cookies, ...rest } = r;
  return rest;
}

// ---------------------------------------------------------------------------
// JSON-RPC (Gen2+)
// ---------------------------------------------------------------------------

/** One method call inside a batch. */
export interface RpcMethodCall {
  method: string;
  params?: Record<string, unknown>;
}

/** Per-method outcome inside a batch response. */
export interface RpcMethodResult {
  ok: boolean;
  result?: unknown;
  error?: { code: number; message: string };
}

/** Outcome of one POST /rpc round-trip (always sent as a batch). */
export interface ShellyRpcResponse {
  /** true when the transport succeeded AND the body was well-formed RPC. */
  ok: boolean;
  status: number;
  /** Per-method results in CALL ORDER (matched by request id). */
  results: RpcMethodResult[];
  setCookies: string[];
  errorKind?: ShellyErrorKind;
  error?: string;
}

/**
 * Executes `methods` in ONE POST /rpc round-trip. The device echoes the
 * request ids back, so responses are matched by id — order-independent.
 */
export async function rpc(
  opts: ShellyClientOptions,
  methods: RpcMethodCall[],
  auth?: ShellyAuth,
): Promise<ShellyRpcResponse> {
  const body = methods.map((m, i) => ({
    jsonrpc: '2.0',
    id: i + 1,
    method: m.method,
    params: m.params ?? {},
  }));

  const r = await doRequest<unknown>(opts, 'post', '/rpc', body, auth);

  if (r.errorKind) {
    return { ok: false, status: r.status, results: [], setCookies: r.setCookies, errorKind: r.errorKind, error: r.error };
  }
  if (!r.ok || !Array.isArray(r.data)) {
    return {
      ok: false,
      status: r.status,
      results: [],
      setCookies: r.setCookies,
      error: Array.isArray(r.data) ? undefined : r.error ?? 'malformed JSON-RPC response (expected an array)',
    };
  }

  const byId = new Map<number, { id?: unknown; result?: unknown; error?: { code: number; message: string } }>();
  for (const item of r.data as Array<Record<string, unknown>>) {
    if (item && typeof item.id === 'number') byId.set(item.id as number, item);
  }

  const results: RpcMethodResult[] = methods.map((_, i) => {
    const item = byId.get(i + 1);
    if (!item) return { ok: false, error: { code: -32603, message: 'no response for method' } };
    if (item.error) return { ok: false, error: item.error };
    return { ok: true, result: item.result };
  });

  return { ok: true, status: r.status, results, setCookies: r.setCookies };
}
