/**
 * Minimal MikroTik RouterOS REST API client.
 *
 * RouterOS exposes its console as a JSON wrapper at `http(s)://<host>/rest`
 * (since 7.1beta4, requires the `www`/`www-ssl` service). Authentication is
 * plain HTTP Basic with the same username/password as the console user. All
 * response values are STRINGS (even numbers and booleans); list endpoints
 * return JSON arrays of objects keyed by property name (`rx-byytes`, `.id`).
 *
 * REST method semantics (verified live on RouterOS 7.21 LTS):
 *   GET     — print a table or single record.
 *   PUT     — CREATE one new record in the table at the path (201 + created row).
 *   PATCH   — UPDATE a single record; the path MUST carry its id/name.
 *             Some singleton tables (e.g. /system/clock) reject PATCH with 500 —
 *             use POST `<table>/set` for those.
 *   DELETE  — REMOVE one record by id in the path (204).
 *   POST    — UNIVERSAL console-command access: `/rest/<command>` runs that
 *             command word (`/export`, `/execute {script}`, `<table>/remove`).
 *             Command-word endpoints take a SINGLE object body; array bodies
 *             are rejected with 400. POST is NOT the CRUD create/update path —
 *             `POST /rest/<table>` answers "no such command".
 *
 * Transport notes:
 *  - We use raw node:http/node:https (NOT global fetch) because Node's fetch
 *    cannot disable TLS certificate verification via an `agent` option, and
 *    RouterOS boxes almost always present self-signed certificates. The
 *    `insecureTls` option maps to https.request({ rejectUnauthorized }).
 *  - Scheme handling is a plugin setting (`schemeMode`): 'auto' (default)
 *    tries HTTPS first and falls back to HTTP when the TLS layer fails; an
 *    explicit scheme in the management address always wins. The winning base
 *    URL is remembered per client so steady-state polls never re-probe.
 */

import http from 'http';
import https from 'https';
import { basicAuthHeader, resolveEndpointCandidates } from '@unm/plugin-sdk';

/** Transport scheme policy (plugin option `schemeMode`). */
export type SchemeMode = 'auto' | 'https' | 'http';

/** 401/403 — the credentials are wrong or the user lacks REST access. */
export class RouterOsAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouterOsAuthError';
  }
}

/** HTTP-level API failure (4xx/5xx with a JSON error body). */
export class RouterOsApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'RouterOsApiError';
    this.status = status;
  }
}

/** Network-level failure (DNS/refused/timeout/TLS handshake). */
export class RouterOsUnreachableError extends Error {
  constructor(message: string, readonly cause?: unknown) {
    super(message);
    this.name = 'RouterOsUnreachableError';
  }
}

/**
 * The endpoint answered but not like a RouterOS REST API — e.g. an HTTP-only
 * server replying "400 Bad Request" (plain text, no JSON) to a TLS handshake.
 * Treated as a scheme mismatch: auto mode falls back to the next candidate.
 */
export class RouterOsProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RouterOsProtocolError';
  }
}

export interface RouterOsClientOptions {
  username: string;
  password: string;
  /** Per-ATTEMPT timeout (ms). In auto mode a scheme fallback may cost up to 2×. */
  timeoutMs: number;
  /** Accept self-signed/invalid TLS certificates (common on RouterOS boxes). */
  insecureTls: boolean;
  /** Scheme policy — see SchemeMode. */
  schemeMode: SchemeMode;
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80) — used for auto-mode fallbacks. */
  httpPort?: number;
}

interface RawResponse {
  status: number;
  body: string;
}

/** One raw HTTP(S) request with Basic auth + hard timeout. Never resolves on network failure — throws RouterOsUnreachableError. */
function rawRequest(url: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', headers: Record<string, string>, body: string | undefined, opts: { timeoutMs: number; insecureTls: boolean }): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch (err) {
      reject(new RouterOsUnreachableError(`Invalid URL "${url}"`, err));
      return;
    }
    const lib = u.protocol === 'https:' ? https : http;
    const req = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        path: `${u.pathname}${u.search}`,
        method,
        headers: { ...headers },
        // Self-signed certs are the norm on RouterOS — opt in explicitly.
        ...(u.protocol === 'https:' ? { rejectUnauthorized: !opts.insecureTls } : {}),
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', (err) => reject(new RouterOsUnreachableError(`Response error: ${(err as Error).message}`, err)));
      }
    );
    req.setTimeout(opts.timeoutMs, () => {
      req.destroy(new Error(`timeout after ${opts.timeoutMs} ms`));
    });
    req.on('error', (err) => reject(new RouterOsUnreachableError((err as Error).message, err)));
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** Parses a RouterOS JSON body; throws typed errors for non-2xx. */
function parseBody<T>(res: RawResponse): T {
  let parsed: unknown = null;
  if (res.body.trim() !== '') {
    try {
      parsed = JSON.parse(res.body);
    } catch {
      // Non-JSON body on a non-2xx is handled below; on 2xx it's malformed.
    }
  }
  if (res.status < 200 || res.status >= 300) {
    const obj = parsed && typeof parsed === 'object' ? (parsed as Record<string, unknown>) : null;
    // RouterOS error bodies are JSON objects carrying `error`/`message`.
    if (obj !== null && ('error' in obj || 'message' in obj)) {
      const detail = obj['message'] ?? obj['detail'];
      const msg = typeof detail === 'string' && detail.trim() !== '' ? detail : `HTTP ${res.status}`;
      if (res.status === 401 || res.status === 403) throw new RouterOsAuthError(`Authentication failed (${msg})`);
      throw new RouterOsApiError(res.status, msg);
    }
    // Non-RouterOS answer (plain-text "Bad Request" from a non-TLS server,
    // an HTML error page, ...) — scheme mismatch, not an API failure.
    throw new RouterOsProtocolError(`Non-RouterOS response on ${res.status} (HTTP ${res.status})`);
  }
  return parsed as T;
}

export class RouterOsClient {
  /** Management address as given (no trailing slash) — used for rate-tracker keys. */
  readonly address: string;
  private readonly opts: RouterOsClientOptions;
  /** Winning base URL once a scheme has proven itself (auto mode). */
  private resolvedBase: string | null = null;

  constructor(address: string, opts: RouterOsClientOptions) {
    this.address = address.trim().replace(/\/+$/, '');
    this.opts = opts;
  }

  /** Ordered candidate base URLs for the current scheme policy (shared SDK resolver). */
  private candidates(): string[] {
    const addr = this.address;
    if (/^https?:\/\//i.test(addr)) return [addr]; // explicit scheme (+ port) always wins
    const ports = { httpsPort: this.opts.httpsPort, httpPort: this.opts.httpPort };
    switch (this.opts.schemeMode) {
      case 'https':
        return resolveEndpointCandidates(addr, { transport: 'https', ports });
      case 'http':
        return resolveEndpointCandidates(addr, { transport: 'http', ports });
      default: {
        const [httpsBase, httpBase] = resolveEndpointCandidates(addr, { ports }); // HTTPS first
        // Remembered scheme first, the other one as fallback.
        if (this.resolvedBase === httpsBase || this.resolvedBase === httpBase) {
          return [this.resolvedBase, this.resolvedBase === httpsBase ? httpBase : httpsBase];
        }
        return [httpsBase, httpBase]; // default: HTTPS first, then HTTP
      }
    }
  }

  /** Executes one REST call across the candidate schemes. HTTP-level errors (auth/API) propagate immediately — only network/TLS failures trigger a scheme fallback. */
  private async request<T>(path: string, method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE', body?: Record<string, unknown> | Array<Record<string, unknown>>): Promise<T> {
    const headers: Record<string, string> = {
      Authorization: basicAuthHeader(this.opts.username, this.opts.password),
      Accept: 'application/json',
    };
    let lastErr: unknown = null;
    for (const base of this.candidates()) {
      try {
        const res = await rawRequest(
          `${base}/rest${path.startsWith('/') ? path : `/${path}`}`,
          method,
          body !== undefined ? { ...headers, 'Content-Type': 'application/json' } : headers,
          body !== undefined ? JSON.stringify(body) : undefined,
          { timeoutMs: this.opts.timeoutMs, insecureTls: this.opts.insecureTls }
        );
        const parsed = parseBody<T>(res); // throws on non-2xx — reaching here means success
        // Remember the scheme that worked (auto mode only — pinned modes have one candidate).
        if (this.opts.schemeMode === 'auto') this.resolvedBase = base;
        return parsed;
      } catch (err) {
        if (err instanceof RouterOsAuthError || err instanceof RouterOsApiError) throw err; // don't scheme-fall back on HTTP-level failures
        lastErr = err; // network/TLS failure or protocol mismatch → try the next candidate
      }
    }
    const detail = lastErr instanceof Error ? lastErr.message : String(lastErr);
    throw new RouterOsUnreachableError(`RouterOS unreachable at ${this.address}: ${detail}`, lastErr);
  }

  /** GET one REST resource (list or single record). */
  get<T = unknown>(path: string): Promise<T> {
    return this.request<T>(path, 'GET');
  }

  /** PUT — CREATE a new record in the table encoded in the path (`/rest/<table>`).
   * Only ONE resource per request; the response is the created object (with `.id`). */
  put<T = unknown>(path: string, body?: Record<string, unknown>): Promise<T> {
    return this.request<T>(path, 'PUT', body);
  }

  /** PATCH — UPDATE a single record. The path MUST carry the record id
   * (`/rest/<table>/<id>` or `/rest/<table>/<name>` for named tables). */
  patch<T = unknown>(path: string, body?: Record<string, unknown>): Promise<T> {
    return this.request<T>(path, 'PATCH', body);
  }

  /** DELETE — REMOVE the record with the id encoded in the path (`/rest/<table>/<id>`). */
  delete(path: string): Promise<unknown> {
    return this.request(path, 'DELETE');
  }

  /** POST to a console command endpoint (e.g. `/export`, `<table>/remove`).
   * This is the UNIVERSAL method — it maps onto arbitrary console commands, so
   * it works for operations with no CRUD equivalent (singleton `set` on tables
   * like /system/clock that reject PATCH, batch removes via a SINGLE object
   * body `{".id": ...}`, scripts via `/execute {script}`). NOTE: array bodies
   * are NOT accepted by command-word endpoints — loop single-object calls. */
  post<T = unknown>(path: string, body?: Record<string, unknown> | Array<Record<string, unknown>>): Promise<T> {
    return this.request<T>(path, 'POST', body);
  }
}

// --- Small value helpers (RouterOS returns everything as strings) -------------------

/** Reads a numeric field from a RouterOS row (numeric strings coerced). */
export function rosNumber(row: Record<string, unknown>, keys: string[]): number | undefined {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && !Number.isNaN(Number(v))) return Number(v);
  }
  return undefined;
}

/** Reads the first non-empty string field from a RouterOS row. */
export function rosString(row: Record<string, unknown>, keys: string[]): string | undefined {
  for (const k of keys) {
    const v = row[k];
    if (typeof v === 'string' && v.trim() !== '') return v;
  }
  return undefined;
}

/** Parses a CIDR ("10.0.0.1/24" or "fe80::1") into ip + prefix + version. */
export function parseCidr(cidr: string): { ip: string; prefix: number | null; version: 'v4' | 'v6' } {
  const [addr, prefixPart] = cidr.split('/');
  const version: 'v4' | 'v6' = addr.includes(':') ? 'v6' : 'v4';
  return { ip: (addr ?? '').trim(), prefix: prefixPart !== undefined && !Number.isNaN(Number(prefixPart)) ? Number(prefixPart) : null, version };
}

/** Parses a RouterOS link-speed string ("1000M", "1G", "auto") into bits/s (null when unknown). */
export function parseSpeedBitsPerSec(raw: string | null | undefined): number | null {
  if (!raw) return null;
  const m = raw.trim().match(/^(\d+(?:\.\d+)?)\s*(k|m|g)?/i);
  if (!m) return null;
  const value = Number(m[1]);
  switch ((m[2] ?? '').toLowerCase()) {
    case 'k':
      return Math.round(value * 1e6); // kbit/s → bits/s (RouterOS reports kbit)
    case 'g':
      return Math.round(value * 1e9);
    case 'm':
    default:
      return Math.round(value * 1e6); // "M" = Mbit/s; bare number treated as Mbit too
  }
}
