/**
 * Outbound device-HTTP shared layer.
 *
 * Every plugin that talks to a device over HTTP(S) re-implemented the same
 * transport mechanics: base-URL/scheme resolution (explicit scheme wins,
 * configured default ports, IPv6 literals), self-signed-TLS acceptance, and —
 * for `auto`-transport plugins — classifying which failures justify an
 * https→http fallback. This module is the single home for those primitives so
 * a new plugin never re-invents them (see docs/PLUGIN-DEVELOPMENT.md).
 *
 * What stays in each plugin: the PROTOCOL on top of HTTP (REST paths, session
 * logins, JSON-RPC framing, typed error classes) — only the transport moves here.
 */

import https from 'https';

/**
 * The canonical result envelope for one device-API call. Non-2xx and network
 * failures come back as `{ ok: false }` results rather than exceptions so a
 * single bad endpoint can never crash a poll. Plugins may alias this type
 * locally (e.g. `OpnsenseApiResult`) or extend it with protocol-specific fields.
 */
export interface DeviceApiResult<T = unknown> {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
}

/** Transport choice owned by a plugin via its `transport` option. */
export type EndpointTransport = 'auto' | 'http' | 'https';

/** Configurable management ports (plugin options, defaults 443/80). */
export interface EndpointPorts {
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80). */
  httpPort?: number;
}

/** Options for {@link resolveEndpointCandidates}. */
export interface EndpointOptions {
  /** Scheme policy. `'auto'`/omitted → both schemes, HTTPS first. */
  transport?: EndpointTransport;
  ports?: EndpointPorts;
}

/** Appends `:<port>` to a scheme+host base when the port differs from the scheme default. */
export function withPort(base: string, port: number | undefined, schemeDefault: number): string {
  if (port === undefined || !Number.isFinite(port) || port <= 0 || port > 65535) return base;
  return port === schemeDefault ? base : `${base}:${Math.floor(port)}`;
}

/**
 * Resolves the candidate base URLs for a device management address.
 *
 * Rules (the union of every plugin's historical behavior):
 *   - An explicit `http(s)://` scheme in the address ALWAYS wins — returned
 *     verbatim, including any port already in it.
 *   - A forced transport (`'http'`/`'https'`) yields a single candidate with
 *     the configured default port applied via {@link withPort}.
 *   - `'auto'` (default) yields BOTH schemes ordered for fallback: HTTPS first
 *     (credentials over TLS preferred), plain HTTP second. A plain-HTTP-only
 *     box simply fails the https attempt and the caller falls through.
 *   - An explicit port in a bare address (`host:8443`, `[::1]:8443`) is kept
 *     for BOTH schemes; otherwise each scheme gets its configured default.
 *
 * Returns an ordered list — single-scheme plugins take `[0]`, auto-fallback
 * plugins iterate until one succeeds. Empty input → empty list.
 */
export function resolveEndpointCandidates(address: string, opts: EndpointOptions = {}): string[] {
  const raw = String(address ?? '').trim().replace(/\/+$/, '');
  if (!raw) return [];

  // Explicit scheme (+ port) wins verbatim.
  if (/^https?:\/\//i.test(raw)) return [raw];

  const t: EndpointTransport = opts.transport ?? 'auto';

  // Bare address: split host from an optional explicit port (IPv6 literals ok).
  let host = raw;
  let explicitPort: number | null = null;
  const v6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) {
    host = `[${v6[1]}]`; // keep the brackets — they are part of a valid URL authority
    if (v6[2]) explicitPort = Number(v6[2]);
  } else {
    const idx = raw.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
      host = raw.slice(0, idx);
      explicitPort = Number(raw.slice(idx + 1));
    }
  }
  if (!host || !Number.isFinite(explicitPort as number) || (explicitPort as number) < 1 || (explicitPort as number) > 65535) {
    explicitPort = null;
  }

  const schemes: string[] = t === 'http' ? ['http'] : t === 'https' ? ['https'] : ['https', 'http'];
  const out: string[] = [];
  for (const scheme of schemes) {
    if (explicitPort !== null) {
      out.push(`${scheme}://${host}:${Math.floor(explicitPort)}`);
    } else {
      const def = scheme === 'https' ? opts.ports?.httpsPort : opts.ports?.httpPort;
      out.push(withPort(`${scheme}://${host}`, def, scheme === 'https' ? 443 : 80));
    }
  }
  return [...new Set(out)];
}

/** Converts an http(s) base URL to its ws(s) equivalent (TrueNAS-style JSON-RPC endpoints). */
export function toWsUrl(httpBase: string): string {
  const b = String(httpBase ?? '').trim().replace(/\/+$/, '');
  if (!b) return '';
  if (/^https:\/\//i.test(b)) return `wss://${b.slice('https://'.length)}`;
  if (/^http:\/\//i.test(b)) return `ws://${b.slice('http://'.length)}`;
  return b; // no scheme — caller decides
}

/** Options for {@link buildWebUiUrl}. */
export interface WebUiUrlOptions {
  /** The plugin's configured web-UI port (from its `webUiPort` option). Applied when the address carries no explicit port. */
  webUiPort?: number;
  /** Scheme to use for bare addresses. Defaults to 'https' — appliance web UIs are TLS by default. */
  scheme?: 'http' | 'https';
}

/**
 * Builds the browser-openable management web-UI URL for a device from its
 * management address + the plugin's configured web-UI port. This is the single
 * home for that knowledge so every plugin resolves URLs identically:
 *   - An explicit `http(s)://` scheme in the address ALWAYS wins (scheme AND any
 *     port already in it are kept verbatim).
 *   - A bare address with an explicit port (`host:8443`, `[::1]:8443`) keeps that
 *     port; the scheme comes from `opts.scheme` (default https).
 *   - A bare address without a port gets `opts.webUiPort` appended when it differs
 *     from the scheme default (so the common 443/80 cases stay clean).
 * An optional path is appended with exactly one separating slash. Empty input → ''.
 */
export function buildWebUiUrl(address: string, opts: WebUiUrlOptions = {}, path?: string): string {
  const raw = String(address ?? '').trim().replace(/\/+$/, '');
  if (!raw) return '';

  let base: string;
  if (/^https?:\/\//i.test(raw)) {
    // Explicit scheme wins verbatim — including any port already in the address.
    base = raw;
  } else {
    const scheme = opts.scheme ?? 'https';
    const v6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
    let host: string;
    let explicitPort: number | null = null;
    if (v6) {
      host = `[${v6[1]}]`; // brackets are part of a valid URL authority
      if (v6[2]) explicitPort = Number(v6[2]);
    } else {
      const idx = raw.lastIndexOf(':');
      if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
        host = raw.slice(0, idx);
        explicitPort = Number(raw.slice(idx + 1));
      } else {
        host = raw;
      }
    }
    if (!host || !Number.isFinite(explicitPort as number) || (explicitPort as number) < 1 || (explicitPort as number) > 65535) {
      explicitPort = null;
    }
    base = explicitPort !== null ? `${scheme}://${host}:${Math.floor(explicitPort)}` : withPort(`${scheme}://${host}`, opts.webUiPort, scheme === 'https' ? 443 : 80);
  }

  const p = String(path ?? '').trim();
  if (!p) return base;
  return `${base}${p.startsWith('/') ? '' : '/'}${p}`;
}

let insecureAgent: https.Agent | null = null;

/**
 * A process-wide shared https agent that accepts self-signed/invalid TLS
 * certificates. Appliances (OPNsense, RouterOS, FRITZ!Box, LuCI…) almost always
 * present one out of the box — rejecting it makes every poll fail with
 * "self-signed certificate" and the device stays offline. One cached instance
 * so plugins don't each create their own agent pool.
 */
export function insecureHttpsAgent(): https.Agent {
  if (!insecureAgent) insecureAgent = new https.Agent({ rejectUnauthorized: false });
  return insecureAgent;
}

/** Network-level axios/node error codes that justify an https→http fallback. */
const NETWORK_ERROR_CODES = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'ETIMEDOUT', 'ECONNRESET', 'EAI_AGAIN', 'EHOSTUNREACH', 'EPROTO', 'ERR_SSL',
]);

/** TLS handshake failures surface as EPROTO with an OpenSSL message — a plain-HTTP box. */
const TLS_FAILURE_PATTERN = /packet length too long|wrong version number|ssl routines|tls routines|record layer failure/i;

/**
 * True when `err` is a NETWORK-level failure (DNS, refused, timeout, reset, or
 * a TLS handshake against a non-TLS endpoint) — the class of error that justifies
 * retrying over plain HTTP in auto-transport mode. HTTP-level outcomes (401/403/…)
 * are NOT network errors: they mean the endpoint answered, so the scheme is right
 * and the failure is final for that candidate.
 */
export function isNetworkLevelError(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: string; message?: string };
  if (typeof e.code === 'string' && NETWORK_ERROR_CODES.has(e.code)) return true;
  const msg = String(e.message ?? '');
  return /timeout|timed out|ECONNREFUSED|ENOTFOUND/i.test(msg) || TLS_FAILURE_PATTERN.test(msg);
}

/** Builds an HTTP Basic `Authorization` header value from a username/password pair. */
export function basicAuthHeader(username: string, password: string): string {
  return `Basic ${Buffer.from(`${username ?? ''}:${password ?? ''}`, 'utf8').toString('base64')}`;
}
