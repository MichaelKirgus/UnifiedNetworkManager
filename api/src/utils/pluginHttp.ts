/**
 * pluginHttp — the ONE place the API talks to plugins (mTLS-aware).
 *
 * Stage 1 of the mTLS plan: every outbound API→plugin call goes through
 * `pluginAxios()` / `probePluginEndpoint()`, which pick the transport from a
 * per-endpoint registry:
 *   - 'https' when the plugin is mTLS-live (enrolled via ACME, serving TLS on
 *     its conventional port with requestCert+rejectUnauthorized) — the API
 *     presents ITS OWN CA-signed leaf (self-enrolled at boot, identity 'unm-api')
 *     and validates the plugin's chain against the UNM root.
 *   - 'http' otherwise (the default until a plugin enrolls).
 *
 * The registry is seeded from the `plugins.tlsLive` column at boot and updated
 * by discovery (which probes BOTH transports, so a plugin that just swapped to
 * TLS — or lost its leaf — is re-detected within one poll cycle without any
 * manual intervention). Call sites never construct their own axios instances
 * for plugin traffic.
 */

import axios, { AxiosInstance, AxiosRequestConfig } from 'axios';
import https from 'https';
import fs from 'fs';
import { resolvePluginEndpoint } from './pluginEndpoint';

export type PluginTransport = 'http' | 'https';

/** The API's own mTLS identity (its CA-signed leaf + the trust bundle). */
export interface ApiMtlsIdentity {
  keyPem: string;
  certChainPem: string;
  caBundlePem: string;
}

let apiMtls: ApiMtlsIdentity | null = null;
let mtlsAgent: https.Agent | null = null;
let agentFor: ApiMtlsIdentity | null = null;

/** Sets the API's mTLS identity (called once at boot after self-enrollment). */
export function setApiMtlsIdentity(identity: ApiMtlsIdentity): void {
  apiMtls = identity;
  mtlsAgent = null; // force agent rebuild with the new material
}

export function getApiMtlsIdentity(): ApiMtlsIdentity | null {
  return apiMtls;
}

/** Shared https.Agent presenting the API's leaf and trusting the UNM root. */
function apiMtlsAgent(): https.Agent {
  if (!apiMtls) throw new Error('pluginHttp: API mTLS identity not loaded yet');
  if (!mtlsAgent || agentFor !== apiMtls) {
    mtlsAgent = new https.Agent({ ca: [apiMtls.caBundlePem], key: apiMtls.keyPem, cert: apiMtls.certChainPem });
    agentFor = apiMtls;
  }
  return mtlsAgent;
}

// --- per-endpoint transport registry -----------------------------------------

const transportByEndpoint = new Map<string, PluginTransport>();

/**
 * Registry keys are bare origins (`http://<host>:<port>`). Inputs may carry a
 * path/query (e.g. `…/console?apiKey=…`) — reduce those to their origin so the
 * transport lookup still resolves.
 */
function normalizeEndpoint(endpoint: string): string {
  try {
    const u = new URL(endpoint);
    return `${u.protocol}//${u.host}`;
  } catch {
    return endpoint.replace(/\/+$/, '');
  }
}

/** Seeds/updates the registry (boot load from `plugins` rows + discovery upserts). */
export function setPluginTransports(rows: Array<{ endpoint: string; tlsLive?: boolean | null }>): void {
  for (const row of rows) {
    if (!row.endpoint) continue;
    transportByEndpoint.set(normalizeEndpoint(row.endpoint), row.tlsLive ? 'https' : 'http');
  }
}

export function setPluginTransport(endpoint: string, transport: PluginTransport): void {
  transportByEndpoint.set(normalizeEndpoint(endpoint), transport);
}

/**
 * The registered transport for an endpoint — defaults to plain http. Registry
 * keys are RAW advertised endpoints (the `plugins.endpoint` value); host-dev
 * rewriting happens only in the URL builders below.
 */
export function getPluginTransport(endpoint: string): PluginTransport {
  return transportByEndpoint.get(normalizeEndpoint(endpoint)) ?? 'http';
}

/** True when the endpoint should be reached over https with the API's client cert. */
function wantsHttps(endpoint: string): boolean {
  return getPluginTransport(endpoint) === 'https' && apiMtls !== null;
}

// --- the factory ---------------------------------------------------------------

/**
 * An axios instance for one plugin endpoint with the correct transport + TLS
 * material. Plain-http endpoints get a bare instance (identical behavior to
 * today's `axios` calls); mTLS-live endpoints get https + the API client cert.
 */
export function pluginAxios(endpoint: string, opts: Omit<AxiosRequestConfig, 'baseURL'> = {}): AxiosInstance {
  const base = pluginUrl(endpoint);
  if (wantsHttps(endpoint)) {
    return axios.create({ baseURL: base, httpsAgent: apiMtlsAgent(), ...opts });
  }
  return axios.create({ baseURL: base, ...opts });
}

/**
 * The resolved base URL for a plugin endpoint under its registered transport.
 * Applies the host-dev rewrite (resolvePluginEndpoint) and flips http→https
 * when the plugin is mTLS-live. Call sites append their path suffix to this.
 */
export function pluginUrl(endpoint: string): string {
  const resolved = resolvePluginEndpoint(endpoint).replace(/\/+$/, '');
  if (wantsHttps(resolved)) return resolved.replace(/^http/i, 'https');
  return resolved;
}

/** ws:// or wss:// URL for a plugin endpoint's WebSocket paths. */
export function pluginWsUrl(endpoint: string): string {
  const url = pluginUrl(endpoint);
  return wantsHttps(url) ? url.replace(/^http/i, 'wss') : url.replace(/^http/i, 'ws');
}

/** TLS options for `ws` client connections to an mTLS-live plugin. */
export function pluginWsTlsOptions(endpoint: string): Record<string, unknown> {
  if (wantsHttps(resolvePluginEndpoint(endpoint))) {
    return { ca: [apiMtls!.caBundlePem], key: apiMtls!.keyPem, cert: apiMtls!.certChainPem, rejectUnauthorized: true };
  }
  return {};
}

// --- dual-transport probing (discovery + self-healing) --------------------------

export interface ProbeResult<T> {
  data: T;
  /** The transport that actually worked — persist it to `plugins.tlsLive`. */
  transport: PluginTransport;
}

/** Is this error a "wrong transport" failure (connection refused / TLS mismatch)? */
function isTransportError(err: unknown): boolean {
  const e = err as { code?: string; message?: string };
  if (!e) return false;
  if (typeof e.code === 'string') {
    // Plain HTTP answered a TLS handshake (or vice versa), refused, or timed out.
    if (['ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ERR_TLS_CERT_ALTNAME_INVALID'].includes(e.code)) return true;
  }
  const msg = e.message ?? '';
  // Node's TLS-vs-plain mismatches surface as these:
  return /wrong version number|record layer failure|unexpected eof|tls handshake|EPROTO/i.test(msg);
}

/**
 * GETs a plugin endpoint trying BOTH transports (registered one first) and
 * returns the data + which transport worked. This is how discovery re-detects
 * plugins that swapped to TLS (or back) — no manual state needed.
 */
export async function probePluginEndpoint<T>(endpoint: string, pathSuffix: string, timeoutMs = 10_000): Promise<ProbeResult<T>> {
  const base = resolvePluginEndpoint(endpoint).replace(/\/+$/, '');
  const preferred = getPluginTransport(base);
  const order: PluginTransport[] = apiMtls ? [preferred, preferred === 'https' ? 'http' : 'https'] : ['http'];

  let lastErr: unknown = null;
  for (const transport of order) {
    try {
      if (transport === 'https') {
        if (!apiMtls) continue; // can't speak mTLS without our own leaf
        const res = await axios.get<T>(`${base.replace(/^http/i, 'https')}${pathSuffix}`, {
          httpsAgent: apiMtlsAgent(),
          timeout: timeoutMs,
          validateStatus: (s) => s >= 200 && s < 300,
        });
        return { data: res.data, transport };
      }
      const res = await axios.get<T>(`${base}${pathSuffix}`, { timeout: timeoutMs, validateStatus: (s) => s >= 200 && s < 300 });
      return { data: res.data, transport };
    } catch (err) {
      lastErr = err;
      if (!isTransportError(err)) throw err; // real failure (4xx/5xx/etc.) — don't retry the other way
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(`probePluginEndpoint: all transports failed for ${base}`);
}

/** Reads a PEM file if present (used by the API's local CA-bundle fetcher). */
export function readPemIfExists(file: string): string | null {
  try {
    const pem = fs.readFileSync(file, 'utf8');
    return /-----BEGIN CERTIFICATE-----/.test(pem) ? pem : null;
  } catch {
    return null;
  }
}
