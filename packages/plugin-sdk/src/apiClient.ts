/**
 * createApiClient — the axios bootstrap for plugins that talk BACK to the UNM
 * API's internal plugin routes (basic-auth, secrets-provider). Previously
 * near-verbatim in both.
 */

import axios, { AxiosInstance } from 'axios';

export interface ApiClientOptions {
  /** Base URL of the API (default http://localhost:3000/v1; set to http://api:3000/v1 inside Docker). */
  baseUrl?: string;
  /** Shared plugin API key (default: PLUGIN_API_KEY env). */
  apiKey?: string;
  timeoutMs?: number;
}

export function createApiClient(opts: ApiClientOptions = {}): AxiosInstance {
  const baseURL = (opts.baseUrl ?? process.env.UNM_API_URL ?? 'http://localhost:3000/v1').replace(/\/+$/, '');
  const apiKey = opts.apiKey ?? process.env.PLUGIN_API_KEY;
  return axios.create({
    baseURL,
    timeout: opts.timeoutMs ?? 5000,
    headers: apiKey ? { 'x-plugin-api-key': apiKey } : undefined,
  });
}

/** True when the error is an axios 404 response (i.e. "not found"). */
export function isNotFound(err: unknown): boolean {
  return axios.isAxiosError(err) && err.response?.status === 404;
}

// ---------------------------------------------------------------------------
// Brokered web fetch — plugins never open outbound internet connections.
// Every download (firmware images, release feeds, …) goes through the API's
// internal POST /plugin/webfetch route, which resolves a web-fetch plugin
// (capability `webFetch`) and performs the egress hop — plain or through an
// egress proxy configured in UNM settings. Same invariant as the GeoIP/OSV
// workers: the API container itself never touches the internet either.
// ---------------------------------------------------------------------------

/** Options for {@link webFetchViaApi}. */
export interface WebFetchViaApiOptions {
  /** Absolute http(s) URL to download (the origin request is a GET). */
  url: string;
  /** Egress proxy override — empty/undefined = the API's configured default. */
  proxyUrl?: string;
  /** Per-request timeout in ms (default 120_000, clamped by the broker). */
  timeoutMs?: number;
  /** Hard ceiling for the download in bytes (default: the broker's maxBytes setting). */
  maxBytes?: number;
  /** Extra origin request headers (hop-by-hop headers are dropped by the plugin). */
  headers?: Record<string, string>;
}

/** Result of one brokered fetch. */
export interface WebFetchViaApiResult {
  /** The downloaded bytes. */
  bytes: Buffer;
  /** Origin HTTP status code. */
  status: number;
  /** Origin Content-Type header. */
  contentType: string;
}

/**
 * Downloads `url` through the UNM API's web-fetch broker (POST /plugin/webfetch).
 * Uses the same bootstrap as {@link createApiClient}: UNM_API_URL + x-plugin-api-key.
 * Throws an Error with a meaningful message when no web-fetch plugin is online
 * or the origin request fails — callers decide how to surface that (e.g. omitting
 * their `updates` metric key rather than wiping it on a transient outage).
 */
export async function webFetchViaApi(opts: WebFetchViaApiOptions): Promise<WebFetchViaApiResult> {
  const client = createApiClient({ timeoutMs: Math.max(5_000, opts.timeoutMs ?? 120_000) + 60_000 });
  let res;
  try {
    res = await client.post<Buffer>(
      '/plugin/webfetch',
      { url: opts.url, proxyUrl: opts.proxyUrl || undefined, timeoutMs: opts.timeoutMs, maxBytes: opts.maxBytes, headers: opts.headers },
      { responseType: 'arraybuffer' }
    );
  } catch (e) {
    // Surface the broker's own error message — axios' default hides what actually
    // went wrong on the egress side.
    const err = e as { response?: { data?: unknown; status?: number }; message: string };
    let detail = '';
    try {
      const raw: unknown = err.response?.data;
      let body: string;
      if (typeof raw === 'string') body = raw;
      else if (raw instanceof ArrayBuffer) body = Buffer.from(new Uint8Array(raw)).toString('utf8');
      else if (ArrayBuffer.isView(raw)) body = Buffer.from(raw as unknown as Uint8Array).toString('utf8');
      else body = String(raw ?? '');
      const parsed = JSON.parse(body) as { error?: unknown };
      if (parsed && typeof parsed.error === 'string') detail = `: ${parsed.error}`;
    } catch {
      /* non-JSON body — keep axios' message */
    }
    throw new Error(`web-fetch broker failed${detail || ` (${err.message})`}`);
  }

  const bytes = Buffer.from(res.data as unknown as ArrayBuffer);
  return {
    bytes,
    status: Number(res.headers['x-webfetch-status'] ?? res.status),
    contentType: String(res.headers['x-webfetch-content-type'] ?? 'application/octet-stream'),
  };
}
