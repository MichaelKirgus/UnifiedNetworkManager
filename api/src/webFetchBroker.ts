import { createHash } from 'crypto';
import { AxiosInstance } from 'axios';
import { pluginAxios } from './utils/pluginHttp';
import { db } from './db';
import * as schema from './db/schema';

/**
 * Web-fetch broker.
 *
 * The API never opens outbound internet connections itself — in enterprise
 * environments egress is proxied (or absent entirely on the API's network
 * segment). Every download goes through a web-fetch plugin (capability
 * `webFetch`), resolved exactly like the file-repo provider: explicit id →
 * reserved built-in UUID → any online plugin advertising the capability. The
 * caller passes proxy/timeout/size per request so the Settings page can steer
 * egress without redeploying anything.
 */

/** Reserved UUID for the built-in web-fetch plugin (plugins/web-fetch). */
export const WEB_FETCH_PLUGIN_UUID = '00000000-0000-4000-8000-0000000013';

const RESOLVE_TIMEOUT_MS = 5_000; // control-plane resolution cache window
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

export interface WebFetchProvider {
  id: string;
  name: string;
  endpoint: string;
}

/** Internal record — carries lastSeenAt for the online check. */
type ProviderRecord = WebFetchProvider & { lastSeenAt: string | null };

let cachedDefaultProvider: { record: ProviderRecord | null; cachedAt: number } | null = null;

function parseCapabilities(raw: string | null | undefined): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as unknown[]).filter((c): c is string => typeof c === 'string') : [];
  } catch {
    return [];
  }
}

function toRecord(row: typeof schema.plugins.$inferSelect): ProviderRecord {
  return {
    id: row.id,
    name: row.name,
    endpoint: row.endpoint,
    lastSeenAt: row.lastSeenAt,
  };
}

function isOnline(record: ProviderRecord, now: number): boolean {
  if (!record.lastSeenAt) return false;
  const last = Date.parse(record.lastSeenAt);
  if (Number.isNaN(last)) return false;
  return now - last <= ONLINE_WINDOW_MS;
}

async function findProviderById(id: string): Promise<ProviderRecord | null> {
  const row = await db.query.plugins.findFirst({ where: (plugins, { eq }) => eq(plugins.id, id) });
  if (!row || !parseCapabilities(row.capabilities).includes('webFetch')) return null;
  return toRecord(row);
}

async function findFirstWebFetchProvider(): Promise<ProviderRecord | null> {
  const rows = await db.query.plugins.findMany();
  const providers = rows.filter((r) => parseCapabilities(r.capabilities).includes('webFetch')).map(toRecord);
  if (providers.length === 0) return null;
  providers.sort((a, b) => (b.lastSeenAt ?? '').localeCompare(a.lastSeenAt ?? ''));
  return providers[0];
}

/**
 * Resolves the web-fetch plugin to use. Explicit id wins (may be offline — the
 * caller decides); otherwise the reserved built-in UUID, then any online plugin
 * advertising `webFetch`. Returns null when nothing is registered/online — the
 * geoip worker surfaces that as a status error instead of failing hard.
 */
export async function resolveWebFetchProvider(providerId?: string | null): Promise<WebFetchProvider | null> {
  if (providerId && providerId.trim()) {
    const explicit = await findProviderById(providerId.trim());
    return explicit ? { id: explicit.id, name: explicit.name, endpoint: explicit.endpoint } : null;
  }

  if (cachedDefaultProvider && Date.now() - cachedDefaultProvider.cachedAt < RESOLVE_TIMEOUT_MS) {
    const r = cachedDefaultProvider.record;
    return r ? { id: r.id, name: r.name, endpoint: r.endpoint } : null;
  }

  let record: ProviderRecord | null = null;
  const builtIn = await findProviderById(WEB_FETCH_PLUGIN_UUID);
  if (builtIn && isOnline(builtIn, Date.now())) record = builtIn;

  if (!record) {
    const any = await findFirstWebFetchProvider();
    record = any && isOnline(any, Date.now()) ? any : null;
  }

  cachedDefaultProvider = { record, cachedAt: Date.now() }; // null is cached too (briefly)
  return record ? { id: record.id, name: record.name, endpoint: record.endpoint } : null;
}

/** One axios instance per provider — the /fetch call streams a large body back. */
const httpCache = new Map<string, AxiosInstance>();
function providerHttp(provider: WebFetchProvider): AxiosInstance {
  let h = httpCache.get(provider.id);
  if (!h) {
    const apiKey = process.env.PLUGIN_API_KEY;
    // mTLS (Stage 1): pluginAxios picks the transport for this provider.
    h = pluginAxios(provider.endpoint, {
      timeout: RESOLVE_TIMEOUT_MS,
      headers: apiKey ? { 'x-plugin-api-key': apiKey } : undefined,
      maxContentLength: Infinity, // downloads are bounded by the caller's maxBytes
      maxBodyLength: Infinity,
    });
    httpCache.set(provider.id, h);
  }
  return h;
}

export interface WebFetchRequest {
  url: string;
  /** Egress proxy (scheme://[user:pass@]host:port) — empty/undefined = direct. */
  proxyUrl?: string;
  timeoutMs?: number;
  maxBytes?: number;
  extract?: 'auto' | 'tar.gz' | 'zip';
  headers?: Record<string, string>;
  /** Origin HTTP method (default GET). POST + `body` for APIs that need a request body. */
  method?: 'GET' | 'POST';
  /** JSON-serializable body sent with a POST request (the plugin serializes it as application/json). */
  body?: unknown;
}

export interface WebFetchResult {
  /** Origin HTTP status (2xx). */
  status: number;
  contentType: string;
  sizeBytes: number;
  sha256: string;
  /** Archive member name when extraction ran (undefined for plain files). */
  extractedFrom?: string;
}

/**
 * Downloads `url` through the web-fetch plugin and returns the bytes as a
 * Buffer with their content identity. The plugin streams the body back as an
 * octet-stream; metadata rides in x-webfetch-* response headers. GeoIP files
 * are <100 MiB, so buffering here is bounded by maxBytes — no temp file needed.
 */
export async function fetchViaWebFetch(
  provider: WebFetchProvider,
  req: WebFetchRequest
): Promise<{ bytes: Buffer; result: WebFetchResult }> {
  const timeoutMs = Math.min(Math.max(5_000, Number(req.timeoutMs) || 120_000), 3_600_000);
  // Generous axios margin on top of the plugin's own download timeout — large
  // files stream slowly through corporate proxies.
  let res;
  try {
    res = await providerHttp(provider).post<Buffer>(
      '/fetch',
      { ...req, proxyUrl: req.proxyUrl || undefined },
      { responseType: 'arraybuffer', timeout: timeoutMs + 60_000 }
    );
  } catch (e) {
    // Surface the plugin's own error message — axios' default ("Request failed
    // with status code N") hides what actually went wrong on the egress side.
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
    } catch { /* non-JSON body — keep axios' message */ }
    throw new Error(`web-fetch plugin failed${detail || ` (${err.message})`}`);
  }

  const bytes = Buffer.from(res.data as unknown as ArrayBuffer);
  // Content identity — computed here (the API is the metadata owner).
  const sha256 = createHash('sha256').update(bytes).digest('hex');
  return {
    bytes,
    result: {
      status: Number(res.headers['x-webfetch-status'] ?? res.status),
      contentType: String(res.headers['x-webfetch-content-type'] ?? 'application/octet-stream'),
      sizeBytes: bytes.length,
      sha256,
      extractedFrom: res.headers['x-webfetch-extracted-from'] ? String(res.headers['x-webfetch-extracted-from']) : undefined,
    },
  };
}
