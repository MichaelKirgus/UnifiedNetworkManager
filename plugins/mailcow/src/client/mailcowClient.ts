/**
 * Mailcow REST API client (mailcow-dockerized).
 *
 * The mailcow web UI's own JSON API is addressed as `<scheme>://host/api/v1/<action>/<category>[/<object>]`
 * and authenticated with a single bearer-style key in the `X-API-Key` header. There are two key kinds:
 * read-only (GET endpoints only) and read-write (all endpoints). The caller's IP must also be on the
 * instance's API whitelist, otherwise requests are rejected with 401.
 *
 * Request-body contract (verified against data/web/json_api.php):
 *   - add    → body is the flat attribute object itself (e.g. { domain, active, ... }).
 *   - edit   → body is `{ attr: {...}, items: [...] }` — `items` names the target(s), `attr` the changes.
 *   - delete → body is a BARE JSON array of ids/names to remove (e.g. ["domain.tld"]).
 *
 * Response contract:
 *   - GET endpoints return a raw JSON ARRAY of row objects (or `{}`/`[]` when empty).
 *   - add/edit/delete return an ARRAY of result objects `{ type, msg, log? }` where `type` is one of
 *     'success' | 'danger' | 'error'. A batch can mix outcomes; we surface the first non-success.
 *
 * Appliances almost always present a self-signed TLS certificate (or run plain HTTP behind nginx), so
 * https candidates use an agent that accepts it, mirroring the OPNsense client.
 */

import axios, { AxiosInstance } from 'axios';
import { insecureHttpsAgent, resolveEndpointCandidates } from '@unm/plugin-sdk';

/** Transport choice owned by this plugin via its `transport` option. */
export type MailcowTransport = 'auto' | 'http' | 'https';

/** Configurable endpoint ports (plugin options httpsPort/httpPort, defaults 443/80). */
export interface MailcowPorts {
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80). */
  httpPort?: number;
}

/** Credentials for one mailcow instance: a single API key. */
export interface MailcowCredentials {
  apiKey: string;
}

/** Default per-request timeout. Inventory reads fan out to three GETs in parallel. */
const DEFAULT_TIMEOUT_MS = 15_000;

/** One result object from an add/edit/delete batch. */
export interface MailcowResultItem {
  type?: string;
  msg?: unknown;
  log?: unknown;
}

/** Raised when the API returns a non-2xx status or a `type: error|danger` result. */
export class MailcowApiError extends Error {
  readonly status: number | null;
  constructor(message: string, status: number | null = null) {
    super(message);
    this.name = 'MailcowApiError';
    this.status = status;
  }
}

/** True when an HTTP-level failure is a bad/missing key or IP-not-whitelisted (401). */
export function isAuthError(err: unknown): boolean {
  return err instanceof MailcowApiError && err.status === 401;
}

/**
 * Resolves the absolute base URL for a device address given the transport option — shared SDK resolver
 * (explicit scheme in the address wins, configured default ports applied, HTTPS preferred in auto mode).
 */
export function resolveBase(host: string, transport?: MailcowTransport, ports?: MailcowPorts): string {
  return resolveEndpointCandidates(host, { transport, ports })[0] ?? '';
}

/**
 * Builds a bound client for one mailcow instance. All methods receive this so credentials/transport stay
 * out of every individual call signature. `validateStatus: () => true` lets us surface non-2xx as typed
 * errors (with the status) instead of axios exceptions, and self-signed TLS is accepted via the agent.
 */
export function createClient(
  host: string,
  credentials: MailcowCredentials,
  transport?: MailcowTransport,
  ports?: MailcowPorts
): AxiosInstance {
  const base = resolveBase(host, transport, ports);
  return axios.create({
    baseURL: base,
    headers: { 'X-API-Key': credentials.apiKey },
    timeout: DEFAULT_TIMEOUT_MS,
    validateStatus: () => true,
    ...(base.startsWith('https://') ? { httpsAgent: insecureHttpsAgent() } : {}),
  });
}

/** Normalizes a raw response body into an array of row objects (GET endpoints). */
function asRows(data: unknown): Record<string, unknown>[] {
  if (Array.isArray(data)) return data.filter((r) => r && typeof r === 'object') as Record<string, unknown>[];
  // Empty GETs come back as `{}` — treat as no rows.
  return [];
}

/**
 * Inspects an add/edit/delete result array and throws a MailcowApiError when ANY entry is not `success`.
 * Returns the parsed items so callers can read per-item messages. A non-2xx HTTP status always throws.
 */
function assertSuccess(status: number, data: unknown): MailcowResultItem[] {
  const items = Array.isArray(data) ? (data as MailcowResultItem[]) : [data as MailcowResultItem];
  if (status < 200 || status >= 300) {
    // mailcow returns `{ type:'error', msg }` on some non-2xx paths; surface the message when present.
    const first = items[0] ?? {};
    const msg = typeof first.msg === 'string' ? first.msg : JSON.stringify(data ?? {});
    throw new MailcowApiError(`mailcow API returned HTTP ${status}: ${msg}`, status);
  }
  for (const it of items) {
    if (it && typeof it.type === 'string' && it.type !== 'success') {
      const msg = Array.isArray(it.msg) ? it.msg.join(', ') : String(it.msg ?? 'operation failed');
      throw new MailcowApiError(msg, status);
    }
  }
  return items;
}

/** One GET against `/api/v1/get/...` — returns the row array (empty when none). */
async function getRows(client: AxiosInstance, path: string): Promise<Record<string, unknown>[]> {
  const res = await client.get(path);
  if (res.status < 200 || res.status >= 300) {
    throw new MailcowApiError(`mailcow GET ${path} returned HTTP ${res.status}`, res.status);
  }
  return asRows(res.data);
}

/** One POST against `/api/v1/<action>/...` with the given body; asserts success. */
async function postAction(client: AxiosInstance, path: string, body: unknown): Promise<MailcowResultItem[]> {
  const res = await client.post(path, body);
  return assertSuccess(res.status, res.data);
}

// --- Domains -----------------------------------------------------------------

/** GET /api/v1/get/domain/all — every domain with live counts + quota. */
export async function getDomains(client: AxiosInstance): Promise<Record<string, unknown>[]> {
  return getRows(client, '/api/v1/get/domain/all');
}

/** POST /api/v1/add/domain — body is the flat attribute object. */
export async function addDomain(client: AxiosInstance, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/add/domain', attr);
}

/** POST /api/v1/edit/domain — body `{ items:[domain], attr }`. */
export async function editDomain(client: AxiosInstance, domain: string, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/edit/domain', { items: [domain], attr });
}

/** POST /api/v1/delete/domain — body is a bare array of domain names. */
export async function deleteDomains(client: AxiosInstance, domains: string[]): Promise<void> {
  await postAction(client, '/api/v1/delete/domain', domains);
}

// --- Mailboxes ---------------------------------------------------------------

/** GET /api/v1/get/mailbox/all — every mailbox with quota/usage + attributes. */
export async function getMailboxes(client: AxiosInstance): Promise<Record<string, unknown>[]> {
  return getRows(client, '/api/v1/get/mailbox/all');
}

/** POST /api/v1/add/mailbox — body is the flat attribute object (passwords echoed as "*" in logs). */
export async function addMailbox(client: AxiosInstance, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/add/mailbox', attr);
}

/** POST /api/v1/edit/mailbox — body `{ items:[username], attr }`. Omit password fields to keep the current one. */
export async function editMailbox(client: AxiosInstance, username: string, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/edit/mailbox', { items: [username], attr });
}

/** POST /api/v1/delete/mailbox — body is a bare array of usernames. */
export async function deleteMailboxes(client: AxiosInstance, usernames: string[]): Promise<void> {
  await postAction(client, '/api/v1/delete/mailbox', usernames);
}

// --- Aliases -----------------------------------------------------------------

/** GET /api/v1/get/alias/all — every alias with goto + catch-all flag. */
export async function getAliases(client: AxiosInstance): Promise<Record<string, unknown>[]> {
  return getRows(client, '/api/v1/get/alias/all');
}

/** POST /api/v1/add/alias — body is the flat attribute object (address, goto, ...). */
export async function addAlias(client: AxiosInstance, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/add/alias', attr);
}

/** POST /api/v1/edit/alias — body `{ items:[id], attr }`. `items` are numeric alias ids. */
export async function editAlias(client: AxiosInstance, id: number | string, attr: Record<string, unknown>): Promise<void> {
  await postAction(client, '/api/v1/edit/alias', { items: [String(id)], attr });
}

/** POST /api/v1/delete/alias — body is a bare array of numeric alias ids. */
export async function deleteAliases(client: AxiosInstance, ids: (number | string)[]): Promise<void> {
  await postAction(client, '/api/v1/delete/alias', ids.map(String));
}

// --- Status ------------------------------------------------------------------

/** GET /api/v1/get/status/version — `{ version: 'YYYY-MM' }`. Used for health + firmwareVersion. */
export async function getStatusVersion(client: AxiosInstance): Promise<string | null> {
  const res = await client.get('/api/v1/get/status/version');
  if (res.status < 200 || res.status >= 300) throw new MailcowApiError(`mailcow status returned HTTP ${res.status}`, res.status);
  const v = (res.data as Record<string, unknown> | undefined)?.['version'];
  return typeof v === 'string' ? v : null;
}
