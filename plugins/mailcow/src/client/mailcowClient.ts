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

/**
 * One GET against `/api/v1/get/...` that returns a single OBJECT (not an array).
 * mailcow's `fail2ban('get')` and `dkim('details', …)` both answer with one object;
 * a non-2xx status throws, but a 200 with `{}` / empty body yields `{}`.
 */
async function getObject(client: AxiosInstance, path: string): Promise<Record<string, unknown>> {
  const res = await client.get(path);
  if (res.status < 200 || res.status >= 300) {
    throw new MailcowApiError(`mailcow GET ${path} returned HTTP ${res.status}`, res.status);
  }
  return res.data && typeof res.data === 'object' && !Array.isArray(res.data) ? (res.data as Record<string, unknown>) : {};
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

// --- Security ------------------------------------------------------------------
// fail2ban + DKIM are the two security-relevant surfaces reachable through the
// JSON API. SPF/DMARC live only in mailcow's live DNS diagnostics (an ajax
// endpoint, not part of /api/v1), so they are intentionally NOT checked here.

/** One active/permanent ban entry from `fail2ban('get')`. */
export interface MailcowBanEntry {
  network: string; // CIDR or host as banned
  ip?: string; // first address of the network
}

/** Normalized fail2ban state from GET /api/v1/get/fail2ban. */
export interface MailcowFail2ban {
  /** Networks currently banned (active_bans). */
  activeBans: MailcowBanEntry[];
  /** Permanently banned networks (perm_bans). */
  permBans: MailcowBanEntry[];
  /** Manually denylisted networks/hosts (blacklist, newline-separated string). */
  blacklist: string[];
  /** Max failed attempts before a ban. */
  maxAttempts?: number;
  /** Retry window in seconds for the attempt count. */
  retryWindowSeconds?: number;
}

/**
 * GET /api/v1/get/fail2ban — fail2ban options + current ban lists.
 * NOTE: mailcow's `fail2ban('get')` returns PHP `false` (→ empty body) for any
 * non-admin API key, so a read-only key yields `{}` here; callers must treat an
 * all-empty result as "not verifiable", not as "no bans".
 */
export async function getFail2ban(client: AxiosInstance): Promise<MailcowFail2ban> {
  const raw = await getObject(client, '/api/v1/get/fail2ban');

  const toEntries = (v: unknown): MailcowBanEntry[] => {
    if (!Array.isArray(v)) return [];
    return v
      .filter((e) => e && typeof e === 'object')
      .map((e) => {
        const o = e as Record<string, unknown>;
        const network = typeof o['network'] === 'string' ? o['network'] : '';
        if (!network) return null;
        const ip = typeof o['ip'] === 'string' && o['ip'] ? o['ip'] : undefined;
        return { network, ...(ip ? { ip } : {}) };
      })
      .filter((e): e is MailcowBanEntry => e !== null);
  };

  const blacklistRaw = typeof raw['blacklist'] === 'string' ? (raw['blacklist'] as string) : '';
  const num = (v: unknown): number | undefined => {
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
    return undefined;
  };

  return {
    activeBans: toEntries(raw['active_bans']),
    permBans: toEntries(raw['perm_bans']),
    blacklist: blacklistRaw.split(/\r?\n/).map((s) => s.trim()).filter(Boolean),
    maxAttempts: num(raw['max_attempts']),
    retryWindowSeconds: num(raw['retry_window']),
  };
}

/** Normalized DKIM key state from GET /api/v1/get/dkim/<domain>. */
export interface MailcowDkim {
  /** True when the domain has a generated/imported DKIM public key. */
  present: boolean;
  /** Estimated key length in bits as reported by mailcow ("1024"…"8192"). */
  length?: string;
  /** The selector (e.g. "dkim") — part of the DNS record name. */
  selector?: string;
}

/**
 * GET /api/v1/get/dkim/<domain> — DKIM key details for one domain. Returns an
 * empty object when the domain has no key (or the caller lacks access). The
 * public key itself is deliberately NOT surfaced here — only presence + length,
 * which is all a security check needs and keeps secrets out of metrics.
 */
export async function getDkimDetails(client: AxiosInstance, domain: string): Promise<MailcowDkim> {
  const raw = await getObject(client, `/api/v1/get/dkim/${encodeURIComponent(domain)}`);
  const pubkey = typeof raw['pubkey'] === 'string' ? (raw['pubkey'] as string) : '';
  if (!pubkey) return { present: false };
  const length = typeof raw['length'] === 'string' && raw['length'] ? raw['length'] : undefined;
  const selector = typeof raw['dkim_selector'] === 'string' && raw['dkim_selector'] ? (raw['dkim_selector'] as string) : undefined;
  return { present: true, ...(length ? { length } : {}), ...(selector ? { selector } : {}) };
}

// --- Security logs & stats -----------------------------------------------------
// The mailcow JSON API exposes three more security-relevant surfaces than the
// fail2ban/DKIM pair above (verified live against a 2026-11b instance):
//   - GET /api/v1/get/logs/netfilter — the netfilter jail log: brute-force
//     pre-ban warnings, failed mail auth attempts and non-SMTP port scans.
//     Append-only ring buffer (newest ~1000 entries), epoch-seconds `time`.
//   - GET /api/v1/get/logs/rspamd-stats — rspamd version/uptime + cumulative
//     scan counters incl. per-action tallies (reject, soft reject, greylist…).
//   - GET /api/v1/get/logs/sasl — recent mail login activity: service, username
//     and source IP (`real_rip`) per event (newest ~1000). No success/failure
//     flag — failures are captured in the netfilter log instead.

/** One raw entry from GET /api/v1/get/logs/netfilter. */
export interface MailcowNetfilterLogEntry {
  /** Unix epoch SECONDS (UTC) when the event was logged. */
  time: number;
  /** syslog-style priority as reported by mailcow ('warn' | 'info'). */
  priority: string;
  /** Human-readable log line (the only per-event detail the API carries). */
  message: string;
}

/**
 * GET /api/v1/get/logs/netfilter — newest ~1000 netfilter jail log entries.
 * Returns [] when the instance has no logged events yet. Entries without a
 * usable timestamp or message are dropped (they cannot be deduped/ordered).
 */
export async function getNetfilterLogs(client: AxiosInstance): Promise<MailcowNetfilterLogEntry[]> {
  const rows = await getRows(client, '/api/v1/get/logs/netfilter');
  return rows
    .map((r) => {
      const time = typeof r['time'] === 'number' ? r['time'] : Number(r['time']);
      const message = typeof r['message'] === 'string' ? r['message'] : '';
      if (!Number.isFinite(time) || time <= 0 || message.trim() === '') return null;
      const priority = typeof r['priority'] === 'string' && r['priority'].trim() !== '' ? (r['priority'] as string).trim().toLowerCase() : 'info';
      return { time, priority, message } as MailcowNetfilterLogEntry;
    })
    .filter((e): e is MailcowNetfilterLogEntry => e !== null);
}

/** Normalized rspamd stats from GET /api/v1/get/logs/rspamd-stats. */
export interface MailcowRspamdStats {
  /** Rspamd version string (e.g. "4.2.3"). Absent when the endpoint is empty. */
  version?: string;
  /** Seconds since rspamd started. */
  uptimeSec?: number;
  /** Total messages scanned since start. */
  scanned?: number;
  /** Messages learned into the bayes database. */
  learned?: number;
  /** Cumulative per-action tallies (reject, soft reject, greylist, …). */
  actions: Record<string, number>;
}

/**
 * GET /api/v1/get/logs/rspamd-stats — rspamd version + cumulative counters.
 * Returns `{ actions: {} }` when the endpoint answers empty (instances without
 * the stats endpoint) so callers can treat it as "not verifiable".
 */
export async function getRspamdStats(client: AxiosInstance): Promise<MailcowRspamdStats> {
  const raw = await getObject(client, '/api/v1/get/logs/rspamd-stats');
  const num = (v: unknown): number | undefined => {
    if (typeof v === 'number' && Number.isFinite(v)) return v;
    if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
    return undefined;
  };
  const actionsRaw = raw['actions'];
  const actions: Record<string, number> = {};
  if (actionsRaw && typeof actionsRaw === 'object' && !Array.isArray(actionsRaw)) {
    for (const [k, v] of Object.entries(actionsRaw as Record<string, unknown>)) {
      const n = num(v);
      if (n !== undefined) actions[k] = n;
    }
  }
  return {
    ...(typeof raw['version'] === 'string' && (raw['version'] as string).trim() !== '' ? { version: (raw['version'] as string).trim() } : {}),
    ...(num(raw['uptime']) !== undefined ? { uptimeSec: num(raw['uptime']) } : {}),
    ...(num(raw['scanned']) !== undefined ? { scanned: num(raw['scanned']) } : {}),
    ...(num(raw['learned']) !== undefined ? { learned: num(raw['learned']) } : {}),
    actions,
  };
}

/** One raw entry from GET /api/v1/get/logs/sasl (recent mail login activity). */
export interface MailcowSaslLogin {
  /** Service the login targeted ('imap', 'smtp', …). */
  service: string;
  /** Account that authenticated. */
  username: string;
  /** Source IP of the connection (`real_rip`). */
  ip: string;
  /** Whether an app password was used (0/1 in mailcow's rows). */
  appPassword: boolean;
}

/**
 * GET /api/v1/get/logs/sasl — newest ~1000 mail login events. Returns [] when
 * the instance has no logged logins yet. Rows without a usable source IP or
 * username are dropped (they cannot be attributed to an address/account).
 */
export async function getSaslLogins(client: AxiosInstance): Promise<MailcowSaslLogin[]> {
  const rows = await getRows(client, '/api/v1/get/logs/sasl');
  return rows
    .map((r) => {
      const ip = typeof r['real_rip'] === 'string' ? (r['real_rip'] as string).trim() : '';
      const username = typeof r['username'] === 'string' ? (r['username'] as string).trim() : '';
      if (ip === '' || username === '') return null;
      const service = typeof r['service'] === 'string' && (r['service'] as string).trim() !== '' ? (r['service'] as string).trim().toLowerCase() : 'unknown';
      const appPassword = r['app_password'] === 1 || r['app_password'] === '1' || r['app_password'] === true;
      return { service, username, ip, appPassword } as MailcowSaslLogin;
    })
    .filter((e): e is MailcowSaslLogin => e !== null);
}
