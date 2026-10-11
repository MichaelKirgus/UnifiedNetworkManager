/**
 * Zabbix JSON-RPC API client.
 *
 * Talks to the Zabbix frontend's `api_jsonrpc.php` endpoint (default base path
 * `/zabbix`). Two auth models are supported, resolved from the bound secret:
 *   - API token (preferred, Zabbix ≥ 5.4): sent as `Authorization: Bearer <token>`;
 *     no session management needed. Secret type `apiKeyNoSecret` (field `apiKey`).
 *   - User login (legacy): `user.login` returns a session id that is passed in the
 *     request body's `auth` field until it expires. Secret type `usernamePassword`.
 *
 * Zabbix appliances frequently sit behind self-signed TLS or plain HTTP, so https
 * candidates use an agent that accepts them (mirrors the other clients).
 */

import axios, { AxiosInstance } from 'axios';
import { insecureHttpsAgent, resolveEndpointCandidates } from '@unm/plugin-sdk';

/** Transport choice owned by this plugin via its `transport` option. */
export type ZabbixTransport = 'auto' | 'http' | 'https';

/** Configurable endpoint ports (plugin options httpsPort/httpPort). */
export interface ZabbixPorts {
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80). */
  httpPort?: number;
}

/** Credentials for one Zabbix frontend: token OR user/password. */
export interface ZabbixCredentials {
  /** API token (preferred). When present, username/password are ignored. */
  token?: string;
  /** Legacy login — used only when no token is bound. */
  username?: string;
  password?: string;
}

/** Default per-request timeout. Inventory reads fan out to several RPCs in parallel. */
const DEFAULT_TIMEOUT_MS = 15_000;

/** Raised for JSON-RPC errors (bad auth, duplicate host, …) — a HARD failure by contract. */
export class ZabbixApiError extends Error {
  readonly code: number | null;
  constructor(message: string, code: number | null = null) {
    super(message);
    this.name = 'ZabbixApiError';
    this.code = code;
  }
}

/** True when the error is an auth failure (bad token / bad credentials). */
export function isAuthError(err: unknown): boolean {
  if (!(err instanceof ZabbixApiError)) return false;
  // JSON-RPC auth errors carry code -32602 with "re-login"/"token" in the data,
  // or a plain "Session terminated" / "Not authorised" message.
  return /authoris|authoriz|login|session|token/i.test(err.message);
}

/**
 * Resolves the absolute API URL for a device address given transport + base path —
 * shared SDK resolver (explicit scheme in the address wins, configured default ports
 * applied, HTTPS preferred in auto mode). The JSON-RPC endpoint is `<base>/api_jsonrpc.php`.
 */
export function resolveApiUrl(host: string, transport?: ZabbixTransport, ports?: ZabbixPorts, basePath = '/zabbix'): string {
  const base = resolveEndpointCandidates(host, { transport, ports })[0] ?? '';
  if (!base) return '';
  const path = basePath.startsWith('/') ? basePath : `/${basePath}`;
  return `${base.replace(/\/$/, '')}${path}/api_jsonrpc.php`;
}

/** One JSON-RPC response envelope. */
interface RpcEnvelope {
  jsonrpc?: string;
  id?: number | string;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

/**
 * A bound client for one Zabbix frontend. All methods receive this so credentials/
 * transport stay out of every individual call signature. `validateStatus: () => true`
 * lets us surface non-2xx as typed errors (with the status) instead of axios exceptions.
 */
export class ZabbixClient {
  private readonly http: AxiosInstance;
  private readonly apiUrl: string;
  private readonly creds: ZabbixCredentials;
  /** Session id from user.login — only used in token-less mode. */
  private sessionId: string | null = null;
  private loginPromise: Promise<void> | null = null;

  constructor(host: string, credentials: ZabbixCredentials, transport?: ZabbixTransport, ports?: ZabbixPorts, basePath = '/zabbix', timeoutMs = DEFAULT_TIMEOUT_MS) {
    this.apiUrl = resolveApiUrl(host, transport, ports, basePath);
    this.creds = credentials;
    this.http = axios.create({
      baseURL: this.apiUrl,
      timeout: timeoutMs,
      headers: { 'Content-Type': 'application/json-rpc' },
      validateStatus: () => true,
      ...(this.apiUrl.startsWith('https://') ? { httpsAgent: insecureHttpsAgent() } : {}),
    });
  }

  /** The resolved API URL (for diagnostics). */
  get url(): string {
    return this.apiUrl;
  }

  /** True when the client authenticates with an API token (no session needed). */
  get usesToken(): boolean {
    return !!this.creds.token;
  }

  private async ensureLogin(): Promise<void> {
    if (this.usesToken || this.sessionId) return;
    if (!this.loginPromise) {
      this.loginPromise = (async () => {
        const user = this.creds.username ?? '';
        const password = this.creds.password ?? '';
        if (!user || !password) throw new ZabbixApiError('No API token and no username/password bound — cannot authenticate.');
        const result = await this.rawCall<string>('user.login', { user, password });
        this.sessionId = String(result);
      })();
    }
    try {
      await this.loginPromise;
    } catch (err) {
      // A failed login must not poison subsequent attempts with a cached rejection.
      this.loginPromise = null;
      throw err;
    }
  }

  /** One raw JSON-RPC round-trip. Throws ZabbixApiError on RPC errors / non-2xx. */
  private async rawCall<T>(method: string, params: unknown): Promise<T> {
    if (!this.apiUrl) throw new ZabbixApiError('Could not resolve the Zabbix API URL from the management address.');

    // apiinfo.version needs no auth; everything else does (token header or session).
    const headers: Record<string, string> = {};
    if (method !== 'apiinfo.version') {
      await this.ensureLogin();
      if (this.usesToken) headers['Authorization'] = `Bearer ${this.creds.token}`;
    }

    const body: Record<string, unknown> = { jsonrpc: '2.0', method, params, id: 1 };
    if (method !== 'apiinfo.version' && !this.usesToken && this.sessionId) body['auth'] = this.sessionId;

    let res;
    try {
      res = await this.http.post('', body, { headers });
    } catch (err) {
      // Network-level failure — rethrow as-is so isTransientTransportError() can classify it.
      throw err;
    }

    if (res.status < 200 || res.status >= 300) {
      const text = typeof res.data === 'string' ? res.data.slice(0, 300) : JSON.stringify(res.data ?? {}).slice(0, 300);
      throw new ZabbixApiError(`Zabbix API returned HTTP ${res.status}: ${text}`, null);
    }

    const env = (res.data ?? {}) as RpcEnvelope;
    if (env.error) {
      // A session expiry surfaces mid-call — drop it so the next call re-logs in.
      if (!this.usesToken && /session|authoris|authoriz/i.test(env.error.message ?? '')) this.sessionId = null;
      throw new ZabbixApiError(`${env.error.message}${typeof env.error.data === 'string' && env.error.data ? ` (${env.error.data})` : ''}`, env.error.code ?? null);
    }
    return env.result as T;
  }

  /** One authenticated JSON-RPC call. */
  async call<T>(method: string, params: unknown = {}): Promise<T> {
    return this.rawCall<T>(method, params);
  }

  // --- Convenience wrappers ---------------------------------------------------

  /** apiinfo.version — the liveness + auth-free probe (returns e.g. "7.0.5"). */
  async version(): Promise<string> {
    const v = await this.rawCall<unknown>('apiinfo.version', []);
    return typeof v === 'string' ? v : String(v ?? '');
  }

  /** host.get — every host with its status + technical/display name. */
  async getHosts(): Promise<Array<{ hostid: string; host: string; name: string; status: string }>> {
    const rows = await this.call<Record<string, unknown>[]>('host.get', {
      output: ['hostid', 'host', 'name', 'status'],
      sortfield: 'host',
    });
    return (rows ?? []).map((r) => ({
      hostid: String(r['hostid']),
      host: String(r['host'] ?? ''),
      name: String(r['name'] ?? r['host'] ?? ''),
      status: String(r['status'] ?? '0'), // '0' = enabled, '1' = disabled
    }));
  }

  /** hostinterface.get — IP interfaces of the given hosts (type 1 = IP). */
  async getHostInterfaces(hostids: string[]): Promise<Map<string, Array<{ ip: string; dns: string }>>> {
    const out = new Map<string, Array<{ ip: string; dns: string }>>();
    if (hostids.length === 0) return out;
    const rows = await this.call<Record<string, unknown>[]>('hostinterface.get', {
      hostids,
      output: ['hostid', 'ip', 'dns'],
      selectMaster: [],
    });
    for (const r of rows ?? []) {
      const ip = String(r['ip'] ?? '');
      if (!ip) continue; // DNS-only interfaces are not addressable by IP — skip in v1
      const list = out.get(String(r['hostid'])) ?? [];
      list.push({ ip, dns: String(r['dns'] ?? '') });
      out.set(String(r['hostid']), list);
    }
    return out;
  }

  /** hostgroup.get — all groups (name → id). */
  async getHostGroups(): Promise<Map<string, string>> {
    const rows = await this.call<Record<string, unknown>[]>('hostgroup.get', { output: ['groupid', 'name'] });
    const m = new Map<string, string>();
    for (const r of rows ?? []) m.set(String(r['name']), String(r['groupid']));
    return m;
  }

  /** hostgroup.create — returns the new group id. */
  async createHostGroup(name: string): Promise<string> {
    const res = await this.call<Record<string, unknown>>('hostgroup.create', [{ name }]);
    const ids = (res?.['groupids'] ?? []) as unknown[];
    return String(ids[0] ?? '');
  }

  /** template.get by exact name — id or null. */
  async findTemplate(name: string): Promise<string | null> {
    const rows = await this.call<Record<string, unknown>[]>('template.get', { output: ['templateid'], filter: { host: [name] } });
    return rows && rows.length > 0 ? String(rows[0]['templateid']) : null;
  }

  /**
   * host.create — registers a new monitored host. `interfaces` are IP interfaces
   * (type 1); the first is marked main. Returns the new host id.
   */
  async createHost(opts: {
    host: string;
    name?: string;
    status?: number;
    groupIds: string[];
    ips: string[];
    tags?: Array<{ tag: string; value?: string }>;
  }): Promise<string> {
    const interfaces = opts.ips.map((ip, i) => ({ type: 1, main: i === 0 ? 1 : 0, useip: 1, ip, dns: '', port: '10050' }));
    const params: Record<string, unknown> = {
      host: opts.host,
      name: opts.name || opts.host,
      status: opts.status ?? 0,
      groups: opts.groupIds.map((groupid) => ({ groupid })),
      ...(interfaces.length > 0 ? { interfaces } : {}),
      ...(opts.tags && opts.tags.length > 0 ? { tags: opts.tags } : {}),
    };
    const res = await this.call<Record<string, unknown>>('host.create', [params]);
    const ids = (res?.['hostids'] ?? []) as unknown[];
    return String(ids[0] ?? '');
  }

  /** host.update — changes status/technical name/display name/tags/groups of an existing host. */
  async updateHost(hostid: string, patch: { status?: number; host?: string; name?: string; tags?: Array<{ tag: string; value?: string }>; groupIds?: string[] }): Promise<void> {
    const params: Record<string, unknown> = { hostid };
    if (patch.status !== undefined) params['status'] = patch.status;
    if (patch.host !== undefined) params['host'] = patch.host; // technical name (unique in Zabbix)
    if (patch.name !== undefined) params['name'] = patch.name; // display name
    if (patch.tags) params['tags'] = patch.tags; // full replacement of the tag set
    if (patch.groupIds && patch.groupIds.length > 0) params['groups'] = patch.groupIds.map((groupid) => ({ groupid }));
    await this.call('host.update', [params]);
  }

  /** host.massupdate — replaces the IP interface set of a host. */
  async replaceInterfaces(hostid: string, ips: string[]): Promise<void> {
    const interfaces = ips.map((ip, i) => ({ type: 1, main: i === 0 ? 1 : 0, useip: 1, ip, dns: '', port: '10050' }));
    await this.call('host.massupdate', [{ hosts: [hostid], interfaces }]);
  }

  /** host.massupdate — links a template onto the given hosts. */
  async addTemplate(hostids: string[], templateId: string): Promise<void> {
    if (hostids.length === 0) return;
    await this.call('host.massupdate', [{ hosts: hostids, addTemplates: [templateId] }]);
  }

  /** host.delete — removes the given hosts. */
  async deleteHosts(hostids: string[]): Promise<void> {
    if (hostids.length === 0) return;
    await this.call('host.delete', [hostids]);
  }

  /** problem.get — active problems (newest first, capped). */
  async getProblems(limit = 50): Promise<Array<{ objectid: string; object: string; name: string; severity: number; eventid: string | null }>> {
    const params = (withEventId: boolean) => ({
      output: withEventId ? ['objectid', 'object', 'name', 'eventid'] : ['objectid', 'object', 'name'],
      // problem.get only allows sorting by eventid — "clock" is rejected.
      sortfield: 'eventid',
      sortorder: 'DESC',
      limit,
    });
    let rows: Record<string, unknown>[];
    try {
      rows = await this.call<Record<string, unknown>[]>('problem.get', params(true));
    } catch (err) {
      // `eventid` is not a valid output field on older frontends — the API rejects
      // the whole call. Retry once without it; eventid then stays null and the
      // notification dedupe key falls back to object+name.
      if (!(err instanceof ZabbixApiError) || !/output|invalid/i.test(err.message)) throw err;
      rows = await this.call<Record<string, unknown>[]>('problem.get', params(false));
    }
    return (rows ?? []).map((r) => ({
      objectid: String(r['objectid'] ?? ''),
      object: String(r['object'] ?? ''),
      name: String(r['name'] ?? ''),
      severity: Number(r['severity'] ?? 0),
      // eventid = the opening event of this problem — stable while the problem
      // persists, so it makes a good dedupe key (null on very old servers).
      eventid: r['eventid'] != null ? String(r['eventid']) : null,
    }));
  }

  /** problem.get with countOutput — total active problem count. */
  async countProblems(): Promise<number> {
    const res = await this.call<Record<string, unknown>>('problem.get', { output: ['objectid'], countOutput: true });
    return Number(res?.['count'] ?? 0);
  }

  /** host.get filtered to hosts carrying the given tag (value match when provided). */
  async getHostsByTag(tag: string, value?: string): Promise<Array<{ hostid: string; host: string; name: string; status: string }>> {
    const rows = await this.call<Record<string, unknown>[]>('host.get', {
      output: ['hostid', 'host', 'name', 'status'],
      selectTags: ['tag', 'value'],
      search: value !== undefined ? { tags: [{ tag, value }] } : { tags: [{ tag }] },
    });
    return (rows ?? []).map((r) => ({
      hostid: String(r['hostid']),
      host: String(r['host'] ?? ''),
      name: String(r['name'] ?? r['host'] ?? ''),
      status: String(r['status'] ?? '0'),
    }));
  }

  /**
   * host.get — every host carrying the marker tag, WITH its full tag list. The
   * sync engine uses this to resolve ownership by the marker's VALUE (the UNM
   * host id) and to find legacy hosts still on the old constant value.
   */
  async getManagedHosts(tag: string): Promise<Array<{ hostid: string; host: string; name: string; status: string; tags: Array<{ tag: string; value?: string }> }>> {
    const rows = await this.call<Record<string, unknown>[]>('host.get', {
      output: ['hostid', 'host', 'name', 'status'],
      selectTags: ['tag', 'value'],
      search: { tags: [{ tag }] },
    });
    return (rows ?? []).map((r) => ({
      hostid: String(r['hostid']),
      host: String(r['host'] ?? ''),
      name: String(r['name'] ?? r['host'] ?? ''),
      status: String(r['status'] ?? '0'),
      tags: ((r['tags'] as Array<Record<string, unknown>> | undefined) ?? []).map((t) => ({ tag: String(t?.['tag'] ?? ''), value: t?.['value'] != null ? String(t['value']) : undefined })),
    }));
  }

  /** host.get — the full tag list of one host (for merge-preserving updates). */
  async getHostTags(hostid: string): Promise<Array<{ tag: string; value?: string }>> {
    const rows = await this.call<Record<string, unknown>[]>('host.get', { output: ['tags'], hostids: [hostid], selectTags: ['tag', 'value'] });
    return ((rows?.[0]?.['tags'] as Array<Record<string, unknown>> | undefined) ?? []).map((t) => ({ tag: String(t?.['tag'] ?? ''), value: t?.['value'] != null ? String(t['value']) : undefined }));
  }
}

/** Builds a bound client for one Zabbix frontend. */
export function createZabbixClient(
  host: string,
  credentials: ZabbixCredentials,
  transport?: ZabbixTransport,
  ports?: ZabbixPorts,
  basePath = '/zabbix',
  timeoutMs = DEFAULT_TIMEOUT_MS
): ZabbixClient {
  return new ZabbixClient(host, credentials, transport, ports, basePath, timeoutMs);
}
