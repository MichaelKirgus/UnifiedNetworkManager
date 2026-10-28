/**
 * Typed HTTP client for the netcup SCP (Server Control Panel) REST API.
 *
 * Contract facts (verified against the live spec, version 2026.1020.160222):
 *   - Base URL: https://servercontrolpanel.de/scp-core — all endpoints below it
 *     are /api/... (e.g. <base>/api/v1/servers). UNM device addresses are bare
 *     network targets (no scheme, no path), so the device's managementAddress is
 *     a host like `servercontrolpanel.de`; normalizeBaseUrl() upgrades it to
 *     https://<host>/scp-core.
 *   - Auth: OAuth2 Bearer tokens from netcup's Keycloak realm "scp". Two modes,
 *     both resolved in this client: a STATIC access token (used as-is, lapses in
 *     ~30 days) or a REFRESH token (exchanged on demand for fresh access tokens,
 *     cached in-process; stays valid while used at least once every ~30 days).
 *     See docs/README.md.
 *   - PATCH /api/v1/servers/{id} requires Content-Type application/merge-patch+json
 *     and accepts ONLY ONE attribute per request; stateOption is a QUERY param.
 *   - Most mutating endpoints answer 202 with a TaskInfo (async work) — callers
 *     verify via task polling or re-reading the resource.
 */

import axios, { AxiosInstance } from 'axios';
import { insecureHttpsAgent } from '@unm/plugin-sdk';

// --- Errors -------------------------------------------------------------------

/** The SCP API answered with an error status (4xx/5xx) — a FINAL failure. */
export class ScpApiError extends Error {
  readonly status: number;
  /** Machine code from the ResponseError body (e.g. "error.not.supported"); '' when absent. */
  readonly code: string;

  constructor(status: number, message: string, code = '') {
    super(message);
    this.name = 'ScpApiError';
    this.status = status;
    this.code = code;
  }
}

/** True for auth failures (bad/expired token) — surfaced as a critical health. */
export function isAuthError(err: unknown): boolean {
  if (!(err instanceof ScpApiError)) return false;
  if (err.status === 401 || err.status === 403) return true;
  return /unauthor|forbidden|invalid.*token|token.*invalid/i.test(`${err.code} ${err.message}`);
}

// --- Wire types (subset of the SCP OpenAPI spec, flattened for plugin use) -----

export type ServerState = 'NOSTATE' | 'RUNNING' | 'BLOCKED' | 'PAUSED' | 'SHUTDOWN' | 'SHUTOFF' | 'CRASHED' | 'PMSUSPENDED' | 'DISK_SNAPSHOT';
export type TaskState = 'PENDING' | 'RUNNING' | 'FINISHED' | 'ERROR' | 'WAITING_FOR_CANCEL' | 'CANCELED' | 'ROLLBACK';

/** Row of GET /api/v1/servers (the list endpoint — no live info). */
export interface ScpServerMinimal {
  id: number;
  name: string;
  hostname?: string | null;
  nickname?: string | null;
  disabled?: boolean;
}

/** Live-info block of GET /api/v1/servers/{id}. */
export interface ScpServerLiveInfo {
  state?: ServerState;
  autostart?: boolean;
  uefi?: boolean;
  bootorder?: Array<'HDD' | 'CDROM' | 'NETWORK'>;
  osOptimization?: string | null;
  keyboardLayout?: string | null;
  backupTime?: string | null;
  sockets?: number | null;
  coresPerSocket?: number | null;
  interfaces?: ScpInterface[];
  disks?: Record<string, unknown>[];
  uptimeInSeconds?: number | null;
  currentServerMemoryInMiB?: number | null;
  maxServerMemoryInMiB?: number | null;
  cpuCount?: number | null;
  cpuMaxCount?: number | null;
  machineType?: string | null;
}

/** Full server object (list fields + optional live info). */
export interface ScpServer extends ScpServerMinimal {
  serverLiveInfo?: ScpServerLiveInfo | null;
  ipv4Addresses?: ScpIpv4[];
  ipv6Addresses?: ScpIpv6[];
  site?: { id: number; city: string } | null;
  exportCount?: number;
  maxCpuCount?: number;
  disksAvailableSpaceInMiB?: number | null;
  rescueSystemActive?: boolean;
  snapshotAllowed?: boolean;
}

export interface ScpIpv4 { id: number; ip: string; netmask?: string; gateway?: string | null; rdns?: string | null }
export interface ScpIpv6 { id: number; networkPrefix: string; networkPrefixLength?: number; gateway?: string | null; rdns?: string | null }

/** Interface row (GET /servers/{id}/interfaces, loadRdns=true by default). */
export interface ScpInterface {
  mac: string;
  driver?: string;
  speedInMBits?: number | null;
  ipv4Addresses?: ScpIpv4[];
  ipv6Addresses?: ScpIpv6[];
}

// --- Firewall -------------------------------------------------------------------

export type FirewallAction = 'ACCEPT' | 'DROP';
export type FirewallProtocol = 'TCP' | 'UDP' | 'ICMP' | 'ICMPv6';
export type FirewallRuleDirection = 'INGRESS' | 'EGRESS';
export type ImplicitRule = 'ACCEPT_ALL' | 'DROP_ALL';

/** One rule of a firewall policy (the save shape — no position/counter fields). */
export interface ScpFirewallRule {
  description?: string | null;
  direction: FirewallRuleDirection;
  protocol: FirewallProtocol;
  action: FirewallAction;
  /** IP/CIDR list; empty/null = any. */
  sources?: string[] | null;
  sourcePorts?: string | null;
  destinations?: string[] | null;
  destinationPorts?: string | null;
}

export interface ScpFirewallPolicy {
  id: number;
  name: string;
  description?: string | null;
  rules: ScpFirewallRule[];
}

/** GET /servers/{id}/interfaces/{mac}/firewall. */
export interface ScpServerFirewall {
  copiedPolicies: (number | { id: number })[];
  userPolicies: (number | { id: number })[];
  ingressImplicitRule?: ImplicitRule;
  egressImplicitRule?: ImplicitRule;
  consistent?: boolean;
  active?: boolean;
}

// --- Snapshots / rescue / ISO / tasks ---------------------------------------------

export interface ScpSnapshot {
  uuid: string;
  name: string;
  description?: string | null;
  disks?: string[];
  creationTime?: string | null;
  state?: ServerState;
  online?: boolean;
  exported?: boolean;
}

export interface ScpRescueStatus { active: boolean; password?: string | null }

export interface ScpIsoImage { id: number; name: string; description?: string | null; architecture?: Record<string, unknown> | null }

export interface ScpTaskInfo {
  uuid: string;
  name?: string;
  state: TaskState;
  startedAt?: string | null;
  finishedAt?: string | null;
  executingUser?: { id: number; username?: string } | null;
  taskProgress?: { expectedFinishedAt?: string | null; progressInPercent?: number | null };
  message?: string | null;
  onRollback?: boolean;
  responseError?: { code?: string; message?: string } | null;
}

// --- Client -----------------------------------------------------------------------

export interface ScpClientOptions {
  /** API base URL (e.g. https://servercontrolpanel.de/scp-core) or a bare host. */
  baseUrl: string;
  /** Static OAuth2 access (Bearer) token — used as-is until it lapses (~30 days). */
  token?: string;
  /** OAuth2 refresh token (Keycloak realm "scp") — exchanged for fresh access
   *  tokens on demand and cached in-process. Preferred over a static token. */
  refreshToken?: string;
  timeoutMs?: number;
  /** How long BEFORE the access token's expiry we proactively re-exchange it
   *  (seconds; default 60 — covers clock skew + in-flight calls). 0 = refresh
   *  only when actually expired. */
  refreshWindowSec?: number;
}

/** The SCP API lives under this path on the panel host (all endpoints are <base>/api/...). */
export const SCP_CORE_PATH = '/scp-core';

/**
 * Normalizes managementAddress → API base URL.
 *
 * UNM device addresses are bare network targets — no scheme, no path (the API's
 * address validation rejects both) — so in practice a host like
 * `servercontrolpanel.de` lands here: we add https:// and append /scp-core.
 * Full URLs still work (e.g. local mocks): an existing non-root path is kept as-is,
 * trailing slashes are stripped.
 */
export function normalizeBaseUrl(managementAddress: string): string {
  let u = managementAddress.trim();
  if (!u) return '';
  if (!/^https?:\/\//i.test(u)) u = `https://${u}`;
  try {
    const parsed = new URL(u);
    let path = parsed.pathname.replace(/\/+$/, '');
    if (path === '') path = SCP_CORE_PATH; // bare host → the standard SCP API base
    return `${parsed.protocol}//${parsed.host}${path}`;
  } catch {
    return '';
  }
}

// --- OAuth2 refresh-token support ---------------------------------------------------
//
// The realm "scp" is a public client (no client secret): netcup's own CLI
// authenticates with client_id "scp" + scope "offline_access openid". A bound
// refresh token is exchanged for short-lived access tokens here and cached in
// process memory — the plugin container holds no credential state on disk.

export const SCP_OAUTH_CLIENT_ID = 'scp';
export const SCP_OAUTH_SCOPE = 'offline_access openid';

/** Token endpoint for a given API base — same host, Keycloak realm path. */
export function tokenEndpointOf(baseUrl: string): string {
  try {
    const u = new URL(baseUrl);
    return `${u.protocol}//${u.host}/realms/scp/protocol/openid-connect/token`;
  } catch {
    return '';
  }
}

interface ScpTokenResponse {
  access_token?: string;
  expires_in?: number;
  refresh_token?: string; // rotated by Keycloak — intentionally NOT persisted (see exchangeRefreshToken)
  token_type?: string;
}

/** In-process access-token cache: one entry per bound refresh token. */
const tokenCache = new Map<string, { accessToken: string; expiresAt: number }>();
const TOKEN_CACHE_MAX = 32;
/** Default proactive-refresh margin (seconds) when the plugin option is unset. */
export const DEFAULT_REFRESH_WINDOW_SEC = 60;

function cacheSet(refreshToken: string, accessToken: string, expiresInSec: number, refreshWindowMs: number): void {
  if (tokenCache.size >= TOKEN_CACHE_MAX) tokenCache.delete(tokenCache.keys().next().value as string); // evict oldest
  const ttlMs = Math.max(expiresInSec * 1000 - refreshWindowMs, 5_000);
  tokenCache.set(refreshToken, { accessToken, expiresAt: Date.now() + ttlMs });
}

/**
 * Exchanges a refresh token for a fresh access token (grant_type=refresh_token).
 * Keycloak rotates the refresh token in the response; we deliberately keep using
 * the ORIGINAL one — netcup's own CLI does exactly this and the realm tolerates it.
 */
export async function exchangeRefreshToken(tokenEndpoint: string, refreshToken: string, timeoutMs: number): Promise<ScpTokenResponse> {
  const body = new URLSearchParams({ grant_type: 'refresh_token', client_id: SCP_OAUTH_CLIENT_ID, refresh_token: refreshToken }).toString();
  const resp = await axios.post(tokenEndpoint, body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    timeout: timeoutMs,
    validateStatus: () => true,
    httpsAgent: insecureHttpsAgent(),
  });
  if (resp.status < 200 || resp.status >= 300) {
    const data = resp.data;
    let code = '';
    let message = typeof data === 'string' ? data : JSON.stringify(data ?? `HTTP ${resp.status}`);
    if (data && typeof data === 'object') {
      if (typeof data['error'] === 'string') code = data['error'];
      if (typeof data['error_description'] === 'string') message = data['error_description'];
    }
    throw new ScpApiError(resp.status, `SCP token refresh failed: ${message} (${resp.status})`, code);
  }
  return resp.data as ScpTokenResponse;
}

export class ScpClient {
  private http: AxiosInstance;
  readonly baseUrl: string;
  /** Static Bearer token (apiKeyNoSecret secret) — used verbatim when set. */
  private staticToken?: string;
  /** Refresh token (scpRefreshToken secret) — exchanged on demand when no static token is bound. */
  private refreshToken?: string;
  private tokenEndpoint: string;
  private timeoutMs: number;
  /** Proactive-refresh margin before the access token's expiry (ms). */
  private refreshWindowMs: number;

  constructor(opts: ScpClientOptions) {
    this.baseUrl = normalizeBaseUrl(opts.baseUrl);
    if (!this.baseUrl) throw new ScpApiError(0, 'Invalid SCP base URL');
    const token = typeof opts.token === 'string' ? opts.token.trim() : '';
    const refreshToken = typeof opts.refreshToken === 'string' ? opts.refreshToken.trim() : '';
    if (!token && !refreshToken) throw new ScpApiError(0, 'Missing SCP credential (access or refresh token)');
    this.staticToken = token || undefined;
    this.refreshToken = refreshToken || undefined;
    this.tokenEndpoint = tokenEndpointOf(this.baseUrl);
    this.timeoutMs = opts.timeoutMs ?? 15_000;
    const windowSec = typeof opts.refreshWindowSec === 'number' && Number.isFinite(opts.refreshWindowSec) ? Math.max(0, opts.refreshWindowSec) : DEFAULT_REFRESH_WINDOW_SEC;
    this.refreshWindowMs = windowSec * 1000;
    this.http = axios.create({
      baseURL: this.baseUrl,
      timeout: this.timeoutMs,
      validateStatus: () => true, // we classify statuses ourselves (2xx vs error body)
      httpsAgent: insecureHttpsAgent(),
    });
  }

  /** Resolves the Authorization header — static token as-is; refresh token via cache/exchange. */
  private async resolveAuth(forceRefresh = false): Promise<string> {
    if (this.staticToken) return `Bearer ${this.staticToken}`;
    const rt = this.refreshToken!;
    if (!forceRefresh) {
      const hit = tokenCache.get(rt);
      if (hit && hit.expiresAt > Date.now()) return `Bearer ${hit.accessToken}`;
    } else {
      tokenCache.delete(rt); // the server rejected the cached token — force a fresh exchange
    }
    const resp = await exchangeRefreshToken(this.tokenEndpoint, rt, this.timeoutMs);
    if (typeof resp.access_token !== 'string' || resp.access_token === '') throw new ScpApiError(0, 'SCP token refresh returned no access_token');
    cacheSet(rt, resp.access_token, typeof resp.expires_in === 'number' ? resp.expires_in : 3600, this.refreshWindowMs);
    return `Bearer ${resp.access_token}`;
  }

  /** Throws ScpApiError for non-2xx; returns the parsed body otherwise.
   *  `noAuth` skips the Authorization header entirely (liveness probes) so a
   *  bad token can't be mistaken for an unreachable API. */
  private async request<T>(method: string, path: string, opts?: { body?: unknown; contentType?: string; params?: Record<string, unknown>; noAuth?: boolean }): Promise<T> {
    const headers: Record<string, string> = {};
    if (opts?.body !== undefined) headers['Content-Type'] = opts.contentType ?? 'application/json';
    if (!opts?.noAuth) headers.Authorization = await this.resolveAuth();
    const config: Record<string, unknown> = { headers };
    if (opts?.body !== undefined) config.data = opts.body;
    if (opts?.params) config.params = opts.params;
    let resp = await this.http.request({ method, url: path, ...config });
    // Refresh mode only: the cached token may have been revoked server-side — force one re-exchange + retry.
    if ((resp.status === 401 || resp.status === 403) && !this.staticToken) {
      headers.Authorization = await this.resolveAuth(true);
      resp = await this.http.request({ method, url: path, ...config });
    }
    if (resp.status >= 200 && resp.status < 300) return resp.data as T;
    // Error body is usually {code, message} — keep both for diagnostics.
    const data = resp.data;
    let code = '';
    let message = typeof data === 'string' ? data : JSON.stringify(data ?? `HTTP ${resp.status}`);
    if (data && typeof data === 'object') {
      if (typeof data['code'] === 'string') code = data['code'];
      if (typeof data['message'] === 'string') message = data['message'];
    }
    throw new ScpApiError(resp.status, `${message} (${resp.status})`, code);
  }

  // --- Misc -----------------------------------------------------------------

  /** Liveness probe — no auth required (and none sent). Resolves "OK". */
  async ping(): Promise<string> {
    const resp = await this.request<string>('GET', '/api/ping', { noAuth: true });
    return typeof resp === 'string' ? resp : JSON.stringify(resp);
  }

  // --- Servers -----------------------------------------------------------------

  listServers(): Promise<ScpServerMinimal[]> {
    return this.request('GET', '/api/v1/servers');
  }

  getServer(serverId: number): Promise<ScpServer> {
    return this.request('GET', `/api/v1/servers/${serverId}`, { params: { loadServerLiveInfo: true } });
  }

  /**
   * CPU metrics time series — GET /servers/{id}/metrics/cpu?hours=N.
   * Shape (verified live): `{ "<ISO-8601 minute>": { "CPU0": <value>, ... } }` —
   * one point per MINUTE, one entry per vCPU. The value is a RATE in ns of CPU
   * time consumed per wall-clock second (cgroup-style accounting; 1e9 = that
   * core at 100%) — the same rate family as disk (IOPS) and network (B/s).
   */
  getServerCpuMetrics(serverId: number, hours?: number): Promise<Record<string, Record<string, number>>> {
    const params: Record<string, unknown> = {};
    if (typeof hours === 'number') params['hours'] = hours;
    return this.request('GET', `/api/v1/servers/${serverId}/metrics/cpu`, { params });
  }

  /**
   * Power control. ONE attribute per PATCH (API constraint); stateOption is a
   * query param — valid values: ON → POWERCYCLE|RESET, OFF → POWEROFF.
   * SUSPENDED freezes the guest's RAM state; resume = plain ON.
   */
  patchServerState(serverId: number, state: 'ON' | 'OFF' | 'SUSPENDED', stateOption?: string): Promise<unknown> {
    const params: Record<string, unknown> = {};
    if (stateOption) params['stateOption'] = stateOption;
    return this.request('PATCH', `/api/v1/servers/${serverId}`, { body: { state }, contentType: 'application/merge-patch+json', params });
  }

  patchServerHostname(serverId: number, hostname: string): Promise<unknown> {
    return this.request('PATCH', `/api/v1/servers/${serverId}`, { body: { hostname }, contentType: 'application/merge-patch+json' });
  }

  patchServerNickname(serverId: number, nickname: string): Promise<unknown> {
    return this.request('PATCH', `/api/v1/servers/${serverId}`, { body: { nickname }, contentType: 'application/merge-patch+json' });
  }

  /**
   * Generic single-attribute merge-patch (API constraint: exactly ONE attribute
   * per request). Body is one of {autostart} | {uefi} | {bootorder} |
   * {os_optimization} | {keyboardLayout}.
   */
  patchServerAttribute(serverId: number, attr: Record<string, unknown>): Promise<unknown> {
    return this.request('PATCH', `/api/v1/servers/${serverId}`, { body: attr, contentType: 'application/merge-patch+json' });
  }

  // --- Interfaces / networking ---------------------------------------------------

  getInterfaces(serverId: number, loadRdns = true): Promise<ScpInterface[]> {
    return this.request('GET', `/api/v1/servers/${serverId}/interfaces`, { params: { loadRdns } });
  }

  setRdnsIpv4(ip: string, rdns: string): Promise<unknown> {
    return this.request('POST', '/api/v1/rdns/ipv4', { body: { ip, rdns } });
  }

  deleteRdnsIpv4(ip: string): Promise<void> {
    return this.request('DELETE', `/api/v1/rdns/ipv4/${encodeURIComponent(ip)}`);
  }

  getRdnsIpv4(ip: string): Promise<{ rdns?: string | null }> {
    return this.request('GET', `/api/v1/rdns/ipv4/${encodeURIComponent(ip)}`);
  }

  setRdnsIpv6(ip: string, rdns: string): Promise<unknown> {
    return this.request('POST', '/api/v1/rdns/ipv6', { body: { ip, rdns } });
  }

  deleteRdnsIpv6(ip: string): Promise<void> {
    return this.request('DELETE', `/api/v1/rdns/ipv6/${encodeURIComponent(ip)}`);
  }

  getRdnsIpv6(ip: string): Promise<{ rdns?: string | null }> {
    return this.request('GET', `/api/v1/rdns/ipv6/${encodeURIComponent(ip)}`);
  }

  // --- Firewalls -------------------------------------------------------------------

  getInterfaceFirewall(serverId: number, mac: string): Promise<ScpServerFirewall> {
    return this.request('GET', `/api/v1/servers/${serverId}/interfaces/${mac}/firewall`);
  }

  /** Configure the policy set on one interface (the "firewall settings" write). */
  putInterfaceFirewall(serverId: number, mac: string, save: { copiedPolicies: number[]; userPolicies: number[]; active?: boolean }): Promise<ScpTaskInfo> {
    return this.request('PUT', `/api/v1/servers/${serverId}/interfaces/${mac}/firewall`, { body: save });
  }

  reapplyInterfaceFirewall(serverId: number, mac: string): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/interfaces/${mac}/firewall:reapply`);
  }

  listFirewallPolicies(userId: number): Promise<ScpFirewallPolicy[]> {
    return this.request('GET', `/api/v1/users/${userId}/firewall-policies`, { params: { limit: 200 } });
  }

  createFirewallPolicy(userId: number, save: { name: string; description?: string; rules: ScpFirewallRule[] }): Promise<ScpFirewallPolicy> {
    return this.request('POST', `/api/v1/users/${userId}/firewall-policies`, { body: save });
  }

  updateFirewallPolicy(userId: number, policyId: number, save: { name?: string; description?: string; rules?: ScpFirewallRule[] }): Promise<Record<string, unknown>> {
    return this.request('PUT', `/api/v1/users/${userId}/firewall-policies/${policyId}`, { body: save });
  }

  deleteFirewallPolicy(userId: number, policyId: number): Promise<void> {
    return this.request('DELETE', `/api/v1/users/${userId}/firewall-policies/${policyId}`);
  }

  // --- Snapshots ---------------------------------------------------------------------

  listSnapshots(serverId: number): Promise<ScpSnapshot[]> {
    return this.request('GET', `/api/v1/servers/${serverId}/snapshots`);
  }

  createSnapshot(serverId: number, body: { name: string; description?: string | null; diskName?: string | null; onlineSnapshot?: boolean }): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/snapshots`, { body });
  }

  deleteSnapshot(serverId: number, name: string): Promise<ScpTaskInfo> {
    return this.request('DELETE', `/api/v1/servers/${serverId}/snapshots/${encodeURIComponent(name)}`);
  }

  revertSnapshot(serverId: number, name: string): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/snapshots/${encodeURIComponent(name)}/revert`);
  }

  // --- Rescue system --------------------------------------------------------------------

  getRescueSystem(serverId: number): Promise<ScpRescueStatus> {
    return this.request('GET', `/api/v1/servers/${serverId}/rescuesystem`);
  }

  activateRescueSystem(serverId: number): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/rescuesystem`);
  }

  deactivateRescueSystem(serverId: number): Promise<ScpTaskInfo> {
    return this.request('DELETE', `/api/v1/servers/${serverId}/rescuesystem`);
  }

  // --- ISO / images ------------------------------------------------------------------------

  getAttachedIso(serverId: number): Promise<{ isoAttached?: boolean; iso?: string | null }> {
    return this.request('GET', `/api/v1/servers/${serverId}/iso`);
  }

  attachIso(serverId: number, body: { isoId?: number; userIsoName?: string; changeBootDeviceToCdrom?: boolean }): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/iso`, { body });
  }

  detachIso(serverId: number): Promise<void> {
    return this.request('DELETE', `/api/v1/servers/${serverId}/iso`);
  }

  listIsoImages(serverId: number): Promise<ScpIsoImage[]> {
    return this.request('GET', `/api/v1/servers/${serverId}/isoimages`);
  }

  setupImage(serverId: number, body: Record<string, unknown>): Promise<ScpTaskInfo> {
    return this.request('POST', `/api/v1/servers/${serverId}/image`, { body });
  }

  listImageFlavours(serverId: number): Promise<Record<string, unknown>[]> {
    return this.request('GET', `/api/v1/servers/${serverId}/imageflavours`);
  }

  // --- Tasks -------------------------------------------------------------------------------

  listTasks(opts?: { limit?: number; serverId?: number; state?: TaskState }): Promise<ScpTaskInfo[]> {
    const params: Record<string, unknown> = { limit: opts?.limit ?? 20 };
    if (opts?.serverId) params['serverId'] = opts.serverId;
    if (opts?.state) params['state'] = opts.state;
    return this.request('GET', '/api/v1/tasks', { params });
  }

  getTask(uuid: string): Promise<ScpTaskInfo> {
    return this.request('GET', `/api/v1/tasks/${uuid}`);
  }

  cancelTask(uuid: string): Promise<ScpTaskInfo | void> {
    return this.request('PUT', `/api/v1/tasks/${encodeURIComponent(uuid)}:cancel`);
  }

  /**
   * Resolves the internal SCP user id bound to THIS token. The API has no
   * /users/me — the community-proven way is reading executingUser off recent
   * tasks (see netcup forum "Howto REST-API nutzen"). Returns null when no
   * task carries an executing user yet.
   */
  async resolveUserId(): Promise<number | null> {
    try {
      const tasks = await this.listTasks({ limit: 10 });
      for (const t of tasks) {
        const id = t.executingUser?.id;
        if (typeof id === 'number' && id > 0) return id;
      }
    } catch { /* no tasks readable — fall through */ }
    return null;
  }
}

/** Factory used by index.ts / actions. */
export function createScpClient(opts: ScpClientOptions): ScpClient {
  return new ScpClient(opts);
}
