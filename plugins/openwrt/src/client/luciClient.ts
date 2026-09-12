/**
 * LuCI ubus-over-HTTP client for OpenWRT.
 *
 * OpenWRT has no stable REST API — but LuCI's own web UI talks to the system
 * ubus daemon over plain HTTP RPC (`POST /ubus/`), authenticated with a
 * session (stok CSRF token + SID cookie). This client reproduces exactly that
 * flow so the plugin can read the SAME data LuCI reads, without depending on
 * any CGI endpoint layout:
 *
 *   1. GET  /                          → extract the stok token from the login page
 *   2. POST /cgi-bin/luci/;stok=…/admin/login (form username/password)
 *                                        → SID cookie set (302 on success)
 *   3. POST /ubus/                     { id, method:'call', service, member, path?, params }
 *      with X-CSRF-Token: <stok> + Cookie: SID=<sid>
 *
 * Session state is per client instance; a 401/503 or ubus session error
 * triggers ONE re-login + retry. All calls are best-effort — failures come back
 * as { ok:false } and never throw (the opnsense OpnsenseApiResult contract).
 */

import axios, { AxiosInstance } from 'axios';
import https from 'https';

/** Result of one LuCI call — mirrors the opnsense client's result shape. */
export interface LuciResult<T = unknown> {
  ok: boolean;
  status: number;
  data?: T;
  error?: string;
}

const DEFAULT_TIMEOUT_MS = 8_000;
const PROBE_TIMEOUT_MS = 5_000;
/** Appliances present self-signed certs (or none at all) — never reject. */
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

/**
 * Resolves the candidate base URLs for a management address + configured ports.
 * An explicit scheme in the address always wins (including its port). A bare
 * "host:port" keeps that port for BOTH schemes (repo convention: an explicit
 * port beats the configured default). Otherwise both schemes are candidates,
 * HTTPS first — credentials over TLS preferred; a plain-HTTP-only box simply
 * fails the https probe and falls through to http.
 */
export function resolveLuciCandidates(
  address: string,
  ports?: { httpsPort?: number; httpPort?: number }
): string[] {
  const raw = String(address ?? '').trim();
  if (!raw) return [];
  if (/^https?:\/\//i.test(raw)) return [raw];

  // Bare address: split host from an optional explicit port (IPv6 literals ok).
  let host = raw;
  let explicitPort: number | null = null;
  const v6 = raw.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) {
    host = v6[1];
    if (v6[2]) explicitPort = Number(v6[2]);
  } else {
    const idx = raw.lastIndexOf(':');
    if (idx > 0 && /^\d+$/.test(raw.slice(idx + 1))) {
      host = raw.slice(0, idx);
      explicitPort = Number(raw.slice(idx + 1));
    }
  }
  const validPort = typeof explicitPort === 'number' ? explicitPort : NaN;
  if (!host || !Number.isFinite(validPort) || validPort < 1 || validPort > 65535) {
    explicitPort = null;
  }

  const port: number | null = explicitPort; // capture the narrowed value for TS control flow
  const out: string[] = [];
  if (port !== null && Number.isFinite(port)) {
    out.push(`https://${raw}`, `http://${raw}`);
  } else {
    out.push(`https://${host}:${ports?.httpsPort ?? 443}`, `http://${host}:${ports?.httpPort ?? 80}`);
  }
  return [...new Set(out)];
}

/** Extracts the stok CSRF token from a LuCI login page (HTML + set-cookie). */
function extractStok(html: string, setCookie?: string[] | string): string | null {
  const cookies = Array.isArray(setCookie) ? setCookie.join('; ') : String(setCookie ?? '');
  // Preferred: the meta tag every LuCI version emits.
  const m1 = html.match(/name="csrf-token"\s+content="([^"]+)"/i);
  if (m1 && m1[1]) return m1[1];
  // Fallback: any ;stok= token embedded in a form action / URL on the page.
  const m2 = html.match(/;stok=([a-f0-9]{8,})/i);
  if (m2 && m2[1]) return m2[1];
  // Last resort: a stok cookie.
  const m3 = cookies.match(/(?:^|;\s*)stok=([^;]+)/i);
  if (m3 && m3[1]) return m3[1];
  return null;
}

/** Extracts the SID session cookie from set-cookie headers. */
function extractSid(setCookie?: string[] | string): string | null {
  const cookies = Array.isArray(setCookie) ? setCookie.join('; ') : String(setCookie ?? '');
  const m = cookies.match(/(?:^|;\s*)SID=([^;]+)/i);
  return m && m[1] ? m[1] : null;
}

/** One authenticated LuCI session bound to a single base URL. */
export class LuciClient {
  private readonly http: AxiosInstance;
  private stok: string | null = null;
  private sid: string | null = null;
  private seq = 0;

  constructor(
    readonly baseUrl: string,
    private readonly username: string,
    private readonly password: string
  ) {
    this.http = axios.create({
      baseURL: baseUrl,
      timeout: DEFAULT_TIMEOUT_MS,
      httpsAgent,
      validateStatus: () => true, // never throw on HTTP failure — we interpret status ourselves
      maxRedirects: 0, // login answers with a 302 whose Set-Cookie we must read directly
    });
  }

  /** True once a session is established. */
  get hasSession(): boolean {
    return this.stok !== null && this.sid !== null;
  }

  /** Drops the current session (forces re-login on the next call). */
  invalidate(): void {
    this.stok = null;
    this.sid = null;
  }

  /**
   * Fetches one page and follows redirects to the final document:
   *   - HTTP Location headers (301/302/307), and
   *   - HTML meta-refresh tags (`<meta http-equiv="refresh" content="0; URL=…">`) —
   *     OpenWRT's web root `/` is a static stub that meta-refreshes to
   *     `cgi-bin/luci/`, so without this the client would only ever see the stub.
   * Bounded (3 hops) with a visited-set against redirect loops. Returns the
   * final page body + the URL it came from.
   */
  private async fetchPage(startPath: string, timeoutMs: number): Promise<{ url: string; html: string }> {
    let current = new URL(startPath, this.baseUrl);
    const visited = new Set<string>();
    for (let hop = 0; hop < 3; hop++) {
      if (visited.has(current.href)) break; // redirect loop
      visited.add(current.href);
      let res: { status: number; data: unknown; headers: Record<string, unknown> };
      try {
        res = await this.http.get(current.pathname + current.search, { timeout: timeoutMs, responseType: 'text' });
      } catch (e) {
        throw new Error(`LuCI login page unreachable at ${current.href}: ${(e as Error).message}`);
      }
      const html = typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '');

      // Location header redirect.
      const loc = res.headers['location'];
      if (typeof loc === 'string' && loc.length > 0) {
        current = new URL(loc, current);
        continue;
      }
      // Meta-refresh redirect (the OpenWRT web-root stub).
      const meta = html.match(/<meta[^>]+http-equiv=["']?refresh["']?[^>]*content=["']?\s*\d+\s*;\s*url\s*=\s*([^"'\s>]+)/i);
      if (meta && meta[1]) {
        current = new URL(meta[1], current.origin);
        continue;
      }
      return { url: current.href, html };
    }
    // Hops exhausted — return whatever we have.
    const res = await this.http.get(current.pathname + current.search, { timeout: timeoutMs, responseType: 'text' });
    return { url: current.href, html: typeof res.data === 'string' ? res.data : JSON.stringify(res.data ?? '') };
  }

  /** Establishes a LuCI session (stok + SID) when not already logged in. */
  private async ensureSession(timeoutMs: number): Promise<void> {
    if (this.hasSession) return;

    // 1. Fetch the login page (following redirects — OpenWRT's `/` is a stub
    //    that meta-refreshes to cgi-bin/luci/) and pull out the stok token.
    const final = await this.fetchPage('/', timeoutMs);
    const stok = extractStok(final.html);
    if (!stok) {
      // No LuCI admin UI (or a non-LuCI web server / custom firmware that mints
      // no stok for anonymous clients) — say so clearly.
      throw new Error(`No LuCI login page at ${this.baseUrl} (no stok token found; last URL ${final.url})`);
    }

    // 2. POST the credentials; success = SID cookie set (302 redirect).
    const body = `username=${encodeURIComponent(this.username)}&password=${encodeURIComponent(this.password)}&redirect_url=%2F`;
    let login: { status: number; headers: Record<string, unknown> };
    try {
      login = await this.http.post(
        `/cgi-bin/luci/;stok=${encodeURIComponent(stok)}/admin/login`,
        body,
        { timeout: timeoutMs, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
    } catch (e) {
      throw new Error(`LuCI login request to ${this.baseUrl} failed: ${(e as Error).message}`);
    }
    const rawCookie: unknown = login.headers['set-cookie'] ?? login.headers['Set-Cookie'];
    const cookieHeader = Array.isArray(rawCookie) ? rawCookie.join('; ') : typeof rawCookie === 'string' ? rawCookie : '';
    const sid = extractSid(cookieHeader);
    if (!sid || login.status >= 400) {
      throw new Error(`LuCI login failed at ${this.baseUrl} (HTTP ${login.status}) — check username/password`);
    }

    this.stok = stok;
    this.sid = sid;
  }

  /**
   * Calls one ubus method. `path` selects a specific object (e.g. an interface
   * name for network.interface status). Returns { ok:false } on any failure —
   * including exactly ONE automatic re-login when the session expired.
   */
  async callUbus<T = unknown>(
    service: string,
    member: string,
    path?: string,
    params?: Record<string, unknown>,
    timeoutMs = DEFAULT_TIMEOUT_MS
  ): Promise<LuciResult<T>> {
    const attempt = async (): Promise<LuciResult<T>> => {
      await this.ensureSession(timeoutMs);
      const payload: Record<string, unknown> = {
        id: ++this.seq,
        method: 'call',
        service,
        member,
        params: params ?? {},
      };
      if (path !== undefined) payload['path'] = path;

      let res: { status: number; data: unknown };
      try {
        res = await this.http.post('/ubus/', payload, {
          timeout: timeoutMs,
          headers: { 'X-CSRF-Token': this.stok as string },
        });
      } catch (e) {
        return { ok: false, status: 0, error: `ubus call ${service}.${member} failed: ${(e as Error).message}` };
      }

      const json = res.data as Record<string, unknown> | undefined;
      if (res.status === 401 || res.status === 503) {
        // Session expired / not authorized — one re-login, then the caller retries.
        this.invalidate();
        return { ok: false, status: res.status, error: 'session expired' };
      }
      if (json && Array.isArray(json['result'])) {
        const result = json['result'] as unknown[];
        return { ok: true, status: res.status, data: (result[0] ?? result) as T };
      }
      const errObj = (json?.['error'] ?? {}) as Record<string, unknown>;
      const msg = typeof errObj['message'] === 'string' ? errObj['message'] : `HTTP ${res.status}`;
      return { ok: false, status: res.status, error: `${service}.${member}: ${msg}` };
    };

    let r = await attempt();
    if (!r.ok && r.error === 'session expired') {
      r = await attempt(); // exactly one retry after re-login
    }
    return r;
  }

  /** Cheap authenticated availability probe (system board). */
  async probe(): Promise<boolean> {
    const r = await this.callUbus('system', 'board', undefined, {}, PROBE_TIMEOUT_MS);
    return r.ok && !!r.data;
  }
}

/** Builds a LuciClient for one base URL with the given credentials. */
export function createLuciClient(
  baseUrl: string,
  username: string,
  password: string
): LuciClient {
  return new LuciClient(baseUrl, username, password);
}
