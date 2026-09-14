/**
 * FRITZ!Box web-UI session transport — dual-mode.
 *
 * Two UI generations exist in the field and are detected at login time:
 *
 * 1. CLASSIC (FRITZ!OS ≤ 8.x, "html" UI):
 *      GET /login_sid.lua?username=…&password=… → `SID` cookie (or a real SID
 *      inside `<SessionInfo>` XML). Every data request then sends the cookie:
 *        GET /systeminfo64.json, /overview.lua?get_data=1, /internetinfo.json,
 *        /laninfo.json, /wlaninfo.json?ifname=wlanN …
 *
 * 2. HTML2 (new FRITZ!OS generation): the classic data endpoints are GONE
 *    (404 even with a valid session). Login is a PBKDF2 challenge-response:
 *      - GET /login_sid.lua → zero SID + `<Challenge>` (8-hex, ignored)
 *      - GET /              → login page embedding `const data = {…}` with
 *        `"challenge":"2$<iter1>$<salt1hex>$<iter2>$<salt2hex>"` and the
 *        auto-generated username for password-only boxes
 *      - response  = hex(salt2) + "$" + hex(PBKDF2-SHA256(
 *                      PBKDF2-SHA256(password, salt1, iter1), salt2, iter2))
 *        (exact port of the box's own /js/box-login.js generatePBKDF2Response)
 *      - POST /index.lua  {uiUser, uiPass, response, lp, forward, loginView,
 *        username} → authenticated main page whose `main.init({…})` blob
 *        carries `"sid":"<16-hex>"`. No cookies are involved at all.
 *    Data requests then go to the single multiplexed endpoint:
 *      POST /data.lua  {page:<pid>, sid, …} → JSON envelope {pid, data, …}
 *    (pages: overview via any pid, netDev host table with xhrId=all, wSet,
 *    energy, usbOv, dslOv — see endpoints.ts).
 *
 * Transport choice (`transport` option): FRITZ!Boxes serve self-signed TLS by
 * default — `auto` (default) tries https first and falls back to plain http
 * only on NETWORK-level failures (connection refused / DNS / timeout), never
 * on HTTP-level ones. The resolved scheme is pinned after a successful login.
 */

import axios, { AxiosInstance } from 'axios';
import crypto from 'crypto';
import { insecureHttpsAgent, isNetworkLevelError, withPort } from '@unm/plugin-sdk';

export type FBoxTransport = 'auto' | 'http' | 'https';

/** Which UI generation the box speaks (set during login). */
export type FBoxUiMode = 'classic' | 'html2';

/** Raised when the box rejects our credentials (401 / no SID issued). */
export class FBoxAuthError extends Error {
  constructor(message = 'Authentication failed — check the assigned username/password secret') {
    super(message);
    this.name = 'FBoxAuthError';
  }
}

/** Raised when the target does not look like an AVM router at all. */
export class FBoxNotFritzError extends Error {
  constructor() {
    super('Target does not respond with a FRITZ!OS web UI — is this an AVM router?');
    this.name = 'FBoxNotFritzError';
  }
}

// Network-vs-HTTP error classification and self-signed-TLS acceptance come from
// the shared SDK transport layer (isNetworkLevelError / insecureHttpsAgent) —
// FRITZ!Boxes, like every other UNM appliance, present a self-signed cert by default.

export interface FBoxCredentials {
  username: string;
  password: string;
}
/**
 * Module-level client cache — one FBoxClient per (host, credentials, options).
 *
 * A fresh client means a FULL LOGIN on every poll (classic: login_sid.lua;
 * html2: login_sid.lua + GET / + POST /index.lua). At the API's 30 s beat that
 * is ~6 logins/minute per box — enough to trip FRITZ!OS' web-UI rate limit,
 * which then blocks further logins for up to ~100 s. Because the block window
 * outlasts the poll interval, naive retries re-trigger it on every beat: a
 * self-sustaining lockout (observed live 2026-08-30 — both boxes offline while
 * ping worked). Reusing one client per box keeps the session alive across polls
 * (FRITZ!OS sessions outlive our poll interval by far), so logins drop to ~1
 * per 15 min / reboot. The key includes a password hash, so credential
 * rotation transparently yields a fresh client; entries are tiny and bounded
 * by the device count.
 */
const clientCache = new Map<string, FBoxClient>();

/** Returns the cached client for this (host, credentials, options) tuple. */
export function getCachedFBoxClient(host: string, creds: FBoxCredentials, options: FBoxClientOptions = {}): FBoxClient {
  const key = [
    host.trim().replace(/\/+$/, ''),
    creds.username ?? '',
    crypto.createHash('sha256').update(creds.password ?? '').digest('hex'),
    options.transport ?? 'auto',
    String(options.timeoutMs ?? 4000),
    `p${options.httpsPort ?? ''}/${options.httpPort ?? ''}`,
  ].join('|');
  let client = clientCache.get(key);
  if (!client) {
    client = new FBoxClient(host, creds, options);
    clientCache.set(key, client);
  }
  return client;
}
export interface FBoxClientOptions {
  transport?: FBoxTransport;
  timeoutMs?: number;
  /** HTTPS management port when the address has no explicit port (default 443). */
  httpsPort?: number;
  /** Plain-HTTP management port (default 80) — used for auto-mode fallbacks. */
  httpPort?: number;
}

/** Extract the SID value from a Set-Cookie header list ('' when absent). */
function extractSid(setCookie: unknown): string {
  if (!Array.isArray(setCookie)) return '';
  for (const c of setCookie) {
    const m = String(c).match(/^SID=([^;]+)/i);
    if (m && m[1].trim() !== '') return m[1].trim();
  }
  return '';
}

/** A zero SID ('0000000000000000') means "not authenticated yet". */
function isZeroSid(sid: string): boolean {
  return /^\d*$/.test(sid) && sid.replace(/0/g, '') === '';
}

interface SessionInfo {
  sid: string;
  challenge: string;
  /** Seconds remaining of a login block (rate limit) — 0 when not blocked. */
  blockTime: number;
  users: { name: string; last: boolean }[];
}

/**
 * Parses the `<SessionInfo>` XML that FRITZ!OS returns from login_sid.lua:
 *   <SessionInfo><SID>0…</SID><Challenge>6cc4df30</Challenge>
 *     <BlockTime>0</BlockTime><Rights></Rights>
 *     <Users><User last="1">fritz1649</User></Users></SessionInfo>
 */
function parseSessionInfo(xml: string): SessionInfo {
  const tag = (name: string): string => {
    const m = xml.match(new RegExp(`<${name}>([^<]*)</${name}>`));
    return m ? m[1].trim() : '';
  };
  const users: { name: string; last: boolean }[] = [];
  for (const m of xml.matchAll(/<User([^>]*)>([^<]*)<\/User>/g)) {
    if (!m[2].trim()) continue;
    users.push({ name: m[2].trim(), last: /last="1"/.test(m[1]) });
  }
  const blockTime = Number(tag('BlockTime'));
  return { sid: tag('SID'), challenge: tag('Challenge'), blockTime: Number.isFinite(blockTime) ? blockTime : 0, users };
}

/**
 * Per-host login backoff — set when the box reports an active rate-limit
 * block (html2 `blockTime` / classic `<BlockTime>`) or by the escalation
 * ladder below. While it is in effect we throw WITHOUT touching the network:
 * retrying a blocked login only EXTENDS the cooldown, which is exactly how the
 * 2026-08-30 fleet lockout sustained itself (poll beat 30 s < block window
 * ~100 s → every beat re-triggered it).
 */
const loginBlockedUntil = new Map<string, number>();

// v4 marker — proves at runtime which build actually loaded (and in which PID).
console.error(`[fbox-backoff v4] fboxClient module loaded pid=${process.pid} at ${new Date().toISOString()}`);

function setLoginBlock(host: string, seconds: number): void {
  // +5 s buffer so we do not race the box' own timer. EXTEND-ONLY: a
  // box-reported block and the escalation ladder may both be in flight — keep
  // whichever ends later, never shorten an active backoff.
  const until = Date.now() + Math.max(0, Math.ceil(seconds)) * 1000 + 5_000;
  if (until > (loginBlockedUntil.get(host) ?? 0)) loginBlockedUntil.set(host, until);
}

/** Remaining block seconds for a host (0 = not blocked). */
function loginBlockRemainingMs(host: string): number {
  const until = loginBlockedUntil.get(host) ?? 0;
  return Math.max(0, until - Date.now());
}

/**
 * Consecutive auth failures per host. After this many in a row we back off for
 * AUTH_FAIL_BACKOFF_MS — otherwise persistently bad credentials (or a box that
 * rejects us) would mean one full login attempt every poll beat, which is the
 * same rate-limit pressure as the block-retry spiral above.
 */
const authFailures = new Map<string, number>();
const AUTH_FAIL_THRESHOLD = 3;
const AUTH_FAIL_BACKOFF_MS = 120_000;

/**
 * Escalation ladder for box-reported blocks (observed live 2026-08-30): while
 * the box is in its penalty state it rejects EVEN VALID logins ("Login
 * rejected") and re-arms a fresh ~96 s block on every attempt — so "wait out
 * the reported cooldown" alone still loses: each beat's single attempt
 * re-triggers the spiral. The fix: after EVERY box-reported block we stay
 * quiet for an escalating window that DOUBLES per consecutive occurrence
 * (5 min → 10 min → cap 30 min). The base MUST exceed the box' penalty decay
 * time — a 2-min base was proven insufficient live (the box re-armed on every
 * attempt, keeping its counters hot indefinitely). A multi-minute silence lets
 * FRITZ!OS' penalty counters fully decay; the next attempt then succeeds and
 * everything resets.
 */
const blockStreak = new Map<string, number>();
const ESCALATION_BASE_MS = 5 * 60_000;
const ESCALATION_CAP_MS = 30 * 60_000;

/** Called when the box reports an active rate-limit block (any UI mode). */
function noteBlockedLogin(host: string): void {
  const streak = (blockStreak.get(host) ?? 0) + 1;
  blockStreak.set(host, streak);
  const seconds = Math.min(ESCALATION_CAP_MS, ESCALATION_BASE_MS * 2 ** (streak - 1)) / 1000;
  console.error(`[fbox-backoff v4] ${host}: box reported a block — streak=${streak}, backing off ${Math.round(seconds)} s`);
  setLoginBlock(host, seconds);
}

function noteAuthFailure(host: string): void {
  const n = (authFailures.get(host) ?? 0) + 1;
  authFailures.set(host, n);
  // Only arm a backoff when none is active — an active one already keeps us
  // quiet and the escalation ladder owns its duration.
  if (n >= AUTH_FAIL_THRESHOLD && loginBlockRemainingMs(host) === 0) {
    setLoginBlock(host, AUTH_FAIL_BACKOFF_MS / 1000);
  }
}

/** A successful login resets every backoff/streak for this host. */
function clearAuthFailures(host: string): void {
  authFailures.delete(host);
  blockStreak.delete(host);
  loginBlockedUntil.delete(host);
}

/** Picks the user to authenticate as when none is configured (password-only boxes). */
function pickDiscoveredUser(users: { name: string; last: boolean }[]): string {
  const last = users.find((u) => u.last);
  return (last ?? users[0])?.name ?? '';
}

/**
 * Extracts the balanced `{…}` object literal starting at `start` in `text`,
 * respecting string literals. Returns '' when no balanced object is found.
 */
function extractBalancedObject(text: string, start: number): string {
  const open = text.indexOf('{', start);
  if (open === -1) return '';
  let depth = 0;
  let inStr: string | null = null;
  for (let i = open; i < text.length; i++) {
    const c = text[i];
    if (inStr) {
      if (c === '\\') i++;
      else if (c === inStr) inStr = null;
      continue;
    }
    if (c === '"' || c === "'") {
      inStr = c;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return text.slice(open, i + 1);
    }
  }
  return '';
}

/** Parses the login page's `const data = {…}` blob (challenge/username/blockTime). */
function parseLoginPageData(html: string): Record<string, unknown> | null {
  const at = html.indexOf('const data');
  if (at === -1) return null;
  const raw = extractBalancedObject(html, at);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    // The blob is a JS literal — tolerate trailing commas.
    try {
      return JSON.parse(raw.replace(/,\s*([}\]])/g, '$1')) as Record<string, unknown>;
    } catch {
      return null;
    }
  }
}

/**
 * Computes the html2 login response — exact port of the box's own
 * /js/box-login.js `generatePBKDF2Response(challenge, password)`:
 *   challenge = "2$<iter1>$<salt1hex>$<iter2>$<salt2hex>"
 *   pass1 = PBKDF2-SHA256(utf8(password), hex(salt1), iter1, 32)
 *   pass2 = PBKDF2-SHA256(pass1, hex(salt2), iter2, 32)
 *   response = hex(salt2) + "$" + hex(pass2)
 */
function computeHtml2Response(challenge: string, password: string): string {
  const parts = challenge.trim().split('$');
  if (parts.length !== 5 || parts[0] !== '2') throw new Error('Unsupported login challenge format');
  const iter1 = Number(parts[1]);
  const salt1hex = parts[2];
  const iter2 = Number(parts[3]);
  const salt2hex = parts[4];
  if (!Number.isInteger(iter1) || !Number.isInteger(iter2) || !salt1hex || !salt2hex) {
    throw new Error('Malformed login challenge');
  }
  const pass1 = crypto.pbkdf2Sync(Buffer.from(password, 'utf8'), Buffer.from(salt1hex, 'hex'), iter1, 32, 'sha256');
  const pass2 = crypto.pbkdf2Sync(pass1, Buffer.from(salt2hex, 'hex'), iter2, 32, 'sha256');
  return `${salt2hex}$${pass2.toString('hex')}`;
}

/** Pulls the session id out of an authenticated html2 main page. */
function extractHtml2Sid(html: string): string {
  const m = html.match(/"sid"\s*:\s*"([0-9a-fA-F]{16})"/);
  return m ? m[1] : '';
}

/**
 * One client PER MANAGEMENT ADDRESS (see getCachedFBoxClient) — the session
 * must survive across polls or every beat costs a full login and trips the
 * box' web-UI rate limit. The only other state is the SID + pinned scheme,
 * both cheap to re-establish on expiry.
 */
export class FBoxClient {
  private readonly host: string;
  private readonly username: string;
  private readonly password: string;
  private readonly timeoutMs: number;
  private readonly transport: FBoxTransport;
  /** Configured management ports (defaults 443/80) — an explicit port in the address wins. */
  private readonly httpsPort?: number;
  private readonly httpPort?: number;

  /** Pinned base URL — set only after a SUCCESSFUL login (see pinBase()). */
  private base: string | null = null;
  /** Base of the last successful withScheme() call — pinned by doLogin(). */
  private lastWorkingBase: string | null = null;
  /** Current session id ('' until logged in). */
  private sid = '';
  /** Dedupes concurrent login attempts. */
  private loginPromise: Promise<void> | null = null;

  /** UI generation detected during login (undefined before the first login). */
  mode: FBoxUiMode | undefined;

  constructor(host: string, credentials: FBoxCredentials, options: FBoxClientOptions = {}) {
    const h = (host ?? '').trim().replace(/\/+$/, '');
    if (!h) throw new Error('No management address');
    this.host = /^https?:\/\//i.test(h) ? h.replace(/^https?:\/\//i, '') : h;
    this.username = credentials?.username ?? '';
    this.password = credentials?.password ?? '';
    this.timeoutMs = options.timeoutMs ?? 4000;
    this.transport = options.transport ?? 'auto';
    // An explicit port in the address (host:8443) wins over the configured default.
    const hasExplicitPort = /:\d+$/.test(this.host.split('/')[0]);
    if (!hasExplicitPort) {
      this.httpsPort = options.httpsPort;
      this.httpPort = options.httpPort;
    }
  }

  /** The host as given (for cache keys / log messages). */
  get baseHost(): string {
    return this.host;
  }

  // --- public API -----------------------------------------------------------------

  /** Log in (or reuse the current session). Throws FBoxAuthError on bad credentials. */
  async login(): Promise<void> {
    if (this.sid) return;
    // Rate-limit backoff: while the box has reported an active block, do NOT
    // even attempt — every attempt during a cooldown extends it.
    const remainingMs = loginBlockRemainingMs(this.host);
    if (remainingMs > 0) {
      // v4 marker: proves at runtime which build is actually serving polls.
      console.error(`[fbox-backoff v4] ${this.host}: skipping login — ${Math.ceil(remainingMs / 1000)} s of backoff remaining`);
      throw new FBoxAuthError(
        `Login temporarily blocked by the box (${Math.ceil(remainingMs / 1000)} s cooldown — too many attempts).`
      );
    }
    if (!this.loginPromise) {
      this.loginPromise = (async () => {
        try {
          await this.doLogin();
          clearAuthFailures(this.host); // success — reset the failure streak
        } catch (err) {
          // Only AUTH failures count toward the backoff — a network blip or
          // timeout must not burn the box' rate-limit budget.
          if (err instanceof FBoxAuthError) noteAuthFailure(this.host);
          throw err;
        } finally {
          this.loginPromise = null;
        }
      })();
    }
    await this.loginPromise;
  }

  /**
   * CLASSIC mode: GET a data endpoint and parse the JSON body. Re-logs in ONCE
   * when the session has expired (login redirect / 401/403). Returns `null`
   * when the box answers but with no parseable JSON (feature absent on this
   * firmware) — callers treat null as "not reported".
   */
  async getJson(path: string): Promise<unknown> {
    await this.login();

    let res = await this.rawGet(path);
    if (this.isSessionExpired(res)) {
      // Session expired mid-poll — re-login once and retry. login() dedupes
      // concurrent re-logins (a parallel batch can hit the expiry together).
      this.sid = '';
      this.mode = undefined;
      await this.login();
      res = await this.rawGet(path);
    }
    if (res.status === 401 || res.status === 403) throw new FBoxAuthError(`HTTP ${res.status} from ${path}`);
    if (res.status === 404) return null; // endpoint unknown on this firmware — feature absent
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from ${path}`);

    const text = res.body.toString('utf8');
    try {
      return JSON.parse(text) as unknown;
    } catch {
      // HTML error page / unsupported feature — not a hard failure.
      if (/login/i.test(text.slice(0, 512))) throw new FBoxAuthError(`Session rejected by ${path}`);
      return null;
    }
  }

  /**
   * HTML2 mode: POST the multiplexed /data.lua endpoint for one page and
   * return its `data` payload (null when the box answers without data).
   * Re-logs in ONCE on session expiry, like getJson().
   */
  async getDataPage(page: string, extraParams: Record<string, string> = {}): Promise<unknown> {
    await this.login();

    // An empty `page` omits the field entirely — that is how the SPA requests
    // the HOME overview (POST /data.lua with only sid). Note: page:"overview"
    // specifically returns null data; omitting it triggers the home payload.
    // Fields are built PER FETCH so a mid-batch re-login retries with the NEW sid.
    const doFetch = (): Promise<{ status: number; headers: Record<string, unknown>; body: Buffer }> =>
      this.rawPost('/data.lua', { ...(page ? { page } : {}), sid: this.sid, ...extraParams });

    let res = await doFetch();
    if (this.isSessionExpired(res) || res.status === 401 || res.status === 403 || this.looksLikeLoginPage(res)) {
      // Session expired mid-poll — re-login once and retry. login() dedupes
      // concurrent re-logins (a parallel batch can hit the expiry together).
      this.sid = '';
      this.mode = undefined;
      await this.login();
      res = await doFetch();
    }
    if (res.status === 401 || res.status === 403) throw new FBoxAuthError(`HTTP ${res.status} from /data.lua (${page})`);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from /data.lua (${page})`);

    const parse = (): unknown => {
      const text = res.body.toString('utf8');
      try {
        const j = JSON.parse(text) as Record<string, unknown>;
        return 'data' in j ? j.data : null;
      } catch {
        // Non-JSON answer (login page / error HTML) — treat as session loss.
        if (/login|challenge/i.test(text.slice(0, 1024))) throw new FBoxAuthError(`Session rejected by /data.lua (${page})`);
        return null;
      }
    };

    let data = parse();
    // The box occasionally drops a batch member's answer under load (observed
    // live: usbOv/wSet returned data:null or timed out right after a burst of
    // logins, full payload on the next poll). Retry with backoff before
    // treating the page as absent — none of the pages we request legitimately
    // return null (unknown pids fall back to the overview payload instead).
    for (const delayMs of [400, 900]) {
      if (data != null) break;
      await new Promise((r) => setTimeout(r, delayMs));
      res = await doFetch();
      if (res.status >= 200 && res.status < 300) data = parse();
    }
    return data;
  }

  /**
   * HTML2 mode: POST /data.lua for a page that answers with an HTML FORM
   * instead of the JSON envelope — e.g. `boxnet` (route /network/ipv4, LAN v4
   * netmask) and `boxnet_ipv6` (route /network/ipv6). Returns the raw HTML, or
   * null when the box answers with a JSON envelope (pid not a form page on this
   * firmware — unknown pids fall back to the overview payload). Same session-
   * expiry handling as getDataPage().
   */
  async getHtmlPage(page: string): Promise<string | null> {
    await this.login();

    const doFetch = (): Promise<{ status: number; headers: Record<string, unknown>; body: Buffer }> =>
      this.rawPost('/data.lua', { page, sid: this.sid });

    let res = await doFetch();
    if (this.isSessionExpired(res) || res.status === 401 || res.status === 403 || this.looksLikeLoginPage(res)) {
      // Session expired mid-poll — re-login once and retry. login() dedupes
      // concurrent re-logins (a parallel batch can hit the expiry together).
      this.sid = '';
      this.mode = undefined;
      await this.login();
      res = await doFetch();
    }
    if (res.status === 401 || res.status === 403) throw new FBoxAuthError(`HTTP ${res.status} from /data.lua (${page})`);
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from /data.lua (${page})`);

    const parse = (): string | null => {
      const text = res.body.toString('utf8');
      // A JSON envelope means this pid is not a form page on this firmware.
      if (text.trimStart().startsWith('{')) {
        try {
          JSON.parse(text);
          return null;
        } catch {
          /* malformed — treat as HTML below */
        }
      }
      return text;
    };

    let html = parse();
    // Under a concurrent batch the box occasionally answers with the overview
    // fallback (JSON envelope) instead of the form page — same flakiness as
    // getDataPage's null-data drops. Retry with backoff before giving up.
    for (const delayMs of [400, 900]) {
      if (html != null) break;
      await new Promise((r) => setTimeout(r, delayMs));
      res = await doFetch();
      if (res.status >= 200 && res.status < 300) html = parse();
    }
    return html;
  }

  /** A 2xx answer that is HTML (the login page) instead of the JSON envelope. */
  private looksLikeLoginPage(res: { status: number; body: Buffer }): boolean {
    if (res.status < 200 || res.status >= 300) return false;
    const head = res.body.toString('utf8', 0, Math.min(1024, res.body.length));
    return /<html|const data\s*=|"challenge"\s*:/.test(head);
  }

  // --- internals --------------------------------------------------------------------

  private isSessionExpired(res: { status: number; headers: Record<string, unknown>; body: Buffer }): boolean {
    if (res.status >= 300 && res.status < 400) {
      const loc = String(res.headers['location'] ?? '');
      return /login/i.test(loc);
    }
    return false;
  }

  private async doLogin(): Promise<void> {
    // An empty username is legitimate — password-only boxes carry `username=`.
    const res = await this.withScheme((base, client) =>
      // validateStatus off — 401/403/404 are handled by the explicit checks below.
      client.get('/login_sid.lua', { params: { username: this.username, password: this.password }, validateStatus: () => true })
    );

    // Some firmware versions answer 401 directly; others redirect without a cookie.
    if (res.status === 401 || res.status === 403) throw new FBoxAuthError();
    if (res.status === 404 || res.status === 405) throw new FBoxNotFritzError();
    if (res.status < 200 || res.status >= 300) throw new Error(`HTTP ${res.status} from login`);

    // The box answered over this scheme — pin it for the data requests.
    this.pinBase();

    const body = Buffer.from(res.data ?? '').toString('utf8');
    let sid = extractSid(res.headers['set-cookie']);
    if (!sid) {
      const info = parseSessionInfo(body);
      // Classic firmware reports an active rate-limit block here too.
      if (info.blockTime > 0 && !info.sid) noteBlockedLogin(this.host);
      if (info.sid && !isZeroSid(info.sid)) sid = info.sid;
    }
    if (sid) {
      this.mode = 'classic';
      this.sid = sid; // classic firmware: SID cookie straight away
      loginBlockedUntil.delete(this.host); // a successful login clears any backoff
      return;
    }

    // No usable SID → the html2 generation. Its login is a PBKDF2
    // challenge-response against the LOGIN PAGE's embedded config (the 8-hex
    // <Challenge> from login_sid.lua is NOT what gets verified).
    await this.html2Login();
  }

  /** html2-generation login: page challenge → PBKDF2 response → POST /index.lua. */
  private async html2Login(): Promise<void> {
    const pageRes = await this.withScheme((base, client) => client.get('/', { validateStatus: () => true }));
    if (pageRes.status === 401 || pageRes.status === 403) throw new FBoxAuthError();
    if (pageRes.status < 200 || pageRes.status >= 300) throw new Error(`HTTP ${pageRes.status} from login page`);

    const html = Buffer.from(pageRes.data ?? '').toString('utf8');
    const gData = parseLoginPageData(html);
    if (!gData || typeof gData.challenge !== 'string' || !gData.challenge.includes('$')) {
      throw new FBoxAuthError('Unsupported FRITZ!OS login protocol — no challenge-response config found.');
    }

    const blockTime = Number(gData.blockTime ?? 0);
    if (Number.isFinite(blockTime) && blockTime > 0) {
      // Record the box-reported cooldown so subsequent polls back off INSTEAD
      // of re-triggering it — retrying a blocked login extends the window.
      noteBlockedLogin(this.host);
      throw new FBoxAuthError(`Login temporarily blocked by the box (${Math.ceil(blockTime)} s cooldown — too many attempts).`);
    }

    // Password-only boxes: the page carries the auto-generated username.
    const user = this.username || (typeof gData.username === 'string' ? gData.username : '');
    const response = computeHtml2Response(gData.challenge, this.password);

    const formRes = await this.withScheme((base, client) =>
      client.post(
        '/index.lua',
        new URLSearchParams({
          uiUser: user,
          uiPass: this.password,
          response,
          lp: '',
          forward: '',
          loginView: 'simple',
          username: user,
        }).toString(),
        { headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, validateStatus: () => true }
      )
    );
    if (formRes.status === 401 || formRes.status === 403) throw new FBoxAuthError();

    const mainHtml = Buffer.from(formRes.data ?? '').toString('utf8');
    // A wrong password (or an active rate-limit penalty) re-serves the LOGIN
    // page; a successful login serves the authenticated MAIN page with SID.
    if (/const data\s*=/.test(mainHtml) && /"challenge"\s*:/.test(mainHtml)) {
      // The box may be in its penalty state — the re-served login page carries
      // blockTime > 0. Honour it via the escalation ladder instead of falling
      // through to the flat 120 s auth-failure backoff (which is too short and
      // keeps re-triggering the spiral).
      const rejData = parseLoginPageData(mainHtml);
      const rejBlock = Number(rejData?.blockTime ?? 0);
      if (Number.isFinite(rejBlock) && rejBlock > 0) {
        noteBlockedLogin(this.host);
        throw new FBoxAuthError(
          `Login temporarily blocked by the box (${Math.ceil(rejBlock)} s cooldown — too many attempts).`
        );
      }
      throw new FBoxAuthError('Login rejected — check the assigned username/password secret.');
    }
    const sid = extractHtml2Sid(mainHtml);
    if (!sid) throw new FBoxAuthError('Challenge login failed — no session id issued (check the assigned username/password secret).');

    this.mode = 'html2';
    this.sid = sid;
  }

  /** One GET over a fresh axios instance (no connection pooling surprises). */
  private rawGet(path: string): Promise<{ status: number; headers: Record<string, unknown>; body: Buffer }> {
    return this.withScheme(async (base, client) => {
      const res = await client.get(path, {
        maxRedirects: 0, // we follow redirects manually to detect login bounces
        validateStatus: () => true,
        headers: this.mode === 'classic' && this.sid ? { Cookie: `SID=${this.sid}` } : {},
      });
      return { status: res.status, headers: res.headers as Record<string, unknown>, body: Buffer.from(res.data ?? '') };
    });
  }

  /** One form-encoded POST (html2 /data.lua + /index.lua). */
  private rawPost(path: string, fields: Record<string, string>): Promise<{ status: number; headers: Record<string, unknown>; body: Buffer }> {
    return this.withScheme(async (base, client) => {
      const res = await client.post(
        path,
        new URLSearchParams(fields).toString(),
        { maxRedirects: 0, validateStatus: () => true, headers: { 'Content-Type': 'application/x-www-form-urlencoded' } }
      );
      return { status: res.status, headers: res.headers as Record<string, unknown>, body: Buffer.from(res.data ?? '') };
    });
  }

  /** Pins the scheme that just made a successful login (called from doLogin). */
  private pinBase(): void {
    // The last withScheme() call resolved against one of our bases — re-derive it
    // from the client we actually used. Simplest correct source: track it there.
    if (this.lastWorkingBase) this.base = this.lastWorkingBase;
  }

  /**
   * Runs `fn` against the pinned base URL; in `auto` mode unpinned calls try
   * https then http — only NETWORK-level failures (connection refused, DNS,
   * timeout, TLS handshake errors like EPROTO from a plain-HTTP box) trigger
   * the fallback. HTTP-level outcomes (401/403/…) are final for that scheme.
   */
  private async withScheme<T>(fn: (base: string, client: AxiosInstance) => Promise<T>): Promise<T> {
    if (this.base) return fn(this.base, this.makeClient(this.base));

    const schemes = this.transport === 'http' ? ['http'] : this.transport === 'https' ? ['https'] : ['https', 'http'];
    let lastErr: unknown = null;
    for (const scheme of schemes) {
      // Configured port per scheme (defaults 443/80); an explicit address port wins.
      const base = withPort(`${scheme}://${this.host}`, scheme === 'https' ? this.httpsPort : this.httpPort, scheme === 'https' ? 443 : 80);
      try {
        const result = await fn(base, this.makeClient(base));
        this.lastWorkingBase = base; // pinned only after a successful login
        return result;
      } catch (err) {
        if (!isNetworkLevelError(err)) throw err; // HTTP-level outcome — final for this client
        lastErr = err;
      }
    }
    throw lastErr instanceof Error ? lastErr : new Error(`Unreachable: ${String(lastErr)}`);
  }

  private makeClient(base: string): AxiosInstance {
    return axios.create({
      baseURL: base,
      timeout: this.timeoutMs,
      // Keep the response body RAW — axios' default transform parses JSON into
      // objects, which breaks Buffer.from() in rawGet(). We parse ourselves.
      transformResponse: [(d) => d],
      ...(base.startsWith('https://') ? { httpsAgent: insecureHttpsAgent() } : {}),
    });
  }
}
