/**
 * Authentication for Shelly devices — one session per device, two mechanisms:
 *
 *   - Gen1 (REST): HTTP Basic auth on every request when credentials are bound.
 *     No state to keep.
 *   - Gen2+ (JSON-RPC): the `shellyun-auth` cookie handshake. The first
 *     authenticated request carries Basic; the device answers with
 *     `Set-Cookie: shellyun-auth=...`, and every subsequent request reuses the
 *     cookie until it is rejected (401/403) or expires — then the session is
 *     dropped and the next request restarts the handshake.
 *
 * Many Shelly devices ship with local login disabled (`auth_en: false`); in that
 * case no credentials are bound, sessions carry no headers, and everything is
 * plain HTTP.
 *
 * Sessions live in a module-level TtlCache keyed by (address, username) so the
 * cookie survives across polls for as long as the device is reachable, and
 * `clearAuthSessions()` is available as a test hook.
 */

import { basicAuthHeader, TtlCache } from '@unm/plugin-sdk';
import type { ShellyAuth } from './client';

/** Decrypted local-login credentials (may be absent — auth-disabled devices). */
export interface ShellyCredentials {
  username?: string;
  password?: string;
}

/** The cookie name Gen2+ devices use for the local-auth session. */
export const SHELLYUN_AUTH_COOKIE = 'shellyun-auth';

/** Sessions expire after this idle window; every successful use refreshes them. */
export const SESSION_TTL_MS = 30 * 60_000;

/** One device's auth state. Implements the client's structural ShellyAuth. */
export class AuthSession implements ShellyAuth {
  private cookie: string | null = null;

  constructor(private readonly creds: ShellyCredentials | undefined) {}

  /** True when credentials are bound (drives Basic / handshake behavior). */
  get hasCredentials(): boolean {
    return Boolean(this.creds?.username);
  }

  /** True once a shellyun-auth cookie has been captured from the device. */
  get hasCookie(): boolean {
    return this.cookie !== null;
  }

  /** Headers for an outbound request: Basic when bound, plus cookie once known. */
  headers(): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.creds?.username) {
      h.Authorization = basicAuthHeader(this.creds.username, this.creds.password ?? '');
    }
    if (this.cookie) {
      h.Cookie = `${SHELLYUN_AUTH_COOKIE}=${this.cookie}`;
    }
    return h;
  }

  /**
   * Feed a response back: capture the shellyun-auth cookie from Set-Cookie, or
   * invalidate the session on 401/403 so the next request restarts the
   * handshake with fresh Basic credentials.
   */
  onResponse(status: number, setCookies: string[]): void {
    if (status === 401 || status === 403) {
      this.cookie = null;
      return;
    }
    for (const c of setCookies) {
      const m = new RegExp(`^${SHELLYUN_AUTH_COOKIE}=([^;]+)`).exec(c.trim());
      if (m) this.cookie = m[1];
    }
  }
}

// ---------------------------------------------------------------------------
// Per-device session registry
// ---------------------------------------------------------------------------

const sessions = new TtlCache<AuthSession>({ isFresh: () => true });

/** Key for one device's session — stable per assignment address + user. */
export function sessionKey(address: string, creds?: ShellyCredentials): string {
  return `${address}|${creds?.username ?? ''}`;
}

/** Returns (and refreshes) the AuthSession for one device. */
export function authSessionFor(address: string, creds?: ShellyCredentials): AuthSession {
  const key = sessionKey(address, creds);
  const existing = sessions.get(key, SESSION_TTL_MS);
  if (existing) return existing;
  const session = new AuthSession(creds);
  sessions.set(key, session);
  return session;
}

/** Test hook — drop all device sessions. */
export function clearAuthSessions(): void {
  sessions.clear();
}
