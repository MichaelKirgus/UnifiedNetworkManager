import WebSocket, { RawData } from 'ws';

/**
 * Core transport for the TrueNAS SCALE API client.
 *
 * The documented TrueNAS API (TrueNAS 25.04+) is JSON-RPC 2.0 over a persistent
 * WebSocket at `ws(s)://<host>/api/current` — see https://api.truenas.com and
 * the official client truenas/api_client. Each request:
 *
 *   { "jsonrpc": "2.0", "id": 1, "method": "pool.query", "params": [] }
 *     → { "jsonrpc": "2.0", "id": 1, "result": [...] }
 *     → { "jsonrpc": "2.0", "id": 1, "error": { code, message, data: { errname, reason } } }
 *
 * Authentication (per the appliance's own API docs for `auth.login_ex`):
 *   - API key (TrueNAS 26+): mechanism `API_KEY_PLAIN` with the owning username
 *     and the raw key (`{id}-{material}` format). SCRAM-SHA-512 is also offered
 *     by the official client; PLAIN over TLS is the documented simple path.
 *   - Username/password: mechanism `PASSWORD_PLAIN`, falling back to legacy
 *     `auth.login [username, password]` on pre-25.04 boxes that lack login_ex.
 * The session stays authenticated for the lifetime of the socket; a dropped
 * connection transparently reconnects + re-authenticates on the next call.
 */

export type TruenasTransport = 'auto' | 'http' | 'https';

/** Thrown when authentication fails (bad credentials / 2FA required). */
export class TruenasAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TruenasAuthError';
  }
}

interface JsonRpcErrorObject {
  code: number;
  message?: string | null;
  data?: { errname?: string; reason?: string } | unknown[] | null;
}

/** Thrown for JSON-RPC method errors and transport failures. */
export class TruenasRpcError extends Error {
  readonly code?: number;
  /** The raw JSON-RPC error object, when the failure came from a method response. */
  readonly rpcError?: JsonRpcErrorObject;
  constructor(message: string, code?: number, rpcError?: JsonRpcErrorObject) {
    super(message);
    this.name = 'TruenasRpcError';
    this.code = code;
    this.rpcError = rpcError;
  }
}

/** Default per-request timeout; overridable via the plugin's `timeoutMs` option. */
export const DEFAULT_TIMEOUT_MS = 5_000;

/**
 * Resolves the WebSocket URL for a device address (same convention as other
 * UNM clients): an explicit http(s) scheme is converted to ws(s); otherwise
 * `transport: 'auto'`/`https` → wss with self-signed certificates accepted
 * (TrueNAS ships one out of the box), `http` → plain ws.
 */
export function resolveWsUrl(host: string, transport?: TruenasTransport): string {
  let h = (host ?? '').trim().replace(/\/+$/, '');
  if (!h) return '';
  const m = h.match(/^https?:\/\/(.*)$/i);
  if (m) h = m[1]; // explicit scheme wins — converted to ws(s) below
  const t = transport ?? 'auto';
  const scheme = t === 'http' ? 'ws://' : 'wss://';
  return `${scheme}${h}/api/current`;
}

/** How the plugin authenticates: username/password or a TrueNAS API key. */
export interface TruenasCredentials {
  kind: 'password' | 'apiKey';
  /** Owner username — required by TrueNAS 26+ for API-key login; also used for password login. */
  username?: string;
  password?: string;
  apiKey?: string;
}

interface JsonRpcResponse<T> {
  jsonrpc?: string;
  id?: number | string;
  result?: T;
  error?: JsonRpcErrorObject;
}

type PendingCall = {
  resolve: (v: JsonRpcResponse<unknown>) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
};

/** One bound client for one appliance (host + transport). */
export class TruenasClient {
  private readonly wsUrl: string;
  private readonly timeoutMs: number;
  private ws: WebSocket | null = null;
  private state: 'idle' | 'connecting' | 'open' = 'idle';
  private connectPromise: Promise<void> | null = null;
  /** Fingerprint of the credentials that authenticated the current socket. */
  private authedFp: string | null = null;
  /** In-flight login dedupe — parallel calls share one auth exchange. */
  private loginPromise: Promise<void> | null = null;
  private loginPromiseFp: string | null = null;
  private nextId = 1;
  private readonly pending = new Map<number, PendingCall>();

  constructor(host: string, transport?: TruenasTransport, timeoutMs: number = DEFAULT_TIMEOUT_MS) {
    this.wsUrl = resolveWsUrl(host, transport);
    if (!this.wsUrl) throw new Error('TruenasClient requires a non-empty host');
    this.timeoutMs = timeoutMs > 0 ? timeoutMs : DEFAULT_TIMEOUT_MS;
  }

  /** True when the given credentials differ from those used for the cached session. */
  private fingerprint(creds: TruenasCredentials): string {
    return creds.kind === 'apiKey'
      ? `key:${creds.username ?? ''}:${creds.apiKey ?? ''}`
      : `user:${creds.username ?? ''}:${creds.password ?? ''}`;
  }

  // ------------------------------------------------------------------ socket

  /** Opens the WebSocket if needed (concurrent callers share one handshake). */
  private connect(): Promise<void> {
    if (this.state === 'open') return Promise.resolve();
    if (this.connectPromise) return this.connectPromise;

    const ws = new WebSocket(this.wsUrl, { rejectUnauthorized: false });
    // Permanent no-op error guard for the socket's WHOLE lifetime. resetAfterFailure()
    // and close() call removeAllListeners(), which would strip the 'error' handler —
    // any late socket error (e.g. a mid-session drop of an established connection)
    // then becomes an UNHANDLED 'error' event that crashes the whole plugin process
    // ("Unhandled 'error' event"). This guard is registered first and never removed,
    // so an 'error' can never go unhandled regardless of listener cleanup. The real
    // handler below still runs (multiple listeners are allowed) for handshake failures.
    ws.on('error', () => { /* guarded — see above */ });
    this.ws = ws;
    this.state = 'connecting';
    let settled = false;

    const p = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        try { ws.terminate(); } catch { /* noop */ }
        this.resetAfterFailure();
        reject(new TruenasRpcError(`WebSocket connect to ${this.wsUrl} timed out after ${Math.max(3000, this.timeoutMs)} ms`));
      }, Math.max(3000, this.timeoutMs));

      ws.on('open', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.state = 'open';
        resolve();
      });
      ws.on('message', (data: RawData) => this.onMessage(data));
      // 'error' fires on EVERY socket failure — including mid-session drops of an
      // ESTABLISHED connection (e.g. the appliance closing a busy socket). A
      // 'close' event always follows; handleClosed() rejects pending calls and
      // resets state for reconnection. When the handshake itself fails we reject
      // here so the caller sees the reason.
      ws.on('error', (err: Error) => {
        if (!settled) {
          settled = true;
          clearTimeout(timer);
          this.resetAfterFailure();
          reject(new TruenasRpcError(`WebSocket connect to ${this.wsUrl} failed: ${err.message}`));
        }
      });
      ws.on('close', () => {
        if (settled) this.handleClosed();
      });
    });

    this.connectPromise = p;
    void p.finally(() => {
      if (this.connectPromise === p) this.connectPromise = null;
    });
    return p;
  }

  /** Clears socket state after a failed handshake (the socket is dead). */
  private resetAfterFailure(): void {
    const ws = this.ws;
    this.ws = null;
    this.state = 'idle';
    this.authedFp = null;
    if (ws) {
      try { ws.removeAllListeners(); } catch { /* noop */ }
    }
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new TruenasRpcError('TrueNAS WebSocket connection failed'));
    }
    this.pending.clear();
  }

  /** Clears socket state after a close of an established session. */
  private handleClosed(): void {
    const ws = this.ws;
    if (!ws) return; // already reset (failed-handshake path)
    this.ws = null;
    this.state = 'idle';
    this.authedFp = null;
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new TruenasRpcError('TrueNAS WebSocket connection closed'));
    }
    this.pending.clear();
  }

  private onMessage(data: RawData): void {
    let m: JsonRpcResponse<unknown>;
    try {
      m = JSON.parse(String(data)) as JsonRpcResponse<unknown>;
    } catch {
      return; // non-JSON push — ignore
    }
    if (typeof m.id !== 'number') return; // server push / event, not a response to our call
    const p = this.pending.get(m.id);
    if (!p) return;
    this.pending.delete(m.id);
    clearTimeout(p.timer);
    p.resolve(m);
  }

  /** Closes the socket and drops any pending calls. */
  close(): void {
    const ws = this.ws;
    this.ws = null;
    this.state = 'idle';
    this.authedFp = null;
    if (ws) {
      try { ws.removeAllListeners(); ws.terminate(); } catch { /* noop */ }
    }
    for (const p of this.pending.values()) {
      clearTimeout(p.timer);
      p.reject(new TruenasRpcError('client closed'));
    }
    this.pending.clear();
  }

  // ------------------------------------------------------------------- auth

  /**
   * Authenticates on the socket. Uses the API key when provided (TrueNAS 26+
   * requires its owning username), otherwise username/password via
   * auth.login_ex with a legacy auth.login fallback for pre-25.04 boxes.
   * Throws TruenasAuthError on failure.
   */
  async login(creds: TruenasCredentials): Promise<void> {
    const fp = this.fingerprint(creds);
    if (this.authedFp === fp) return; // still valid
    // Dedupe concurrent logins with the same credentials — /monitoring fires
    // several calls in parallel and they must not each run an auth exchange.
    if (this.loginPromise && this.loginPromiseFp === fp) return this.loginPromise;

    const p = this.doLogin(creds, fp);
    this.loginPromise = p;
    this.loginPromiseFp = fp;
    try {
      await p;
    } finally {
      if (this.loginPromise === p) {
        this.loginPromise = null;
        this.loginPromiseFp = null;
      }
    }
  }

  private async doLogin(creds: TruenasCredentials, fp: string): Promise<void> {
    await this.connect();

    if (creds.kind === 'apiKey') {
      const apiKey = creds.apiKey ?? '';
      if (!apiKey) throw new TruenasAuthError('API key is empty');
      // TrueNAS 26+ requires the owning username for API-key login.
      if (!creds.username) {
        throw new TruenasAuthError(
          'TrueNAS 26+ API-key login needs the key\'s owner username — set the "API key owner username" option (e.g. root)'
        );
      }
      const resp = await this.rpc('auth.login_ex', [
        { mechanism: 'API_KEY_PLAIN', username: creds.username, api_key: apiKey },
      ]);
      this.assertLoginSuccess(resp.result, 'TrueNAS rejected the API key (check owner username + key)');
    } else {
      if (!creds.username || !creds.password) {
        throw new TruenasAuthError('Missing username or password for TrueNAS login');
      }
      try {
        const resp = await this.rpc('auth.login_ex', [
          { mechanism: 'PASSWORD_PLAIN', username: creds.username, password: creds.password },
        ]);
        this.assertLoginSuccess(resp.result, `TrueNAS login failed for user "${creds.username}"`);
      } catch (e) {
        if (!(e instanceof TruenasRpcError) || !this.isMethodNotFound(e)) throw e;
        // Pre-25.04 boxes have no auth.login_ex — legacy path returns a boolean.
        const ok = await this.rpc<boolean>('auth.login', [creds.username, creds.password]);
        if (ok.error) throw new TruenasAuthError(this.errorMessage(ok.error));
        if (!ok.result) throw new TruenasAuthError(`TrueNAS login failed for user "${creds.username}"`);
      }
    }

    this.authedFp = fp;
  }

  /** Maps an auth.login_ex result object to success or a descriptive error. */
  private assertLoginSuccess(result: unknown, fallbackMessage: string): void {
    const r = (result ?? {}) as { response_type?: unknown };
    switch (r.response_type) {
      case 'SUCCESS':
        return;
      case 'OTP_REQUIRED':
        throw new TruenasAuthError('TrueNAS requires a one-time password for this account');
      case 'AUTH_ERR':
        throw new TruenasAuthError(fallbackMessage);
      case 'EXPIRED':
        throw new TruenasAuthError('The credential is expired — regenerate it on the appliance');
      default:
        throw new TruenasAuthError(`Unexpected TrueNAS auth response type: ${String(r.response_type)}`);
    }
  }

  // -------------------------------------------------------------------- rpc

  /** One JSON-RPC round-trip on the socket (authenticated or not). */
  private rpc<T>(method: string, params: unknown[], timeoutMs?: number): Promise<JsonRpcResponse<T>> {
    return new Promise((resolve, reject) => {
      void this.connect()
        .then(() => {
          const ws = this.ws;
          if (!ws || ws.readyState !== WebSocket.OPEN) {
            reject(new TruenasRpcError('WebSocket is not open'));
            return;
          }
          const id = this.nextId++;
          // Per-call override (bulk queries on large fleets need more than the
          // default); falls back to the client-wide value.
          const effTimeout = timeoutMs && timeoutMs > 0 ? timeoutMs : this.timeoutMs;
          // Only invalidate the socket THIS call used — a concurrent reconnect
          // may have already swapped in a newer one. A SHORT custom timeout must
          // NOT kill a healthy session (the appliance was just slow), so only
          // timeouts at/above the client default count as "socket likely dead".
          const invalidateOnTimeout = effTimeout >= this.timeoutMs;
          const usedWs = ws;
          const timer = setTimeout(() => {
            this.pending.delete(id);
            if (invalidateOnTimeout && this.ws === usedWs && this.state === 'open') {
              // A round-trip timeout means the socket is likely dead (server-side
              // session drop / half-open TCP). Invalidate it so the NEXT call
              // reconnects + re-authenticates instead of reusing a stuck socket.
              this.ws = null;
              this.state = 'idle';
              this.authedFp = null;
              try { usedWs.removeAllListeners(); usedWs.terminate(); } catch { /* noop */ }
              for (const p of this.pending.values()) {
                clearTimeout(p.timer);
                p.reject(new TruenasRpcError('TrueNAS WebSocket session unresponsive — reconnecting'));
              }
              this.pending.clear();
            }
            reject(new TruenasRpcError(`TrueNAS call ${method} timed out after ${effTimeout} ms`));
          }, Math.max(1000, effTimeout));
          this.pending.set(id, {
            resolve: (v) => resolve(v as JsonRpcResponse<T>),
            reject,
            timer,
          });
          ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }));
        })
        .catch(reject);
    });
  }

  /** True when the error is a JSON-RPC "method does not exist" (pre-25.04 fallback). */
  private isMethodNotFound(e: TruenasRpcError): boolean {
    return e.code === -32601 || /method does not exist/i.test(e.message);
  }

  /**
   * Executes one JSON-RPC method call. Ensures an authenticated session (logging
   * in when needed), and on a lost-session ENOTAUTHENTICATED re-authenticates
   * ONCE and retries — the second failure is surfaced to the caller.
   * `timeoutMs` overrides the client-wide per-call timeout for this one round-trip
   * (bulk queries like app.query/app.image.query on large fleets need more).
   */
  async call<T = unknown>(method: string, params: unknown[] = [], creds?: TruenasCredentials, timeoutMs?: number): Promise<T> {
    if (creds) await this.login(creds);
    if (!this.authedFp) throw new TruenasAuthError('Not authenticated — no credentials supplied');

    const doCall = async (): Promise<JsonRpcResponse<T>> => {
      try {
        return await this.rpc<T>(method, params, timeoutMs);
      } catch (e) {
        if (e instanceof TruenasRpcError && e.code === -32001 && /ENOTAUTHENTICATED/i.test(e.message)) {
          // Session lost server-side → force re-login on the next attempt.
          this.authedFp = null;
          throw new TruenasAuthError('TrueNAS session expired');
        }
        throw e;
      }
    };

    let resp: JsonRpcResponse<T>;
    try {
      resp = await doCall();
    } catch (err) {
      if (!(err instanceof TruenasAuthError) || !creds) throw err;
      // Session expired mid-poll → re-login once and retry the same call.
      this.authedFp = null;
      await this.login(creds);
      resp = await doCall();
    }

    if (resp.error) {
      throw new TruenasRpcError(this.errorMessage(resp.error), resp.error.code, resp.error);
    }
    return resp.result as T;
  }

  /** Human-readable message from a JSON-RPC error object. */
  private errorMessage(err: JsonRpcErrorObject): string {
    const data = err.data;
    if (data && typeof data === 'object' && !Array.isArray(data)) {
      const d = data as { errname?: string; reason?: string };
      return [d.errname, d.reason].filter(Boolean).join(': ') || err.message || `JSON-RPC error ${err.code}`;
    }
    return err.message || `JSON-RPC error ${err.code}`;
  }
}

/** Convenience: a fresh client for one host (used by the probe script too). */
export function createTruenasClient(host: string, transport?: TruenasTransport, timeoutMs?: number): TruenasClient {
  return new TruenasClient(host, transport, timeoutMs);
}
