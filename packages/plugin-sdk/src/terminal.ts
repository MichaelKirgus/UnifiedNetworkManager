/**
 * @unm/plugin-sdk — shared interactive SSH terminal (console) for plugins.
 *
 * Some devices are best operated the way an operator would from a laptop: an
 * interactive shell over SSH (TrueNAS SCALE's own web UI does exactly this).
 * This module gives any plugin the transport half of that experience — a PTY
 * session primitive plus a WebSocket bridge helper — so the logic lives in ONE
 * audited place instead of being re-implemented per plugin. It is the
 * interactive counterpart of ssh.ts's exec() (one-shot commands) and sftp.ts
 * (file operations).
 *
 * End-to-end flow (see docs/PLUGIN-DEVELOPMENT.md, "SSH console"):
 *   1. The webapp mints a short-lived CONSOLE TICKET from the API
 *      (POST /devices/:id/console — gated on devices:write) and opens a
 *      WebSocket to the API with that ticket.
 *   2. The API verifies the user + ticket, resolves FRESH credentials and
 *      connects to the plugin's WebSocket endpoint (`/console` by convention).
 *   3. The plugin redeems the ticket back at the API (internal route) and gets
 *      { managementAddress, sshSlot, context } — it NEVER sees the user's JWT.
 *   4. The plugin opens a PTY session here (openShell for a host login shell,
 *      openExec for e.g. `docker exec -it <name> /bin/sh`) and pipes bytes:
 *        browser ⇄ API ⇄ plugin = WebSocket frames (binary = raw terminal I/O,
 *        text = JSON control messages), plugin ⇄ device = one ssh2 channel.
 *
 * Credential flow (identical to ssh.ts/sftp.ts — it rides the existing secrets
 * pipeline): the user binds an `ssh` slot (usernamePassword or sshKeyPair); the
 * API delivers it decrypted on every call; normalize with resolveSshCredentials().
 *
 * Session lifecycle:
 *   - A SshTerminalConnection wraps ONE authenticated ssh2 connection and is
 *     POOLED per host|port|username (createTerminalPool) — consoles reuse the
 *     authenticated TCP/SSH session instead of re-handshaking per terminal.
 *   - Each console opens its OWN channel on that connection (openShell /
 *     openExec), so several users can hold concurrent terminals to one device;
 *     closing a terminal never disturbs the others or the pool entry.
 *   - A dropped connection is detected via socket events and transparently
 *     re-established by the next openShell/openExec call.
 *
 * Security:
 *   - Private keys are NEVER logged or embedded in error messages.
 *   - Host-key verification: pin `hostKeyFingerprint` ("SHA256:<base64>") for
 *     strict verification (mismatch → SshHostKeyError); without a pin the
 *     observed fingerprint is surfaced via onHostKey for review + pinning.
 *   - The WebSocket bridge itself carries NO credentials — only an opaque,
 *     single-purpose, 60 s ticket that the plugin redeems over the authenticated
 *     internal API route (x-plugin-api-key). Nothing secret ever travels in a
 *     URL or across the browser boundary.
 */

import { EventEmitter } from 'events';
import { Client as Ssh2Client, type ConnectConfig } from 'ssh2';
import {
  SshError,
  SshAuthError,
  SshHostKeyError,
  SshTimeoutError,
  normalizeFingerprint,
  fingerprintMatches,
  computeFingerprint,
  normalizePrivateKey,
} from './ssh';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** Normalized SSH credentials (re-exported for convenience — see ssh.ts). */
export type TerminalCredentials = import('./ssh').SshCredentials;

/** PTY geometry + terminal type for one interactive session. */
export interface TerminalPtyOptions {
  /** Columns (default 80). */
  cols?: number;
  /** Rows (default 24). */
  rows?: number;
  /** $TERM value advertised to the remote side (default 'xterm-256color'). */
  term?: string;
}

/** Options for a terminal connection (same host-key model as ssh.ts/sftp.ts). */
export interface TerminalConnectionOptions {
  host: string;
  port?: number;
  /** Connect/handshake timeout budget (default 15 s). Interactive sessions have NO per-op timeout — they are long-lived by design. */
  timeoutMs?: number;
  /** Pinned host-key fingerprint — strict verification when set. */
  hostKeyFingerprint?: string | null;
  /** Called once after a successful connect with the OBSERVED fingerprint. */
  onHostKey?: (fingerprint: import('./ssh').SshFingerprint) => void;
  /** Full host-key verifier override — takes precedence over hostKeyFingerprint
   *  (UNM certificate pinning via makeSshHostVerifier). Runs during the handshake,
   *  before any authentication message is sent. */
  hostKeyVerifier?: ((key: unknown, cb: (ok: boolean) => void) => void) | null;
}

/** Options for createTerminalPool(). */
export interface TerminalPoolOptions {
  /** Drop idle connections (no open sessions) after this long (default 5 min). */
  idleTtlMs?: number;
  /** Max pooled connections (default 64) — oldest evicted beyond that. */
  maxSize?: number;
}

// ---------------------------------------------------------------------------
// Session — one interactive channel (PTY shell or PTY exec command)
// ---------------------------------------------------------------------------

/**
 * One interactive SSH session: a single ssh2 session channel with an allocated
 * PTY, exposed as an EventEmitter. Events:
 *   - 'data'  (Buffer) — remote output (stdout+stderr merged; a PTY merges them anyway).
 *   - 'exit'  ({ code }) — the remote command/shell finished (code may be null → -1).
 *   - 'error' (Error) — transport/session failure.
 *   - 'close' () — the channel is gone (always after exit/error or close()).
 *
 * Ownership: created via SshTerminalConnection.openShell/openExec; call close()
 * when the browser side goes away so the channel is released promptly.
 */
export class SshTerminalSession extends EventEmitter {
  private readonly conn: Ssh2Client;
  /** The live session channel (null once closed). */
  private chan: import('ssh2').ClientChannel | null = null;
  private ownerClosed = false;

  constructor(conn: Ssh2Client) {
    super();
    this.conn = conn;
  }

  get connected(): boolean {
    return !this.ownerClosed && this.chan !== null;
  }

  /** Wires one freshly-opened session channel to the emitter. */
  attach(chan: import('ssh2').ClientChannel): void {
    this.chan = chan;
    // Permanent no-op guard FIRST — a late async error must never become an
    // unhandled 'error' event that crashes the plugin process (same lesson as ssh.ts).
    chan.on('error', () => { /* guarded */ });

    chan.on('data', (d: Buffer) => this.emit('data', d));
    // Merge stderr into the same stream — a terminal wants ONE byte order, and
    // with a PTY the remote side already interleaves them.
    const err = (chan as unknown as { stderr?: { on?: (ev: string, cb: (d: Buffer) => void) => unknown } }).stderr;
    if (err && typeof err.on === 'function') {
      err.on('data', (d: Buffer) => this.emit('data', d));
    }
    chan.on('close', (code?: number | null) => {
      const c = typeof code === 'number' ? code : -1;
      this.chan = null;
      this.emit('exit', { code: c });
      this.emit('close');
    });
    chan.on('error', (err: Error) => {
      if (!this.ownerClosed && this.chan !== null) {
        this.chan = null;
        this.emit('error', err instanceof SshError ? err : new SshError(`Terminal session failed: ${err.message}`));
        this.emit('close');
      }
    });
  }

  /** Writes raw input to the remote PTY (keyboard bytes from the browser).
   *  Buffers are written VERBATIM — a string is UTF-8 encoded first. Never pass
   *  latin-1-decoded strings: ssh2 re-encodes them and non-ASCII would corrupt. */
  write(data: string | Buffer): void {
    const chan = this.chan;
    if (!chan || !chan.writable) return; // closed — drop silently, like a dead terminal
    try {
      chan.write(typeof data === 'string' ? Buffer.from(data, 'utf8') : data);
    } catch { /* channel gone mid-write */ }
  }

  /** Resizes the remote PTY (window-change). No-op when not connected. */
  resize(cols: number, rows: number): void {
    const chan = this.chan as unknown as { setWindow?: (rows: number, cols: number, height: number, width: number) => void } | null;
    if (!chan || typeof chan.setWindow !== 'function') return;
    try {
      // ssh2's Channel.setWindow(rows, cols, height, width) — pixel dims unused.
      chan.setWindow(Math.max(1, rows), Math.max(1, cols), 0, 0);
    } catch { /* channel gone mid-resize */ }
  }

  /** Closes the channel (browser disconnect / owner shutdown). Idempotent. */
  close(): void {
    if (this.ownerClosed) return;
    this.ownerClosed = true;
    const chan = this.chan;
    this.chan = null;
    if (chan) {
      try {
        chan.removeAllListeners();
        chan.on('error', () => { /* permanent guard */ });
        chan.end();
        chan.close();
      } catch { /* noop */ }
    }
    this.emit('close');
  }
}

// ---------------------------------------------------------------------------
// Connection — one pooled authenticated ssh2 client (channels multiplex on it)
// ---------------------------------------------------------------------------

interface PoolEntry {
  conn: SshTerminalConnection;
  lastUsedAt: number;
}

/**
 * One authenticated SSH connection that can host MULTIPLE concurrent terminal
 * sessions (each openShell/openExec opens a fresh session channel). Designed
 * for RE-USE via createTerminalPool(): the handshake happens once per
 * host|port|username and consoles share it. A dropped connection is detected
 * via socket events; the next open*() call reconnects transparently.
 */
export class SshTerminalConnection {
  private readonly opts: Required<Pick<TerminalConnectionOptions, 'host' | 'port' | 'timeoutMs'>> & TerminalConnectionOptions;
  /** The live ssh2 connection (null = not connected / closed). */
  private conn: Ssh2Client | null = null;
  /** In-flight handshake — concurrent open*() calls share one connect attempt. */
  private connectPromise: Promise<void> | null = null;
  /** True once close() was called by the owner (no auto-reconnect after that). */
  private ownerClosed = false;
  /** Host-key mismatch captured by the verifier (set before the error event). */
  private hostKeyMismatch: SshHostKeyError | null = null;
  /** Open sessions on this connection (for pool idle accounting + closeAll). */
  readonly sessions = new Set<SshTerminalSession>();

  constructor(opts: TerminalConnectionOptions) {
    this.opts = { port: 22, timeoutMs: 15_000, ...opts };
  }

  get host(): string {
    return this.opts.host;
  }

  get connected(): boolean {
    return !this.ownerClosed && this.conn !== null;
  }

  get closedByOwner(): boolean {
    return this.ownerClosed;
  }

  private connect(creds: TerminalCredentials): Promise<void> {
    if (this.conn) return Promise.resolve(); // already connected — RE-USE, no re-auth
    if (this.connectPromise) return this.connectPromise;
    const o = this.opts;
    const pinned = normalizeFingerprint(o.hostKeyFingerprint);

    // A full verifier override (hostKeyVerifier — UNM certificate pinning) takes
    // precedence over the built-in hostKeyFingerprint logic.
    const hostVerifier = o.hostKeyVerifier ?? ((key: unknown, cb: (ok: boolean) => void): void => {
      try {
        if (!Buffer.isBuffer(key)) {
          cb(true); // unexpected shape — accept (nothing to compare against)
          return;
        }
        const fp = computeFingerprint(key);
        if (pinned && !fingerprintMatches(pinned, fp)) {
          this.hostKeyMismatch = new SshHostKeyError(
            `Host key mismatch for ${o.host}:${o.port} — expected ${pinned}, observed ${fp}`,
            fp
          );
          cb(false); // reject the handshake; connect() surfaces SshHostKeyError
          return;
        }
        o.onHostKey?.(fp);
        cb(true);
      } catch {
        cb(true); // verifier must never throw into ssh2's internals
      }
    });

    const config: ConnectConfig = {
      host: o.host,
      port: o.port,
      username: creds.username,
      readyTimeout: Math.max(3000, o.timeoutMs),
      // Consoles are long-lived — keep the session alive across idle gaps so
      // NAT/firewalls don't drop it mid-terminal.
      keepaliveInterval: 30_000,
      keepaliveCountMax: 3,
      ...(creds.privateKey ? { privateKey: normalizePrivateKey(creds.privateKey, creds.passphrase) as Buffer | string } : {}),
      ...(creds.passphrase ? { passphrase: creds.passphrase } : {}),
      ...(creds.password ? { password: creds.password } : {}),
      hostVerifier,
    };

    const conn = new Ssh2Client();
    this.conn = conn;
    this.hostKeyMismatch = null;

    // Permanent no-op guard FIRST (see ssh.ts teardown notes).
    conn.on('error', () => { /* guarded */ });

    const p = new Promise<void>((resolve, reject) => {
      let settled = false;
      const fail = (e: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.teardown(); // socket is dead — drop state so the next open* reconnects
        reject(e);
      };
      const timer = setTimeout(() => {
        fail(new SshTimeoutError(`SSH connect to ${o.host}:${o.port} timed out after ${o.timeoutMs} ms`));
      }, Math.max(3000, o.timeoutMs));

      conn.on('ready', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      });
      conn.on('error', (err: Error) => {
        if (!settled) {
          const msg = this.hostKeyMismatch ?? (/auth|permission denied|handshake/i.test(err.message)
            ? new SshAuthError(`SSH auth failed for ${o.host}:${o.port}: ${err.message}`)
            : new SshError(`SSH connect to ${o.host}:${o.port} failed: ${err.message}`));
          fail(msg);
        } else {
          // Established connection dropped mid-flight — mark dead; next open* reconnects.
          this.teardown();
        }
      });
      conn.on('close', () => {
        if (!settled) return; // connect-failure path already handled it
        this.teardown();
      });

      try {
        conn.connect(config);
      } catch (e) {
        fail(e instanceof Error ? e : new SshError(String(e)));
      }
    }).finally(() => {
      if (this.connectPromise === p) this.connectPromise = null;
    });
    this.connectPromise = p;
    return p;
  }

  /** Drops socket state after a dead connection (keeps ownerClosed intact). */
  private teardown(): void {
    const conn = this.conn;
    this.conn = null;
    if (conn) {
      try {
        // Same late-error guard as ssh.ts: a no-op 'error' listener must survive
        // removeAllListeners(), or ssh2's async error events crash the process.
        conn.removeAllListeners();
        conn.on('error', () => { /* permanent guard */ });
        conn.end();
      } catch { /* noop */ }
    }
  }

  private ensure(creds: TerminalCredentials): Promise<Ssh2Client> {
    if (this.ownerClosed) return Promise.reject(new SshError(`Terminal connection for ${this.opts.host} is closed`));
    return this.connect(creds).then(() => {
      const conn = this.conn;
      if (!conn) throw new SshError(`SSH connect to ${this.opts.host}:${this.opts.port} failed`);
      return conn;
    });
  }

  private track(session: SshTerminalSession): void {
    this.sessions.add(session);
    const drop = (): void => { this.sessions.delete(session); };
    session.on('close', drop);
  }

  /**
   * Opens an interactive LOGIN SHELL (PTY) on a fresh session channel. This is
   * the "connect to the host like PuTTY" path — the user's real shell with its
   * rc files, exactly what TrueNAS' own web console does.
   */
  async openShell(creds: TerminalCredentials, pty?: TerminalPtyOptions): Promise<SshTerminalSession> {
    const conn = await this.ensure(creds);
    return new Promise<SshTerminalSession>((resolve, reject) => {
      const session = new SshTerminalSession(conn);
      try {
        conn.shell({ term: pty?.term ?? 'xterm-256color', cols: pty?.cols ?? 80, rows: pty?.rows ?? 24 }, (err: Error | undefined, chan?: import('ssh2').ClientChannel) => {
          if (err || !chan) {
            reject(err instanceof SshError ? err : new SshError(`SSH shell failed: ${err?.message ?? 'unknown'}`));
            return;
          }
          session.attach(chan);
          this.track(session);
          resolve(session);
        });
      } catch (e) {
        reject(e instanceof Error ? e : new SshError(String(e)));
      }
    });
  }

  /**
   * Runs ONE command with an allocated PTY on a fresh session channel — the
   * "execute something in a container" path, e.g. `docker exec -it <name> /bin/sh`.
   * The outer SSH PTY is what makes docker's `-t` work (TTY + resize propagation).
   */
  async openExec(command: string, creds: TerminalCredentials, pty?: TerminalPtyOptions): Promise<SshTerminalSession> {
    const conn = await this.ensure(creds);
    return new Promise<SshTerminalSession>((resolve, reject) => {
      const session = new SshTerminalSession(conn);
      try {
        conn.exec(command, { pty: { term: pty?.term ?? 'xterm-256color', cols: pty?.cols ?? 80, rows: pty?.rows ?? 24 } }, (err: Error | undefined, chan?: import('ssh2').ClientChannel) => {
          if (err || !chan) {
            reject(err instanceof SshError ? err : new SshError(`SSH exec failed: ${err?.message ?? 'unknown'}`));
            return;
          }
          session.attach(chan);
          this.track(session);
          resolve(session);
        });
      } catch (e) {
        reject(e instanceof Error ? e : new SshError(String(e)));
      }
    });
  }

  /** Closes the connection permanently + every open session on it. */
  close(): void {
    if (this.ownerClosed) return;
    this.ownerClosed = true;
    for (const s of [...this.sessions]) s.close();
    const conn = this.conn;
    this.conn = null;
    if (conn) {
      try {
        conn.removeAllListeners();
        conn.on('error', () => { /* permanent guard */ });
        conn.end();
      } catch { /* noop */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/** Handle returned by createTerminalPool(). */
export interface TerminalPool {
  /** Returns a live connection for host+port+username, creating one when needed. */
  get(host: string, port: number, creds: TerminalCredentials, opts?: Partial<TerminalConnectionOptions>): Promise<SshTerminalConnection>;
  /** Closes every pooled connection (plugin shutdown). */
  closeAll(): void;
}

/**
 * Creates a process-wide SSH terminal connection pool. Keyed by host|port|username —
 * NEVER by secret material, so key rotation does not leak into the cache key and
 * two plugins sharing a host reuse one authenticated session. Idle entries (no
 * open sessions) are evicted after idleTtlMs; dead ones lazily on each get().
 */
export function createTerminalPool(opts: TerminalPoolOptions = {}): TerminalPool {
  const idleTtlMs = opts.idleTtlMs ?? 5 * 60_000;
  const maxSize = opts.maxSize ?? 64;
  const entries = new Map<string, PoolEntry>();

  return {
    async get(host: string, port: number, creds: TerminalCredentials, o?: Partial<TerminalConnectionOptions>): Promise<SshTerminalConnection> {
      const key = `${host}|${port}|${creds.username}`;
      const now = Date.now();
      // Evict owner-closed + idle entries (lazy sweep — cheap at plugin scale).
      for (const [k, e] of entries) {
        if (e.conn.closedByOwner || (e.conn.sessions.size === 0 && now - e.lastUsedAt > idleTtlMs)) {
          e.conn.close();
          entries.delete(k);
        }
      }
      let entry = entries.get(key);
      if (!entry) {
        const conn = new SshTerminalConnection({ host, port, ...o });
        entry = { conn, lastUsedAt: now };
        entries.set(key, entry);
        // Opportunistic size cap — drop the oldest.
        if (entries.size > maxSize) {
          const oldestFirst = [...entries.entries()].sort((a, b) => a[1].lastUsedAt - b[1].lastUsedAt);
          for (const [k, e] of oldestFirst.slice(0, entries.size - maxSize)) {
            if (k === key) continue; // never evict the one we just made
            e.conn.close();
            entries.delete(k);
          }
        }
      }
      entry.lastUsedAt = now;
      return entry.conn;
    },
    closeAll(): void {
      for (const e of entries.values()) e.conn.close();
      entries.clear();
    },
  };
}
