/**
 * @unm/plugin-sdk — shared SFTP file-system client for plugins.
 *
 * Some devices expose their filesystem over SSH/SFTP that their vendor API does
 * not (e.g. TrueNAS SCALE: dataset contents, container volume mounts). This
 * module gives any plugin a small, safe SFTP primitive so the transport logic
 * lives in ONE audited place instead of being re-implemented per plugin — the
 * file-system counterpart of ssh.ts's exec() primitive.
 *
 * Credential flow (identical to ssh.ts — it rides the existing secrets pipeline):
 *   1. The user creates an `sshKeyPair` or `usernamePassword` secret.
 *   2. The plugin declares a credential slot `{ name: 'ssh', ... }` in /discover
 *      and advertises the `filesystem` capability (see types.ts).
 *   3. On every call the API delivers the decrypted fields — bound slots under
 *      `credentials.slots.ssh`, or at top level when SSH IS the primary secret.
 *   4. The plugin calls resolveSshCredentials(body.credentials) and gets a
 *      normalized SshCredentials (or undefined → skip the SFTP path, best-effort).
 *
 * Session lifecycle: an SftpSession wraps ONE authenticated ssh2 connection with
 * its SFTP subsystem channel. A plugin should open ONE session per host and RE-USE
 * it across calls instead of re-authenticating every request — see createSftpPool().
 * The pool keys by host|port|username (NEVER by secret material), so key rotation
 * does not leak into the cache key and two plugins sharing a host reuse one session.
 * A dropped connection is detected via socket events and transparently re-established
 * on the next operation.
 *
 * Security:
 *   - Private keys are NEVER logged or embedded in error messages.
 *   - Host-key verification: pin `hostKeyFingerprint` ("SHA256:<base64>") to get
 *     strict TOFU-free verification (mismatch → SshHostKeyError). Without a pin,
 *     the observed fingerprint is surfaced via onHostKey so the plugin can ship it
 *     to UNM logs for the user to review + pin.
 *   - Path safety: every public method resolves its argument through resolvePath()
 *     and rejects absolute paths that escape the configured root (when a root is set)
 *     or any path containing `..` traversal segments — so a webapp-supplied relative
 *     path can never walk out of the dataset/volume it was scoped to.
 */

import { Readable } from 'node:stream';
import { Client as Ssh2Client, type ConnectConfig, type SFTPWrapper } from 'ssh2';
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
export type SftpCredentials = import('./ssh').SshCredentials;

/** One entry in a directory listing. */
export interface FsEntry {
  /** Entry name (basename, no leading/trailing slash). */
  name: string;
  /** True when the entry is a directory. */
  isDirectory: boolean;
  /** File size in bytes (0 for directories on most servers). */
  sizeBytes: number | null;
  /** Last-modified time as epoch milliseconds (null when unknown). */
  mtimeMs: number | null;
  /** Owner name (when the server reports it), else null. */
  owner?: string | null;
  /** Group name (when the server reports it), else null. */
  group?: string | null;
}

/** Result of a directory listing. */
export interface FsListResult {
  /** The absolute path that was listed (after root resolution). */
  path: string;
  entries: FsEntry[];
}

/** Metadata for one file or directory. */
export interface FsStat {
  isDirectory: boolean;
  sizeBytes: number | null;
  mtimeMs: number | null;
  owner?: string | null;
  group?: string | null;
}

/** Options shared by the read/write/mkdir operations. */
export interface SftpSessionOptions {
  host: string;
  port?: number;
  timeoutMs?: number;
  /** Pinned host-key fingerprint — strict verification when set (see normalizeFingerprint). */
  hostKeyFingerprint?: string | null;
  /** Called once after a successful connect with the OBSERVED fingerprint. */
  onHostKey?: (fingerprint: import('./ssh').SshFingerprint) => void;
  /** Full host-key verifier override — takes precedence over hostKeyFingerprint
   *  (UNM certificate pinning via makeSshHostVerifier). Runs during the handshake,
   *  before any authentication message is sent. */
  hostKeyVerifier?: ((key: unknown, cb: (ok: boolean) => void) => void) | null;
  /** Optional root directory that all paths are resolved against and confined to.
   *  When set, every operation's path is resolved relative to this root and any
   *  attempt to escape it (or use `..`) throws SftpPathError. This is how a plugin
   *  scopes a browser-driven file manager to one dataset or volume mount. */
  root?: string | null;
}

/** Options for createSftpPool(). */
export interface SftpPoolOptions {
  /** Drop idle connections after this long (default 5 min). */
  idleTtlMs?: number;
  /** Max pooled connections (default 64) — oldest evicted beyond that. */
  maxSize?: number;
}

/** Handle returned by createSftpPool(). */
export interface SftpPool {
  /** Returns a live session for host+port, creating one when needed. */
  get(host: string, port: number, creds: SftpCredentials, opts?: Partial<SftpSessionOptions>): Promise<SftpSession>;
  /** Closes every pooled connection (plugin shutdown). */
  closeAll(): void;
}

// ---------------------------------------------------------------------------
// Path safety
// ---------------------------------------------------------------------------

/**
 * Resolves a user-supplied path against an optional root. Rules:
 *   - `..` traversal segments are ALWAYS rejected (SftpPathError) — even inside the
 *     root, they are never legitimate for a browser-driven file manager.
 *   - When `root` is set, the resolved absolute path MUST stay within it; escaping
 *     (e.g. `/etc/passwd` when root is `/mnt/tank`) → SftpPathError.
 *   - A leading `/` with no root means "absolute on the device" — allowed.
 * Returns a normalized absolute path (no `//`, no trailing slash except for root).
 */
export class SftpPathError extends SshError {}

function normalizeSegment(p: string): string {
  // Collapse duplicate slashes, strip trailing slash (keep bare "/").
  let s = p.replace(/\/{2,}/g, '/');
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return s;
}

export function resolvePath(input: string | null | undefined, root?: string | null): string {
  const raw = typeof input === 'string' ? input.trim() : '';
  if (!raw) throw new SftpPathError('Empty path');
  // Reject NUL bytes — a classic injection vector.
  if (raw.includes('\0')) throw new SftpPathError('Invalid path: contains NUL byte');

  const isAbs = raw.startsWith('/');
  const segments = raw.split('/').filter((s) => s.length > 0 && s !== '.');

  // `..` traversal is never allowed — a file manager should navigate by clicking,
  // not by typing parent references. This also blocks the classic /a/b/../../etc escape.
  for (const seg of segments) {
    if (seg === '..') throw new SftpPathError(`Path traversal ("..") is not allowed: ${raw}`);
  }

  let abs: string;
  if (isAbs) {
    abs = '/' + segments.join('/');
  } else {
    const base = root ? normalizeSegment(root) : '/';
    abs = base === '/' ? '/' + segments.join('/') : `${base}/${segments.join('/')}`;
  }

  // When a root is configured, the result must stay inside it. A bare "/" root
  // contains every absolute path (the `r + '/'` prefix check would be "//" and
  // match nothing — that bug broke full-tree browsing for any plugin).
  if (root) {
    const r = normalizeSegment(root);
    if (r !== '/' && abs !== r && !abs.startsWith(r + '/')) {
      throw new SftpPathError(`Path escapes the allowed root ${r}: ${raw}`);
    }
  }
  return abs;
}

// ---------------------------------------------------------------------------
// Session
// ---------------------------------------------------------------------------

interface PoolEntry {
  session: SftpSession;
  lastUsedAt: number;
}

/**
 * One SFTP session wrapper around ssh2's Client + its SFTP subsystem channel.
 * Designed for RE-USE: a plugin opens one session per host (via createSftpPool or
 * directly) and calls list/read/write/etc on every request — the authenticated
 * connection is kept alive between requests, so no re-auth happens per call. A
 * dropped connection is detected via socket events ('close'/'error') and
 * transparently re-established on the next operation.
 *
 * Ownership: whoever creates the session must close() it (the pool does this for
 * pooled sessions; a plugin managing its own session should closeAll/close on
 * SIGTERM/SIGINT).
 */
export class SftpSession {
  private readonly opts: Required<Pick<SftpSessionOptions, 'host' | 'port' | 'timeoutMs'>> & SftpSessionOptions;
  /** The live ssh2 connection (null = not connected / closed). */
  private conn: Ssh2Client | null = null;
  /** The SFTP subsystem channel for the current connection. */
  private sftp: SFTPWrapper | null = null;
  /** In-flight handshake — concurrent operations share one connect attempt. */
  private connectPromise: Promise<void> | null = null;
  /** True once close() was called by the owner (no auto-reconnect after that). */
  private ownerClosed = false;
  /** Host-key mismatch captured by the verifier (set before the error event). */
  private hostKeyMismatch: SshHostKeyError | null = null;

  constructor(opts: SftpSessionOptions) {
    this.opts = { port: 22, timeoutMs: 15_000, ...opts };
  }

  get host(): string {
    return this.opts.host;
  }

  /** True while a live connection is established. */
  get connected(): boolean {
    return !this.ownerClosed && this.conn !== null;
  }

  /** True once the owner called close() — operations will no longer reconnect. */
  get closedByOwner(): boolean {
    return this.ownerClosed;
  }

  private connect(creds: SftpCredentials): Promise<void> {
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
      keepaliveInterval: 30_000,
      keepaliveCountMax: 3,
      ...(creds.privateKey ? { privateKey: normalizePrivateKey(creds.privateKey, creds.passphrase) as Buffer | string } : {}),
      ...(creds.passphrase ? { passphrase: creds.passphrase } : {}),
      ...(creds.password ? { password: creds.password } : {}),
      hostVerifier,
    };

    const conn = new Ssh2Client();
    this.conn = conn;
    this.sftp = null;
    this.hostKeyMismatch = null;

    // Permanent no-op guard FIRST: a late socket error must never become an
    // unhandled 'error' event that crashes the plugin process.
    conn.on('error', () => { /* guarded */ });

    const p = new Promise<void>((resolve, reject) => {
      let settled = false;
      const fail = (e: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.teardown(); // socket is dead — drop state so the next op reconnects
        reject(e);
      };
      const timer = setTimeout(() => {
        fail(new SshTimeoutError(`SFTP connect to ${o.host}:${o.port} timed out after ${o.timeoutMs} ms`));
      }, Math.max(3000, o.timeoutMs));

      conn.on('ready', () => {
        if (settled) return;
        // Open the SFTP subsystem channel as part of "connect" so every operation
        // can assume this.sftp is live. A failure here is a connect failure.
        conn.sftp((err: Error | undefined, sftp?: SFTPWrapper) => {
          if (settled) return;
          if (err || !sftp) {
            fail(new SshError(`SFTP subsystem failed on ${o.host}:${o.port}: ${err?.message ?? 'unknown'}`));
            return;
          }
          settled = true;
          clearTimeout(timer);
          this.sftp = sftp;
          resolve();
        });
      });
      conn.on('error', (err: Error) => {
        if (!settled) {
          const msg = this.hostKeyMismatch ?? (/auth|permission denied|handshake/i.test(err.message)
            ? new SshAuthError(`SSH auth failed for ${o.host}:${o.port}: ${err.message}`)
            : new SshError(`SFTP connect to ${o.host}:${o.port} failed: ${err.message}`));
          fail(msg);
        } else {
          // Established session dropped mid-flight — mark dead; next op reconnects.
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

  /** Drops socket + sftp state after a dead connection (keeps ownerClosed intact). */
  private teardown(): void {
    const conn = this.conn;
    this.conn = null;
    this.sftp = null;
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

  /** Ensures a live connection + SFTP channel, returning the channel. */
  private async ensure(creds: SftpCredentials): Promise<SFTPWrapper> {
    if (this.ownerClosed) throw new SshError(`SFTP session for ${this.opts.host} is closed`);
    await this.connect(creds);
    const sftp = this.sftp;
    if (!sftp || !this.conn) throw new SshError(`SFTP connect to ${this.opts.host}:${this.opts.port} failed`);
    return sftp;
  }

  /** Wraps a callback-style ssh2 call in a promise with the session timeout. */
  private withTimeout<T>(label: string, fn: (cb: (err: Error | undefined, ...args: any[]) => void) => void): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.close(); // a hung op poisons the session — drop it so the pool can replace it
        reject(new SshTimeoutError(`SFTP ${label} on ${this.opts.host} timed out after ${this.opts.timeoutMs} ms`));
      }, Math.max(3000, this.opts.timeoutMs));
      fn((err: Error | undefined, ...args: any[]) => {
        clearTimeout(timer);
        if (err) reject(new SshError(`SFTP ${label} failed: ${err.message}`));
        else resolve(args[0] as T);
      });
    });
  }

  // --- Directory operations -------------------------------------------------

  /** Lists one directory. `path` is resolved against the session root (if any). */
  async list(path: string, creds: SftpCredentials): Promise<FsListResult> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    const entries = await this.withTimeout<import('ssh2').FileEntryWithStats[]>(`readdir ${abs}`, (cb) =>
      sftp.readdir(abs, cb as any),
    );
    return {
      path: abs,
      entries: entries.map((e) => toFsEntry(e)),
    };
  }

  /** Creates a directory. `parents=true` creates intermediate directories as needed. */
  async mkdir(path: string, creds: SftpCredentials, parents = false): Promise<void> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    if (parents) {
      // Walk the path segments from root down, creating each missing level.
      // STAT-FIRST: OpenSSH SFTP answers EEXIST with a generic "Failure" status
      // (no message to match), so error-text sniffing is unreliable — check
      // whether the directory already exists before attempting to create it.
      const parts = abs.split('/').filter(Boolean);
      let cur = '';
      for (const part of parts) {
        cur += '/' + part;
        try {
          await this.withTimeout<import('ssh2').Stats>(`stat ${cur}`, (cb) => sftp.stat(cur, cb as any));
          continue; // already exists — descend into it
        } catch (e) {
          if (!(e instanceof SshError) || !/no such file|not found/i.test(e.message)) throw e;
        }
        await this.withTimeout<void>(`mkdir ${cur}`, (cb) => sftp.mkdir(cur, cb as any));
      }
    } else {
      await this.withTimeout<void>(`mkdir ${abs}`, (cb) => sftp.mkdir(abs, cb as any));
    }
  }

  /** Removes an EMPTY directory. */
  async rmdir(path: string, creds: SftpCredentials): Promise<void> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    await this.withTimeout<void>(`rmdir ${abs}`, (cb) => sftp.rmdir(abs, cb as any));
  }

  // --- File operations ------------------------------------------------------

  /** Reads a file's full contents. `maxBytes` caps the transfer (default 10 MiB). */
  async readFile(path: string, creds: SftpCredentials, maxBytes = 10 * 1024 * 1024): Promise<Buffer> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    return new Promise<Buffer>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.close();
        reject(new SshTimeoutError(`SFTP read ${abs} timed out after ${this.opts.timeoutMs} ms`));
      }, Math.max(3000, this.opts.timeoutMs));
      const chunks: Buffer[] = [];
      let total = 0;
      const rs = sftp.createReadStream(abs);
      rs.on('data', (d: Buffer) => {
        total += d.length;
        if (total > maxBytes) {
          rs.destroy();
          clearTimeout(timer);
          reject(new SshError(`SFTP read ${abs} exceeded the ${maxBytes}-byte limit`));
          return;
        }
        chunks.push(d);
      });
      rs.on('error', (err: Error) => {
        clearTimeout(timer);
        this.close(); // a broken stream poisons the session — force a fresh one next time
        reject(new SshError(`SFTP read ${abs} failed: ${err.message}`));
      });
      rs.on('close', () => {
        clearTimeout(timer);
        resolve(Buffer.concat(chunks));
      });
    });
  }

  /** Writes a file's full contents (creates or truncates the target). */
  async writeFile(path: string, data: Buffer | string, creds: SftpCredentials): Promise<void> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    const buf = typeof data === 'string' ? Buffer.from(data) : data;
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.close();
        reject(new SshTimeoutError(`SFTP write ${abs} timed out after ${this.opts.timeoutMs} ms`));
      }, Math.max(3000, this.opts.timeoutMs));
      const ws = sftp.createWriteStream(abs);
      ws.on('error', (err: Error) => {
        clearTimeout(timer);
        this.close();
        reject(new SshError(`SFTP write ${abs} failed: ${err.message}`));
      });
      ws.end(buf, () => {
        // 'close' fires after the final flush is acknowledged.
      });
      ws.on('close', () => {
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /**
   * Streams a readable into the target file (creates or truncates it) — the
   * multi-GB-safe counterpart of writeFile(): nothing is buffered in memory.
   * Resolves when the final flush is acknowledged by the server. The session's
   * timeoutMs acts as an IDLE timer (cleared on every chunk); a stalled transfer
   * closes the session so the pool can replace it with a fresh connection.
   */
  async writeStream(path: string, source: Readable, creds: SftpCredentials): Promise<void> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    return new Promise<void>((resolve, reject) => {
      let settled = false;
      const fail = (e: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try { source.destroy(); } catch { /* noop */ }
        this.close(); // a broken stream poisons the session — force a fresh one next time
        reject(e);
      };
      const timer = setTimeout(() => {
        fail(new SshTimeoutError(`SFTP write ${abs} stalled (no data for ${this.opts.timeoutMs} ms)`));
      }, Math.max(3000, this.opts.timeoutMs));

      const ws = sftp.createWriteStream(abs);
      ws.on('error', (err: Error) => fail(new SshError(`SFTP write ${abs} failed: ${err.message}`)));
      source.on('data', (chunk: Buffer | string) => {
        clearTimeout(timer); // bytes are flowing — reset the idle timer
        if (!ws.write(chunk)) {
          // Backpressure: pause the source until the SFTP window drains.
          source.pause();
          ws.once('drain', () => { try { source.resume(); } catch { /* noop */ } });
        }
      });
      source.on('error', (err: Error) => fail(new SshError(`reading source for ${abs} failed: ${err.message}`)));
      source.on('end', () => {
        ws.end(() => { /* 'close' fires after the final flush is acknowledged */ });
      });
      ws.on('close', () => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        resolve();
      });
    });
  }

  /** Deletes a file (or symlink). Directories require rmdir(). */
  async unlink(path: string, creds: SftpCredentials): Promise<void> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    await this.withTimeout<void>(`unlink ${abs}`, (cb) => sftp.unlink(abs, cb as any));
  }

  /** Renames / moves a file or directory. */
  async rename(from: string, to: string, creds: SftpCredentials): Promise<void> {
    const absFrom = resolvePath(from, this.opts.root);
    const absTo = resolvePath(to, this.opts.root);
    const sftp = await this.ensure(creds);
    await this.withTimeout<void>(`rename ${absFrom} → ${absTo}`, (cb) => sftp.rename(absFrom, absTo, cb as any));
  }

  /** Returns metadata for one file or directory. */
  async stat(path: string, creds: SftpCredentials): Promise<FsStat> {
    const abs = resolvePath(path, this.opts.root);
    const sftp = await this.ensure(creds);
    const stats = await this.withTimeout<import('ssh2').Stats>(`stat ${abs}`, (cb) => sftp.stat(abs, cb as any));
    return toFsStat(stats);
  }

  /** Closes the connection permanently (owner shutdown). No auto-reconnect after this. */
  close(): void {
    this.ownerClosed = true;
    const conn = this.conn;
    this.conn = null;
    this.sftp = null;
    if (conn) {
      try {
        // Same late-error guard as teardown().
        conn.removeAllListeners();
        conn.on('error', () => { /* permanent guard */ });
        conn.end();
      } catch { /* noop */ }
    }
  }

  /** The configured root (if any) — exposed for diagnostics/UI hints. */
  get root(): string | null {
    return this.opts.root ?? null;
  }

  /**
   * Resolves a user-supplied path against the session root WITHOUT performing an
   * SFTP operation — useful to compute the absolute target before calling list/
   * read/etc. Empty or "/" resolves to the root itself (or "/" when no root is set).
   * Throws SftpPathError on `..` traversal or root escape, exactly like every other op.
   */
  resolve(input?: string | null): string {
    const raw = typeof input === 'string' ? input.trim() : '';
    if (!raw || raw === '/') return this.opts.root ?? '/';
    return resolvePath(raw, this.opts.root);
  }
}

// ---------------------------------------------------------------------------
// ssh2 stat/entry → normalized shapes
// ---------------------------------------------------------------------------

function toFsEntry(e: import('ssh2').FileEntryWithStats): FsEntry {
  const a = e.attrs;
  // S_IFDIR (0o40000) in the mode field marks directories. Some servers omit
  // `mode` — fall back to the longname's leading 'd' when present.
  let isDir: boolean;
  if (typeof a?.mode === 'number') {
    isDir = (a.mode & 0o170000) === 0o40000;
  } else {
    isDir = typeof e.longname === 'string' && e.longname.startsWith('d');
  }
  return {
    name: e.filename,
    isDirectory: isDir,
    sizeBytes: typeof a?.size === 'number' ? a.size : null,
    mtimeMs: typeof a?.mtime === 'number' ? a.mtime * 1000 : null,
    owner: (a as any)?.uid != null ? String((a as any).uid) : null,
    group: (a as any)?.gid != null ? String((a as any).gid) : null,
  };
}

function toFsStat(s: import('ssh2').Stats): FsStat {
  const isDir = typeof s.mode === 'number' && (s.mode & 0o170000) === 0o40000;
  return {
    isDirectory: isDir,
    sizeBytes: typeof s.size === 'number' ? s.size : null,
    mtimeMs: typeof s.mtime === 'number' ? s.mtime * 1000 : null,
    owner: (s as any).uid != null ? String((s as any).uid) : null,
    group: (s as any).gid != null ? String((s as any).gid) : null,
  };
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

/**
 * Creates a process-wide SFTP session pool. Keyed by host|port — NEVER by secret
 * material, so key rotation does not leak into the cache key and two plugins
 * sharing a host reuse one session. Dead sessions are evicted lazily on each get();
 * idle ones after idleTtlMs.
 */
export function createSftpPool(opts: SftpPoolOptions = {}): SftpPool {
  const idleTtlMs = opts.idleTtlMs ?? 5 * 60_000;
  const maxSize = opts.maxSize ?? 64;
  const entries = new Map<string, PoolEntry>();

  return {
    async get(host: string, port: number, creds: SftpCredentials, o?: Partial<SftpSessionOptions>): Promise<SftpSession> {
      // Key includes the root scope so two different roots on the same host get
      // distinct pooled connections (a session's confinement is fixed at creation).
      const key = `${host}|${port}|${o?.root ?? ''}`;
      const now = Date.now();
      // Evict owner-closed + idle entries (lazy sweep — cheap at plugin scale).
      for (const [k, e] of entries) {
        if (e.session.closedByOwner || now - e.lastUsedAt > idleTtlMs) {
          e.session.close();
          entries.delete(k);
        }
      }
      let entry = entries.get(key);
      if (!entry) {
        const session = new SftpSession({ host, port, ...o });
        entry = { session, lastUsedAt: now };
        entries.set(key, entry);
        // Opportunistic size cap — drop the oldest.
        if (entries.size > maxSize) {
          const oldestFirst = [...entries.entries()].sort((a, b) => a[1].lastUsedAt - b[1].lastUsedAt);
          for (const [k, e] of oldestFirst.slice(0, entries.size - maxSize)) {
            if (k === key) continue; // never evict the one we just made
            e.session.close();
            entries.delete(k);
          }
        }
      }
      entry.lastUsedAt = now;
      return entry.session;
    },
    closeAll(): void {
      for (const e of entries.values()) e.session.close();
      entries.clear();
    },
  };
}
