/**
 * @unm/plugin-sdk — shared SSH client for plugins.
 *
 * Some devices expose data over SSH that their vendor API does not (e.g. TrueNAS
 * SCALE: per-container MAC addresses via `docker inspect`). This module gives any
 * plugin a small, safe SSH exec primitive so the transport logic lives in ONE
 * audited place instead of being re-implemented per plugin.
 *
 * Credential flow (no API changes needed — it rides the existing secrets pipeline):
 *   1. The user creates an `sshKeyPair` or `usernamePassword` secret (the
 *      secrets provider serves both types; sshKeyPair is generatable).
 *   2. The plugin declares a credential slot `{ name: 'ssh', secretType: ... }`
 *      in /discover and advertises the `ssh` capability.
 *   3. On every poll the API delivers the decrypted fields — bound slots under
 *      `credentials.slots.ssh`, or at top level when SSH IS the primary secret.
 *   4. The plugin calls resolveSshCredentials(body.credentials) and gets a
 *      normalized SshCredentials (or undefined → skip the SSH path, best-effort).
 *
 * Security:
 *   - Private keys are NEVER logged or embedded in error messages.
 *   - Host-key verification: pin `hostKeyFingerprint` ("SHA256:<base64>") to get
 *      strict TOFU-free verification (mismatch → SshHostKeyError). Without a pin,
 *      the observed fingerprint is surfaced via onHostKey so the plugin can ship
 *      it to UNM logs for the user to review + pin.
 *
 * Session lifecycle (IMPORTANT — read before using):
 *   A plugin should open ONE session per host and RE-USE it across poll cycles
 *   instead of re-authenticating every 30 s:
 *
 *     // module scope, once at startup:
 *     const sshPool = createSshPool();
 *     process.on('SIGTERM', () => sshPool.closeAll());
 *
 *     // inside /monitoring (every poll):
 *     const creds = resolveSshCredentials(body.credentials);
 *     if (creds) {
 *       const client = await sshPool.get(host, 22, creds, { hostKeyFingerprint });
 *       const r = await client.exec('docker inspect ...', creds);
 *     }
 *
 *   The pool keeps the authenticated session alive between polls (keyed by
 *   host|port|username — never by secret material). A plugin that manages its
 *   own SshClient directly must call close() itself on shutdown; a dropped
 *   connection is detected via socket events and transparently re-established on
 *   the next exec().
 */

import { Client as Ssh2Client } from 'ssh2';
import type { ConnectConfig } from 'ssh2';
import * as crypto from 'crypto';
import { pickString } from './settings';

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** Base class for all SSH failures (plugins can catch this to skip the path). */
export class SshError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

/** Authentication failed (bad username/password or key/passphrase). */
export class SshAuthError extends SshError {}

/** The host presented a different key than the pinned fingerprint. */
export class SshHostKeyError extends SshError {
  /** Fingerprint actually observed on the wire. */
  readonly observedFingerprint: string;
  constructor(message: string, observedFingerprint: string) {
    super(message);
    this.observedFingerprint = observedFingerprint;
  }
}

/** Connect or exec exceeded its timeout budget. */
export class SshTimeoutError extends SshError {}

// ---------------------------------------------------------------------------
// Credentials
// ---------------------------------------------------------------------------

/** Normalized SSH credentials (resolved from a monitoring/config body). */
export interface SshCredentials {
  /** Login user — defaults to 'root' when the secret carries none. */
  username: string;
  /** Password auth (mutually exclusive with privateKey in practice). */
  password?: string;
  /** PEM-encoded private key (ed25519/rsa/ecdsa all work via ssh2). */
  privateKey?: string;
  /** Passphrase protecting the private key, when set. */
  passphrase?: string;
}

/**
 * Resolves SSH credentials from a StepCredentials body (the `credentials` field
 * of POST /monitoring or POST /config). Preference order:
 *   1. A bound credential slot named 'ssh' (fields under slots.ssh) — this is
 *      the documented convention; use it whenever the plugin declares an ssh slot.
 *   2. The PRIMARY secret fields at top level, but only when they actually look
 *      like SSH credentials (a privateKey, or username+password). A primary of a
 *      different type (apiKey, snmp, ...) yields undefined — never misread.
 * Returns undefined when no usable SSH credential is present; callers treat the
 * whole SSH path as best-effort and skip it.
 */
export function resolveSshCredentials(creds?: Record<string, unknown> | null): SshCredentials | undefined {
  if (!creds || typeof creds !== 'object') return undefined;
  const slots = (creds['slots'] ?? {}) as Record<string, Record<string, string>>;
  // Slot wins over primary — a plugin whose PRIMARY is an API key must not be
  // authenticated to the device with that key.
  const src: Record<string, unknown> = slots['ssh'] && typeof slots['ssh'] === 'object' ? slots['ssh'] : creds;
  const username = pickString(src, ['username']);
  const password = pickString(src, ['password']);
  const privateKey = pickString(src, ['privateKey']);
  const passphrase = pickString(src, ['passphrase']) ?? undefined;
  if (privateKey) {
    return { username: username || 'root', privateKey, ...(passphrase ? { passphrase } : {}) };
  }
  if (username && password) {
    return { username, password };
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Host-key fingerprints
// ---------------------------------------------------------------------------

/** Canonical fingerprint form: "SHA256:<base64>" (OpenSSH known_hosts style). */
export type SshFingerprint = string;

/**
 * Normalizes a user-supplied fingerprint to canonical "SHA256:<base64>" form.
 * Accepts "SHA256:abc", "sha256 abc", bare base64, and strips whitespace AND
 * trailing '=' padding — so a value copied from `ssh-keygen -lf` (which omits
 * the padding) matches the SDK's own padded computation of the same key.
 * Returns null when the input is not usable (so callers can treat it as "no pin").
 */
export function normalizeFingerprint(input?: string | null): SshFingerprint | null {
  if (!input) return null;
  let s = String(input).trim();
  if (!s) return null;
  const m = s.match(/^(?:SHA256|sha256)\s*[:=]?\s*(.+)$/);
  if (m) s = m[1].trim();
  // Bare base64 (may contain + / and trailing '=' padding). Anything else is not
  // a fingerprint we can use.
  if (!/^[A-Za-z0-9+\/]+={0,2}$/.test(s)) return null;
  return `SHA256:${s.replace(/=+$/, '')}`;
}

/** True when two fingerprints denote the same key (case-insensitive base64). */
export function fingerprintMatches(a?: string | null, b?: string | null): boolean {
  const na = normalizeFingerprint(a);
  const nb = normalizeFingerprint(b);
  return !!na && !!nb && na === nb;
}

/**
 * Computes the OpenSSH-style SHA-256 fingerprint of a public key: sha256 over
 * the FULL SSH wire-format blob (type-name string + key material), base64-encoded
 * WITHOUT trailing '=' padding — byte-for-byte what `ssh-keygen -lf` prints and
 * what ssh2's hostVerifier receives as its input.
 */
export function computeFingerprint(keyBlob: Buffer): SshFingerprint {
  return `SHA256:${crypto.createHash('sha256').update(keyBlob).digest('base64').replace(/=+$/, '')}`;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/** Result of one remote command. */
export interface ExecResult {
  /** Process exit code (0 = success). */
  code: number;
  stdout: string;
  stderr: string;
}

export interface SshClientOptions {
  host: string;
  port?: number;
  timeoutMs?: number;
  /** Pinned host-key fingerprint — strict verification when set (see normalizeFingerprint). */
  hostKeyFingerprint?: string | null;
  /** Called once after a successful connect with the OBSERVED fingerprint.
   *  Plugins should ship it to UNM logs so users can review + pin it. */
  onHostKey?: (fingerprint: SshFingerprint) => void;
}

interface PoolEntry {
  client: SshClient;
  lastUsedAt: number;
}

/**
 * One SSH session wrapper around ssh2's Client. Designed for RE-USE: a plugin
 * opens one client per host (via createSshPool or directly) and calls exec() on
 * every poll — the authenticated connection is kept alive between polls, so no
 * re-auth happens per cycle. A dropped connection is detected via socket events
 * ('close'/'error') and transparently re-established on the next exec().
 *
 * Ownership: whoever creates the client must close() it (the pool does this for
 * pooled clients; a plugin managing its own client should closeAll/close on
 * SIGTERM/SIGINT).
 */
export class SshClient {
  private readonly opts: Required<Pick<SshClientOptions, 'host' | 'port' | 'timeoutMs'>> & SshClientOptions;
  /** The live ssh2 connection (null = not connected / closed). */
  private conn: Ssh2Client | null = null;
  /** In-flight handshake — concurrent exec() calls share one connect attempt. */
  private connectPromise: Promise<void> | null = null;
  /** True once close() was called by the owner (no auto-reconnect after that). */
  private ownerClosed = false;

  constructor(opts: SshClientOptions) {
    this.opts = { port: 22, timeoutMs: 10_000, ...opts };
  }

  get host(): string {
    return this.opts.host;
  }

  /** True while a live connection is established. */
  get connected(): boolean {
    return !this.ownerClosed && this.conn !== null;
  }

  /** True once the owner called close() — exec() will no longer reconnect. */
  get closedByOwner(): boolean {
    return this.ownerClosed;
  }

  private connect(creds: SshCredentials): Promise<void> {
    if (this.conn) return Promise.resolve(); // already connected — RE-USE, no re-auth
    if (this.connectPromise) return this.connectPromise;
    const o = this.opts;
    const pinned = normalizeFingerprint(o.hostKeyFingerprint);

    // Host-key verification. ssh2's hostVerifier receives the RAW SSH wire-format
    // blob of the server host key (string(type) || key material) — exactly what
    // OpenSSH hashes for its SHA-256 fingerprints, so computeFingerprint() yields
    // the same value `ssh-keygen -lf` prints. We either enforce the pin or surface
    // the fingerprint via onHostKey for logging/pinning.
    const hostVerifier = (key: unknown, cb: (ok: boolean) => void): void => {
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
    };

    const config: ConnectConfig = {
      host: o.host,
      port: o.port,
      username: creds.username,
      readyTimeout: Math.max(3000, o.timeoutMs),
      // Keep the session alive across idle poll gaps so NAT/firewalls don't
      // drop it and force a re-auth on the next cycle.
      keepaliveInterval: 30_000,
      keepaliveCountMax: 3,
      // No agent / known-hosts files — credentials come exclusively from the
      // UNM secrets pipeline (ssh2 only consults agents when explicitly configured).
      ...(creds.privateKey ? { privateKey: creds.privateKey as Buffer | string } : {}),
      ...(creds.passphrase ? { passphrase: creds.passphrase } : {}),
      ...(creds.password ? { password: creds.password } : {}),
      hostVerifier,
    };

    const conn = new Ssh2Client();
    this.conn = conn;
    this.hostKeyMismatch = null;

    // Permanent no-op guard FIRST: a late socket error must never become an
    // unhandled 'error' event that crashes the plugin process (same lesson as
    // truenasClient). The real handler below still runs — multiple listeners OK.
    conn.on('error', () => { /* guarded */ });

    const p = new Promise<void>((resolve, reject) => {
      let settled = false;
      const fail = (e: Error): void => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        this.teardown(); // socket is dead — drop state so the next exec reconnects
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
        // Distinguish a rejected handshake (host-key mismatch / auth failure)
        // from a plain transport error. ssh2 emits 'ready' only on success, so
        // any error before ready is a connect/auth failure.
        if (!settled) {
          const msg = this.hostKeyMismatch ?? (/auth|permission denied|handshake/i.test(err.message)
            ? new SshAuthError(`SSH auth failed for ${o.host}:${o.port}: ${err.message}`)
            : new SshError(`SSH connect to ${o.host}:${o.port} failed: ${err.message}`));
          fail(msg);
        } else {
          // Established session dropped mid-flight — mark dead; next exec() reconnects.
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

  /** Host-key mismatch captured by the verifier (set before the error event). */
  private hostKeyMismatch: SshHostKeyError | null = null;

  /** Drops socket state after a dead connection (keeps ownerClosed intact). */
  private teardown(): void {
    const conn = this.conn;
    this.conn = null;
    if (conn) {
      try { conn.removeAllListeners(); conn.end(); } catch { /* noop */ }
    }
  }

  /**
   * Runs one remote command and resolves with its exit code + output. The first
   * call establishes the connection (with the given credentials); subsequent
   * calls RE-USE the live session — no re-auth per poll cycle. After a drop,
   * the next call reconnects transparently.
   */
  async exec(command: string, creds: SshCredentials): Promise<ExecResult> {
    if (this.ownerClosed) throw new SshError(`SSH client for ${this.opts.host} is closed`);
    await this.connect(creds);
    const conn = this.conn;
    if (!conn) throw new SshError(`SSH connect to ${this.opts.host}:${this.opts.port} failed`);

    return new Promise<ExecResult>((resolve, reject) => {
      let settled = false;
      const timer = setTimeout(() => {
        if (settled) return;
        settled = true;
        this.close(); // a hung exec poisons the session — drop it so the pool can replace it
        reject(new SshTimeoutError(`SSH exec on ${this.opts.host} timed out after ${this.opts.timeoutMs} ms`));
      }, Math.max(3000, this.opts.timeoutMs));

      conn.exec(command, (err: Error | undefined, stream?: import('ssh2').ClientChannel) => {
        if (err || !stream) {
          if (!settled) {
            settled = true;
            clearTimeout(timer);
            this.close(); // session is broken — force a fresh one next time
            reject(err instanceof SshError ? err : new SshError(`SSH exec failed: ${err?.message ?? 'unknown'}`));
          }
          return;
        }
        let stdout = '';
        let stderr = '';
        stream.on('data', (d: Buffer) => { stdout += d.toString(); });
        stream.stderr.on('data', (d: Buffer) => { stderr += d.toString(); });
        stream.on('close', (code: number | null) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          // Truncate defensively — appliance output can be huge, and plugins log it.
          resolve({ code: code ?? -1, stdout: stdout.slice(0, 256 * 1024), stderr: stderr.slice(0, 32 * 1024) });
        });
      });
    });
  }

  /** Closes the connection permanently (owner shutdown). No auto-reconnect after this. */
  close(): void {
    this.ownerClosed = true;
    const conn = this.conn;
    this.conn = null;
    if (conn) {
      try { conn.removeAllListeners(); conn.end(); } catch { /* noop */ }
    }
  }
}

// ---------------------------------------------------------------------------
// Pool
// ---------------------------------------------------------------------------

export interface SshPoolOptions {
  /** Drop idle connections after this long (default 5 min). */
  idleTtlMs?: number;
  /** Max pooled connections (default 64) — oldest evicted beyond that. */
  maxSize?: number;
}

/** Handle returned by createSshPool(). */
export interface SshPool {
  /** Returns a live client for host+port+username, creating one when needed. */
  get(host: string, port: number, creds: SshCredentials, opts?: Partial<SshClientOptions>): Promise<SshClient>;
  /** Closes every pooled connection (plugin shutdown). */
  closeAll(): void;
}

/**
 * Creates a process-wide SSH connection pool. Keyed by host|port|username —
 * NEVER by secret material, so key rotation does not leak into the cache key and
 * two plugins sharing a host reuse one session. Dead clients are evicted lazily
 * on each get(); idle ones after idleTtlMs.
 */
export function createSshPool(opts: SshPoolOptions = {}): SshPool {
  const idleTtlMs = opts.idleTtlMs ?? 5 * 60_000;
  const maxSize = opts.maxSize ?? 64;
  const entries = new Map<string, PoolEntry>();

  return {
    async get(host: string, port: number, creds: SshCredentials, o?: Partial<SshClientOptions>): Promise<SshClient> {
      const key = `${host}|${port}|${creds.username}`;
      const now = Date.now();
      // Evict owner-closed + idle entries (lazy sweep — cheap at plugin scale).
      // Dropped-but-not-closed clients are kept: exec() re-establishes them.
      for (const [k, e] of entries) {
        if (e.client.closedByOwner || now - e.lastUsedAt > idleTtlMs) {
          e.client.close();
          entries.delete(k);
        }
      }
      let entry = entries.get(key);
      if (!entry) {
        const client = new SshClient({ host, port, ...o });
        entry = { client, lastUsedAt: now };
        entries.set(key, entry);
        // Opportunistic size cap — drop the oldest.
        if (entries.size > maxSize) {
          const oldestFirst = [...entries.entries()].sort((a, b) => a[1].lastUsedAt - b[1].lastUsedAt);
          for (const [k, e] of oldestFirst.slice(0, entries.size - maxSize)) {
            if (k === key) continue; // never evict the one we just made
            e.client.close();
            entries.delete(k);
          }
        }
      }
      entry.lastUsedAt = now;
      return entry.client;
    },
    closeAll(): void {
      for (const e of entries.values()) e.client.close();
      entries.clear();
    },
  };
}
