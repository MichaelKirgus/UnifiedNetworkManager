/**
 * Generic SSH plugin — privilege escalation (sudo / root slot).
 *
 * Many Linux boxes are managed with a NON-root login user. User-level reads
 * (/proc, /sys) still work, but privileged commands (package manager queries,
 * route writes, snapshot restore) fail. This module resolves the best available
 * execution mode for one host and hands out an ElevatedBackend that transparently
 * runs commands with root privileges:
 *
 *   1. `root` credential slot bound + login verified as uid 0
 *        → ALL commands run on a direct SSH session as that user (no sudo at all).
 *   2. primary login is already uid 0
 *        → plain exec, exactly like before this feature existed.
 *   3. primary has PASSWORDLESS sudo (`sudo -n true` succeeds)
 *        → commands are wrapped in `sudo sh -c '…'` (optionally as another user).
 *   4. nothing else works
 *        → plain exec; privileged sections degrade exactly like before
 *          (best-effort POSIX — a missing capability never sinks the poll).
 *
 * The probe result is cached per host+credential-identity for 10 minutes so a
 * dead box or a bad root secret costs at most one extra auth attempt per cache
 * window, not one per poll.
 */

import { probePrivilege, resolveRootSlotCredentials, wrapSudo } from '@unm/plugin-sdk';
import type { ExecResult } from '@unm/plugin-sdk';
import { SshBackend } from './sshClient';
import type { SshSection } from './sshClient';

/** The execution mode resolved for one host. */
export interface PrivilegeContext {
  /** 'root' = commands already run as root (uid-0 login or direct root session).
   *  'sudo' = passwordless sudo is available and commands get wrapped in it. */
  mode: 'root' | 'sudo';
  /** True when a privileged command was actually verified to succeed. */
  verified: boolean;
  /** True when a dedicated `root` slot session is active (mode is always 'root'). */
  hasRootSession?: boolean;
}

/** The command surface every collector/action needs — SshBackend satisfies it
 *  structurally, so pre-existing call sites keep working unchanged. */
export interface CommandRunner {
  host: string;
  exec(command: string, timeoutMs?: number): Promise<ExecResult>;
  runSections(sections: SshSection[], timeoutMs?: number): Promise<Map<string, string>>;
  /** Human-readable description of the effective execution mode (for metrics
   *  + logs). Optional — a plain user-level backend simply has none. */
  describePrivilege?(): string;
}

/** A backend that transparently elevates commands to root when needed. */
export class ElevatedBackend implements CommandRunner {
  constructor(
    readonly host: string,
    private readonly user: SshBackend,
    /** Direct root-slot session (validated uid 0), or undefined. */
    private readonly root?: SshBackend,
    readonly priv: PrivilegeContext = { mode: 'root', verified: true },
    /** Optional sudo target user (`sudo -u <user>`); empty = default (root). */
    private readonly sudoUser?: string,
  ) {}

  /** True when a command should run on the direct root session. */
  get useRootSession(): boolean {
    return this.root !== undefined;
  }

  /** What mode this backend actually runs in — surfaced as the system.privilege metric. */
  describePrivilege(): string {
    if (this.useRootSession) return 'root-slot';
    if (this.priv.mode === 'sudo' && this.priv.verified) return 'sudo';
    if (this.priv.mode === 'root') return 'root';
    return 'user (no elevation)';
  }

  /** One remote command with automatic privilege escalation. */
  async exec(command: string, timeoutMs?: number): Promise<ExecResult> {
    if (this.useRootSession) return this.root!.exec(command, timeoutMs);
    if (this.priv.mode === 'sudo' && this.priv.verified) {
      return this.user.exec(wrapSudo(command, 'sudo', this.sudoUser), timeoutMs);
    }
    return this.user.exec(command, timeoutMs);
  }

  /** Marker-delimited batch — the whole script is elevated as one unit (the
   *  sections share a single shell, so per-section elevation would not help). */
  async runSections(sections: SshSection[], timeoutMs?: number): Promise<Map<string, string>> {
    const parts: string[] = [];
    for (const s of sections) {
      parts.push(`echo "UNM_SECTION:${s.name}:BEGIN"; (${s.cmd}) 2>&1 || true; echo "UNM_SECTION:${s.name}:END"`);
    }
    const r = await this.exec(parts.join('\n'), timeoutMs);
    return parseSectionsLocal(r.stdout);
  }
}

/** Same marker parser as sshClient.parseSections (kept local to avoid a cycle). */
function parseSectionsLocal(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  let buf = '';
  for (const line of stdout.split('\n')) {
    const m = line.match(/^UNM_SECTION:(.+?):(BEGIN|END)$/);
    if (m) {
      if (current !== null && m[2] === 'END') out.set(current, buf.replace(/\n$/, ''));
      current = m[2] === 'BEGIN' ? m[1] : null;
      buf = '';
      continue;
    }
    if (current !== null) buf += line + '\n';
  }
  return out;
}

// --- Probe cache ---------------------------------------------------------------

interface CacheEntry {
  at: number;
  backend: ElevatedBackend;
}
const probeCache = new Map<string, CacheEntry>();
/** Re-probe at most once per 10 minutes per host+credential identity. */
const PROBE_TTL_MS = 10 * 60_000;

/**
 * Resolves the best execution mode for one host and returns a cached
 * ElevatedBackend. `credentials` is the assignment's decrypted field map (the
 * primary at top level, bound slots under `slots`). Never throws — any probe
 * failure degrades to plain user-level exec.
 */
export async function createElevatedBackend(
  host: string,
  port: number,
  credentials: Record<string, unknown>,
  sudoUser?: string,
): Promise<ElevatedBackend> {
  const primary = resolvePrimaryCreds(credentials);
  if (!primary) throw new Error('No SSH credential bound');

  // Cache key = identity only (never secret material).
  const rootFields = resolveRootSlotCredentials(credentials);
  const cacheKey = `${host}|${port}|${primary.username}|${rootFields?.username ?? ''}`;
  const hit = probeCache.get(cacheKey);
  if (hit && Date.now() - hit.at < PROBE_TTL_MS) return hit.backend;

  const userBackend = new SshBackend(host, port, primary);

  // 1) Dedicated root slot — validate it with ONE cheap exec. A bad secret or a
  //    non-uid-0 login is ignored (we fall through to the sudo probe below).
  let rootBackend: SshBackend | undefined;
  if (rootFields) {
    const candidate = new SshBackend(host, port, rootFields);
    try {
      const r = await candidate.exec('id -u', 10_000);
      if (r && r.code === 0 && r.stdout.trim() === '0') rootBackend = candidate;
    } catch { /* unusable root slot — ignore */ }
  }

  let priv: PrivilegeContext;
  if (rootBackend) {
    priv = { mode: 'root', verified: true, hasRootSession: true };
  } else {
    // 2)+3) primary uid-0 check + passwordless-sudo probe.
    priv = await probePrivilege(userBackend);
  }

  const backend = new ElevatedBackend(host, userBackend, rootBackend, priv, sudoUser);
  probeCache.set(cacheKey, { at: Date.now(), backend });
  return backend;
}

/** Resolves the PRIMARY SSH credential (top-level fields only — this plugin's
 *  primary secret IS an SSH login by definition). Mirrors the SDK's
 *  resolveFromFields semantics exactly: a key pair, or username+password. */
function resolvePrimaryCreds(credentials: Record<string, unknown>): import('@unm/plugin-sdk').SshCredentials | undefined {
  const username = typeof credentials['username'] === 'string' ? credentials['username'] : '';
  const password = typeof credentials['password'] === 'string' ? credentials['password'] : '';
  const privateKey = typeof credentials['privateKey'] === 'string' ? credentials['privateKey'] : '';
  const passphrase = typeof credentials['passphrase'] === 'string' && credentials['passphrase'] !== '' ? credentials['passphrase'] : undefined;
  if (privateKey) return { username: username || 'root', privateKey, ...(passphrase ? { passphrase } : {}) };
  if (username && password) return { username, password };
  return undefined;
}
