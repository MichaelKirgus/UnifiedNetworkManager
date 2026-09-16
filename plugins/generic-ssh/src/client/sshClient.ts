/**
 * Generic SSH plugin — SSH data path.
 *
 * Wraps the SDK's process-wide SSH pool and adds the one primitive every
 * collector needs: runSections() — MANY read commands in ONE round-trip,
 * marker-delimited (the opnsense zfsSsh / openwrt pattern). Linux boxes are
 * often low-end; a single SSH channel carrying 10 small reads beats 10
 * sequential execs.
 *
 * Security: host-key pinning runs inside the handshake via the SDK's
 * dynamicSshHostVerifier (resolves UNM's current trusted fingerprint per
 * device — a re-keyed box is verified against the CURRENT inventory, not one
 * baked in at pool-creation time). Credentials come exclusively from the UNM
 * secrets pipeline (resolveSshCredentials) and are never logged.
 */

import {
  createSshPool,
  dynamicSshHostVerifier,
  resolveSshCredentials,
} from '@unm/plugin-sdk';
import type { ExecResult, SshClient, SshCredentials } from '@unm/plugin-sdk';

/** Process-wide SSH pool (one session per host|port|username). */
const sshPool = createSshPool();

/** Closes every pooled connection on shutdown. */
export function closeSshPools(): void {
  try {
    sshPool.closeAll();
  } catch {
    /* noop */
  }
}

const DEFAULT_EXEC_TIMEOUT_MS = 15_000;
/** Marker prefix/suffix for runSections — must not appear in command output. */
const MARKER = 'UNM_SECTION';

/** One named section of a combined exec. */
export interface SshSection {
  name: string;
  cmd: string;
}

/** A bound SSH backend for one host (credentials + port resolved). */
export class SshBackend {
  constructor(
    readonly host: string,
    readonly port: number,
    private readonly creds: SshCredentials
  ) {}

  /** One remote command. Throws on transport/auth/host-key failure. */
  async exec(command: string, timeoutMs = DEFAULT_EXEC_TIMEOUT_MS): Promise<ExecResult> {
    const client: SshClient = await sshPool.get(this.host, this.port, this.creds, {
      hostKeyVerifier: dynamicSshHostVerifier(this.host, this.port),
      timeoutMs,
    });
    return client.exec(command, this.creds);
  }

  /**
   * Runs several read commands in ONE exec. Each section's stdout is captured
   * between markers; per-section exit codes are ignored (best-effort reads — a
   * missing file must not sink the batch). Returns name → combined output.
   */
  async runSections(sections: SshSection[], timeoutMs = DEFAULT_EXEC_TIMEOUT_MS): Promise<Map<string, string>> {
    const parts: string[] = [];
    for (const s of sections) {
      // `2>&1` merges stderr so a "No such file" lands in the section too;
      // `|| true` keeps the shell going when one command fails.
      parts.push(`echo "${MARKER}:${s.name}:BEGIN"; (${s.cmd}) 2>&1 || true; echo "${MARKER}:${s.name}:END"`);
    }
    const r = await this.exec(parts.join('\n'), timeoutMs);
    return parseSections(r.stdout);
  }
}

/** Parses marker-delimited combined output into a name → text map. */
export function parseSections(stdout: string): Map<string, string> {
  const out = new Map<string, string>();
  let current: string | null = null;
  let buf = '';
  for (const line of stdout.split('\n')) {
    const m = line.match(new RegExp(`^${MARKER}:(.+?):(BEGIN|END)$`));
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

/** Resolves SSH credentials for this plugin: the bound `ssh` slot first, then a
 *  top-level username/password or key primary secret. Returns undefined when
 *  nothing usable is present — every collector treats that as "no data". */
export function resolveGenericSshCredentials(creds?: Record<string, unknown> | null): SshCredentials | undefined {
  return resolveSshCredentials(creds);
}
