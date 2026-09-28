/**
 * LCOS interactive-CLI client over an SSH shell (PTY).
 *
 * Why a PTY and not ssh2's exec channel: the LCOS CLI is a menu-driven,
 * INTERACTIVE program — it paginates long output with "MORE [Q(uit)]>", asks
 * confirmation questions ("Check for difference? [y/n]"), and only accepts
 * commands at its `user@host:/dir` prompt. A non-interactive exec channel has
 * no pager/prompt semantics, so this module drives a real shell session:
 *   1. wait for the login banner + first prompt to settle (idle-based),
 *   2. send one command line at a time,
 *   3. while output flows: auto-advance the MORE pager (Enter — Space does NOT
 *      advance on LCOS 10.x) and answer y/n confirmation prompts with a
 *      configurable default (default 'n' — never accept an implicit reboot),
 *   4. finish when the shell goes idle at a prompt again.
 *
 * Transport: rides the SDK's terminal pool (createTerminalPool / openShell) —
 * the SAME audited ssh2 session layer as the interactive web console, so no
 * second SSH implementation lives in this plugin. One PTY channel per command
 * batch; the shell's cwd persists across a batch (`cd Setup` then `set Time ?`).
 *
 * Verified live on WLC01 (LANCOM vRouter, LCOS 10.94) and GW_Ralf
 * (LANCOM 1803VAW-5G): `dir`, `set <path> ?`, `readconfig` (~11k lines),
 * `cd Setup/...` all work through this driver; the pager advances with Enter.
 */

import { SshTerminalSession, type TerminalPool } from '@unm/plugin-sdk';
import type { SshCredentials } from '@unm/plugin-sdk';

/** One command's captured output (banner + echoes included — callers filter). */
export interface CliResult {
  /** Raw PTY text produced while the command ran (may contain pager breaks). */
  raw: string;
  /** True when the shell went idle at a prompt before the hard timeout. */
  completed: boolean;
}

export interface LcosCliOptions {
  host: string;
  port?: number;
  creds: SshCredentials;
  /** Per-command budget (default 30 s). readconfig of a large config needs more. */
  timeoutMs?: number;
  /** Idle window that counts as "the shell is done" (default 1200 ms). */
  idleMs?: number;
  /** Answer for y/n confirmation prompts (default 'n' — safe: declines reboots). */
  confirmAnswer?: string;
  /** Terminal geometry (LCOS wraps at the PTY width — keep it wide). */
  cols?: number;
  rows?: number;
}

/** The LCOS pager footer (trailing whitespace tolerated). */
const MORE_RE = /\bMORE \[Q\(uit\)\]>\s*$/i;

/** A y/n confirmation question, e.g. "Check for difference? [y/n]" or "... reboot now? [y/n]". */
const CONFIRM_RE = /\[[yYnN]\]\s*$|\(y\/n\)\s*$/;

export class LcosCliError extends Error {}

/**
 * One LCOS CLI session over one PTY channel. Open it, run() commands in
 * sequence (the shell's cwd persists between them — `cd Setup` sticks), close().
 */
export class LcosCli {
  private readonly pool: TerminalPool;
  private readonly opts: Required<Pick<LcosCliOptions, 'host' | 'port' | 'timeoutMs' | 'idleMs' | 'confirmAnswer' | 'cols' | 'rows'>> & Pick<LcosCliOptions, 'creds'>;
  private session: SshTerminalSession | null = null;

  constructor(pool: TerminalPool, opts: LcosCliOptions) {
    this.pool = pool;
    this.opts = { port: 22, timeoutMs: 30_000, idleMs: 1_200, confirmAnswer: 'n', cols: 220, rows: 50, ...opts };
  }

  /** Opens the PTY and waits for the login banner to settle. */
  async open(): Promise<void> {
    if (this.session) return; // already open — reuse
    const o = this.opts;
    try {
      const conn = await this.pool.get(o.host, o.port, o.creds);
      this.session = await conn.openShell(o.creds, { cols: o.cols, rows: o.rows });
    } catch (e) {
      throw new LcosCliError(`LCOS CLI connect to ${o.host}:${o.port} failed: ${e instanceof Error ? e.message : String(e)}`);
    }
    // The banner arrives in a burst right after the shell opens — wait for it to
    // settle before treating "idle" as "prompt ready".
    await new Promise((r) => setTimeout(r, 2_500));
  }

  /**
   * Sends ONE command line to the session's PTY and captures everything until
   * the shell is idle at a prompt again. Pager pages are advanced automatically;
   * y/n prompts get the configured confirmAnswer (default 'n'). Resolves even on
   * timeout — check `completed`.
   */
  async run(command: string, opts?: { timeoutMs?: number }): Promise<CliResult> {
    const session = this.session;
    if (!session) throw new LcosCliError('CLI session is not open');
    const o = this.opts;
    const budget = Math.max(3_000, opts?.timeoutMs ?? o.timeoutMs);

    return new Promise<CliResult>((resolve) => {
      let settled = false;
      let buf = '';
      let idleTimer: NodeJS.Timeout | null = null;
      let hardTimer: NodeJS.Timeout | null = null;

      const finish = (completed: boolean, extra = '') => {
        if (settled) return;
        settled = true;
        if (idleTimer) clearTimeout(idleTimer);
        if (hardTimer) clearTimeout(hardTimer);
        session.off('data', onData);
        resolve({ raw: buf + extra, completed });
      };

      const onIdle = () => {
        if (settled || !session.connected) return;
        // Pager first — it keeps the command running.
        if (MORE_RE.test(buf)) {
          buf += '\n----- page break -----\n';
          session.write('\r'); // Enter advances LCOS's MORE pager (Space does not).
          arm();
          return;
        }
        // Confirmation question — answer it, keep waiting for the result.
        if (CONFIRM_RE.test(buf)) {
          buf += `\n----- auto-answer: ${o.confirmAnswer} -----\n`;
          session.write(o.confirmAnswer + '\r');
          arm();
          return;
        }
        // Idle at a prompt → done.
        finish(true);
      };

      const arm = () => {
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(onIdle, o.idleMs);
      };

      const onData = (d: Buffer) => {
        buf += d.toString('utf8');
        arm();
      };

      session.on('data', onData);
      hardTimer = setTimeout(() => finish(false, '\n[TIMEOUT]'), budget + 10_000);
      // Give the prompt a moment to settle, then send.
      setTimeout(() => {
        if (settled) return;
        session.write(command + '\r');
        arm();
      }, 800);
    });
  }

  /** Closes the PTY channel (the pooled connection stays for reuse). */
  close(): void {
    const s = this.session;
    this.session = null;
    if (s) {
      try { s.close(); } catch { /* noop */ }
    }
  }
}

/**
 * Runs a sequence of commands in ONE fresh LCOS CLI session (the shell's cwd
 * persists across the list — `cd Setup` then `set Time ?` works). Returns one
 * CliResult per command. The PTY is always closed, even on failure.
 */
export async function runLcosCliCommands(pool: TerminalPool, opts: LcosCliOptions, commands: string[]): Promise<CliResult[]> {
  const cli = new LcosCli(pool, opts);
  try {
    await cli.open();
    const out: CliResult[] = [];
    for (const c of commands) {
      out.push(await cli.run(c));
    }
    return out;
  } finally {
    cli.close();
  }
}

/**
 * Strips the login banner + command echoes from a captured CLI result, leaving
 * just the command's own output. The banner ends at the first prompt line; each
 * echoed command line (`> <cmd>` followed by its output) is dropped together
 * with trailing prompts.
 */
export function stripCliFraming(raw: string): string {
  // Drop everything up to and including the FIRST prompt (the banner).
  const firstPrompt = raw.search(/\n>\s*$/m);
  let text = firstPrompt >= 0 ? raw.slice(firstPrompt + 2) : raw;
  // Remove echoed command lines: "> <cmd>" at line start, plus a trailing prompt.
  text = text.replace(/^> [^\r\n]*\r?\n/gm, '');
  text = text.replace(/\n>\s*$/g, '\n');
  return text.trim();
}

/**
 * Strips the framing from ONE per-command buffer (as captured by LcosCli.run —
 * no banner; the banner was consumed during open()). Removes: OSC title escapes
 * (`\x1b]0;root@host:/cwd\x07`), the leading echoed command line, and the
 * trailing `<hostpath>\r\n> ` prompt. Page-break markers inserted by run() are
 * kept (they mark where the pager advanced).
 */
export function stripCommandEcho(raw: string, command?: string): string {
  let text = raw.replace(/\x1b\][0;][^\x07]*\x07/g, ''); // OSC title escapes
  if (command) {
    const esc = command.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    text = text.replace(new RegExp(`^[\\s>]*${esc}\\r?\\n`, 'm'), ''); // leading echo
  }
  // Trailing prompt: optional host-path line + "> " at end of buffer.
  text = text.replace(/(?:[^\r\n]+\r?\n)?>\s*$/, '');
  return text.trim();
}
