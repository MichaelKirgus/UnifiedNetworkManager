/**
 * Shared helpers for uci-based write actions: read-modify-commit over ONE SSH
 * exec (all uci set/add_list/del commands + a single `uci commit` in one
 * round-trip), service reloads, and result shaping.
 */

import type { ActionResult } from '@unm/plugin-sdk';
import type { SshBackend } from '../client/sshBackend';
import { parseUciShow, uciCommitCmd } from '../client/sshBackend';

/** Runs a batch of shell commands in one exec; returns combined output. */
export async function runCommands(ssh: SshBackend, cmds: string[], timeoutMs = 20_000): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  // `set -e` so the first failing command stops the batch (its message is kept).
  const script = ['set -e', ...cmds].join('\n');
  const r = await ssh.exec(script, timeoutMs);
  return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr };
}

/** Reads one uci package as a parsed tree ({} on failure). */
export async function readUciPackage(ssh: SshBackend, pkg: string): Promise<Record<string, Record<string, Record<string, string>>>> {
  const r = await ssh.exec(`uci show ${pkg} 2>/dev/null || true`).catch(() => null);
  if (!r) return {};
  return parseUciShow(r.stdout);
}

/** Reloads a procd service (best-effort — some services have no reload). */
export async function reloadService(ssh: SshBackend, name: string): Promise<void> {
  await ssh.exec(`/etc/init.d/${name} restart >/dev/null 2>&1 || /etc/init.d/${name} enable >/dev/null 2>&1 || true`).catch(() => undefined);
}

/** Standard success result with details. */
export function okResult(details?: Record<string, unknown>): ActionResult {
  return { success: true, applied: true, verified: false, ...(details ? { details } : {}) };
}

/** Standard failure result. */
export function failResult(error: string): ActionResult {
  return { success: false, error };
}

/** Builds the commit command for one or more packages (single commit when possible). */
export function commitCmd(pkgs?: string[]): string {
  if (!pkgs || pkgs.length === 0) return uciCommitCmd();
  // One `uci commit` with no args commits ALL pending changes — simplest and
  // safest for multi-package actions.
  return uciCommitCmd();
}
