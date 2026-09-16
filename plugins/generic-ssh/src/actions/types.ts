/**
 * Action contract for the Generic SSH plugin.
 *
 * An "action" is one unit of work against a device, described declaratively so
 * /discover advertises the catalog, /plan composes multi-device intents and
 * /config dispatches a single step to its executor — one registry serves all
 * three (the API never interprets payloads).
 *
 * Generic-SSH-specific: SSH IS the transport for this plugin (there is no
 * second read path), so every action executes over the pooled SshBackend. All
 * commands are plain POSIX / iproute2 / systemd — best-effort across distros,
 * with sysvinit fallbacks where a box has no systemd.
 */

import type { ActionDescriptor as SdkActionDescriptor, ActionResult, StepCredentials } from '@unm/plugin-sdk';
import type { SshBackend } from '../client/sshClient';

export type { ActionResult };

/** Everything an action executor needs to run against one device. */
export interface ActionContext {
  /** The SSH data path (always present — it is the only transport here). */
  backend: SshBackend;
  host: string;
  deviceId?: string | null;
  /** Assignment credentials + provisioned plan material namespaced by secretRef. */
  credentials: StepCredentials;
}

/** A fully-described action (SDK descriptor bound to this plugin's context). */
export interface ActionDescriptor extends SdkActionDescriptor<ActionContext> {}

// --- Shared executor helpers ----------------------------------------------------

/** Runs a batch of shell commands in ONE exec; `set -e` stops at the first failure. */
export async function runCommands(
  backend: SshBackend,
  cmds: string[],
  timeoutMs = 20_000,
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  const script = ['set -e', ...cmds].join('\n');
  const r = await backend.exec(script, timeoutMs);
  return { ok: r.code === 0, stdout: r.stdout, stderr: r.stderr };
}

/** Standard success result with details. */
export function okResult(details?: Record<string, unknown>): ActionResult {
  return { success: true, applied: true, verified: false, ...(details ? { details } : {}) };
}

/** Standard failure result. */
export function failResult(error: string): ActionResult {
  return { success: false, error };
}

/** Shell-quotes a value for safe embedding in a command (single quotes). */
export function shq(v: string): string {
  return `'${v.replace(/'/g, "'\\''")}'`;
}

/** Service control that works on systemd AND sysvinit boxes. */
export function serviceCmd(action: 'start' | 'stop' | 'restart' | 'status', name: string): string {
  return `if command -v systemctl >/dev/null 2>&1; then systemctl ${action} ${name}; elif [ -x /etc/init.d/${name} ]; then /etc/init.d/${name} ${action}; else service ${name} ${action}; fi`;
}

/** Reads provisioned key material for one secretRef (plan steps). */
export function keyMaterial(ctx: ActionContext, ref: string): { publicKey?: string; privateKey?: string } | null {
  const slot = ctx.credentials[ref];
  if (!slot || typeof slot !== 'object') return null;
  const s = slot as Record<string, unknown>;
  return {
    publicKey: typeof s['publicKey'] === 'string' ? (s['publicKey'] as string) : undefined,
    privateKey: typeof s['privateKey'] === 'string' ? (s['privateKey'] as string) : undefined,
  };
}

// --- Input validators -------------------------------------------------------------

/** IPv4 address or CIDR (v4 only — v6 routes are out of scope for the generic plugin). */
export function isV4Cidr(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(s);
}

/** IPv4 address (no prefix). */
export function isV4Addr(s: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(s);
}

/** Interface / unit names — conservative charset that can never break the shell. */
export function isSafeName(s: string): boolean {
  return /^[a-zA-Z0-9][a-zA-Z0-9._@:-]{0,63}$/.test(s);
}
