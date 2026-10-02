/**
 * Shared SSH/SFTP transport for the RouterOS plugin.
 *
 * The REST API covers CRUD + command words, but two operations have no REST
 * equivalent and need a real shell:
 *  - `/export` (full running config) — `POST /rest/export` answers with an
 *    empty array on 7.x; the console command prints to stdout instead.
 *  - Config restore — RouterOS keeps its configuration in RAM, so there is no
 *    SFTP file to overwrite; a restored export must be piped through the shell
 *    (`/import` reads from stdin).
 *
 * Credential resolution mirrors index.ts's `resolveRouterOsSsh`: an optional
 * bound `ssh` slot (key or dedicated user) wins, otherwise the PRIMARY
 * username/password secret doubles as the SSH login — RouterOS shares one
 * credential set across REST + SSH, and a default admin with an EMPTY password
 * is legitimate.
 */

import { dynamicSshHostVerifier, resolveSshCredentials } from '@unm/plugin-sdk';
import type { SshClient, SshCredentials, SftpSession } from '@unm/plugin-sdk';
import type { ActionContext } from './types';

/** Resolves SSH credentials for this step (slot wins over primary). */
export function sshCreds(ctx: ActionContext): SshCredentials | undefined {
  return resolveSshCredentials(ctx.credentials as Record<string, unknown>);
}

export const NO_SSH_CREDENTIALS_ERROR =
  'No usable SSH credentials — bind a usernamePassword or sshKeyPair secret to the assignment (primary or "ssh" slot) for config backup/restore.';

/** Opens (or reuses) a pooled SSH client with UNM host-key pinning. */
export async function sshClient(ctx: ActionContext, creds: SshCredentials): Promise<SshClient> {
  const port = ctx.sshPort ?? 22;
  return ctx.sshPool.get(ctx.host, port, creds, {
    timeoutMs: 60_000,
    hostKeyVerifier: dynamicSshHostVerifier(ctx.host, port),
  });
}

/** Opens (or reuses) a pooled SFTP session with UNM host-key pinning. */
export async function sftpSession(ctx: ActionContext, creds: SshCredentials): Promise<SftpSession> {
  const port = ctx.sshPort ?? 22;
  return ctx.sftpPool.get(ctx.host, port, creds, {
    timeoutMs: 60_000,
    hostKeyVerifier: dynamicSshHostVerifier(ctx.host, port),
  });
}

/** RouterOS exports are small (a few hundred KB at most) — bound the payload anyway. */
export const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
