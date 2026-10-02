/**
 * Config backup + restore for RouterOS.
 *
 * The REST API cannot return the running configuration (`POST /rest/export`
 * answers with an empty array on 7.x — verified live), so both directions go
 * over SSH:
 *  - BACKUP: `exec('/export')` prints the full config to stdout → stored in
 *    UNM's central file repository (same contract as LCOS/TrueNAS backups).
 *  - RESTORE: RouterOS keeps its configuration in RAM — there is no SFTP file
 *    to overwrite. The export text is written via SFTP to a temp file under
 *    /file/, then piped through the shell with `/import file=...` (the same
 *    primitive winbox's "Import" uses), and the temp file is removed again.
 */

import { configBackupFileName, createFileRepoClient } from '@unm/plugin-sdk';
import type { FileRepoClient } from '@unm/plugin-sdk';
import type { ActionContext, ActionDescriptor } from './types';
import { MAX_CONFIG_BYTES, NO_SSH_CREDENTIALS_ERROR, sftpSession, sshCreds, sshClient } from './sshTransport';

/** Lazily-built shared UNM file-repo client (the SDK's ONE implementation). */
let repoClient: FileRepoClient | null = null;
function fileRepo(): FileRepoClient {
  if (!repoClient) repoClient = createFileRepoClient();
  return repoClient;
}

/** Strips the `#` comment header lines RouterOS prepends to /export output. */
function stripExportHeader(text: string): string {
  const lines = text.split('\n');
  let start = 0;
  while (start < lines.length && (lines[start].startsWith('#') || lines[start].trim() === '')) start += 1;
  return lines.slice(start).join('\n').replace(/\s+$/, '');
}

// --- config.backup.download ---------------------------------------------------------------------------

export const configBackupDownloadAction: ActionDescriptor = {
  id: 'config.backup.download',
  label: 'Download configuration backup',
  description:
    "Downloads the router's complete running configuration via SSH (`/export` — the REST API cannot return it) and stores it in UNM's central file repository, downloadable/archivable from the Files page. Named with the shared convention (<device>__config-backup-<UTC-ts>.cfg). Read-only on the device; use as a rollback point before risky changes — reference it later via details.repoFileId (restore it with config.restore).",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {},
  execute: async (ctx) => {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_CREDENTIALS_ERROR };

    let text: string;
    try {
      const client = await sshClient(ctx, creds);
      const res = await client.exec('/export', creds, 60_000);
      if (res.code !== 0) return { success: false, error: `/export failed over SSH (exit ${res.code}): ${res.stderr.slice(0, 300)}` };
      text = res.stdout;
    } catch (e) {
      return { success: false, error: `Could not run /export over SSH: ${e instanceof Error ? e.message : String(e)}` };
    }

    const config = stripExportHeader(text);
    if (config.length === 0 || !/^\s*#?\s*(\/|#[A-Z])/m.test(config)) {
      return { success: false, error: 'The router returned an empty or unrecognized configuration export.' };
    }

    const data = Buffer.from(config, 'utf8');
    if (data.length > MAX_CONFIG_BYTES) {
      return { success: false, error: `Export is ${(data.length / 1024).toFixed(0)} KB — exceeds the ${MAX_CONFIG_BYTES / 1024} KB limit.` };
    }

    const fileName = configBackupFileName({ device: ctx.deviceName, host: ctx.host, ext: 'cfg' });
    try {
      const entry = await fileRepo().upload(data, { name: fileName, category: 'config-backup' }, 120_000);
      void fileRepo().recordUse(entry.id, { deviceId: ctx.deviceId ?? undefined, note: `config backup of ${ctx.host} (SSH /export)` }).catch(() => undefined);
      return { success: true, details: { sizeBytes: data.length, fileName, repoFileId: entry.id } };
    } catch (e) {
      // The repo is a convenience — a failed store must not fail the backup itself.
      return {
        success: true,
        details: {
          sizeBytes: data.length,
          fileName,
          warning: `Backup downloaded but could NOT be stored in the UNM file repository: ${e instanceof Error ? e.message : String(e)}`,
          // Fallback so the bytes are still available (legacy contract).
          backupBase64: data.toString('base64'),
        },
      };
    }
  },
};

// --- config.restore -------------------------------------------------------------------------------------

const RESTORE_TEMP_FILE = 'unm-restore.cfg';

export const configRestoreAction: ActionDescriptor = {
  id: 'config.restore',
  label: 'Restore configuration backup',
  description:
    "Restores a RouterOS export onto the router: the file is fetched from UNM's central repository (repoFileId, e.g. one produced by config.backup.download) or supplied inline as base64, written via SFTP to /file/ and applied with `/import` — the same primitive winbox uses. DANGEROUS — replaces the entire running configuration; take a fresh backup first and never restore a config whose management IP differs from how you reach this device.",
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 180_000,
  retryOnDispatchFailure: false, // a half-applied restore must never be re-dispatched
  inputSchema: {
    repoFileId: { type: 'string', description: "UNM file-repo id of the backup to restore (preferred)" },
    fileBase64: { type: 'string', description: 'Inline base64-encoded RouterOS export (alternative to repoFileId)' },
  },
  execute: async (ctx, input) => {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_CREDENTIALS_ERROR };

    let payload: Buffer;
    let source: string;
    try {
      if (typeof input.repoFileId === 'string' && input.repoFileId.trim()) {
        const [data, meta] = await Promise.all([fileRepo().get(input.repoFileId.trim()), fileRepo().getMeta(input.repoFileId.trim())]);
        payload = data;
        source = `repo:${meta?.name ?? input.repoFileId}`;
      } else if (typeof input.fileBase64 === 'string' && input.fileBase64.trim()) {
        payload = Buffer.from(input.fileBase64, 'base64');
        source = 'inline';
      } else {
        return { success: false, error: 'Provide repoFileId (preferred) or fileBase64.' };
      }
    } catch (e) {
      return { success: false, error: `Could not fetch the configuration to restore: ${e instanceof Error ? e.message : String(e)}` };
    }

    const text = payload.toString('utf8');
    if (!/^\s*#?\s*\//m.test(text)) {
      return { success: false, error: 'Refusing to restore: the file does not look like a RouterOS export (expected lines starting with "/" such as /system identity set ...).' };
    }

    // 1. Write the temp file via SFTP (/file/ is the router's writable store).
    const session = await sftpSession(ctx, creds);
    try {
      await session.writeFile(`/file/${RESTORE_TEMP_FILE}`, payload, creds);
    } catch (e) {
      return { success: false, error: `Writing /file/${RESTORE_TEMP_FILE} over SFTP failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // 2. Apply it through the shell — `/import` reads the file and applies live.
    try {
      const client = await sshClient(ctx, creds);
      const res = await client.exec(`/import file=${RESTORE_TEMP_FILE}`, creds, 120_000);
      if (res.code !== 0) {
        return { success: false, error: `/import failed (exit ${res.code}): ${(res.stderr || res.stdout).slice(0, 300)} — the temp file was left at /file/${RESTORE_TEMP_FILE} for inspection.` };
      }
    } catch (e) {
      return { success: false, error: `Running /import over SSH failed: ${e instanceof Error ? e.message : String(e)} — the temp file was left at /file/${RESTORE_TEMP_FILE}.` };
    }

    // 3. Clean up the temp file (best-effort).
    try {
      await session.unlink(`/file/${RESTORE_TEMP_FILE}`, creds);
    } catch { /* best-effort */ }

    if (typeof input.repoFileId === 'string' && input.repoFileId.trim()) {
      void fileRepo().recordUse(input.repoFileId.trim(), { deviceId: ctx.deviceId ?? undefined, note: `restored on ${ctx.host} (/import)` }).catch(() => undefined);
    }

    return {
      success: true,
      applied: true,
      details: {
        source,
        sizeBytes: payload.length,
        note: 'Configuration imported and applied live. Verify reachability and key settings (management IP, NTP, DNS) — the router may have restarted services.',
      },
    };
  },
};

export const backupActions: ActionDescriptor[] = [configBackupDownloadAction, configRestoreAction];
