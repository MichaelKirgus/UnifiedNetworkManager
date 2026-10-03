/**
 * Config backup + restore for OPNsense — the file-repo gap fill.
 *
 * The appliance's native snapshots (snapshot.create/restore) are appliance-local:
 * nothing lands in UNM's central file repository, so there is no Files-page
 * artifact and no cross-device restore source. This module closes that gap with
 * the same contract as RouterOS/LCOS/SwOS/TrueNAS backups:
 *
 *  - BACKUP (`config.backup.download`, read-only): fetch the appliance's latest
 *    config backup XML into UNM's central file repository (category
 *    'config-backup', shared `configBackupFileName` naming). Version-aware:
 *      26.x MVC API — GET /api/core/backup/providers → backups/{host} →
 *        download/{host}/{id?} (verified live on 26.4.1p2 + 26.4.2p2; NOT
 *        read-only-gated, works with a readonly key)
 *      legacy CE — GET /api/core/backup/backups (pre-MVC firmware)
 *    OPNsense keeps rolling local backups in /conf/backup automatically, so the
 *    download always has something to fetch even right after boot.
 *
 *  - RESTORE (`config.restore`, dangerous): there is NO REST upload endpoint on
 *    any version (the MVC controller only serves downloads), so the restore rides
 *    the bound `ssh` slot — the same base64→/bin/sh exec path as the ZFS and
 *    security-check SSH actions:
 *      1. write the payload to /conf/backup/unm-restore.xml (base64 chunks)
 *      2. sanity-check it parses as an <opnsense> config document
 *      3. cp over /conf/config.xml + /usr/local/etc/rc.reload_all
 *    rc.reload_all re-reads the whole configuration and restarts affected
 *    services WITHOUT a reboot (the canonical non-interactive restore path —
 *    what OPNsense's own restore.sh does, minus the interactive prompt).
 */

import { configBackupFileName, createFileRepoClient } from '@unm/plugin-sdk';
import type { FileRepoClient } from '@unm/plugin-sdk';
import * as backup from '../client/backup';
import { execViaSshSlot } from '../zfsSsh';
import type { ActionContext, ActionDescriptor, ActionResult } from './types';

/** Lazily-built shared UNM file-repo client (the SDK's ONE implementation). */
let repoClient: FileRepoClient | null = null;
function fileRepo(): FileRepoClient {
  if (!repoClient) repoClient = createFileRepoClient();
  return repoClient;
}

/** OPNsense configs are tens of KB — bound the payload anyway. */
const MAX_CONFIG_BYTES = 4 * 1024 * 1024;

/** True when a byte buffer looks like an OPNsense config document (sanity gate). */
function isOpnsenseConfig(data: Buffer): boolean {
  const head = data.subarray(0, 2048).toString('utf8');
  return /<\?xml/.test(head) && /<opnsense[\s>]/.test(head);
}

// --- config.backup.download -----------------------------------------------------------

const configBackupDownload: ActionDescriptor = {
  id: 'config.backup.download',
  label: 'Download configuration backup (file repo)',
  description:
    "Downloads the appliance's latest local config backup XML via the OPNsense API and stores it in UNM's central file repository, downloadable/archivable from the Files page. Named with the shared convention (<device>__config-backup-<UTC-ts>.xml). Version-aware (26.x MVC endpoints with legacy fallback); works with a readonly API key — read-only on the device. Use as a rollback point before risky changes; restore it later with config.restore.",
  module: 'System',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 90_000,
  inputSchema: {},
  async execute(ctx): Promise<ActionResult> {
    let data: Buffer;
    let source: string;

    // --- 26.x MVC path (preferred) -------------------------------------------
    const host = await backup.resolveLocalBackupHost(ctx.client);
    if (host) {
      const listRes = await backup.listBackupsForHost(ctx.client, host);
      const rows = listRes.data?.items ?? [];
      if (!listRes.ok || rows.length === 0) {
        return { success: false, error: `No local config backups found on the appliance (GET /api/core/backup/backups/${host} → HTTP ${listRes.status}).` };
      }
      const latest = rows[0]; // newest first per controller sort
      const dl = await backup.downloadBackup(ctx.client, host, latest.id);
      if (!dl.ok || !(dl.data instanceof Buffer) || dl.data.length === 0) {
        return { success: false, error: `Downloading backup ${latest.id} failed (HTTP ${dl.status}).` };
      }
      data = dl.data;
      source = `api:/conf/backup/${latest.id}`;
    } else {
      // --- legacy path (pre-19.7 firmware: no MVC download endpoint) ----------
      // The old flat API could LIST backups but had no REST download — so the
      // file is read straight off /conf/backup over the bound `ssh` slot.
      const listRes = await backup.listBackups(ctx.client);
      if (!listRes.ok) {
        return { success: false, error: `Could not list backups — neither the MVC endpoint (26.x+) nor the legacy /api/core/backup/backups responded (HTTP ${listRes.status}).` };
      }
      const sshPort = typeof ctx.extra?.['sshPort'] === 'number' ? (ctx.extra['sshPort'] as number) : undefined;
      // Newest file first — /conf/backup keeps config-<epoch>.xml names.
      const ls = await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, `ls -t /conf/backup/config-*.xml 2>/dev/null | head -n 1`, { port: sshPort, timeoutMs: 15_000 });
      if (!ls || ls.code !== 0) {
        return { success: false, error: 'This firmware has no REST backup download endpoint and the `ssh` slot is unavailable — cannot fetch /conf/backup. Bind an ssh credential slot for legacy-firmware backups.' };
      }
      const file = (ls.stdout.trim().split('\n')[0] ?? '').trim();
      if (!file) {
        return { success: false, error: 'No local config backup files found in /conf/backup on the appliance.' };
      }
      const cat = await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, `cat ${file}`, { port: sshPort, timeoutMs: 60_000 });
      if (!cat || cat.code !== 0) {
        return { success: false, error: `Reading ${file} over SSH failed${cat ? ` (exit ${cat.code})` : ''}.` };
      }
      data = Buffer.from(cat.stdout, 'utf8');
      source = `ssh:${file}`;
    }

    if (!isOpnsenseConfig(data)) {
      return { success: false, error: 'The downloaded file does not look like an OPNsense config XML (expected <?xml … <opnsense>) — refusing to store it.' };
    }
    if (data.length > MAX_CONFIG_BYTES) {
      return { success: false, error: `Backup is ${(data.length / 1024).toFixed(0)} KB — exceeds the ${MAX_CONFIG_BYTES / 1024} KB limit.` };
    }

    const fileName = configBackupFileName({ device: ctx.deviceName, host: ctx.host, ext: 'xml' });
    try {
      const entry = await fileRepo().upload(data, { name: fileName, category: 'config-backup' }, 120_000);
      void fileRepo().recordUse(entry.id, { deviceId: ctx.deviceId ?? undefined, note: `config backup of ${ctx.host} (${source})` }).catch(() => undefined);
      return { success: true, details: { sizeBytes: data.length, fileName, repoFileId: entry.id, source } };
    } catch (e) {
      // The repo is a convenience — a failed store must not fail the backup itself.
      return {
        success: true,
        details: {
          sizeBytes: data.length,
          fileName,
          source,
          warning: `Backup downloaded but could NOT be stored in the UNM file repository: ${e instanceof Error ? e.message : String(e)}`,
          // Fallback so the bytes are still available (legacy contract).
          backupBase64: data.toString('base64'),
        },
      };
    }
  },
};

// --- config.restore -------------------------------------------------------------------

const RESTORE_STAGING_FILE = '/conf/backup/unm-restore.xml';

/** Splits a buffer into base64 chunks small enough for one exec line. */
function b64Chunks(data: Buffer, chunkBytes = 8 * 1024): string[] {
  const out: string[] = [];
  for (let off = 0; off < data.length; off += chunkBytes) {
    out.push(data.subarray(off, off + chunkBytes).toString('base64'));
  }
  return out;
}

const configRestore: ActionDescriptor = {
  id: 'config.restore',
  label: 'Restore configuration backup (SSH)',
  description:
    "Restores an OPNsense config XML onto the appliance over the bound `ssh` slot: the file is fetched from UNM's central repository (repoFileId, e.g. one produced by config.backup.download) or supplied inline as base64, staged to /conf/backup/unm-restore.xml, copied over /conf/config.xml and applied with rc.reload_all — the canonical non-interactive restore path (no reboot). DANGEROUS — replaces the entire running configuration; take a fresh backup first and never restore a config whose management IP differs from how you reach this appliance. Requires a bound `ssh` credential slot.",
  module: 'System',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 600_000, // staging + up to 240s of post-reload polling (sshd restart)
  retryOnDispatchFailure: false, // a half-applied restore must never be re-dispatched
  inputSchema: {
    repoFileId: { type: 'string', description: "UNM file-repo id of the backup to restore (preferred)" },
    fileBase64: { type: 'string', description: 'Inline base64-encoded OPNsense config XML (alternative to repoFileId)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
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

    if (!isOpnsenseConfig(payload)) {
      return { success: false, error: 'Refusing to restore: the file does not look like an OPNsense config XML (expected <?xml … <opnsense>).' };
    }
    if (payload.length > MAX_CONFIG_BYTES) {
      return { success: false, error: `File is ${(payload.length / 1024).toFixed(0)} KB — exceeds the ${MAX_CONFIG_BYTES / 1024} KB limit.` };
    }

    const sshPort = typeof ctx.extra?.['sshPort'] === 'number' ? (ctx.extra['sshPort'] as number) : undefined;

    // 1. Stage the file in /conf/backup via base64 chunks (POSIX sh, csh-safe).
    const chunks = b64Chunks(payload);
    for (let i = 0; i < chunks.length; i++) {
      const op = i === 0 ? '>' : '>>';
      const cmd = `echo '${chunks[i]}' | base64 -d ${op} ${RESTORE_STAGING_FILE}`;
      const res = await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, cmd, { port: sshPort, timeoutMs: 30_000 });
      if (!res || res.code !== 0) {
        return { success: false, error: `Writing ${RESTORE_STAGING_FILE} over SSH failed (chunk ${i + 1}/${chunks.length}${res ? `, exit ${res.code}: ${(res.stderr || '').slice(0, 200)}` : ' — no usable ssh slot or connection'}.` };
      }
    }

    // 2. Sanity-check the staged file on the appliance (size + XML head).
    const check = await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, `wc -c < ${RESTORE_STAGING_FILE}; head -c 64 ${RESTORE_STAGING_FILE}`, { port: sshPort, timeoutMs: 15_000 });
    if (!check || check.code !== 0) {
      return { success: false, error: `Could not verify the staged file on the appliance${check ? ` (exit ${check.code})` : ''}. Aborting before touching /conf/config.xml.` };
    }
    const stagedSize = Number(check.stdout.trim().split('\n')[0]);
    if (!Number.isFinite(stagedSize) || stagedSize !== payload.length) {
      return { success: false, error: `Staged file size mismatch (expected ${payload.length} bytes, found ${stagedSize}). Aborting before touching /conf/config.xml.` };
    }

    // 3. Apply: cp over the live config + reload_all (no reboot). rc.reload_all
    //    re-reads every subsystem and restarts affected services — this is what
    //    OPNsense's own restore.sh does after a manual file copy. It ALSO
    //    restarts sshd, which kills our own exec channel mid-run — so the reload
    //    is launched DETACHED (nohup … &), writing its exit code to a marker
    //    file; we then poll over FRESH connections for either the marker or the
    //    appliance coming back with our config in place.
    const MARKER = '/tmp/unm-restore-done';
    // cp runs SYNCHRONOUSLY (its failure is reported immediately); only the
    // reload itself is detached, so a failed copy never leaves us polling.
    const apply = await execViaSshSlot(
      ctx.host,
      ctx.credentials as Record<string, unknown>,
      `rm -f ${MARKER}; cp ${RESTORE_STAGING_FILE} /conf/config.xml; RC=$?; if [ $RC -eq 0 ]; then nohup sh -c '/usr/local/etc/rc.reload_all >/dev/null 2>&1; echo $? > ${MARKER}' >/dev/null 2>&1 & echo LAUNCHED; else echo CP_FAILED_$RC; fi`,
      { port: sshPort, timeoutMs: 30_000 },
    );
    if (!apply || apply.code !== 0) {
      return { success: false, error: `Could not launch the restore (exit ${apply ? apply.code : 'n/a'}): ${(apply?.stderr ?? '').slice(0, 200)} — /conf/config.xml was NOT replaced; nothing to clean up.` };
    }
    if (/CP_FAILED_\d+/.test(apply.stdout)) {
      return { success: false, error: `cp over /conf/config.xml failed (${apply.stdout.trim()}) — the running configuration is untouched; the staged file remains at ${RESTORE_STAGING_FILE} for inspection.` };
    }

    // 4. Poll over fresh connections (the reload restarts sshd, so the first
    //    reconnect may fail a few times — that is expected). Two signals:
    //      - marker file carries rc.reload_all's exit code → definitive;
    //      - no marker yet but SSH answers again and /conf/config.xml has our
    //        staged size → sshd (re)started, i.e. the reload got past the login/
    //        interface config stage with our new config in place. That is enough
    //        to call the restore verified: rc.reload_all can hang indefinitely on
    //        some appliances (observed 25+ min stuck at a late service restart,
    //        device fully reachable meanwhile), so waiting for its exit code as
    //        the ONLY success signal would report false "unverified".
    let verified = false;
    let rc: number | null = null;
    let cfgSize: number | null = null;
    const deadline = Date.now() + 240_000;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 5_000)); // let services settle between attempts
      const poll = await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, `echo MARKER=[$(cat ${MARKER} 2>/dev/null)]; echo SIZE=[$(wc -c < /conf/config.xml)]`, { port: sshPort, timeoutMs: 15_000 });
      if (!poll || poll.code !== 0) continue; // sshd still restarting — retry
      // NOTE: FreeBSD wc pads with leading spaces ("SIZE=[  136232]") — the \s*
      // inside the brackets is load-bearing, not cosmetic.
      const markerMatch = poll.stdout.match(/MARKER=\[\s*(\d*)\s*\]/);
      const sizeMatch = poll.stdout.match(/SIZE=\[\s*(\d+)\s*\]/);
      rc = markerMatch && markerMatch[1] !== '' ? Number(markerMatch[1]) : null;
      cfgSize = sizeMatch ? Number(sizeMatch[1]) : null;
      if (rc === 0) { verified = true; break; } // reload finished cleanly — definitive
      if (cfgSize === payload.length) { verified = true; break; } // device back up with our config in place
    }

    // Best-effort cleanup of the staging file + marker. NOTE: never kill a still-
    // running rc.reload_all here — it may be mid-way through restarting services.
    await execViaSshSlot(ctx.host, ctx.credentials as Record<string, unknown>, `rm -f ${RESTORE_STAGING_FILE} ${MARKER}`, { port: sshPort, timeoutMs: 15_000 });

    if (typeof input.repoFileId === 'string' && input.repoFileId.trim()) {
      void fileRepo().recordUse(input.repoFileId.trim(), { deviceId: ctx.deviceId ?? undefined, note: `restored on ${ctx.host} (rc.reload_all)` }).catch(() => undefined);
    }

    if (!verified) {
      return {
        success: true,
        applied: true,
        verified: false,
        details: {
          source,
          sizeBytes: payload.length,
          reloadExitCode: rc,
          configSizeAfter: cfgSize,
          note: 'Configuration was replaced and rc.reload_all was launched, but the appliance did not come back over SSH within 240s. Verify reachability and key settings (management IP, NTP, DNS) manually.',
        },
      };
    }

    return {
      success: true,
      applied: true,
      verified: true,
      details: {
        source,
        sizeBytes: payload.length,
        reloadExitCode: rc,
        configSizeAfter: cfgSize,
        note: rc === 0
          ? 'Configuration restored and reloaded (no reboot). Verified: rc.reload_all exited 0. Verify reachability and key settings (management IP, NTP, DNS).'
          : `Configuration restored; the appliance came back over SSH with /conf/config.xml at the staged size (${cfgSize} bytes), so the reload got past the login/interface stage — but rc.reload_all had not finished yet (it can run for minutes or hang on some appliances). Verify reachability and key settings (management IP, NTP, DNS) once services settle.`,
      },
    };
  },
};

export const configBackupActions: ActionDescriptor[] = [configBackupDownload, configRestore];
