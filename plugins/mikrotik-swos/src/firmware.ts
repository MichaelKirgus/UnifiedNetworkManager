/**
 * SwOS firmware update + config restore support — protocol reverse-engineered
 * from the switch's OWN web UI (live-verified 2026-09-19 against a CRS326 by
 * parsing its inline engine.js; read-only GETs only, no device writes):
 *
 *   Firmware upgrade: POST /pboot body "*" → on HTTP 200: multipart POST
 *                     /upgrade with the .bin as form field "blob" → then
 *                     POST /reboot body "*". The switch flashes during reboot.
 *   Config restore:   multipart POST /backup.swb with the .swb file as form
 *                     field "file" (the UI's "Restore Backup") → then
 *                     POST /reboot body "*" (the UI's yb() ALWAYS reboots
 *                     after a restore).
 *   Reboot:           POST /reboot body "*".
 *
 * All files come from the UNM side as base64 in the plan-step input — NO CDN
 * polling, NO version resolution. A future Files page will manage the actual
 * firmware/backup files; until then they ride along in the step input (SwOS
 * images are ~70–150 KB and .swb backups a few hundred KB at most — well
 * inside the API's 12 MB JSON limit).
 */

import type { SwosClient } from './swosClient';

/** Hard cap for an uploaded image/backup (SwOS images are ~70–150 KB; 50 MB is generous). */
export const FIRMWARE_MAX_BYTES = 50 * 1024 * 1024;

/** Decodes a base64 file payload from plan-step input, enforcing the size cap. */
export function decodeFilePayload(base64: string, maxBytes: number): Buffer {
  if (typeof base64 !== 'string' || base64.trim() === '') throw new Error('Missing file content (base64)');
  const buf = Buffer.from(base64.trim(), 'base64');
  if (buf.length === 0) throw new Error('File payload is empty after base64 decode');
  if (buf.length > maxBytes) throw new Error(`File exceeds the ${maxBytes} byte limit (${buf.length} bytes)`);
  return buf;
}

/** True for transport errors that mean "the device dropped us as it went down". */
function isRebootDrop(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /timed out|ECONNRESET|socket hang up|connection (closed|reset)|destroyed/i.test(msg);
}

/** POSTs the final /reboot, tolerating the connection drop that happens when
 *  the switch actually reboots — a transport error HERE means it was accepted. */
async function postReboot(client: SwosClient): Promise<void> {
  try {
    await client.post('reboot', '*');
  } catch (err) {
    if (!isRebootDrop(err)) throw err;
  }
}

/**
 * Runs the switch's own firmware upgrade sequence (UI function Lb, verified live):
 *   POST /pboot "*" → multipart POST /upgrade (field "blob") → POST /reboot "*".
 */
export async function runFirmwareUpgrade(client: SwosClient, image: Buffer, fileName: string): Promise<void> {
  // 1) Prepare the boot loader — the UI only checks HTTP 200 here.
  await client.post('pboot', '*');

  // 2) Upload the image — multipart field "blob" (verified from engine.js).
  await client.postMultipart('upgrade', [
    { name: 'blob', filename: fileName, contentType: 'application/octet-stream', data: image },
  ]);

  // 3) Reboot into the new firmware (the UI does this immediately after /upgrade).
  await postReboot(client);
}

/**
 * Restores a configuration backup (the UI's "Restore Backup"): multipart POST
 * /backup.swb with the file as field "file", then reboot — yb() always reboots
 * after a restore.
 */
export async function restoreConfig(client: SwosClient, backup: Buffer, fileName: string): Promise<void> {
  await client.postMultipart('backup.swb', [
    { name: 'file', filename: fileName, contentType: 'application/octet-stream', data: backup },
  ]);
  await postReboot(client);
}

/** Plain reboot (the UI's "Reboot" button): POST /reboot "*". */
export async function rebootSwitch(client: SwosClient): Promise<void> {
  await postReboot(client);
}
