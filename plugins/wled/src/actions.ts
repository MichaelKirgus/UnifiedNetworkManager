/**
 * WLED action catalog — plan-executable operations against one controller.
 *
 * Egress invariant: firmware images are downloaded through UNM's web-fetch
 * broker (SDK `webFetchViaApi`), never by this plugin directly. The device hop
 * itself is plain LAN HTTP to the box's own /update endpoint — exactly what
 * WLED's official web UI does (multipart POST, file field "update", optional
 * PIN form param). After a successful upload the device reboots into the new
 * firmware; we verify by polling /json/info until it reports the target version.
 */

import { ActionResult, ActionDescriptor, createRegistry, compareVersions, webFetchViaApi } from '@unm/plugin-sdk';
import { WledClientOptions, get, getInfo, postJson, postMultipart } from './client';

/** Hard cap for a firmware image (WLED bins are ~1–2 MB; 20 MB is generous). */
export const FIRMWARE_MAX_BYTES = 20 * 1024 * 1024;

/** How long to wait for the device to come back after it reboots into new firmware.
 *  Env overrides (WLED_REBOOT_WAIT_MS / WLED_REBOOT_POLL_MS) exist as test hooks —
 *  production runs use the defaults below. */
const REBOOT_WAIT_MS = Number(process.env.WLED_REBOOT_WAIT_MS) > 0 ? Math.min(Number(process.env.WLED_REBOOT_WAIT_MS), 3_600_000) : 3 * 60_000;
const REBOOT_POLL_INTERVAL_MS = Number(process.env.WLED_REBOOT_POLL_MS) > 0 ? Math.max(250, Number(process.env.WLED_REBOOT_POLL_MS)) : 10_000;

export interface WledActionContext {
  /** Client options bound to this device (address + effective settings). */
  client: WledClientOptions;
  deviceId?: string;
  /** The optional PIN from the bound apiKey secret (empty when unbound). */
  pin: string;
}

/** Reads a trimmed string input, or undefined. */
function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v.trim() : undefined;
}

/**
 * Polls /json/info until the device is reachable AND reports `targetVersion` —
 * or gives up after REBOOT_WAIT_MS. Returns the final info (or null when it
 * never came back). The first few polls are expected to fail: the box is down
 * while it flashes + reboots.
 */
async function waitForRebooted(client: WledClientOptions, targetVersion?: string): Promise<{ ver?: string } | null> {
  const deadline = Date.now() + REBOOT_WAIT_MS;
  let lastInfo: { ver?: string } | null = null;
  while (Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, REBOOT_POLL_INTERVAL_MS));
    const res = await getInfo(client);
    if (!res.ok || !res.data || typeof res.data === 'string') continue; // still down / non-JSON
    lastInfo = res.data as { ver?: string };
    if (targetVersion && compareVersions(String(lastInfo.ver ?? ''), targetVersion) >= 0) return lastInfo;
  }
  return lastInfo;
}

/** The firmware update action — the headline feature. */
const firmwareUpdateAction: ActionDescriptor<WledActionContext> = {
  id: 'wled.firmware.update',
  label: 'Update firmware',
  description:
    "DANGEROUS — flashes a new WLED firmware onto the device (the same flow as its official web UI): downloads the .bin from `url` through UNM's web-fetch broker, uploads it to the device's /update endpoint (multipart field \"update\"), and waits for the reboot. The device is unreachable while flashing (~1–3 min). Pass `pin` when the controller has a settings PIN (or bind an apiKey secret carrying it).",
  module: 'Firmware',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000, // download + flash + reboot wait must fit inside the plan step budget
  retryOnDispatchFailure: false, // a failed flash must never be re-dispatched blindly
  inputSchema: {
    url: { type: 'string', required: true, minLength: 8, description: "Absolute https:// URL of the .bin to install (e.g. https://download.wled.me/WLED_16.0.1_ESP32.bin) — prefilled by the Updates page" },
    fileName: { type: 'string', required: false, maxLength: 200, description: "Original file name (used for the multipart part; defaults to update.bin)" },
    pin: { type: 'string', required: false, minLength: 1, maxLength: 64, description: "WLED settings PIN when one is set — overrides the bound apiKey secret" },
  },
  async execute(ctx: WledActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const url = str(input, 'url');
    if (!url) return { success: false, details: { error: 'Missing required input "url"' } };

    // Current version — best-effort (the idempotency guard below is optional).
    let current: string | undefined;
    try {
      const before = await getInfo(ctx.client);
      if (before.ok && before.data && typeof before.data !== 'string') current = String((before.data as { ver?: unknown }).ver ?? '');
    } catch { /* device may be slow — the upload will surface a real error */ }

    // Idempotency guard: already at/above the target version named in the file.
    const fileName = str(input, 'fileName') ?? url.split('/').pop() ?? '';
    const m = fileName.match(/(\d+\.\d+(?:\.\d+)?)/);
    if (current && m && compareVersions(current, m[1]) >= 0) {
      return { success: true, applied: false, verified: true, details: { note: `Already on ${current} — the file targets ${m[1]} (or older), nothing to do.` } };
    }

    // Download through the web-fetch broker — this plugin never touches the internet.
    let image: Buffer;
    try {
      const dl = await webFetchViaApi({ url, timeoutMs: 300_000, maxBytes: FIRMWARE_MAX_BYTES });
      image = dl.bytes;
    } catch (e) {
      return { success: false, details: { error: `Firmware download failed: ${(e as Error).message}`, hint: 'Check that a web-fetch plugin is online and the URL is reachable from it.' } };
    }
    if (image.length === 0) return { success: false, details: { error: 'Downloaded firmware image is empty' } };

    // Upload to the device — multipart field "update" (+ optional PIN param).
    const pin = str(input, 'pin') ?? ctx.pin;
    const res = await postMultipart(ctx.client, '/update', pin ? { pin } : {}, { name: 'update', filename: fileName || 'update.bin', contentType: 'application/octet-stream', data: image });

    if (!res.ok) {
      // WLED's distinct failure modes (source-verified): 401 = PIN required/wrong,
      // otaLock active, or a validation error in the body. Surface verbatim.
      return { success: false, details: { error: `Device rejected the firmware upload (${res.error})`, hint: res.status === 401 ? 'The controller has a settings PIN — pass it via "pin" or bind an apiKey secret carrying it.' : undefined } };
    }

    // The device reboots now. Verify it comes back on the target version.
    const after = await waitForRebooted(ctx.client, m?.[1]);
    if (!after) {
      return { success: true, applied: true, details: { note: 'Firmware accepted — the device has not come back yet (it may take a few minutes). Check its health on the next poll.', from: current ?? null } };
    }
    const to = String(after.ver ?? '');
    if (m && compareVersions(to, m[1]) < 0) {
      return { success: false, details: { error: `Device is back but reports ${to}, expected ${m[1]} — the update may have failed on the device side.` } };
    }
    return { success: true, applied: true, verified: true, details: { from: current ?? null, to, note: 'Firmware updated and verified after reboot.' } };
  },
};

/** ESP8266-only revert to the previous firmware (GET /update?revert). */
const firmwareRevertAction: ActionDescriptor<WledActionContext> = {
  id: 'wled.firmware.revert',
  label: 'Revert firmware (ESP8266)',
  description:
    "Restores the PREVIOUS firmware on ESP8266 devices only (WLED's own /update?revert endpoint). Not available on ESP32 — use wled.firmware.update with an older .bin instead. The device reboots.",
  module: 'Firmware',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {},
  async execute(ctx: WledActionContext): Promise<ActionResult> {
    const info = await getInfo(ctx.client);
    if (!info.ok || !info.data || typeof info.data === 'string') {
      return { success: false, details: { error: `Device not reachable: ${info.error}` } };
    }
    const arch = String((info.data as { arch?: unknown }).arch ?? '').toLowerCase();
    if (arch !== 'esp8266' && arch !== 'espressif') {
      return { success: false, details: { error: `Revert is only supported on ESP8266 devices — this one reports arch "${arch}". Flash an older .bin via wled.firmware.update instead.` } };
    }
    const res = await get(ctx.client, '/update?revert'); // WLED's own endpoint is a GET (source-verified)
    if (!res.ok) return { success: false, details: { error: `Revert rejected (${res.error})` } };
    return { success: true, applied: true, details: { note: 'Revert accepted — the device is rebooting into the previous firmware.' } };
  },
};

/** Renames the controller (POST /json/cfg {"id":{"name":…}}), verified by re-read. */
const renameAction: ActionDescriptor<WledActionContext> = {
  id: 'wled.rename',
  label: 'Rename device',
  description: "Changes the WLED instance name shown in its own UI and reported as hostname (POST /json/cfg). PIN-gated when a settings PIN is set.",
  module: 'Settings',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: "New instance name (e.g. \"Living Room\")" },
    pin: { type: 'string', required: false, minLength: 1, maxLength: 64, description: "WLED settings PIN when one is set — overrides the bound apiKey secret" },
  },
  async execute(ctx: WledActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Missing required input "name"' } };

    const pin = str(input, 'pin') ?? ctx.pin;
    // /json/cfg is PIN-gated when a PIN is set — send it as the `pin` field.
    const res = await postJson(ctx.client, '/json/cfg', { id: { name }, ...(pin ? { pin } : {}) });
    if (!res.ok) return { success: false, details: { error: `Rename rejected (${res.error})`, hint: res.status === 401 ? 'The controller has a settings PIN — pass it via "pin" or bind an apiKey secret carrying it.' : undefined } };

    // Verify by re-reading /json/info.
    const after = await getInfo(ctx.client);
    if (after.ok && after.data && typeof after.data !== 'string' && String((after.data as { name?: unknown }).name ?? '') === name) {
      return { success: true, applied: true, verified: true, details: { note: `Renamed to "${name}".` } };
    }
    return { success: true, applied: true, details: { note: 'Rename accepted — could not verify the new name by re-read (device slow?).', name } };
  },
};

/** Sets basic light state (on/off + brightness) via POST /json — no auth needed. */
const setStateAction: ActionDescriptor<WledActionContext> = {
  id: 'wled.state.set',
  label: 'Set on/brightness',
  description: "Turns the lights on/off and/or sets brightness (POST /json state). No PIN required for state changes.",
  module: 'Settings',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  inputSchema: {
    on: { type: 'boolean', required: false, description: "Power state (true = lights on)" },
    bri: { type: 'number', required: false, min: 0, max: 255, description: "Brightness 0–255" },
  },
  async execute(ctx: WledActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const state: Record<string, unknown> = {};
    if (input['on'] === true || input['on'] === false) state.on = input['on'];
    if (typeof input['bri'] === 'number' && Number.isFinite(input['bri'])) state.bri = Math.max(0, Math.min(255, Math.round(input['bri'] as number)));
    if (Object.keys(state).length === 0) return { success: false, details: { error: 'Nothing to set — provide "on" and/or "bri"' } };

    const res = await postJson(ctx.client, '/json', { state });
    if (!res.ok) return { success: false, details: { error: `State change rejected (${res.error})` } };
    return { success: true, applied: true, details: { note: `State set: ${JSON.stringify(state)}.` } };
  },
};

/** The full WLED action registry. */
export const wledActions = createRegistry<WledActionContext>([firmwareUpdateAction, firmwareRevertAction, renameAction, setStateAction]);
