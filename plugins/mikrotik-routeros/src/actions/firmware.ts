/**
 * Firmware actions for RouterOS (verified live on 7.21 LTS).
 *
 * The package manager is reachable over REST:
 *  - `POST /system/package/update/check-for-updates {}` → [{channel, installed-version, latest-version, status}]
 *    (verified live — returns e.g. "New version is available" with the latest stable).
 *  - `POST /system/package/update/install {version?}` — downloads + installs the
 *    update; the command word exists on 7.x (verified by its parameter validation).
 *    The install takes MINUTES and the REST connection drops when the router
 *    reboots into the new version — that is EXPECTED.
 */

import { rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

/** Runs check-for-updates and normalizes its single-row answer. */
async function checkForUpdates(ctx: ActionContext): Promise<Row | null> {
  try {
    const res = await ctx.client.post<unknown>('/system/package/update/check-for-updates', {});
    if (Array.isArray(res)) return res[0] && typeof res[0] === 'object' ? (res[0] as Row) : null;
    return res && typeof res === 'object' ? (res as Row) : null;
  } catch {
    return null;
  }
}

// --- firmware.status.read ---------------------------------------------------------------------------

export const firmwareStatusReadAction: ActionDescriptor = {
  id: 'firmware.status.read',
  label: 'Check for RouterOS updates',
  description: "Queries the router's package manager (POST /system/package/update/check-for-updates) — installed version, channel and whether a newer release is available.",
  module: 'Updates',
  riskLevel: 'read',
  deviceCount: 1,
  timeoutMs: 60_000,
  inputSchema: {},
  execute: async (ctx) => {
    const row = await checkForUpdates(ctx);
    if (!row) return { success: false, error: 'The router did not answer the update check — is it connected to a package server / the internet?' };
    return {
      success: true,
      details: {
        installedVersion: rosString(row, ['installed-version']) ?? null,
        latestVersion: rosString(row, ['latest-version']) ?? null,
        channel: rosString(row, ['channel']) ?? null,
        status: rosString(row, ['status']) ?? null,
      },
    };
  },
};

/** Canonical alias (OPNsense-compatible id) — same executor as firmware.status.read. */
export const firmwareCheckAction: ActionDescriptor = { ...firmwareStatusReadAction, id: 'firmware.check' };

// --- firmware.update ------------------------------------------------------------------------------------

export const firmwareUpdateAction: ActionDescriptor = {
  id: 'firmware.update',
  label: 'Download + install RouterOS update (reboots)',
  description:
    "Installs the latest available RouterOS release via the package manager (POST /system/package/update/install). The router DOWNLOADS, INSTALLS and REBOOTS — the REST connection drops mid-response; that is EXPECTED and reported as success. Takes several minutes depending on link speed. Use only in a maintenance window.",
  module: 'Updates',
  riskLevel: 'dangerous',
  deviceCount: 1,
  timeoutMs: 600_000, // download + install + reboot can take many minutes
  retryOnDispatchFailure: false, // never re-dispatch a firmware update
  inputSchema: {
    version: { type: 'string', description: "Specific version to install (e.g. 7.24.5) — omit for the latest available" },
  },
  execute: async (ctx, input) => {
    // Pre-flight — is there actually an update?
    const check = await checkForUpdates(ctx);
    if (!check) return { success: false, error: 'The router did not answer the update check — cannot verify an update exists.' };
    const latest = rosString(check, ['latest-version']);
    const installed = rosString(check, ['installed-version']);
    const status = rosString(check, ['status']) ?? '';

    if (!/new version is available/i.test(status)) {
      return { success: true, applied: false, details: { skipped: `no update available (installed ${installed}, channel ${rosString(check, ['channel'])})` } };
    }

    const body: Record<string, unknown> = {};
    if (typeof input.version === 'string' && input.version.trim()) {
      const wanted = input.version.trim();
      if (latest && wanted !== latest) {
        return { success: false, error: `Requested version ${wanted} is not the available one (${latest}) — RouterOS package updates install the channel's current release.` };
      }
      body['version'] = wanted;
    }

    try {
      await ctx.client.post('/system/package/update/install', body);
      return { success: true, applied: true, details: { note: `Update to ${latest ?? 'the latest version'} accepted — the router is downloading, installing and rebooting.` } };
    } catch (e) {
      // A dropped connection during install/reboot means it is already going down.
      const msg = e instanceof Error ? e.message : String(e);
      if (/unreachable|timeout|socket|ECONNRESET/i.test(msg)) {
        return { success: true, applied: true, details: { note: `Update accepted (connection dropped during install/reboot — expected).` } };
      }
      return { success: false, error: `Firmware update failed: ${msg}` };
    }
  },
};

export const firmwareActions: ActionDescriptor[] = [firmwareStatusReadAction, firmwareCheckAction, firmwareUpdateAction];
