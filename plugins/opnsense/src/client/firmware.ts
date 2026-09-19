import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Firmware module: update status + the appliance's own update/upgrade jobs.
 * Docs: development/api/core/firmware.html (verified live on 26.4 BE).
 *
 * The appliance distinguishes two kinds of change:
 *   - MINOR "update"  — point releases within the current series (26.4.2p1 →
 *     26.4.2p2) plus package upgrades; `POST /api/core/firmware/update`.
 *   - MAJOR "upgrade" — a new release line (26.4 → 26.7); reported in
 *     `upgrade_sets[]`; `POST /api/core/firmware/upgrade`.
 * Both are ASYNC configd jobs: the POST returns immediately with a msg_uuid and
 * progress is read via `GET /api/core/firmware/upgradestatus` (status running →
 * done | reboot, plus the job log). A major upgrade reboots the appliance.
 */

/** One pending package change as reported by `firmware status`. */
export interface FirmwarePackageChange {
  name: string;
  currentVersion?: string | null;
  newVersion?: string | null;
}

/** Parsed view of `POST /api/core/firmware/status` (the product_check blob). */
export interface FirmwareStatus {
  /** True when the appliance has run a check and reports concrete data. */
  checked: boolean;
  /** 'update' = minor updates pending, 'upgrade' = major line available, 'none'. */
  status?: string | null;
  productVersion?: string | null;
  productId?: string | null;
  /** Target series for a MAJOR upgrade (e.g. "26.10"); empty when none. */
  nextSeries?: string | null;
  /** Human-readable download size as reported ("20MiB"). */
  downloadSize?: string | null;
  /** True when the pending change requires a reboot after applying. */
  needsReboot: boolean;
  /** All pending package changes (the OS itself is usually first). */
  packages: FirmwarePackageChange[];
  /** Major release sets (non-empty ⇒ an `upgrade` — not just `update` — applies). */
  majorSets: FirmwarePackageChange[];
}

function str(v: unknown): string | null {
  return typeof v === 'string' && v.trim() !== '' ? v : null;
}

/** Parses the raw status response into a stable shape. Tolerant of older
 * firmware that omits fields — anything missing degrades to "no data". */
export function parseFirmwareStatus(data: unknown): FirmwareStatus {
  const d = (data && typeof data === 'object' ? data : {}) as Record<string, unknown>;
  // The controller returns the product_check blob directly (+ `product` key).
  const check = (d['product_check'] && typeof d['product_check'] === 'object' ? d['product_check'] : d) as Record<string, unknown>;

  const pkgOf = (v: unknown): FirmwarePackageChange => {
    const p = (v && typeof v === 'object' ? v : {}) as Record<string, unknown>;
    return { name: str(p['name']) ?? '?', currentVersion: str(p['current_version']), newVersion: str(p['new_version']) };
  };

  const upgrades = Array.isArray(check['upgrade_packages']) ? (check['upgrade_packages'] as unknown[]).map(pkgOf) : [];
  const sets = Array.isArray(check['upgrade_sets']) ? (check['upgrade_sets'] as unknown[]).map(pkgOf) : [];

  return {
    checked: check['product_check'] !== undefined || d['status_msg'] !== undefined || upgrades.length > 0,
    status: str(d['status']),
    productVersion: str(check['product_version']) ?? str(d['product_version']),
    productId: str(check['product_id']) ?? str(d['product_id']),
    nextSeries: str((d['product'] as Record<string, unknown> | undefined)?.['CORE_NEXT']) ?? null,
    downloadSize: str(check['download_size']) ?? str(d['download_size']),
    needsReboot: check['status_reboot'] === '1' || d['status_reboot'] === '1',
    packages: upgrades,
    majorSets: sets,
  };
}

/** GET /api/core/firmware/status — the appliance's CACHED check result (fast,
 * ~hundreds of ms). Used by monitoring so inventory polls stay quick; data is as
 * fresh as the appliance's last automatic check. */
export function getFirmwareStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/firmware/status');
}

/** POST /api/core/firmware/status — forces a SYNCHRONOUS probe against the
 * mirror (can take ~30–90 s), then returns the fresh check result. Used by the
 * "check for updates" action when current data is wanted on demand. */
export function checkForUpdates(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/firmware/status', {}, { timeoutMs: 120_000 });
}

/** POST /api/core/firmware/changelog/$version — release notes for one version. */
export function getFirmwareChangelog(client: AxiosInstance, version: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/firmware/changelog/${encodeURIComponent(version)}`, {});
}

/** POST /api/core/firmware/update — start the MINOR update job (async). */
export function runFirmwareUpdate(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/firmware/update', {}, { timeoutMs: 30_000 });
}

/** POST /api/core/firmware/upgrade — start the MAJOR upgrade job (async). */
export function runFirmwareUpgrade(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/firmware/upgrade', {}, { timeoutMs: 30_000 });
}

/** GET /api/core/firmware/upgradestatus — job progress + log. */
export function getFirmwareUpgradeStatus(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/firmware/upgradestatus');
}
