/**
 * LCOS-LX firmware images in UNM's central file repository.
 *
 * LANCOM ships per-model `.upx` update packages named `LC-LX-<MODEL>-<VERSION>.upx`
 * (e.g. LC-LX-6500-7.20.0192-RU1.upx). An admin uploads one to the Files page
 * (category `firmware`) and the Updates page offers a one-click upgrade when a
 * file matches this device's hardware model AND is newer than the live version —
 * applied through the plan workflow by action `lx.firmware.update`.
 *
 * The matching logic here is pure (unit-testable); only listFirmwareFiles()
 * touches the network, with a short TTL cache so per-device polls don't hammer
 * the repo API.
 */

import { compareVersions, createFileRepoClient, FileRepoEntry } from '@unm/plugin-sdk';

/** A parsed LCOS-LX firmware file name. */
export interface ParsedLxFwFile {
  /** The hardware model digits (e.g. "6500" for LC-LX-6500). */
  modelDigits: string;
  /** The version part of the name (e.g. "7.20.0192-RU1"). */
  version: string;
}

/** LANCOM's firmware file naming convention — case-insensitive, - or _ separators (tolerant of user-renamed uploads). */
const FW_NAME_RE = /^lc-lx[-_](\d{3,4})[-_](.+)\.upx$/i;

/** Parses `LC-LX-<model>-<version>.upx` → { modelDigits, version }; null when the name doesn't follow the convention. */
export function parseLxFwFileName(name: string): ParsedLxFwFile | null {
  const m = FW_NAME_RE.exec((name ?? '').trim());
  if (!m) return null;
  return { modelDigits: m[1], version: m[2].trim() };
}

/** Extracts the hardware-model digits from a device model string ("LC-LX-6500" → "6500"); null when absent. */
export function deviceModelDigits(model?: string | null): string | null {
  const m = (model ?? '').match(/(\d{3,4})/);
  return m ? m[1] : null;
}

/**
 * Strips the trailing build date from a live swVersion ("7.20.0087Rel / 31.10.2026"
 * → "7.20.0087Rel"). The date tokens would otherwise make compareVersions treat
 * every same-build file as OLDER than the live string (extra segments = newer).
 */
export function liveVersionCore(swVersion: string | null | undefined): string {
  return ((swVersion ?? '').split(' / ')[0] ?? '').trim();
}

/** One firmware-file upgrade candidate for a device. */
export interface RepoFirmwareTarget {
  fileId: string;
  fileName: string;
  /** The version parsed from the file name (e.g. "7.20.0192-RU1"). */
  version: string;
  sizeBytes?: number | null;
}

/**
 * Finds the NEWEST repo firmware file that matches this device's model and is
 * strictly newer than the live version — or null when none qualifies. Files
 * whose names don't follow the LC-LX convention are skipped, and NO candidate
 * is offered when the device's hardware model is unknown (an image for the wrong
 * model must never get an Update button).
 */
export function findRepoFirmwareTarget(
  liveSwVersion: string | null | undefined,
  deviceModel: string | null | undefined,
  files: Array<Pick<FileRepoEntry, 'id' | 'name'> & { sizeBytes?: number }>,
): RepoFirmwareTarget | null {
  const live = liveVersionCore(liveSwVersion);
  if (!live) return null;
  const wantModel = deviceModelDigits(deviceModel);
  if (!wantModel) return null;

  let best: RepoFirmwareTarget | null = null;
  for (const f of files ?? []) {
    const parsed = parseLxFwFileName(f.name);
    if (!parsed || parsed.modelDigits !== wantModel) continue;
    // Strictly newer than the live build?
    let cmp: -1 | 0 | 1;
    try {
      cmp = compareVersions(live, parsed.version);
    } catch {
      continue; // malformed version — skip, never throw from a poll path
    }
    if (cmp >= 0) continue;
    const candidate: RepoFirmwareTarget = { fileId: f.id, fileName: f.name, version: parsed.version, sizeBytes: f.sizeBytes ?? null };
    if (!best || compareVersions(best.version, candidate.version) < 0) best = candidate;
  }
  return best;
}

// --- Repo listing with a short TTL cache ---------------------------------------------

/** How long the firmware-file list stays fresh between polls. Kept short (1 min)
 * so an image uploaded via the Files page shows up as an update row on the very
 * next poll beat — the listing is one cheap internal GET per plugin instance,
 * shared across all of its devices. */
const REPO_LIST_TTL_MS = 60_000;

let repoListCache: { at: number; files: FileRepoEntry[] } | null = null;

/** Test hook — drops the cached listing. */
export function clearFirmwareFileCache(): void {
  repoListCache = null;
}

/** Lists category=firmware repo files (TTL-cached; throws when the repo is unreachable). */
export async function listFirmwareFiles(): Promise<FileRepoEntry[]> {
  if (repoListCache && Date.now() - repoListCache.at < REPO_LIST_TTL_MS) return repoListCache.files;
  const files = await createFileRepoClient().list('firmware');
  repoListCache = { at: Date.now(), files };
  return files;
}
