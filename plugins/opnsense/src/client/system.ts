import { AxiosInstance } from 'axios';
import { pickString } from '@unm/plugin-sdk';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Core/system module: status, information, power actions, service control,
 * tunables and defaults. Docs: development/api/core/core.html + core/system.
 */

export interface SystemStatus {
  metadata?: { system?: { status?: number; uptime?: string; version?: string } };
}

/** GET /api/core/system/status — appliance health (0=critical,1=warning,2=ok) + uptime. */
export function getSystemStatus(client: AxiosInstance): Promise<OpnsenseApiResult<SystemStatus>> {
  return get(client, '/api/core/system/status');
}

/** POST /api/core/system/reboot — DANGEROUS: reboots the appliance. */
export function reboot(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/system/reboot', {});
}

/** POST /api/core/system/halt — DANGEROUS: powers off the appliance. */
export function halt(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/system/halt', {});
}

/** GET /api/diagnostics/system/system_information — hostname + version list. */
export function getSystemInformation(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_information');
}

/**
 * GET /api/diagnostics/system/system_time — the appliance's CURRENT date/time
 * (device-local wall clock) + uptime + loadavg. This is the source for the Time
 * page's `system.deviceTime` metric: OPNsense has no separate "clock" endpoint,
 * and this one returns the live local time string directly.
 */
export function getSystemTime(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_time');
}

/**
 * GET /api/system/timezone/get_timezone — the appliance's configured IANA
 * timezone (e.g. "Europe/Berlin"). Combined with `system_time`'s local wall
 * clock this lets the Time page resolve an absolute instant and compute drift.
 */
export function getSystemTimezone(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/system/timezone/get_timezone');
}

/** POST /api/system/timezone/set_timezone — set the appliance IANA timezone.
 * Body: `{ timezone: 'Europe/Berlin' }`. Applies immediately (no staging). */
export function setSystemTimezone(client: AxiosInstance, timezone: string): Promise<OpnsenseApiResult> {
  return post(client, '/api/system/timezone/set_timezone', { timezone });
}

/** GET /api/diagnostics/system/system_resources — memory/cpu/uptime details. */
export function getSystemResources(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_resources');
}

// --- Storage (best-effort) --------------------------------------------------
// OPNsense exposes NO ZFS pool/dataset listing API — the only storage data is
// the mounted-filesystem overview below. Callers treat a missing endpoint as
// "no data" — never an error (see collectStorage in index.ts).

/** GET /api/diagnostics/system/system_disk/ — mounted filesystems.
 * Returns `{ devices: [{ device, type, blocks, used, available, used_pct,
 * mountpoint }] }` where the size fields are BASE-10 human strings ("5.2G")
 * exactly as OPNsense's own Disk widget consumes them (`_convertToBytes`). */
export function getSystemDisk(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/diagnostics/system/system_disk/');
}

// --- Storage parsing (pure, unit-tested) --------------------------------------
/** Parses OPNsense's base-10 human size strings ("5.2G", "800M") into bytes —
 * the SAME format + units (K=1000) the appliance's own Disk widget uses in
 * `_convertToBytes`. Accepts a raw number too, for defensive multi-shape reads. */
export function parseBase10Bytes(v: unknown): number | null {
  if (typeof v === 'number' && Number.isFinite(v)) return Math.round(v);
  if (typeof v !== 'string') return null;
  const m = v.trim().match(/^(\d+(?:\.\d+)?)([BKMGTPE]?)$/i);
  if (!m) return null;
  const num = parseFloat(m[1]);
  if (!Number.isFinite(num)) return null;
  const unit = (m[2] ?? '').toUpperCase();
  const mult: Record<string, number> = { '': 1, B: 1, K: 1e3, M: 1e6, G: 1e9, T: 1e12, P: 1e15, E: 1e18 };
  return Math.round(num * (mult[unit] ?? 1));
}

/** Maps OPNsense's mounted-filesystem `type` to a Storage-page filesystem type.
 * The ZFS case is resolved by the CALLER (see parseSystemDiskRows): on a
 * ZFS-rooted appliance df reports every MOUNTED DATASET as its own entry with
 * type "zfs", so only a slash-free name is a real pool. */
export function opnsenseFsType(raw: string | null): string {
  switch ((raw ?? '').toLowerCase()) {
    case 'zfs': return 'zfs-pool';
    case 'ext2':
    case 'ext3':
    case 'ext4': return 'ext4';
    case 'squashfs': return 'squashfs';
    default: return 'other'; // ufs, msdosfs and anything else — no dedicated badge
  }
}

/**
 * Parses the mounted-filesystem overview (`/api/diagnostics/system/system_disk`)
 * into Storage-page rows. The appliance runs `df -abT` server-side (disk_info.py):
 * on a ZFS-rooted box EVERY MOUNTED DATASET appears as its own entry with type
 * "zfs" — zroot, zroot/ROOT/default, zroot/home, zroot/var/log, … A real pool
 * name never contains '/', so slash-free names are pools and everything else is
 * a dataset nested under the first path segment (its pool). Without this split a
 * ZFS-rooted appliance shows up as N fake top-level "pools" (one per mounted
 * dataset) and the Storage summary double-counts capacity. A missing/404
 * response yields an empty array — the caller then omits the metric keys
 * entirely (no wipe). Field names vary across OPNsense releases, so every read
 * is defensive multi-key; size fields are base-10 human strings ("5.2G").
 */
export function parseSystemDiskRows(
  diskRes: { ok: boolean; data?: unknown } | undefined
): Record<string, unknown>[] {
  const filesystems: Record<string, unknown>[] = [];
  if (!diskRes?.ok) return filesystems;

  // system_disk returns `{ devices: [...] }` (not a recordset). Be defensive.
  const d = diskRes.data as Record<string, unknown> | undefined;
  const rows = Array.isArray(d?.['devices']) ? (d!['devices'] as unknown[]) : [];
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue;
    const r = raw as Record<string, unknown>;
    const name = pickString(r, ['device', 'name']);
    if (!name) continue;
    // `blocks` = total capacity; `used`/`available` are base-10 human strings.
    const sizeBytes = parseBase10Bytes(r['blocks']);
    const usedBytes = parseBase10Bytes(r['used']);
    const freeBytes = parseBase10Bytes(r['available']);
    // ZFS: a mounted dataset (slash in the name) nests under its pool — only a
    // slash-free name is a real pool. See the function doc for why this matters.
    let type = opnsenseFsType(pickString(r, ['type']) ?? null);
    let parent: string | null = null;
    if (type === 'zfs-pool' && name.includes('/')) {
      type = 'zfs-dataset';
      parent = name.slice(0, name.indexOf('/'));
    }
    filesystems.push({
      name,
      type,
      mountpoint: pickString(r, ['mountpoint', 'mounted-on']) ?? null,
      sizeBytes: sizeBytes ?? null,
      usedBytes: usedBytes ?? (sizeBytes !== null && freeBytes !== null ? sizeBytes - freeBytes : null),
      freeBytes: freeBytes ?? (sizeBytes !== null && usedBytes !== null ? Math.max(0, sizeBytes - usedBytes) : null),
      status: 'online', // present in the mounted list = active + readable
      parent,
    });
  }

  return filesystems;
}

// --- Service control (core/service) ---------------------------------------

/** GET /api/core/service/search — all services + running state. */
export function searchServices(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/service/search', query);
}

/** POST /api/core/service/start/$name — start one service (e.g. `pf`, `unbound`). */
export function startService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/start/${encodeURIComponent(name)}`, {});
}

/** POST /api/core/service/stop/$name — stop one service. */
export function stopService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/stop/${encodeURIComponent(name)}`, {});
}

/** POST /api/core/service/restart/$name — restart one service. */
export function restartService(client: AxiosInstance, name: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/service/restart/${encodeURIComponent(name)}`, {});
}

// --- Tunables (core/tunables) ---------------------------------------------

/** GET /api/core/tunables/get — all tunable items. */
export function getTunables(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/tunables/get');
}

/** POST /api/core/tunables/add_item — add a kernel tunable (staged). */
export function addTunable(client: AxiosInstance, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/tunables/add_item', { item });
}

/** POST /api/core/tunables/set_item/$uuid — update a tunable (staged). */
export function setTunable(client: AxiosInstance, uuid: string, item: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/tunables/set_item/${encodeURIComponent(uuid)}`, { item });
}

/** POST /api/core/tunables/del_item/$uuid — remove a tunable (staged). */
export function deleteTunable(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/tunables/del_item/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/core/tunables/reconfigure — activate staged tunable changes. */
export function reconfigureTunables(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return post(client, '/api/core/tunables/reconfigure', {});
}

// --- Defaults (core/defaults) ---------------------------------------------

/** GET /api/core/defaults/get — current default values. */
export function getDefaults(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/defaults/get');
}
