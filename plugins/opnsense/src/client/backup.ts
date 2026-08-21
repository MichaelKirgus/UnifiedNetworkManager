import { AxiosInstance } from 'axios';
import { get, post, OpnsenseApiResult } from './http';

/**
 * Snapshots + backups (core/snapshots, core/backup). This is the appliance's
 * native rollback primitive: snapshots are point-in-time config copies that can
 * be activated; remote/local backups can be reverted. The plugin uses these to
 * capture pre-change state before dangerous/staged-write plans.
 */

/** GET /api/core/snapshots/is_supported — whether this firmware supports snapshots. */
export function snapshotsSupported(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/snapshots/is_supported');
}

/** GET /api/core/snapshots/search — list existing snapshots (rows[]). */
export function searchSnapshots(client: AxiosInstance, query?: Record<string, unknown>): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/snapshots/search', query);
}

/** POST /api/core/snapshots/add — create a snapshot. Returns the new uuid in data. */
export function addSnapshot(client: AxiosInstance): Promise<OpnsenseApiResult<{ uuid?: string }>> {
  return post(client, '/api/core/snapshots/add', {});
}

/** GET /api/core/snapshots/get/$uuid — one snapshot's metadata. */
export function getSnapshot(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return get(client, `/api/core/snapshots/get/${encodeURIComponent(uuid)}`);
}

/** POST /api/core/snapshots/activate/$uuid — DANGEROUS: restore this snapshot (reboots into it). */
export function activateSnapshot(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/snapshots/activate/${encodeURIComponent(uuid)}`, {});
}

/** POST /api/core/snapshots/del/$uuid — delete a snapshot. */
export function deleteSnapshot(client: AxiosInstance, uuid: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/snapshots/del/${encodeURIComponent(uuid)}`, {});
}

// --- Backups (core/backup) --------------------------------------------------

/** GET /api/core/backup/backups — list available backups. */
export function listBackups(client: AxiosInstance): Promise<OpnsenseApiResult> {
  return get(client, '/api/core/backup/backups');
}

/** POST /api/core/backup/revert_backup/$backup — DANGEROUS: revert to a backup. */
export function revertBackup(client: AxiosInstance, backup: string): Promise<OpnsenseApiResult> {
  return post(client, `/api/core/backup/revert_backup/${encodeURIComponent(backup)}`, {});
}
