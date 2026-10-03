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

// --- Backups, MVC endpoints (26.x restructured API; also present since ~19.7) --
//
// OPNsense 26.x removed the legacy flat endpoints (`/api/core/backup/backups`
// answers "Endpoint not found" — verified live on 26.4). The current surface is
// the MVC BackupController (OPNsense/Core/Api/BackupController.php):
//   GET /api/core/backup/providers          → { items: { this: { description, dirname }, <remote-host>: … } }
//   GET /api/core/backup/backups/{host}     → { items: [{ time, time_iso, description, username, filesize, id }] } (newest first; id = filename)
//   GET /api/core/backup/download/{host}[/{id}]  → raw config XML (application/octet-stream); empty id = latest
// None of the three are read-only-gated (only delete/revert call throwReadOnly),
// so a readonly API key can list AND download — verified live on OPNSENSE01
// (26.4.2p2) and GWBN01 (26.4.1p2).

/** One backup provider entry from /api/core/backup/providers. */
export interface BackupProvider {
  description?: string;
  dirname?: string;
}

/** GET /api/core/backup/providers — the local host ('this') plus any configured remote hosts. */
export function listBackupProviders(client: AxiosInstance): Promise<OpnsenseApiResult<{ items?: Record<string, BackupProvider> }>> {
  return get(client, '/api/core/backup/providers');
}

/** One row of /api/core/backup/backups/{host}. */
export interface MvcBackupRow {
  time: string;
  time_iso?: string;
  description?: string;
  username?: string;
  filesize?: number;
  /** The backup filename (e.g. `config-1789915464.3856.xml`) — also the download id. */
  id: string;
}

/** GET /api/core/backup/backups/{host} — list backups for one provider host ('this' = local). */
export function listBackupsForHost(client: AxiosInstance, host: string): Promise<OpnsenseApiResult<{ items?: MvcBackupRow[] }>> {
  return get(client, `/api/core/backup/backups/${encodeURIComponent(host)}`);
}

/**
 * GET /api/core/backup/download/{host}[/{id}] — download one backup as raw XML.
 * `id` empty = the LATEST local backup (the controller walks newest-first and
 * stops at the first match). Returns the raw bytes; callers sanity-check that
 * they look like an OPNsense config before storing/applying them.
 */
export async function downloadBackup(
  client: AxiosInstance,
  host: string,
  id?: string,
): Promise<OpnsenseApiResult> {
  const path = `/api/core/backup/download/${encodeURIComponent(host)}${id ? `/${encodeURIComponent(id)}` : ''}`;
  // The controller streams the file verbatim (application/octet-stream) — ask
  // axios for raw bytes so we don't lose anything to text decoding.
  const response = await client.get(path, { responseType: 'arraybuffer' });
  return { ok: response.status >= 200 && response.status < 300, status: response.status, data: Buffer.from(response.data as ArrayBuffer) };
}

/**
 * Resolves the local provider host key from /providers — normally `this`, but
 * some builds label it differently; fall back to the first entry. Returns null
 * when the endpoint is unavailable (pre-MVC firmware → legacy path).
 */
export async function resolveLocalBackupHost(client: AxiosInstance): Promise<string | null> {
  const res = await listBackupProviders(client);
  if (!res.ok || !res.data?.items) return null;
  const items = res.data.items as Record<string, BackupProvider>;
  if (items['this']) return 'this';
  const first = Object.keys(items)[0];
  return first ?? null;
}
