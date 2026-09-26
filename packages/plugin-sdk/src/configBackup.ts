/**
 * @unm/plugin-sdk — shared config-backup naming convention.
 *
 * Every plugin that downloads a device's running configuration (TrueNAS
 * `config.save`, SwOS `.swb`, LCOS web-UI backup, …) stores it in UNM's central
 * file repository through the API broker (`createFileRepoClient`). This module
 * is the ONE place that decides how those files are named, so backups from all
 * vendors follow the same pattern and stay sortable/recognizable on the Files
 * page:
 *
 *   <device>__config-backup-<YYYYMMDD-HHMMSS>.<ext>
 *
 * e.g. `KIRGUSBANDE__config-backup-20260926-134502.db`,
 *      `swos-leaf-01__config-backup-20260926-134502.swb`.
 *
 * The device part is the UNM DEVICE NAME when the API provides one, else the
 * management host (sanitized — no path separators, spaces or other characters
 * that would break on-disk names). The timestamp is UTC so files from different
 * timezones sort consistently.
 */

/** Sanitizes a device name / host into a safe file-name fragment. */
export function sanitizeBackupDevicePart(raw: string | null | undefined): string {
  const base = (raw ?? '').trim();
  if (!base) return 'device';
  // Keep letters, digits, dots and dashes; everything else → '-'. Collapse runs.
  let out = base.replace(/[^A-Za-z0-9.\-]+/g, '-').replace(/-{2,}/g, '-').replace(/^[-.]+|[-.]+$/g, '');
  if (!out) return 'device';
  // Bound the length so name + timestamp + extension stays well under limits.
  return out.slice(0, 80);
}

/** UTC timestamp fragment for backup file names: YYYYMMDD-HHMMSS. */
export function backupTimestamp(date: Date = new Date()): string {
  const p = (n: number): string => String(n).padStart(2, '0');
  return `${date.getUTCFullYear()}${p(date.getUTCMonth() + 1)}${p(date.getUTCDate())}-${p(date.getUTCHours())}${p(date.getUTCMinutes())}${p(date.getUTCSeconds())}`;
}

export interface ConfigBackupNameOptions {
  /** UNM device name (preferred) — falls back to the management host. */
  device?: string | null;
  /** Management address / host of the device (fallback when no device name). */
  host?: string | null;
  /** File extension WITHOUT leading dot, e.g. 'db', 'swb'. Default 'cfg'. */
  ext?: string;
  /** Injectable clock (tests). Defaults to now. */
  date?: Date;
}

/**
 * Builds the canonical config-backup file name for a device:
 * `<device>__config-backup-<YYYYMMDD-HHMMSS>.<ext>` (UTC timestamp).
 *
 * Plugins call this when storing a freshly downloaded configuration backup in
 * UNM's central file repository, so every vendor produces the same pattern and
 * new plugins inherit it for free.
 */
export function configBackupFileName(opts: ConfigBackupNameOptions = {}): string {
  const devicePart = sanitizeBackupDevicePart(opts.device ?? opts.host);
  const ext = (opts.ext ?? 'cfg').replace(/^\./, '').trim() || 'cfg';
  return `${devicePart}__config-backup-${backupTimestamp(opts.date)}.${ext}`;
}
