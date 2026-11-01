/**
 * Auto-backup scheduler — leader-gated worker that creates scheduled backups.
 *
 * Driven entirely by the `autoBackup*` system settings (see systemSettings.ts):
 * when `autoBackupEnabled` is true, every beat we check whether a backup named
 * `auto-backup-<preset>-YYYY-MM-DD` exists from within `autoBackupIntervalMinutes`.
 * If not, one is created into the configured destination (local volume or the
 * bound file-repo instance) and stored like any manual backup.
 *
 * The "due" check is stateless — it looks at the backups table itself — so the
 * schedule self-heals after downtime, container restarts, or a manually deleted
 * archive: no extra state row to drift out of sync.
 */

import { randomUUID } from 'crypto';
import { and, gte, like } from 'drizzle-orm';
import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { db } from '../db';
import * as schema from '../db/schema';
import { getEffectiveSettingValue } from '../systemSettings';
import { PRESETS, buildArchive, gzipArchive, resolveBoundProvider, scopeForSections, storeLocalBackup, storeRepoBackup } from '../backup';

const BEAT_MS = 60_000; // scheduler granularity — cadence comes from the interval setting

/** Name prefix marking a row as auto-created (also used for the due check). */
export const AUTO_BACKUP_NAME_PREFIX = 'auto-backup-';

interface AutoBackupConfig {
  enabled: boolean;
  intervalMinutes: number;
  preset: string;
  destination: 'local' | 'repo';
  providerId: string | null;
}

/** Reads the effective auto-backup settings, clamped to sane ranges. */
export async function readAutoBackupConfig(): Promise<AutoBackupConfig> {
  const enabled = (await getEffectiveSettingValue('autoBackupEnabled')) === true;
  let intervalMinutes = Number(await getEffectiveSettingValue('autoBackupIntervalMinutes'));
  if (!Number.isFinite(intervalMinutes) || intervalMinutes < 15) intervalMinutes = 24 * 60;
  if (intervalMinutes > 7 * 24 * 60) intervalMinutes = 7 * 24 * 60;
  const presetRaw = String((await getEffectiveSettingValue('autoBackupPreset')) ?? 'config');
  const preset = PRESETS[presetRaw] ? presetRaw : 'config';
  const destination: 'local' | 'repo' = (await getEffectiveSettingValue('autoBackupDestination')) === 'repo' ? 'repo' : 'local';
  const providerIdRaw = String((await getEffectiveSettingValue('autoBackupProviderId')) ?? '').trim();
  return { enabled, intervalMinutes, preset, destination, providerId: providerIdRaw !== '' ? providerIdRaw.slice(0, 128) : null };
}

/** True when a backup created within the last `intervalMinutes` already exists. */
async function hasRecentAutoBackup(cfg: AutoBackupConfig): Promise<boolean> {
  const since = new Date(Date.now() - cfg.intervalMinutes * 60_000).toISOString();
  // LIKE with a literal prefix — the preset is validated against PRESETS above.
  const rows = await db
    .select({ id: schema.backups.id })
    .from(schema.backups)
    .where(and(like(schema.backups.name, `${AUTO_BACKUP_NAME_PREFIX}${cfg.preset}-%`), gte(schema.backups.createdAt, since)))
    .limit(1);
  return rows.length > 0;
}

/** Creates one auto-backup archive into the configured destination. */
export async function runAutoBackup(cfg: AutoBackupConfig): Promise<{ id: string; name: string }> {
  const sections = [...PRESETS[cfg.preset]];
  const archive = await buildArchive(sections);
  const { buffer, sha256, sizeBytes } = gzipArchive(archive);
  const id = randomUUID();
  const name = `${AUTO_BACKUP_NAME_PREFIX}${cfg.preset}-${new Date().toISOString().slice(0, 10)}`;

  let source: 'local' | 'repo' = 'local';
  let storedProviderId: string | null = null;
  if (cfg.destination === 'repo') {
    if (!cfg.providerId) throw new Error('autoBackupDestination is "repo" but autoBackupProviderId is empty');
    const provider = await resolveBoundProvider(cfg.providerId); // throws when the instance is gone/offline
    const identity = await storeRepoBackup(provider, buffer);
    source = 'repo';
    storedProviderId = provider.id;
  } else {
    await storeLocalBackup(id, buffer);
  }

  await db.insert(schema.backups).values({
    id,
    name,
    scope: scopeForSections(sections),
    sections: JSON.stringify(sections),
    sizeBytes,
    sha256,
    source,
    providerId: storedProviderId,
    createdAt: new Date().toISOString(),
  });

  // eslint-disable-next-line no-console
  console.log(`[auto-backup] created ${name} (${source}, ${(sizeBytes / 1024).toFixed(1)} KiB)`);
  return { id, name };
}

/** One scheduler beat: due check + fire the backup (errors logged, never thrown). */
async function beat(): Promise<void> {
  const cfg = await readAutoBackupConfig();
  if (!cfg.enabled) return;
  if (await hasRecentAutoBackup(cfg)) return;
  try {
    await runAutoBackup(cfg);
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[auto-backup] scheduled backup failed:', err);
  }
}

/**
 * Starts the auto-backup scheduler loop. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startAutoBackupWorker(): () => void {
  initWorker('autoBackup', LEADER_KEYS.autoBackup);
  // eslint-disable-next-line no-console
  console.log('[auto-backup] scheduler started');

  void trackBeat('autoBackup', beat).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[auto-backup] initial scan failed:', err);
  });

  const timer = setInterval(() => {
    void trackBeat('autoBackup', beat).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[auto-backup] scheduler beat failed:', err);
    });
  }, BEAT_MS);

  return () => clearInterval(timer);
}
