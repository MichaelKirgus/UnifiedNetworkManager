import { LEADER_KEYS } from './leader';
import { initWorker, trackBeat } from './stats';
import { sweepFileRepoRetention } from '../fileRepoRetention';

/**
 * Retention worker for central file-repo files (see src/fileRepoRetention.ts).
 *
 * Runs the policy-driven sweep on an hourly beat: every ENABLED retention
 * policy deletes its ASSIGNED files that violate maxAgeDays and/or
 * keepLatestPerDevice. Files with no assigned policy are NEVER touched — they
 * are kept forever by design (the "no policy = infinite" contract). Deletion
 * goes through deleteRepoFile(), so bytes are removed from whichever file-repo
 * provider owns them, for every plugin with the `fileRepo` capability.
 */

const SWEEP_INTERVAL_MS = 3_600_000; // hourly — same cadence as log retention

async function sweep(): Promise<void> {
  const result = await sweepFileRepoRetention();
  if (result.totalDeleted > 0) {
    // eslint-disable-next-line no-console
    console.log(`[file-repo-retention] sweep removed ${result.totalDeleted} file(s)`);
  }
}

/**
 * Starts the file-repo retention sweep. Must be called only after the API has
 * bound its port (same rule as every other worker — see index.ts app.listen).
 */
export function startFileRepoRetentionWorker(): NodeJS.Timeout {
  initWorker('fileRepoRetention', LEADER_KEYS.fileRepoRetention);
  // eslint-disable-next-line no-console
  console.log('[file-repo-retention] worker started (policies read live from the database)');

  // First sweep runs immediately so files that aged out while the feature was
  // off (or a policy changed) are cleaned up without waiting an hour.
  void trackBeat('fileRepoRetention', sweep).catch((err) => {
    // eslint-disable-next-line no-console
    console.error('[file-repo-retention] initial sweep failed:', err);
  });

  return setInterval(() => {
    void trackBeat('fileRepoRetention', sweep).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[file-repo-retention] sweep failed:', err);
    });
  }, SWEEP_INTERVAL_MS);
}
