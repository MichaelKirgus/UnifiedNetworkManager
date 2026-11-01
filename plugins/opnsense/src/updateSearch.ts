/**
 * Automatic update search — cadence gate.
 *
 * OPNsense appliances only ADVERTISE available updates after an update search
 * has run on-device (`POST /api/core/firmware/status`, a synchronous probe
 * against pkg.opnsense.org that takes ~30–90 s). The monitoring path reads the
 * appliance's CACHED check result (fast GET), so a device that never ran a
 * search shows no updates forever. This module decides WHEN the plugin should
 * trigger such a probe on its poll cadence; the actual fire-and-forget call
 * lives in index.ts next to the other per-host background work.
 */

/** Per-appliance state for the automatic update search (keyed by management address). */
export interface UpdateSearchEntry {
  /** Epoch ms of the last SUCCESSFUL search — cadence is measured from success, so a failed probe retries on the next beat. */
  lastRunAt: number;
  /** A probe is currently in flight for this appliance (prevents overlap). */
  inFlight: boolean;
}

/** Why the gate allowed or denied an update search. */
export type UpdateSearchDecision = 'run' | 'skip-disabled' | 'skip-cadence' | 'skip-inflight';

/** Default interval — 6 h. One 30–90 s probe per device per 6 h is trivial load; 0 disables automatic searches entirely. */
export const DEFAULT_UPDATE_CHECK_INTERVAL_SEC = 21_600;

/**
 * Staleness guard for FORCED checks: a forced check younger than this is
 * skipped because the appliance's cache was refreshed by that probe moments
 * ago — re-probing would only serialize every REST call behind configd's lock
 * for another 30–90 s (rapid "Check now" clicks, overlapping refreshes).
 */
export const FORCED_CHECK_MIN_SINCE_MS = 5 * 60_000;

/**
 * Pure cadence gate for the automatic update search (unit-tested in isolation).
 *
 * - `everyMs === 0` and no force → disabled by setting, never runs.
 * - a probe already in flight → skip (rapid "Check now" clicks / overlapping polls must not stack probes).
 * - cadence not elapsed since the last SUCCESSFUL search → skip — UNLESS this is an explicit forced check ("Check now"), which bypasses both cadence and a zero interval.
 * - a FORCED check younger than `minSinceMs` (default 5 min) → skip: the cache is already fresh from that probe, re-probing would only block every REST call on the appliance for another 30–90 s.
 */
export function decideUpdateSearch(
  entry: UpdateSearchEntry | undefined,
  nowMs: number,
  everyMs: number,
  force: boolean,
  minSinceMs = FORCED_CHECK_MIN_SINCE_MS
): UpdateSearchDecision {
  if (everyMs === 0 && !force) return 'skip-disabled';
  if (entry?.inFlight) return 'skip-inflight';
  if (!force && entry !== undefined && nowMs - entry.lastRunAt < everyMs) return 'skip-cadence';
  if (force && entry !== undefined && nowMs - entry.lastRunAt < minSinceMs) return 'skip-cadence';
  return 'run';
}
