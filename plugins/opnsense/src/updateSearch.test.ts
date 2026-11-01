/**
 * Unit tests for the automatic update-search cadence gate (decideUpdateSearch).
 * Pure logic — no appliance, no network. The gate decides whether /monitoring
 * should trigger a fresh on-device update probe given the per-host state, the
 * configured interval and whether this is an explicit forced check ("Check now").
 */
import { decideUpdateSearch, DEFAULT_UPDATE_CHECK_INTERVAL_SEC } from './updateSearch';

const NOW = 1_700_000_000_000; // arbitrary fixed "now" — the gate must be deterministic
const HOUR_MS = 3_600_000;

describe('decideUpdateSearch', () => {
  it('runs on first sight (no entry yet) when an interval is configured', () => {
    expect(decideUpdateSearch(undefined, NOW, 21_600_000, false)).toBe('run');
  });

  it('never runs when the interval is 0 and this is not a forced check (disabled by setting)', () => {
    expect(decideUpdateSearch(undefined, NOW, 0, false)).toBe('skip-disabled');
    // …even with a stale entry from before the user set 0.
    expect(
      decideUpdateSearch({ lastRunAt: NOW - 10 * HOUR_MS, inFlight: false }, NOW, 0, false)
    ).toBe('skip-disabled');
  });

  it('skips while a probe is already in flight (no overlapping probes)', () => {
    expect(
      decideUpdateSearch({ lastRunAt: 0, inFlight: true }, NOW, 21_600_000, false)
    ).toBe('skip-inflight');
    // In-flight wins over cadence — a due probe must not stack on the running one.
    expect(
      decideUpdateSearch({ lastRunAt: NOW - 48 * HOUR_MS, inFlight: true }, NOW, 21_600_000, false)
    ).toBe('skip-inflight');
  });

  it('skips when the cadence has not elapsed since the last successful search', () => {
    const entry = { lastRunAt: NOW - HOUR_MS, inFlight: false }; // searched 1 h ago
    expect(decideUpdateSearch(entry, NOW, 21_600_000, false)).toBe('skip-cadence');
  });

  it('runs again once the cadence has elapsed', () => {
    const entry = { lastRunAt: NOW - 21 * HOUR_MS, inFlight: false }; // exactly due
    expect(decideUpdateSearch(entry, NOW, 21_600_000, false)).toBe('run');
    const overdue = { lastRunAt: NOW - 48 * HOUR_MS, inFlight: false };
    expect(decideUpdateSearch(overdue, NOW, 21_600_000, false)).toBe('run');
  });

  it('a forced check bypasses the cadence', () => {
    const entry = { lastRunAt: NOW - HOUR_MS, inFlight: false }; // searched 1 h ago
    expect(decideUpdateSearch(entry, NOW, 21_600_000, true)).toBe('run');
  });

  it('a forced check bypasses a zero interval (explicit "Check now" always probes)', () => {
    expect(decideUpdateSearch(undefined, NOW, 0, true)).toBe('run');
    expect(
      decideUpdateSearch({ lastRunAt: NOW - HOUR_MS, inFlight: false }, NOW, 0, true)
    ).toBe('run');
  });

  it('a forced check still skips while a probe is in flight (one probe at a time)', () => {
    expect(decideUpdateSearch({ lastRunAt: 0, inFlight: true }, NOW, 0, true)).toBe(
      'skip-inflight'
    );
  });

  it('a forced check younger than the staleness guard (5 min) is skipped — cache already fresh', () => {
    const entry = { lastRunAt: NOW - 60_000, inFlight: false }; // probed 1 min ago
    expect(decideUpdateSearch(entry, NOW, 21_600_000, true)).toBe('skip-cadence');
    expect(decideUpdateSearch(entry, NOW, 0, true)).toBe('skip-cadence'); // also with interval 0
  });

  it('a forced check older than the staleness guard runs', () => {
    const entry = { lastRunAt: NOW - 6 * 60_000, inFlight: false }; // probed 6 min ago
    expect(decideUpdateSearch(entry, NOW, 21_600_000, true)).toBe('run');
  });

  it('exposes the documented default interval (6 h)', () => {
    expect(DEFAULT_UPDATE_CHECK_INTERVAL_SEC).toBe(21_600);
  });
});
