/**
 * CounterTracker — the single counter-delta rate implementation (previously 4
 * independent copies: snmp sampleRate, lancom-lx sampleRate+sampleDelta, swos
 * StatsSample, opnsense attachTunnelRates).
 *
 * Invariants every copy encoded:
 *   - first sample for a key → null (no delta yet),
 *   - counter reset/wrap (new < old) → skip this sample,
 *   - baseline is refreshed on EVERY call so the next cycle has a reference,
 *   - stale hosts are evicted so the map can't grow unbounded.
 */

interface Baseline {
  value: number;
  at: number;
}

export interface CounterTrackerOptions {
  /** Octets→bits/s conversion (×8). Default true — set false for event counters or byte-rate trackers. */
  toBitsPerSec?: boolean;
  /** Evict keys unseen longer than this (default 2h). */
  staleMs?: number;
}

export class CounterTracker {
  private baselines = new Map<string, Baseline>();
  private readonly toBits: boolean;
  private readonly staleMs: number;

  constructor(opts: CounterTrackerOptions = {}) {
    this.toBits = opts.toBitsPerSec ?? true;
    this.staleMs = opts.staleMs ?? 2 * 60 * 60 * 1000;
  }

  /**
   * Samples one counter and returns the rate since the previous sample, or
   * null on first sample / reset. The baseline is always refreshed.
   */
  sample(key: string, current: number, now: number = Date.now()): number | null {
    const prev = this.baselines.get(key);
    // Always refresh the baseline so the NEXT cycle has a reference point.
    this.baselines.set(key, { value: current, at: now });

    if (!prev || now <= prev.at) return null; // first sample — no delta yet
    if (current < prev.value) return null; // counter reset/wrap — skip this sample

    const seconds = (now - prev.at) / 1000;
    const delta = current - prev.value;
    return this.toBits ? (delta * 8) / seconds : delta / seconds;
  }

  /** Drops keys unseen for longer than the stale window. */
  evictStale(now: number = Date.now()): void {
    for (const [key, b] of this.baselines) {
      if (now - b.at > this.staleMs) this.baselines.delete(key);
    }
  }

  /** Test hook. */
  clear(): void {
    this.baselines.clear();
  }
}
