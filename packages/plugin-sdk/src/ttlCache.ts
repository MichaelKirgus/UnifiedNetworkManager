/**
 * TtlCache — the shared TTL cache (previously 4 hand-rolled copies with the
 * same shape: Map<key,{at,value}> + TTL check + set-on-success). Adds an
 * optional quality gate (only cache complete snapshots) and max-size eviction.
 */

export interface TtlCacheOptions {
  /** Only store values for which this returns true (quality gate against partial data). */
  isFresh?: (value: unknown) => boolean;
  /** Opportunistic eviction above this many entries (default 512). */
  maxSize?: number;
}

export class TtlCache<V> {
  private store = new Map<string, { at: number; value: V }>();
  private readonly isFresh?: (value: unknown) => boolean;
  private readonly maxSize: number;

  constructor(opts: TtlCacheOptions = {}) {
    this.isFresh = opts.isFresh;
    this.maxSize = opts.maxSize ?? 512;
  }

  /** Returns the cached value when younger than ttlMs, else undefined. */
  get(key: string, ttlMs: number, now: number = Date.now()): V | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    if (now - entry.at >= ttlMs) {
      this.store.delete(key);
      return undefined;
    }
    return entry.value;
  }

  /** Stores a value (skipped when the quality gate rejects it). */
  set(key: string, value: V, now: number = Date.now()): void {
    if (this.isFresh && !this.isFresh(value)) return;
    this.store.set(key, { at: now, value });
    // Opportunistic eviction so the map can't grow unbounded across devices:
    // drop the OLDEST entries until we're back under maxSize.
    if (this.store.size > this.maxSize) {
      const oldestFirst = [...this.store.entries()].sort((a, b) => a[1].at - b[1].at);
      for (const [k] of oldestFirst.slice(0, this.store.size - this.maxSize)) this.store.delete(k);
    }
  }

  /** Test hook. */
  clear(): void {
    this.store.clear();
  }

  get size(): number {
    return this.store.size;
  }
}
