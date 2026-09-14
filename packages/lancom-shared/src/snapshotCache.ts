/**
 * The LANCOM slow-path snapshot cache trio — previously copy-pasted verbatim in
 * lancom-lcos, lancom-lx and lancom-sx:
 *   - a TTL-gated fresh-snapshot cache (TtlCache), and
 *   - a last-known map so a failed refresh can still fall back to the most
 *     recent data even after TTL expiry.
 *
 * Each plugin instantiates its own pair (typed to its snapshot) via
 * createSnapshotCaches() — one per process, keyed by host string.
 */

import { TtlCache } from '@unm/plugin-sdk';

/** The cache trio for one plugin's slow-path snapshots. */
export interface SnapshotCaches<V> {
  /** Fresh-snapshot cache (TTL-gated). */
  inventory: TtlCache<V>;
  /** Returns the last-known snapshot for a host (expired-but-usable fallback). */
  getStale(host: string): V | undefined;
  /** Records a complete snapshot as the last-known value (bounded to 512 hosts). */
  rememberLastKnown(host: string, snapshot: V): void;
}

/**
 * Creates a fresh-snapshot TTL cache + last-known fallback map for one plugin.
 * The last-known map is insertion-ordered and evicts its oldest entry above 512
 * hosts so it cannot grow unbounded across the device fleet.
 */
export function createSnapshotCaches<V>(): SnapshotCaches<V> {
  const inventory = new TtlCache<V>();
  const lastKnown = new Map<string, V>();
  return {
    inventory,
    getStale: (host) => lastKnown.get(host),
    rememberLastKnown: (host, snapshot) => {
      lastKnown.set(host, snapshot);
      if (lastKnown.size > 512) {
        const oldest = lastKnown.keys().next().value; // Map iteration = insertion order
        if (oldest !== undefined) lastKnown.delete(oldest);
      }
    },
  };
}
