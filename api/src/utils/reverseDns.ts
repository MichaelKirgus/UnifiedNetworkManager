/**
 * Best-effort reverse DNS (PTR) lookups for flow endpoint IPs.
 *
 * Used by the top-talkers route to attach a hostname to EXTERNAL talker IPs —
 * internal/known-device IPs are never looked up (they're already identified).
 * The lookup is strictly best-effort: it must never throw, never block the
 * request for long, and caches both positive and negative results.
 */

import { promises as dns } from 'node:dns';

const IP_LITERAL_RE = /^\d{1,3}(\.\d{1,3}){3}$/; // IPv4 only — v6 PTR is out of scope for v1

const CACHE_TTL_MS = 60 * 60_000; // 1 h — PTR records rarely change
// Negatives (no PTR, timeout) get a SHORT ttl: a transient resolver hiccup
// (e.g. DNS not ready right after container start) must self-heal within
// minutes, not sit in the cache for an hour.
const NEGATIVE_TTL_MS = 5 * 60_000;
const LOOKUP_TIMEOUT_MS = 2_000; // hard cap per lookup so a dead resolver can't stall the route

interface CacheEntry {
  hostname: string | null;
  at: number;
  ttlMs: number;
}

const cache = new Map<string, CacheEntry>();
/** In-flight dedup — concurrent lookups for the same IP share one promise. */
const inFlight = new Map<string, Promise<string | null>>();

// Bound the cache so a long-running process with churning IPs can't grow it forever.
const MAX_CACHE_ENTRIES = 10_000;

function pruneCache(): void {
  if (cache.size <= MAX_CACHE_ENTRIES) return;
  const now = Date.now();
  for (const [ip, entry] of cache) {
    if (now - entry.at > entry.ttlMs) cache.delete(ip);
  }
  // Still over the cap (all fresh) — drop the oldest entries.
  if (cache.size > MAX_CACHE_ENTRIES) {
    const excess = cache.size - MAX_CACHE_ENTRIES;
    let dropped = 0;
    for (const ip of cache.keys()) {
      if (dropped++ >= excess) break;
      cache.delete(ip);
    }
  }
}

/**
 * Reverse-resolve an IPv4 literal to a hostname. Returns `null` when the IP is
 * not a plain IPv4 literal, has no PTR record, or the lookup times out/fails.
 * Never throws. Positive results cache for 1 h; negatives (incl. timeouts)
 * only 5 min so transient resolver failures self-heal quickly.
 */
export async function reverseLookup(ip: string): Promise<string | null> {
  if (!IP_LITERAL_RE.test(ip)) return null;

  const hit = cache.get(ip);
  if (hit && Date.now() - hit.at < hit.ttlMs) return hit.hostname;

  const pending = inFlight.get(ip);
  if (pending) return pending;

  const promise = (async (): Promise<string | null> => {
    let hostname: string | null = null;
    try {
      // dns.promises.reverse takes no options/signal — race a timer instead.
      const answers = await Promise.race([
        dns.reverse(ip),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('reverse-dns timeout')), LOOKUP_TIMEOUT_MS).unref()),
      ]);
      // First answer wins — multi-PTR records are rare and order is arbitrary.
      hostname = Array.isArray(answers) && answers.length > 0 ? String(answers[0]) : null;
    } catch {
      hostname = null; // timeout, or no PTR — all "no name"
    }
    cache.set(ip, { hostname, at: Date.now(), ttlMs: hostname === null ? NEGATIVE_TTL_MS : CACHE_TTL_MS });
    pruneCache();
    return hostname;
  })().finally(() => {
    inFlight.delete(ip);
  });

  inFlight.set(ip, promise);
  return promise;
}

/** Test hook — clear the lookup cache. */
export function resetReverseDnsCache(): void {
  cache.clear();
  inFlight.clear();
}
