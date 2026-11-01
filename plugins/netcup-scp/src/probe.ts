/**
 * Short-cycle live probe for netcup SCP devices (capability 'probe').
 *
 * The webapp's VMs page polls POST /probe every 3 s through the API broker,
 * requesting the keys `vmStates` + `vmStats`. SCP has no SSH access and no
 * per-poll state endpoint — its live data comes from the metrics time series:
 *   GET /servers/{id}/metrics/cpu?hours=N → { "<ISO minute>": { "CPU0": <rate>, ... } }
 * where each value is a RATE in ns of CPU time consumed per wall-clock second
 * (cgroup-style accounting; 1e9 = that core at 100%) — the same rate family as
 * disk (IOPS) and network (B/s). Verified live against www.servercontrolpanel.de.
 *
 * vmStats: cpuPct = mean over vCPUs of (latest point / 1e9), clamped to 0–100 —
 * "percent of ALLOCATED vCPUs", the same semantics as TrueNAS's virsh-based
 * column. A short in-process cache (keyed by device) absorbs the 3 s page poll:
 * netcup is only hit at most once per PROBE_CACHE_TTL_MS, and a failed refresh
 * keeps serving the last good snapshot until it goes stale.
 */

import type { ScpClient } from './client/scpClient';

/** How long a collected probe snapshot stays fresh (page polls every 3 s). */
const PROBE_CACHE_TTL_MS = 15_000;
/** Max cached snapshots (one per device) — evict the oldest on overflow. */
const PROBE_CACHE_MAX = 64;

interface ProbeCacheEntry {
  at: number;
  stats: Record<string, { cpuPct?: number; vcpus?: number }>;
}

/** In-process snapshot cache (module-level — one plugin process per device fleet). */
const probeCache = new Map<string, ProbeCacheEntry>();

function cacheSet(key: string, entry: ProbeCacheEntry): void {
  if (probeCache.size >= PROBE_CACHE_MAX) {
    // Evict the oldest entry (Map iteration order = insertion order).
    const oldest = probeCache.keys().next().value;
    if (oldest !== undefined) probeCache.delete(oldest);
  }
  probeCache.set(key, entry);
}

/**
 * Collects live per-VM CPU stats for one SCP account.
 * Returns a map keyed by VM NAME: `{ cpuPct?, vcpus? }`.
 * Throws when the server list (auth probe) fails — the broker maps that to 502.
 */
export async function collectScpVmStats(client: ScpClient, deviceId: string): Promise<Record<string, { cpuPct?: number; vcpus?: number }>> {
  const key = `${deviceId}|${client.baseUrl}`;

  // Serve a fresh cached snapshot without touching netcup at all.
  const hit = probeCache.get(key);
  if (hit && Date.now() - hit.at < PROBE_CACHE_TTL_MS) return hit.stats;

  // 1. Server inventory — doubles as the auth probe and provides id + name.
  const servers = await client.listServers();

  // 2. CPU metrics for every server, in parallel (one call each, hours=1 keeps
  //    the payload small: ≤60 points × vCPUs). A failed per-server read degrades
  //    to "no cpuPct for that VM" — never fails the whole probe.
  const results = await Promise.allSettled(
    servers.map((s) => client.getServerCpuMetrics(s.id, 1)),
  );

  const stats: Record<string, { cpuPct?: number; vcpus?: number }> = {};
  for (let i = 0; i < servers.length; i++) {
    const r = results[i];
    if (r.status !== 'fulfilled') continue; // keep whatever the cache had for this VM
    const series = r.value ?? {};
    const points = Object.entries(series)
      .filter(([, v]) => v && typeof v === 'object')
      .sort(([a], [b]) => a.localeCompare(b)); // ISO-8601 → lexicographic = chronological
    if (points.length === 0) continue;

    const latest = points[points.length - 1][1] as Record<string, number>;
    const values = Object.values(latest).filter((v): v is number => typeof v === 'number' && Number.isFinite(v));
    if (values.length === 0) continue;

    // Mean over the VM's vCPUs of (ns CPU-time / s wall) ÷ 1e9 → percent of one
    // core, i.e. percent of ALLOCATED capacity (2 cores at 50% = 50%, not 100%).
    const meanRate = values.reduce((sum, v) => sum + v, 0) / values.length;
    const cpuPct = Math.min(100, Math.max(0, (meanRate / 1e9) * 100));

    stats[servers[i].name] = {
      cpuPct: Math.round(cpuPct * 10) / 10,
      vcpus: values.length, // one series entry per allocated vCPU
    };
  }

  cacheSet(key, { at: Date.now(), stats });
  return stats;
}
