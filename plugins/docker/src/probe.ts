/**
 * Live probe collectors (POST /probe, capability 'probe') for the Docker Engine.
 * Unlike ix-truenas (which shells out to `docker stats` over SSH), this plugin
 * talks straight to the Engine REST API — so both keys are served from the same
 * transport the monitoring poll uses:
 *   - 'containerStates' → ONE /containers/json?all=true; running set = names in
 *     state "running". Absence = stopped. An EMPTY map is valid (all stopped).
 *   - 'containerStats'  → per-container GET /containers/{id}/stats?stream=false,
 *     fanned out with limited concurrency inside the ~8 s budget. CPU% comes from
 *     cpu_stats vs precpu_stats in the SAME sample; memory is direct; network +
 *     block I/O are cumulative counters fed to dedicated probe CounterTrackers so
 *     fast cycles yield fresh rates without disturbing any other baseline.
 */

import { CounterTracker } from '@unm/plugin-sdk';
import { DockerClientOptions, containerStats, listContainers } from './client';

/** One container's live stat snapshot as served by POST /probe (key 'containerStats'). */
export interface ProbeContainerStat {
  name: string;
  cpuPct?: number;
  memUsedBytes?: number;
  memLimitBytes?: number;
  netRxRate?: number;
  netTxRate?: number;
  blkReadRate?: number;
  blkWriteRate?: number;
}

/** One container's live state as served by POST /probe (key 'containerStates'). */
export interface ProbeContainerState {
  name: string;
  status: string; // always 'running' — only running containers are listed
}

// SEPARATE rate trackers for the probe path — the webapp polls every few seconds,
// so each interval yields a fresh average. (No other cycle samples these counters.)
const netRxTracker = new CounterTracker({ toBitsPerSec: false });
const netTxTracker = new CounterTracker({ toBitsPerSec: false });
const blkReadTracker = new CounterTracker({ toBitsPerSec: false });
const blkWriteTracker = new CounterTracker({ toBitsPerSec: false });

/** Throttled failure logging — a flaky daemon must not spam the log every poll. */
const lastProbeFailLog = new Map<string, number>();
function probeFailLog(host: string, message: string, log?: (level: 'info' | 'warn', message: string) => void): void {
  const now = Date.now();
  if (now - (lastProbeFailLog.get(host) ?? 0) < 60_000) return; // at most one warn/min/host
  lastProbeFailLog.set(host, now);
  log?.('warn', message);
}

/** Cap on concurrent /stats calls — keeps a busy host inside the probe budget. */
const STATS_CONCURRENCY = 12;
/** Hard cap on how many containers we'll stat in one probe (defensive). */
const MAX_STATS = 400;

interface RawContainer {
  Id?: string;
  Names?: string[];
  State?: string;
}

function nameOf(c: RawContainer): string {
  const raw = Array.isArray(c.Names) && c.Names.length > 0 ? String(c.Names[0]) : '';
  return raw.replace(/^\/+/, '') || 'unknown';
}

/**
 * Collects the set of RUNNING container names for the PROBE path: ONE cheap
 * /containers/json?all=true. Absence from the result IS the "stopped" signal —
 * callers treat a missing name as not-running. Returns null on transport failure;
 * an EMPTY map is a valid answer (all containers stopped) and must NOT be
 * conflated with failure.
 */
export async function collectProbeStates(
  opts: DockerClientOptions,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeContainerState> | null> {
  const host = opts.host || 'local';
  try {
    const r = await listContainers(opts);
    if (!r.ok || !Array.isArray(r.data)) {
      probeFailLog(host, `Docker /containers/json probe failed (HTTP ${r.status}): ${(r.error ?? '').slice(0, 200)}`, log);
      return null;
    }
    const out = new Map<string, ProbeContainerState>();
    for (const c of r.data as RawContainer[]) {
      if (!c || typeof c !== 'object') continue;
      if (String(c.State ?? '').toLowerCase() !== 'running') continue;
      const name = nameOf(c);
      if (name) out.set(name, { name, status: 'running' });
    }
    return out;
  } catch (e) {
    probeFailLog(host, `Docker /containers/json probe unexpected error: ${(e as Error).message}`, log);
    return null;
  }
}

/** Reads a number defensively from an unknown value. */
function num(v: unknown): number | undefined {
  return typeof v === 'number' && Number.isFinite(v) ? v : undefined;
}

/** CPU% from one non-streaming stats sample (cpu_stats vs precpu_stats). */
function cpuPctOf(s: Record<string, unknown>): number | undefined {
  const cur = s['cpu_stats'] as Record<string, unknown> | undefined;
  const pre = s['precpu_stats'] as Record<string, unknown> | undefined;
  if (!cur || !pre) return undefined;
  const cu = (cur['cpu_usage'] ?? {}) as Record<string, unknown>;
  const pu = (pre['cpu_usage'] ?? {}) as Record<string, unknown>;
  const totalDelta = num(cu['total_usage']) !== undefined && num(pu['total_usage']) !== undefined ? (num(cu['total_usage'])! - num(pu['total_usage'])!) : undefined;
  const sysDelta = num(cur['system_cpu_usage']) !== undefined && num(pre['system_cpu_usage']) !== undefined ? (num(cur['system_cpu_usage'])! - num(pre['system_cpu_usage'])!) : undefined;
  if (totalDelta === undefined || sysDelta === undefined || sysDelta <= 0) return undefined;
  const online = num(cur['online_cpus']) ?? 1;
  return Math.max(0, (totalDelta / sysDelta) * online * 100);
}

/** Sums a cumulative counter across all network interfaces. */
function netTotals(s: Record<string, unknown>): { rx?: number; tx?: number } {
  const nets = s['networks'] as Record<string, Record<string, unknown>> | undefined;
  if (!nets || typeof nets !== 'object') return {};
  let rx: number | undefined;
  let tx: number | undefined;
  for (const n of Object.values(nets)) {
    const r = num(n?.['rx_bytes']);
    const t = num(n?.['tx_bytes']);
    if (r !== undefined) rx = (rx ?? 0) + r;
    if (t !== undefined) tx = (tx ?? 0) + t;
  }
  return { rx, tx };
}

/** Sums blkio read/write cumulative counters. */
function blkTotals(s: Record<string, unknown>): { read?: number; write?: number } {
  const blkio = s['blkio_stats'] as Record<string, unknown> | undefined;
  const entries = (blkio?.['io_service_bytes'] ?? []) as Array<Record<string, unknown>>;
  let read: number | undefined;
  let write: number | undefined;
  for (const e of entries) {
    if (!e || typeof e !== 'object') continue;
    const op = String(e['op'] ?? '').toLowerCase();
    const v = num(e['value']);
    if (v === undefined) continue;
    if (op === 'read') read = (read ?? 0) + v;
    else if (op === 'write') write = (write ?? 0) + v;
  }
  return { read, write };
}

/** Maps one non-streaming stats sample onto a ProbeContainerStat. */
function statFromSample(name: string, host: string, s: Record<string, unknown>): ProbeContainerStat {
  const out: ProbeContainerStat = { name };
  const cpu = cpuPctOf(s);
  if (cpu !== undefined) out.cpuPct = Math.round(cpu * 10) / 10;

  const mem = s['memory_stats'] as Record<string, unknown> | undefined;
  const used = num(mem?.['usage']);
  const limit = num(mem?.['limit']);
  if (used !== undefined) out.memUsedBytes = used;
  // A limit of 0 or a huge sentinel means "unlimited" — don't surface it.
  if (limit !== undefined && limit > 0 && limit < Number.MAX_SAFE_INTEGER / 2) out.memLimitBytes = limit;

  const key = `probe|${host}|${name}`;
  const { rx, tx } = netTotals(s);
  const nr = rx !== undefined ? netRxTracker.sample(`${key}|netRx`, rx) : null;
  if (nr !== null && nr > 0) out.netRxRate = Math.round(nr);
  const nt = tx !== undefined ? netTxTracker.sample(`${key}|netTx`, tx) : null;
  if (nt !== null && nt > 0) out.netTxRate = Math.round(nt);

  const { read, write } = blkTotals(s);
  const br = read !== undefined ? blkReadTracker.sample(`${key}|blkRead`, read) : null;
  if (br !== null && br > 0) out.blkReadRate = Math.round(br);
  const bw = write !== undefined ? blkWriteTracker.sample(`${key}|blkWrite`, write) : null;
  if (bw !== null && bw > 0) out.blkWriteRate = Math.round(bw);

  return out;
}

/**
 * Collects live per-container stats for the PROBE path: one /containers/json to
 * enumerate running containers, then a bounded-concurrency fan-out of
 * /containers/{id}/stats?stream=false. Returns null on transport failure (the
 * webapp keeps its last good snapshot); an EMPTY map is valid (nothing running).
 */
export async function collectProbeStats(
  opts: DockerClientOptions,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeContainerStat> | null> {
  const host = opts.host || 'local';
  try {
    const list = await listContainers(opts);
    if (!list.ok || !Array.isArray(list.data)) {
      probeFailLog(host, `Docker /containers/json (stats) failed (HTTP ${list.status}): ${(list.error ?? '').slice(0, 200)}`, log);
      return null;
    }
    const running = (list.data as RawContainer[]).filter((c) => c && String(c.State ?? '').toLowerCase() === 'running').slice(0, MAX_STATS);
    if (running.length === 0) return new Map();

    const out = new Map<string, ProbeContainerStat>();
    let cursor = 0;
    async function worker(): Promise<void> {
      while (cursor < running.length) {
        const idx = cursor++;
        const c = running[idx];
        const idOrName = typeof c.Id === 'string' && c.Id ? c.Id : nameOf(c);
        if (!idOrName) continue;
        try {
          const r = await containerStats(opts, idOrName);
          if (r.ok && r.data && typeof r.data === 'object') {
            out.set(nameOf(c), statFromSample(nameOf(c), host, r.data));
          }
        } catch { /* per-container failure is non-fatal — skip it */ }
      }
    }
    const workers = Array.from({ length: Math.min(STATS_CONCURRENCY, running.length) }, () => worker());
    await Promise.all(workers);
    return out;
  } catch (e) {
    probeFailLog(host, `Docker stats probe unexpected error: ${(e as Error).message}`, log);
    return null; // best-effort — the webapp keeps its last good snapshot
  }
}
