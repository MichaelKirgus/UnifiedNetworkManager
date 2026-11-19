/**
 * Container BOM (bill of materials) for the Docker plugin — per-container
 * installed-package inventory via Engine API exec (NO SSH needed):
 *   POST /containers/{id}/exec {Cmd: ['sh','-c', BOM_PROBE_SCRIPT]} → Id
 *   POST /exec/{Id}/start {Tty:false} → multiplexed stdout stream
 * The shared SDK probe script reports the container's distro + full package
 * list (dpkg/apk/rpm/pacman); rows are emitted into the generic
 * `installedPackages` metric with component='container' so the API's CVE
 * worker matches them exactly like host packages.
 *
 * BUDGET: /monitoring has a hard ~10 s budget, so one poll probes only as many
 * STALE containers as fit in BOM_POLL_DEADLINE_MS (waves of BOM_CONCURRENCY);
 * the rest carry over to the next inventory-due poll. A per-container TTL
 * cache means steady-state polls cost nothing — packages only change when a
 * container is recreated with a new image (new id → fresh probe).
 *
 * Emission contract (same as every other CONFIG-object metric):
 *   - key present + rows = upsert those, delete-on-absent the rest;
 *   - key present + EMPTY array = authoritative wipe (no running containers);
 *   - a container whose probe FAILED keeps its last cached rows (stale beats
 *     wiped) — only containers that vanished from `docker ps` lose their rows.
 *
 * COVERAGE GUARD: the cache is in-memory, so after a plugin restart it starts
 * empty. Emitting PARTIAL coverage would make delete-on-absent wipe the stored
 * rows of not-yet-probed containers on every deploy — therefore this function
 * returns null (caller omits the key → no wipe) until EVERY running container
 * has at least one cache entry, fresh or stale.
 */

import { BOM_PROBE_SCRIPT, parseBomOutput } from '@unm/plugin-sdk';
import type { BomProbeResult } from '@unm/plugin-sdk';
import { containerExecCreate, containerExecStartRaw, demuxDockerStream, DockerClientOptions } from './client';
import type { DockerContainerRaw } from './inventory';

/** Package lists change only on image update/recreate — 6 h is plenty. */
const BOM_TTL_MS = 6 * 3_600_000;
/** Concurrent exec probes per wave — keeps a busy daemon responsive. */
const BOM_CONCURRENCY = 4;
/** Hard cap on BOM work inside ONE /monitoring poll (the API's budget is ~10 s). */
const BOM_POLL_DEADLINE_MS = 6_000;

interface BomCacheEntry {
  at: number;
  /** null = probed but no data (no shell / scratch image) — cached so we don't re-probe it. */
  result: BomProbeResult | null;
}

/** Per-container probe cache, keyed by container id (recreate → new id). */
const bomCache = new Map<string, BomCacheEntry>();

function nameOf(c: DockerContainerRaw): string {
  const raw = Array.isArray(c.Names) && c.Names.length > 0 ? String(c.Names[0]) : '';
  return raw.replace(/^\/+/, '') || 'unknown';
}

/** One container's probe: exec create + start + demux + parse. null = no data. */
async function probeOne(opts: DockerClientOptions, c: DockerContainerRaw): Promise<BomProbeResult | null> {
  const created = await containerExecCreate(opts, String(c.Id), ['sh', '-c', BOM_PROBE_SCRIPT]);
  if (!created.ok || !created.data?.Id) return null; // no sh in the image (scratch/distroless) or exec refused
  const started = await containerExecStartRaw(opts, String(created.data.Id));
  if (!started.ok) return null;
  return parseBomOutput(demuxDockerStream(started.data));
}

/**
 * Probes stale running containers (TTL-cached, deadline-capped per poll) and
 * returns `installedPackages` rows for every container with known data — or
 * null while coverage is incomplete (see module docs). NEVER throws — a failed
 * probe degrades to "keep previous rows" for that container.
 */
export async function collectContainerPackages(
  opts: DockerClientOptions,
  rawContainers: DockerContainerRaw[],
): Promise<Record<string, unknown>[] | null> {
  const running = rawContainers.filter((c) => c && typeof c.Id === 'string' && String(c.State ?? '').toLowerCase() === 'running');

  // GC cache entries for containers that no longer exist (deleted/stopped).
  const liveIds = new Set(running.map((c) => String(c.Id)));
  for (const key of Array.from(bomCache.keys())) {
    if (!liveIds.has(key)) bomCache.delete(key);
  }

  // Probe stale containers in waves until the per-poll deadline. Containers
  // whose probe fails keep their previous cache entry (stale beats wiped).
  const now = Date.now();
  const deadline = now + BOM_POLL_DEADLINE_MS;
  const stale = running.filter((c) => {
    const e = bomCache.get(String(c.Id));
    return !e || now - e.at >= BOM_TTL_MS;
  });
  for (let i = 0; i < stale.length && Date.now() < deadline; i += BOM_CONCURRENCY) {
    const wave = stale.slice(i, i + BOM_CONCURRENCY);
    await Promise.all(wave.map(async (c) => {
      try {
        bomCache.set(String(c.Id), { at: Date.now(), result: await probeOne(opts, c) });
      } catch {
        /* keep previous entry — a failed probe must never wipe data */
      }
    }));
  }

  // COVERAGE GUARD — see module docs. `running` empty → vacuously covered →
  // the EMPTY array below is the authoritative wipe (host has no containers).
  const covered = running.every((c) => bomCache.has(String(c.Id)));
  if (!covered) return null;

  // Rows for every running container with known data (fresh or stale cache).
  const rows: Record<string, unknown>[] = [];
  for (const c of running) {
    const entry = bomCache.get(String(c.Id));
    if (!entry || !entry.result) continue; // probed but no shell/data — nothing to emit
    const eco = entry.result.ecosystemTag ?? 'unknown';
    const cname = nameOf(c);
    for (const p of entry.result.packages) {
      rows.push({
        name: p.name,
        version: p.version,
        ecosystem: eco,
        component: 'container',
        componentName: cname,
        extra: { image: typeof c.Image === 'string' ? c.Image : null },
      });
    }
  }
  return rows; // EMPTY = no running containers (authoritative wipe)
}
