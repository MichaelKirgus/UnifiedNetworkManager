/**
 * Container BOM (bill of materials) for the TrueNAS plugin — per-container
 * installed-package lists via `docker exec` over the pooled SSH session.
 *
 * WHY: the CVE/vulnerability feature matches OSV advisories against the
 * `installedPackages` metric, but until now only HOST packages were collected.
 * The software that actually runs in TrueNAS apps (nginx, php-fpm, …) lives in
 * containers — this module makes "which version of which package runs in which
 * container" visible fleet-wide and CVE-matchable (`component: 'container'`).
 *
 * HOW: mirrors the enrichment.ts background pattern — /monitoring never blocks.
 * One cycle = ONE small `docker ps` enumeration + one `docker exec <probe>` per
 * running container, SEQUENTIALLY over the shared SSH session (the same sshd
 * connection enrichment uses must not be flooded with parallel execs). Results
 * are cached per host with a 6-hour TTL; while coverage is incomplete the retry
 * interval drops to 15 min.
 *
 * WHY PER-CONTAINER (not one combined loop command): a single combined command
 * for a real fleet (250+ containers, mostly Debian-based apps with hundreds of
 * packages each) produces MULTI-MEGABYTE output — the SDK's exec() truncates
 * stdout at 256 KB, so the tail of the list would be silently dropped while the
 * exit code stayed 0. Per-container execs keep every response far below that cap,
 * give each probe its own timeout budget (a combined loop for 259 containers
 * exceeds any sane single-exec budget on a loaded appliance), and make progress
 * incrementally: an interrupted cycle keeps everything it already probed.
 */

import { BOM_PROBE_SCRIPT, dynamicSshHostVerifier, parseBomOutput, resolveSshCredentials, SshAuthError, SshError, SshHostKeyError, type SshClient } from '@unm/plugin-sdk';
import { hostSshPort, sshPool } from './ssh';

/** One installed package row as emitted into the `installedPackages` metric. */
export interface BomPackageRow {
  name: string;
  version: string | null;
  ecosystem: string;
  component: 'container';
  componentName: string;
}

/** Healthy hosts re-probe every 6 h — package lists change with app updates,
 * not continuously. */
const BOM_TTL_MS = 6 * 3_600_000;
/** While coverage is incomplete (or after a failed cycle) retry every 15 min —
 * the same cadence as the enrichment cycles. */
const BOM_RETRY_MS = 15 * 60_000;
/** Same defensive cap as enrichment.ts — a runaway box must not pin the shared
 * SSH session for hours. Containers beyond the cap keep their previous entries. */
const MAX_CONTAINERS = 400;
/** Budget for the `docker ps` enumeration command (output is a few KB). */
const BOM_ENUMERATE_TIMEOUT_MS = 30_000;
/** Per-container probe budget — the script is one package-manager query, so a
 * healthy probe takes <5 s even on a loaded appliance. The SDK retries a timed-
 * out exec once, so a WEDGED container (pkg lock held forever / unresponsive
 * runtime) costs at most ~2× this per cycle attempt — kept short because real
 * fleets have several of them and they must not dominate the shared session. */
const BOM_PROBE_TIMEOUT_MS = 10_000;
/** Consecutive probe failures after which we ACCEPT THE GAP for one full TTL:
 * a container that keeps failing (e.g. dpkg lock held forever) stops burning
 * every cycle's budget and is only re-probed on the next 6 h sweep. */
const BOM_FAIL_STREAK_ACCEPT_GAP = 3;
/** Soft wall-clock deadline for ONE full cycle: if the appliance degrades
 * mid-cycle (every probe eating its full budget) we stop rather than holding
 * the shared SSH session indefinitely — coverage stays incomplete and the next
 * retry resumes where the cache left off. */
const BOM_CYCLE_DEADLINE_MS = 30 * 60_000;

/** Per-host cached BOM state. */
interface HostBomState {
  /** container name → last known-good rows (may be [] for no-shell images). */
  entries: Map<string, BomPackageRow[]>;
  /** container name → last successful probe time (drives per-container TTL skips
   * so steady-state cycles don't re-probe everything on a loaded appliance). */
  freshAt: Map<string, number>;
  /** container name → consecutive probe failures (drives the accept-the-gap
   * backoff for permanently wedged containers). */
  failStreak: Map<string, number>;
  /** Running set considered in the last cycle (null = never probed). */
  lastRunning: Set<string> | null;
  /** When the last collection attempt started (0 = never). */
  lastAttemptAt: number;
  /** Whether the last completed cycle covered every running container. */
  covered: boolean;
}

const bomState = new Map<string, HostBomState>();
/** Per-host in-flight dedup — a second poll arriving mid-collection shares the
 * promise instead of piling up more execs on the appliance sshd. */
const bomInFlight = new Map<string, Promise<void>>();

function newHostBomState(): HostBomState {
  return { entries: new Map(), freshAt: new Map(), failStreak: new Map(), lastRunning: null, lastAttemptAt: 0, covered: false };
}

/** Enumerates running containers (short id + name) with ONE small command.
 * Returns null when the docker CLI failed — the caller must keep ALL previous
 * state in that case (a broken `docker ps` says nothing about the fleet). */
async function enumerateContainers(
  client: SshClient,
  sshCreds: NonNullable<ReturnType<typeof resolveSshCredentials>>
): Promise<{ id: string; name: string }[] | null> {
  const r = await client.exec(`docker ps --format '{{.ID}} {{.Names}}' 2>/dev/null`, sshCreds, BOM_ENUMERATE_TIMEOUT_MS);
  if (r.code !== 0) return null;
  const out: { id: string; name: string }[] = [];
  for (const line of r.stdout.split('\n')) {
    const sp = line.indexOf(' ');
    if (sp <= 0) continue; // blank / malformed — skip
    out.push({ id: line.slice(0, sp), name: line.slice(sp + 1).trim() });
  }
  return out;
}

/** Runs ONE BOM collection cycle over the shared SSH pool and merges results
 * into the per-host cache INCREMENTALLY. Never throws — a failed or interrupted
 * cycle keeps all previous state (the API then simply re-serves what it has). */
async function collectBom(
  host: string,
  sshCreds: NonNullable<ReturnType<typeof resolveSshCredentials>>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<void> {
  const st = bomState.get(host) ?? newHostBomState();
  const startedAt = Date.now();
  try {
    const port = hostSshPort(host);
    const client = await sshPool.get(host, port, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host, port) });

    // 1. Enumerate the running set — one small command (a few KB of output).
    const running = await enumerateContainers(client, sshCreds);
    if (running === null) {
      log?.('warn', `SSH container BOM on ${host}: docker ps failed — keeping previous data`);
      return; // keep all previous state entirely
    }

    // 2. Probe each container with its OWN exec: bounded output (one package
    // list, far below the SDK's 256 KB stdout cap), a per-container timeout,
    // and incremental progress — an interrupted cycle keeps what it probed.
    // Containers whose data is still within the TTL are skipped (steady-state
    // cycles stay cheap; only gaps and expired entries get re-probed).
    const fresh = new Set<string>();
    // A container that fails repeatedly must not burn every cycle's budget:
    // after N consecutive failures we ACCEPT THE GAP for one full TTL — it then
    // counts as covered (its rows stay absent/stale in the API) and is only
    // re-probed on the next 6 h sweep.
    const noteProbeFailure = (name: string): void => {
      const streak = (st.failStreak.get(name) ?? 0) + 1;
      st.failStreak.set(name, streak);
      if (streak >= BOM_FAIL_STREAK_ACCEPT_GAP) {
        log?.('warn', `SSH container BOM on ${host}: "${name}" failed ${streak}× in a row — accepting the gap for one TTL cycle`);
        st.freshAt.set(name, Date.now()); // skip until the next full-TTL sweep
        fresh.add(name); // counts as covered → stops the 15-min retry storm
      }
    };
    for (const c of running.slice(0, MAX_CONTAINERS)) {
      if (Date.now() - startedAt > BOM_CYCLE_DEADLINE_MS) break; // soft deadline — the retry resumes
      const probedAt = st.freshAt.get(c.name);
      if (probedAt !== undefined && Date.now() - probedAt < BOM_TTL_MS) {
        fresh.add(c.name); // still valid — no need to re-probe this cycle
        continue;
      }
      let r: { code: number; stdout: string; stderr: string };
      try {
        r = await client.exec(`docker exec "${c.id}" sh -c '${BOM_PROBE_SCRIPT}' 2>/dev/null`, sshCreds, BOM_PROBE_TIMEOUT_MS);
      } catch (e) {
        if (e instanceof SshAuthError || e instanceof SshHostKeyError) {
          // Real credential/pinning failure — every subsequent probe fails the same way.
          log?.('warn', `SSH container BOM on ${host} aborted: ${e.message}`);
          return;
        }
        if (e instanceof SshError) {
          // Transient — timeout or dropped session (the SDK already tore down and
          // reconnects on the next exec). One wedged container must not kill the
          // whole cycle: keep its previous entry (a coverage gap until retry).
          log?.('warn', `SSH container BOM on ${host}: probe of "${c.name}" failed — keeping previous data (${e.message})`);
          noteProbeFailure(c.name);
          continue;
        }
        throw e;
      }
      if (r.code === 126 || r.code === 127) {
        // "no such file / not executable" from the runtime — the image has no
        // usable sh. Deterministic → authoritative empty (nothing to track).
        st.entries.set(c.name, []);
        st.freshAt.set(c.name, Date.now());
        st.failStreak.delete(c.name);
        fresh.add(c.name);
      } else if (r.code !== 0) {
        // Transient/unknown exec failure — keep the previous entry; this name
        // stays a coverage gap until the next cycle.
        noteProbeFailure(c.name);
      } else {
        const res = parseBomOutput(r.stdout);
        if (res === null) {
          // Exec "succeeded" but produced no ECO header — unexpected; keep previous.
          noteProbeFailure(c.name);
        } else {
          st.entries.set(
            c.name,
            res.packages.map((p) => ({
              name: p.name,
              version: p.version,
              ecosystem: res.ecosystemTag ?? 'unknown',
              component: 'container' as const,
              componentName: c.name,
            }))
          );
          st.freshAt.set(c.name, Date.now());
          st.failStreak.delete(c.name);
          fresh.add(c.name);
        }
      }
    }

    // 3. GC entries whose container is gone — but ONLY when we saw the FULL
    // running set (cap not hit): beyond MAX_CONTAINERS unprobed rows must stay.
    const considered = new Set(running.slice(0, MAX_CONTAINERS).map((c) => c.name));
    if (running.length <= MAX_CONTAINERS) {
      for (const name of Array.from(st.entries.keys())) {
        if (!considered.has(name)) st.entries.delete(name);
      }
      for (const name of Array.from(st.freshAt.keys())) {
        if (!considered.has(name)) st.freshAt.delete(name);
      }
      for (const name of Array.from(st.failStreak.keys())) {
        if (!considered.has(name)) st.failStreak.delete(name);
      }
    }
    st.lastRunning = considered;
    st.lastAttemptAt = Date.now();
    // Coverage: every running container we considered must have FRESH data from
    // this cycle (ok or no-shell). Stale entries alone never count as covered.
    st.covered = Array.from(considered).every((n) => fresh.has(n));
    bomState.set(host, st);
  } catch (e) {
    if (e instanceof SshError) log?.('warn', `SSH container BOM on ${host} failed: ${e.message}`);
    else log?.('warn', `SSH container BOM on ${host} unexpected error: ${(e as Error).message}`);
    // best-effort — keep previous data, never sink the poll
  }
}

/**
 * Schedules a background BOM collection when due (TTL / retry-aware) with
 * per-host in-flight dedup. Called from the /monitoring handler; returns
 * immediately and NEVER blocks the poll. No-op without a bound ssh slot —
 * API-only devices simply have no container BOM data.
 */
export function ensureBom(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  log?: (level: 'info' | 'warn', message: string) => void
): void {
  if (!sshCreds) return; // no ssh slot bound — nothing to probe over
  if (bomInFlight.has(host)) return; // collection already running for this host
  const st = bomState.get(host);
  const interval = st?.covered ? BOM_TTL_MS : BOM_RETRY_MS;
  if (st && Date.now() - st.lastAttemptAt < interval) return; // fresh enough

  const p = collectBom(host, sshCreds, log).finally(() => {
    if (bomInFlight.get(host) === p) bomInFlight.delete(host);
  });
  bomInFlight.set(host, p);
}

/**
 * Reads the cached BOM rows for emission into `installedPackages`. Emits whatever
 * the cache holds for currently-running containers — INCLUDING partial coverage:
 * ingestion is keyed per (component|container|package), so a container missing
 * from this batch simply keeps its previous rows (nothing is ever wiped by a gap).
 * Returns null only while there is nothing usable to emit at all (never probed,
 * or every probe failed) — the caller then OMITS the key. An empty array IS
 * emitted when the host genuinely runs no containers (authoritative wipe).
 */
export function getBomRows(host: string): BomPackageRow[] | null {
  const st = bomState.get(host);
  if (!st || !st.lastRunning) return null; // never probed successfully
  const out: BomPackageRow[] = [];
  for (const [name, rows] of st.entries) {
    if (!st.lastRunning.has(name)) continue; // defensive: only running containers
    out.push(...rows);
  }
  if (out.length === 0 && st.lastRunning.size > 0) return null; // nothing usable yet — keep previous
  return out;
}

/** Test hook — clears all cached state. */
export function __resetBomForTests(): void {
  bomState.clear();
  bomInFlight.clear();
}
