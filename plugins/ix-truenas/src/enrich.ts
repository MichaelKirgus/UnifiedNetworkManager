/**
 * Optional enrichment data path for the TrueNAS plugin — per-app compose detail
 * (app.config) and per-container docker facts over SSH.
 *
 * WHY: the public API's `app.query` gives app-level state but NO static IPs,
 * NO per-container MACs and NO start times; `app.config(name)` carries the
 * compose config (static IPs + hostnames) but is a PER-APP call — ~250+ apps
 * take far longer than the API's hard 10 s poll budget when fetched inline.
 * And the per-container MAC simply does not exist anywhere in the public API
 * (verified: no docker.container.* methods, core.arp blind to macvlan peers).
 *
 * HOW: this module runs BOTH enrichments in the BACKGROUND with a 15-minute
 * cache — /monitoring never blocks on them and always serves the freshest
 * cached state it has (possibly empty right after startup):
 *
 *   - app.config wave: bounded concurrency (8) on the shared WebSocket, only
 *     when no /monitoring poll is in flight for this host (the appliance's
 *     socket tolerates ~4 calls/s; overlapping bursts used to close it).
 *   - docker inspect over SSH (ONE combined command): real per-container MACs,
 *     IPs and start times — only when the user bound an `ssh` credential slot.
 *     Independent transport → safe to run while a poll is in flight.
 *
 * The API data stays PRIMARY: everything already available via pool.query /
 * app.query / interface.query is never re-fetched over SSH; SSH fills exactly
 * the gaps above (and only what the user opted into).
 */

import { CounterTracker, createSshPool, dynamicSshHostVerifier, pickString, resolveSshCredentials, SshError } from '@unm/plugin-sdk';
import type { TruenasClient, TruenasCredentials } from './client/truenasClient';

// ---------------------------------------------------------------------------
// Compose-config detail (moved here from index.ts — shared with the wave below)
// ---------------------------------------------------------------------------

/** One service's network placement from its compose config (app.config). */
/** One volume mount as declared in a compose service's `volumes`. */
export interface ContainerVolume {
  /** Host path or named volume (the source). */
  source: string;
  /** Path inside the container (the target); omitted when not resolvable. */
  target?: string;
  /** 'ro' | 'rw'. */
  mode?: string;
}

export interface ServiceNetDetail {
  /** Compose `hostname` — the container's L3 name. */
  hostname: string;
  /** Static IPv4/IPv6 addresses assigned on the app's networks. */
  ips: string[];
  /** Network names this service is attached to. */
  networks: string[];
  /** Volume mounts declared for this service (compose `volumes`), host→container. */
  volumes: ContainerVolume[];
}

/**
 * Extracts per-service network + volume detail from ONE app's compose config
 * (app.config). The TrueNAS public API exposes NO per-container MAC — but the
 * compose config carries each service's `hostname` + static
 * `ipv4_address`/`ipv6_address`, and its declared `volumes` mounts.
 */
export function serviceNetDetails(cfg: Record<string, unknown> | undefined): ServiceNetDetail[] {
  const out: ServiceNetDetail[] = [];
  if (!cfg || typeof cfg !== 'object') return out;
  const svcs = cfg['services'];
  if (!svcs || typeof svcs !== 'object' || Array.isArray(svcs)) return out;
  for (const svc of Object.values(svcs as Record<string, unknown>)) {
    const s = svc as Record<string, unknown>;
    // Compose `hostname` is the container's L3 name. Fall back to container_name
    // then the service key — but prefer an explicit hostname when present.
    const hostname = pickString(s, ['hostname']) ?? pickString(s, ['container_name']) ?? '';
    if (!hostname) continue;
    const ips = new Set<string>();
    const networks: string[] = [];
    const svcNets = s['networks'];
    if (svcNets && typeof svcNets === 'object' && !Array.isArray(svcNets)) {
      for (const [netName, netCfg] of Object.entries(svcNets as Record<string, unknown>)) {
        networks.push(netName);
        const nc = (netCfg ?? {}) as Record<string, unknown>;
        const ip4 = pickString(nc, ['ipv4_address']);
        if (ip4) ips.add(ip4);
        const ip6 = pickString(nc, ['ipv6_address']);
        if (ip6) ips.add(ip6);
      }
    }
    // Declared volume mounts: "source[:target[:mode]]" strings or {type,...} objects.
    const volumes: ContainerVolume[] = [];
    const rawVols = s['volumes'];
    if (Array.isArray(rawVols)) {
      for (const rv of rawVols) {
        let source = '';
        let target = '';
        let mode = '';
        if (typeof rv === 'string') {
          const parts = rv.split(':');
          source = (parts[0] ?? '').trim();
          target = (parts[1] ?? '').trim();
          mode = (parts[2] ?? '').trim();
        } else if (rv && typeof rv === 'object') {
          const o = rv as Record<string, unknown>;
          source = pickString(o, ['source']) ?? '';
          target = pickString(o, ['target']) ?? '';
          mode = o['read_only'] === true ? 'ro' : '';
        }
        if (!source) continue;
        volumes.push({ source, ...(target ? { target } : {}), ...(mode ? { mode } : {}) });
      }
    }
    out.push({ hostname, ips: Array.from(ips).sort(), networks: networks.sort(), volumes });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Docker facts over SSH
// ---------------------------------------------------------------------------

/** One container's observed network placement (from `docker inspect`). */
export interface DockerContainerNet {
  network: string;
  mac: string;
  ip: string;
}

/** Per-container facts the public API cannot provide. */
export interface DockerContainerInfo {
  /** Full 64-char docker container id (matches app.query container_details[].id). */
  id: string;
  /** Container name without leading slash. */
  name: string;
  /** running | exited | paused | ... (docker State.Status, lowercase). */
  state: string;
  /** ISO-8601 UTC start of the current RUNNING period (only when state=running). */
  startedAt?: string;
  /** One entry per attached network with a real MAC. */
  nets: DockerContainerNet[];
}

/** Process-wide SSH pool — one session per appliance, RE-USED across polls.
 *  Exported so the action registry (containers.logs.read) can reuse the SAME
 *  pooled sessions instead of opening a fresh connection per log read. */
export const sshPool = createSshPool();
process.on('SIGTERM', () => sshPool.closeAll());
process.on('SIGINT', () => sshPool.closeAll());

/** Caps the container list (defensive — a runaway box must not bloat the command). */
const MAX_CONTAINERS = 400;

/**
 * Builds ONE combined read-only shell command that inspects every known
 * container in a single pass. Output contract (parsed by parseDockerInspect /
 * parseDockerStats):
 *   <64-hex-id>|<name>|<state>|<startedAt>     one line per container
 *   NET|<network>|<mac>|<ip>                   one line per attached network
 *   STAT|<name>|<cpu%>|<memUsed/memLimit>|<netRx/netTx>|<blkRead/blkWrite>
 *                                              one line per container (docker stats)
 */
function buildDockerInspectCommand(ids: string[]): string {
  const fmt =
    "{{.Id}}|{{.Name}}|{{.State.Status}}|{{.State.StartedAt}}" +
    '{{range $n, $v := .NetworkSettings.Networks}}\nNET|{{$n}}|{{$v.MacAddress}}|{{$v.IPAddress}}{{end}}';
  // Known ids from app.query (exact set UNM tracks); fall back to `docker ps`
  // when the API gave none (e.g. custom apps without container_details).
  const list =
    ids.length > 0
      ? ids.join(' ')
      : `$(docker ps -aq 2>/dev/null | head -n ${MAX_CONTAINERS})`;
  return [
    `for id in ${list}; do docker inspect "$id" --format '${fmt}' 2>/dev/null; done`,
    // Live per-container stats — the SAME source the TrueNAS UI shows (CPU
    // utilization, RAM usage/limit, network + block I/O). CPU% and memory are
    // instantaneous; Net IO / Block IO are CUMULATIVE since container start,
    // so rates come from deltas across enrichment cycles (computeContainerStats).
    `docker stats --no-stream ${list} --format 'STAT|{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}' 2>/dev/null`,
  ].join('\n');
}

const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;

/** Parses the combined `docker inspect` output into container infos. */
export function parseDockerInspect(stdout: string): DockerContainerInfo[] {
  const out: DockerContainerInfo[] = [];
  let cur: DockerContainerInfo | null = null;
  for (const line of stdout.split('\n')) {
    if (!line) continue;
    if (line.startsWith('NET|')) {
      if (!cur) continue; // network line before any container header — skip
      const parts = line.split('|');
      const net = parts[1] ?? '';
      const mac = (parts[2] ?? '').toLowerCase();
      const ip = parts[3] ?? '';
      if (net && MAC_RE.test(mac)) cur.nets.push({ network: net, mac, ip });
      continue;
    }
    const parts = line.split('|');
    // Container header: 64-hex id first. Anything else is noise — ignore.
    if (parts.length >= 3 && /^[0-9a-f]{64}$/.test(parts[0] ?? '')) {
      cur = {
        id: parts[0],
        name: (parts[1] ?? '').replace(/^\//, ''),
        state: (parts[2] ?? '').toLowerCase(),
        startedAt: parts[3] && parts[3].trim() !== '' ? parts[3].trim() : undefined,
        nets: [],
      };
      out.push(cur);
    } else {
      cur = null; // malformed line — detach any dangling NET lines
    }
  }
  return out;
}

/** One container's RAW docker-stats observation (keyed by container name).
 * CPU% + memory are instantaneous; the four I/O fields are CUMULATIVE byte
 * counters since container start (rates are derived across cycles). */
export interface DockerStatsRaw {
  cpuPct?: number;
  memUsedBytes?: number;
  /** Memory limit in bytes — absent when the container has no limit. */
  memLimitBytes?: number;
  netRxBytes?: number;
  netTxBytes?: number;
  blkReadBytes?: number;
  blkWriteBytes?: number;
}

/** One container's derived stats as emitted into container rows: instantaneous
 * CPU/RAM + AVERAGE throughput since the previous enrichment cycle (bytes/s).
 * Rates are absent on the first sample after a restart or counter reset. */
export interface ContainerStat {
  /** Instantaneous CPU utilization in percent (docker stats sampling window). */
  cpuPct?: number;
  memUsedBytes?: number;
  /** Memory limit in bytes — undefined when the container has no limit. */
  memLimitBytes?: number;
  /** Average network throughput since the previous cycle, bytes/s. */
  netRxRate?: number;
  netTxRate?: number;
  /** Average block (disk) I/O since the previous cycle, bytes/s. */
  blkReadRate?: number;
  blkWriteRate?: number;
}

/** docker stats human sizes: "512.2kB", "7.8GiB", "0B" — base-1024 suffixes. */
const HUMAN_SIZE_RE = /^([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?i?B?)$/i;
const SIZE_MULT: Record<string, number> = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4, PB: 1024 ** 5 };

/** Parses one docker humanized size ("5.2MiB") into bytes; undefined for "—"/garbage. */
export function parseHumanBytes(s: string | null | undefined): number | undefined {
  const t = (s ?? '').trim();
  if (!t || t === '—') return undefined;
  const m = HUMAN_SIZE_RE.exec(t);
  if (!m) return undefined;
  const mult = SIZE_MULT[m[2].toUpperCase().replace('I', '')] ?? 1;
  const v = parseFloat(m[1]) * mult;
  return Number.isFinite(v) ? Math.round(v) : undefined;
}

/** Splits a docker "a / b" pair (memory usage/limit, net rx/tx, …). */
function splitPair(s: string | null | undefined): [string, string] {
  const t = (s ?? '').trim();
  if (!t || t === '—') return ['', ''];
  const i = t.indexOf(' / ');
  if (i < 0) return [t, ''];
  return [t.slice(0, i), t.slice(i + 3)];
}

/** Parses the STAT| lines of the combined SSH output into per-name raw stats. */
export function parseDockerStats(stdout: string): Map<string, DockerStatsRaw> {
  const out = new Map<string, DockerStatsRaw>();
  for (const line of stdout.split('\n')) {
    if (!line.startsWith('STAT|')) continue;
    const parts = line.split('|'); // STAT | name | cpu% | memUsed/memLimit | netRx/netTx | blkRead/blkWrite
    if (parts.length < 6) continue;
    const name = (parts[1] ?? '').replace(/^\//, '');
    if (!name) continue;
    const raw: DockerStatsRaw = {};
    const cpu = parseFloat((parts[2] ?? '').replace('%', ''));
    if (Number.isFinite(cpu)) raw.cpuPct = cpu;
    const [mu, ml] = splitPair(parts[3]);
    const used = parseHumanBytes(mu);
    if (used !== undefined) raw.memUsedBytes = used;
    const limit = parseHumanBytes(ml);
    if (limit !== undefined && limit > 0) raw.memLimitBytes = limit;
    const [nr, nt] = splitPair(parts[4]);
    const rx = parseHumanBytes(nr);
    if (rx !== undefined) raw.netRxBytes = rx;
    const tx = parseHumanBytes(nt);
    if (tx !== undefined) raw.netTxBytes = tx;
    const [br, bw] = splitPair(parts[5]);
    const rd = parseHumanBytes(br);
    if (rd !== undefined) raw.blkReadBytes = rd;
    const wr = parseHumanBytes(bw);
    if (wr !== undefined) raw.blkWriteBytes = wr;
    out.set(name, raw);
  }
  return out;
}

/** One CounterTracker per cumulative counter — baselines survive across the
 * 15-min enrichment cycles so each cycle yields an average rate over the gap. */
const statTrackers: Record<'netRx' | 'netTx' | 'blkRead' | 'blkWrite', CounterTracker> = {
  netRx: new CounterTracker({ toBitsPerSec: false }),
  netTx: new CounterTracker({ toBitsPerSec: false }),
  blkRead: new CounterTracker({ toBitsPerSec: false }),
  blkWrite: new CounterTracker({ toBitsPerSec: false }),
};

/** Derives per-container stats (instantaneous CPU/RAM + average I/O rates) from
 * one cycle's raw docker-stats observations. First sample / counter reset →
 * the rate is simply absent for that container this cycle. */
export function computeContainerStats(host: string, raw: Map<string, DockerStatsRaw>): Map<string, ContainerStat> {
  const out = new Map<string, ContainerStat>();
  for (const [name, r] of raw) {
    const key = `${host}|${name}`;
    const stat: ContainerStat = {};
    if (r.cpuPct !== undefined) stat.cpuPct = r.cpuPct;
    if (r.memUsedBytes !== undefined) stat.memUsedBytes = r.memUsedBytes;
    if (r.memLimitBytes !== undefined) stat.memLimitBytes = r.memLimitBytes;
    const nr = r.netRxBytes !== undefined ? statTrackers.netRx.sample(`${key}|netRx`, r.netRxBytes) : null;
    if (nr !== null && nr > 0) stat.netRxRate = Math.round(nr);
    const nt = r.netTxBytes !== undefined ? statTrackers.netTx.sample(`${key}|netTx`, r.netTxBytes) : null;
    if (nt !== null && nt > 0) stat.netTxRate = Math.round(nt);
    const br = r.blkReadBytes !== undefined ? statTrackers.blkRead.sample(`${key}|blkRead`, r.blkReadBytes) : null;
    if (br !== null && br > 0) stat.blkReadRate = Math.round(br);
    const bw = r.blkWriteBytes !== undefined ? statTrackers.blkWrite.sample(`${key}|blkWrite`, r.blkWriteBytes) : null;
    if (bw !== null && bw > 0) stat.blkWriteRate = Math.round(bw);
    out.set(name, stat);
  }
  return out;
}

/** Collects docker container facts + live stats over SSH (null when no slot / on failure). */
async function collectDockerViaSsh(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  containerIds: string[],
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<{ infos: DockerContainerInfo[]; stats: Map<string, DockerStatsRaw> } | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  try {
    const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
    const r = await client.exec(buildDockerInspectCommand(containerIds.slice(0, MAX_CONTAINERS)), sshCreds);
    if (r.code !== 0 && !r.stdout) {
      log?.('warn', `SSH docker inspect on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`);
      return null;
    }
    const infos = parseDockerInspect(r.stdout);
    if (infos.length === 0 && containerIds.length > 0) {
      log?.('warn', `SSH docker inspect on ${host}: no containers parsed (${r.stderr.slice(0, 120)})`);
    }
    return { infos, stats: parseDockerStats(r.stdout) };
  } catch (e) {
    if (e instanceof SshError) log?.('warn', `SSH docker inspect on ${host} failed: ${e.message}`);
    else log?.('warn', `SSH docker inspect on ${host} unexpected error: ${(e as Error).message}`);
    return null; // best-effort — keep previous data, never sink the poll
  }
}

// ---------------------------------------------------------------------------
// Live probe (POST /probe) — short-cycle stats for on-demand webapp polling
// ---------------------------------------------------------------------------

/** One container's live stat snapshot as served by POST /probe (key 'containerStats'). */
export interface ProbeContainerStat {
  /** Container name (docker, no leading slash). */
  name: string;
  cpuPct?: number;
  memUsedBytes?: number;
  memLimitBytes?: number;
  netRxRate?: number;
  netTxRate?: number;
  blkReadRate?: number;
  blkWriteRate?: number;
}

/** SEPARATE rate trackers for the probe path — the webapp polls every few
 * seconds, so each interval yields a fresh average WITHOUT disturbing the
 * 15-min enrichment baselines (which would otherwise see a "reset" whenever
 * the fast cycle refreshes them first). */
const probeStatTrackers: Record<'netRx' | 'netTx' | 'blkRead' | 'blkWrite', CounterTracker> = {
  netRx: new CounterTracker({ toBitsPerSec: false }),
  netTx: new CounterTracker({ toBitsPerSec: false }),
  blkRead: new CounterTracker({ toBitsPerSec: false }),
  blkWrite: new CounterTracker({ toBitsPerSec: false }),
};

/** Throttled failure logging — a flaky sshd must not spam the log every poll. */
const lastProbeFailLog = new Map<string, number>();
function probeFailLog(host: string, message: string, log?: (level: 'info' | 'warn', message: string) => void): void {
  const now = Date.now();
  if (now - (lastProbeFailLog.get(host) ?? 0) < 60_000) return; // at most one warn/min/host
  lastProbeFailLog.set(host, now);
  log?.('warn', message);
}

/**
 * Per-host in-flight dedup for the PROBE collectors. `docker stats` over ~250
 * containers takes several seconds on a busy box, but the webapp probes every
 * few seconds — without this, each new poll would start ANOTHER heavy SSH exec
 * while the previous one is still running (concurrent reconnects/execs are what
 * trip appliance sshd into resetting connections). A caller that arrives while a
 * collection is in flight shares its promise instead of piling up.
 */
const probeInFlight = new Map<string, Promise<unknown>>();
function dedupeProbe<T>(host: string, key: string, fn: () => Promise<T>): Promise<T> {
  const k = `${key}|${host}`;
  const existing = probeInFlight.get(k);
  if (existing) return existing as Promise<T>;
  const p = fn().finally(() => { if (probeInFlight.get(k) === p) probeInFlight.delete(k); });
  probeInFlight.set(k, p);
  return p;
}

/**
 * Collects live per-container stats for the PROBE path: ONE `docker stats
 * --no-stream` over the shared SSH pool (connection RE-USED — cheap), parsed
 * with the same parser as the enrichment cycle. Covers ALL running containers
 * (`docker ps -q`) so custom apps without app.query rows are included too.
 * Returns null when no ssh slot is bound or SSH fails — the caller then throws
 * and the webapp keeps its last good snapshot / falls back to enrichment data.
 */
export async function collectProbeStats(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeContainerStat> | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  return dedupeProbe(host, 'stats', () => collectProbeStatsInner(host, sshCreds, log));
}

async function collectProbeStatsInner(
  host: string,
  sshCreds: NonNullable<ReturnType<typeof resolveSshCredentials>>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeContainerStat> | null> {
  try {
    const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
    const list = `$(docker ps -q 2>/dev/null | head -n ${MAX_CONTAINERS})`;
    const cmd = `docker stats --no-stream ${list} --format 'STAT|{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}' 2>/dev/null`;
    const r = await client.exec(cmd, sshCreds);
    if (r.code !== 0 && !r.stdout) {
      probeFailLog(host, `SSH docker stats probe on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`, log);
      return null;
    }
    const raw = parseDockerStats(r.stdout);
    const out = new Map<string, ProbeContainerStat>();
    for (const [name, s] of raw) {
      const key = `probe|${host}|${name}`;
      const stat: ProbeContainerStat = { name };
      if (s.cpuPct !== undefined) stat.cpuPct = s.cpuPct;
      if (s.memUsedBytes !== undefined) stat.memUsedBytes = s.memUsedBytes;
      if (s.memLimitBytes !== undefined) stat.memLimitBytes = s.memLimitBytes;
      const nr = s.netRxBytes !== undefined ? probeStatTrackers.netRx.sample(`${key}|netRx`, s.netRxBytes) : null;
      if (nr !== null && nr > 0) stat.netRxRate = Math.round(nr);
      const nt = s.netTxBytes !== undefined ? probeStatTrackers.netTx.sample(`${key}|netTx`, s.netTxBytes) : null;
      if (nt !== null && nt > 0) stat.netTxRate = Math.round(nt);
      const br = s.blkReadBytes !== undefined ? probeStatTrackers.blkRead.sample(`${key}|blkRead`, s.blkReadBytes) : null;
      if (br !== null && br > 0) stat.blkReadRate = Math.round(br);
      const bw = s.blkWriteBytes !== undefined ? probeStatTrackers.blkWrite.sample(`${key}|blkWrite`, s.blkWriteBytes) : null;
      if (bw !== null && bw > 0) stat.blkWriteRate = Math.round(bw);
      out.set(name, stat);
    }
    return out;
  } catch (e) {
    probeFailLog(host, e instanceof SshError ? `SSH docker stats probe on ${host} failed: ${e.message}` : `SSH docker stats probe on ${host} unexpected error: ${(e as Error).message}`, log);
    return null; // best-effort — the webapp keeps its last good snapshot
  }
}

/** One container's live state as served by POST /probe (key 'containerStates'). */
export interface ProbeContainerState {
  /** Container name (docker, no leading slash). */
  name: string;
  /** Docker-native lowercase state ('running', 'exited', 'created', …). */
  status: string;
}

/**
 * Collects the live state of containers for the PROBE path: ONE `docker ps -a`
 * over the shared SSH pool (sub-second, zero TrueNAS API load). Unlike a plain
 * `docker ps`, this lists ALL containers with their real docker state — so a
 * caller can watch specific containers through a start/stop transition and see
 * 'exited'/'created' as soon as docker reports it. `names` optionally restricts
 * the result to a subset of container names (absent = all). Returns null when
 * no ssh slot is bound or SSH fails; an EMPTY map is a valid answer (no
 * containers at all) and must NOT be conflated with failure.
 */
export async function collectProbeStates(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  log?: (level: 'info' | 'warn', message: string) => void,
  names?: string[]
): Promise<Map<string, ProbeContainerState> | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  // `names` selection is per-caller, so dedupe only the full (unfiltered)
  // collection and apply the filter afterwards.
  const full = await dedupeProbe(host, 'states', () => collectProbeStatesInner(host, sshCreds, log));
  if (!full) return null;
  if (!names || names.length === 0) return full;
  const wanted = new Set(names);
  const out = new Map<string, ProbeContainerState>();
  for (const [name, s] of full) if (wanted.has(name)) out.set(name, s);
  return out;
}

async function collectProbeStatesInner(
  host: string,
  sshCreds: NonNullable<ReturnType<typeof resolveSshCredentials>>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeContainerState> | null> {
  try {
    const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
    const r = await client.exec(`docker ps -a --format 'PS|{{.State}}|{{.Names}}' 2>/dev/null`, sshCreds);
    if (r.code !== 0 && !r.stdout) {
      probeFailLog(host, `SSH docker ps probe on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`, log);
      return null;
    }
    // Full collection — per-caller `names` filtering happens in collectProbeStates.
    const out = new Map<string, ProbeContainerState>();
    for (const line of r.stdout.split('\n')) {
      if (!line.startsWith('PS|')) continue;
      const rest = line.slice('PS|'.length);
      const sep = rest.indexOf('|');
      if (sep < 0) continue;
      // {{.State}} is a lowercase docker state ('running', 'exited (13)', …).
      const status = rest.slice(0, sep).trim().toLowerCase();
      const name = rest.slice(sep + 1).replace(/^\//, '').trim();
      if (!name || !status) continue;
      out.set(name, { name, status });
    }
    return out;
  } catch (e) {
    probeFailLog(host, e instanceof SshError ? `SSH docker ps probe on ${host} failed: ${e.message}` : `SSH docker ps probe on ${host} unexpected error: ${(e as Error).message}`, log);
    return null; // best-effort — the webapp keeps its last good snapshot
  }
}

/** One VM's live libvirt state as served by POST /probe (key 'vmStates'). */
export interface ProbeVmState {
  /** Domain name (= the VM name in vm.query). */
  name: string;
  /** Lowercase libvirt state ('running', 'shut off', 'paused', …). */
  status: string;
}

/**
 * Collects the live state of ALL VMs for the PROBE path: ONE `virsh list` over
 * the shared SSH pool (sub-second, zero TrueNAS API load) — so a page can watch
 * specific guests through a start/stop transition and flip their State badge in
 * ~1.5 s instead of waiting for the next inventory poll. Reuses the same socket
 * detection as the VM IP enrichment (TrueNAS SCALE runs libvirtd on a custom
 * socket). `names` optionally restricts the result to a subset of guest names
 * (absent = all). Returns null when no ssh slot is bound or SSH fails; an EMPTY
 * map is a valid answer (no guests at all) and must NOT be conflated with failure.
 */
export async function collectProbeVmStates(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  log?: (level: 'info' | 'warn', message: string) => void,
  names?: string[]
): Promise<Map<string, ProbeVmState> | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  const full = await dedupeProbe(host, 'vmStates', () => collectProbeVmStatesInner(host, sshCreds, log));
  if (!full) return null;
  if (!names || names.length === 0) return full;
  const wanted = new Set(names);
  const out = new Map<string, ProbeVmState>();
  for (const [name, s] of full) if (wanted.has(name)) out.set(name, s);
  return out;
}

async function collectProbeVmStatesInner(
  host: string,
  sshCreds: NonNullable<ReturnType<typeof resolveSshCredentials>>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, ProbeVmState> | null> {
  try {
    const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
    const r = await client.exec(buildVirshCommand(), sshCreds);
    if (r.code !== 0 && !r.stdout) {
      probeFailLog(host, `SSH virsh list probe on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`, log);
      return null;
    }
    // Full collection — per-caller `names` filtering happens in collectProbeVmStates.
    const out = new Map<string, ProbeVmState>();
    for (const line of r.stdout.split('\n')) {
      if (!line.startsWith('VS|')) continue;
      const rest = line.slice('VS|'.length);
      const sep = rest.indexOf('|');
      if (sep < 0) continue;
      // virsh list --all: "running" / "shut off" / "paused" / … (lowercase).
      const status = rest.slice(0, sep).trim().toLowerCase();
      const name = rest.slice(sep + 1).trim();
      if (!name || !status) continue;
      out.set(name, { name, status });
    }
    return out;
  } catch (e) {
    probeFailLog(host, e instanceof SshError ? `SSH virsh list probe on ${host} failed: ${e.message}` : `SSH virsh list probe on ${host} unexpected error: ${(e as Error).message}`, log);
    return null; // best-effort — the webapp keeps its last good snapshot
  }
}

// ---------------------------------------------------------------------------
// Background refresh orchestration (15-min cache per host)
// ---------------------------------------------------------------------------

/** Per-host enrichment state — each part has its own freshness stamp. */
export interface EnrichmentState {
  /** app.config wave result: app name → per-service compose detail. */
  serviceDetails?: Map<string, ServiceNetDetail[]>;
  /** docker inspect result over SSH (null = attempted but failed/absent). */
  dockerInfo?: DockerContainerInfo[] | null;
  /** docker stats result over SSH: container NAME → derived CPU/RAM/I-O rates. */
  dockerStats?: Map<string, ContainerStat>;
  atServiceDetails?: number;
  atDockerInfo?: number;
}

/** Per-host VM enrichment state — live guest IPs from `virsh domifaddr`
 * (guest agent) and the host's neighbor table over SSH. */
export interface VmEnrichmentState {
  /** NIC MAC (lowercase) → best live IP (IPv4 preferred, else first address). */
  ipsByMac?: Map<string, string>;
  atVmIps?: number;
}

/** Candidate libvirt socket paths probed when the stock `virsh` cannot reach its
 * daemon. TrueNAS SCALE runs libvirtd on a NON-standard socket and the stock
 * virsh binary ignores both `-c` URI overrides in some positions AND the
 * LIBVIRT_DEFAULT_URI env var — but the query-parameter form
 * `qemu+unix:///system?socket=<path>` works (verified live on 26.0 BETA). */
const LIBVIRT_SOCKET_CANDIDATES = [
  '/var/run/libvirt/libvirt-sock',
  '/run/truenas_libvirt/libvirt-sock',
];

/** Normalizes ONE vm.query devices[] entry to its dtype + attribute map. The
 * shape differs by release: TrueNAS 26+ nests everything under `attributes`
 * (`{id, attributes:{dtype,...}, vm, order}` — verified live on 26.0 BETA),
 * older releases carry the fields flat at the top level. Both are handled so a
 * mixed fleet parses identically. */
export function normalizeVmDevice(d: unknown): { dtype: string; attrs: Record<string, unknown> } | null {
  if (!d || typeof d !== 'object') return null;
  const obj = d as Record<string, unknown>;
  const topDtype = pickString(obj, ['dtype']);
  if (topDtype) return { dtype: topDtype, attrs: obj }; // legacy flat shape
  const attrs = (obj['attributes'] ?? {}) as Record<string, unknown>;
  const attrDtype = pickString(attrs, ['dtype']);
  return attrDtype ? { dtype: attrDtype, attrs } : null;
}

const vmEnrichmentCache = new Map<string, VmEnrichmentState>();
/** In-flight VM enrichment per host. */
const vmInFlight = new Set<string>();

/**
 * Builds ONE combined read-only shell command that dumps every libvirt guest's
 * interface addresses in a single pass. Output contract (parsed by
 * parseVmIpLines): one `source|MAC|proto|address` line per entry, source ∈
 * {domifaddr, arp}. The domain name is irrelevant — we key everything by MAC,
 * which is what the VMs page and Hosts ingestion need.
 *
 * Two IP sources are merged (guest agent first, ARP as fallback):
 *   - `virsh domifaddr` — authoritative when the guest runs qemu-guest-agent;
 *     EMPTY otherwise (verified: most TrueNAS VMs don't ship the agent).
 *   - host `ip neigh show` — the appliance has seen traffic from its bridged
 *     VMs and learned their MAC→IP bindings; works WITHOUT any guest agent.
 *
 * Socket detection runs first: stock `virsh` hardcodes /var/run/libvirt/
 * libvirt-sock on some appliances (TrueNAS SCALE uses a custom socket), so we
 * probe the known candidate paths with the working query-parameter URI form.
 */
function buildVirshCommand(): string {
  const candidates = LIBVIRT_SOCKET_CANDIDATES.map((s) => `'${s}'`).join(' ');
  return [
    // run_virsh: plain `virsh` when its stock socket works, otherwise the
    // query-parameter URI against the first candidate socket that answers.
    'run_virsh() { if [ -n "$VIRSH_URI" ]; then virsh -c "$VIRSH_URI" "$@"; else virsh "$@"; fi; }',
    'VIRSH_URI=',
    `if ! run_virsh list --name >/dev/null 2>&1; then`,
    `  for s in ${candidates}; do`,
    `    if [ -S "$s" ] && virsh -c "qemu+unix:///system?socket=$s" list --name >/dev/null 2>&1; then VIRSH_URI="qemu+unix:///system?socket=$s"; break; fi`,
    '  done',
    'fi',
    // Live guest states for the probe path (key 'vmStates'): one `virsh list --all`
    // covers every domain. State is columns 3..NF ("running", "shut off", …).
    "run_virsh list --all 2>/dev/null | awk 'NR>2 && NF>=3 {st=$3; for(i=4;i<=NF;i++) st=st\" \"$i; print \"VS|\" st \"|\" $2}'",
    'for d in $(run_virsh list --name 2>/dev/null); do',
    "  run_virsh domifaddr \"$d\" 2>/dev/null | awk -v OFS='|' 'NR>1 && NF>=4 {print \"domifaddr|\" $2, $3, $4}'",
    'done',
    // Host neighbor table: MAC→IP bindings the appliance learned from bridged
    // VM traffic — works without any guest agent. FAILED entries are dropped.
    "ip neigh show 2>/dev/null | awk '$NF!=\"FAILED\" {for(i=1;i<=NF;i++) if($i==\"lladdr\") print \"arp|\" $(i+1) \"|\" (($1 ~ /:/)?\"ipv6\":\"ipv4\") \"|\" $1}'",
  ].join('\n');
}

/** Parses the combined enrichment output into a MAC → IP map. Priority per MAC:
 * guest-agent IPv4 > host-ARP IPv4 > guest-agent IPv6 > host-ARP IPv6 (a real
 * IPv4 is more useful than any IPv6; the first address of each kind is kept —
 * multi-homed guests are rare and one representative suffices for Hosts). */
export function parseVmIpLines(stdout: string): Map<string, string> {
  const gaV4 = new Map<string, string>();
  const gaV6 = new Map<string, string>();
  const arpV4 = new Map<string, string>();
  const arpV6 = new Map<string, string>();
  for (const line of stdout.split('\n')) {
    if (!line) continue;
    const parts = line.split('|');
    if (parts.length < 4) continue;
    const source = parts[0].trim(); // 'domifaddr' | 'arp'
    const mac = (parts[1] ?? '').trim().toLowerCase();
    const proto = (parts[2] ?? '').trim().toLowerCase();
    // Strip a CIDR suffix ("192.168.1.10/24") — the Hosts page stores bare IPs.
    const ip = ((parts[3] ?? '').trim()).split('/')[0];
    if (!MAC_RE.test(mac) || !ip || ip === '0.0.0.0' || ip === '::') continue;
    if (source === 'domifaddr') {
      if (proto === 'ipv4' && !gaV4.has(mac)) gaV4.set(mac, ip);
      else if (proto === 'ipv6' && !gaV6.has(mac)) gaV6.set(mac, ip);
    } else if (source === 'arp') {
      if (proto === 'ipv4' && !arpV4.has(mac)) arpV4.set(mac, ip);
      else if (proto === 'ipv6' && !arpV6.has(mac)) arpV6.set(mac, ip);
    }
  }
  const out = new Map<string, string>();
  for (const [mac, ip] of gaV4) out.set(mac, ip);
  for (const [mac, ip] of arpV4) if (!out.has(mac)) out.set(mac, ip);
  for (const [mac, ip] of gaV6) if (!out.has(mac)) out.set(mac, ip);
  for (const [mac, ip] of arpV6) if (!out.has(mac)) out.set(mac, ip);
  return out;
}

/** Collects live VM guest IPs over SSH (null when no slot / on failure).
 * Merges `virsh domifaddr` (guest agent) with the host's neighbor table so a
 * missing qemu-guest-agent doesn't leave every row MAC-only. */
async function collectVmIpsViaSsh(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<Map<string, string> | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  try {
    const client = await sshPool.get(host, 22, sshCreds, { hostKeyVerifier: dynamicSshHostVerifier(host) });
    const r = await client.exec(buildVirshCommand(), sshCreds);
    if (r.code !== 0 && !r.stdout) {
      log?.('warn', `SSH VM IP collection on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`);
      return null;
    }
    return parseVmIpLines(r.stdout);
  } catch (e) {
    if (e instanceof SshError) log?.('warn', `SSH VM IP collection on ${host} failed: ${e.message}`);
    else log?.('warn', `SSH VM IP collection on ${host} unexpected error: ${(e as Error).message}`);
    return null; // best-effort — keep previous data, never sink the poll
  }
}

/**
 * Schedules a background refresh of live VM guest IPs when stale and returns
 * immediately — /monitoring NEVER awaits the work. Safe to call on every poll:
 * fresh parts are skipped, in-flight parts dedupe. No-op when no ssh slot is
 * bound or the appliance reports no VM NIC MACs at all (nothing to enrich).
 */
export function ensureVmEnrichment(args: {
  host: string;
  sshCreds?: ReturnType<typeof resolveSshCredentials>;
  /** Fresh vm.query rows — used only to detect whether any NIC MAC exists. */
  vms: Record<string, unknown>[];
  log?: (level: 'info' | 'warn', message: string) => void;
}): void {
  const { host, sshCreds, vms, log } = args;
  if (!sshCreds || !vms || vms.length === 0) return; // nothing to enrich

  let hasNicMac = false;
  for (const v of vms) {
    const devicesRaw = Array.isArray(v['devices']) ? (v['devices'] as Record<string, unknown>[]) : [];
    for (const d of devicesRaw) {
      const dev = normalizeVmDevice(d);
      if (!dev || dev.dtype !== 'NIC') continue;
      const mac = pickString(dev.attrs, ['mac']);
      if (mac && mac !== '') { hasNicMac = true; break; }
    }
    if (hasNicMac) break;
  }
  if (!hasNicMac) return;

  const state = vmEnrichmentCache.get(host);
  if (state?.atVmIps && Date.now() - state.atVmIps < ENRICHMENT_TTL_MS) return; // fresh
  if (vmInFlight.has(host)) return; // already running — dedupe
  vmInFlight.add(host);
  void collectVmIpsViaSsh(host, sshCreds, log)
    .then((ips) => {
      const s = vmEnrichmentCache.get(host) ?? {};
      // Only overwrite on SUCCESS — a failed cycle keeps the last good data.
      if (ips !== null) {
        s.ipsByMac = ips;
        s.atVmIps = Date.now();
        vmEnrichmentCache.set(host, s);
      }
    })
    .catch((e) => log?.('warn', `SSH virsh refresh for ${host} crashed: ${(e as Error).message}`))
    .finally(() => vmInFlight.delete(host));
}

/** Current (possibly stale/empty) VM enrichment state for a host. */
export function getVmEnrichment(host: string): VmEnrichmentState | undefined {
  return vmEnrichmentCache.get(host);
}

const ENRICHMENT_TTL_MS = 15 * 60_000; // same cadence as the OPNsense inventory cache
/** Bounded concurrency for the app.config wave (measured safe on real boxes). */
const CONFIG_CONCURRENCY = 8;

const enrichmentCache = new Map<string, EnrichmentState>();
/** In-flight refresh parts: `${host}|api` / `${host}|ssh`. */
const inFlightParts = new Set<string>();
/** Hosts with an active /monitoring poll — the API wave must not overlap it. */
export const monitoringInFlight = new Set<string>();
/** Hosts whose app.config wave is DEFERRED (a poll was in flight when it became
 * stale) — one pending timer per host so overlapping polls don't stack timers. */
const deferredParts = new Set<string>();

/** Runs the bounded-concurrency app.config wave for ONE host and caches the
 * result. Extracted from ensureEnrichment so a wave blocked by an in-flight
 * poll can be DEFERRED (re-checked shortly after) instead of silently dropped —
 * previously it could never start, because ensureEnrichment is only called from
 * inside /monitoring while monitoringInFlight already contains the host. */
function runConfigWave(
  host: string,
  client: TruenasClient,
  creds: TruenasCredentials,
  apps: Record<string, unknown>[],
  log?: (level: 'info' | 'warn', message: string) => void
): void {
  const key = `${host}|api`;
  if (inFlightParts.has(key)) return; // already running — dedupe
  inFlightParts.add(key);
  void (async () => {
    try {
      const details = new Map<string, ServiceNetDetail[]>();
      let cursor = 0;
      async function worker(): Promise<void> {
        while (cursor < apps.length) {
          const i = cursor++;
          const appName = pickString(apps[i], ['name', 'id']) ?? '';
          if (!appName) continue;
          try {
            const cfg = await client.call<Record<string, unknown>>('app.config', [appName], creds);
            if (cfg && typeof cfg === 'object') details.set(appName, serviceNetDetails(cfg));
          } catch { /* best-effort — this app stays empty for this cycle */ }
        }
      }
      const workers: Promise<void>[] = [];
      for (let w = 0; w < Math.min(CONFIG_CONCURRENCY, apps.length); w++) workers.push(worker());
      await Promise.all(workers);
      // Merge with the previous map — a failed app.config must not wipe an app
      // that succeeded last cycle.
      const prev = enrichmentCache.get(host)?.serviceDetails;
      if (prev) for (const [k, v] of prev) if (!details.has(k)) details.set(k, v);
      const s = enrichmentCache.get(host) ?? {};
      s.serviceDetails = details;
      s.atServiceDetails = Date.now();
      enrichmentCache.set(host, s);
    } finally {
      inFlightParts.delete(key);
    }
  })().catch((e) => log?.('warn', `app.config wave for ${host} crashed: ${(e as Error).message}`));
}

/** Current (possibly stale/empty) enrichment state for a host. */
export function getEnrichment(host: string): EnrichmentState | undefined {
  return enrichmentCache.get(host);
}

function isStale(at?: number): boolean {
  return at === undefined || Date.now() - at > ENRICHMENT_TTL_MS;
}

/**
 * Schedules background refreshes for any stale part and returns immediately —
 * /monitoring NEVER awaits the work, it reads getEnrichment(host) right after.
 * Safe to call on every poll: fresh parts are skipped, in-flight parts dedupe.
 */
export function ensureEnrichment(args: {
  host: string;
  client: TruenasClient;
  creds: TruenasCredentials;
  sshCreds?: ReturnType<typeof resolveSshCredentials>;
  /** Fresh app.query rows (carries container_details[].id + service names). */
  apps: Record<string, unknown>[];
  log?: (level: 'info' | 'warn', message: string) => void;
}): void {
  const { host, client, creds, sshCreds, apps, log } = args;
  if (!apps || apps.length === 0) return; // nothing to enrich

  const state = enrichmentCache.get(host) ?? {};

  // --- Part 1: app.config wave (API transport — never overlap a live poll) --
  if (isStale(state.atServiceDetails)) {
    const key = `${host}|api`;
    if (!inFlightParts.has(key)) {
      if (!monitoringInFlight.has(host)) {
        // No poll in flight right now → run the wave immediately.
        runConfigWave(host, client, creds, apps, log);
      } else if (!deferredParts.has(key)) {
        // A poll IS in flight (ensureEnrichment is only called from inside one) —
        // DEFER: re-check shortly after it finishes so the wave actually runs.
        deferredParts.add(key);
        setTimeout(() => {
          deferredParts.delete(key);
          if (!isStale(enrichmentCache.get(host)?.atServiceDetails)) return; // refreshed meanwhile
          if (monitoringInFlight.has(host) || inFlightParts.has(key)) return; // still busy — next poll re-defers
          runConfigWave(host, client, creds, apps, log);
        }, 1500).unref?.();
      }
    }
  }

  // --- Part 2: docker inspect over SSH (independent transport — safe anytime) --
  if (isStale(state.atDockerInfo)) {
    const key = `${host}|ssh`;
    if (!inFlightParts.has(key)) {
      inFlightParts.add(key);
      const ids: string[] = [];
      for (const a of apps) {
        const aw = (a['active_workloads'] ?? {}) as Record<string, unknown>;
        const details = Array.isArray(aw['container_details']) ? (aw['container_details'] as Record<string, unknown>[]) : [];
        for (const d of details) {
          const id = pickString(d, ['id']);
          if (id && !ids.includes(id)) ids.push(id);
        }
      }
      void collectDockerViaSsh(host, sshCreds, ids, log)
        .then((snap) => {
          const s = enrichmentCache.get(host) ?? {};
          // Only overwrite on SUCCESS — a failed cycle keeps the last good data.
          if (snap !== null) {
            s.dockerInfo = snap.infos;
            s.atDockerInfo = Date.now();
            s.dockerStats = computeContainerStats(host, snap.stats);
            enrichmentCache.set(host, s);
          }
        })
        .catch((e) => log?.('warn', `SSH docker refresh for ${host} crashed: ${(e as Error).message}`))
        .finally(() => inFlightParts.delete(key));
    }
  }
}

/** Strips scheme/path from a management address → bare hostname for SSH. */
export function sshHostOf(managementAddress: string): string {
  const trimmed = managementAddress.trim();
  if (!trimmed) return '';
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
    return new URL(withScheme).hostname;
  } catch {
    // Not a parseable URL — take the host part before any port/path.
    const noPath = trimmed.split('/')[0];
    const m = noPath.match(/^(?:\[[0-9a-fA-F:]+\]|[^:\[]+)(?::\d+)?$/);
    return m ? (m[1].startsWith('[') ? m[1].slice(1, -1) : m[1]) : '';
  }
}
