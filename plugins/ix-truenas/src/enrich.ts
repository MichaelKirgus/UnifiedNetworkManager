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

import { createSshPool, pickString, resolveSshCredentials, SshError } from '@unm/plugin-sdk';
import type { TruenasClient, TruenasCredentials } from './client/truenasClient';

// ---------------------------------------------------------------------------
// Compose-config detail (moved here from index.ts — shared with the wave below)
// ---------------------------------------------------------------------------

/** One service's network placement from its compose config (app.config). */
export interface ServiceNetDetail {
  /** Compose `hostname` — the container's L3 name. */
  hostname: string;
  /** Static IPv4/IPv6 addresses assigned on the app's networks. */
  ips: string[];
  /** Network names this service is attached to. */
  networks: string[];
}

/**
 * Extracts per-service network detail from ONE app's compose config (app.config).
 * The TrueNAS public API exposes NO per-container MAC — but the compose config
 * carries each service's `hostname` + static `ipv4_address`/`ipv6_address`.
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
    out.push({ hostname, ips: Array.from(ips).sort(), networks: networks.sort() });
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

/** Process-wide SSH pool — one session per appliance, RE-USED across polls. */
const sshPool = createSshPool();
process.on('SIGTERM', () => sshPool.closeAll());
process.on('SIGINT', () => sshPool.closeAll());

/** Caps the container list (defensive — a runaway box must not bloat the command). */
const MAX_CONTAINERS = 400;

/**
 * Builds ONE combined read-only shell command that inspects every known
 * container in a single pass. Output contract (parsed by parseDockerInspect):
 *   <64-hex-id>|<name>|<state>|<startedAt>     one line per container
 *   NET|<network>|<mac>|<ip>                   one line per attached network
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
  return `for id in ${list}; do docker inspect "$id" --format '${fmt}' 2>/dev/null; done`;
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

/** Collects docker container facts over SSH (null when no slot / on failure). */
async function collectDockerViaSsh(
  host: string,
  sshCreds: ReturnType<typeof resolveSshCredentials>,
  containerIds: string[],
  log?: (level: 'info' | 'warn', message: string) => void
): Promise<DockerContainerInfo[] | null> {
  if (!sshCreds) return null; // no ssh slot bound — API-only mode
  try {
    const client = await sshPool.get(host, 22, sshCreds);
    const r = await client.exec(buildDockerInspectCommand(containerIds.slice(0, MAX_CONTAINERS)), sshCreds);
    if (r.code !== 0 && !r.stdout) {
      log?.('warn', `SSH docker inspect on ${host} failed (exit ${r.code}): ${r.stderr.slice(0, 200)}`);
      return null;
    }
    const infos = parseDockerInspect(r.stdout);
    if (infos.length === 0 && containerIds.length > 0) {
      log?.('warn', `SSH docker inspect on ${host}: no containers parsed (${r.stderr.slice(0, 120)})`);
    }
    return infos;
  } catch (e) {
    if (e instanceof SshError) log?.('warn', `SSH docker inspect on ${host} failed: ${e.message}`);
    else log?.('warn', `SSH docker inspect on ${host} unexpected error: ${(e as Error).message}`);
    return null; // best-effort — keep previous data, never sink the poll
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
  atServiceDetails?: number;
  atDockerInfo?: number;
}

const ENRICHMENT_TTL_MS = 15 * 60_000; // same cadence as the OPNsense inventory cache
/** Bounded concurrency for the app.config wave (measured safe on real boxes). */
const CONFIG_CONCURRENCY = 8;

const enrichmentCache = new Map<string, EnrichmentState>();
/** In-flight refresh parts: `${host}|api` / `${host}|ssh`. */
const inFlightParts = new Set<string>();
/** Hosts with an active /monitoring poll — the API wave must not overlap it. */
export const monitoringInFlight = new Set<string>();

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
    if (!inFlightParts.has(key) && !monitoringInFlight.has(host)) {
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
          // Merge with the previous map — a failed app.config must not wipe an
          // app that succeeded last cycle.
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
        .then((infos) => {
          const s = enrichmentCache.get(host) ?? {};
          // Only overwrite on SUCCESS — a failed cycle keeps the last good data.
          if (infos !== null) {
            s.dockerInfo = infos;
            s.atDockerInfo = Date.now();
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
