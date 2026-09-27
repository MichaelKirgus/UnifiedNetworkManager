/**
 * Docker / Docker Compose support for the Generic SSH plugin.
 *
 * This module is the ONE place that knows how to talk to a docker daemon over
 * plain SSH (the host's `docker` CLI). It serves three consumers:
 *   - monitoring.ts  → emits the generic `containers[]` + `images[]` metrics at
 *     the inventory cadence (one row per "App" = compose project, same grouping
 *     rule as plugins/docker/src/rows.ts so both plugins render identically).
 *   - index.ts       → POST /probe keys `containerStates` (live states from one
 *     cheap `docker ps -a`) and `containerStats` (one bounded `docker stats
 *     --no-stream` pass — the same source the TrueNAS plugin uses over SSH).
 *   - actions/docker.ts → lifecycle + deploy/update/logs/images actions.
 *
 * Everything is best-effort: a host without docker installed simply yields no
 * container data (the metric keys are omitted — absent = no wipe, per the
 * ingestion contract), and a transient failure never sinks the poll.
 */

import { CounterTracker } from '@unm/plugin-sdk';
import type { CommandRunner } from './client/privilege';
import { shq } from './actions/types';

// --- UNM row shapes (mirror plugins/docker/src/rows.ts + webapp client) --------

export interface ContainerVolume {
  source: string;
  target?: string;
  mode?: 'ro' | 'rw';
}

/** Published port with the full host→container mapping (clone prefill). */
export interface PortMapping {
  hostPort: number;
  containerPort: number;
  protocol: 'tcp' | 'udp';
}

/** Per-container detail row for the expandable tree. */
export interface ContainerServiceDetail {
  service?: string | null;
  image?: string | null;
  state?: string | null;
  mac?: string | null;
  ip?: string | null;
  startedAt?: string | null;
  volumes?: ContainerVolume[];
}

/** One UNM "App" row → `metrics['containers']`. */
export interface UnmContainerRow {
  name: string;
  state: string; // UPPERCASE — the API uppercases at ingest anyway
  image?: string | null;
  version?: string | null;
  upgradeAvailable?: boolean | null;
  startedAt?: string | null;
  extra?: Record<string, unknown>;
}

/** One row of the images inventory → `metrics['images']`. */
export interface UnmImageRow {
  name: string;
  sizeBytes?: number | null;
  createdAt?: string | null;
  updateAvailable?: boolean | null;
  dangling?: boolean;
  extra?: Record<string, unknown>;
}

// --- Raw docker JSON shapes (defensive reads — field sets vary by version) -----

interface DockerPort {
  IP?: string;
  PrivatePort?: number;
  PublicPort?: number | null;
  Type?: string;
}

interface DockerNetworkSettings {
  Networks?: Record<string, { MacAddress?: string; IPAddress?: string }>;
}

interface DockerMount {
  Name?: string;
  Source?: string;
  Destination?: string;
  Mode?: string;
  Type?: string; // bind | volume | tmpfs
  RW?: boolean;
}

export interface DockerContainerRaw {
  Id?: string;
  /** Engine API (inspect): singular STRING. CLI `ps --format json`: array. */
  Name?: string;
  Names?: string[];
  Image?: string; // inspect: image ID (sha256:…) — repo tag merged in at collection time
  /** Engine API (inspect): an object with Status. CLI `ps --format json`: a plain
   *  string. Both are normalized through stateOf(). */
  State?: string | { Status?: string; StartedAt?: string };
  Status?: string;
  Ports?: DockerPort[];
  /** Engine API (inspect): labels live under Config.Labels — merged in at
   *  collection time by normalizeContainerRaw(). */
  Labels?: Record<string, string>;
  Config?: { Labels?: Record<string, string> };
  /** Engine API (inspect): published ports live here as "80/tcp" → bindings. */
  HostConfig?: { PortBindings?: Record<string, Array<{ HostIp?: string; HostPort?: string }>> };
  NetworkSettings?: DockerNetworkSettings;
  Mounts?: DockerMount[];
}

/** Normalizes the two container JSON shapes onto the fields this module reads:
 *   - Engine API (`docker inspect`): `Name` (string), labels under `Config.Labels`,
 *     published ports under `HostConfig.PortBindings`, `State.Status` — what we
 *     actually collect over SSH.
 *   - CLI / ps shape: `Names[]`, top-level `Labels`, `Ports[]`, `State` string.
 * Mutates + returns the object so callers can map over parsed lines directly. */
function normalizeContainerRaw(c: DockerContainerRaw): DockerContainerRaw {
  if (!Array.isArray(c.Names) || c.Names.length === 0) {
    const n = typeof c.Name === 'string' ? c.Name.replace(/^\/+/, '') : '';
    c.Names = n ? [n] : [];
  }
  if ((!c.Labels || Object.keys(c.Labels).length === 0) && c.Config?.Labels && typeof c.Config.Labels === 'object') {
    c.Labels = c.Config.Labels;
  }
  // inspect has no top-level Ports[] — derive it from HostConfig.PortBindings.
  if ((!c.Ports || c.Ports.length === 0) && c.HostConfig?.PortBindings && typeof c.HostConfig.PortBindings === 'object') {
    const ports: DockerPort[] = [];
    for (const [key, bindings] of Object.entries(c.HostConfig.PortBindings)) {
      if (!Array.isArray(bindings)) continue;
      // Key is "<port>/<proto>" — the port part may be empty for range mappings.
      const slash = key.lastIndexOf('/');
      const containerPort = parseInt(slash > 0 ? key.slice(0, slash) : key, 10);
      if (!Number.isFinite(containerPort)) continue;
      const protocol: 'tcp' | 'udp' = key.endsWith('/udp') ? 'udp' : 'tcp';
      for (const b of bindings) {
        const hostPort = parseInt(typeof b?.HostPort === 'string' ? b.HostPort : '', 10);
        if (!Number.isFinite(hostPort)) continue; // ephemeral (-p 80:) — no fixed host port
        ports.push({ IP: typeof b?.HostIp === 'string' && b.HostIp ? b.HostIp : '0.0.0.0', PrivatePort: containerPort, PublicPort: hostPort, Type: protocol });
      }
    }
    if (ports.length > 0) c.Ports = ports;
  }
  return c;
}

/** Normalizes the two `State` shapes (inspect object vs CLI string) to a lowercase state word. */
function stateOf(c: DockerContainerRaw): string {
  const s = c.State;
  if (typeof s === 'string') return s.toLowerCase();
  if (s && typeof s === 'object' && typeof s.Status === 'string') return s.Status.toLowerCase();
  return '';
}

export interface DockerImageRaw {
  Id?: string; // sha256:<hex>
  RepoTags?: string[] | null; // inspect: null when untagged (dangling)
  /** inspect: ISO-8601 string. CLI `images --format json`: unix seconds. */
  Created?: number | string;
  Size?: number;
  VirtualSize?: number;
  Containers?: number;
}

/** Parses the two `Created` shapes (ISO string vs unix seconds) to an ISO date or null. */
function imageCreatedAt(v: number | string | undefined): string | null {
  if (typeof v === 'number' && Number.isFinite(v) && v > 0) return new Date(v * 1000).toISOString();
  if (typeof v === 'string' && v.length > 0) {
    const t = Date.parse(v);
    if (!Number.isNaN(t)) return new Date(t).toISOString();
  }
  return null;
}

// --- Shared constants -----------------------------------------------------------

/** The compose-project label — the grouping key for "App" rows. */
export const COMPOSE_PROJECT_LABEL = 'com.docker.compose.project';

/** Default working directory for deployed compose stacks (user-overridable). */
export const DEFAULT_COMPOSE_WORKDIR = '/opt/compose';

/** Compose project / app name slug — same pattern as the Docker plugin. */
const NAME_SLUG_RE = /^[a-z]([-a-z0-9]*[a-z0-9])?$/;

/** Validates a compose project / app name (lowercase slug). */
export function isValidAppName(name: string): boolean {
  return NAME_SLUG_RE.test(name);
}

/** Validates an absolute working-directory path (no shell metacharacters, no `..`). */
export function isSafeWorkdir(p: string): boolean {
  if (!p.startsWith('/') || p.length > 512) return false;
  if (p.includes('..')) return false;
  // Conservative charset — anything else could break the shell or escape the dir.
  return /^[A-Za-z0-9._/-]+$/.test(p);
}

// --- Workdir registry -------------------------------------------------------------
// `docker compose up` only stamps com.docker.compose.project.working_dir onto the
// containers since Compose v2.17 — older hosts (and podman-compose) leave it empty,
// so label-based workdir resolution silently falls back to the default and can't find
// a stack deployed elsewhere. UNM deploys therefore ALSO record the chosen workdir in
// a GLOBAL registry: one file per project under WORKDIR_REGISTRY_DIR containing just
// the absolute path (the file lives at a fixed location — inside the workdir itself
// would be unfindable without already knowing it). Resolution order:
//   1. registry file <WORKDIR_REGISTRY_DIR>/<name> (UNM deploys — authoritative),
//   2. com.docker.compose.project.working_dir label (Compose v2.17+ / foreign stacks),
//   3. default <DEFAULT_COMPOSE_WORKDIR>/<name>.

/** Global dir holding one workdir-registry file per UNM-deployed compose project. */
export const WORKDIR_REGISTRY_DIR = '/var/lib/unm/compose-workdirs';

/** Registry file for one project (the name slug is filesystem-safe by pattern). */
export function workdirRegistryPath(name: string): string {
  return `${WORKDIR_REGISTRY_DIR}/${name}`;
}

/**
 * Resolves a project's saved workdir on the host in ONE exec. Returns the resolved
 * dir (always safe to shell-quote) or null when docker is absent.
 */
export async function resolveWorkdir(backend: { exec(cmd: string, timeoutMs?: number): Promise<{ code: number; stdout?: string | null }> }, name: string): Promise<string | null> {
  const def = `${DEFAULT_COMPOSE_WORKDIR}/${name}`;
  try {
    const r = await backend.exec(
      [
        'command -v docker >/dev/null 2>&1 || exit 95',
        `reg=${shq(workdirRegistryPath(name))}`,
        '[ -f "$reg" ] && cat "$reg" 2>/dev/null | head -n 1',
        `docker ps -a --filter label=${COMPOSE_PROJECT_LABEL}=${shq(name)} --format '${WORKDIR_FMT}' 2>/dev/null | head -n 1`,
      ].join('\n'),
      15_000,
    );
    const lines = (r.stdout ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
    for (const l of lines) {
      if (isSafeWorkdir(l)) return l; // first hit wins: registry file, then label
    }
  } catch { /* fall through to the default */ }
  return def;
}

/** Go template that prints one container's working-dir label value. */
export const WORKDIR_FMT = `{{index .Labels "com.docker.compose.project.working_dir"}}`;

/** Container display name — first of Names with the leading "/" stripped. */
export function containerName(c: DockerContainerRaw): string {
  const raw = Array.isArray(c.Names) && c.Names.length > 0 ? String(c.Names[0]) : '';
  return raw.replace(/^\/+/, '') || 'unknown';
}

/** Go zero-time ("0001-01-01T00:00:00Z") and empty strings → null. */
function cleanStartedAt(v: unknown): string | null {
  if (typeof v !== 'string' || !v) return null;
  if (v.startsWith('0001-')) return null; // Go zero time = never started
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : v;
}

const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;

/** Per-container network detail: first net with a real IP wins for ip+mac. */
function netDetail(c: DockerContainerRaw): { ip?: string | null; mac?: string | null } {
  const nets = c.NetworkSettings?.Networks ?? {};
  let fallbackMac: string | null = null;
  for (const entry of Object.values(nets)) {
    if (!entry) continue;
    const mac = typeof entry.MacAddress === 'string' && MAC_RE.test(entry.MacAddress) ? entry.MacAddress : null;
    if (!fallbackMac && mac) fallbackMac = mac;
    const ip = entry.IPAddress || undefined;
    if (ip) return { ip, mac: mac ?? fallbackMac };
  }
  return { ip: null, mac: fallbackMac };
}

/** Volume mounts from Mounts[] — bind + named volumes only (tmpfs is noise). */
function volumeMounts(c: DockerContainerRaw): ContainerVolume[] {
  const out: ContainerVolume[] = [];
  for (const m of c.Mounts ?? []) {
    if (!m || typeof m.Source !== 'string' || !m.Source) continue;
    if (m.Type && m.Type !== 'bind' && m.Type !== 'volume') continue; // skip tmpfs & friends
    const mode: 'ro' | 'rw' = typeof m.Mode === 'string' && m.Mode.includes('ro') ? 'ro' : 'rw';
    out.push({ source: m.Source, target: typeof m.Destination === 'string' ? m.Destination : undefined, mode });
  }
  return out;
}

/** Per-container detail row for the expandable tree. */
function serviceDetail(c: DockerContainerRaw): ContainerServiceDetail {
  const { ip, mac } = netDetail(c);
  const image = typeof c.Image === 'string' && c.Image && c.Image !== '<none>' ? c.Image : null;
  return {
    service: containerName(c),
    image,
    state: stateOf(c) || null,
    ip: ip ?? null,
    mac: mac ?? null,
    startedAt: cleanStartedAt(startedAtOf(c)),
    volumes: volumeMounts(c),
  };
}

/** ISO start of the current RUNNING period (top-level `StartedAt`, newer engines). */
function startedAtOf(c: DockerContainerRaw): unknown {
  const rec = c as Record<string, unknown>;
  if (typeof rec['StartedAt'] === 'string') return rec['StartedAt'];
  const s = rec['State'];
  if (s && typeof s === 'object') return (s as Record<string, unknown>)['StartedAt'];
  return undefined;
}

/** Aggregates an app-level state from its containers' Docker states. */
function aggregateState(states: string[]): string {
  const has = (s: string) => states.includes(s);
  if (has('running')) return 'RUNNING';
  if (has('restarting')) return 'RESTARTING';
  if (has('paused')) return 'PAUSED';
  if (has('dead')) return 'ERROR';
  return 'STOPPED'; // exited | created | removing | unknown
}

/** Deduped port-mapping list (same triple keeps the first). */
function dedupePortMappings(ms: PortMapping[]): PortMapping[] {
  const seen = new Set<string>();
  const out: PortMapping[] = [];
  for (const m of ms) {
    const k = `${m.hostPort}→${m.containerPort}/${m.protocol}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(m);
  }
  return out.sort((a, b) => a.hostPort - b.hostPort || a.containerPort - b.containerPort);
}

/** App-level deduped mount list (same source+target keeps the first). */
function dedupeVolumes(vols: ContainerVolume[]): ContainerVolume[] {
  const seen = new Set<string>();
  const out: ContainerVolume[] = [];
  for (const v of vols) {
    const k = `${v.source}→${v.target ?? ''}`;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(v);
  }
  return out.sort((a, b) => a.source.localeCompare(b.source));
}

// --- Main mapping ----------------------------------------------------------------

/**
 * Groups raw containers by compose project and builds one UNM row per group —
 * the SAME rule as plugins/docker/src/rows.ts: one row per "App" = compose
 * project (label com.docker.compose.project); non-compose containers each
 * become their own single-container row.
 */
export function buildContainerRows(raw: DockerContainerRaw[]): UnmContainerRow[] {
  const groups = new Map<string, DockerContainerRaw[]>();
  for (const c of raw) {
    if (!c || typeof c !== 'object') continue;
    const project = typeof c.Labels?.[COMPOSE_PROJECT_LABEL] === 'string' && c.Labels[COMPOSE_PROJECT_LABEL] ? c.Labels[COMPOSE_PROJECT_LABEL] : null;
    const key = project ?? `__single__:${containerName(c)}`;
    const list = groups.get(key);
    if (list) list.push(c);
    else groups.set(key, [c]);
  }

  const rows: UnmContainerRow[] = [];
  for (const [key, members] of groups) {
    const name = key.startsWith('__single__:') ? containerName(members[0]) : key;
    const sorted = [...members].sort((a, b) => containerName(a).localeCompare(containerName(b)));

    // Per-container detail for the tree.
    const containers: ContainerServiceDetail[] = sorted.map(serviceDetail);

    // App-level aggregates.
  const states = sorted.map(stateOf);    const state = aggregateState(states);
    const networks = new Map<string, { name: string }>();
    const ips = new Set<string>();
    const ports = new Set<number>();
    const portMappingsAll: PortMapping[] = [];
    const volumeMountsAll: ContainerVolume[] = [];
    for (const c of sorted) {
      for (const netName of Object.keys(c.NetworkSettings?.Networks ?? {})) networks.set(netName, { name: netName });
      const { ip } = netDetail(c);
      if (ip) ips.add(ip);
      for (const p of c.Ports ?? []) {
        if (typeof p.PublicPort === 'number' && p.PublicPort > 0) ports.add(p.PublicPort);
        // Full host→container mapping — used by the webapp's clone/duplicate flow.
        if (typeof p.PublicPort === 'number' && p.PublicPort > 0 && typeof p.PrivatePort === 'number') {
          portMappingsAll.push({ hostPort: p.PublicPort, containerPort: p.PrivatePort, protocol: p.Type === 'udp' ? 'udp' : 'tcp' });
        }
      }
      volumeMountsAll.push(...volumeMounts(c));
    }

    // App-level image/startedAt only for single-container rows (mirrors the Docker plugin).
    const single = sorted.length === 1 ? serviceDetail(sorted[0]) : null;
    const runningSingle = single && states.includes('running') ? single : null;

    rows.push({
      name,
      state,
      image: single?.image ?? null,
      startedAt: runningSingle ? runningSingle.startedAt : null,
      extra: {
        networks: [...networks.values()].sort((a, b) => a.name.localeCompare(b.name)),
        ips: [...ips].sort(),
        ports: [...ports].sort((a, b) => a - b),
        portMappings: dedupePortMappings(portMappingsAll),
        containerCount: sorted.length,
        containers,
        volumeMounts: dedupeVolumes(volumeMountsAll),
      },
    });
  }

  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

// --- Image inventory (`docker image inspect`, one JSON object per line) ----------

const NONE_TAG = '<none>:<none>';

/** Maps raw `docker images` entries to UNM image rows: one row per IMAGE (not
 * per tag) — the first real tag is the name, all tags ride in `extra`. An image
 * whose only tag is <none> is dangling and named by its short id. */
export function buildImageRows(raw: DockerImageRaw[]): UnmImageRow[] {
  const rows: UnmImageRow[] = [];
  for (const img of raw) {
    if (!img || typeof img !== 'object') continue;
    // inspect emits RepoTags: null for untagged images — treat as no tags.
    const tags = Array.isArray(img.RepoTags) ? img.RepoTags.filter((t): t is string => typeof t === 'string' && t.length > 0) : [];
    const realTags = tags.filter((t) => t !== NONE_TAG);
    const dangling = realTags.length === 0;

    let name: string;
    if (!dangling) {
      name = realTags[0];
    } else {
      // Untagged — short id (first 12 hex chars of the sha).
      const id = typeof img.Id === 'string' ? img.Id.replace(/^sha256:/, '') : '';
      name = id.slice(0, 12) || 'unknown';
    }

    const sizeBytes = Number.isFinite(img.Size) && (img.Size ?? 0) > 0 ? img.Size! : Number.isFinite(img.VirtualSize) ? img.VirtualSize : null;
    const createdAt = imageCreatedAt(img.Created);

    rows.push({
      name,
      sizeBytes: sizeBytes ?? null,
      createdAt,
      updateAvailable: null, // plain Docker hosts do no registry checks
      dangling,
      extra: {
        id: typeof img.Id === 'string' ? img.Id.replace(/^sha256:/, '') : undefined,
        tags: realTags.length > 1 ? realTags.slice(0, 8) : undefined,
        containers: Number.isFinite(img.Containers) ? img.Containers ?? null : null,
      },
    });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}

// --- Collection over SSH ----------------------------------------------------------

/** Fleet caps for the inventory pass. Beyond these we REFUSE to emit partial
 *  data (the API's delete-on-absent ingestion would wipe rows for the uncollected
 *  tail) — null keeps previously stored rows instead. Hosts with bigger fleets
 *  should use the Docker plugin (Engine API, no SSH output limits). */
const MAX_INVENTORY_CONTAINERS = 150;
const MAX_INVENTORY_IMAGES = 200;

/** Batch size for `docker inspect` — one full inspect object is ~3–8 KB and the
 *  SDK truncates stdout at 256 KB, so each batch must stay well under that. */
const INSPECT_BATCH = 24;

/** One SSH round-trip: list every container id (with docker presence/error
 *  markers). Output contract:
 *    DOCKER_OK   — the docker CLI exists on this host
 *    DOCKER_ERR  — `docker ps` itself failed (socket permission denied, …)
 *    <id>        — one short container id per line (only when OK and non-empty) */
function buildIdListCommand(): string {
  return [
    'if command -v docker >/dev/null 2>&1; then',
    '  echo "DOCKER_OK"',
    // Capture WITHOUT a pipe so $? is docker's own exit code — a failed `docker ps`
    // (socket permission denied) must not look like an empty fleet.
    "  ids=$(docker ps -a --format '{{.ID}}' 2>/dev/null)",
    '  if [ $? -ne 0 ]; then',
    '    echo "DOCKER_ERR"',
    '  else',
    '    printf "%s\\n" "$ids"',
    '  fi',
    'fi',
  ].join('\n');
}

/** One SSH round-trip: list every image id (only when docker exists). */
function buildImageIdCommand(): string {
  return [
    'if command -v docker >/dev/null 2>&1; then',
    "  docker images -q 2>/dev/null | head -n ${MAX_INVENTORY_IMAGES}",
    'fi',
  ].join('\n');
}

/** Parses a section of inspect output (one compact JSON object per line). */
function parseJsonLines<T>(section: string): T[] {
  const out: T[] = [];
  for (const line of section.split('\n')) {
    const t = line.trim();
    if (!t.startsWith('{')) continue;
    try {
      out.push(JSON.parse(t) as T);
    } catch { /* malformed/truncated line — skip */ }
  }
  return out;
}

/** Splits an id list into batches (word-safe: ids are hex). */
function chunk<T>(items: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

export interface DockerInventoryResult {
  /** null = docker CLI not present / collection failed (caller omits the keys — no wipe). */
  containers: UnmContainerRow[] | null;
  images: UnmImageRow[] | null;
}

/** Throttled diagnostics for inventory failures — one line per host per minute. */
const lastInventoryFailLog = new Map<string, number>();
function inventoryFailLog(host: string, message: string): void {
  const now = Date.now();
  if (now - (lastInventoryFailLog.get(host) ?? 0) < 60_000) return;
  lastInventoryFailLog.set(host, now);
  console.warn(`[generic-ssh-plugin] ${message}`);
}

/**
 * Collects the container + image inventory over SSH. Uses `docker inspect`
 * (Engine API JSON — the STABLE schema: Name string, Config.Labels, State.Status)
 * in bounded batches instead of `docker ps -a --format json`, whose field shape
 * varies between docker versions and podman-docker. Returns `{ null, null }` when
 * docker is absent OR collection fails (absent = no wipe); a present-but-empty
 * array IS authoritative (the host genuinely runs none).
 */
export async function collectDockerInventory(backend: CommandRunner): Promise<DockerInventoryResult> {
  // Pass 1 — container ids + presence markers.
  const listR = await backend.exec(buildIdListCommand(), 20_000).catch(() => null);
  if (!listR || listR.code !== 0) {
    inventoryFailLog(backend.host, `Container inventory: id-list exec failed (code ${listR?.code ?? 'null'})`);
    return { containers: null, images: null };
  }
  const out = listR.stdout ?? '';
  if (!out.includes('DOCKER_OK')) return { containers: null, images: null }; // no docker — omit keys
  if (out.includes('DOCKER_ERR')) {
    inventoryFailLog(backend.host, 'Container inventory: `docker ps` failed on host (socket permission?)');
    return { containers: null, images: null };
  }
  const ids = out.split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]{12,64}$/.test(l));

  // Pass 2 — inspect in bounded batches (stdout truncation guard).
  let rawContainers: DockerContainerRaw[] = [];
  for (const batch of chunk(ids.slice(0, MAX_INVENTORY_CONTAINERS), INSPECT_BATCH)) {
    const r = await backend.exec(`docker inspect --format '{{json .}}' ${batch.join(' ')} 2>/dev/null || true`, 25_000).catch(() => null);
    if (!r) return { containers: null, images: null }; // transport failure — no wipe
    rawContainers.push(...parseJsonLines<DockerContainerRaw>(r.stdout ?? ''));
  }
  // Count check — a truncated/failed batch must not masquerade as an empty fleet.
  if (ids.length > MAX_INVENTORY_CONTAINERS) {
    inventoryFailLog(backend.host, `Container inventory: ${ids.length} containers exceeds cap ${MAX_INVENTORY_CONTAINERS} — keeping stored rows`);
    return { containers: null, images: null };
  }
  if (rawContainers.length !== ids.length) {
    inventoryFailLog(backend.host, `Container inventory: inspected ${rawContainers.length}/${ids.length} containers — keeping stored rows`);
    return { containers: null, images: null };
  }

  // Pass 3 — image ids + inspect batches (same guards). `docker ps` already
  // succeeded above, so a failure here is transport-level → keep container data,
  // omit images (no wipe).
  const imgListR = await backend.exec(buildImageIdCommand(), 20_000).catch(() => null);
  let rawImages: DockerImageRaw[] = [];
  if (imgListR && imgListR.code === 0) {
    const imageIds = (imgListR.stdout ?? '').split('\n').map((l) => l.trim()).filter((l) => /^[0-9a-f]{12,64}$/.test(l));
    for (const batch of chunk(imageIds.slice(0, MAX_INVENTORY_IMAGES), 40)) {
      const r = await backend.exec(`docker image inspect --format '{{json .}}' ${batch.join(' ')} 2>/dev/null || true`, 25_000).catch(() => null);
      if (!r) return { containers: buildContainerRows(rawContainers.map(normalizeContainerRaw)), images: null }; // keep container data, no image wipe
      rawImages.push(...parseJsonLines<DockerImageRaw>(r.stdout ?? ''));
    }
    if (imageIds.length > MAX_INVENTORY_IMAGES || rawImages.length !== Math.min(imageIds.length, MAX_INVENTORY_IMAGES)) {
      inventoryFailLog(backend.host, `Container inventory: inspected ${rawImages.length}/${Math.min(imageIds.length, MAX_INVENTORY_IMAGES)} images — keeping stored rows`);
      return { containers: buildContainerRows(rawContainers.map(normalizeContainerRaw)), images: null };
    }
  }

  const containers = rawContainers.map(normalizeContainerRaw);

  // inspect reports a container's Image as the IMAGE ID (sha256:…) — map it to a
  // display tag from the image inventory so rows show "nginx:alpine", not a sha.
  const tagById = new Map<string, string>();
  for (const img of rawImages) {
    if (!img || typeof img.Id !== 'string') continue;
    const id = img.Id.replace(/^sha256:/, '');
    if (!id) continue;
    const tags = Array.isArray(img.RepoTags) ? img.RepoTags.filter((t): t is string => typeof t === 'string' && t.length > 0 && t !== NONE_TAG) : [];
    tagById.set(id.slice(0, 12), tags[0] ?? id.slice(0, 12));
  }
  for (const c of containers) {
    if (!c || typeof c.Image !== 'string') continue;
    const bare = c.Image.replace(/^sha256:/, '');
    const tag = tagById.get(bare.slice(0, 12));
    if (tag) c.Image = tag;
  }

  return { containers: buildContainerRows(containers), images: buildImageRows(rawImages) };
}

// --- Live probe collectors (POST /probe) -------------------------------------------

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
  /** Docker-native lowercase state ('running', 'exited', 'created', …). */
  status: string;
}

// SEPARATE rate trackers for the probe path — the webapp polls every few seconds,
// so each interval yields a fresh average. (No other cycle samples these counters.)
const netRxTracker = new CounterTracker({ toBitsPerSec: false });
const netTxTracker = new CounterTracker({ toBitsPerSec: false });
const blkReadTracker = new CounterTracker({ toBitsPerSec: false });
const blkWriteTracker = new CounterTracker({ toBitsPerSec: false });

/** Throttled failure logging — a flaky host must not spam the log every poll. */
const lastProbeFailLog = new Map<string, number>();
function probeFailLog(host: string, message: string): void {
  const now = Date.now();
  if (now - (lastProbeFailLog.get(host) ?? 0) < 60_000) return; // at most one warn/min/host
  lastProbeFailLog.set(host, now);
  console.warn(`[generic-ssh-plugin] ${message}`);
}

/** Cap on how many containers we'll stat in one probe (defensive). */
const MAX_STATS = 200;

/**
 * Collects the live state of ALL containers: ONE cheap `docker ps -a` pass with
 * stable template accessors. Reports every container with its real docker state —
 * so a caller can watch specific containers through a start/stop transition.
 * `names` optionally restricts the result to a subset (absent = all). Returns
 * null on failure; an EMPTY map is a valid answer (no containers at all) and
 * must NOT be conflated with failure.
 */
export async function collectProbeStates(backend: CommandRunner, names?: string[]): Promise<Map<string, ProbeContainerState> | null> {
  try {
    // Template accessors (.Names/.State) are documented + version-stable — the
    // `--format json` field shape is NOT (it varies across docker/podman-docker).
    const r = await backend.exec('command -v docker >/dev/null 2>&1 && docker ps -a --format "{{.Names}}|{{.State}}" 2>/dev/null || true', 15_000);
    if (!r) return null;
    const wanted = names && names.length > 0 ? new Set(names) : null;
    const out = new Map<string, ProbeContainerState>();
    for (const line of (r.stdout ?? '').split('\n')) {
      const t = line.trim();
      if (!t || !t.includes('|')) continue;
      const i = t.lastIndexOf('|'); // state never contains '|'; names may
      const name = t.slice(0, i).replace(/^\/+/, '');
      const status = t.slice(i + 1).trim().toLowerCase();
      if (!name || !status) continue;
      if (wanted && !wanted.has(name)) continue;
      out.set(name, { name, status });
    }
    return out;
  } catch (e) {
    probeFailLog(backend.host, `Docker states probe failed: ${(e as Error).message}`);
    return null;
  }
}

// --- Lite container listing (stable template accessors) ---------------------------

/** One lite row from the ps template pass — enough for membership + state checks. */
interface ContainerLite {
  id: string;
  name: string; // leading "/" stripped
  state: string; // lowercase docker state ('running', 'exited', …)
  project: string | null; // com.docker.compose.project label value (null when absent)
}

/** The stable one-pass listing used by membership resolution + state verification.
 *  `.ID`, `.Names`, `.State` and `.Label "key"` are documented ps template fields —
 *  unlike `--format json`, whose object shape changes between docker versions. */
async function listContainersLite(backend: CommandRunner): Promise<ContainerLite[] | null> {
  const r = await backend.exec(
    'command -v docker >/dev/null 2>&1 && docker ps -a --format \'{{.ID}}|{{.Names}}|{{.State}}|{{.Label "com.docker.compose.project"}}\' 2>/dev/null || true',
    15_000,
  ).catch(() => null);
  if (!r) return null;
  const out: ContainerLite[] = [];
  for (const line of (r.stdout ?? '').split('\n')) {
    const t = line.trim();
    if (!t) continue;
    // Split into exactly 4 fields — the label value may itself contain '|'.
    const parts = t.split('|');
    if (parts.length < 4) continue;
    const id = parts[0] ?? '';
    const name = (parts[1] ?? '').replace(/^\/+/, '');
    const state = (parts[2] ?? '').trim().toLowerCase();
    let project: string | null = parts.slice(3).join('|').trim() || null;
    if (project === '<no value>') project = null; // Go template missing-map sentinel
    if (!id || !name) continue;
    out.push({ id, name, state, project });
  }
  return out;
}

/** docker stats human sizes: "512.2kB", "7.8GiB", "0B" — base-1024 suffixes. */
const HUMAN_SIZE_RE = /^([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?i?B?)$/i;
const SIZE_MULT: Record<string, number> = { B: 1, KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3, TB: 1024 ** 4, PB: 1024 ** 5 };

/** Parses one docker humanized size ("5.2MiB") into bytes; undefined for "—". */
function parseHumanBytes(s: string | null | undefined): number | undefined {
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

/** One container's RAW docker-stats observation. CPU% + memory are instantaneous;
 * the four I/O fields are CUMULATIVE byte counters since container start. */
interface DockerStatsRaw {
  cpuPct?: number;
  memUsedBytes?: number;
  memLimitBytes?: number;
  netRxBytes?: number;
  netTxBytes?: number;
  blkReadBytes?: number;
  blkWriteBytes?: number;
}

/** Parses the STAT| lines of `docker stats --no-stream` output. */
function parseDockerStats(stdout: string): Map<string, DockerStatsRaw> {
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

/**
 * Collects live per-container stats for the PROBE path: ONE `docker stats
 * --no-stream` pass over all running containers (the same source the TrueNAS
 * plugin uses over SSH). CPU% + memory are instantaneous; Net/Block I/O are
 * cumulative counters fed to dedicated probe trackers so fast cycles yield
 * fresh rates. Returns null on failure (webapp keeps last good data); an EMPTY
 * map is valid (nothing running).
 */
export async function collectProbeStats(backend: CommandRunner): Promise<Map<string, ProbeContainerStat> | null> {
  try {
    // Enumerate running containers first — stats only makes sense for those.
    const list = await backend.exec('command -v docker >/dev/null 2>&1 && docker ps --format "{{.Names}}" 2>/dev/null || true', 15_000);
    if (!list) return null;
    const names = (list.stdout ?? '').split('\n').map((l) => l.trim()).filter(Boolean).slice(0, MAX_STATS);
    if (names.length === 0) return new Map(); // nothing running — valid empty answer

    const quoted = names.map((n) => `'${n.replace(/'/g, "'\\''")}'`).join(' ');
    const cmd = `docker stats --no-stream ${quoted} --format 'STAT|{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.NetIO}}|{{.BlockIO}}' 2>/dev/null`;
    // docker stats samples each container over ~1 s — scale the budget with the fleet.
    const r = await backend.exec(cmd, Math.min(60_000, 15_000 + names.length * 1_000));
    if (!r) return null;

    const raw = parseDockerStats(r.stdout ?? '');
    const out = new Map<string, ProbeContainerStat>();
    for (const [name, x] of raw) {
      const stat: ProbeContainerStat = { name };
      if (x.cpuPct !== undefined) stat.cpuPct = Math.round(x.cpuPct * 10) / 10;
      if (x.memUsedBytes !== undefined) stat.memUsedBytes = x.memUsedBytes;
      if (x.memLimitBytes !== undefined && x.memLimitBytes < Number.MAX_SAFE_INTEGER / 2) stat.memLimitBytes = x.memLimitBytes;

      const key = `probe|${backend.host}|${name}`;
      const nr = x.netRxBytes !== undefined ? netRxTracker.sample(`${key}|netRx`, x.netRxBytes) : null;
      if (nr !== null && nr > 0) stat.netRxRate = Math.round(nr);
      const nt = x.netTxBytes !== undefined ? netTxTracker.sample(`${key}|netTx`, x.netTxBytes) : null;
      if (nt !== null && nt > 0) stat.netTxRate = Math.round(nt);
      const br = x.blkReadBytes !== undefined ? blkReadTracker.sample(`${key}|blkRead`, x.blkReadBytes) : null;
      if (br !== null && br > 0) stat.blkReadRate = Math.round(br);
      const bw = x.blkWriteBytes !== undefined ? blkWriteTracker.sample(`${key}|blkWrite`, x.blkWriteBytes) : null;
      if (bw !== null && bw > 0) stat.blkWriteRate = Math.round(bw);

      out.set(name, stat);
    }
    return out;
  } catch (e) {
    probeFailLog(backend.host, `Docker stats probe failed: ${(e as Error).message}`);
    return null;
  }
}

// --- Member resolution (shared by the lifecycle actions) ----------------------------

/**
 * Resolves an app NAME to its member containers over SSH.
 *   - compose project → every container carrying com.docker.compose.project=<name>
 *   - else            → a single standalone container whose docker name == <name>
 * Returns null when nothing matches (the caller reports it as "missing").
 */
export async function resolveMembers(backend: CommandRunner, app: string): Promise<DockerContainerRaw[] | null> {
  const all = await listContainersLite(backend);
  if (!all) return null;

  // Try the compose-project interpretation first.
  const byProject = all.filter((c) => c.project === app);
  if (byProject.length > 0) return toRaw(byProject);

  // Fall back to a standalone container with this exact docker name.
  const hit = all.filter((c) => c.name === app);
  return hit.length > 0 ? toRaw(hit) : null;
}

/** Maps lite rows onto the raw shape (only Id/Names/State are consumed downstream). */
function toRaw(lite: ContainerLite[]): DockerContainerRaw[] {
  return lite.map((c) => ({ Id: c.id, Names: [c.name], State: c.state }));
}

/** Re-reads the current state map name→state for the given member names ('gone' when absent). */
export async function readStates(backend: CommandRunner, names: string[]): Promise<Record<string, string> | null> {
  const all = await listContainersLite(backend);
  if (!all) return null; // transient failure — caller retries
  const byName = new Map(all.map((c) => [c.name, c.state || 'unknown']));
  const out: Record<string, string> = {};
  for (const n of names) out[n] = byName.get(n) ?? 'gone';
  return out;
}

/** Waits until every member is in one of `want` states. Returns the last observed map. */
export async function verifyStates(backend: CommandRunner, members: DockerContainerRaw[], want: Set<string>): Promise<{ ok: boolean; after: Record<string, string> }> {
  const names = members.map(containerName);
  let last: Record<string, string> | null = null;
  const deadline = Date.now() + 30_000;
  for (;;) {
    const cur = await readStates(backend, names);
    if (cur !== null) {
      last = cur;
      // `cur` is a const — the closure below keeps its non-null narrowing.
      if (names.every((n) => want.has(cur[n]))) return { ok: true, after: cur };
    }
    if (Date.now() >= deadline) break;
    await new Promise((res) => setTimeout(res, 1_500));
  }
  return { ok: false, after: last ?? {} };
}

/** Waits until every member has DISAPPEARED (delete verification). */
export async function verifyGone(backend: CommandRunner, members: DockerContainerRaw[]): Promise<{ ok: boolean; after: Record<string, string> }> {
  return verifyStates(backend, members, new Set(['gone']));
}
