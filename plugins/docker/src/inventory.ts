/**
 * Maps raw Docker Engine API data (`/containers/json?all=true`) onto UNM's
 * generic `containers[]` metric contract (docs/PLUGIN-DEVELOPMENT.md §5) so the
 * webapp Containers page renders it with zero changes:
 *
 *   one row per "App"  =  compose project (label com.docker.compose.project);
 *   non-compose containers each become their own single-container row.
 *
 * Row shape: { name, state (UPPERCASE), image?, startedAt?, extra } where extra
 * carries networks[] / ips[] / ports[] / containerCount / containers[] (the
 * per-container detail the expandable tree renders) / volumeMounts[].
 */

// --- Raw Docker JSON shapes (defensive reads everywhere — field sets vary by
//     engine version; a missing field must never break a poll). ---------------

interface DockerPort {
  IP?: string;
  PrivatePort?: number;
  PublicPort?: number | null;
  Type?: string;
}

interface DockerNetworkSettings {
  Networks?: Record<string, { MacAddress?: string; IPAMConfig?: { IPv4Address?: string; IPv6Address?: string } ; GlobalIPv6Address?: string }>;
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
  Names?: string[];
  Image?: string;
  State?: string; // running | exited | created | restarting | paused | dead | removing
  Status?: string;
  Ports?: DockerPort[];
  Labels?: Record<string, string>;
  NetworkSettings?: DockerNetworkSettings;
  Mounts?: DockerMount[];
}

// --- UNM row shapes (mirror webapp/src/api/client.ts) -------------------------

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

export interface ContainerServiceDetail {
  service?: string | null;
  image?: string | null;
  state?: string | null;
  mac?: string | null;
  ip?: string | null;
  startedAt?: string | null;
  volumes?: ContainerVolume[];
}

export interface ContainerRow {
  name: string;
  state: string; // UPPERCASE — the API uppercases at ingest anyway
  image?: string | null;
  version?: string | null;
  upgradeAvailable?: boolean | null;
  startedAt?: string | null;
  extra?: Record<string, unknown>;
}

// --- Helpers -------------------------------------------------------------------

const COMPOSE_PROJECT_LABEL = 'com.docker.compose.project';
const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/i;

/** Container display name — first of Names with the leading "/" stripped. */
function containerName(c: DockerContainerRaw): string {
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

/** Per-container network detail: first net with a real IP wins for ip+mac, else
 * the first net that at least carries a MAC. */
function netDetail(c: DockerContainerRaw): { ip?: string | null; mac?: string | null } {
  const nets = c.NetworkSettings?.Networks ?? {};
  let fallbackMac: string | null = null;
  for (const entry of Object.values(nets)) {
    if (!entry) continue;
    const mac = typeof entry.MacAddress === 'string' && MAC_RE.test(entry.MacAddress) ? entry.MacAddress : null;
    if (!fallbackMac && mac) fallbackMac = mac;
    const ip = entry.IPAMConfig?.IPv4Address || entry.IPAMConfig?.IPv6Address || entry.GlobalIPv6Address || undefined;
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
    state: typeof c.State === 'string' && c.State ? c.State.toLowerCase() : null,
    ip: ip ?? null,
    mac: mac ?? null,
    startedAt: cleanStartedAt(startedAtOf(c)),
    volumes: volumeMounts(c),
  };
}

/** ISO start of the current RUNNING period — read defensively from wherever an
 * engine version puts it: top-level `StartedAt` (newer engines) or nested under
 * a State object. Older engines expose neither in /containers/json → null, and
 * UNM then tracks uptime itself from RUNNING state transitions at ingest. */
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

// --- Main mapping ----------------------------------------------------------------

/** Groups raw containers by compose project and builds one UNM row per group. */
export function buildContainerRows(raw: DockerContainerRaw[]): ContainerRow[] {
  const groups = new Map<string, DockerContainerRaw[]>();
  for (const c of raw) {
    if (!c || typeof c !== 'object') continue;
    const project = typeof c.Labels?.[COMPOSE_PROJECT_LABEL] === 'string' && c.Labels[COMPOSE_PROJECT_LABEL] ? c.Labels[COMPOSE_PROJECT_LABEL] : null;
    const key = project ?? `__single__:${containerName(c)}`;
    const list = groups.get(key);
    if (list) list.push(c);
    else groups.set(key, [c]);
  }

  const rows: ContainerRow[] = [];
  for (const [key, members] of groups) {
    const name = key.startsWith('__single__:') ? containerName(members[0]) : key;
    const sorted = [...members].sort((a, b) => containerName(a).localeCompare(containerName(b)));

    // Per-container detail for the tree.
    const containers: ContainerServiceDetail[] = sorted.map(serviceDetail);

    // App-level aggregates.
    const states = sorted.map((c) => (typeof c.State === 'string' ? c.State.toLowerCase() : ''));
    const state = aggregateState(states);

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

    // App-level image/startedAt only for single-container rows (mirrors ix-truenas).
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

// --- Image inventory (/images/json → UNM `images[]` metric) -------------------

export interface DockerImageRaw {
  Id?: string; // sha256:<hex>
  RepoTags?: string[]; // ["nginx:1.27-alpine", "<none>:<none>", ...] or [] for untagged
  RepoDigests?: string[];
  Created?: number; // unix seconds
  Size?: number;
  VirtualSize?: number;
  Containers?: number;
}

/** One row of the images inventory (shape consumed by the API's ingestInventory). */
export interface ImageRow {
  name: string;
  sizeBytes?: number | null;
  createdAt?: string | null;
  /** Plain Docker hosts do no registry checks — always null. */
  updateAvailable?: boolean | null;
  dangling?: boolean;
  extra?: Record<string, unknown>;
}

const NONE_TAG = '<none>:<none>';

/** Maps raw /images/json entries to UNM image rows: one row per IMAGE (not per
 * tag) — the first real tag is the name, all tags/digests ride in `extra`. An
 * image whose only tag is <none>:<none> is dangling and named by its short id. */
export function buildImageRows(raw: DockerImageRaw[]): ImageRow[] {
  const rows: ImageRow[] = [];
  for (const img of raw) {
    if (!img || typeof img !== 'object') continue;
    const tags = Array.isArray(img.RepoTags) ? img.RepoTags.filter((t): t is string => typeof t === 'string' && t.length > 0) : [];
    const realTags = tags.filter((t) => t !== NONE_TAG);
    const dangling = realTags.length === 0;

    let name: string;
    if (!dangling) {
      name = realTags[0];
    } else {
      // Untagged image — identify by short id so the row is stable + readable.
      const id = typeof img.Id === 'string' ? img.Id.replace(/^sha256:/, '') : '';
      name = id ? `sha256:${id.slice(0, 12)}` : 'unknown';
    }

    const sizeBytes = typeof img.Size === 'number' && img.Size > 0
      ? img.Size
      : (typeof img.VirtualSize === 'number' && img.VirtualSize > 0 ? img.VirtualSize : null);
    const createdAt = typeof img.Created === 'number' && Number.isFinite(img.Created)
      ? new Date(img.Created * 1000).toISOString()
      : null;

    rows.push({
      name,
      sizeBytes,
      createdAt,
      updateAvailable: null, // no registry check on plain Docker hosts
      dangling,
      extra: {
        ...(realTags.length > 1 ? { tags: realTags } : {}),
        ...(Array.isArray(img.RepoDigests) && img.RepoDigests.length > 0 ? { digests: img.RepoDigests } : {}),
        ...(typeof img.Containers === 'number' ? { containersUsing: img.Containers } : {}),
      },
    });
  }
  return rows.sort((a, b) => a.name.localeCompare(b.name));
}
