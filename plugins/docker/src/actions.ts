/**
 * The Docker Engine action registry — makes this plugin config-capable so the
 * Containers page's Start / Stop / Restart / Delete buttons (and image delete)
 * light up for bare-metal Docker hosts. Serves two entry points:
 *   - /discover → listCatalog()  (the catalog the API persists + validates)
 *   - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * The webapp sends APP-level `names[]` for container actions and image `ids[]`
 * for images.delete. An "app" here is either a compose PROJECT (label
 * com.docker.compose.project=<name>) or a single standalone container — the
 * same grouping rows.ts uses to build inventory rows, so names line up 1:1 with
 * what the Containers page shows. We resolve each name to its member containers
 * via /containers/json and drive them through the Engine API (start/stop/
 * restart/delete). Idempotent by design: a container already in the target
 * state is skipped, not failed — mirroring ix-truenas's app.* actions.
 */

import { ActionDescriptor, ActionResult, INTENT_CONTAINERS_IMAGE_SET, createRegistry, createSshPool, pollUntil, resolveSshCredentials } from '@unm/plugin-sdk';
import { DockerClientOptions, containerLogsRaw, dockerDelete, dockerGet, dockerPost, dockerRequest, listComposeMembers, listContainers, listImages, pullImageStream } from './client';

/** Executor context for one /config step — resolved client options + the raw
 *  decrypted credentials body (needed by SSH-based actions like deploy-compose). */
export interface DockerActionContext {
  opts: DockerClientOptions;
  /** The request's `credentials` field (decrypted primary secret + slots). */
  credentials?: Record<string, unknown> | null;
}

// One shared SSH pool for the whole plugin process — deploy-compose reuses a
// live session per host instead of re-authenticating on every step. Exported so
// /monitoring's GPU probe (collectGpus option) reuses the SAME pooled sessions.
export const sshPool = createSshPool();
process.on('SIGTERM', () => sshPool.closeAll());
process.on('SIGINT', () => sshPool.closeAll());

const COMPOSE_PROJECT_LABEL = 'com.docker.compose.project';

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v : undefined;
}

function strArray(input: Record<string, unknown>, key: string): string[] {
  const v = input[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map((s) => s.trim());
}

/** One raw container as the Engine API returns it (defensive reads). */
interface RawContainer {
  Id?: string;
  Names?: string[];
  State?: string; // running | exited | created | restarting | paused | dead | removing
  /** Image ref exactly as used at creation (e.g. "nginx:latest") — /containers/json only. */
  Image?: string;
  Labels?: Record<string, string>;
}

function nameOf(c: RawContainer): string {
  const raw = Array.isArray(c.Names) && c.Names.length > 0 ? String(c.Names[0]) : '';
  return raw.replace(/^\/+/, '') || 'unknown';
}

/**
 * Resolves an app NAME to the set of member containers that should be driven.
 *   - compose project → every container carrying com.docker.compose.project=<name>
 *   - else            → a single standalone container whose docker name == <name>
 * Returns null when nothing matches (the caller reports it as "missing").
 */
async function resolveMembers(opts: DockerClientOptions, app: string): Promise<RawContainer[] | null> {
  // Try the compose-project interpretation first.
  const byProject = await listComposeMembers(opts, app);
  if (byProject.ok && Array.isArray(byProject.data) && byProject.data.length > 0) {
    return byProject.data as RawContainer[];
  }
  // Fall back to a standalone container with this exact docker name.
  const all = await listContainers(opts);
  if (!all.ok || !Array.isArray(all.data)) return null;
  const hit = (all.data as RawContainer[]).filter((c) => {
    const n = nameOf(c);
    return n === app || c.Labels?.[COMPOSE_PROJECT_LABEL] === app;
  });
  return hit.length > 0 ? hit : null;
}

/** Drives one container to a target lifecycle verb (start/stop/restart). */
async function drive(opts: DockerClientOptions, idOrName: string, verb: 'start' | 'stop' | 'restart'): Promise<{ ok: boolean; error?: string }> {
  // stop/restart block for the graceful-stop period before force-killing. Docker's
  // default is 10 s — too long when several members run sequentially under the API's
  // config-job budget, so we pass a short `t` (4 s). start returns immediately.
  const t = verb === 'start' ? '' : '?t=4';
  const r = await dockerPost<unknown>(opts, `/containers/${encodeURIComponent(idOrName)}/${verb}${t}`);
  if (r.ok) return { ok: true };
  // Engine returns 304 Not Modified when the container is already in that state.
  if (r.status === 304) return { ok: true };
  const msg = r.error || `HTTP ${r.status}`;
  return { ok: false, error: msg };
}

/** Drives all member containers of one app to a verb IN PARALLEL — each op is
 * independent and the wall-clock time stays ~one grace period regardless of how
 * many services an app has (keeps multi-service compose apps under budget). */
async function driveMembers(opts: DockerClientOptions, members: RawContainer[], verb: 'start' | 'stop' | 'restart'): Promise<{ ok: boolean; error?: string }> {
  const results = await Promise.all(members.map((m) => drive(opts, nameOf(m), verb)));
  const firstError = results.find((r) => !r.ok)?.error;
  return firstError ? { ok: false, error: firstError } : { ok: true };
}

// --- Post-apply state verification ---------------------------------------------
// UNM marks a plan step "verified" only when the plugin RE-READS device state
// after applying and confirms the target was reached (ActionResult.verified).
// The Engine API's start/stop/restart return as soon as the daemon ACKNOWLEDGES
// the transition — a container can still be restarting, or a stop can time out
// into a force-kill later. These helpers poll /containers/json until every
// driven member reaches its target state (or disappears, for deletes), bounded
// so a stuck container surfaces as "unverified" instead of blocking forever.

/** Engine states that count as "stopped". */
const STOPPED_STATES = new Set(['exited', 'created', 'dead']);

/** Re-reads the current state map name→state for the given member names ('gone' when absent). */
async function readStates(opts: DockerClientOptions, names: string[]): Promise<Record<string, string> | null> {
  const all = await listContainers(opts);
  if (!all.ok || !Array.isArray(all.data)) return null; // transient failure — pollUntil retries
  const byName = new Map((all.data as RawContainer[]).map((c) => [nameOf(c), c.State ?? 'unknown']));
  const out: Record<string, string> = {};
  for (const n of names) out[n] = byName.get(n) ?? 'gone';
  return out;
}

/** Waits until every member is in one of `want` states. Returns the last observed map. */
async function verifyStates(opts: DockerClientOptions, members: RawContainer[], want: Set<string>): Promise<{ ok: boolean; after: Record<string, string> }> {
  const names = members.map(nameOf);
  const wait = await pollUntil(
    () => readStates(opts, names),
    (states) => states !== null && names.every((n) => want.has(states[n])),
    { timeoutMs: 30_000, intervalMs: 1_500 },
  );
  return { ok: wait.ok, after: wait.value ?? {} };
}

/** Waits until every member has DISAPPEARED (delete verification). */
async function verifyGone(opts: DockerClientOptions, members: RawContainer[]): Promise<{ ok: boolean; after: Record<string, string> }> {
  const names = members.map(nameOf);
  const wait = await pollUntil(
    () => readStates(opts, names),
    (states) => states !== null && names.every((n) => states[n] === 'gone'),
    { timeoutMs: 30_000, intervalMs: 1_500 },
  );
  return { ok: wait.ok, after: wait.value ?? {} };
}

// --- containers.start ---------------------------------------------------------
const containersStartAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.start',
  label: 'Start container(s)',
  description: 'Starts the selected apps (docker start). Apps already running are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App / container names to start' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };

    let started = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx.opts, members, 'start');
      if (!r.ok) { errors[n] = r.error!; continue; }
      started++;
      // Verify: the daemon acks a start before it completes — every member must
      // actually be running for this step to count as verified.
      const v = await verifyStates(ctx.opts, members, new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { started, skipped, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.stop ----------------------------------------------------------
const containersStopAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.stop',
  label: 'Stop container(s)',
  description: 'Stops the selected apps (docker stop). Apps already stopped are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App / container names to stop' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };

    let stopped = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx.opts, members, 'stop');
      if (!r.ok) { errors[n] = r.error!; continue; }
      stopped++;
      // Verify: an explicit stop sticks (restart policies only re-fire on daemon
      // start / crash-exit), so every member must end in a stopped state.
      const v = await verifyStates(ctx.opts, members, STOPPED_STATES);
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { stopped, skipped, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.restart -------------------------------------------------------
const containersRestartAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.restart',
  label: 'Restart container(s)',
  description: 'Restarts the selected apps (docker restart). Stopped apps are started directly.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App / container names to restart' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };

    let restarted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      // A stopped container can't be restarted — start it instead. Run all
      // members in parallel so a multi-service app stays under budget.
      const results = await Promise.all(members.map((m) => drive(ctx.opts, nameOf(m), m.State === 'running' ? 'restart' : 'start')));
      const firstError = results.find((r) => !r.ok)?.error;
      if (firstError) { errors[n] = firstError; continue; }
      restarted++;
      // Verify: a restart is only done when every member is running again.
      const v = await verifyStates(ctx.opts, members, new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { restarted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

/**
 * Resolves ONE exact docker container NAME (no compose-project fan-out). The
 * per-container actions target a single member of an app — the webapp's child
 * rows carry each member's real docker name, so an exact match is all that's
 * needed. Returns null when nothing matches (caller reports "missing").
 */
async function resolveExact(opts: DockerClientOptions, containerName: string): Promise<RawContainer | null> {
  const all = await listContainers(opts); // ?all=true — stopped containers included
  if (!all.ok || !Array.isArray(all.data)) return null;
  const hit = (all.data as RawContainer[]).find((c) => nameOf(c) === containerName);
  return hit ?? null;
}

// --- containers.stop-one ------------------------------------------------------
const containersStopOneAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.stop-one',
  label: 'Stop one container',
  description:
    'Stops a SINGLE container by its exact docker name (docker stop) — per-container control for members of an app. Unlike containers.stop it never fans out to the whole compose project, and on a bare Docker host an explicit stop STICKS even with a restart policy (policies only re-fire on daemon start or crash-exit). Already-stopped containers are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Exact docker container name(s) to stop' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No container names provided' } };

    let stopped = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      const r = await drive(ctx.opts, nameOf(c), 'stop');
      if (!r.ok) { errors[n] = r.error!; continue; } // 304 (already stopped) counts as ok inside drive()
      stopped++;
      const v = await verifyStates(ctx.opts, [c], STOPPED_STATES);
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { stopped, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.start-one -----------------------------------------------------
const containersStartOneAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.start-one',
  label: 'Start one container',
  description:
    'Starts a SINGLE container by its exact docker name (docker start) — per-container control for members of an app. Already-running containers are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Exact docker container name(s) to start' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No container names provided' } };

    let started = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      const r = await drive(ctx.opts, nameOf(c), 'start');
      if (!r.ok) { errors[n] = r.error!; continue; } // 304 (already running) counts as ok inside drive()
      started++;
      const v = await verifyStates(ctx.opts, [c], new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { started, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.restart-one ---------------------------------------------------
const containersRestartOneAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.restart-one',
  label: 'Restart one container',
  description:
    'Restarts a SINGLE container by its exact docker name (docker restart; stopped ones are started instead) — per-container control for members of an app.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Exact docker container name(s) to restart' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No container names provided' } };

    let restarted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      // A stopped container can't be restarted — start it instead.
      const r = await drive(ctx.opts, nameOf(c), c.State === 'running' ? 'restart' : 'start');
      if (!r.ok) { errors[n] = r.error!; continue; }
      restarted++;
      const v = await verifyStates(ctx.opts, [c], new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { restarted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.delete-one ----------------------------------------------------
const containersDeleteOneAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.delete-one',
  label: 'Delete one container',
  description:
    'DELETES a SINGLE container by its exact docker name (docker rm -f) — per-container control for members of an app. Named volumes are NOT removed; anonymous volumes are. The rest of the compose project keeps running.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Exact docker container name(s) to delete' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No container names provided' } };

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      // -f forces removal of running containers; v=false keeps named volumes.
      const r = await dockerDelete<unknown>(ctx.opts, `/containers/${encodeURIComponent(nameOf(c))}?force=true&v=false`);
      if (!r.ok && r.status !== 304) { errors[n] = r.error || `HTTP ${r.status}`; continue; }
      deleted++;
      // Verify: the container must be gone from /containers/json.
      const v = await verifyGone(ctx.opts, [c]);
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { deleted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.delete --------------------------------------------------------
const containersDeleteAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.delete',
  label: 'Delete container(s)',
  description:
    'DELETES the selected apps and their docker resources (docker rm -f). This is destructive — named volumes are NOT removed, but any anonymous volumes are.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App / container names to delete' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      // -f forces removal of running containers; -v=false keeps named volumes.
      // Run all members in parallel so a multi-service app stays under budget.
      const results = await Promise.all(
        members.map(async (m) => {
          const r = await dockerDelete<unknown>(ctx.opts, `/containers/${encodeURIComponent(nameOf(m))}?force=true&v=false`);
          return !r.ok && r.status !== 304 ? (r.error || `HTTP ${r.status}`) : undefined;
        })
      );
      const firstError = results.find((e) => e !== undefined);
      if (firstError) { errors[n] = firstError; continue; }
      deleted++;
      // Verify: every member must be gone from /containers/json.
      const v = await verifyGone(ctx.opts, members);
      if (!v.ok) unverifiedNames.push(n);
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedNames.length === 0, details: { deleted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- containers.deploy-compose -------------------------------------------------
// Deploys a NEW compose stack on the host via SSH (`docker compose up -d`). The
// Engine API has no classic compose endpoint (its /services/create is swarm-only),
// so the host's compose CLI is the transport — same pattern as TrueNAS enrichment.
const COMPOSE_YAML_DELIM = '__UNM_COMPOSE_YAML_8f3a__';

/** Strips scheme + port from a management address for SSH (port 22). */
function sshHostOf(managementAddress: string): string {
  const bare = (managementAddress ?? '').trim().replace(/^https?:\/\//i, '');
  return bare.split(':')[0] || bare;
}

const containersDeployComposeAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.deploy-compose',
  label: 'Deploy compose stack',
  description:
    'Deploys a new Docker Compose stack on the host (docker compose up -d via SSH). The project name becomes an "app" in the Containers page. Image pulls included — may take several minutes.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000, // image pulls dominate
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, pattern: '^[a-z]([-a-z0-9]*[a-z0-9])?$', description: 'Compose project / app name (lowercase slug)' },
    composeString: { type: 'string', required: true, minLength: 2, description: 'Docker Compose YAML' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    const composeString = str(input, 'composeString');
    if (!name || !composeString) return { success: false, details: { error: 'Project name and compose YAML are required' } };
    if (composeString.includes(COMPOSE_YAML_DELIM)) {
      return { success: false, details: { error: `Compose YAML must not contain the delimiter "${COMPOSE_YAML_DELIM}"` } };
    }

    // Idempotency guard — a compose project with this name already exists.
    try {
      const all = await listContainers(ctx.opts);
      if (all.ok && Array.isArray(all.data)) {
        const existing = (all.data as RawContainer[]).some((c) => c.Labels?.[COMPOSE_PROJECT_LABEL] === name);
        if (existing) return { success: false, details: { error: `A compose project named "${name}" already exists on this host` } };
      }
    } catch { /* best-effort guard — up -d would just update it */ }

    const creds = resolveSshCredentials(ctx.credentials);
    if (!creds) {
      return {
        success: false,
        details: {
          error:
            'No SSH credential bound to this device — bind an ssh secret (username/password or key pair) to the Docker host assignment to deploy compose stacks.',
        },
      };
    }

    // Single remote script: write the YAML to a temp dir, run `docker compose up -d`
    // under the project name, tail the output, clean up. The quoted heredoc keeps
    // the YAML byte-exact (no shell expansion); the slug pattern makes `name` safe.
    const script = [
      'set -u',
      'd=$(mktemp -d) || exit 97',
      `cat > "$d/docker-compose.yml" <<'${COMPOSE_YAML_DELIM}'`,
      composeString.replace(/\n$/, ''),
      COMPOSE_YAML_DELIM,
      'cd "$d"',
      'if ! docker compose version >/dev/null 2>&1; then echo "ERROR: docker compose CLI not available on host (need Compose v2)"; rm -rf "$d"; exit 96; fi',
      `out=$(docker compose -f docker-compose.yml up -d --project-name ${name} 2>&1); rc=$?`,
      'echo "$out" | tail -n 40',
      'rm -rf "$d"',
      'exit $rc',
    ].join('\n');

    const host = sshHostOf(ctx.opts.host);
    try {
      // Long budget — image pulls dominate; the pool keeps the session warm after.
      // The budget MUST ride on the exec call itself: a pooled session created by
      // an earlier short-budget caller would otherwise cap this at its creation-time value.
      const client = await sshPool.get(host, 22, creds, { timeoutMs: 570_000 });
      const r = await client.exec(script, creds, 570_000);
      if (r.code !== 0) {
        return { success: false, details: { error: `docker compose up failed (exit ${r.code}): ${(r.stderr || r.stdout).slice(-800)}` } };
      }
      return { success: true, applied: true, details: { name, note: 'Compose stack deployed — containers appear in the next inventory poll.' } };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/timed out/i.test(msg)) {
        return { success: true, applied: true, details: { name, note: 'Deploy dispatched — the SSH session timed out while images pulled; check the host.' } };
      }
      throw e;
    }
  },
};

// --- containers.run-image ------------------------------------------------------
// Runs a SINGLE image as a standalone container via the Engine API (pull +
// create + start) — NO SSH needed, works over tcp/tls/socket like every other
// action here. The new container becomes a single-container "app" row on the
// Containers page (rows.ts groups by compose project; standalones are their own app).
const PULL_TIMEOUT_MS = 570_000; // image pulls dominate

/** Splits an image reference into { repo, tag } — handles registries with ports
 *  and digest refs ("registry:5000/x/y@sha256:…" keeps the whole ref as repo). */
function splitImageRef(ref: string): { fromImage: string; tag?: string } {
  if (ref.includes('@')) return { fromImage: ref }; // digest — pass through verbatim
  const lastColon = ref.lastIndexOf(':');
  const lastSlash = ref.lastIndexOf('/');
  if (lastColon > lastSlash) {
    return { fromImage: ref.slice(0, lastColon), tag: ref.slice(lastColon + 1) };
  }
  return { fromImage: ref, tag: 'latest' };
}

const containersRunImageAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.run-image',
  label: 'Run image (single container)',
  description:
    'Pulls a docker image and runs it as a standalone container (docker run equivalent via the Engine API — no SSH needed). Optional port mappings and environment variables.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000, // image pulls dominate
  // Flapping guard — create+start is NOT idempotent (a partial success leaks a
  // container; a re-dispatch would hit the name-exists guard and fail anyway).
  retryOnDispatchFailure: false,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, pattern: '^[a-z]([-a-z0-9]*[a-z0-9])?$', description: 'Container / app name (lowercase slug)' },
    image: { type: 'string', required: true, minLength: 2, description: 'Image reference (e.g. "nginx:latest", "ghcr.io/org/app:v1")' },
    ports: {
      type: 'array',
      required: false,
      items: {
        type: 'object',
        properties: {
          hostPort: { type: 'number', required: true, min: 1, max: 65535 },
          containerPort: { type: 'number', required: true, min: 1, max: 65535 },
          protocol: { type: 'string', enum: ['tcp', 'udp'] },
        },
      },
      description: 'Optional host→container port mappings',
    },
    env: { type: 'object', required: false, properties: {}, description: 'Optional environment variables (key → value)' },
    volumes: {
      type: 'array',
      required: false,
      items: {
        type: 'object',
        properties: {
          source: { type: 'string', required: true, minLength: 1, description: 'Host path (bind) or named volume' },
          target: { type: 'string', required: false, description: 'Container path (default: the source path)' },
          mode: { type: 'string', enum: ['ro', 'rw'], description: 'Mount mode (default rw)' },
        },
      },
      description: 'Optional volume mounts (host path or named volume → container path)',
    },
    network: { type: 'string', required: false, minLength: 1, description: 'Optional docker network to attach the container to (default: bridge)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    const image = str(input, 'image');
    if (!name || !image) return { success: false, details: { error: 'Container name and image reference are required' } };

    // Idempotency guard — a container with this exact name already exists.
    try {
      const all = await listContainers(ctx.opts);
      if (all.ok && Array.isArray(all.data)) {
        const existing = (all.data as RawContainer[]).some((c) => nameOf(c) === name || c.Labels?.[COMPOSE_PROJECT_LABEL] === name);
        if (existing) return { success: false, details: { error: `A container or compose project named "${name}" already exists on this host` } };
      }
    } catch { /* best-effort guard — create would 409 anyway */ }

    // 1) Pull the image (streamed progress; wait for completion). Streaming
    // variant — /images/create answers with NDJSON lines, not a JSON document.
    const { fromImage, tag } = splitImageRef(image);
    const pullPath = `/images/create?fromImage=${encodeURIComponent(fromImage)}${tag ? `&tag=${encodeURIComponent(tag)}` : ''}`;
    const pull = await pullImageStream(ctx.opts, pullPath, PULL_TIMEOUT_MS);
    if (!pull.ok) {
      return { success: false, details: { error: `Image pull failed (${image}): ${pull.error || 'pull failed'}` } };
    }

    // 2) Create the container.
    const portsRaw = Array.isArray(input['ports']) ? (input['ports'] as Record<string, unknown>[]) : [];
    const portBindings: Record<string, { HostPort: string }[]> = {};
    const exposedPorts: Record<string, Record<string, never>> = {};
    for (const p of portsRaw) {
      const hostPort = Number(p['hostPort']);
      const containerPort = Number(p['containerPort']);
      if (!Number.isInteger(hostPort) || !Number.isInteger(containerPort)) continue;
      const proto = p['protocol'] === 'udp' ? 'udp' : 'tcp';
      const key = `${containerPort}/${proto}`;
      exposedPorts[key] = {};
      portBindings[key] = [{ HostPort: String(hostPort) }];
    }
    const envRaw = input['env'] && typeof input['env'] === 'object' ? (input['env'] as Record<string, unknown>) : {};
    const env = Object.entries(envRaw)
      .filter(([, v]) => typeof v === 'string')
      .map(([k, v]) => `${k}=${v}`);

    // Volume mounts → Engine Binds ("source:target[:ro|rw]"). Named volumes are
    // passed through as-is; the engine resolves them. Host paths must exist on
    // the host — a missing bind path is created by docker, matching `docker run`.
    const volsRaw = Array.isArray(input['volumes']) ? (input['volumes'] as Record<string, unknown>[]) : [];
    const binds: string[] = [];
    for (const v of volsRaw) {
      const source = typeof v['source'] === 'string' && v['source'].trim() !== '' ? v['source'].trim() : null;
      if (!source) continue;
      const target = typeof v['target'] === 'string' && v['target'].trim() !== '' ? v['target'].trim() : source;
      const mode = v['mode'] === 'ro' ? ':ro' : ''; // rw is the default — omit it
      binds.push(`${source}:${target}${mode}`);
    }
    const network = typeof input['network'] === 'string' && input['network'].trim() !== '' ? input['network'].trim() : undefined;

    const createBody: Record<string, unknown> = {
      Image: image,
      ...(env.length > 0 ? { Env: env } : {}),
      HostConfig: {
        RestartPolicy: { Name: 'unless-stopped' },
        ...(Object.keys(portBindings).length > 0 ? { PortBindings: portBindings } : {}),
        ...(binds.length > 0 ? { Binds: binds } : {}),
        ...(network ? { NetworkMode: network } : {}),
      },
    };
    const created = await dockerRequest<{ Id?: string; Warnings?: string[] }>(ctx.opts, 'POST', `/containers/create?name=${encodeURIComponent(name)}`, createBody);
    if (!created.ok || !created.data?.Id) {
      return { success: false, details: { error: `Container create failed (${name}): ${created.error || JSON.stringify(created.data ?? {})}` } };
    }

    // 3) Start it.
    const started = await dockerPost<unknown>(ctx.opts, `/containers/${encodeURIComponent(created.data.Id)}/start`);
    if (!started.ok && started.status !== 304) {
      return { success: false, details: { error: `Container start failed (${name}): ${started.error || `HTTP ${started.status}`}`, containerId: created.data.Id } };
    }

    return {
      success: true,
      applied: true,
      details: { name, image, containerId: created.data.Id, note: 'Container running — it appears in the next inventory poll.' },
    };
  },
};

// --- images.delete ------------------------------------------------------------
const imagesDeleteAction: ActionDescriptor<DockerActionContext> = {
  id: 'images.delete',
  label: 'Delete image(s)',
  description:
    'DELETES the selected docker images (docker rmi). Images still in use by a container fail unless force is implied; dangling/unused ones are removed.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    ids: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Image names/tags or sha256 ids to delete' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const ids = strArray(input, 'ids');
    if (ids.length === 0) return { success: false, details: { error: 'No image ids provided' } };

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedIds: string[] = [];
    for (const id of ids) {
      // The Engine API accepts a tag OR a sha256 id in the path. A short/long
      // sha is passed through verbatim; anything else is treated as a name:tag.
      const r = await dockerDelete<unknown>(ctx.opts, `/images/${encodeURIComponent(id)}`);
      if (r.ok || r.status === 304) deleted++;
      else if (r.status === 404) missing.push(id);
      else { errors[id] = r.error || `HTTP ${r.status}`; continue; }
    }
    // Verify: every deleted id must be gone from /images/json (tag match or sha prefix).
    const wait = await pollUntil(
      async () => {
        const all = await listImages(ctx.opts);
        if (!all.ok || !Array.isArray(all.data)) return null;
        const images = all.data as Record<string, unknown>[];
        return ids.every((id) => {
          const sha = id.startsWith('sha256:') ? id.slice(7) : /^[0-9a-f]{12,}$/i.test(id) ? id : null;
          return !images.some((img) => {
            const tags = Array.isArray(img['RepoTags']) ? (img['RepoTags'] as string[]) : [];
            if (tags.includes(id)) return true;
            const imgId = typeof img['Id'] === 'string' ? (img['Id'] as string).replace(/^sha256:/, '') : '';
            return sha !== null && imgId.startsWith(sha.slice(0, 12));
          });
        });
      },
      (gone) => gone === true,
      { timeoutMs: 30_000, intervalMs: 1_500 },
    );
    if (!wait.ok && deleted > 0) unverifiedIds.push(...ids.filter((id) => !missing.includes(id)));
    return { success: Object.keys(errors).length === 0, applied: true, verified: unverifiedIds.length === 0, details: { deleted, missing, ...(unverifiedIds.length ? { unverified: unverifiedIds } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

/**
 * Demuxes the Docker Engine log stream. With BOTH stdout+stderr requested the
 * daemon multiplexes: each frame = 8-byte header (stream-type byte + 3-byte
 * zero pad + uint32 BE payload length) + payload, and frames may be split or
 * coalesced across TCP chunks — so we walk a cursor over the buffer. A body
 * that does NOT start with a valid header is treated as plain text (single
 * stream / older daemons). Returns interleaved lines tagged [out]/[err].
 */
function demuxDockerLogs(buf: Buffer): string {
  if (buf.length === 0) return '';
  // Plain-text heuristic: first byte must be a known stream type (1=stdout, 2=stderr).
  const looksMultiplexed = buf.length >= 8 && (buf[0] === 1 || buf[0] === 2);
  if (!looksMultiplexed) return buf.toString('utf8').replace(/\n$/, '');

  let cursor = 0;
  const out: string[] = [];
  while (cursor + 8 <= buf.length) {
    const streamType = buf[cursor]; // 1=stdout, 2=stderr
    if (streamType !== 1 && streamType !== 2) break; // not a frame — stop demuxing
    const len = buf.readUInt32BE(cursor + 4);
    if (cursor + 8 + len > buf.length) {
      // Truncated final frame (daemon cut the stream mid-frame) — take what's left.
      out.push(buf.slice(cursor + 8).toString('utf8'));
      break;
    }
    const payload = buf.slice(cursor + 8, cursor + 8 + len);
    if (payload.length > 0) {
      // Tag stderr lines so the webapp can tint them; stdout stays untagged.
      out.push(streamType === 2 ? `[err] ${payload.toString('utf8')}` : payload.toString('utf8'));
    }
    cursor += 8 + len;
  }
  return out.join('').replace(/\n$/, '');
}

// --- containers.logs.read -----------------------------------------------------
const containersLogsReadAction: ActionDescriptor<DockerActionContext> = {
  id: 'containers.logs.read',
  label: 'Read container logs',
  description: 'Returns the recent log output of a single app\'s container(s) via the Engine API (GET /containers/{id}/logs). No SSH needed.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App / container name to read the logs of' },
    tail: { type: 'number', required: false, min: 20, max: 5000, default: 300, description: 'Number of trailing log lines (default 300)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Container/app name is required' } };
    const tailRaw = typeof input['tail'] === 'number' ? Math.floor(input['tail']) : 300;
    const tail = Math.min(5000, Math.max(20, Number.isFinite(tailRaw) ? tailRaw : 300));

    // Resolve the app to its member containers (compose project OR standalone).
    const members = await resolveMembers(ctx.opts, name);
    if (!members || members.length === 0) {
      return { success: false, details: { error: `No container found for "${name}"` } };
    }

    // Fetch each member's log stream (bounded by tail). Parallel — independent.
    const results = await Promise.all(members.map(async (m) => {
      const r = await containerLogsRaw(ctx.opts, nameOf(m), { tail });
      if (!r.ok) return { id: m.Id ?? '', name: nameOf(m), state: m.State ?? 'unknown', error: r.error || `HTTP ${r.status}`, logs: '' };
      return { id: m.Id ?? '', name: nameOf(m), state: m.State ?? 'unknown', error: undefined as string | undefined, logs: demuxDockerLogs(r.data) };
    }));

    const failed = results.filter((x) => x.error);
    if (results.length > 0 && failed.length === results.length) {
      return { success: false, details: { error: `Could not read logs for "${name}": ${failed[0].error}` } };
    }
    return {
      success: true,
      details: {
        name,
        tail,
        containers: results.map((x) => ({ id: x.id.slice(0, 12), service: x.name, state: x.state, logs: x.logs, ...(x.error ? { error: x.error } : {}) })),
      },
    };
  },
};

// --- Image management (pull / update / prune) ------------------------------------
// The generic contract the Containers page image panel is built on — same action
// ids + input shapes as the Generic SSH plugin's docker-over-SSH implementation.

/** Validates an image reference for safe embedding in a URL path/query. */
function isValidImageRef(ref: string): boolean {
  return ref.length > 0 && ref.length <= 512 && /^[a-zA-Z0-9_./:@\-]+$/.test(ref);
}

// --- images.pull ------------------------------------------------------------------
const imagesPullAction: ActionDescriptor<DockerActionContext> = {
  id: 'images.pull',
  label: 'Pull image(s)',
  description:
    'Pulls docker image references into the local store (POST /images/create). Existing tags are refreshed to the registry version; new ones are downloaded. May take several minutes for large images.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: PULL_TIMEOUT_MS,
  inputSchema: {
    refs: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to pull (e.g. "nginx:latest", "ghcr.io/org/app:v1")' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const refs = strArray(input, 'refs');
    if (refs.length === 0) return { success: false, details: { error: 'No image references provided' } };
    for (const ref of refs) {
      if (!isValidImageRef(ref)) return { success: false, details: { error: `Invalid image reference "${ref}"` } };
    }

    // One pull per ref — sequential so a single huge image cannot starve the rest.
    const pulled: string[] = [];
    const errors: Record<string, string> = {};
    for (const ref of refs) {
      const { fromImage, tag } = splitImageRef(ref);
      const pullPath = `/images/create?fromImage=${encodeURIComponent(fromImage)}${tag ? `&tag=${encodeURIComponent(tag)}` : ''}`;
      // Streaming variant — /images/create answers with NDJSON progress lines,
      // which the generic JSON helper rejects on socket transport.
      const r = await pullImageStream(ctx.opts, pullPath, PULL_TIMEOUT_MS);
      if (r.ok) pulled.push(ref);
      else errors[ref] = r.error || 'pull failed';
    }
    return { success: Object.keys(errors).length === 0, applied: true, verified: Object.keys(errors).length === 0, details: { pulled, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- images.update ----------------------------------------------------------------
const imagesUpdateAction: ActionDescriptor<DockerActionContext> = {
  id: 'images.update',
  label: 'Update image(s)',
  description:
    'Re-pulls the given image references (refreshing them to the registry version) and — by default — restarts every RUNNING container that uses one of those refs so it picks up the new version. Set restart=false to only refresh the local store.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: PULL_TIMEOUT_MS + 60_000, // pulls + graceful restarts
  inputSchema: {
    refs: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to update (e.g. "nginx:latest")' },
    restart: { type: 'boolean', required: false, default: true, description: 'Restart running containers that use the updated images (default true)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const refs = strArray(input, 'refs');
    if (refs.length === 0) return { success: false, details: { error: 'No image references provided' } };
    for (const ref of refs) {
      if (!isValidImageRef(ref)) return { success: false, details: { error: `Invalid image reference "${ref}"` } };
    }
    const restart = input['restart'] !== false; // default true

    // 1) Refresh the local store.
    const pullRes = await imagesPullAction.execute(ctx, { refs });
    if (!pullRes.success) return { success: false, details: { error: `Image update failed: ${pullRes.error ?? 'pull errors'}` } };
    const pulled = Array.isArray((pullRes.details as Record<string, unknown> | undefined)?.['pulled']) ? (pullRes.details as Record<string, unknown>)['pulled'] as string[] : [];

    if (!restart) {
      return { success: true, applied: true, verified: true, details: { updated: pulled, restarted: [], note: 'Images refreshed — no containers were restarted (restart=false).' } };
    }

    // 2) Find every RUNNING container whose image matches one of the refs. ONE
    // pass over /containers/json?all=true&limit=500 — each entry's `Image` field is
    // exactly the ref string used at creation, so a tag update ("nginx:latest")
    // matches containers started from that same ref. Digest-pinned / short-id
    // creations are not matched — they must be restarted manually.
    const list = await listContainers(ctx.opts);
    if (!list.ok || !Array.isArray(list.data)) {
      return { success: true, applied: true, verified: false, details: { updated: pulled, restarted: [], note: 'Images refreshed — could not read the container list to restart users.' } };
    }

    const matched = (list.data as RawContainer[]).filter((c) => c.State === 'running' && typeof c.Image === 'string' && refs.includes(c.Image));

    let restarted: string[] = [];
    const errors: Record<string, string> = {};
    if (matched.length > 0) {
      // Restart in parallel — each op is independent.
      const results = await Promise.all(matched.map(async (m) => {
        const r = await drive(ctx.opts, m.Id ?? nameOf(m), 'restart');
        return { id: m.Id ?? '', name: nameOf(m), ...r };
      }));
      for (const x of results) {
        if (x.ok) restarted.push(x.name);
        else errors[x.name] = x.error ?? 'restart failed';
      }

      // Verify: every restarted container must be running again.
      const v = await verifyStates(ctx.opts, matched, new Set(['running']));
      if (!v.ok) {
        for (const [n, s] of Object.entries(v.after)) {
          if (s !== 'running') errors[`verify:${n}`] = `container is ${s} after restart`;
        }
      }
    }

    return { success: Object.keys(errors).length === 0, applied: true, verified: Object.keys(errors).length === 0, details: { updated: pulled, restarted, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

// --- images.prune -----------------------------------------------------------------
const imagesPruneAction: ActionDescriptor<DockerActionContext> = {
  id: 'images.prune',
  label: 'Prune unused images',
  description:
    'Removes UNUSED docker images (POST /images/prune). With all=false only dangling (<none>) layers are removed; with all=true every image no container references is removed — including stopped containers\' images. DESTRUCTIVE for the local store.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    all: { type: 'boolean', required: false, default: false, description: 'Prune ALL unused images (not just dangling). Default false.' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const all = input['all'] === true;
    // The Engine API's prune endpoint returns { ImagesDeleted: [...], SpaceReclaimed: bytes }.
    const r = await dockerRequest<{ ImagesDeleted?: string[]; SpaceReclaimed?: number }>(ctx.opts, 'POST', `/images/prune?all=${all ? 'true' : 'false'}`);
    if (!r.ok) return { success: false, details: { error: `Image prune failed: ${r.error || `HTTP ${r.status}`}` } };
    const deleted = Array.isArray(r.data?.ImagesDeleted) ? r.data.ImagesDeleted.length : 0;
    const freedBytes = typeof r.data?.SpaceReclaimed === 'number' ? r.data.SpaceReclaimed : null;
    return { success: true, applied: true, verified: true, details: { all, deleted, freedBytes } };
  },
};

// --- containers.image.set -----------------------------------------------------
// Canonical fleet intent (SDK INTENT_CONTAINERS_IMAGE_SET): point one or more
// containers at a different image — a tag bump ("app:v1.4.2" → "app:v1.4.3") or
// an entirely different image ("redis:7" → "valkey:8"). The Engine API has no
// compose-file access, so the change is applied by RECREATING each matched
// container with its full configuration copied from `inspect` and only the
// Image swapped — env, labels (incl. compose project/service), ports, binds,
// volumes, restart policy, hostname/user/cmd/entrypoint and network attachments
// (incl. static IPs + aliases) all survive. Recreations run SEQUENTIALLY: a
// replacement may only attach to a user-defined network once the old container
// has released its static IP. Compose members are ordered by `depends_on` so
// dependencies come up first.
//
// Honest limitation (documented in the action description + docs/INTENTS.md):
// this changes what is RUNNING, not the compose file on disk — a later manual
// `docker compose up -d` would revert to the file's image refs.

const COMPOSE_SERVICE_LABEL = 'com.docker.compose.service';
const COMPOSE_DEPENDS_ON_LABEL = 'com.docker.compose.depends_on';

/** One image-change mapping as accepted by the canonical intent (defensive parse). */
interface ImageSetMapping {
  /** Optional container/service name scoping the match. */
  name?: string;
  /** Current image ref — the match key. */
  from: string;
  /** New full image ref. */
  to: string;
}

function parseMappings(input: Record<string, unknown>): ImageSetMapping[] {
  const raw = input['mappings'];
  if (!Array.isArray(raw)) return [];
  const out: ImageSetMapping[] = [];
  for (const m of raw) {
    if (!m || typeof m !== 'object') continue;
    const o = m as Record<string, unknown>;
    const from = typeof o['from'] === 'string' ? o['from'].trim() : '';
    const to = typeof o['to'] === 'string' ? o['to'].trim() : '';
    if (from.length < 2 || to.length < 2) continue;
    out.push({ ...(typeof o['name'] === 'string' && o['name'].trim() !== '' ? { name: o['name'].trim() } : {}), from, to });
  }
  return out;
}

/** Pulls one image ref (Engine API). Reuses the deploy/run-image split so
 *  registry ports and digest refs work. Uses the streaming variant — /images/create
 *  answers with NDJSON progress lines, which the generic JSON helper rejects on
 *  socket transport. */
async function pullImageRefDocker(opts: DockerClientOptions, ref: string): Promise<{ ok: boolean; error?: string }> {
  const { fromImage, tag } = splitImageRef(ref);
  const path = `/images/create?fromImage=${encodeURIComponent(fromImage)}${tag ? `&tag=${encodeURIComponent(tag)}` : ''}`;
  return pullImageStream(opts, path, PULL_TIMEOUT_MS);
}

/** One user-defined network attachment of a container (name + static IPs + aliases). */
interface NetAttachment {
  name: string;
  ipv4?: string;
  ipv6?: string;
  aliases?: string[];
}

/** Reads the container's network attachments from its inspect payload. The
 *  default bridge is included when it was actually attached (compose services
 *  on user networks are NOT — that drives the exact-topology restore below). */
function networkAttachments(insp: Record<string, unknown>): NetAttachment[] {
  const ns = insp['NetworkSettings'];
  if (!ns || typeof ns !== 'object' || Array.isArray(ns)) return [];
  const nets = (ns as Record<string, unknown>)['Networks'];
  if (!nets || typeof nets !== 'object' || Array.isArray(nets)) return [];
  const out: NetAttachment[] = [];
  for (const [netName, v] of Object.entries(nets as Record<string, unknown>)) {
    if (!v || typeof v !== 'object') continue;
    // 'host' is a pseudo-network with no IPAM — nothing to re-attach.
    if (netName === 'host') continue;
    const n = v as Record<string, unknown>;
    const ipam = (n['IPAMConfig'] ?? {}) as Record<string, unknown>;
    out.push({
      name: netName,
      ipv4: typeof ipam['IPv4Address'] === 'string' && ipam['IPv4Address'] !== '' ? ipam['IPv4Address'] : undefined,
      ipv6: typeof ipam['IPv6Address'] === 'string' && ipam['IPv6Address'] !== '' ? ipam['IPv6Address'] : undefined,
      aliases: Array.isArray(n['Aliases']) ? (n['Aliases'] as unknown[]).filter((a): a is string => typeof a === 'string') : undefined,
    });
  }
  return out;
}

/** Builds the POST /containers/create body for a replacement container — the
 *  original's full Config + HostConfig with only the Image swapped. Inspect-only
 *  fields (Mounts, AutoRemove…) are dropped; special NetworkModes (host/none/
 *  container:/ns:) pass through, everything else is created on the default
 *  bridge and re-attached explicitly so static IPs survive. */
function buildCreateBody(insp: Record<string, unknown>, newImage: string): Record<string, unknown> {
  const cfg = (insp['Config'] ?? {}) as Record<string, unknown>;
  const hc = (insp['HostConfig'] ?? {}) as Record<string, unknown>;
  const mode = typeof hc['NetworkMode'] === 'string' ? hc['NetworkMode'] : '';

  const body: Record<string, unknown> = { Image: newImage };
  for (const k of ['Hostname', 'Domainname', 'User', 'AttachStdin', 'Tty', 'OpenStdin', 'StdinOnce', 'Env', 'Cmd', 'Healthcheck', 'ArgsEscaped', 'WorkingDir', 'Entrypoint', 'NetworkDisabled', 'MacAddress', 'Labels', 'StopSignal', 'Shell', 'ExposedPorts', 'Volumes']) {
    if (cfg[k] != null) body[k] = cfg[k];
  }

  const host: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(hc)) {
    // Inspect-only / create-invalid fields.
    if (['Mounts', 'AutoRemove', 'Networks', 'RestartCount'].includes(k)) continue;
    host[k] = v;
  }
  // Only special modes pass through — a user-defined network name as mode is
  // handled by the explicit connect step (which also restores static IPs).
  if (mode === 'host' || mode === 'none' || mode.startsWith('container:') || mode.startsWith('ns:')) {
    host['NetworkMode'] = mode;
  } else {
    delete host['NetworkMode']; // default bridge at create time
  }
  body['HostConfig'] = host;
  return body;
}

/** Recreates ONE container on a new image, preserving its full configuration.
 *  Sequence: inspect → create (temp name) → stop+remove old (frees static IPs)
 *  → re-attach networks (static IPs + aliases) → restore exact topology →
 *  rename back to the original name → start when it was running. */
async function recreateWithImage(opts: DockerClientOptions, c: RawContainer, newImage: string): Promise<{ ok: boolean; error?: string }> {
  const name = nameOf(c);
  // /json is the canonical inspect path — some daemon builds (observed on
  // Engine 29.x, API 1.56) answer the /inspect alias with a bare 404.
  const insp = await dockerGet<Record<string, unknown>>(opts, `/containers/${encodeURIComponent(name)}/json`);
  if (!insp.ok || !insp.data) return { ok: false, error: `could not inspect ${name}: ${insp.error ?? `HTTP ${insp.status}`}` };

  const wasRunning = (c.State ?? '') === 'running';
  const tempName = `${name}-unm-imgset`;
  // Defensive cleanup of a leftover from an earlier interrupted run.
  await dockerDelete<unknown>(opts, `/containers/${encodeURIComponent(tempName)}?force=true&v=false`);

  const created = await dockerRequest<{ Id?: string }>(opts, 'POST', `/containers/create?name=${encodeURIComponent(tempName)}`, buildCreateBody(insp.data, newImage));
  if (!created.ok || !created.data?.Id) {
    return { ok: false, error: `create failed for ${name}: ${created.error ?? JSON.stringify(created.data ?? {})}` };
  }
  const newId = created.data.Id;

  // Free the original name + its network resources. Graceful stop first when
  // running (apps get a chance to flush state), then force-remove. v=false —
  // named volumes are NEVER touched by an image change.
  if (wasRunning) await dockerPost<unknown>(opts, `/containers/${encodeURIComponent(name)}/stop?t=4`);
  const del = await dockerDelete<unknown>(opts, `/containers/${encodeURIComponent(name)}?force=true&v=false`);
  if (!del.ok && del.status !== 304) return { ok: false, error: `could not remove old container ${name}: ${del.error ?? `HTTP ${del.status}`}` };

  // Re-attach every user-defined network with its static IPs + aliases.
  const attachments = networkAttachments(insp.data);
  for (const n of attachments) {
    const ipam: Record<string, unknown> = {};
    if (n.ipv4) ipam['IPv4Address'] = n.ipv4;
    if (n.ipv6) ipam['IPv6Address'] = n.ipv6;
    const connBody: Record<string, unknown> = { Container: newId };
    if (Object.keys(ipam).length > 0 || (n.aliases?.length ?? 0) > 0) {
      connBody['IPAMConfig'] = { ...ipam, ...(n.aliases && n.aliases.length > 0 ? { Aliases: n.aliases } : {}) };
    }
    const r = await dockerRequest<unknown>(opts, 'POST', `/networks/${encodeURIComponent(n.name)}/connect`, connBody);
    if (!r.ok) return { ok: false, error: `could not attach ${name} to network ${n.name}: ${r.error ?? `HTTP ${r.status}`}` };
  }

  // Restore the EXACT topology — the create step always lands on the default
  // bridge; drop it when the original was not attached there (compose services
  // on user-defined networks).
  const hadBridge = attachments.some((n) => n.name === 'bridge');
  if (!hadBridge && !attachments.some((n) => n.name === 'host')) {
    await dockerRequest<unknown>(opts, 'POST', '/networks/bridge/disconnect', { Container: newId }); // best-effort
  }

  const ren = await dockerRequest<unknown>(opts, 'POST', `/containers/${encodeURIComponent(newId)}/rename?name=${encodeURIComponent(name)}`);
  if (!ren.ok) return { ok: false, error: `could not rename replacement to ${name}: ${ren.error ?? `HTTP ${ren.status}`}` };

  if (wasRunning) {
    const st = await dockerPost<unknown>(opts, `/containers/${encodeURIComponent(name)}/start`);
    if (!st.ok && st.status !== 304) return { ok: false, error: `could not start ${name}: ${st.error ?? `HTTP ${st.status}`}` };
  }
  return { ok: true };
}

/** Waits until the container under `name` runs on `ref` (and is running when
 *  expected). Returns false on timeout — the caller reports "unverified". */
async function verifyImage(opts: DockerClientOptions, name: string, ref: string, wantRunning: boolean): Promise<boolean> {
  const wait = await pollUntil(
    async () => {
      const all = await listContainers(opts);
      if (!all.ok || !Array.isArray(all.data)) return null; // transient — keep polling
      const c = (all.data as RawContainer[]).find((x) => nameOf(x) === name);
      if (!c) return false;
      return c.Image === ref && (!wantRunning || c.State === 'running');
    },
    (ok) => ok === true,
    { timeoutMs: 60_000, intervalMs: 2_000 },
  );
  return wait.ok;
}

/** One resolved recreation target. */
interface ImageSetTarget {
  mapping: ImageSetMapping;
  container: RawContainer;
}

/** Orders targets so compose services are recreated AFTER their `depends_on`
 *  dependencies (labels carry the service name + comma-separated deps, possibly
 *  with conditions like "db:service_healthy"). Cycles fall back to original order. */
function orderByDependencies(targets: ImageSetTarget[]): ImageSetTarget[] {
  const byService = new Map<string, number>();
  targets.forEach((t, i) => {
    const s = t.container.Labels?.[COMPOSE_SERVICE_LABEL];
    if (s && !byService.has(s)) byService.set(s, i);
  });
  const depsOf = (i: number): number[] => {
    const raw = targets[i].container.Labels?.[COMPOSE_DEPENDS_ON_LABEL];
    if (!raw) return [];
    const out: number[] = [];
    for (const part of String(raw).split(',')) {
      const depSvc = part.split(':')[0]?.trim();
      if (!depSvc) continue;
      const j = byService.get(depSvc);
      if (j !== undefined && j !== i) out.push(j);
    }
    return out;
  };
  const placed = new Array(targets.length).fill(false);
  const result: ImageSetTarget[] = [];
  let remaining = targets.length;
  while (remaining > 0) {
    let progress = false;
    for (let i = 0; i < targets.length && remaining > 0; i++) {
      if (placed[i]) continue;
      const pendingDeps = depsOf(i).filter((j) => !placed[j]);
      if (pendingDeps.length === 0) {
        placed[i] = true;
        result.push(targets[i]);
        remaining--;
        progress = true;
      }
    }
    if (!progress) { // dependency cycle — append the rest in original order
      for (let i = 0; i < targets.length; i++) if (!placed[i]) { placed[i] = true; result.push(targets[i]); remaining--; }
      break;
    }
  }
  return result;
}

const containersImageSetAction: ActionDescriptor<DockerActionContext> = {
  id: INTENT_CONTAINERS_IMAGE_SET,
  label: 'Change container image(s)',
  description:
    'Points the selected containers at a different image — a tag bump (e.g. "app:v1.4.2" → "app:v1.4.3") or an entirely new image ("redis:7" → "valkey:8"). Each matched container is RECREATED via the Engine API with its full configuration preserved (env, labels, ports, volumes, restart policy, static IPs); named volumes are never touched and stopped containers stay stopped. Idempotent — a container already on the target ref is skipped. Note: this changes what is running, not any compose file on disk.',
  module: 'Containers',
  riskLevel: 'write' as const,
  // Single-device action (one step per device) — registered in CANONICAL_INTENTS
  // so the plan API fans it out across a batch like every other fleet intent.
  deviceCount: 1 as const,
  timeoutMs: 900_000, // image pulls dominate
  inputSchema: {
    mappings: {
      type: 'array',
      required: true,
      items: {
        type: 'object',
        properties: {
          name: { type: 'string', required: false, minLength: 1, maxLength: 200, description: 'Optional container/service name to scope the match (omit = every service using `from`)' },
          from: { type: 'string', required: true, minLength: 2, maxLength: 512, description: 'Current image reference of the container(s) to change' },
          to: { type: 'string', required: true, minLength: 2, maxLength: 512, description: 'New full image reference (tag bump or a different image entirely)' },
        },
      },
      description: 'Image changes to apply on this device — one entry per container/service',
    },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const mappings = parseMappings(input);
    if (mappings.length === 0) return { success: false, details: { error: 'No image mappings provided' } };

    // 1) Resolve every mapping against the live container list.
    const all = await listContainers(ctx.opts);
    if (!all.ok || !Array.isArray(all.data)) return { success: false, details: { error: `Could not read the container list: ${all.error ?? 'unknown'}` } };
    const containers = all.data as RawContainer[];

    const targets: ImageSetTarget[] = [];
    const missing: Record<string, string> = {};
    for (const m of mappings) {
      const key = `${m.from} → ${m.to}${m.name ? ` (${m.name})` : ''}`;
      const hits = containers.filter((c) => c.Image === m.from && (!m.name || nameOf(c) === m.name));
      if (hits.length === 0) { missing[key] = `no container with image ${m.from}${m.name ? ` named "${m.name}"` : ''} found`; continue; }
      for (const c of hits) targets.push({ mapping: m, container: c });
    }

    // Idempotent skip — already on the target ref.
    const toApply: ImageSetTarget[] = [];
    const skipped: Record<string, string> = {};
    const seenIds = new Set<string>();
    for (const t of targets) {
      const id = t.container.Id ?? nameOf(t.container);
      if (seenIds.has(id)) continue; // duplicate mapping hit the same container — first wins
      seenIds.add(id);
      if ((t.container.Image ?? '') === t.mapping.to) skipped[nameOf(t.container)] = `already running ${t.mapping.to}`;
      else toApply.push(t);
    }

    const errors: Record<string, string> = {};
    if (toApply.length > 0) {
      // 2) Pull every distinct new ref once (sequential — one huge image must not starve the rest).
      for (const ref of [...new Set(toApply.map((t) => t.mapping.to))]) {
        const p = await pullImageRefDocker(ctx.opts, ref);
        if (!p.ok) errors[ref] = `image pull failed: ${p.error}`;
      }

      // 3) Recreate SEQUENTIALLY (static IPs must be released before the
      // replacement attaches), dependencies first.
      const unverifiedNames: string[] = [];
      let changed = 0;
      for (const t of orderByDependencies(toApply)) {
        if (errors[t.mapping.to]) continue; // pull failed — nothing to recreate with
        const name = nameOf(t.container);
        const r = await recreateWithImage(ctx.opts, t.container, t.mapping.to);
        if (!r.ok) { errors[name] = r.error!; continue; }
        changed++;
        const verified = await verifyImage(ctx.opts, name, t.mapping.to, (t.container.State ?? '') === 'running');
        if (!verified) unverifiedNames.push(name);
      }

      return {
        success: Object.keys(errors).length === 0,
        applied: true,
        verified: unverifiedNames.length === 0,
        details: { changed, skipped, missing, ...(unverifiedNames.length > 0 ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length > 0 ? { errors } : {}) },
      };
    }

    // Nothing to apply — every match was already on its target ref (or absent).
    return { success: Object.keys(missing).length === 0, verified: true, details: { changed: 0, skipped, missing } };
  },
};

export const registry = createRegistry<DockerActionContext>([
  containersStartAction,
  containersStopAction,
  containersRestartAction,
  containersDeleteAction,
  // Per-container (single member) variants — exact docker-name resolution only.
  containersStartOneAction,
  containersStopOneAction,
  containersRestartOneAction,
  containersDeleteOneAction,
  containersRunImageAction,
  containersDeployComposeAction,
  imagesDeleteAction,
  imagesPullAction,
  imagesUpdateAction,
  imagesPruneAction,
  containersLogsReadAction,
  containersImageSetAction,
]);
