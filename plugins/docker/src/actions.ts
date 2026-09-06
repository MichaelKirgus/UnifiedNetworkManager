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

import { ActionDescriptor, ActionResult, createRegistry } from '@unm/plugin-sdk';
import { DockerClientOptions, dockerDelete, dockerPost, listComposeMembers, listContainers } from './client';

/** Executor context for one /config step — just the resolved client options. */
export interface DockerActionContext {
  opts: DockerClientOptions;
}

const COMPOSE_PROJECT_LABEL = 'com.docker.compose.project';

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
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx.opts, members, 'start');
      if (r.ok) started++; else errors[n] = r.error!;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx.opts, members, 'stop');
      if (r.ok) stopped++; else errors[n] = r.error!;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { stopped, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const members = await resolveMembers(ctx.opts, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      // A stopped container can't be restarted — start it instead. Run all
      // members in parallel so a multi-service app stays under budget.
      const results = await Promise.all(members.map((m) => drive(ctx.opts, nameOf(m), m.State === 'running' ? 'restart' : 'start')));
      const firstError = results.find((r) => !r.ok)?.error;
      if (firstError) errors[n] = firstError; else restarted++;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { restarted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      const r = await drive(ctx.opts, nameOf(c), 'stop');
      if (r.ok) stopped++; else errors[n] = r.error!; // 304 (already stopped) counts as ok inside drive()
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { stopped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      const r = await drive(ctx.opts, nameOf(c), 'start');
      if (r.ok) started++; else errors[n] = r.error!; // 304 (already running) counts as ok inside drive()
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { started, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      // A stopped container can't be restarted — start it instead.
      const r = await drive(ctx.opts, nameOf(c), c.State === 'running' ? 'restart' : 'start');
      if (r.ok) restarted++; else errors[n] = r.error!;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { restarted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const n of names) {
      const c = await resolveExact(ctx.opts, n);
      if (!c) { missing.push(n); continue; }
      // -f forces removal of running containers; v=false keeps named volumes.
      const r = await dockerDelete<unknown>(ctx.opts, `/containers/${encodeURIComponent(nameOf(c))}?force=true&v=false`);
      if (r.ok || r.status === 304) deleted++;
      else errors[n] = r.error || `HTTP ${r.status}`;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
      if (firstError) errors[n] = firstError; else deleted++;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
    for (const id of ids) {
      // The Engine API accepts a tag OR a sha256 id in the path. A short/long
      // sha is passed through verbatim; anything else is treated as a name:tag.
      const r = await dockerDelete<unknown>(ctx.opts, `/images/${encodeURIComponent(id)}`);
      if (r.ok || r.status === 304) deleted++;
      else if (r.status === 404) missing.push(id);
      else errors[id] = r.error || `HTTP ${r.status}`;
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
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
  imagesDeleteAction,
]);
