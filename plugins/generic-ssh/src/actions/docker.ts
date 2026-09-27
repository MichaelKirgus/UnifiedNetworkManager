/**
 * Docker / Docker Compose actions — makes this plugin config-capable for the
 * Containers page on ANY Linux host that runs docker (bare-metal servers, NAS
 * sidecars, …). The transport is the host's `docker` CLI over the pooled,
 * privilege-aware SSH backend — there is no Engine API here.
 *
 * Serves two entry points:
 *   - /discover → listCatalog()  (the catalog the API persists + validates)
 *   - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * The webapp sends APP-level `names[]` for container actions and image `ids[]`
 * for images.delete. An "app" is either a compose PROJECT (label
 * com.docker.compose.project=<name>) or a single standalone container — the
 * same grouping containers.ts uses to build inventory rows, so names line up
 * 1:1 with what the Containers page shows. Idempotent by design: a container
 * already in the target state is skipped, not failed (mirrors plugins/docker).
 *
 * containers.deploy-compose writes the YAML into a USER-CHOSEN working dir on
 * the host (`workdir` input, default /opt/compose/<name>) and runs
 * `COMPOSE_PROJECT_NAME=<name> docker compose up -d` there (the env var pins
 * the project name portably — the --project-name flag needs a newer CLI) — so
 * the stack's files persist where the user wants them (the Docker plugin uses
 * mktemp instead).
 */

import type { ActionContext, ActionDescriptor, ActionResult } from './types';
import { failResult, okResult, shq } from './types';
import {
  COMPOSE_PROJECT_LABEL,
  DEFAULT_COMPOSE_WORKDIR,
  WORKDIR_REGISTRY_DIR,
  containerName,
  isSafeWorkdir,
  isValidAppName,
  resolveMembers,
  resolveWorkdir,
  verifyGone,
  verifyStates,
  workdirRegistryPath,
} from '../containers';
import type { DockerContainerRaw } from '../containers';

/** Engine states that count as "stopped". */
const STOPPED_STATES = new Set(['exited', 'created', 'dead']);

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v : undefined;
}

function strArray(input: Record<string, unknown>, key: string): string[] {
  const v = input[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string' && x.trim() !== '').map((s) => s.trim());
}

/**
 * Drives all member containers of one app to a lifecycle verb in ONE remote
 * script (one SSH round-trip per app). Emits "OK|<name>" / "ERR|<name>|<msg>"
 * lines; docker's exit codes are mapped so an already-in-target-state container
 * is reported OK (idempotent — skipped, not failed).
 */
async function driveMembers(
  ctx: ActionContext,
  members: DockerContainerRaw[],
  verb: 'start' | 'stop' | 'restart',
): Promise<{ ok: boolean; error?: string }> {
  const names = members.map(containerName);
  // stop/restart block for the graceful-stop period before force-killing. Docker's
  // default is 10 s — too long when several apps run sequentially under the API's
  // config-job budget, so we pass a short timeout (4 s). The docker CLI takes it as
  // a FLAG (`docker stop -t 4 <name>`) — appending `?t=4` to the name makes the
  // daemon look for a container literally named "<name>?t=4". start returns immediately.
  // NOTE the trailing space in `t` — without it the flag value and the container
  // name concatenate into one argument ("4unme2e…-web-1").
  const t = verb === 'start' ? '' : '-t 4 ';
  const lines: string[] = ['set -u'];
  for (const n of names) {
    lines.push(`out=$(docker ${verb} ${t}${shq(n)} 2>&1); rc=$?`);
    // docker start/stop/restart exit 0 on success AND when the container is
    // already in the target state — both count as OK here (idempotent).
    lines.push(`if [ $rc -eq 0 ]; then echo "OK|${n}"; else echo "ERR|${n}|$(echo "$out" | tail -c 300)"; fi`);
  }
  const r = await ctx.backend.exec(lines.join('\n'), 120_000);
  if (r.code !== 0 && !r.stdout) {
    return { ok: false, error: `drive script failed (exit ${r.code}): ${(r.stderr || '').slice(-300)}` };
  }
  for (const line of (r.stdout ?? '').split('\n')) {
    if (!line.startsWith('ERR|')) continue;
    const parts = line.split('|');
    return { ok: false, error: `${parts[1]}: ${parts.slice(2).join('|')}` };
  }
  return { ok: true };
}

// --- containers.start ---------------------------------------------------------
const containersStartAction: ActionDescriptor = {
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
    if (names.length === 0) return failResult('No app names provided');

    let started = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.backend, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx, members, 'start');
      if (!r.ok) { errors[n] = r.error!; continue; }
      started++;
      // Verify: the daemon acks a start before it completes — every member must
      // actually be running for this step to count as verified.
      const v = await verifyStates(ctx.backend, members, new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return okResult({ started, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) }, unverifiedNames.length === 0 && Object.keys(errors).length === 0);
  },
};

// --- containers.stop ----------------------------------------------------------
const containersStopAction: ActionDescriptor = {
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
    if (names.length === 0) return failResult('No app names provided');

    let stopped = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.backend, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      const r = await driveMembers(ctx, members, 'stop');
      if (!r.ok) { errors[n] = r.error!; continue; }
      stopped++;
      // Verify: an explicit stop sticks (restart policies only re-fire on daemon
      // start / crash-exit), so every member must end in a stopped state.
      const v = await verifyStates(ctx.backend, members, STOPPED_STATES);
      if (!v.ok) unverifiedNames.push(n);
    }
    return okResult({ stopped, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) }, unverifiedNames.length === 0 && Object.keys(errors).length === 0);
  },
};

// --- containers.restart -------------------------------------------------------
const containersRestartAction: ActionDescriptor = {
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
    if (names.length === 0) return failResult('No app names provided');

    let restarted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.backend, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      // A stopped container can't be restarted — start it instead. One script:
      // each member gets the verb matching its current state (read in the same pass).
      const lines: string[] = ['set -u'];
      for (const m of members) {
        const name = containerName(m);
        lines.push(`st=$(docker inspect --format '{{.State.Status}}' ${shq(name)} 2>/dev/null || echo unknown)`);
        // -t is a FLAG before the name — `name?t=4` would be parsed as part of the container id.
        lines.push(`if [ "$st" = "running" ]; then out=$(docker restart -t 4 ${shq(name)} 2>&1); else out=$(docker start ${shq(name)} 2>&1); fi; rc=$?`);
        lines.push(`if [ $rc -eq 0 ]; then echo "OK|${name}"; else echo "ERR|${name}|$(echo "$out" | tail -c 300)"; fi`);
      }
      const r = await ctx.backend.exec(lines.join('\n'), 120_000);
      if (r.code !== 0 && !r.stdout) { errors[n] = `restart script failed (exit ${r.code})`; continue; }
      let firstError: string | undefined;
      for (const line of (r.stdout ?? '').split('\n')) {
        if (!line.startsWith('ERR|')) continue;
        const parts = line.split('|');
        firstError = `${parts[1]}: ${parts.slice(2).join('|')}`;
        break;
      }
      if (firstError) { errors[n] = firstError; continue; }
      restarted++;
      // Verify: a restart is only done when every member is running again.
      const v = await verifyStates(ctx.backend, members, new Set(['running']));
      if (!v.ok) unverifiedNames.push(n);
    }
    return okResult({ restarted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) }, unverifiedNames.length === 0 && Object.keys(errors).length === 0);
  },
};

// --- containers.delete --------------------------------------------------------
const containersDeleteAction: ActionDescriptor = {
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
    if (names.length === 0) return failResult('No app names provided');

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const unverifiedNames: string[] = [];
    for (const n of names) {
      const members = await resolveMembers(ctx.backend, n);
      if (!members || members.length === 0) { missing.push(n); continue; }
      // -f forces removal of running containers; named volumes are kept.
      const lines: string[] = ['set -u'];
      for (const m of members) {
        const name = containerName(m);
        lines.push(`out=$(docker rm -f ${shq(name)} 2>&1); rc=$?`);
        lines.push(`if [ $rc -eq 0 ]; then echo "OK|${name}"; else echo "ERR|${name}|$(echo "$out" | tail -c 300)"; fi`);
      }
      const r = await ctx.backend.exec(lines.join('\n'), 120_000);
      if (r.code !== 0 && !r.stdout) { errors[n] = `delete script failed (exit ${r.code})`; continue; }
      let firstError: string | undefined;
      for (const line of (r.stdout ?? '').split('\n')) {
        if (!line.startsWith('ERR|')) continue;
        const parts = line.split('|');
        firstError = `${parts[1]}: ${parts.slice(2).join('|')}`;
        break;
      }
      if (firstError) { errors[n] = firstError; continue; }
      deleted++;
      // Verify: every member must be gone from `docker ps -a`.
      const v = await verifyGone(ctx.backend, members);
      if (!v.ok) unverifiedNames.push(n);
    }
    return okResult({ deleted, missing, ...(unverifiedNames.length ? { unverified: unverifiedNames } : {}), ...(Object.keys(errors).length ? { errors } : {}) }, unverifiedNames.length === 0 && Object.keys(errors).length === 0);
  },
};

// --- containers.deploy-compose -------------------------------------------------
// Deploys a NEW compose stack on the host via `docker compose up -d`. The YAML is
// written into a USER-CHOSEN working directory (input `workdir`, default
// /opt/compose/<name>) so the stack's files persist where the user wants them —
// unlike the Docker plugin, which deploys from mktemp and leaves no trace.

const COMPOSE_YAML_DELIM = '__UNM_COMPOSE_YAML_8f3a__';

/** Resolves + validates the working dir for one deploy (default when omitted). */
function workdirOf(input: Record<string, unknown>, name: string): { dir?: string; error?: string } {
  const raw = str(input, 'workdir');
  if (!raw) return { dir: `${DEFAULT_COMPOSE_WORKDIR}/${name}` };
  const dir = raw.replace(/\/+$/, ''); // normalize trailing slashes
  if (!isSafeWorkdir(dir)) {
    return { error: `Invalid working directory "${raw}" — must be an absolute path without shell metacharacters or ".."` };
  }
  return { dir };
}

const containersDeployComposeAction: ActionDescriptor = {
  id: 'containers.deploy-compose',
  label: 'Deploy compose stack',
  description:
    'Deploys a new Docker Compose stack on the host (docker compose up -d). The YAML is saved to the chosen working directory (default /opt/compose/<name>) so it persists for later edits. Image pulls included — may take several minutes.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000, // image pulls dominate
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, pattern: '^[a-z]([-a-z0-9]*[a-z0-9])?$', description: 'Compose project / app name (lowercase slug)' },
    composeString: { type: 'string', required: true, minLength: 2, description: 'Docker Compose YAML' },
    workdir: { type: 'string', required: false, maxLength: 512, description: `Absolute directory on the host where docker-compose.yml is saved (default ${DEFAULT_COMPOSE_WORKDIR}/<name>)` },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    const composeString = str(input, 'composeString');
    if (!name || !composeString) return failResult('Project name and compose YAML are required');
    if (!isValidAppName(name)) return failResult(`Invalid project name "${name}" — use a lowercase slug (a-z, 0-9, "-")`);
    if (composeString.includes(COMPOSE_YAML_DELIM)) {
      return failResult(`Compose YAML must not contain the delimiter "${COMPOSE_YAML_DELIM}"`);
    }

    const wd = workdirOf(input, name);
    if (wd.error) return failResult(wd.error);
    const dir = wd.dir!;

    // Idempotency guard — a compose project with this name already exists.
    try {
      const r = await ctx.backend.exec(
        `command -v docker >/dev/null 2>&1 && docker ps -a --filter label=${COMPOSE_PROJECT_LABEL}=${shq(name)} --format '{{.Names}}' 2>/dev/null || true`,
        15_000,
      );
      if (r.code === 0 && (r.stdout ?? '').trim() !== '') {
        return failResult(`A compose project named "${name}" already exists on this host`);
      }
    } catch { /* best-effort guard — up -d would just update it */ }

    // Single remote script: mkdir the workdir, write the YAML (quoted heredoc
    // keeps it byte-exact), run `docker compose up -d` from that dir with the
    // project name pinned via COMPOSE_PROJECT_NAME (portable across ALL compose
    // CLI versions — the --project-name flag only exists on newer ones), tail
    // the output. The slug pattern makes `name` safe; the workdir is validated
    // above and single-quoted everywhere.
    const script = [
      'set -u',
      `mkdir -p ${shq(dir)} || exit 97`,
      // Global registry file — lets compose.config.read / containers.update find this
      // workdir on hosts whose Compose version doesn't stamp the working_dir label.
      `mkdir -p ${shq(WORKDIR_REGISTRY_DIR)} && printf '%s\\n' ${shq(dir)} > ${shq(workdirRegistryPath(name))}`,
      `cat > ${shq(`${dir}/docker-compose.yml`)} <<'${COMPOSE_YAML_DELIM}'`,
      composeString.replace(/\n$/, ''),
      COMPOSE_YAML_DELIM,
      'if ! docker compose version >/dev/null 2>&1; then echo "ERROR: docker compose CLI not available on host (need Compose v2)"; exit 96; fi',
      `cd ${shq(dir)} || exit 98`,
      `out=$(COMPOSE_PROJECT_NAME=${name} docker compose -f docker-compose.yml up -d 2>&1); rc=$?`,
      'echo "$out" | tail -n 40',
      'exit $rc',
    ].join('\n');

    try {
      // Long budget — image pulls dominate; the pool keeps the session warm after.
      const r = await ctx.backend.exec(script, 570_000);
      if (r.code !== 0) {
        return failResult(`docker compose up failed (exit ${r.code}): ${(r.stderr || r.stdout).slice(-800)}`);
      }
      // Verify: `up -d` returns once containers are CREATED — confirm they actually
      // come up running before reporting the step as verified.
      const members = await resolveMembers(ctx.backend, name);
      if (members && members.length > 0) {
        const v = await verifyStates(ctx.backend, members, new Set(['running']));
        return okResult({ name, workdir: dir, note: 'Compose stack deployed — containers appear in the next inventory poll.' }, v.ok);
      }
      return okResult({ name, workdir: dir, note: 'Compose stack deployed — containers appear in the next inventory poll.' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/timed out/i.test(msg)) {
        return okResult({ name, workdir: dir, note: 'Deploy dispatched — the SSH session timed out while images pulled; check the host.' });
      }
      throw e;
    }
  },
};

// --- containers.update -----------------------------------------------------------
const containersUpdateAction: ActionDescriptor = {
  id: 'containers.update',
  label: 'Update compose stack',
  description:
    'Replaces the saved docker-compose.yml of an existing app and re-applies it (docker compose up -d). The workdir is resolved from the project\'s com.docker.compose.project.working_dir label — apps deployed outside UNM fall back to /opt/compose/<name>.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 600_000, // image pulls dominate (new tags)
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, description: 'Compose project / app name' },
    composeString: { type: 'string', required: true, minLength: 2, description: 'New Docker Compose YAML' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    const composeString = str(input, 'composeString');
    if (!name || !composeString) return failResult('Project name and compose YAML are required');
    if (composeString.includes(COMPOSE_YAML_DELIM)) {
      return failResult(`Compose YAML must not contain the delimiter "${COMPOSE_YAML_DELIM}"`);
    }

    // Resolve the project's working dir: UNM registry file → working_dir label
    // (Compose v2.17+) → default.
    const workdir = (await resolveWorkdir(ctx.backend, name)) ?? `${DEFAULT_COMPOSE_WORKDIR}/${name}`;

    // The project must exist — update, never create.
    try {
      const r = await ctx.backend.exec(
        `command -v docker >/dev/null 2>&1 && docker ps -a --filter label=${COMPOSE_PROJECT_LABEL}=${shq(name)} --format '{{.Names}}' 2>/dev/null || true`,
        15_000,
      );
      if (r.code !== 0 || (r.stdout ?? '').trim() === '') {
        return failResult(`No compose project named "${name}" found on this host`);
      }
    } catch { /* best-effort — up -d would create it; the guard above is authoritative */ }

    const script = [
      'set -u',
      `mkdir -p ${shq(workdir)} || exit 97`,
      // Keep the global registry in sync (also covers first-time UNM updates of stacks
      // deployed outside UNM — from then on the workdir is resolvable everywhere).
      `mkdir -p ${shq(WORKDIR_REGISTRY_DIR)} && printf '%s\\n' ${shq(workdir)} > ${shq(workdirRegistryPath(name))}`,
      `cat > ${shq(`${workdir}/docker-compose.yml`)} <<'${COMPOSE_YAML_DELIM}'`,
      composeString.replace(/\n$/, ''),
      COMPOSE_YAML_DELIM,
      'if ! docker compose version >/dev/null 2>&1; then echo "ERROR: docker compose CLI not available on host (need Compose v2)"; exit 96; fi',
      `cd ${shq(workdir)} || exit 98`,
      `out=$(COMPOSE_PROJECT_NAME=${name} docker compose -f docker-compose.yml up -d 2>&1); rc=$?`,
      'echo "$out" | tail -n 40',
      'exit $rc',
    ].join('\n');

    try {
      const r = await ctx.backend.exec(script, 570_000);
      if (r.code !== 0) {
        return failResult(`docker compose up failed (exit ${r.code}): ${(r.stderr || r.stdout).slice(-800)}`);
      }
      return okResult({ name, workdir, note: 'Compose stack updated — containers appear in the next inventory poll.' });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/timed out/i.test(msg)) {
        return okResult({ name, workdir, note: 'Update dispatched — the SSH session timed out while images pulled; check the host.' });
      }
      throw e;
    }
  },
};

// --- compose.config.read -----------------------------------------------------------
const composeConfigReadAction: ActionDescriptor = {
  id: 'compose.config.read',
  label: 'Read app compose YAML',
  description:
    'Returns the saved docker-compose.yml of an existing app (from its working dir) plus the workdir itself — powers the Containers page\'s "Edit compose YAML" and clone prefill.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 30_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App / compose project name' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return failResult('App name is required');

    // Resolve the working dir: UNM registry file → working_dir label (Compose v2.17+)
    // → default — same rule as containers.update.
    const workdir = (await resolveWorkdir(ctx.backend, name)) ?? `${DEFAULT_COMPOSE_WORKDIR}/${name}`;

    // Read the YAML from every candidate location — first hit wins.
    const candidates = Array.from(new Set([`${workdir}/docker-compose.yml`, `${workdir}/compose.yaml`, `${workdir}/compose.yml`]));
    for (const f of candidates) {
      try {
        const r = await ctx.backend.exec(`[ -f ${shq(f)} ] && cat ${shq(f)} || true`, 15_000);
        if (r.code === 0 && (r.stdout ?? '').trim() !== '') {
          return okResult({ name, yaml: r.stdout, workdir });
        }
      } catch { /* try the next candidate */ }
    }

    // Standalone container (no compose file) — report it clearly.
    const members = await resolveMembers(ctx.backend, name);
    if (!members || members.length === 0) return failResult(`No app or compose project named "${name}" found on this host`);
    return failResult(`"${name}" is a standalone container without a saved compose file — nothing to edit. Delete and re-deploy it as a compose stack instead.`);
  },
};

// --- containers.logs.read -----------------------------------------------------------
const containersLogsReadAction: ActionDescriptor = {
  id: 'containers.logs.read',
  label: 'Read container logs',
  description: "Returns the recent log output (docker logs --tail) of a single app's container(s).",
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
    if (!name) return failResult('Container/app name is required');
    const tailRaw = typeof input['tail'] === 'number' ? Math.floor(input['tail']) : 300;
    const tail = Math.min(5000, Math.max(20, Number.isFinite(tailRaw) ? tailRaw : 300));

    // Resolve the app to its member containers (compose project OR standalone).
    const members = await resolveMembers(ctx.backend, name);
    if (!members || members.length === 0) {
      return failResult(`No container found for "${name}"`);
    }

    // One script: `docker logs --tail N` per member between markers.
    const lines: string[] = ['set -u'];
    for (const m of members) {
      const n = containerName(m);
      lines.push(`echo "UNM_LOGS:${n}:BEGIN"`);
      lines.push(`docker logs --tail ${tail} ${shq(n)} 2>&1 || true`);
      lines.push(`echo "UNM_LOGS:${n}:END"`);
    }
    const r = await ctx.backend.exec(lines.join('\n'), 45_000).catch(() => null);
    if (!r) return failResult(`Could not read logs for "${name}": SSH exec failed`);

    // Parse the marker-delimited sections.
    const out: Record<string, string> = {};
    let current: string | null = null;
    let buf = '';
    for (const line of (r.stdout ?? '').split('\n')) {
      const m = line.match(/^UNM_LOGS:(.+?):(BEGIN|END)$/);
      if (m) {
        if (current !== null && m[2] === 'END') out[current] = buf.replace(/\n$/, '');
        current = m[2] === 'BEGIN' ? m[1] : null;
        buf = '';
        continue;
      }
      if (current !== null) buf += line + '\n';
    }

    const containers = members.map((m) => {
      const n = containerName(m);
      return { id: (m.Id ?? '').slice(0, 12), service: n, state: m.State ?? 'unknown', logs: out[n] ?? '' };
    });
    return okResult({ name, tail, containers });
  },
};

// --- images.delete -------------------------------------------------------------------
const imagesDeleteAction: ActionDescriptor = {
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
    if (ids.length === 0) return failResult('No image ids provided');

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const id of ids) {
      // The docker CLI accepts a tag OR a sha256 id. A short/long sha is passed
      // through verbatim; anything else is treated as a name:tag.
      const r = await ctx.backend.exec(`docker rmi ${shq(id)} 2>&1 || true`, 60_000).catch(() => null);
      if (!r) { errors[id] = 'SSH exec failed'; continue; }
      const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
      if (r.code === 0 && !/no such image|not found/i.test(out)) deleted++;
      else if (/no such image|not found/i.test(out)) missing.push(id);
      else errors[id] = out.slice(-300) || `exit ${r.code}`;
    }

    // Verify: every deleted id must be gone from `docker images`. Template
    // accessors (.ID/.Tag) are version-stable — the --format json shape is not.
    let verified = true;
    const unverifiedIds: string[] = [];
    try {
      const r = await ctx.backend.exec('command -v docker >/dev/null 2>&1 && docker images --format "{{.ID}}|{{.Repository}}:{{.Tag}}" 2>/dev/null || true', 30_000);
      if (r.code === 0) {
        for (const id of ids) {
          if (missing.includes(id)) continue;
          const sha = id.startsWith('sha256:') ? id.slice(7) : /^[0-9a-f]{12,}$/i.test(id) ? id : null;
          const stillThere = (r.stdout ?? '').split('\n').some((line) => {
            const t = line.trim();
            if (!t || !t.includes('|')) return false;
            const i = t.indexOf('|');
            const imgId = t.slice(0, i).replace(/^sha256:/, '');
            const ref = t.slice(i + 1); // "repo:tag" ("<none>:<none>" when untagged)
            if (ref !== '<none>:<none>' && ref === id) return true;
            return sha !== null && imgId.startsWith(sha.slice(0, 12));
          });
          if (stillThere) { verified = false; unverifiedIds.push(id); }
        }
      }
    } catch { /* best-effort verification */ }

    return okResult({ deleted, missing, ...(unverifiedIds.length ? { unverified: unverifiedIds } : {}), ...(Object.keys(errors).length ? { errors } : {}) }, verified && Object.keys(errors).length === 0);
  },
};

// --- Image management (pull / update / prune) ------------------------------------
// Generic contract for the Containers page's image panel — any plugin that can
// manage images advertises these ids and gets the same UI buttons for free:
//   images.pull    { refs[] }            pull new/updated tags into the local store
//   images.update  { refs[], restart? }  re-pull + (optionally) restart containers using them
//   images.prune   { all? }              remove unused images (dangling, or ALL unused with all=true)

/** Validates an image reference for safe shell embedding (docker ref charset). */
function isValidImageRef(ref: string): boolean {
  return ref.length > 0 && ref.length <= 512 && /^[a-zA-Z0-9_./:@\-]+$/.test(ref);
}

const PULL_TIMEOUT_MS = 600_000; // image pulls dominate (same budget as deploy)

// --- images.pull ------------------------------------------------------------------
const imagesPullAction: ActionDescriptor = {
  id: 'images.pull',
  label: 'Pull image(s)',
  description:
    'Pulls docker image references into the local store (docker pull). Existing tags are refreshed to the registry version; new ones are downloaded. May take several minutes for large images.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: PULL_TIMEOUT_MS,
  inputSchema: {
    refs: { type: 'array', required: true, items: { type: 'string', minLength: 2 }, description: 'Image references to pull (e.g. "nginx:latest", "ghcr.io/org/app:v1")' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const refs = strArray(input, 'refs');
    if (refs.length === 0) return failResult('No image references provided');
    for (const ref of refs) {
      if (!isValidImageRef(ref)) return failResult(`Invalid image reference "${ref}"`);
    }

    // One remote script: each pull is marker-delimited; only the LAST lines per
    // pull are kept (progress output can be huge — stdout truncates at 256 KB).
    const lines: string[] = ['set -u'];
    for (const ref of refs) {
      lines.push(`echo "UNM_PULL:${ref}:BEGIN"`);
      lines.push(`out=$(docker pull ${shq(ref)} 2>&1); rc=$?`);
      lines.push('if [ $rc -eq 0 ]; then echo "OK|${#out}"; else echo "ERR|$rc|$(echo "$out" | tail -n 5)"; fi');
      lines.push(`echo "UNM_PULL:${ref}:END"`);
    }
    let r;
    try {
      r = await ctx.backend.exec(lines.join('\n'), PULL_TIMEOUT_MS - 30_000);
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      if (/timed out/i.test(msg)) return okResult({ pulled: [], note: 'Pull dispatched — the SSH session timed out while images downloaded; check the host.' });
      throw e;
    }

    // Parse marker sections → per-ref outcome.
    const results = new Map<string, { ok: boolean; error?: string }>();
    let current: string | null = null;
    for (const line of (r.stdout ?? '').split('\n')) {
      const m = line.match(/^UNM_PULL:(.+?):(BEGIN|END)$/);
      if (m) {
        if (current !== null && m[2] === 'END') current = null;
        else if (m[2] === 'BEGIN') current = m[1];
        continue;
      }
      if (current === null) continue;
      if (line.startsWith('OK|')) results.set(current, { ok: true });
      else if (line.startsWith('ERR|')) {
        const parts = line.split('|');
        results.set(current, { ok: false, error: `${parts.slice(2).join('|')}`.trim().slice(-300) || `exit ${parts[1] ?? '?'}` });
      }
    }

    const pulled: string[] = [];
    const errors: Record<string, string> = {};
    for (const ref of refs) {
      const res = results.get(ref);
      if (!res) { errors[ref] = 'no output received (SSH session may have dropped mid-pull)'; continue; }
      if (res.ok) pulled.push(ref);
      else errors[ref] = res.error ?? 'pull failed';
    }
    return okResult({ pulled, ...(Object.keys(errors).length ? { errors } : {}) }, Object.keys(errors).length === 0);
  },
};

// --- images.update ----------------------------------------------------------------
const imagesUpdateAction: ActionDescriptor = {
  id: 'images.update',
  label: 'Update image(s)',
  description:
    'Re-pulls the given image references (refreshing them to the registry version) and — by default — restarts every RUNNING container that uses one of those images so it picks up the new version. Set restart=false to only refresh the local store.',
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
    if (refs.length === 0) return failResult('No image references provided');
    for (const ref of refs) {
      if (!isValidImageRef(ref)) return failResult(`Invalid image reference "${ref}"`);
    }
    const restart = input['restart'] !== false; // default true

    // 1) Refresh the local store.
    const pullRes = await imagesPullAction.execute(ctx, { refs });
    if (!pullRes.success) return failResult(`Image update failed: ${pullRes.error ?? 'pull errors'}`);
    const pulled = Array.isArray((pullRes.details as Record<string, unknown> | undefined)?.['pulled']) ? (pullRes.details as Record<string, unknown>)['pulled'] as string[] : [];

    if (!restart) {
      return okResult({ updated: pulled, restarted: [], note: 'Images refreshed — no containers were restarted (restart=false).' }, true);
    }

    // 2) Find every RUNNING container whose image matches one of the refs. ONE
    // pass: `docker ps` reports each running container's .Image exactly as it was
    // specified at creation (the repo:tag string), so a tag update ("nginx:latest")
    // matches containers started from that same ref. Digest-pinned / short-id
    // creations are not matched — they must be restarted manually.
    const matchR = await ctx.backend.exec(
      "command -v docker >/dev/null 2>&1 && docker ps --format '{{.ID}}|{{.Names}}|{{.Image}}' 2>/dev/null || true",
      30_000,
    ).catch(() => null);

    const matched: Array<{ id: string; name: string }> = [];
    if (matchR) {
      for (const line of (matchR.stdout ?? '').split('\n')) {
        const t = line.trim();
        if (!t.includes('|')) continue;
        // Split into exactly 3 fields — the image ref may itself contain '|'.
        const parts = t.split('|');
        if (parts.length < 3) continue;
        const id = parts[0] ?? '';
        const name = (parts[1] ?? '').replace(/^\/+/, '');
        const img = parts.slice(2).join('|').trim();
        if (!id || !name || !img) continue;
        if (refs.includes(img) && !matched.some((m) => m.id === id)) matched.push({ id, name });
      }
    }

    let restarted: string[] = [];
    const errors: Record<string, string> = {};
    if (matched.length > 0) {
      // Restart by id — names are never interpolated into the script.
      const rl: string[] = ['set -u'];
      for (const m of matched) {
        rl.push(`out=$(docker restart ${shq(m.id)} 2>&1); rc=$?`);
        rl.push('if [ $rc -eq 0 ]; then echo "OK|' + m.name + '"; else echo "ERR|' + m.name + '|$(echo "$out" | tail -c 300)"; fi');
      }
      const rr = await ctx.backend.exec(rl.join('\n'), 120_000).catch(() => null);
      if (!rr) {
        errors['restart'] = 'SSH exec failed while restarting containers';
      } else {
        for (const line of (rr.stdout ?? '').split('\n')) {
          const t = line.trim();
          if (t.startsWith('OK|')) restarted.push(t.slice(3));
          else if (t.startsWith('ERR|')) {
            const parts = t.split('|');
            errors[parts[1] ?? 'container'] = `${parts.slice(2).join('|')}`.trim().slice(-300);
          }
        }
      }

      // Verify: every restarted container must be running again (a restart is a
      // no-op ack until the process is actually up). verifyStates matches by NAME.
      const members = matched.map((m) => ({ Id: m.id, Names: [m.name] })) as DockerContainerRaw[];
      const v = await verifyStates(ctx.backend, members, new Set(['running']));
      if (!v.ok) {
        for (const [n, s] of Object.entries(v.after)) {
          if (s !== 'running') errors[`verify:${n}`] = `container is ${s} after restart`;
        }
      }
    }

    return okResult(
      { updated: pulled, restarted, ...(Object.keys(errors).length ? { errors } : {}) },
      Object.keys(errors).length === 0,
    );
  },
};

// --- images.prune -----------------------------------------------------------------
const imagesPruneAction: ActionDescriptor = {
  id: 'images.prune',
  label: 'Prune unused images',
  description:
    'Removes UNUSED docker images (docker image prune). With all=false only dangling (<none>) layers are removed; with all=true every image no container references is removed — including stopped containers\' images. DESTRUCTIVE for the local store.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    all: { type: 'boolean', required: false, default: false, description: 'Prune ALL unused images (not just dangling). Default false.' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const all = input['all'] === true;
    const flag = all ? '--all' : '';
    // -f skips the interactive confirmation prompt.
    const r = await ctx.backend.exec(`docker image prune ${flag} -f 2>&1 || true`, 240_000).catch(() => null);
    if (!r) return failResult('Could not run docker image prune: SSH exec failed');
    const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
    if (/command not found|cannot execute/i.test(out)) return failResult('docker CLI not available on this host');

    // "Total reclaimed space: 1.2GB" — the humanized size docker reports.
    const m = out.match(/Total reclaimed space:\s*([0-9]+(?:\.[0-9]+)?)\s*([KMGTP]?i?B)/i);
    const freedBytes = m ? Math.round(parseFloat(m[1]) * (m[2].toUpperCase().startsWith('T') ? 1024 ** 4 : m[2].toUpperCase().startsWith('G') ? 1024 ** 3 : m[2].toUpperCase().startsWith('M') ? 1024 ** 2 : m[2].toUpperCase().startsWith('K') ? 1024 : 1)) : null;
    return okResult({ all, freedBytes, note: out.trim().slice(-300) }, true);
  },
};

export const DOCKER_ACTIONS: ActionDescriptor[] = [
  containersStartAction,
  containersStopAction,
  containersRestartAction,
  containersDeleteAction,
  containersDeployComposeAction,
  containersUpdateAction,
  composeConfigReadAction,
  containersLogsReadAction,
  imagesDeleteAction,
  imagesPullAction,
  imagesUpdateAction,
  imagesPruneAction,
];
