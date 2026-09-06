/**
 * The TrueNAS action registry — first config-capable release of this plugin.
 * Serves two entry points (same contract as the other plugins):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * All methods are documented TrueNAS JSON-RPC calls (api.truenas.com /
 * middleware source): system.info, pool.query, interface.query for reads;
 * system.reboot(reason, {delay}) and system.shutdown(reason, {delay}) for the
 * DANGEROUS power actions — both FULL_ADMIN jobs that drop our socket as the
 * appliance goes down (a job id or a transport error after dispatch both mean
 * "initiated").
 */

import { ActionDescriptor, ActionResult, createRegistry, pickString } from '@unm/plugin-sdk';
import { TruenasClient, TruenasCredentials, TruenasRpcError } from './client/truenasClient';

/** Executor context for one /config step. */
export interface TruenasActionContext {
  client: TruenasClient;
  creds: TruenasCredentials;
}

function str(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

/** TrueNAS job methods (reboot/shutdown) resolve to a JOB ID — the work runs server-side. */
function describeJobResult(result: unknown): Record<string, unknown> {
  if (typeof result === 'number') return { jobId: result, note: 'Accepted as an asynchronous job — the appliance will go down shortly.' };
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') {
    const r = result as Record<string, unknown>;
    return { jobId: r['id'], note: 'Accepted as an asynchronous job — the appliance will go down shortly.' };
  }
  return {};
}

/**
 * Stable dedupe key for one alert (class + subject) — shared by index.ts (which
 * mirrors active alerts into the UNM notification center, where the API prefixes
 * it with `plugin:<uuid>:`) and the `alerts.dismiss` action below (which matches
 * UNM rows back to appliance alerts). Args are usually `[diskName]` or
 * `{name: ...}` — take the first string-ish piece as the subject so e.g.
 * "SMART uncorrected errors on da0" dedupes per disk.
 */
export function alertDedupeKey(klass: string, argsRaw: unknown): string {
  let subject = '';
  if (Array.isArray(argsRaw) && argsRaw.length > 0) {
    const first = argsRaw[0];
    subject = typeof first === 'string' ? first : pickString((first ?? {}) as Record<string, unknown>, ['name', 'disk']) ?? '';
  } else if (argsRaw && typeof argsRaw === 'object') {
    subject = pickString(argsRaw as Record<string, unknown>, ['name', 'disk']) ?? '';
  }
  return `alert:${klass}:${subject}`.toLowerCase();
}

const systemInfoAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.info.read',
  label: 'Read system information',
  description: 'Fetches hostname, version, CPU load, memory and uptime from system.info.',
  module: 'System',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const si = await ctx.client.call<Record<string, unknown>>('system.info', [], ctx.creds);
    return { success: true, details: { systemInfo: si } };
  },
};

const poolsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'pools.read',
  label: 'Read ZFS pool status',
  description: 'Fetches all pools with size/used/free and scrub state from pool.query.',
  module: 'Storage',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const pools = await ctx.client.call<Record<string, unknown>[]>('pool.query', [], ctx.creds);
    return { success: true, details: { poolCount: pools.length } };
  },
};

const interfacesReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'interfaces.read',
  label: 'Read network interfaces',
  description: 'Fetches all interfaces with link state, MAC and IP aliases from interface.query.',
  module: 'Network',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const ifaces = await ctx.client.call<Record<string, unknown>[]>('interface.query', [], ctx.creds);
    return { success: true, details: { interfaceCount: ifaces.length } };
  },
};

const systemRebootAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.reboot',
  label: 'Reboot the appliance',
  description:
    'Gracefully reboots TrueNAS (documented `system.reboot` job, FULL_ADMIN). The WebSocket drops as the box goes down — a job id or a transport error after dispatch both mean "initiated".',
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    reason: { type: 'string', required: true, minLength: 3, maxLength: 200, description: 'Reason recorded in the appliance audit log' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const reason = str(input, 'reason') ?? 'Reboot initiated from Unified Network Manager';
    try {
      const result = await ctx.client.call<unknown>('system.reboot', [reason, {}], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
    } catch (e) {
      // The socket dies mid-job when the appliance powers off — that is EXPECTED.
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Reboot initiated — connection lost as expected while the appliance went down.' } };
      }
      throw e;
    }
  },
};

const systemShutdownAction: ActionDescriptor<TruenasActionContext> = {
  id: 'system.shutdown',
  label: 'Shut down the appliance',
  description:
    'Gracefully powers off TrueNAS (documented `system.shutdown` job, FULL_ADMIN). The WebSocket drops as the box goes down — a job id or a transport error after dispatch both mean "initiated".',
  module: 'System',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    reason: { type: 'string', required: true, minLength: 3, maxLength: 200, description: 'Reason recorded in the appliance audit log' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const reason = str(input, 'reason') ?? 'Shutdown initiated from Unified Network Manager';
    try {
      const result = await ctx.client.call<unknown>('system.shutdown', [reason, {}], ctx.creds);
      return { success: true, applied: true, details: describeJobResult(result) };
    } catch (e) {
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Shutdown initiated — connection lost as expected while the appliance went down.' } };
      }
      throw e;
    }
  },
};

/**
 * Dismiss active alerts on the appliance (TrueNAS `alert.dismiss` RPC). The API
 * calls this when a user closes TrueNAS alert notifications in UNM so the
 * acknowledgment reaches the box itself — dismissed alerts stop driving health
 * and are skipped by the plugin's alert mirroring. Matching is by dedupe key
 * (class + subject, see alertDedupeKey): it survives re-polls even when the
 * appliance regenerates alert UUIDs. `alert.dismiss` on an already-dismissed or
 * gone alert raises a method error — treated as "already handled", not failure.
 */
const alertsDismissAction: ActionDescriptor<TruenasActionContext> = {
  id: 'alerts.dismiss',
  label: 'Dismiss appliance alerts',
  description:
    'Dismissing TrueNAS alerts (alert.dismiss) for the given dedupe keys — used when a user closes alert notifications in UNM so the acknowledgment reaches the appliance.',
  module: 'Alerts',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    keys: { type: 'array', required: true, items: { type: 'string', minLength: 3 } },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const keys = Array.isArray(input.keys) ? (input.keys as unknown[]).filter((k): k is string => typeof k === 'string' && k.length > 0) : [];
    if (keys.length === 0) return { success: false, details: { error: 'No alert keys provided' } };

    const alerts = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
    // One UNM row can aggregate several appliance alerts of the same class+subject.
    const byKey = new Map<string, string[]>();
    for (const a of alerts) {
      if ((a['dismissed'] as boolean | undefined) === true) continue;
      const uuid = pickString(a, ['id', 'uuid']);
      if (!uuid) continue;
      const k = alertDedupeKey(pickString(a, ['klass']) ?? '', a['args']);
      const list = byKey.get(k) ?? [];
      list.push(uuid);
      byKey.set(k, list);
    }

    let dismissed = 0;
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // already gone or already dismissed — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          await ctx.client.call('alert.dismiss', [uuid], ctx.creds);
          dismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // transport error — surface it
          // Method error = alert vanished or was dismissed in the meantime.
        }
      }
    }
    return { success: true, details: { dismissed, missing } };
  },
};

/**
 * Re-enable previously dismissed alerts (TrueNAS `alert.undismiss` RPC) — the
 * inverse of alerts.dismiss, used when a user re-opens a closed alert in UNM.
 */
const alertsUndismissAction: ActionDescriptor<TruenasActionContext> = {
  id: 'alerts.undismiss',
  label: 'Re-enable appliance alerts',
  description:
    'Re-enables previously dismissed TrueNAS alerts (alert.undismiss) for the given dedupe keys — used when a user re-opens closed alert notifications in UNM.',
  module: 'Alerts',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  inputSchema: {
    keys: { type: 'array', required: true, items: { type: 'string', minLength: 3 } },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const keys = Array.isArray(input.keys) ? (input.keys as unknown[]).filter((k): k is string => typeof k === 'string' && k.length > 0) : [];
    if (keys.length === 0) return { success: false, details: { error: 'No alert keys provided' } };

    const alerts = await ctx.client.call<Record<string, unknown>[]>('alert.list', [], ctx.creds);
    // Undismiss targets DISMISSED alerts — the inverse of alerts.dismiss.
    const byKey = new Map<string, string[]>();
    for (const a of alerts) {
      if ((a['dismissed'] as boolean | undefined) !== true) continue;
      const uuid = pickString(a, ['id', 'uuid']);
      if (!uuid) continue;
      const k = alertDedupeKey(pickString(a, ['klass']) ?? '', a['args']);
      const list = byKey.get(k) ?? [];
      list.push(uuid);
      byKey.set(k, list);
    }

    let undismissed = 0;
    const missing: string[] = [];
    for (const k of keys) {
      const uuids = byKey.get(k);
      if (!uuids || uuids.length === 0) {
        missing.push(k); // never dismissed or already gone — nothing to do
        continue;
      }
      for (const uuid of uuids) {
        try {
          await ctx.client.call('alert.undismiss', [uuid], ctx.creds);
          undismissed++;
        } catch (e) {
          if (!(e instanceof TruenasRpcError)) throw e; // transport error — surface it
          // Method error = alert vanished or was re-enabled in the meantime.
        }
      }
    }
    return { success: true, details: { undismissed, missing } };
  },
};

// ---------------------------------------------------------------------------
// Container / image lifecycle actions (Containers page bulk actions).
//
// These are GENERIC single-device actions: the UNM webapp's Containers page
// offers them as bulk operations and fans one step out per selected app/image.
// Any future vendor plugin that manages docker workloads can expose the same
// action ids so the UI stays identical across vendors. All of them target the
// TrueNAS SCALE `app.*` / `app.image.*` JSON-RPC methods (documented in the
// middleware source). The mutating ones are @job methods — the RPC resolves to
// a JOB ID immediately and the work runs server-side, so each step returns fast
// ("accepted") rather than blocking until the workload settles.
// ---------------------------------------------------------------------------

/** Reads a non-empty string array from an action input (defensive). */
function strArray(input: Record<string, unknown>, key: string): string[] {
  const v = input[key];
  if (!Array.isArray(v)) return [];
  return v.filter((x): x is string => typeof x === 'string' && x.length > 0);
}

/** One app row as returned by `app.query` (only the fields we need). */
interface AppRow {
  name: string;
  state?: string | null;
  upgrade_available?: boolean | null;
  custom_app?: boolean | null;
}

/**
 * One JSON-RPC call with a single retry on timeout. Bulk reads (app.query /
 * app.image.query) can exceed the client's default per-call budget when the
 * appliance is busy — e.g. right after a bulk stop/start of several apps, or on
 * fleets with hundreds of apps/images. The retry uses a 15s round-trip budget;
 * non-timeout errors (auth, method errors) are surfaced immediately.
 */
async function callWithRetry<T>(ctx: TruenasActionContext, method: string, params: unknown[]): Promise<T> {
  try {
    return await ctx.client.call<T>(method, params, ctx.creds);
  } catch (e) {
    if (!(e instanceof TruenasRpcError) || !/timed out/i.test(e.message)) throw e;
    return await ctx.client.call<T>(method, params, ctx.creds, 15_000);
  }
}

/** Fetches all installed apps with their current state. */
async function listApps(ctx: TruenasActionContext): Promise<AppRow[]> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.query', []);
  return (rows ?? []).map((r) => ({
    name: pickString(r, ['name']) ?? '',
    state: pickString(r, ['state']),
    upgrade_available: typeof r['upgrade_available'] === 'boolean' ? (r['upgrade_available'] as boolean) : null,
    custom_app: typeof r['custom_app'] === 'boolean' ? (r['custom_app'] as boolean) : null,
  }));
}

/** Normalizes an app state to uppercase (SCALE emits e.g. RUNNING/STOPPED). */
function normState(s: string | null | undefined): string {
  return (s ?? '').toUpperCase();
}

/**
 * Builds the per-name outcome for a lifecycle action. `target` is the set of
 * states that mean "already done" (idempotent skip); apps in those states are
 * reported as skipped, not failed — so re-running a bulk stop/start is safe.
 */
function planAppOutcomes(
  names: string[],
  apps: AppRow[],
  target: Set<string>,
): { toRun: string[]; skipped: Record<string, string>; missing: string[] } {
  const byName = new Map(apps.map((a) => [a.name, a]));
  const toRun: string[] = [];
  const skipped: Record<string, string> = {};
  const missing: string[] = [];
  for (const n of names) {
    const app = byName.get(n);
    if (!app) {
      missing.push(n); // already gone — nothing to do
      continue;
    }
    if (target.has(normState(app.state))) skipped[n] = normState(app.state).toLowerCase();
    else toRun.push(n);
  }
  return { toRun, skipped, missing };
}

/** True when a JSON-RPC error means "the app is already in the target state". */
function isAlreadyInState(e: unknown): boolean {
  if (!(e instanceof TruenasRpcError)) return false;
  return /already|not (running|stopped)|in an invalid state/i.test(e.message);
}

/** Describes a job-method result (job id = accepted, work runs server-side). */
function describeAccepted(result: unknown): Record<string, unknown> {
  if (typeof result === 'number') return { jobId: result, note: 'Accepted as an asynchronous appliance job.' };
  if (result && typeof result === 'object' && typeof (result as Record<string, unknown>)['id'] === 'number') {
    return { jobId: (result as Record<string, unknown>)['id'], note: 'Accepted as an asynchronous appliance job.' };
  }
  return {};
}

const containersStopAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.stop',
  label: 'Stop container(s)',
  description: 'Stops the selected apps (app.stop). Apps already stopped are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to stop' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const { toRun, skipped, missing } = planAppOutcomes(names, apps, new Set(['STOPPED', 'STOPPING']));

    let stopped = 0;
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        await ctx.client.call('app.stop', [n], ctx.creds);
        stopped++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already stopped';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { stopped, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersStartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.start',
  label: 'Start container(s)',
  description: 'Starts the selected apps (app.start). Apps already running are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to start' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const { toRun, skipped, missing } = planAppOutcomes(names, apps, new Set(['RUNNING', 'DEPLOYING']));

    let started = 0;
    const errors: Record<string, string> = {};
    for (const n of toRun) {
      try {
        await ctx.client.call('app.start', [n], ctx.creds);
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersRestartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.restart',
  label: 'Restart container(s)',
  description: 'Restarts the selected apps (app.stop then app.start). Apps already stopped are started directly.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to restart' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let restarted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const app = byName.get(n);
      if (!app) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // Stop first unless it is not running, then start.
        if (normState(app.state) !== 'STOPPED') {
          await ctx.client.call('app.stop', [n], ctx.creds);
        }
        await ctx.client.call('app.start', [n], ctx.creds);
        restarted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { restarted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersUpgradeAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.upgrade',
  label: 'Update container(s)',
  description:
    'Upgrades the selected apps to their latest version (app.upgrade). Apps with no update available are skipped, not failed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to update' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let upgraded = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const app = byName.get(n);
      if (!app) {
        missing.push(n);
        continue;
      }
      // Only upgrade when the appliance reports an update — otherwise skip.
      if (app.upgrade_available !== true) {
        skipped[n] = 'no update available';
        continue;
      }
      try {
        await ctx.client.call('app.upgrade', [n, { app_version: 'latest' }], ctx.creds);
        upgraded++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { upgraded, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const containersDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.delete',
  label: 'Delete container(s)',
  description:
    'DELETES the selected apps and their docker resources (app.delete, remove_images). This is destructive — data in app-managed volumes is removed.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'App names to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No app names provided' } };
    const apps = await listApps(ctx);
    const byName = new Map(apps.map((a) => [a.name, a]));

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      if (!byName.has(n)) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        await ctx.client.call('app.delete', [n, { remove_images: true, force_remove_custom_app: true }], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const imagesDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'images.delete',
  label: 'Delete image(s)',
  description:
    'DELETES the selected docker images from the appliance (app.image.delete). Images still in use by a running app may fail; dangling/unused ones are removed.',
  module: 'Containers',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    ids: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'Image ids or tag references to delete' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const ids = strArray(input, 'ids');
    if (ids.length === 0) return { success: false, details: { error: 'No image ids provided' } };

    // Build the set of known images (id + every tag/digest) so we can tell
    // "already gone" from a real failure, plus a map from any reference to its
    // sha256 id — app.image.delete only accepts ids, not tags.
    const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'app.image.query', []);
    const known = new Set<string>();
    const idByRef = new Map<string, string>();
    for (const r of rows ?? []) {
      const id = pickString(r, ['id']);
      if (!id) continue;
      known.add(id);
      idByRef.set(id, id);
      for (const t of Array.isArray(r['repo_tags']) ? (r['repo_tags'] as unknown[]) : []) {
        if (typeof t === 'string') {
          known.add(t);
          idByRef.set(t, id);
        }
      }
    }

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    const doneIds = new Set<string>(); // several tags can share one image id — delete it once
    for (const ref of ids) {
      if (!known.has(ref)) {
        missing.push(ref); // already gone — nothing to do
        continue;
      }
      const target = idByRef.get(ref)!;
      if (doneIds.has(target)) continue;
      doneIds.add(target);
      try {
        await ctx.client.call('app.image.delete', [target, { force: false }], ctx.creds);
        deleted++;
      } catch (e) {
        errors[ref] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

/**
 * Reads the current compose YAML of a custom app (app.config with
 * retrieve_config). The webapp's Containers page uses this to pre-fill its YAML
 * editor before submitting `containers.update`. For catalog apps the compose is
 * generated from the schema, so only custom apps expose an editable string.
 */
const composeConfigReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'compose.config.read',
  label: 'Read app compose YAML',
  description: 'Returns the current Docker Compose configuration (YAML) of a single custom app.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to read the compose config of' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };

    // app.query with retrieve_config returns the full config incl. compose.
    let cfg: Record<string, unknown> | null = null;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('app.query', [[], { extra: { retrieve_config: true } }], ctx.creds);
      for (const r of rows ?? []) {
        if ((pickString(r, ['name']) ?? '') === name) {
          const c = r['config'];
          cfg = c && typeof c === 'object' ? (c as Record<string, unknown>) : null;
          break;
        }
      }
    } catch (e) {
      // Older appliances may not support retrieve_config — fall back to app.config.
      if (!(e instanceof TruenasRpcError)) throw e;
    }
    if (!cfg) {
      try {
        cfg = await ctx.client.call<Record<string, unknown>>('app.config', [name], ctx.creds);
      } catch (e) {
        return { success: false, details: { error: `Could not read config for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
      }
    }

    // The compose lives in custom_compose_config_string when present; otherwise
    // fall back to the structured services map (serialized as YAML-ish JSON).
    const yamlStr = pickString(cfg, ['custom_compose_config_string']);
    let yaml: string;
    if (yamlStr && yamlStr.trim() !== '') {
      yaml = yamlStr;
    } else {
      const svcs = cfg['services'];
      yaml = svcs && typeof svcs === 'object' ? JSON.stringify({ services: svcs }, null, 2) : '';
    }
    if (yaml.trim() === '') return { success: false, details: { error: `No editable compose config found for "${name}" (catalog apps generate their compose from the schema)` } };

    const customApp = typeof cfg['custom_app'] === 'boolean' ? (cfg['custom_app'] as boolean) : null;
    return { success: true, details: { name, yaml, ...(customApp !== null ? { customApp } : {}) } };
  },
};

const containersUpdateAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.update',
  label: 'Edit app compose YAML',
  description:
    'Applies an edited Docker Compose configuration to a single custom app (app.update with custom_compose_config_string). The app is redeployed.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to update' },
    composeString: { type: 'string', required: true, minLength: 2, description: 'New Docker Compose YAML for the app' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const composeString = str(input, 'composeString');
    if (!name || !composeString) return { success: false, details: { error: 'App name and compose YAML are required' } };

    try {
      const result = await ctx.client.call('app.update', [name, { custom_compose_config_string: composeString }], ctx.creds);
      return { success: true, applied: true, details: describeAccepted(result) };
    } catch (e) {
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Update accepted — connection dropped while the app redeployed.' } };
      }
      throw e;
    }
  },
};

export const registry = createRegistry<TruenasActionContext>([
  systemInfoAction,
  poolsReadAction,
  interfacesReadAction,
  systemRebootAction,
  systemShutdownAction,
  alertsDismissAction,
  alertsUndismissAction,
  containersStopAction,
  containersStartAction,
  containersRestartAction,
  containersUpgradeAction,
  containersDeleteAction,
  imagesDeleteAction,
  composeConfigReadAction,
  containersUpdateAction,
]);
