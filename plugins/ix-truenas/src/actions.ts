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

import { ActionDescriptor, ActionResult, createRegistry, pickString, resolveSshCredentials, SshError } from '@unm/plugin-sdk';
import { TruenasClient, TruenasCredentials, TruenasRpcError } from './client/truenasClient';
import { normalizeVmDevice, sshPool } from './enrich';

/** Executor context for one /config step. */
export interface TruenasActionContext {
  client: TruenasClient;
  creds: TruenasCredentials;
  /** The device management address (host[:port]) — needed by actions that reach the appliance over a different channel than the RPC socket (e.g. SSH for container logs). */
  host?: string;
  /** The request's raw `credentials` body (primary secret + bound slots) — needed by actions that use a slot distinct from the primary (e.g. SSH for container logs). */
  rawCredentials?: Record<string, unknown> | null;
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

// ---------------------------------------------------------------------------
// VM lifecycle + NIC actions (VMs page) — a GENERIC contract any hypervisor
// plugin can implement: input is always guest NAMES (`names[]` for bulk, `name`
// for single-VM ops), each action resolves them to appliance ids via vm.query
// and reports per-name outcomes, so re-running a bulk start/stop is idempotent
// (already in the target state = skipped, not failed). TrueNAS mapping:
//   vms.start    → vm.start(id)            immediate
//   vms.stop     → vm.stop(id)             JOB — ACPI powerdown, bounded by the
//                                           appliance's shutdown timeout
//   vms.kill     → vm.poweroff(id)         hard kill for unresponsive guests
//   vms.restart  → vm.restart(id)          JOB — stop + start server-side
//   vms.suspend  → vm.suspend(id)          freeze RAM state (guest must run)
//   vms.resume   → vm.resume(id)           unfreeze SUSPENDED/PAUSED guests
//   vms.delete   → vm.delete(id,{zvols})   destructive; zvols removes storage
// NICs are VM devices: attach = vm.device.create({id, attributes:{dtype:'NIC',…}}),
// detach = vm.device.delete(deviceId) — the integer device id is resolved from
// the NIC's MAC via vm.query. `vms.nic-choices` (read-only) feeds the webapp's
// attach dialog with the appliance's bridges + MACVLANs.
// ---------------------------------------------------------------------------

/** One VM as returned by `vm.query` (only the fields these actions need). */
interface VmInfo {
  id: number;
  name: string;
  /** Normalized uppercase libvirt state (RUNNING / STOPPED / SUSPENDED / …). */
  state: string;
  /** Raw devices[] entries — NIC detach resolves its integer device id from here. */
  devices: Record<string, unknown>[];
}

/** Fetches all VMs with their current state (vm.query). */
async function listVms(ctx: TruenasActionContext): Promise<VmInfo[]> {
  const rows = await callWithRetry<Record<string, unknown>[]>(ctx, 'vm.query', []);
  const out: VmInfo[] = [];
  for (const r of rows ?? []) {
    if (!r || typeof r !== 'object') continue;
    const name = pickString(r, ['name']);
    if (!name) continue;
    const status = (r['status'] ?? {}) as Record<string, unknown>;
    out.push({
      id: typeof r['id'] === 'number' ? (r['id'] as number) : -1,
      name,
      state: normState(pickString(status, ['state'])),
      devices: Array.isArray(r['devices']) ? (r['devices'] as Record<string, unknown>[]) : [],
    });
  }
  return out;
}

/** Resolves guest names to VMs — the per-name outcome for a lifecycle action. */
function planVmOutcomes(
  names: string[],
  vms: VmInfo[],
  target: Set<string>,
): { toRun: VmInfo[]; skipped: Record<string, string>; missing: string[] } {
  const byName = new Map(vms.map((v) => [v.name, v]));
  const toRun: VmInfo[] = [];
  const skipped: Record<string, string> = {};
  const missing: string[] = [];
  for (const n of names) {
    const vm = byName.get(n);
    if (!vm) {
      missing.push(n); // already gone — nothing to do
      continue;
    }
    if (target.has(vm.state)) skipped[n] = vm.state.toLowerCase();
    else toRun.push(vm);
  }
  return { toRun, skipped, missing };
}

const vmsStartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.start',
  label: 'Start VM(s)',
  description: 'Starts the selected VMs (vm.start). VMs already running are skipped, not failed.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to start' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['RUNNING']));

    let started = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.call('vm.start', [vm.id], ctx.creds);
        started++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already running';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { started, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsStopAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.stop',
  label: 'Stop VM(s)',
  description:
    'Gracefully stops the selected VMs (vm.stop — ACPI powerdown, an appliance job). The step waits for each stop job to settle; a guest that ignores the shutdown is reported per-VM so it can be killed. VMs already stopped are skipped.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to stop' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['STOPPED']));

    let stopped = 0;
    const notes: Record<string, string> = {};
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        // vm.stop is a JOB method — the ACPI powerdown runs server-side and the
        // job settles when the guest acks or its shutdown timeout elapses. Wait
        // with a bounded budget so an unresponsive guest surfaces as a per-VM
        // error (the user can then Kill it) instead of a silent "accepted".
        const r = await ctx.client.call<unknown>('vm.stop', [vm.id], ctx.creds);
        const job = describeAccepted(r);
        if (typeof job['jobId'] === 'number') {
          const wait = await waitForJob(ctx, job['jobId'], 150_000);
          if (wait.state === 'RUNNING') {
            notes[vm.name] = 'Stop initiated — still in progress on the appliance';
            stopped++;
            continue;
          }
          if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
            errors[vm.name] = wait.error ?? `Stop job ended in state ${wait.state}`;
            continue;
          }
        }
        stopped++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already stopped';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { stopped, skipped, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsKillAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.kill',
  label: 'Kill VM(s)',
  description:
    'HARD-KILLS the selected VMs (vm.poweroff) — no ACPI handshake, use for guests that are unresponsive to a graceful stop. VMs already stopped are skipped.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to kill' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['STOPPED']));

    let killed = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      try {
        await ctx.client.call('vm.poweroff', [vm.id], ctx.creds);
        killed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already stopped';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { killed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsRestartAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.restart',
  label: 'Restart VM(s)',
  description:
    'Restarts the selected VMs (vm.restart — an appliance job). Stopped VMs are started directly. The step waits for each restart job to settle.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to restart' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let restarted = 0;
    const notes: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        if (vm.state === 'STOPPED') {
          await ctx.client.call('vm.start', [vm.id], ctx.creds);
        } else {
          const r = await ctx.client.call<unknown>('vm.restart', [vm.id], ctx.creds);
          const job = describeAccepted(r);
          if (typeof job['jobId'] === 'number') {
            const wait = await waitForJob(ctx, job['jobId'], 150_000);
            if (wait.state === 'RUNNING') {
              notes[n] = 'Restart initiated — still in progress on the appliance';
              restarted++;
              continue;
            }
            if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
              errors[n] = wait.error ?? `Restart job ended in state ${wait.state}`;
              continue;
            }
          }
        }
        restarted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { restarted, missing, ...(Object.keys(notes).length ? { notes } : {}), ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsSuspendAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.suspend',
  label: 'Suspend VM(s)',
  description: 'Suspends the selected RUNNING VMs (vm.suspend) — RAM state is frozen, resume continues exactly where it left off.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to suspend' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const { toRun, skipped, missing } = planVmOutcomes(names, vms, new Set(['SUSPENDED']));

    let suspended = 0;
    const errors: Record<string, string> = {};
    for (const vm of toRun) {
      if (vm.state !== 'RUNNING') {
        skipped[vm.name] = `not running (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        await ctx.client.call('vm.suspend', [vm.id], ctx.creds);
        suspended++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[vm.name] = 'already suspended';
        else errors[vm.name] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { suspended, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsResumeAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.resume',
  label: 'Resume VM(s)',
  description: 'Resumes the selected SUSPENDED/PAUSED VMs (vm.resume).',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to resume' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let resumed = 0;
    const skipped: Record<string, string> = {};
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n);
        continue;
      }
      if (vm.state === 'RUNNING') {
        skipped[n] = 'already running';
        continue;
      }
      if (vm.state !== 'SUSPENDED' && vm.state !== 'PAUSED') {
        skipped[n] = `not suspended (${vm.state.toLowerCase()})`;
        continue;
      }
      try {
        await ctx.client.call('vm.resume', [vm.id], ctx.creds);
        resumed++;
      } catch (e) {
        if (isAlreadyInState(e)) skipped[n] = 'already running';
        else errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { resumed, skipped, missing, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsDeleteAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.delete',
  label: 'Delete VM(s)',
  description:
    'DELETES the selected VMs (vm.delete). Running VMs are stopped first. With removeStorage=true the backing zvols/disks are removed too — this is destructive.',
  module: 'VMs',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000,
  inputSchema: {
    names: { type: 'array', required: true, items: { type: 'string', minLength: 1 }, description: 'VM names to delete' },
    removeStorage: { type: 'boolean', required: false, default: false, description: 'Also delete the VMs\' backing storage (zvols)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const names = strArray(input, 'names');
    if (names.length === 0) return { success: false, details: { error: 'No VM names provided' } };
    const removeStorage = input['removeStorage'] === true;
    const vms = await listVms(ctx);
    const byName = new Map(vms.map((v) => [v.name, v]));

    let deleted = 0;
    const missing: string[] = [];
    const errors: Record<string, string> = {};
    for (const n of names) {
      const vm = byName.get(n);
      if (!vm) {
        missing.push(n); // already gone — nothing to do
        continue;
      }
      try {
        // vm.delete refuses running guests — stop first (bounded job wait).
        if (vm.state === 'RUNNING') {
          const r = await ctx.client.call<unknown>('vm.stop', [vm.id], ctx.creds);
          const job = describeAccepted(r);
          if (typeof job['jobId'] === 'number') {
            const wait = await waitForJob(ctx, job['jobId'], 150_000);
            if (wait.state !== 'RUNNING' && wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
              errors[n] = `Could not stop before delete: ${wait.error ?? `stop job ended in state ${wait.state}`}`;
              continue;
            }
          }
        }
        await ctx.client.call('vm.delete', [vm.id, removeStorage ? { zvols: true } : {}], ctx.creds);
        deleted++;
      } catch (e) {
        errors[n] = e instanceof Error ? e.message : String(e);
      }
    }
    return { success: Object.keys(errors).length === 0, applied: true, details: { deleted, missing, removeStorage, ...(Object.keys(errors).length ? { errors } : {}) } };
  },
};

const vmsNicChoicesAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-choices',
  label: 'List attachable NIC interfaces',
  description: 'Read-only list of the bridges and MACVLANs this appliance can attach to VMs (vm.device.nic_attach_choices). Feeds the VMs page attach dialog.',
  module: 'VMs',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  inputSchema: {},
  async execute(ctx: TruenasActionContext): Promise<ActionResult> {
    const r = await ctx.client.call<{ BRIDGE?: string[]; MACVLAN?: string[] }>('vm.device.nic_attach_choices', [], ctx.creds);
    return {
      success: true,
      details: {
        bridges: Array.isArray(r?.BRIDGE) ? (r.BRIDGE as string[]) : [],
        macvlans: Array.isArray(r?.MACVLAN) ? (r.MACVLAN as string[]) : [],
      },
    };
  },
};

const vmsNicAttachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-attach',
  label: 'Attach NIC to VM',
  description:
    'Attaches a network interface to ONE VM (vm.device.create with dtype NIC). nicAttach is a bridge or MACVLAN from vms.nic-choices; omit mac to let the appliance assign one.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    nicAttach: { type: 'string', required: true, minLength: 1, description: 'Bridge or MACVLAN interface to attach (from vms.nic-choices)' },
    type: { type: 'string', required: false, enum: ['BRIDGE', 'MACVLAN'], default: 'BRIDGE', description: 'NIC attachment kind' },
    mac: { type: 'string', required: false, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'Optional fixed MAC (appliance assigns one when omitted)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    const nicAttach = str(input, 'nicAttach');
    if (!nicAttach) return { success: false, details: { error: 'nicAttach (bridge/MACVLAN) is required' } };
    const type = (str(input, 'type') ?? 'BRIDGE').toUpperCase();
    if (type !== 'BRIDGE' && type !== 'MACVLAN') return { success: false, details: { error: `Unsupported NIC type "${type}" (expected BRIDGE or MACVLAN)` } };
    const mac = str(input, 'mac');

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    try {
      const attributes: Record<string, unknown> = { dtype: 'NIC', type, nic_attach: nicAttach };
      if (mac) attributes['mac'] = mac;
      await ctx.client.call('vm.device.create', [{ id: vm.id, attributes }], ctx.creds);
      return { success: true, applied: true, details: { name, nicAttach, type, ...(mac ? { mac } : {}), note: 'NIC attached — visible after the next inventory poll.' } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
  },
};

const vmsNicDetachAction: ActionDescriptor<TruenasActionContext> = {
  id: 'vms.nic-detach',
  label: 'Detach NIC from VM',
  description:
    'Removes ONE network interface from a VM (vm.device.delete). The target NIC is identified by its MAC; the integer device id is resolved via vm.query.',
  module: 'VMs',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'VM name' },
    mac: { type: 'string', required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$', description: 'MAC of the NIC to remove' },
    force: { type: 'boolean', required: false, default: false, description: 'Force removal even if the appliance would otherwise refuse' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    const mac = (str(input, 'mac') ?? '').toLowerCase();
    if (!name) return { success: false, details: { error: 'VM name is required' } };
    if (!mac) return { success: false, details: { error: 'NIC MAC is required' } };

    const vms = await listVms(ctx);
    const vm = vms.find((v) => v.name === name);
    if (!vm) return { success: false, details: { error: `VM "${name}" not found on this appliance` } };

    // Resolve the integer device id of the NIC with this MAC. The id sits at the
    // entry top level (TrueNAS 26+ nested shape) or flat inside attrs (legacy).
    let deviceId: number | null = null;
    for (const d of vm.devices) {
      const dev = normalizeVmDevice(d);
      if (!dev || dev.dtype !== 'NIC') continue;
      const dmac = pickString(dev.attrs, ['mac']);
      if (!dmac || dmac.toLowerCase() !== mac) continue;
      const raw = d as Record<string, unknown>;
      deviceId = typeof raw['id'] === 'number' ? (raw['id'] as number) : typeof dev.attrs['id'] === 'number' ? (dev.attrs['id'] as number) : null;
      break;
    }
    if (deviceId === null) return { success: false, details: { error: `No NIC with MAC ${mac.toUpperCase()} on VM "${name}"` } };

    try {
      const force = input['force'] === true;
      await ctx.client.call('vm.device.delete', [deviceId, force ? { force: true } : {}], ctx.creds);
      return { success: true, applied: true, details: { name, mac: mac.toUpperCase(), deviceId, note: 'NIC detached — visible after the next inventory poll.' } };
    } catch (e) {
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
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

/** Quote a YAML scalar when it could be misread (leading indicator chars,
 * trailing space, colon-space, or looking like a number/bool/null). */
function yamlScalar(v: string): string {
  if (v === '') return "''";
  const risky = /^[\s#&*!|>%@`"'{}\[\],-]/.test(v) || /[:\s]$/.test(v) || /:\s/.test(v);
  if (!risky && !/^[0-9]+(\.[0-9]+)?$/.test(v) && !/^(true|false|null|yes|no|on|off)$/i.test(v)) return v;
  const escaped = v.replace(/\\/g, '\\\\').replace(/'/g, "''");
  return `'${escaped}'`;
}

/** Serializes a TrueNAS app config object (the structured `services`/`networks`
 * map of a custom app) into Docker Compose YAML. TrueNAS 26 does NOT store the
 * original compose string for custom apps — only this structured form — so the
 * clone/duplicate flow reconstructs an editable YAML from it. Keys are sorted
 * alphabetically (compose is order-insensitive); values keep their native types.
 */
function serializeComposeYaml(cfg: Record<string, unknown>): string {
  const TOP_KEYS = ['networks', 'services', 'volumes', 'configs', 'secrets'];
  const lines: string[] = [];
  for (const key of TOP_KEYS) {
    if (!(key in cfg)) continue;
    const v = cfg[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      lines.push(`${key}:`);
      for (const [name, def] of Object.entries(v as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
        const d = def;
        if (d && typeof d === 'object' && !Array.isArray(d)) {
          lines.push(`  ${name}:`);
          for (const [fk, fv] of Object.entries(d as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
            const ind = '    ';
            if (fv && typeof fv === 'object' && !Array.isArray(fv)) {
              lines.push(`${ind}${fk}:`);
              for (const [gk, gv] of Object.entries(fv as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
                if (gv && typeof gv === 'object' && !Array.isArray(gv)) {
                  lines.push(`${ind}  ${gk}:`);
                  for (const [hk, hv] of Object.entries(gv as Record<string, unknown>).sort(([a], [b]) => a.localeCompare(b))) {
                    if (hv && typeof hv === 'object') lines.push(`${ind}    ${hk}: ${JSON.stringify(hv)}`);
                    else if (typeof hv === 'string') lines.push(`${ind}    ${hk}: ${yamlScalar(hv)}`);
                    else lines.push(`${ind}    ${hk}: ${String(hv ?? '')}`);
                  }
                } else if (Array.isArray(gv)) {
                  if (gv.length === 0) { lines.push(`${ind}  ${gk}: []`); continue; }
                  lines.push(`${ind}  ${gk}:`);
                  for (const item of gv) lines.push(`${ind}    - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
                } else if (typeof gv === 'string') lines.push(`${ind}  ${gk}: ${yamlScalar(gv)}`);
                else lines.push(`${ind}  ${gk}: ${String(gv ?? '')}`);
              }
            } else if (Array.isArray(fv)) {
              if (fv.length === 0) { lines.push(`${ind}${fk}: []`); continue; }
              lines.push(`${ind}${fk}:`);
              for (const item of fv) lines.push(`${ind}  - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
            } else if (typeof fv === 'string') lines.push(`${ind}${fk}: ${yamlScalar(fv)}`);
            else lines.push(`${ind}${fk}: ${String(fv ?? '')}`);
          }
        } else {
          lines.push(`  ${name}: ${JSON.stringify(d)}`);
        }
      }
    } else if (Array.isArray(v)) {
      if (v.length === 0) { lines.push(`${key}: []`); continue; }
      lines.push(`${key}:`);
      for (const item of v) lines.push(`  - ${typeof item === 'string' ? yamlScalar(item) : JSON.stringify(item)}`);
    } else if (typeof v === 'string') {
      lines.push(`${key}: ${yamlScalar(v)}`);
    }
  }
  return lines.join('\n');
}

/**
 * Reads the current compose YAML of a custom app. The webapp's Containers page
 * uses this to pre-fill its YAML editor (and the Create-app dialog's duplicate
 * flow). TrueNAS 26 stores custom apps as a STRUCTURED config ({networks,
 * services}) — there is no original compose string — so it is reconstructed as
 * editable YAML. Catalog apps return their template identity + saved values
 * instead, which drives the catalog-clone prefill.
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

    // app.query with retrieve_config returns the full config. Long budget +
    // retry — on a busy appliance (250+ apps) this query can take 30 s+, and
    // silently falling back to app.config would return a DIFFERENT shape and
    // break the clone prefill.
    let cfg: Record<string, unknown> | null = null;
    // Row-level custom_app flag — ALWAYS present on TrueNAS 26 and the most
    // reliable catalog-vs-custom signal (the config object itself omits it).
    let rowCustomApp: boolean | null = null;
    try {
      const rows = await ctx.client.call<Record<string, unknown>[]>('app.query', [[], { extra: { retrieve_config: true } }], ctx.creds, 45_000);
      for (const r of rows ?? []) {
        if ((pickString(r, ['name']) ?? '') === name) {
          const c = r['config'];
          cfg = c && typeof c === 'object' ? (c as Record<string, unknown>) : null;
          rowCustomApp = typeof r['custom_app'] === 'boolean' ? (r['custom_app'] as boolean) : null;
          break;
        }
      }
    } catch (e) {
      return { success: false, details: { error: `Could not read config for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (!cfg) {
      // Not found in the query — try app.config directly (older appliances).
      try {
        cfg = await ctx.client.call<Record<string, unknown>>('app.config', [name], ctx.creds);
      } catch (e) {
        return { success: false, details: { error: `Could not read config for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
      }
    }

    const cfgCustomApp = typeof cfg['custom_app'] === 'boolean' ? (cfg['custom_app'] as boolean) : null;
    // Prefer the row flag; fall back to the config's own field on older boxes.
    const isCatalog = rowCustomApp !== null ? rowCustomApp === false : (cfgCustomApp === false || typeof pickString(cfg, ['catalog_app']) === 'string');

    // Catalog apps have no editable compose string — their configuration is the
    // saved `values` map plus the template identity. Return those so the webapp's
    // clone/duplicate flow can re-open the catalog form pre-filled (change one
    // setting, redeploy). Custom apps keep the existing YAML payload.
    if (isCatalog) {
      const catalogApp = pickString(cfg, ['catalog_app']);
      const valuesRaw = cfg['values'];
      return {
        success: true,
        details: {
          name,
          yaml: '',
          customApp: false,
          catalogApp,
          train: pickString(cfg, ['train']) ?? 'stable',
          values: valuesRaw && typeof valuesRaw === 'object' && !Array.isArray(valuesRaw) ? (valuesRaw as Record<string, unknown>) : {},
        },
      };
    }

    // Custom apps — the original compose string when present (older appliances);
    // otherwise reconstruct editable YAML from the structured config. The
    // top-level `networks:` map MUST be included — it's where users change the
    // network of a cloned app.
    const yamlStr = pickString(cfg, ['custom_compose_config_string']);
    let yaml: string;
    if (yamlStr && yamlStr.trim() !== '') {
      yaml = yamlStr;
    } else {
      yaml = serializeComposeYaml(cfg);
    }
    if (yaml.trim() === '') return { success: false, details: { error: `No editable compose config found for "${name}"` } };

    return { success: true, details: { name, yaml, customApp: true } };
  },
};

/**
 * Reads the recent log output of one app's container(s). TrueNAS 26 exposes NO
 * RPC for app/container logs (verified against the full core.get_methods
 * catalog — no app.logs / docker.logs / journal method exists), so this runs
 * `docker logs --tail N` over the shared SSH pool — the same channel used for
 * per-container enrichment. Requires a bound `ssh` credential slot; without one
 * it reports a clear "bind an SSH secret" error instead of failing opaquely.
 */
const containersLogsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.logs.read',
  label: 'Read container logs',
  description: 'Returns the recent log output (docker logs --tail) of a single app\'s container(s). Requires an SSH credential bound to this device.',
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'App name to read the logs of' },
    tail: { type: 'number', required: false, min: 20, max: 5000, default: 300, description: 'Number of trailing log lines (default 300)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };
    const tailRaw = typeof input['tail'] === 'number' ? Math.floor(input['tail']) : 300;
    const tail = Math.min(5000, Math.max(20, Number.isFinite(tailRaw) ? tailRaw : 300));

    // SSH slot — the ONLY log path on TrueNAS (no API method exists).
    const sshCreds = resolveSshCredentials(ctx.rawCredentials ?? undefined, { slotOnly: true });
    if (!sshCreds) {
      return { success: false, details: { error: 'No SSH credential is bound to this device — container logs need the optional "SSH" secret slot (username/password or key pair).' } };
    }

    // Resolve the app's docker container ids via RPC (no SSH needed for this).
    let idMap: Record<string, { id?: string; service_name?: string; state?: string }> | null = null;
    try {
      const r = await ctx.client.call<Record<string, { id?: string; service_name?: string; state?: string }>>('app.container_ids', [name, { alive_only: false }], ctx.creds, 20_000);
      if (r && typeof r === 'object' && Object.keys(r).length > 0) idMap = r;
    } catch (e) {
      return { success: false, details: { error: `Could not resolve containers for "${name}": ${e instanceof Error ? e.message : String(e)}` } };
    }
    if (!idMap || Object.keys(idMap).length === 0) {
      return { success: false, details: { error: `App "${name}" has no containers (it may not exist or is not deployed yet)` } };
    }

    // ONE combined SSH command — every container in a single exec (reuses the pooled session).
    const parts = Object.values(idMap)
      .map((c) => c.id ?? '')
      .filter((id) => /^[a-f0-9]{12,64}$/i.test(id))
      .slice(0, 32); // defensive cap — a single app should never have more than a handful
    if (parts.length === 0) return { success: false, details: { error: `App "${name}" has no resolvable container ids` } };

    const host = (ctx.host ?? '').trim().replace(/^https?:\/\//i, '').replace(/\/+$/, '');
    if (!host) return { success: false, details: { error: 'No management address available for the SSH log read' } };

    // ONE combined SSH command — every container in a single exec (reuses the pooled session).
    const cmd = parts.map((id) => `echo "=== ${id}"; docker logs --tail ${tail} --timestamps ${id} 2>&1 | tail -c 512000`).join(' ; ');
    try {
      const client = await sshPool.get(host, 22, sshCreds);
      const r = await client.exec(cmd, sshCreds);
      if (r.code !== 0 && !r.stdout) {
        return { success: false, details: { error: `docker logs over SSH failed (exit ${r.code}): ${r.stderr.slice(0, 300) || 'no output'}` } };
      }
      // Split the combined output back into per-container sections. Markers are
      // full 64-char ids in command order — locate each marker, section ends at
      // the NEXT marker (or end of output).
      const byId = new Map(Object.values(idMap).map((c) => [c.id ?? '', c]));
      const markers: Array<{ id: string; idx: number }> = [];
      for (const id of parts) {
        const idx = r.stdout.indexOf(`=== ${id}`);
        if (idx !== -1) markers.push({ id, idx });
      }
      const containers: Array<{ id: string; service?: string; state?: string; logs: string }> = [];
      for (let i = 0; i < markers.length; i++) {
        const m = markers[i];
        const end = i + 1 < markers.length ? markers[i + 1].idx : r.stdout.length;
        const c = byId.get(m.id);
        containers.push({ id: m.id, service: c?.service_name, state: c?.state, logs: r.stdout.slice(m.idx + (`=== ${m.id}`).length, end).trim() });
      }
      if (containers.length === 0) {
        return { success: false, details: { error: `docker logs over SSH returned no parseable output${r.stderr ? ` (${r.stderr.slice(0, 200)})` : ''}` } };
      }
      return { success: true, details: { name, tail, containers } };
    } catch (e) {
      if (e instanceof SshError) return { success: false, details: { error: `SSH to the appliance failed: ${e.message}` } };
      return { success: false, details: { error: e instanceof Error ? e.message : String(e) } };
    }
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

// --- Catalog (app store) + install -------------------------------------------------
// TrueNAS 25.04+/26 renamed the community-apps API: `communityapps.*` is gone,
// replaced by `catalog.trains`, `catalog.apps({trains:[...]})` and
// `catalog.get_app_details(name, {train})`. Installation is `app.create` — a
// JOB method (returns a job id; the work runs server-side). Verified live on
// 26.0.0-BETA: AppCreateArgs = { custom_app, app_name, catalog_app?, train?
// ('stable'), version? ('latest'), values{}, custom_compose_config_string }.

/** One template summary as surfaced to the webapp's Create-app dialog. */
interface CatalogTemplateSummary {
  name: string; // catalog slug (catalog_app)
  title: string;
  description?: string;
  iconUrl?: string;
  latestVersion?: string;
  latestHumanVersion?: string;
  categories?: string[];
  tags?: string[];
  recommended?: boolean;
  healthy?: boolean;
}

/** TrueNAS question-schema node (the appliance's own form definition). */
interface TnQuestion {
  variable: string;
  label?: string;
  group?: string;
  schema?: Record<string, unknown>;
}

function strOr(input: Record<string, unknown>, key: string, fallback: string): string {
  const v = input[key];
  return typeof v === 'string' && v.trim() !== '' ? v : fallback;
}

/** Maps a TrueNAS scalar type onto the UNM InputSchemaProperty types. */
function scalarType(t: string): 'string' | 'number' | 'boolean' {
  if (t === 'number') return 'number';
  if (t === 'boolean') return 'boolean';
  return 'string';
}

/** Converts a leaf attr (no group nesting expected below attrs). */
function convertAttr(a: TnQuestion): Record<string, unknown> | null {
  const s = a.schema ?? {};
  const type = String(s['type'] ?? 'string');
  if (type === 'dict' || type === 'list') return convertQuestion({ ...a, schema: s });
  const out: Record<string, unknown> = { type: scalarType(type), label: a.label || undefined, description: pickString(s, ['description']) };
  if (s['required'] === true) out['required'] = true;
  if (s['default'] !== undefined) out['default'] = s['default'];
  const enumRaw = s['enum'];
  if (Array.isArray(enumRaw)) {
    // TrueNAS enums are [{value, description?}] — flatten to values.
    out['enum'] = enumRaw.map((e: unknown) => (e && typeof e === 'object' ? (e as Record<string, unknown>)['value'] : e));
  }
  const validChars = pickString(s, ['valid_chars']);
  if (validChars) out['pattern'] = validChars;
  return out;
}

/**
 * Converts one TrueNAS question-schema node into the UNM InputSchemaProperty
 * shape (the subset SchemaForm renders). Handles the nesting styles observed
 * in real templates: dict groups with `attrs[]`, list-of-dict rows, enums as
 * {value, description}[], valid_chars → pattern. show_if is dropped — fields
 * are always rendered; the appliance re-validates everything on install.
 */
function convertQuestion(q: TnQuestion): Record<string, unknown> | null {
  const s = q.schema ?? {};
  const type = String(s['type'] ?? 'string');

  if (type === 'dict') {
    // Group container — its fields live in attrs[].
    const attrs = Array.isArray(s['attrs']) ? (s['attrs'] as TnQuestion[]) : [];
    const properties: Record<string, unknown> = {};
    for (const a of attrs) {
      if (!a.variable) continue;
      const sub = convertAttr(a);
      if (sub) properties[a.variable] = sub;
    }
    return { type: 'object', label: q.label || undefined, description: pickString(s, ['description']), properties };
  }

  if (type === 'list') {
    const itemsRaw = Array.isArray(s['items']) ? s['items'] : [];
    const first = itemsRaw.length > 0 ? (itemsRaw[0] as TnQuestion) : null;
    let itemProp: Record<string, unknown> = { type: 'string' };
    if (first) {
      const isDict = String((first.schema ?? {})['type']) === 'dict';
      if (isDict) {
        const attrs = Array.isArray((first.schema ?? {})['attrs']) ? ((first.schema as Record<string, unknown>)['attrs'] as TnQuestion[]) : [];
        const properties: Record<string, unknown> = {};
        for (const a of attrs) {
          if (!a.variable) continue;
          const sub = convertAttr(a);
          if (sub) properties[a.variable] = sub;
        }
        itemProp = { type: 'object', properties };
      } else {
        itemProp = convertAttr(first) ?? { type: 'string' };
      }
    }
    return {
      type: 'array',
      label: q.label || undefined,
      description: pickString(s, ['description']),
      default: s['default'] !== undefined ? s['default'] : [],
      items: itemProp,
    };
  }

  // Scalar (string/number/boolean) — may carry an enum of {value, description}.
  const out: Record<string, unknown> = { type: scalarType(type), label: q.label || undefined, description: pickString(s, ['description']) };
  if (s['required'] === true) out['required'] = true;
  if (s['default'] !== undefined) out['default'] = s['default'];
  const enumRaw = s['enum'];
  if (Array.isArray(enumRaw)) {
    out['enum'] = enumRaw.map((e: unknown) => (e && typeof e === 'object' ? (e as Record<string, unknown>)['value'] : e));
  }
  const validChars = pickString(s, ['valid_chars']);
  if (validChars) out['pattern'] = validChars;
  return out;
}

/** Picks the version entry to use: explicit `version` input, else latest. */
function pickVersionEntry(versions: Record<string, unknown>, wanted?: string): { key: string; entry: Record<string, unknown> } | null {
  if (!versions || typeof versions !== 'object') return null;
  const keys = Object.keys(versions);
  if (keys.length === 0) return null;
  if (wanted && versions[wanted]) return { key: wanted, entry: versions[wanted] as Record<string, unknown> };
  // "latest" or no preference → the highest version-ish key.
  const sorted = [...keys].sort((a, b) => compareVersions(b, a));
  return { key: sorted[0], entry: versions[sorted[0]] as Record<string, unknown> };
}

/** Loose version comparator (handles "1.2.3" and "26.04.3.2.1_1.5.28" style). */
function compareVersions(a: string, b: string): number {
  const pa = a.split(/[._-]/).map((x) => parseInt(x, 10)).filter((n) => !Number.isNaN(n));
  const pb = b.split(/[._-]/).map((x) => parseInt(x, 10)).filter((n) => !Number.isNaN(n));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0;
    const y = pb[i] ?? 0;
    if (x !== y) return x - y;
  }
  return 0;
}

/** catalog.templates.list — read-only template gallery for the Create-app dialog. */
const catalogTemplatesListAction: ActionDescriptor<TruenasActionContext> = {
  id: 'catalog.templates.list',
  label: 'List app store templates',
  description:
    "Returns the appliance's community-app catalog (per train) with name, title, description, icon and latest version — drives the Create-app dialog. Read-only.",
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000, // catalog.apps can be slow right after a catalog sync
  inputSchema: {
    train: { type: 'string', required: false, description: 'Catalog train to list (default: stable)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const train = strOr(input, 'train', 'stable');

    let trains: string[];
    try {
      const t = await callWithRetry<unknown>(ctx, 'catalog.trains', []);
      trains = Array.isArray(t) ? (t as string[]) : ['stable'];
    } catch {
      trains = [train]; // catalog.trains missing on older boxes — fall back to the requested train
    }

    let byTrain: Record<string, unknown>;
    try {
      const r = await callWithRetry<Record<string, unknown>>(ctx, 'catalog.apps', [{ trains: [train] }]);
      byTrain = r && typeof r === 'object' ? r : {};
    } catch (e) {
      // Pre-25.04 boxes lack the catalog.* namespace — surface a clear error so
      // the dialog can hide itself for this device.
      return { success: false, details: { error: `Catalog API unavailable on this appliance (${e instanceof Error ? e.message : String(e)})` } };
    }

    const appMap = (byTrain[train] ?? {}) as Record<string, Record<string, unknown>>;
    const templates: CatalogTemplateSummary[] = Object.values(appMap).map((a) => ({
      name: pickString(a, ['name']) ?? '',
      title: pickString(a, ['title']) ?? pickString(a, ['name']) ?? '',
      description: pickString(a, ['description']),
      iconUrl: pickString(a, ['icon_url']),
      latestVersion: pickString(a, ['latest_version']),
      latestHumanVersion: pickString(a, ['latest_human_version']),
      categories: Array.isArray(a['categories']) ? (a['categories'] as string[]) : undefined,
      tags: Array.isArray(a['tags']) ? (a['tags'] as string[]) : undefined,
      recommended: typeof a['recommended'] === 'boolean' ? (a['recommended'] as boolean) : undefined,
      healthy: typeof a['healthy'] === 'boolean' ? (a['healthy'] as boolean) : undefined,
    })).filter((t) => t.name !== '');

    return { success: true, details: { train, trains, templates } };
  },
};

/** template.details.read — one template's config schema for the form. */
const templateDetailsReadAction: ActionDescriptor<TruenasActionContext> = {
  id: 'template.details.read',
  label: 'Read template config schema',
  description:
    "Returns one catalog template's configuration questions (converted to UNM form fields) plus its default values — pre-fills the Create-app dialog. Read-only.",
  module: 'Containers',
  riskLevel: 'read' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, description: 'Catalog template slug (e.g. "collabora")' },
    train: { type: 'string', required: false, description: 'Catalog train (default: stable)' },
    version: { type: 'string', required: false, description: 'Specific version to read the schema of (default: latest)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'Template name is required' } };
    const train = strOr(input, 'train', 'stable');

    let d: Record<string, unknown>;
    try {
      d = await callWithRetry<Record<string, unknown>>(ctx, 'catalog.get_app_details', [name, { train }]);
    } catch (e) {
      return { success: false, details: { error: `Could not read template "${name}" from train "${train}": ${e instanceof Error ? e.message : String(e)}` } };
    }

    const versions = (d['versions'] ?? {}) as Record<string, unknown>;
    const picked = pickVersionEntry(versions, str(input, 'version'));
    if (!picked) return { success: false, details: { error: `Template "${name}" has no version entries` } };
    const ve = picked.entry;

    // Convert the question schema into UNM InputSchema shape.
    const questions = (((ve['schema'] as Record<string, unknown> | undefined)?.['questions']) ?? []) as TnQuestion[];
    const fields: Record<string, unknown> = {};
    for (const q of questions) {
      if (!q.variable) continue;
      const converted = convertQuestion(q);
      if (converted) fields[q.variable] = converted;
    }

    // Group layout for the dialog's collapsible sections. TrueNAS questions
    // carry a `group` name; dict containers are self-contained sub-forms and
    // become their own section; ungrouped scalars land in "General". Order of
    // first appearance is preserved (matches the appliance's form order).
    const groupOrder: string[] = [];
    const groupsByTitle: Record<string, string[]> = {};
    for (const q of questions) {
      if (!q.variable || !fields[q.variable]) continue;
      const converted = fields[q.variable] as Record<string, unknown>;
      let title: string;
      if (converted['type'] === 'object' && converted['properties']) {
        title = String(converted['label'] ?? q.label ?? q.variable); // dict sub-form → own section
      } else if (typeof q.group === 'string' && q.group.trim() !== '') {
        title = q.group;
      } else {
        title = 'General';
      }
      if (!groupsByTitle[title]) {
        groupsByTitle[title] = [];
        groupOrder.push(title);
      }
      groupsByTitle[title].push(q.variable);
    }
    const groups = groupOrder.map((title) => ({ title, fields: groupsByTitle[title] }));

    // Default values shipped with the template (the appliance's own defaults).
    const values = (ve['values'] ?? {}) as Record<string, unknown>;

    return {
      success: true,
      details: {
        name,
        train,
        version: picked.key,
        humanVersion: pickString(ve, ['human_version']),
        title: pickString(d, ['title']) ?? name,
        description: pickString(d, ['description']),
        fields, // InputSchema-compatible map for SchemaForm
        values, // defaults to pre-fill the form (appliance-side source of truth)
        groups, // [{title, fields[]}] — section layout for the dialog
      },
    };
  },
};

/** Waits for a TrueNAS job (by id from app.create etc.) until it settles or budget runs out. */
async function waitForJob(
  ctx: TruenasActionContext,
  jobId: number,
  budgetMs: number,
): Promise<{ state: string; error?: string }> {
  const deadline = Date.now() + budgetMs;
  for (;;) {
    let jobs: Record<string, unknown>[];
    try {
      jobs = await ctx.client.call<Record<string, unknown>[]>('core.get_jobs', [], ctx.creds);
    } catch (e) {
      return { state: 'UNKNOWN', error: `Lost track of job ${jobId}: ${e instanceof Error ? e.message : String(e)}` };
    }
    const j = (jobs ?? []).find((x) => x['id'] === jobId);
    if (!j) return { state: 'UNKNOWN', error: `Job ${jobId} no longer listed` };
    const state = pickString(j, ['state']) ?? '';
    if (state !== 'RUNNING') {
      const errRaw = j['error'];
      return { state, ...(errRaw ? { error: String(errRaw) } : {}) };
    }
    if (Date.now() >= deadline) return { state: 'RUNNING', error: `Still running after ${Math.round(budgetMs / 1000)}s — the install continues on the appliance; check its Apps page.` };
    await new Promise((r) => setTimeout(r, 3_000));
  }
}

/** containers.install — creates a NEW app (catalog template or custom compose). */
const containersInstallAction: ActionDescriptor<TruenasActionContext> = {
  id: 'containers.install',
  label: 'Create app (install)',
  description:
    'Creates a new app on the appliance via app.create — either from a catalog template (with its config values) or as a custom Docker Compose stack. Runs to completion (image pulls included), so it may take several minutes.',
  module: 'Containers',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 900_000, // image pulls dominate — give the plan executor a 15-min budget
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 40, pattern: '^[a-z]([-a-z0-9]*[a-z0-9])?$', description: 'App instance name (lowercase slug — TrueNAS enforces this)' },
    mode: { type: 'string', required: true, enum: ['catalog', 'custom'], description: 'catalog = install a store template; custom = deploy your own compose YAML' },
    catalogApp: { type: 'string', required: false, description: 'Catalog template slug (required when mode=catalog)' },
    train: { type: 'string', required: false, description: 'Catalog train (default stable)' },
    version: { type: 'string', required: false, description: 'Template version to install (default latest)' },
    config: { type: 'object', required: false, properties: {}, description: 'Template configuration values (mode=catalog)' },
    composeString: { type: 'string', required: false, minLength: 2, description: 'Docker Compose YAML (required when mode=custom)' },
  },
  async execute(ctx: TruenasActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const name = str(input, 'name');
    if (!name) return { success: false, details: { error: 'App name is required' } };
    const mode = strOr(input, 'mode', 'catalog');

    // Idempotency guard — an app with this name already exists.
    try {
      const apps = await listApps(ctx);
      if (apps.some((a) => a.name === name)) {
        return { success: false, details: { error: `An app named "${name}" already exists on this appliance` } };
      }
    } catch { /* best-effort guard — app.create will reject duplicates anyway */ }

    let params: Record<string, unknown>;
    if (mode === 'catalog') {
      const catalogApp = str(input, 'catalogApp');
      if (!catalogApp) return { success: false, details: { error: 'catalogApp is required when mode=catalog' } };
      params = {
        custom_app: false,
        app_name: name,
        catalog_app: catalogApp,
        train: strOr(input, 'train', 'stable'),
        version: strOr(input, 'version', 'latest'),
        values: input['config'] && typeof input['config'] === 'object' ? (input['config'] as Record<string, unknown>) : {},
      };
    } else if (mode === 'custom') {
      const composeString = str(input, 'composeString');
      if (!composeString) return { success: false, details: { error: 'composeString is required when mode=custom' } };
      params = { custom_app: true, app_name: name, custom_compose_config_string: composeString };
    } else {
      return { success: false, details: { error: `Unknown mode "${mode}" (expected catalog|custom)` } };
    }

    // app.create is a JOB method — it returns the job id immediately.
    let jobId: number;
    try {
      const r = await ctx.client.call<unknown>('app.create', [params], ctx.creds);
      if (typeof r !== 'number') return { success: false, details: { error: `Unexpected app.create result: ${JSON.stringify(r)}` } };
      jobId = r;
    } catch (e) {
      // The socket can drop while a long install runs — treat as "initiated" only
      // when the transport died AFTER dispatch (same convention as reboot).
      if (e instanceof TruenasRpcError && /timed out|closed|unresponsive/i.test(e.message)) {
        return { success: true, applied: true, details: { note: 'Install accepted — connection dropped while the appliance worked; check its Apps page.' } };
      }
      throw e;
    }

    // Wait for the job to settle (budget = our timeout minus a safety margin).
    const wait = await waitForJob(ctx, jobId, 840_000);
    if (wait.state === 'RUNNING') {
      return { success: true, applied: true, details: { jobId, state: wait.state, note: wait.error } };
    }
    if (wait.state !== 'SUCCESS' && wait.state !== 'FINISHED') {
      return { success: false, details: { jobId, state: wait.state, error: wait.error ?? `Job ended in state ${wait.state}` } };
    }
    return { success: true, applied: true, details: { jobId, state: wait.state, name, mode } };
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
  vmsStartAction,
  vmsStopAction,
  vmsKillAction,
  vmsRestartAction,
  vmsSuspendAction,
  vmsResumeAction,
  vmsDeleteAction,
  vmsNicChoicesAction,
  vmsNicAttachAction,
  vmsNicDetachAction,
  imagesDeleteAction,
  composeConfigReadAction,
  containersLogsReadAction,
  containersUpdateAction,
  catalogTemplatesListAction,
  templateDetailsReadAction,
  containersInstallAction,
]);
