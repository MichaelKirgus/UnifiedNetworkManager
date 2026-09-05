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

export const registry = createRegistry<TruenasActionContext>([
  systemInfoAction,
  poolsReadAction,
  interfacesReadAction,
  systemRebootAction,
  systemShutdownAction,
  alertsDismissAction,
  alertsUndismissAction,
]);
