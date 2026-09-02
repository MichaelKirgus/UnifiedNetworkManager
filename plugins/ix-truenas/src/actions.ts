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

import { ActionDescriptor, ActionResult, createRegistry } from '@unm/plugin-sdk';
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

export const registry = createRegistry<TruenasActionContext>([
  systemInfoAction,
  poolsReadAction,
  interfacesReadAction,
  systemRebootAction,
  systemShutdownAction,
]);
