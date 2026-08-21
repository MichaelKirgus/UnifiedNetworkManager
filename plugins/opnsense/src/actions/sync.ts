import * as be from '../client/editions';
import { ActionDescriptor } from './types';

/**
 * Business Edition sync actions. These use OPNBE's `opncentral/sync` surface —
 * the same central-sync API OPNcentral uses: section-level read/write with md5
 * drift detection. They are `beOnly`; on CE appliances the planner falls back to
 * the per-module read/apply equivalents (ceFallback) so one intent works across
 * both editions.
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const syncActions: ActionDescriptor[] = [
  {
    id: 'sync.classes.read',
    label: 'Read synchronizable config sections (+ md5)',
    module: 'Sync',
    riskLevel: 'read',
    deviceCount: 1,
    beOnly: true,
    ceFallback: undefined, // no CE equivalent — the catalog simply omits it on CE devices at plan time
    inputSchema: {},
    execute: async (ctx) => {
      const res = await be.listSyncClasses(ctx.client);
      return { success: res.ok, details: dataOf(res as { ok: boolean; status: number; data: unknown }) ?? {} };
    },
  },
  {
    id: 'sync.section.read',
    label: 'Read one config section (BE)',
    module: 'Sync',
    riskLevel: 'read',
    deviceCount: 1,
    beOnly: true,
    inputSchema: { path: { type: 'string', required: true, description: 'Config path, e.g. OPNsense.Firewall.Alias' } },
    execute: async (ctx, input) => {
      const res = await be.readConfigPath(ctx.client, String(input.path));
      return { success: res.ok, details: dataOf(res as { ok: boolean; status: number; data: unknown }) ?? {} };
    },
  },
  {
    id: 'sync.section.apply',
    label: 'Apply config section (BE reconfigure)',
    module: 'Sync',
    riskLevel: 'dangerous',
    deviceCount: 1,
    beOnly: true,
    timeoutMs: 60_000,
    inputSchema: { payload: { type: 'object', required: true, description: 'Config data as returned by sync.section.read' } },
    execute: async (ctx, input) => {
      const res = await be.reconfigureSync(ctx.client, (input.payload as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: res.ok, details: dataOf(res as { ok: boolean; status: number; data: unknown }) ?? {} };
    },
  },
  {
    id: 'sync.driftCheck',
    label: 'Compare config sections against a reference (md5)',
    module: 'Sync',
    riskLevel: 'read',
    deviceCount: 1,
    beOnly: true,
    inputSchema: {
      /** md5 values to compare against, keyed by section id. */
      referenceMd5: { type: 'object', required: true },
    },
    execute: async (ctx, input) => {
      const res = await be.listSyncClasses(ctx.client);
      const classes = Array.isArray((res.data as { classes?: unknown })?.classes) ? ((res.data as { classes?: be.SyncClass[] }).classes ?? []) : [];
      const reference = (input.referenceMd5 ?? {}) as Record<string, string>;
      const drift: Record<string, { local: string; reference: string; inSync: boolean }> = {};
      for (const c of classes) {
        if (!c.id || !c.md5) continue;
        const ref = reference[c.id];
        if (ref === undefined) continue;
        drift[c.id] = { local: c.md5, reference: ref, inSync: c.md5 === ref };
      }
      return { success: res.ok, details: { drift, sectionsChecked: Object.keys(drift).length } };
    },
  },
  {
    id: 'sync.services.read',
    label: 'Read active services (BE)',
    module: 'Sync',
    riskLevel: 'read',
    deviceCount: 1,
    beOnly: true,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await be.listSyncServices(ctx.client);
      return { success: res.ok, details: dataOf(res as { ok: boolean; status: number; data: unknown }) ?? {} };
    },
  },
];
