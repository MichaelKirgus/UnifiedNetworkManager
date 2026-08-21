import * as ts from '../client/trafficshaper';
import { ActionDescriptor } from './types';

/** Trafficshaper actions (pipes + rules). Writes are staged; reconfigure activates. */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const trafficshaperActions: ActionDescriptor[] = [
  {
    id: 'trafficshaper.pipes.read',
    label: 'Read shaper pipes',
    module: 'TrafficShaper',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ts.searchPipes(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'trafficshaper.pipe.add',
    label: 'Add shaper pipe (staged)',
    module: 'TrafficShaper',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { pipe: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await ts.addPipe(ctx.client, (input.pipe as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'trafficshaper.pipe.delete',
    label: 'Delete shaper pipe (staged)',
    module: 'TrafficShaper',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ts.deletePipe(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'trafficshaper.rule.add',
    label: 'Add shaper rule (staged)',
    module: 'TrafficShaper',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { rule: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await ts.addRule(ctx.client, (input.rule as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'trafficshaper.rule.delete',
    label: 'Delete shaper rule (staged)',
    module: 'TrafficShaper',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ts.deleteRule(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'trafficshaper.reconfigure',
    label: 'Apply staged trafficshaper changes',
    module: 'TrafficShaper',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ts.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
