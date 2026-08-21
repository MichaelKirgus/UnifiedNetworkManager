import * as sys from '../client/system';
import * as backup from '../client/backup';
import { ActionDescriptor, ActionResult } from './types';

/**
 * System + snapshot actions. Snapshots are the appliance's native rollback
 * primitive: `snapshot.create` is auto-prepended to dangerous/staged plans so a
 * later `snapshot.restore` can undo them (the created uuid travels in the step
 * result for output-ref substitution).
 */

// Extracts the response body object when the call succeeded.
function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const systemActions: ActionDescriptor[] = [
  {
    id: 'system.status.read',
    label: 'Read system status',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.getSystemStatus(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? { status: res.status } };
    },
  },
  {
    id: 'system.info.read',
    label: 'Read system information',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.getSystemInformation(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.services.read',
    label: 'Read services + running state',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.searchServices(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.service.restart',
    label: 'Restart a service',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: { name: { type: 'string', required: true, description: 'Service name (e.g. pf, unbound, dnsmasq)' } },
    execute: async (ctx, input) => {
      const res = await sys.restartService(ctx.client, String(input.name));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.reboot',
    label: 'Reboot appliance',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.reboot(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'system.halt',
    label: 'Power off appliance',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 30_000,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await sys.halt(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  // --- Snapshots / backups -----------------------------------------------------

  {
    id: 'snapshot.create',
    label: 'Create config snapshot (rollback point)',
    module: 'System',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const supported = await backup.snapshotsSupported(ctx.client);
      if (!supported.ok || !supported.data) {
        return { success: false, error: `Snapshots not available on this appliance (HTTP ${supported.status})` };
      }
      const res = await backup.addSnapshot(ctx.client);
      const d = dataOf(res);
      const uuid = typeof d?.['uuid'] === 'string' ? (d['uuid'] as string) : undefined;
      return { success: res.ok, applied: res.ok, details: { snapshotUuid: uuid ?? null } };
    },
  },
  {
    id: 'snapshot.restore',
    label: 'Restore config snapshot',
    module: 'System',
    riskLevel: 'dangerous',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: { snapshotUuid: { type: 'string', required: true, description: 'Snapshot uuid (e.g. from a prior snapshot.create step)' } },
    execute: async (ctx, input) => {
      const res = await backup.activateSnapshot(ctx.client, String(input.snapshotUuid));
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'snapshot.list',
    label: 'List config snapshots',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await backup.searchSnapshots(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'backup.list',
    label: 'List backups',
    module: 'System',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await backup.listBackups(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
