import * as fw from '../client/firewall';
import { ActionDescriptor } from './types';

/**
 * Firewall actions: filter rules, aliases and NAT rule sets. All writes are
 * STAGED — they modify the configuration but only become active after an
 * explicit `firewall.apply` / reconfigure step (OPNsense's two-phase model).
 */

function dataOf(res: { ok: boolean; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

/** Extracts the rows[] array from a search response. */
function rowsOf(res: { ok: boolean; data: unknown }): Record<string, unknown>[] {
  const d = dataOf(res);
  return Array.isArray(d?.['rows']) ? (d!['rows'] as Record<string, unknown>[]) : [];
}

export const firewallActions: ActionDescriptor[] = [
  // --- Reads -----------------------------------------------------------------

  {
    id: 'firewall.rules.read',
    label: 'Read filter rules',
    module: 'Firewall',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: { searchPhrase: { type: 'string' } },
    execute: async (ctx, input) => {
      const res = await fw.searchFilterRules(ctx.client, input.searchPhrase ? { searchPhrase: String(input.searchPhrase), current: 1, rowCount: 200 } : undefined);
      return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
    },
  },
  {
    id: 'firewall.aliases.read',
    label: 'Read aliases',
    module: 'Firewall',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await fw.searchAliases(ctx.client);
      return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
    },
  },

  // --- Filter rules ------------------------------------------------------------

  {
    id: 'firewall.rule.add',
    label: 'Add filter rule (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      rule: { type: 'object', required: true, description: 'Rule object (description, source_net, destination_net, protocol, ...)' },
    },
    execute: async (ctx, input) => {
      const res = await fw.addFilterRule(ctx.client, (input.rule as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.rule.update',
    label: 'Update filter rule (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      uuid: { type: 'string', required: true },
      rule: { type: 'object', required: true },
    },
    execute: async (ctx, input) => {
      const res = await fw.setFilterRule(ctx.client, String(input.uuid), (input.rule as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.rule.toggle',
    label: 'Enable/disable filter rule (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true }, enabled: { type: 'boolean', required: true } },
    execute: async (ctx, input) => {
      const res = await fw.toggleFilterRule(ctx.client, String(input.uuid), Boolean(input.enabled));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.rule.delete',
    label: 'Delete filter rule (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await fw.deleteFilterRule(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.apply',
    label: 'Apply staged firewall changes (reload pf)',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await fw.applyFilter(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- Aliases -------------------------------------------------------------------

  {
    id: 'firewall.alias.add',
    label: 'Add alias (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { item: { type: 'object', required: true, description: 'Alias object (name, address, ...)' } },
    execute: async (ctx, input) => {
      const res = await fw.addAlias(ctx.client, (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.alias.update',
    label: 'Update alias (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true }, item: { type: 'object', required: true } },
    execute: async (ctx, input) => {
      const res = await fw.setAlias(ctx.client, String(input.uuid), (input.item as Record<string, unknown>) ?? {});
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.alias.delete',
    label: 'Delete alias (staged)',
    module: 'Firewall',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await fw.deleteAlias(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'firewall.alias.reconfigure',
    label: 'Apply staged alias changes',
    module: 'Firewall',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await fw.reconfigureAliases(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- NAT (port forwards / source nat / one-to-one / npt) ---------------------------

  ...(['dNat', 'sourceNat', 'oneToOne', 'npt'] as const).flatMap((kind): ActionDescriptor[] => {
    const ops = kind === 'dNat' ? fw.dNat : kind === 'sourceNat' ? fw.sourceNat : kind === 'oneToOne' ? fw.oneToOne : fw.npt;
    const label = kind === 'dNat' ? 'Port forward (DNAT)' : kind === 'sourceNat' ? 'Source NAT' : kind === 'oneToOne' ? 'One-to-one NAT' : 'NPT';
    return [
      {
        id: `firewall.${kind}.read`,
        label: `Read ${label} rules`,
        module: 'Firewall',
        riskLevel: 'read',
        deviceCount: 1,
        inputSchema: {},
        execute: async (ctx) => {
          const res = await ops.search(ctx.client);
          return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
        },
      },
      {
        id: `firewall.${kind}.add`,
        label: `Add ${label} rule (staged)`,
        module: 'Firewall',
        riskLevel: 'write',
        staged: true,
        deviceCount: 1,
        inputSchema: { rule: { type: 'object', required: true } },
        execute: async (ctx, input) => {
          const res = await ops.add(ctx.client, (input.rule as Record<string, unknown>) ?? {});
          return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
        },
      },
      {
        id: `firewall.${kind}.update`,
        label: `Update ${label} rule (staged)`,
        module: 'Firewall',
        riskLevel: 'write',
        staged: true,
        deviceCount: 1,
        inputSchema: { uuid: { type: 'string', required: true }, rule: { type: 'object', required: true } },
        execute: async (ctx, input) => {
          const res = await ops.set(ctx.client, String(input.uuid), (input.rule as Record<string, unknown>) ?? {});
          return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
        },
      },
      {
        id: `firewall.${kind}.toggle`,
        label: `Enable/disable ${label} rule (staged)`,
        module: 'Firewall',
        riskLevel: 'write',
        staged: true,
        deviceCount: 1,
        inputSchema: { uuid: { type: 'string', required: true }, enabled: { type: 'boolean', required: true } },
        execute: async (ctx, input) => {
          const res = await ops.toggle(ctx.client, String(input.uuid), Boolean(input.enabled));
          return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
        },
      },
      {
        id: `firewall.${kind}.delete`,
        label: `Delete ${label} rule (staged)`,
        module: 'Firewall',
        riskLevel: 'write',
        staged: true,
        deviceCount: 1,
        inputSchema: { uuid: { type: 'string', required: true } },
        execute: async (ctx, input) => {
          const res = await ops.del(ctx.client, String(input.uuid));
          return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
        },
      },
    ];
  }),
];
