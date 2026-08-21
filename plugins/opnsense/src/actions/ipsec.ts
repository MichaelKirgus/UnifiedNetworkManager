import * as ipsec from '../client/ipsec';
import { ActionDescriptor } from './types';

/**
 * IPsec (swanctl) actions. Pre-shared keys are provisioned by the secrets
 * provider and arrive in `ctx.credentials` under a namespace named after the
 * plan's secretRef (e.g. credentials['psk'] = { psk: '...' }); actions reference
 * it via `input.credentialRef`.
 */

function dataOf(res: { ok: boolean; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

function rowsOf(res: { ok: boolean; data: unknown }): Record<string, unknown>[] {
  const d = dataOf(res);
  return Array.isArray(d?.['rows']) ? (d!['rows'] as Record<string, unknown>[]) : [];
}

export const ipsecActions: ActionDescriptor[] = [
  {
    id: 'ipsec.connections.read',
    label: 'Read IPsec connections',
    module: 'IPsec',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ipsec.searchConnections(ctx.client);
      return { success: res.ok, details: { rows: rowsOf(res as { ok: boolean; data: unknown }) } };
    },
  },
  {
    id: 'ipsec.connection.add',
    label: 'Add IPsec connection (staged)',
    module: 'IPsec',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true },
      /** Remote peer's public address. */
      remoteAddress: { type: 'string', required: true },
      localNetwork: { type: 'string', description: 'Own-side network (CIDR)' },
      remoteNetwork: { type: 'string', description: 'Peer-side network (CIDR)' },
      /** Namespace in step credentials holding the shared PSK ({ psk }). */
      credentialRef: { type: 'string', default: 'psk' },
    },
    execute: async (ctx, input) => {
      const ref = typeof input.credentialRef === 'string' ? input.credentialRef : 'psk';
      const cred = ctx.credentials[ref] as { psk?: string } | undefined;
      if (!cred?.psk) {
        return { success: false, error: `No PSK found under credentials["${ref}"] — the plan must provision one for this step` };
      }
      const conn: Record<string, unknown> = {
        name: String(input.name),
        remoteAddress: String(input.remoteAddress),
        localNetwork: input.localNetwork !== undefined ? String(input.localNetwork) : '',
        remoteNetwork: input.remoteNetwork !== undefined ? String(input.remoteNetwork) : '',
        presharedKey: cred.psk,
      };
      const res = await ipsec.addConnection(ctx.client, conn);
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'ipsec.connection.delete',
    label: 'Delete IPsec connection (staged)',
    module: 'IPsec',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ipsec.deleteConnection(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'ipsec.service.reconfigure',
    label: 'Apply staged IPsec changes (reload swanctl)',
    module: 'IPsec',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ipsec.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
