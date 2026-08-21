import * as ovpn from '../client/openvpn';
import { ActionDescriptor } from './types';

/**
 * OpenVPN actions. Certificate/key material (CA + cert + key PEMs) is
 * provisioned by the secrets provider and arrives in `ctx.credentials` under a
 * namespace named after the plan's secretRef; actions reference it via
 * `input.credentialRef`.
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

export const openvpnActions: ActionDescriptor[] = [
  {
    id: 'openvpn.instances.read',
    label: 'Read OpenVPN instances',
    module: 'OpenVPN',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ovpn.searchInstances(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'openvpn.instance.set',
    label: 'Create/update OpenVPN instance (staged)',
    module: 'OpenVPN',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true },
      mode: { type: 'string', enum: ['server', 'client'], description: 'Instance role' },
      /** Namespace in step credentials holding the profile bundle ({ ca, cert, key }). */
      credentialRef: { type: 'string', default: 'profile' },
    },
    execute: async (ctx, input) => {
      const ref = typeof input.credentialRef === 'string' ? input.credentialRef : 'profile';
      const cred = ctx.credentials[ref] as { ca?: string; cert?: string; key?: string } | undefined;
      if (!cred?.ca || !cred.cert || !cred.key) {
        return { success: false, error: `No OpenVPN profile bundle (ca/cert/key) found under credentials["${ref}"] — the plan must provision one for this step` };
      }
      const instance: Record<string, unknown> = {
        name: String(input.name),
        mode: input.mode !== undefined ? String(input.mode) : 'server',
        ca: cred.ca,
        cert: cred.cert,
        key: cred.key,
      };
      const res = await ovpn.addInstance(ctx.client, instance);
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'openvpn.instance.delete',
    label: 'Delete OpenVPN instance (staged)',
    module: 'OpenVPN',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await ovpn.deleteInstance(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'openvpn.service.reconfigure',
    label: 'Apply staged OpenVPN changes (reload service)',
    module: 'OpenVPN',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await ovpn.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
