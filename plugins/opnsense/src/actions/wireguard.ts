import * as wg from '../client/wireguard';
import { ActionDescriptor } from './types';

/**
 * WireGuard actions. Key pairs are NOT generated here — they are provisioned by
 * the secrets provider and arrive in `ctx.credentials` under a namespace named
 * after the plan's secretRef (e.g. credentials['keyA'] = { publicKey, privateKey }).
 * Actions reference that namespace via `input.credentialRef`, so the same action
 * works for whichever endpoint's key material was injected. This is what makes
 * the multi-device tunnel intent possible: each side's peer step receives the
 * REMOTE side's public key as a resolved credential at execution time (the
 * plugin never sees key values during planning).
 */

function dataOf(res: { ok: boolean; status: number; data: unknown }): Record<string, unknown> | undefined {
  return res.ok && res.data !== null && typeof res.data === 'object' ? (res.data as Record<string, unknown>) : undefined;
}

/** Reads a provisioned keypair from the step credentials by ref name. */
function keypairOf(ctx: { credentials: Record<string, unknown> }, ref: string): { publicKey?: string; privateKey?: string } | undefined {
  const v = ctx.credentials[ref];
  return v && typeof v === 'object' ? (v as { publicKey?: string; privateKey?: string }) : undefined;
}

export const wireguardActions: ActionDescriptor[] = [
  // --- Reads -----------------------------------------------------------------

  {
    id: 'wireguard.servers.read',
    label: 'Read WireGuard servers',
    module: 'WireGuard',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await wg.listServers(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'wireguard.peers.read',
    label: 'Read WireGuard peers',
    module: 'WireGuard',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await wg.getPeers(ctx.client);
      return { success: res.ok, details: dataOf(res) ?? {} };
    },
  },

  // --- Server ------------------------------------------------------------------

  {
    id: 'wireguard.server.set',
    label: 'Create/update WireGuard server (staged)',
    module: 'WireGuard',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true },
      interface: { type: 'string', description: 'Interface to bind (e.g. wan)' },
      listenPort: { type: 'number' },
      subnet: { type: 'string', description: 'Tunnel subnet, e.g. 10.255.0.0/24' },
      /** Namespace in step credentials holding THIS endpoint's keypair (default 'self'). */
      credentialRef: { type: 'string', default: 'self' },
    },
    execute: async (ctx, input) => {
      const ref = typeof input.credentialRef === 'string' ? input.credentialRef : 'self';
      const keys = keypairOf(ctx, ref);
      if (!keys?.publicKey || !keys.privateKey) {
        return { success: false, error: `No WireGuard keypair found under credentials["${ref}"] — the plan must provision one for this step` };
      }
      const server: Record<string, unknown> = {
        name: String(input.name),
        interface: input.interface !== undefined ? String(input.interface) : 'wan',
        listenPort: typeof input.listenPort === 'number' ? input.listenPort : 51820,
        subnet: input.subnet !== undefined ? String(input.subnet) : '',
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
      };
      const res = await wg.addServer(ctx.client, server);
      const d = dataOf(res);
      // Surface the created uuid so a later peer step can bind to it via
      // output-ref substitution (${steps[N].result.uuid}).
      return { success: res.ok, applied: false, details: { ...(d ?? {}), uuid: typeof d?.['uuid'] === 'string' ? (d['uuid'] as string) : undefined } };
    },
  },
  {
    id: 'wireguard.server.delete',
    label: 'Delete WireGuard server (staged)',
    module: 'WireGuard',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await wg.deleteServer(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },

  // --- Peers ---------------------------------------------------------------------

  {
    id: 'wireguard.peer.add',
    label: 'Add WireGuard peer (staged)',
    module: 'WireGuard',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true },
      /** The REMOTE endpoint's public address (e.g. its WAN IP). */
      endpoint: { type: 'string', required: true },
      allowedSubnets: { type: 'array', items: { type: 'string' }, description: 'CIDRs this peer may reach, e.g. ["10.255.0.0/24"]' },
      /** Namespace in step credentials holding the REMOTE endpoint's keypair (its publicKey is used). */
      credentialRef: { type: 'string', required: true },
      /** Optional uuid of the local server this peer belongs to (from a prior server.set step on the same device). */
      serverUuid: { type: 'string' },
    },
    execute: async (ctx, input) => {
      const ref = String(input.credentialRef);
      const keys = keypairOf(ctx, ref);
      if (!keys?.publicKey) {
        return { success: false, error: `No public key found under credentials["${ref}"] — the plan must provision the remote endpoint's keypair for this step` };
      }
      const peer: Record<string, unknown> = {
        name: String(input.name),
        publicKey: keys.publicKey,
        endpoint: String(input.endpoint),
        allowedSubnets: Array.isArray(input.allowedSubnets) ? (input.allowedSubnets as string[]).join(',') : '',
      };
      if (typeof input.serverUuid === 'string' && input.serverUuid.length > 0) {
        peer['server_uuid'] = input.serverUuid;
      }
      const res = await wg.addPeer(ctx.client, peer);
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },
  {
    id: 'wireguard.peer.delete',
    label: 'Delete WireGuard peer (staged)',
    module: 'WireGuard',
    riskLevel: 'write',
    staged: true,
    deviceCount: 1,
    inputSchema: { uuid: { type: 'string', required: true } },
    execute: async (ctx, input) => {
      const res = await wg.deletePeer(ctx.client, String(input.uuid));
      return { success: res.ok, applied: false, details: dataOf(res) ?? {} };
    },
  },

  // --- Service -----------------------------------------------------------------------

  {
    id: 'wireguard.service.reconfigure',
    label: 'Apply staged WireGuard changes (reload service)',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const res = await wg.reconfigureService(ctx.client);
      return { success: res.ok, applied: res.ok, details: dataOf(res) ?? {} };
    },
  },
];
