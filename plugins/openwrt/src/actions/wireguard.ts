/**
 * WireGuard actions — server/peer management over uci + `wg` CLI.
 *
 * Key material NEVER comes from this plugin: provisioned key pairs arrive in
 * ctx.credentials namespaced by the plan's secretRef (e.g. credentials.keyA =
 * { publicKey, privateKey }). The action only writes them into /etc/config and
 * /etc/wireguard/.
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciAddListCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount, shq } from '../client/sshBackend';

/** Reads provisioned key material for one secretRef. */
function keyMaterial(ctx: Parameters<ActionDescriptor['execute']>[0], ref: string): { publicKey?: string; privateKey?: string } | null {
  const slot = ctx.credentials[ref];
  if (!slot || typeof slot !== 'object') return null;
  const s = slot as Record<string, unknown>;
  return {
    publicKey: typeof s['publicKey'] === 'string' ? s['publicKey'] : undefined,
    privateKey: typeof s['privateKey'] === 'string' ? s['privateKey'] : undefined,
  };
}

export const WIREGUARD_ACTIONS: ActionDescriptor[] = [
  {
    id: 'wireguard.servers.read',
    label: 'Read WireGuard servers',
    description: 'Configured wireguard interfaces (proto=wireguard) + live `wg show` state.',
    module: 'WireGuard',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const tunnels = await ctx.backend.tunnels().catch(() => []);
      return okResult({ servers: tunnels.filter((t) => t.type === 'wireguard') });
    },
  },
  {
    id: 'wireguard.server.set',
    label: 'Create/update WireGuard server',
    description:
      'Creates a wireguard interface with the provisioned key pair (credentialRef), listen port and subnet. Staged — service reconfigure activates it.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Interface/section name' },
      listenPort: { type: 'number', min: 1, max: 65535, default: 51820 },
      subnet: { type: 'string', required: true, description: 'Tunnel subnet CIDR, e.g. 10.255.0.0/24' },
      credentialRef: { type: 'string', required: true, description: 'secretRef of the provisioned wireguardKeyPair for THIS endpoint' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const key = keyMaterial(ctx, String(input.credentialRef));
      if (!key?.privateKey || !key.publicKey) return failResult(`No WireGuard key material found for credentialRef "${input.credentialRef}".`);

      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, '');
      if (!name) return failResult('Invalid interface name.');
      const subnet = String(input.subnet);
      const listenPort = Number(input.listenPort ?? 51820);

      // The tunnel IP is the first usable address of the subnet.
      const ipMatch = subnet.match(/^(\d+\.\d+\.\d+)\.0\/\d+$/);
      const localIp = ipMatch ? `${ipMatch[1]}.1` : '';

      const cmds: string[] = [];
      // Idempotent: reuse the section when it exists, else add a new one.
      const tree = await readUciPackage(ssh, 'network');
      const existing = Object.keys(tree['network'] ?? {}).find((k) => k.startsWith('@interface[') && (tree['network'][k]['name'] === name));
      let sectionKey: string;
      if (existing) {
        sectionKey = existing;
        cmds.push(uciSetCmd('network', sectionKey, 'proto', 'wireguard'));
        cmds.push(uciSetCmd('network', sectionKey, 'device', `wg${name}`));
        cmds.push(uciSetCmd('network', sectionKey, 'listen_port', String(listenPort)));
      } else {
        const idx = uciSectionCount(tree['network'], 'interface');
        const added = uciAddSectionCmds('network', 'interface', idx);
        sectionKey = added.sectionKey;
        cmds.push(...added.cmds);
        cmds.push(uciSetCmd('network', sectionKey, 'name', name));
        cmds.push(uciSetCmd('network', sectionKey, 'proto', 'wireguard'));
        cmds.push(uciSetCmd('network', sectionKey, 'device', `wg${name}`));
        cmds.push(uciSetCmd('network', sectionKey, 'listen_port', String(listenPort)));
      }
      if (localIp) cmds.push(uciAddListCmd('network', sectionKey, 'ip4addr', localIp));

      // Key material on the device: netifd's wireguard proto accepts a FILE PATH
      // for `private_key` (values containing '/' are read from disk), so the key
      // itself never lands in /etc/config.
      cmds.push(`mkdir -p /etc/wireguard`);
      cmds.push(`printf '%s' ${shq(key.privateKey)} > /etc/wireguard/${name}.key && chmod 600 /etc/wireguard/${name}.key`);
      cmds.push(uciSetCmd('network', sectionKey, 'private_key', `/etc/wireguard/${name}.key`));

      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || /etc/init.d/firewall restart >/dev/null 2>&1 || true']);
      if (!r.ok) return failResult(`wireguard.server.set failed: ${r.stderr.slice(0, 300)}`);

      // Verify the interface came up (best-effort).
      const check = await ssh.exec(`wg show wg${name} 2>/dev/null | head -1 || true`).catch(() => null);
      return okResult({ name, device: `wg${name}`, subnet, listenPort, up: !!check?.stdout.trim() });
    },
  },
  {
    id: 'wireguard.peer.add',
    label: 'Add WireGuard peer',
    description:
      'Adds a peer (remote endpoint + allowed subnets) to an existing server using the REMOTE side\'s public key (credentialRef). Staged.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Server/interface name the peer belongs to' },
      endpoint: { type: 'string', required: true, description: 'Remote public address (host or host:port)' },
      allowedSubnets: { type: 'array', items: { type: 'string' }, description: 'CIDRs reachable through this peer' },
      credentialRef: { type: 'string', required: true, description: 'secretRef carrying the REMOTE endpoint\'s public key' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const key = keyMaterial(ctx, String(input.credentialRef));
      if (!key?.publicKey) return failResult(`No public key found for credentialRef "${input.credentialRef}".`);

      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, '');
      const endpoint = String(input.endpoint);
      const subnets: string[] = Array.isArray(input.allowedSubnets) ? (input.allowedSubnets as string[]) : [];

      // Locate the interface section and its device name (peers live in
      // sections of type `wireguard_<device>` — netifd's standard layout).
      const tree = await readUciPackage(ssh, 'network');
      const ifSection = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === name && o['proto'] === 'wireguard');
      if (!ifSection) return failResult(`No wireguard interface named "${name}" found.`);
      const device = ifSection[1]['device'] ?? `wg${name}`;

      // New peer section: config wireguard_<dev> '<peername>'.
      const peerType = `wireguard_${device}`;
      const existingPeers = Object.keys(tree['network'] ?? {}).filter((k) => k.startsWith(`@${peerType}[`));
      const peerIdx = existingPeers.length;
      const peerKey = `@${peerType}[${peerIdx}]`;

      const cmds: string[] = [`uci add network ${peerType}`];
      cmds.push(uciSetCmd('network', peerKey, 'name', name)); // informational label
      cmds.push(uciSetCmd('network', peerKey, 'public_key', key.publicKey));
      cmds.push(uciSetCmd('network', peerKey, 'endpoint', endpoint.includes(':') ? endpoint : `${endpoint}:51820`));
      for (const cidr of subnets.length > 0 ? subnets : ['0.0.0.0/0']) {
        cmds.push(uciAddListCmd('network', peerKey, 'allowed_ips', cidr));
      }
      cmds.push(uciCommitCmd());

      const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || true']);
      if (!r.ok) return failResult(`wireguard.peer.add failed: ${r.stderr.slice(0, 300)}`);
      return okResult({ name, peer: peerKey, endpoint, allowedSubnets: subnets });
    },
  },
  {
    id: 'wireguard.service.reconfigure',
    label: 'Reconfigure WireGuard',
    description: 'Reloads the network service so pending wireguard changes take effect.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/network reload >/dev/null 2>&1 || /etc/init.d/firewall restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`wireguard reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
