/**
 * Interface actions — settings + VLANs over uci (network package).
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddListCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

export const INTERFACE_ACTIONS: ActionDescriptor[] = [
  {
    id: 'interfaces.read',
    label: 'Read interfaces',
    description: 'Configured network interfaces with IPs, gateways and live status.',
    module: 'Interfaces',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const networks = await ctx.backend.networks().catch(() => []);
      return okResult({ count: networks.length, interfaces: networks });
    },
  },
  {
    id: 'interface.settings.set',
    label: 'Set interface IP settings',
    description: 'Sets static IPv4 (ipaddr) and/or DNS on an interface. Staged — reload applies it.',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Interface section name (e.g. lan)' },
      ipaddr: { type: 'string', description: 'Static IPv4 address with prefix (e.g. 192.168.1.1/24). Omit to leave unchanged.' },
      dns: { type: 'array', items: { type: 'string' }, description: 'DNS server IPs (replaces the current list)' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'network');
      const section = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === String(input.name));
      if (!section) return failResult(`No interface named "${input.name}" found.`);

      const cmds: string[] = [];
      if (typeof input.ipaddr === 'string' && input.ipaddr) {
        // Replace the ipaddr list: delete existing entries first.
        for (const opt of Object.keys(section[1])) {
          if (/^ipaddr$/.test(opt)) cmds.push(`uci del network.${section[0]}.ipaddr`);
        }
        cmds.push(uciSetCmd('network', section[0], 'proto', 'static'));
        cmds.push(uciSetCmd('network', section[0], 'ipaddr', input.ipaddr));
      }
      if (Array.isArray(input.dns) && input.dns.length > 0) {
        // Replace the dns list: clear it, then add each entry.
        cmds.push(`uci del network.${section[0]}.dns || true`);
        for (const d of input.dns as string[]) cmds.push(uciAddListCmd('network', section[0], 'dns', String(d)));
      }
      if (cmds.length === 0) return failResult('Nothing to change — provide ipaddr and/or dns.');
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ interface: input.name }) : failResult(`interface.settings.set failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'vlan.add',
    label: 'Add VLAN',
    description: 'Adds a VLAN sub-interface (device = parent.tag) with an optional static IP. Staged.',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'New interface section name (e.g. lan2)' },
      device: { type: 'string', required: true, description: 'Physical device + tag (e.g. eth0.100)' },
      ipaddr: { type: 'string', description: 'Static IPv4 with prefix' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const tree = await readUciPackage(ssh, 'network');
      const idx = uciSectionCount(tree['network'], 'interface');
      const { sectionKey, cmds } = uciAddSectionCmds('network', 'interface', idx);
      cmds.push(uciSetCmd('network', sectionKey, 'name', String(input.name)));
      cmds.push(uciSetCmd('network', sectionKey, 'device', String(input.device)));
      if (typeof input.ipaddr === 'string' && input.ipaddr) {
        cmds.push(uciSetCmd('network', sectionKey, 'proto', 'static'));
        cmds.push(uciSetCmd('network', sectionKey, 'ipaddr', input.ipaddr));
      } else {
        cmds.push(uciSetCmd('network', sectionKey, 'proto', 'none'));
      }
      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ interface: input.name, device: input.device }) : failResult(`vlan.add failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'interfaces.reconfigure',
    label: 'Reload interfaces',
    description: 'Reloads the network service so pending interface changes take effect.',
    module: 'Interfaces',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/network reload >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`interfaces.reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
