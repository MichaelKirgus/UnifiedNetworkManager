/**
 * OpenVPN actions — instance management over uci + file drops.
 *
 * Prechecks that the `openvpn` package is installed and fails cleanly when it
 * isn't (most small routers don't ship it). Certificate bundles arrive via the
 * provisioned 'profile' secretRef ({ ca, cert, key }).
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, shq } from '../client/sshBackend';
import type { SshBackend } from '../client/sshBackend';

/** True when the openvpn package is installed on the device. */
async function hasOpenVpn(ssh: SshBackend): Promise<boolean> {
  const r = await ssh.exec('command -v openvpn >/dev/null 2>&1 && echo yes || echo no').catch(() => null);
  return (r?.stdout ?? '').trim() === 'yes';
}

export const OPENVPN_ACTIONS: ActionDescriptor[] = [
  {
    id: 'openvpn.instances.read',
    label: 'Read OpenVPN instances',
    description: 'Configured openvpn interfaces (proto=openvpn) with mode + status.',
    module: 'OpenVPN',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const tunnels = await ctx.backend.tunnels().catch(() => []);
      return okResult({ instances: tunnels.filter((t) => t.type === 'openvpn') });
    },
  },
  {
    id: 'openvpn.instance.set',
    label: 'Create/update OpenVPN instance',
    description:
      'Creates an openvpn interface (server or client mode) with the provisioned certificate bundle (credentialRef → ca/cert/key). Staged — reconfigure activates it.',
    module: 'OpenVPN',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true },
      mode: { type: 'string', enum: ['server', 'client'], default: 'server' },
      credentialRef: { type: 'string', required: true, description: "secretRef of the provisioned openvpnProfile ({ ca, cert, key })" },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      if (!(await hasOpenVpn(ssh))) {
        return failResult('The openvpn package is not installed on this device — install it first (opkg install openvpn-easy-rsa).');
      }

      const ref = String(input.credentialRef);
      const slot = ctx.credentials[ref];
      if (!slot || typeof slot !== 'object') return failResult(`No certificate bundle found for credentialRef "${ref}".`);
      const s = slot as Record<string, unknown>;
      const ca = typeof s['ca'] === 'string' ? s['ca'] : '';
      const cert = typeof s['cert'] === 'string' ? s['cert'] : '';
      const keyPem = typeof s['key'] === 'string' ? s['key'] : '';
      if (!ca || !cert || !keyPem) return failResult(`Incomplete certificate bundle for credentialRef "${ref}" (need ca + cert + key).`);

      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, '');
      if (!name) return failResult('Invalid instance name.');
      const mode = input.mode === 'client' ? 'client' : 'server';

      // Drop the bundle into /etc/openvpn/<name>/ (PEM material is shell-quoted).
      const dir = `/etc/openvpn/${name}`;
      const cmds: string[] = [
        `mkdir -p ${dir}`,
        `printf '%s' ${shq(ca)} > ${dir}/ca.crt`,
        `printf '%s' ${shq(cert)} > ${dir}/${name}.crt`,
        `printf '%s' ${shq(keyPem)} > ${dir}/${name}.key && chmod 600 ${dir}/${name}.key`,
      ];

      // uci: reuse or create the interface section.
      const tree = await readUciPackage(ssh, 'network');
      const existing = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === name && o['proto'] === 'openvpn');
      let sectionKey: string;
      if (existing) {
        sectionKey = existing[0];
      } else {
        // New list section @interface[N].
        const idx = Object.keys(tree['network'] ?? {}).filter((k) => k.startsWith('@interface[')).length;
        sectionKey = `@interface[${idx}]`;
        cmds.push(`uci add network interface`);
        cmds.push(uciSetCmd('network', sectionKey, 'name', name));
      }
      cmds.push(uciSetCmd('network', sectionKey, 'proto', 'openvpn'));
      cmds.push(uciSetCmd('network', sectionKey, 'config', `${dir}/${name}.conf`));

      // Minimal config file (server: port 1194 + push; client: remote).
      const conf = mode === 'server'
        ? `mode server\nport 1194\nproto udp\nda ca ${dir}/ca.crt\ncert ${dir}/${name}.crt\nkey ${dir}/${name}.key\ndh /etc/openvpn/easy-rsa/keys/dh2048.pem\nserver 10.9.0.0 255.255.255.0`
        : `client\nproto udp\nda ca ${dir}/ca.crt\ncert ${dir}/${name}.crt\nkey ${dir}/${name}.key`;
      cmds.push(`printf '%s' ${shq(conf)} > ${dir}/${name}.conf`);

      cmds.push(uciCommitCmd());
      const r = await runCommands(ssh, [...cmds, '/etc/init.d/network reload >/dev/null 2>&1 || true']);
      if (!r.ok) return failResult(`openvpn.instance.set failed: ${r.stderr.slice(0, 300)}`);
      return okResult({ name, mode });
    },
  },
  {
    id: 'openvpn.instance.delete',
    label: 'Delete OpenVPN instance',
    description: 'Removes an openvpn interface + its config directory.',
    module: 'OpenVPN',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {
      name: { type: 'string', required: true },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const name = String(input.name).replace(/[^a-zA-Z0-9_-]/g, '');
      const tree = await readUciPackage(ssh, 'network');
      const existing = Object.entries(tree['network'] ?? {}).find(([, o]) => o['name'] === name && o['proto'] === 'openvpn');
      if (!existing) return failResult(`No openvpn instance named "${name}" found.`);
      const r = await runCommands(ssh, [
        uciDelCmd('network', existing[0]),
        `rm -rf /etc/openvpn/${name}`,
        uciCommitCmd(),
        '/etc/init.d/network reload >/dev/null 2>&1 || true',
      ]);
      return r.ok ? okResult({ deleted: name }) : failResult(`openvpn.instance.delete failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'openvpn.service.reconfigure',
    label: 'Reconfigure OpenVPN',
    description: 'Reloads the network service so pending openvpn changes take effect.',
    module: 'OpenVPN',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/network reload >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`openvpn reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
