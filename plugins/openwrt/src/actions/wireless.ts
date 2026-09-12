/**
 * Wireless actions — SSID management over uci (wireless package).
 */

import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

export const WIRELESS_ACTIONS: ActionDescriptor[] = [
  {
    id: 'wireless.ssids.read',
    label: 'Read wireless SSIDs',
    description: 'Configured wifi-iface sections (SSID, encryption, channel).',
    module: 'Wireless',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const ssids = await ctx.backend.wifiSsids().catch(() => []);
      return okResult({ count: ssids.length, ssids });
    },
  },
  {
    id: 'wireless.ssid.set',
    label: 'Create/update SSID',
    description:
      'Creates or updates a wifi-iface (SSID + encryption). The pre-shared key is supplied via credentialRef (a usernamePassword secret whose password field carries the WPA key) — never typed into the plan UI. Staged.',
    module: 'Wireless',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      name: { type: 'string', required: true, description: 'SSID (network name)' },
      encryption: { type: 'string', enum: ['psk2', 'psk2+ccmp', 'none'], default: 'psk2+ccmp', description: 'WPA2-PSK (or open when none)' },
      channel: { type: 'number', min: 1, max: 177, description: 'Channel (default = keep current/auto)' },
      credentialRef: { type: 'string', required: true, description: "secretRef whose password field is the WPA pre-shared key" },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;

      // Locate an existing wifi-iface with this SSID on any radio.
      const tree = await readUciPackage(ssh, 'wireless');
      const existing = Object.entries(tree['wireless'] ?? {}).find(([k, o]) => /^@wifi-iface\[\d+\]$/.test(k) && o['ssid'] === String(input.name));

      // Determine the radio to attach to: reuse the existing one, else radio0.
      let sectionKey: string;
      const cmds: string[] = [];
      if (existing) {
        sectionKey = existing[0];
      } else {
        const idx = uciSectionCount(tree['wireless'], 'wifi-iface');
        const added = uciAddSectionCmds('wireless', 'wifi-iface', idx);
        sectionKey = added.sectionKey;
        cmds.push(...added.cmds);
        // Attach to the first configured radio (best-effort default).
        const radios = Object.keys(tree['wireless'] ?? {}).filter((k) => /^@wifi-iface\[\d+\]$/.test(k));
        const anyIface = tree['wireless'][radios[0] ?? ''];
        cmds.push(uciSetCmd('wireless', sectionKey, 'device', anyIface?.['device'] ?? 'radio0'));
      }

      cmds.push(uciSetCmd('wireless', sectionKey, 'network', 'lan'));
      cmds.push(uciSetCmd('wireless', sectionKey, 'mode', 'ap'));
      cmds.push(uciSetCmd('wireless', sectionKey, 'ssid', String(input.name)));
      const encryption = String(input.encryption ?? 'psk2+ccmp');
      if (encryption === 'none') {
        cmds.push(`uci del wireless.${sectionKey}.encryption || true`);
        cmds.push(`uci del wireless.${sectionKey}.key || true`);
      } else {
        const slot = ctx.credentials[String(input.credentialRef)];
        const key = slot && typeof slot === 'object' ? (slot as Record<string, unknown>)['password'] : undefined;
        if (typeof key !== 'string' || !key) return failResult(`No WPA pre-shared key found for credentialRef "${input.credentialRef}".`);
        cmds.push(uciSetCmd('wireless', sectionKey, 'encryption', encryption));
        cmds.push(uciSetCmd('wireless', sectionKey, 'key', key));
      }
      if (typeof input.channel === 'number') {
        // Channel is set on the RADIO section, not the iface. Resolve the radio
        // this iface references by its `device` option (a wifi-device name).
        const deviceRef = existing ? tree['wireless'][existing[0]]?.['device'] : undefined;
        let radioKey: string | null = null;
        for (const [k, o] of Object.entries(tree['wireless'] ?? {})) {
          if (!/^@wifi-radio\[\d+\]$/.test(k)) continue;
          if (!deviceRef || o['name'] === deviceRef) { radioKey = k; break; }
        }
        if (radioKey) cmds.push(uciSetCmd('wireless', radioKey, 'channel', String(input.channel)));
      }
      cmds.push(uciCommitCmd());

      const r = await runCommands(ssh, [...cmds, '/etc/init.d/wireless restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ ssid: input.name, encryption }) : failResult(`wireless.ssid.set failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'wireless.ssid.delete',
    label: 'Delete SSID',
    description: 'Removes a wifi-iface section by its uci key (from wireless.ssids.read).',
    module: 'Wireless',
    riskLevel: 'write',
    deviceCount: 1,
    staged: true,
    inputSchema: {
      ifaceKey: { type: 'string', required: true, description: 'uci key, e.g. @wifi-iface[0]' },
    },
    execute: async (ctx, input) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const ssh = ctx.backend.ssh!;
      const ifaceKey = String(input.ifaceKey);
      if (!/^@\w+\[\d+\]$/.test(ifaceKey)) return failResult('Invalid iface key — expected form @wifi-iface[N].');
      const r = await runCommands(ssh, [uciDelCmd('wireless', ifaceKey), uciCommitCmd(), '/etc/init.d/wireless restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult({ deleted: ifaceKey }) : failResult(`wireless.ssid.delete failed: ${r.stderr.slice(0, 300)}`);
    },
  },
  {
    id: 'wireless.reconfigure',
    label: 'Reload wireless',
    description: 'Restarts the wireless service so pending SSID changes take effect.',
    module: 'Wireless',
    riskLevel: 'write',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      if (!sshAvailable(ctx)) return noSshResult();
      const r = await runCommands(ctx.backend.ssh!, ['/etc/init.d/wireless restart >/dev/null 2>&1 || true']);
      return r.ok ? okResult() : failResult(`wireless.reconfigure failed: ${r.stderr.slice(0, 300)}`);
    },
  },
];
