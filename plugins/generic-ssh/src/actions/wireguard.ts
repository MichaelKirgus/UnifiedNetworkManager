/**
 * WireGuard actions — server/peer management via wg-quick + systemd.
 *
 * Key material NEVER comes from this plugin: provisioned key pairs arrive in
 * ctx.credentials namespaced by the plan's secretRef (e.g. credentials.keyA =
 * { publicKey, privateKey }). The action only writes them to /etc/wireguard/.
 *
 * Idempotency model (plans may re-run):
 *   - server.set  → regenerates the [Interface] section of <name>.conf from scratch
 *                   (peers are preserved by rewriting only up to the first [Peer]).
 *   - peer.add    → no-op when the remote PublicKey is already present, else appends.
 */

import type { CommandRunner } from '../client/privilege';
import type { ActionDescriptor } from './types';
import { okResult, failResult, runCommands, shq, keyMaterial, isSafeName } from './types';

const WG_DIR = '/etc/wireguard';

/** First usable address of a /24-style subnet (x.x.x.1) — the server's own IP. */
function firstHostIp(subnet: string): string | null {
  const m = subnet.match(/^(\d+\.\d+\.\d+)\.\d+\/\d{1,2}$/);
  return m ? `${m[1]}.1` : null;
}

/** Ensures wireguard-tools is present (best-effort install on common distros).
 *  The install itself runs elevated — the backend escalates automatically. */
async function ensureWg(backend: CommandRunner): Promise<{ ok: boolean; error?: string }> {
  const have = await backend.exec('command -v wg >/dev/null 2>&1 && echo yes || echo no').catch(() => null);
  if (have?.stdout.trim() === 'yes') return { ok: true };
  // Best-effort install — a box without package access gets a clear error instead.
  const r = await backend.exec(
    '(command -v apt-get >/dev/null 2>&1 && apt-get update -qq && apt-get install -y -qq wireguard-tools) ' +
      '|| (command -v dnf >/dev/null 2>&1 && dnf install -y wireguard-tools) ' +
      '|| (command -v apk >/dev/null 2>&1 && apk add --no-cache wireguard-tools) ' +
      '|| (command -v yum >/dev/null 2>&1 && yum install -y wireguard-tools)',
    90_000,
  ).catch(() => null);
  const now = await backend.exec('command -v wg >/dev/null 2>&1 && echo yes || echo no').catch(() => null);
  if (now?.stdout.trim() === 'yes') return { ok: true };
  return { ok: false, error: `wireguard-tools is not installed and could not be installed automatically${r ? ` (${(r.stderr || r.stdout).slice(-200)})` : ''}. Install it on the device and retry.` };
}

/** systemd unit for one wg-quick config. */
function unitOf(name: string): string {
  return `wg-quick@${name}`;
}

export const WIREGUARD_ACTIONS: ActionDescriptor[] = [
  {
    id: 'wireguard.tunnels.read',
    label: 'Read WireGuard tunnels',
    description: 'Configured wg-quick interfaces (/etc/wireguard/*.conf, private keys masked) + live `wg show` state.',
    module: 'WireGuard',
    riskLevel: 'read',
    deviceCount: 1,
    inputSchema: {},
    execute: async (ctx) => {
      const r = await ctx.backend.exec(
        `ls ${WG_DIR}/*.conf 2>/dev/null; echo ---; for f in ${WG_DIR}/*.conf; do [ -f "$f" ] || continue; echo "## $f"; grep -vE '^PrivateKey' "$f" | head -40; done; echo ---; wg show all 2>/dev/null || true`,
      ).catch(() => null);
      if (!r) return failResult('Could not read WireGuard configuration.');
      const parts = r.stdout.split('---');
      const files: string[] = (parts[0] ?? '').split('\n').map((l) => l.trim()).filter(Boolean);
      const live = (parts[2] ?? '').trim();
      return okResult({ count: files.length, configs: files.map((f) => f.split('/').pop()), liveState: live || null });
    },
  },
  {
    id: 'wireguard.server.set',
    label: 'Create/update WireGuard server',
    description:
      'Creates or updates a wg-quick interface with the provisioned key pair (credentialRef), listen port and subnet. Existing [Peer] sections are preserved. Staged — wireguard.service.reconfigure activates it.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 90_000,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Tunnel/interface name (e.g. "unm-tun")' },
      listenPort: { type: 'number', min: 1, max: 65535, default: 51820 },
      subnet: { type: 'string', required: true, description: 'Tunnel subnet CIDR, e.g. "10.255.0.0/24"' },
      credentialRef: { type: 'string', required: true, description: 'secretRef of the provisioned wireguardKeyPair for THIS endpoint' },
    },
    execute: async (ctx, input) => {
      const name = String(input.name).trim();
      if (!isSafeName(name)) return failResult('Invalid tunnel name.');
      const key = keyMaterial(ctx, String(input.credentialRef));
      if (!key?.privateKey || !key.publicKey) return failResult(`No WireGuard key material found for credentialRef "${input.credentialRef}".`);

      const wgCheck = await ensureWg(ctx.backend);
      if (!wgCheck.ok) return failResult(wgCheck.error ?? 'wireguard-tools unavailable.');

      const subnet = String(input.subnet).trim();
      const listenPort = Number(input.listenPort ?? 51820);
      const localIp = firstHostIp(subnet);
      if (!localIp) return failResult(`Could not derive a local IP from subnet "${subnet}" (expected x.x.x.0/NN).`);

      // Regenerate the [Interface] section, preserving any existing [Peer] blocks:
      // keep everything from the first "[Peer]" line onward of the old file.
      const conf = `${WG_DIR}/${name}.conf`;
      const keyFile = `${WG_DIR}/${name}.key`;
      const cmds: string[] = [
        `mkdir -p ${WG_DIR}`,
        `printf '%s' ${shq(key.privateKey)} > ${keyFile} && chmod 600 ${keyFile}`,
        // Extract preserved peers (from the first [Peer] line to EOF) of any old conf.
        `PEERS=$(awk '/^\\[Peer\\]/,0' ${conf} 2>/dev/null || true)`,
        `{ printf '[Interface]\\n'; echo "PrivateKey = $(cat ${keyFile})"; echo "Address = ${localIp}/${subnet.split('/')[1]}"; echo "ListenPort = ${listenPort}"; [ -n "$PEERS" ] && printf '%s\\n' "$PEERS"; } > ${conf}.new`,
        `mv ${conf}.new ${conf}`,
      ];
      const r = await runCommands(ctx.backend, cmds, 90_000);
      if (!r.ok) return failResult(`wireguard.server.set failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

      // Enable the unit so it survives reboots (start happens in .reconfigure).
      const en = await ctx.backend.exec(`if command -v systemctl >/dev/null 2>&1; then systemctl enable ${unitOf(name)} >/dev/null 2>&1 || true; fi`).catch(() => null);
      return okResult({ name, device: `wg${name}`, subnet, listenPort, localIp, enabled: en?.code === 0 });
    },
  },
  {
    id: 'wireguard.peer.add',
    label: 'Add WireGuard peer',
    description:
      'Adds a [Peer] (remote endpoint + allowed subnets) to an existing server using the REMOTE side\'s public key (credentialRef). Idempotent — re-adding the same public key is a no-op. Staged.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Server/interface name the peer belongs to' },
      endpoint: { type: 'string', required: true, description: 'Remote public address (host or host:port)' },
      allowedSubnets: { type: 'array', items: { type: 'string' }, description: 'CIDRs reachable THROUGH this peer' },
      credentialRef: { type: 'string', required: true, description: 'secretRef carrying the REMOTE endpoint\'s public key' },
    },
    execute: async (ctx, input) => {
      const name = String(input.name).trim();
      if (!isSafeName(name)) return failResult('Invalid tunnel name.');
      const key = keyMaterial(ctx, String(input.credentialRef));
      if (!key?.publicKey) return failResult(`No public key found for credentialRef "${input.credentialRef}".`);

      const endpoint = String(input.endpoint).trim();
      // Endpoint = host or host:port — conservative charset (no shell metachars).
      if (!/^[a-zA-Z0-9._:-]+(:\d{1,5})?$/.test(endpoint)) return failResult('Invalid endpoint address.');
      const subnets = Array.isArray(input.allowedSubnets) ? (input.allowedSubnets as unknown[]).map((s) => String(s)).filter(Boolean) : [];

      const conf = `${WG_DIR}/${name}.conf`;
      // Idempotency: same public key already present → no-op.
      const have = await ctx.backend.exec(`grep -qF "PublicKey = ${shq(key.publicKey)}" ${conf} 2>/dev/null && echo yes || echo no`).catch(() => null);
      if (have?.stdout.trim() === 'yes') {
        return okResult({ name, peer: endpoint, alreadyPresent: true });
      }

      const block = [
        '[Peer]',
        `PublicKey = ${key.publicKey}`,
        `AllowedIPs = ${subnets.join(', ') || '0.0.0.0/0'}`,
        `Endpoint = ${endpoint}`,
        'PersistentKeepalive = 25',
      ].join('\n');

      const r = await runCommands(ctx.backend, [
        `[ -f ${conf} ] || { echo "server config ${conf} missing — run wireguard.server.set first"; exit 1; }`,
        `printf '%s\\n' ${shq(block)} >> ${conf}`,
      ], 60_000);
      if (!r.ok) return failResult(`wireguard.peer.add failed: ${(r.stderr || r.stdout).slice(0, 300)}`);
      return okResult({ name, peer: endpoint, allowedSubnets: subnets });
    },
  },
  {
    id: 'wireguard.service.reconfigure',
    label: 'Activate WireGuard interface',
    description: 'Brings the wg-quick interface up (wg-quick up) and verifies it is live.',
    module: 'WireGuard',
    riskLevel: 'write',
    deviceCount: 1,
    timeoutMs: 60_000,
    inputSchema: {
      name: { type: 'string', required: true, description: 'Tunnel/interface name' },
    },
    execute: async (ctx, input) => {
      const name = String(input.name).trim();
      if (!isSafeName(name)) return failResult('Invalid tunnel name.');

      const r = await runCommands(ctx.backend, [
        `if command -v systemctl >/dev/null 2>&1; then systemctl restart ${unitOf(name)}; else wg-quick up ${name}; fi`,
      ], 60_000);
      if (!r.ok) return failResult(`Activation of ${name} failed: ${(r.stderr || r.stdout).slice(0, 300)}`);

      // Verify the interface is actually up.
      const check = await ctx.backend.exec(`wg show wg${name} 2>/dev/null | head -1 || true`).catch(() => null);
      return okResult({ name, device: `wg${name}`, up: !!check?.stdout.trim() });
    },
  },
];
