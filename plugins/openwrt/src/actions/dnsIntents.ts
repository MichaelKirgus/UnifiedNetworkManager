/**
 * Canonical fleet intents for OpenWrt — `dns.set` / `dns.delete`.
 *
 * Static DNS host entries live in the uci `dhcp` package as dnsmasq
 * @host/@map sections (name → ip). Both intents are SELF-CONTAINED: they read
 * the current state, stage the change, commit + restart dnsmasq inside one
 * step, then verify by re-reading — so a plan fan-out (deviceCount 'N') needs
 * no extra steps. Idempotent: set on an existing identical entry is a skip;
 * delete of a missing name is a skip. All writes go over SSH regardless of the
 * negotiated read transport (uci syntax is version-stable).
 */

import { INTENT_DNS_SET, INTENT_DNS_DELETE } from '@unm/plugin-sdk';
import type { ActionDescriptor } from './types';
import { sshAvailable, noSshResult } from './types';
import { okResult, failResult, runCommands, readUciPackage } from './helpers';
import type { SshBackend } from '../client/sshBackend';
import { uciSetCmd, uciDelCmd, uciCommitCmd, uciAddSectionCmds, uciSectionCount } from '../client/sshBackend';

/** One parsed @host/@map section of the dhcp package. */
interface HostSection {
  key: string; // e.g. '@host[2]'
  name: string | null;
  ip: string | null;
}

/** Reads all dnsmasq host sections from the live uci state (null on read failure). */
async function readHostSections(ssh: SshBackend): Promise<HostSection[] | null> {
  try {
    const tree = await readUciPackage(ssh, 'dhcp');
    const sections: HostSection[] = [];
    for (const [key, options] of Object.entries(tree['dhcp'] ?? {})) {
      if (!key.startsWith('@host[') && !key.startsWith('@map[')) continue;
      sections.push({
        key,
        name: typeof options['name'] === 'string' ? options['name'].trim().toLowerCase() : typeof options['hostname'] === 'string' ? options['hostname'].trim().toLowerCase() : null,
        ip: typeof options['ip'] === 'string' && options['ip'].trim() ? options['ip'].trim() : null,
      });
    }
    return sections;
  } catch {
    return null;
  }
}

// --- dns.set --------------------------------------------------------------------

export const dnsSetAction: ActionDescriptor = {
  id: INTENT_DNS_SET,
  label: 'Add/update static DNS entry (hostname → IP)',
  description:
    'Adds a dnsmasq host record to the uci dhcp package (or updates an existing one in place when the name already maps to a different address). Commits + restarts dnsmasq and verifies by re-reading. Idempotent — an identical entry is skipped.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 90_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname (stored lowercase by UNM)' },
    ip: { type: 'string' as const, required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'IPv4 or IPv6 address the hostname resolves to (record type A/AAAA is derived from the shape)' },
    // uci dhcp @host/@map sections have no native note field — accepted for
    // contract symmetry, ignored on write.
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Optional note — not stored (OpenWrt has no native field for it)' },
  },
  execute: async (ctx, input) => {
    if (!sshAvailable(ctx)) return noSshResult();
    const ssh = ctx.backend.ssh!;

    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = String(input.ip ?? '').trim();
    if (!name || !ip) return failResult('both `name` and `ip` are required');

    // 1. Live state — refuse to write when the read fails (state unknown).
    const sections = await readHostSections(ssh);
    if (sections === null) return failResult('could not read current uci dhcp host records — state unknown, refusing to write');

    // Idempotency — identical entry already present. The desired state was
    // CONFIRMED by the live read, so it is self-evidently verified (top-level).
    if (sections.some((s) => s.name === name && s.ip === ip)) {
      return okResult({ skipped: `entry ${name} → ${ip} already exists` }, true);
    }

    const details: Record<string, unknown> = {};
    // 2. Same name with a DIFFERENT address → update in place; otherwise add a new section.
    const existing = sections.find((s) => s.name === name);
    let cmds: string[];
    if (existing) {
      cmds = [uciSetCmd('dhcp', existing.key, 'name', name), uciSetCmd('dhcp', existing.key, 'ip', ip)];
      details.updatedFrom = existing.ip ?? '(none)';
    } else {
      // `uci add dhcp host` assigns the next free @host[N] index (count of existing @host sections).
      const allKeys: Record<string, Record<string, string>> = {};
      for (const s of sections) allKeys[s.key] = {};
      const idx = uciSectionCount(allKeys, 'host');
      const { sectionKey, cmds: addCmds } = uciAddSectionCmds('dhcp', 'host', idx);
      cmds = [...addCmds, uciSetCmd('dhcp', sectionKey, 'name', name), uciSetCmd('dhcp', sectionKey, 'ip', ip)];
    }

    // 3. One batch: staged changes + commit + dnsmasq restart.
    const r = await runCommands(ssh, [...cmds, uciCommitCmd(), '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
    if (!r.ok) return failResult(`dns.set failed: ${r.stderr.slice(0, 300)}`);

    // 4. Verify by re-read.
    const after = await readHostSections(ssh);
    if (after === null) return okResult(details, false);
    if (!after.some((s) => s.name === name && s.ip === ip)) {
      return failResult(`entry ${name} → ${ip} not present after commit`);
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract).
    return okResult(details, true);
  },
};

// --- dns.delete -----------------------------------------------------------------

export const dnsDeleteAction: ActionDescriptor = {
  id: INTENT_DNS_DELETE,
  label: 'Remove static DNS entry (hostname)',
  description:
    'Removes dnsmasq host record(s) from the uci dhcp package by hostname (optionally scoped to one address). Commits + restarts dnsmasq and verifies absence by re-reading. Idempotent — a missing name is skipped.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 90_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove' },
    ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — when the name maps to several addresses, remove only this one' },
    // Accepted for contract symmetry; deletion matches on name(+ip) only.
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Accepted for contract symmetry — not used by the delete' },
  },
  execute: async (ctx, input) => {
    if (!sshAvailable(ctx)) return noSshResult();
    const ssh = ctx.backend.ssh!;

    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = typeof input.ip === 'string' && input.ip.trim() ? input.ip.trim() : null;
    if (!name) return failResult('`name` is required');

    // 1. Live state — refuse to write when the read fails (state unknown).
    const sections = await readHostSections(ssh);
    if (sections === null) return failResult('could not read current uci dhcp host records — state unknown, refusing to write');

    const targets = sections.filter((s) => s.name === name && (ip === null || s.ip === ip));
    if (targets.length === 0) {
      // Absence was CONFIRMED by the live read (verified).
      return okResult({ skipped: `no DNS entry named "${name}"${ip ? ` → ${ip}` : ''} on this device` }, true);
    }

    // 2. One batch: delete each section + commit + dnsmasq restart.
    const cmds = targets.map((t) => uciDelCmd('dhcp', t.key));
    const r = await runCommands(ssh, [...cmds, uciCommitCmd(), '/etc/init.d/dnsmasq restart >/dev/null 2>&1 || true']);
    if (!r.ok) return failResult(`dns.delete failed: ${r.stderr.slice(0, 300)}`);

    // 3. Verify absence by re-read.
    const after = await readHostSections(ssh);
    if (after === null) return okResult({ removed: targets.length }, false);
    const leftover = ip === null
      ? after.some((s) => s.name === name)
      : after.some((s) => s.name === name && s.ip === ip);
    if (leftover) return failResult(`entry ${name}${ip ? ` → ${ip}` : ''} still present after delete`);

    // `verified` is TOP-LEVEL on ActionResult (SDK contract).
    return okResult({ removed: targets.length }, true);
  },
};

export const dnsIntentActions: ActionDescriptor[] = [dnsSetAction, dnsDeleteAction];
