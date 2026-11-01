/**
 * LCOS DHCP static-host (reservation) intents — `dhcp.staticMapping.add` /
 * `dhcp.staticMapping.delete`.
 *
 * Reservations live in the Setup/DHCP/Hosts table (CLI: `cd /Setup/DHCP/Hosts`;
 * SNMP config mirror: 11.2.10.9, verified live on GW_Ralf + WLC01, LCOS 10.94,
 * 2026-10). The READ path is SNMP (the primary credential — no SSH slot needed
 * for idempotency checks); the WRITE path is the interactive CLI over SSH PTY
 * (SNMP SET cannot create rows in this table — same limitation as every other
 * LCOS setup table, see networkIntents.ts). Verified live on WLC01 2026-10:
 *   add <bareMac> <NetworkName> <ip> "" ""     (TAB-HEADER column order!)
 *   del Setup/DHCP/Hosts/<bareMac>             (single-key table, from root prompt)
 * Key facts that shape the actions below:
 *  - The MAC is BARE lowercase hex ("00a0574c1acf") — no colons. UNM stores and
 *    sends colon form; we normalize before writing.
 *  - `add` takes values in TAB-HEADER order [MAC, Network-name, IP-Address,
 *    Hostname, Image-alias] — NOT the numeric column order shown under the
 *    header (IP is display-col 2 but value-position 3). Empty optional columns
 *    are passed as quoted empty strings ("") — accepted on this table.
 *  - The reservation IP MUST fall inside a configured DHCP pool of that network
 *    name, or LCOS rejects the add with "Value invalid: <ip>". Pools live in
 *    Setup/DHCP/Network-list (SNMP mirror 11.2.10.20) — we pre-check and report
 *    the available pools instead of surfacing the cryptic CLI error.
 *  - Targeted `set` is NOT supported on this table ("Path name wrong") — an
 *    edit is a del + re-add, which the webapp's deleteAdd mode drives with no
 *    vendor-specific code (there is deliberately NO dhcp.staticMapping.set here).
 * Both writes are verified by a CLI `dir -a` re-read inside cliAddRow/cliDelRow.
 * Idempotent: add of an identical row is a skip; delete of a missing MAC is a skip.
 */

import { snmpWalkMulti } from '@unm/snmp-client';
import type { SnmpValue } from '@unm/snmp-client';
import { DHCP_HOSTS, DHCP_NET_LIST } from '../lcosOids';
import { parseDhcpHosts, parseDhcpPools } from '../lcosClient';
import { ActionContext, ActionDescriptor, ActionResult } from './types';
import { sshCreds, cliTableRows, cliAddRow, cliDelRow } from './networkIntents';

const NO_SSH_SLOT_ERROR =
  'No `ssh` credential slot bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot for CLI-based DHCP reservation writes.';

/** Normalizes any MAC spelling (colon/dash/bare, any case) to bare lowercase hex. */
function normalizeBareMac(raw: unknown): string | null {
  const hex = String(raw ?? '').replace(/[^0-9a-f]/gi, '');
  return /^[0-9a-f]{12}$/.test(hex) ? hex : null;
}

/** Dotted v4 → uint32 (null when not a valid address). */
function ipToU32(ip: string): number | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip);
  if (!m) return null;
  let n = 0;
  for (let i = 1; i <= 4; i++) {
    const o = Number(m[i]);
    if (o > 255) return null;
    n = n * 256 + o;
  }
  return n >>> 0;
}

/** Reads the live Hosts + pool tables via SNMP in one walk (null on read failure). */
async function readDhcpState(ctx: ActionContext): Promise<{ hosts: ReturnType<typeof parseDhcpHosts>; pools: ReturnType<typeof parseDhcpPools> } | null> {
  try {
    const out = await snmpWalkMulti(ctx.host, ctx.credentials.snmp, [DHCP_HOSTS.base, DHCP_NET_LIST.base], ctx.opts);
    return { hosts: parseDhcpHosts(out as Map<string, SnmpValue>), pools: parseDhcpPools(out as Map<string, SnmpValue>) };
  } catch {
    return null;
  }
}

/** Human-readable list of the device's pools ("NET_X (10.0.0.10–10.0.0.99)"). */
function poolList(pools: Array<{ name: string; startIp: string; endIp: string }>): string {
  if (pools.length === 0) return 'none configured';
  return pools.map((p) => `${p.name} (${p.startIp || '?'}–${p.endIp || '?'})`).join(', ');
}

/**
 * Resolves the Network-name a reservation must be scoped to. An explicit value
 * (the webapp's network dropdown sends the pool name — see the dhcpNetworks
 * emission in index.ts) wins and is validated against the live pools; otherwise
 * it is derived from the IP by pool-range containment. Returns null + error when
 * no unambiguous scope exists — LCOS would reject the add with "Value invalid".
 */
function resolvePoolName(
  explicit: string,
  ip: string,
  pools: Array<{ name: string; startIp: string; endIp: string }>
): { name: string | null; error?: string } {
  const ipN = ipToU32(ip);
  if (explicit) {
    const pool = pools.find((p) => p.name.toUpperCase() === explicit.toUpperCase());
    if (!pool && pools.length > 0) {
      return { name: null, error: `network "${explicit}" has no DHCP pool on this device — available pools: ${poolList(pools)}` };
    }
    // Range pre-check (only when the matched pool carries a parseable range).
    if (pool && ipN !== null) {
      const s = ipToU32(pool.startIp);
      const e = ipToU32(pool.endIp);
      if (s !== null && e !== null && (ipN < s || ipN > e)) {
        return { name: null, error: `${ip} is outside the ${pool.name} pool range (${pool.startIp}–${pool.endIp}) — LCOS would reject it` };
      }
    }
    return { name: explicit.toUpperCase() };
  }
  // No explicit scope — find the pools whose range contains the IP.
  if (ipN === null) return { name: null, error: `${ip} is not a valid IPv4 address` };
  const containing = pools.filter((p) => {
    const s = ipToU32(p.startIp);
    const e = ipToU32(p.endIp);
    return s !== null && e !== null && ipN >= s && ipN <= e;
  });
  if (containing.length === 0) {
    return { name: null, error: `no DHCP pool on this device contains ${ip} — available pools: ${poolList(pools)} (create one first, or pass the network name explicitly)` };
  }
  if (containing.length > 1) {
    return { name: null, error: `${ip} falls inside several pools (${containing.map((p) => p.name).join(', ')}) — pass the intended network name explicitly` };
  }
  return { name: containing[0].name.toUpperCase() };
}

/** True when a CLI `dir -a` row is the given MAC and carries the given IP. */
function hostRowMatches(rows: string[], mac: string, ip: string): boolean {
  for (const raw of rows) {
    const m = /^\S+/.exec(raw.trim());
    if (!m || m[0].toLowerCase() !== mac.toLowerCase()) continue;
    // LCOS wraps long rows across lines (parseDirARows merges them with a space),
    // so strip ALL whitespace before matching the address.
    return raw.replace(/\s+/g, '').includes(ip);
  }
  return false;
}

// --- dhcp.staticMapping.add ---------------------------------------------------------

export const dhcpStaticMappingAddAction: ActionDescriptor = {
  id: 'dhcp.staticMapping.add',
  label: 'Add/update DHCP reservation (MAC → fixed IP)',
  description:
    'Adds a row to Setup/DHCP/Hosts via the LCOS CLI (SNMP read for state). Idempotent — an identical MAC+IP+network is skipped; an existing MAC with different values replaces in place (del + add, since targeted set is unsupported on this table). The IP must fall inside a configured DHCP pool of the network scope. Verified by a CLI re-read.',
  module: 'DHCP',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 180_000,
  inputSchema: {
    mac: { type: 'string' as const, required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$', description: 'MAC address (aa:bb:cc:dd:ee:ff or bare hex) — the reservation key' },
    ip: { type: 'string' as const, required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$', description: 'Fixed IPv4 to bind (must fall inside a configured DHCP pool of the network scope)' },
    hostname: { type: 'string' as const, required: false, maxLength: 64, description: 'Optional hostname stored with the reservation' },
    // The LCOS network/pool name the mapping is scoped to. OPTIONAL — when omitted
    // it is resolved from `ip` by pool-range containment (the webapp's network
    // dropdown sends the selected pool name here).
    interface: { type: 'string' as const, required: false, maxLength: 16, description: 'Network/pool name scope (e.g. NET_MANAGEMENT) — resolved from the IP when omitted' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const mac = normalizeBareMac(input.mac);
    if (!mac) return { success: false, error: '`mac` must be a valid MAC address (aa:bb:cc:dd:ee:ff or bare hex)' };
    const ip = String(input.ip ?? '').trim();
    if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) return { success: false, error: '`ip` must be a valid IPv4 address' };
    const hostname = typeof input.hostname === 'string' ? input.hostname.trim() : '';
    if (hostname.length > 64) return { success: false, error: '`hostname` is limited to 64 characters on LCOS' };

    // 1. Live state (SNMP — the primary credential). Refuse to write when unknown.
    const state = await readDhcpState(ctx);
    if (state === null) return { success: false, error: 'could not read Setup/DHCP/Hosts via SNMP — state unknown, refusing to write' };

    // 2. Resolve the network/pool scope (explicit wins; else IP containment).
    const explicit = typeof input.interface === 'string' ? input.interface.trim() : '';
    const resolved = resolvePoolName(explicit, ip, state.pools);
    if (!resolved.name) return { success: false, error: resolved.error ?? 'could not resolve the network scope for this reservation' };

    // Idempotency — desired state already matches what is on the device.
    const existing = state.hosts.find((h) => h.mac === mac);
    if (existing && existing.ip === ip && existing.hostname === hostname && existing.networkName.toUpperCase() === resolved.name) {
      return { success: true, verified: true, details: { skipped: `reservation ${mac} → ${ip} on ${resolved.name} already present` } };
    }

    // 3. Write — del first when replacing (targeted set is unsupported), then add in
    // TAB-HEADER order [MAC, Network-name, IP-Address, Hostname, Image-alias].
    if (existing) {
      const del = await cliDelRow(ctx, creds, 'DHCP/Hosts', existing.mac);
      if (!del.ok) return { success: false, error: `Failed to remove old reservation ${existing.mac}: ${del.detail}` };
    }
    const r = await cliAddRow(ctx, creds, 'DHCP/Hosts', [mac, resolved.name, ip, hostname || '', ''], mac);
    if (!r.ok) {
      // Surface the pool constraint explicitly when LCOS rejected the value.
      if (/value invalid/i.test(r.detail)) {
        return { success: false, error: `LCOS rejected ${ip} for network ${resolved.name}: ${r.detail} — available pools: ${poolList(state.pools)}` };
      }
      return { success: false, error: `Failed to add reservation ${mac} → ${ip} on ${resolved.name}: ${r.detail}` };
    }

    // 4. Verify by CLI re-read — the row must carry both the MAC and the IP.
    const after = await cliTableRows(ctx, creds, 'DHCP/Hosts');
    if (!hostRowMatches(after, mac, ip)) {
      return { success: false, error: `reservation ${mac} → ${ip} not present in DHCP/Hosts after add` };
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract).
    return { success: true, applied: true, verified: true, details: { network: resolved.name, replacedFrom: existing ? `${existing.ip || 'no ip'} on ${existing.networkName}` : null } };
  },
};

// --- dhcp.staticMapping.delete ------------------------------------------------------

export const dhcpStaticMappingDeleteAction: ActionDescriptor = {
  id: 'dhcp.staticMapping.delete',
  label: 'Remove DHCP reservation (MAC)',
  description:
    'Removes the Setup/DHCP/Hosts row for a MAC via the LCOS CLI (SNMP read for state). The table is single-keyed by MAC — this removes the whole mapping. Idempotent — a missing MAC is skipped.',
  module: 'DHCP',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 180_000,
  inputSchema: {
    mac: { type: 'string' as const, required: true, pattern: '^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$|^[0-9A-Fa-f]{12}$', description: 'MAC address of the reservation to remove (aa:bb:cc:dd:ee:ff or bare hex)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const mac = normalizeBareMac(input.mac);
    if (!mac) return { success: false, error: '`mac` must be a valid MAC address (aa:bb:cc:dd:ee:ff or bare hex)' };

    // 1. Live state (SNMP). Refuse to write when unknown.
    const state = await readDhcpState(ctx);
    if (state === null) return { success: false, error: 'could not read Setup/DHCP/Hosts via SNMP — state unknown, refusing to write' };

    const existing = state.hosts.find((h) => h.mac === mac);
    if (!existing) {
      // Idempotent skip — absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DHCP reservation for ${mac} on this device` } };
    }

    // 2. Delete the row by its stored MAC key from the root prompt (cliDelRow
    // re-reads and verifies absence).
    const r = await cliDelRow(ctx, creds, 'DHCP/Hosts', existing.mac);
    if (!r.ok) return { success: false, error: `Failed to delete reservation ${existing.mac}: ${r.detail}` };

    // 3. Verify by CLI re-read — the MAC is gone entirely.
    const after = await cliTableRows(ctx, creds, 'DHCP/Hosts');
    if (hostRowMatches(after, mac, '')) {
      return { success: false, error: `reservation ${mac} still present in DHCP/Hosts after delete` };
    }
    // `verified` is TOP-LEVEL on ActionResult.
    return { success: true, applied: true, verified: true, details: { removed: 1, was: `${existing.ip || 'no ip'} on ${existing.networkName}` } };
  },
};

export const DHCP_INTENT_ACTIONS: ActionDescriptor[] = [dhcpStaticMappingAddAction, dhcpStaticMappingDeleteAction];
