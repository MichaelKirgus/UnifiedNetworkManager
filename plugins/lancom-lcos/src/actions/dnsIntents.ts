/**
 * Canonical fleet intents for LCOS routers — `dns.set` / `dns.delete`.
 *
 * Static DNS host entries live in the Setup/DNS/DNS-List table (CLI:
 * `cd /Setup/DNS/DNS-List`; SNMP config mirror: 11.2.17.5, verified live on
 * GW_Ralf 2026-10). The READ path is SNMP (the primary credential — no SSH
 * slot needed for idempotency checks); the WRITE path is the interactive CLI
 * over SSH PTY (SNMP SET cannot create rows in this table — same limitation as
 * the network tables, see networkIntents.ts). Verified live on WLC01 2026-10:
 *   add "NAME" 0 <v4>            (3 values; v6 column defaults to ::)
 *   add "NAME" 0 0.0.0.0 <v6>    (explicit zero-v4 placeholder for v6-only rows)
 *   del Setup/DNS/DNS-List/<name>        (single-key table — removes the whole row)
 * An empty quoted value ("") is REJECTED by the CLI (`Value invalid: "`).
 * Both writes are verified by a CLI `dir -a` re-read inside cliAddRow/cliDelRow.
 * Idempotent: set on an existing identical entry is a skip; delete of a missing
 * name is a skip. The table is single-keyed by Host-name — one v4 + one v6 per
 * row, so dns.set with the same name but different address replaces in place
 * (del + add).
 */

import { INTENT_DNS_SET, INTENT_DNS_DELETE, INTENT_DNS_RENAME } from '@unm/plugin-sdk';
import type { SshCredentials } from '@unm/plugin-sdk';
import { snmpWalkMulti } from '@unm/snmp-client';
import { splitRow } from '@unm/lancom-shared';
import { DNS_LIST } from '../lcosOids';
import { decodeDnsIndex } from '../lcosClient';
import { ActionContext, ActionDescriptor, ActionResult } from './types';
import { sshCreds, cliTableRows, cliAddRow, cliDelRow } from './networkIntents';

const NO_SSH_SLOT_ERROR =
  'No `ssh` credential slot bound — bind a usernamePassword or sshKeyPair secret to the assignment\'s "ssh" slot for CLI-based DNS writes.';

/** Quotes an LCOS CLI value in double quotes (same convention as networkIntents). */
function q(v: string): string {
  return `"${v}"`;
}

/** One parsed DNS-List row (SNMP config mirror). */
interface DnsRow {
  name: string; // case preserved as configured
  ip: string; // '' when absent
  ipv6: string; // '' when absent ('::' normalized away)
}

/** Reads the live DNS-List table via SNMP (null on read failure — state unknown). */
async function readDnsRows(ctx: ActionContext): Promise<DnsRow[] | null> {
  try {
    // GetBulk multi-walk, NOT snmpWalk: the LCOS agent's getNext path returns
    // nothing for this table (verified live on GW_Ralf — subtree() yields 0 OIDs
    // while a single-base GetBulk walk yields all rows).
    const out = await snmpWalkMulti(ctx.host, ctx.credentials.snmp, [DNS_LIST.base], ctx.opts);
    const byName = new Map<string, DnsRow>();
    for (const [oid, value] of out) {
      const row = splitRow(oid, DNS_LIST.base);
      if (!row) continue;
      const name = decodeDnsIndex(row.idx);
      if (!name) continue;
      let e = byName.get(name);
      if (!e) { e = { name, ip: '', ipv6: '' }; byName.set(name, e); }
      switch (row.col) {
        // '0.0.0.0' in the v4 column = LCOS's placeholder for a v6-only row
        // (verified live on WLC01 2026-10) — normalize away like '::'.
        case DNS_LIST.COL_IP: e.ip = String(value).trim() === '0.0.0.0' ? '' : String(value).trim(); break;
        case DNS_LIST.COL_IPV6: e.ipv6 = String(value).trim() === '::' ? '' : String(value).trim(); break;
        default: break; // COL_NAME echoes the index, COL_RTG_TAG is not needed for writes
      }
    }
    return [...byName.values()];
  } catch {
    return null;
  }
}

/** True when a CLI `dir -a` row carries the given name + (optional) address. */
function cliRowMatches(rows: string[], name: string, ip: string | null): boolean {
  for (const raw of rows) {
    const m = /^"([^"]+)"|^\S+/.exec(raw.trim());
    if (!m) continue;
    if ((m[1] ?? m[0]).toUpperCase() !== name.toUpperCase()) continue;
    if (ip === null) return true;
    // LCOS wraps long rows across lines (parseDirARows merges them with a space),
    // so an address can be split mid-token — strip ALL whitespace before matching.
    // Works for both v4 and v6 (v6 is case-insensitive on the wire).
    return raw.replace(/\s+/g, '').toLowerCase().includes(ip.toLowerCase());
  }
  return false;
}

/**
 * Builds the CLI `add` value list for a DNS-List row from its two address
 * columns. Column order: Host-name Rtg-tag IP-Address(v4) IPV6-Address(v6).
 * Verified live on WLC01 (LCOS vRouter 10.94, 2026-10): an EMPTY quoted value
 * is rejected (`Value invalid: "`), so the unset family is expressed per shape —
 *   both:    add "NAME" 0 <v4> <v6>        (dual row in ONE command)
 *   v4-only: add "NAME" 0 <v4>             (v6 column defaults to ::)
 *   v6-only: add "NAME" 0 0.0.0.0 <v6>     (explicit zero-v4 placeholder + v6)
 */
function dnsAddValues(name: string, v4: string | null, v6: string | null): string[] {
  if (v4 && v6) return [q(name), '0', v4, v6];
  if (v4) return [q(name), '0', v4];
  if (v6) return [q(name), '0', '0.0.0.0', v6];
  throw new Error('dnsAddValues: at least one address is required');
}

// --- dns.set --------------------------------------------------------------------

export const dnsSetAction: ActionDescriptor = {
  id: INTENT_DNS_SET,
  label: 'Add/update static DNS entry (hostname → IP)',
  description:
    'Adds a row to Setup/DNS/DNS-List via the LCOS CLI (SNMP read for state). Idempotent — an identical name+address is skipped; the same name with a different address replaces in place. Verified by a CLI re-read.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname (stored lowercase by UNM; LCOS preserves the configured case)' },
    ip: { type: 'string' as const, required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'IPv4 or IPv6 address the hostname resolves to (one row per family on LCOS)' },
    // Optional second family — lets a single call write BOTH v4 and v6 into one
    // DNS-List row. When omitted, the sibling address of an existing row is
    // preserved (a v4-only set never wipes the row's v6, and vice versa).
    ipv6: { type: 'string' as const, required: false, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional IPv6 address to store alongside `ip` in the same row (dual A+AAAA entry)' },
    // The DNS-List table has no native note field — accepted for contract
    // symmetry, ignored on write.
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Optional note — not stored (LCOS has no native field for it)' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const name = String(input.name ?? '').trim();
    const ip = String(input.ip ?? '').trim();
    if (!name || !ip) return { success: false, error: 'both `name` and `ip` are required' };

    // 1. Live state (SNMP — the primary credential). Refuse to write when unknown.
    const rows = await readDnsRows(ctx);
    if (rows === null) return { success: false, error: 'could not read Setup/DNS/DNS-List via SNMP — state unknown, refusing to write' };

    // 2. Build the DESIRED row from the requested address(es), preserving any
    // sibling family already on the device. The DNS-List table is single-keyed
    // by name with one v4 + one v6 column; a second `add` for an existing name
    // REPLACES the whole row (verified live on WLC01 2026-10), so we must write
    // both families in ONE command or the untouched family is wiped.
    const desired: { v4: string | null; v6: string | null } = ip.includes(':') ? { v4: null, v6: ip } : { v4: ip, v6: null };
    const extra = typeof input.ipv6 === 'string' ? input.ipv6.trim() : '';
    if (extra && extra !== ip) desired.v6 = extra; // explicit second family wins
    const existing = rows.find((r) => r.name.toLowerCase() === name.toLowerCase());
    if (existing) {
      if (!desired.v4 && existing.ip) desired.v4 = existing.ip;   // keep the row's v4
      if (!desired.v6 && existing.ipv6) desired.v6 = existing.ipv6; // keep the row's v6
    }

    // Idempotency — desired state already matches what is on the device.
    if (existing && (existing.ip ?? '') === (desired.v4 ?? '') && (existing.ipv6 ?? '') === (desired.v6 ?? '')) {
      // The desired state was CONFIRMED present → self-evidently verified.
      return { success: true, verified: true, details: { skipped: `entry ${name} already holds ${[desired.v4, desired.v6].filter(Boolean).join(' + ')}` } };
    }

    // 3. Write the row — del first when replacing (proven across firmware), then a
    // single add carrying BOTH families so neither is lost.
    if (existing) {
      const del = await cliDelRow(ctx, creds, 'DNS/DNS-List', existing.name);
      if (!del.ok) return { success: false, error: `Failed to remove old entry ${existing.name}: ${del.detail}` };
    }
    const r = await cliAddRow(ctx, creds, 'DNS/DNS-List', dnsAddValues(name, desired.v4, desired.v6), name);
    if (!r.ok) return { success: false, error: `Failed to add DNS entry ${name} → ${[desired.v4, desired.v6].filter(Boolean).join(' + ')}: ${r.detail}` };

    // 4. Verify by CLI re-read — every requested address must be present.
    const after = await cliTableRows(ctx, creds, 'DNS/DNS-List');
    for (const addr of [desired.v4, desired.v6]) {
      if (addr && !cliRowMatches(after, name, addr)) {
        return { success: false, error: `entry ${name} → ${addr} not present in DNS-List after add` };
      }
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract) — the plan
    // executor reads result.verified to decide succeeded vs unverified.
    return { success: true, applied: true, verified: true, details: { replacedFrom: existing ? [existing.ip, existing.ipv6].filter(Boolean).join(' + ') || null : null } };
  },
};

// --- dns.delete -----------------------------------------------------------------

export const dnsDeleteAction: ActionDescriptor = {
  id: INTENT_DNS_DELETE,
  label: 'Remove static DNS entry (hostname)',
  description:
    'Removes the Setup/DNS/DNS-List row for a hostname via the LCOS CLI (SNMP read for state). The table is single-keyed by name — this removes ALL addresses of that name. Idempotent — a missing name is skipped.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove (without `ip`: removes the whole row — all its addresses)' },
    ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — remove only THIS address. On a dual (v4+v6) row the surviving family is kept; without it the whole row is removed.' },
    // Accepted for contract symmetry; deletion matches on name(+ip) only.
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Accepted for contract symmetry — not used by the delete' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const name = String(input.name ?? '').trim();
    const ip = typeof input.ip === 'string' && input.ip.trim() ? input.ip.trim() : null;
    if (!name) return { success: false, error: '`name` is required' };

    // 1. Live state (SNMP). Refuse to write when unknown.
    const rows = await readDnsRows(ctx);
    if (rows === null) return { success: false, error: 'could not read Setup/DNS/DNS-List via SNMP — state unknown, refusing to write' };

    const existing = rows.find((r) => r.name.toLowerCase() === name.toLowerCase());
    if (!existing) {
      // Idempotent skip — absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}" on this device` } };
    }
    // ip-scoped guard — the row must actually carry the requested address.
    if (ip !== null && existing.ip !== ip && existing.ipv6 !== ip) {
      return { success: true, verified: true, details: { skipped: `entry ${existing.name} does not carry ${ip} (has ${[existing.ip, existing.ipv6].filter(Boolean).join(', ') || 'no address'})` } };
    }

    // 2. Decide the outcome. Without an ip scope the WHOLE row goes. With one,
    // a dual (v4+v6) row keeps its surviving family — we must REWRITE it with
    // only that address, because `del` removes the entire single-keyed row and
    // would wipe the sibling too.
    const survivor: { v4: string | null; v6: string | null } = ip === null
      ? { v4: null, v6: null }
      : (ip.includes(':') ? { v4: existing.ip || null, v6: null } : { v4: null, v6: existing.ipv6 || null });

    // 3. Delete the row by name from the root prompt (verified inside cliDelRow).
    const r = await cliDelRow(ctx, creds, 'DNS/DNS-List', existing.name);
    if (!r.ok) return { success: false, error: `Failed to delete DNS entry ${existing.name}: ${r.detail}` };

    // 4. Re-add the surviving family when one remains (dual row → single-family).
    if (survivor.v4 || survivor.v6) {
      const add = await cliAddRow(ctx, creds, 'DNS/DNS-List', dnsAddValues(existing.name, survivor.v4, survivor.v6), existing.name);
      if (!add.ok) return { success: false, error: `Failed to restore surviving address of ${existing.name}: ${add.detail}` };
    }

    // 5. Verify by CLI re-read — the removed address is gone; a survivor (if any) remains.
    const after = await cliTableRows(ctx, creds, 'DNS/DNS-List');
    if (ip !== null && cliRowMatches(after, name, ip)) {
      return { success: false, error: `entry ${existing.name} → ${ip} still present in DNS-List after delete` };
    }
    for (const addr of [survivor.v4, survivor.v6]) {
      if (addr && !cliRowMatches(after, name, addr)) {
        return { success: false, error: `entry ${existing.name} → ${addr} lost during family-scoped delete` };
      }
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract).
    return { success: true, applied: true, verified: true, details: ip === null ? { removed: 1 } : { removedAddress: ip, kept: [survivor.v4, survivor.v6].filter(Boolean).join(' + ') || null } };
  },
};

// --- dns.rename -------------------------------------------------------------------

export const dnsRenameAction: ActionDescriptor = {
  id: INTENT_DNS_RENAME,
  label: 'Rename static DNS entry (hostname)',
  description:
    'Renames a Setup/DNS/DNS-List row in place — the whole single-keyed row (both address families of a dual v4+v6 entry) moves to the new name via del + one CLI add. Idempotent — already renamed is a skip.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Current hostname to rename (stored lowercase by UNM)' },
    newName: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'New hostname for the entry' },
  },
  async execute(ctx, input): Promise<ActionResult> {
    const creds = sshCreds(ctx);
    if (!creds) return { success: false, error: NO_SSH_SLOT_ERROR };

    const name = String(input.name ?? '').trim();
    const newName = String(input.newName ?? '').trim().toLowerCase();
    if (!name || !newName) return { success: false, error: 'both `name` and `newName` are required' };
    if (name.toLowerCase() === newName) {
      // Idempotent skip — nothing to rename.
      return { success: true, verified: true, details: { skipped: `entry ${name} is already named "${newName}"` } };
    }

    // 1. Live state (SNMP). Refuse to write when unknown.
    const rows = await readDnsRows(ctx);
    if (rows === null) return { success: false, error: 'could not read Setup/DNS/DNS-List via SNMP — state unknown, refusing to write' };

    const existing = rows.find((r) => r.name.toLowerCase() === name.toLowerCase());
    if (!existing) {
      // Idempotent skip — absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}" on this device` } };
    }

    // Collision guard — a DIFFERENT row already holds the new name. Merging two
    // logical entries would silently mix their addresses; refuse and let the
    // caller decide (delete or rename that one first).
    if (rows.some((r) => r.name.toLowerCase() === newName && r !== existing)) {
      return { success: false, error: `entry "${newName}" already exists on this device — delete or rename it first` };
    }

    // 2. Rename = del the old row + ONE add under the new name carrying BOTH
    // families (the table is single-keyed; a second add would replace, not merge).
    const del = await cliDelRow(ctx, creds, 'DNS/DNS-List', existing.name);
    if (!del.ok) return { success: false, error: `Failed to remove old entry ${existing.name}: ${del.detail}` };
    const r = await cliAddRow(ctx, creds, 'DNS/DNS-List', dnsAddValues(newName, existing.ip || null, existing.ipv6 || null), newName);
    if (!r.ok) return { success: false, error: `Failed to re-add DNS entry as ${newName}: ${r.detail}` };

    // 3. Verify by CLI re-read — the old name is gone; every address of the row
    // now sits under the new name.
    const after = await cliTableRows(ctx, creds, 'DNS/DNS-List');
    if (cliRowMatches(after, existing.name, null)) {
      return { success: false, error: `entry ${existing.name} still present in DNS-List after rename` };
    }
    for (const addr of [existing.ip, existing.ipv6]) {
      if (addr && !cliRowMatches(after, newName, addr)) {
        return { success: false, error: `address ${addr} not present under "${newName}" in DNS-List after rename` };
      }
    }

    // `verified` is TOP-LEVEL on ActionResult.
    return { success: true, applied: true, verified: true, details: { renamedFrom: existing.name, addresses: [existing.ip, existing.ipv6].filter(Boolean).join(' + ') || null } };
  },
};

export const dnsIntentActions: ActionDescriptor[] = [dnsSetAction, dnsDeleteAction, dnsRenameAction];
