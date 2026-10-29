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

import { INTENT_DNS_SET, INTENT_DNS_DELETE } from '@unm/plugin-sdk';
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
  for (const row of rows) {
    const m = /^"([^"]+)"|^\S+/.exec(row.trim());
    if (!m) continue;
    if ((m[1] ?? m[0]).toUpperCase() !== name.toUpperCase()) continue;
    // Columns after the quoted name: Rtg-tag, IP-Address, IPV6-Address.
    const rest = row.slice(m[0].length).trim().split(/\s+/);
    const v4 = rest.find((t) => /^\d{1,3}(\.\d{1,3}){3}$/.test(t)) ?? '';
    if (ip === null || v4 === ip) return true;
  }
  return false;
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

    // Idempotency — identical entry already present (v4 in the IP column or v6 in the IPV6 column).
    const existing = rows.find((r) => r.name.toLowerCase() === name.toLowerCase());
    if (existing && ((ip.includes(':') ? existing.ipv6 : existing.ip) === ip)) {
      // Idempotent skip — the desired state was CONFIRMED present, so it is
      // self-evidently verified (top-level `verified`, SDK contract).
      return { success: true, verified: true, details: { skipped: `entry ${name} → ${ip} already exists` } };
    }

    // 2. Same name with a DIFFERENT address → replace in place (single-key table).
    if (existing) {
      const del = await cliDelRow(ctx, creds, 'DNS/DNS-List', existing.name);
      if (!del.ok) return { success: false, error: `Failed to remove old entry ${existing.name}: ${del.detail}` };
    }

    // 3. Add the row — column order Host-name Rtg-tag IP-Address IPV6-Address.
    // Verified live on WLC01 (LCOS vRouter 10.94, 2026-10): an EMPTY quoted
    // value ("") is rejected with `Value invalid: "`, so the unset family is
    // expressed differently per direction —
    //   v4-only: add "NAME" 0 <v4>            (3 values; v6 column defaults to ::)
    //   v6-only: add "NAME" 0 0.0.0.0 <v6>    (explicit zero-v4 placeholder + v6)
    const isV6 = ip.includes(':');
    const values = [q(name), '0', ...(isV6 ? ['0.0.0.0', ip] : [ip])];
    const r = await cliAddRow(ctx, creds, 'DNS/DNS-List', values, name);
    if (!r.ok) return { success: false, error: `Failed to add DNS entry ${name} → ${ip}: ${r.detail}` };

    // 4. Verify by CLI re-read (cliAddRow already confirmed the row exists).
    const after = await cliTableRows(ctx, creds, 'DNS/DNS-List');
    if (!cliRowMatches(after, name, ip)) {
      return { success: false, error: `entry ${name} → ${ip} not present in DNS-List after add` };
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract) — the plan
    // executor reads result.verified to decide succeeded vs unverified.
    return { success: true, applied: true, verified: true, details: { replacedFrom: existing ? (existing.ip || existing.ipv6) : null } };
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
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove (removes the whole row — all its addresses)' },
    ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — only delete when the row actually carries this address (guards against deleting a different entry with the same name)' },
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

    // 2. Delete the whole row by name from the root prompt (verified inside cliDelRow).
    const r = await cliDelRow(ctx, creds, 'DNS/DNS-List', existing.name);
    if (!r.ok) return { success: false, error: `Failed to delete DNS entry ${existing.name}: ${r.detail}` };

    // 3. Verify absence by CLI re-read (cliDelRow already confirmed).
    const after = await cliTableRows(ctx, creds, 'DNS/DNS-List');
    if (after.some((row) => {
      const m = /^"([^"]+)"|^\S+/.exec(row.trim());
      return !!m && (m[1] ?? m[0]).toUpperCase() === existing.name.toUpperCase();
    })) {
      return { success: false, error: `entry ${existing.name} still present in DNS-List after delete` };
    }
    return { success: true, applied: true, verified: true, details: { removed: 1 } };
  },
};

export const dnsIntentActions: ActionDescriptor[] = [dnsSetAction, dnsDeleteAction];
