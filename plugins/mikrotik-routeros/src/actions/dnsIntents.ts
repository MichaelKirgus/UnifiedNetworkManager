/**
 * Canonical fleet intents for RouterOS — `dns.set` / `dns.delete`.
 *
 * Static DNS host records live in the `/ip/dns/static` REST table. Both intents
 * are SELF-CONTAINED: they read the current state, apply (RouterOS writes take
 * effect immediately — no staged/reconfigure model), then verify by re-read.
 * Idempotent: set on an existing identical record is a skip; delete of a
 * missing name is a skip. The single-device `dns.host.add` / `dns.host.delete`
 * actions (network.ts) keep their own `address` field for the device-detail UI;
 * these canonical wrappers use the fleet-wide `name` + `ip` contract.
 */

import { INTENT_DNS_SET, INTENT_DNS_DELETE, INTENT_DNS_RENAME } from '@unm/plugin-sdk';
import { rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

/** Reads the live /ip/dns/static table (null on read failure). */
async function readDnsStatic(ctx: ActionContext): Promise<Array<{ name: string; ip: string; id: string | null; description: string }> | null> {
  try {
    const rows = await ctx.client.get<Row[]>('/ip/dns/static');
    if (!Array.isArray(rows)) return null;
    return rows
      .filter((r): r is Row => !!r && typeof r === 'object')
      .map((h) => ({ name: (rosString(h, ['name']) ?? '').trim().toLowerCase(), ip: (rosString(h, ['address']) ?? '').trim(), id: rosString(h, ['.id']) ?? null, description: (rosString(h, ['comment']) ?? '').trim() }))
      .filter((e) => e.name !== '' && e.ip !== '');
  } catch {
    return null;
  }
}

// --- dns.set --------------------------------------------------------------------

export const dnsSetAction: ActionDescriptor = {
  id: INTENT_DNS_SET,
  label: 'Add/update static DNS entry (hostname → IP)',
  description:
    'Adds a local DNS record to /ip/dns/static (A or AAAA by address shape). Idempotent — an identical name+address is skipped; the same name with a different address is updated in place. Verified by re-read.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname (stored lowercase by UNM)' },
    ip: { type: 'string' as const, required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'IPv4 or IPv6 address the hostname resolves to (record type A/AAAA is derived from the shape)' },
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Optional note — stored in the record\'s `comment` field on RouterOS' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = String(input.ip ?? '').trim();
    if (!name || !ip) return { success: false, error: 'both `name` and `ip` are required' };
    // Optional note → RouterOS `comment`. Absent/empty = no comment.
    const description = typeof input.description === 'string' ? input.description.trim() : '';

    // 1. Live state — refuse to write when the read fails (state unknown).
    const entries = await readDnsStatic(ctx);
    if (entries === null) return { success: false, error: 'could not read /ip/dns/static — state unknown, refusing to write' };

    // Idempotency — identical record already present (address AND note).
    const same = entries.find((e) => e.name === name && e.ip === ip);
    if (same && same.description === description) {
      // Idempotent skip — the desired state was CONFIRMED present (verified).
      return { success: true, verified: true, details: { skipped: `entry ${name} → ${ip} already exists` } };
    }

    const details: Record<string, unknown> = {};
    // 2. Same name with a DIFFERENT address (or note) → update in place.
    for (const e of entries.filter((x) => x.name === name && (x.ip !== ip || x.description !== description))) {
      if (!e.id) continue;
      await ctx.client.delete(`/ip/dns/static/${e.id}`).catch(() => undefined);
      details.updatedFrom = e.ip;
    }

    // 3. Add the new record (RouterOS applies immediately).
    try {
      const body: Record<string, unknown> = { name, address: ip };
      if (description !== '') body['comment'] = description;
      await ctx.client.put('/ip/dns/static', body);
    } catch (e) {
      return { success: false, error: `Adding DNS host ${name} failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    // 4. Verify by re-read.
    const after = await readDnsStatic(ctx);
    if (after === null) return { success: true, applied: true, verified: false, details };
    if (!after.some((e) => e.name === name && e.ip === ip)) {
      return { success: false, error: `entry ${name} → ${ip} not present after write` };
    }
    // `verified` is TOP-LEVEL on ActionResult (SDK contract) — the plan
    // executor reads result.verified to decide succeeded vs unverified.
    return { success: true, applied: true, verified: true, details };
  },
};

// --- dns.delete -----------------------------------------------------------------

export const dnsDeleteAction: ActionDescriptor = {
  id: INTENT_DNS_DELETE,
  label: 'Remove static DNS entry (hostname)',
  description:
    'Removes local DNS records from /ip/dns/static by hostname (optionally scoped to one address). Verified by re-read. Idempotent — a missing name is skipped.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove' },
    ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — when the name maps to several addresses, remove only this one' },
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Accepted for contract symmetry — deletion matches on name(+ip) only' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = typeof input.ip === 'string' && input.ip.trim() ? input.ip.trim() : null;
    if (!name) return { success: false, error: '`name` is required' };

    // 1. Live state — refuse to write when the read fails (state unknown).
    const entries = await readDnsStatic(ctx);
    if (entries === null) return { success: false, error: 'could not read /ip/dns/static — state unknown, refusing to write' };

    const targets = entries.filter((e) => e.name === name && (ip === null || e.ip === ip));
    if (targets.length === 0) {
      // Idempotent skip — absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}"${ip ? ` → ${ip}` : ''} on this device` } };
    }

    // 2. Delete each matching record by .id.
    for (const t of targets) {
      if (!t.id) return { success: false, error: `entry ${name} has no .id — cannot address it for deletion` };
      await ctx.client.delete(`/ip/dns/static/${t.id}`).catch(() => undefined);
    }

    // 3. Verify absence by re-read.
    const after = await readDnsStatic(ctx);
    if (after === null) return { success: true, applied: true, verified: false, details: { removed: targets.length } };
    const leftover = ip === null
      ? after.some((e) => e.name === name)
      : after.some((e) => e.name === name && e.ip === ip);
    if (leftover) return { success: false, error: `entry ${name}${ip ? ` → ${ip}` : ''} still present after delete` };

    return { success: true, applied: true, verified: true, details: { removed: targets.length } };
  },
};

// --- dns.rename -------------------------------------------------------------------

export const dnsRenameAction: ActionDescriptor = {
  id: INTENT_DNS_RENAME,
  label: 'Rename static DNS entry (hostname)',
  description:
    'Renames a local DNS record in /ip/dns/static in place — every address of the old name moves to the new name. The record\'s `comment` is preserved by the in-place update. Idempotent — already renamed is a skip.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per router).
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Current hostname to rename (stored lowercase by UNM)' },
    newName: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'New hostname for the entry' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim().toLowerCase();
    const newName = String(input.newName ?? '').trim().toLowerCase();
    if (!name || !newName) return { success: false, error: 'both `name` and `newName` are required' };
    if (name === newName) {
      // Idempotent skip — nothing to rename.
      return { success: true, verified: true, details: { skipped: `entry ${name} is already named "${newName}"` } };
    }

    // 1. Live state — refuse to write when the read fails (state unknown).
    const entries = await readDnsStatic(ctx);
    if (entries === null) return { success: false, error: 'could not read /ip/dns/static — state unknown, refusing to write' };

    const targets = entries.filter((e) => e.name === name);
    if (targets.length === 0) {
      // Absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}" on this device` } };
    }

    // Collision guard — a DIFFERENT record already holds the new name. Merging
    // would silently mix two logical entries; refuse and let the caller decide.
    if (entries.some((e) => e.name === newName)) {
      return { success: false, error: `entry "${newName}" already exists on this device — delete or rename it first` };
    }

    // 2. In-place update of each record's name (RouterOS applies immediately; the
    // comment field is untouched by a partial PUT).
    for (const t of targets) {
      if (!t.id) return { success: false, error: `entry ${name} has no .id — cannot address it for rename` };
      try {
        await ctx.client.put(`/ip/dns/static/${t.id}`, { name: newName });
      } catch (e) {
        return { success: false, error: `Renaming DNS host to ${newName} failed: ${e instanceof Error ? e.message : String(e)}` };
      }
    }

    // 3. Verify by re-read — the old name is gone and every address sits under the new one.
    const after = await readDnsStatic(ctx);
    if (after === null) return { success: true, applied: true, verified: false, details: { renamedFrom: name, records: targets.length } };
    if (after.some((e) => e.name === name)) {
      return { success: false, error: `entry ${name} still present after rename` };
    }
    for (const t of targets) {
      if (!after.some((e) => e.name === newName && e.ip === t.ip)) {
        return { success: false, error: `address ${t.ip} not present under "${newName}" after rename` };
      }
    }

    // `verified` is TOP-LEVEL on ActionResult.
    return { success: true, applied: true, verified: true, details: { renamedFrom: name, records: targets.length } };
  },
};

export const dnsIntentActions: ActionDescriptor[] = [dnsSetAction, dnsDeleteAction, dnsRenameAction];
