/**
 * Canonical fleet intents for OPNsense — `dns.set` / `dns.delete`.
 *
 * Static DNS host entries live in the appliance's active DNS backend (dnsmasq
 * host records on older installs, Unbound local-zone overrides on newer ones;
 * auto-detected per appliance via ctx.dnsBackend). Both intents are
 * SELF-CONTAINED: they stage the change AND reconfigure the service inside one
 * step, then verify by re-reading — so a plan fan-out (deviceCount 'N') needs
 * no extra steps. Idempotent: set on an existing identical entry is a skip;
 * delete of a missing name is a skip.
 */

import { INTENT_DNS_SET, INTENT_DNS_DELETE, INTENT_DNS_RENAME } from '@unm/plugin-sdk';
import * as dns from '../client/dns';
import type { ActionDescriptor } from './types';

/** True when an OPNsense item-controller write actually succeeded (HTTP 200 alone is not proof). */
function writeOk(res: { ok: boolean; data: unknown }): boolean {
  if (!res.ok) return false;
  const d = res.data as Record<string, unknown> | null;
  if (!d || typeof d !== 'object') return true; // no body — treat transport success as ok
  if (typeof d['result'] === 'string') return d['result'] === 'success';
  return !('validations' in d);
}

/** Reads the live host records, or null when the read failed. */
async function readHosts(ctx: { client: import('axios').AxiosInstance; dnsBackend: dns.DnsBackend }): Promise<Array<{ name: string; ip: string; domain?: string }> | null> {
  try {
    const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
    return res.ok && res.data ? dns.parseHostRecordRows(res.data) : null;
  } catch {
    return null;
  }
}

/** Applies staged DNS changes and verifies the expected entries are present.
 * `verified` is only true when the post-apply RE-READ confirmed the state —
 * a failed verification read must NOT claim verified (the plan executor maps
 * top-level ActionResult.verified to succeeded vs unverified). When an entry
 * carries a `domain`, the re-read row's domain must match too (unbound splits
 * records into bare hostname + separate domain field). */
async function applyAndVerify(
  ctx: { client: import('axios').AxiosInstance; dnsBackend: dns.DnsBackend },
  expect: Array<{ name: string; ip: string; domain?: string }>,
): Promise<{ ok: boolean; verified: boolean; detail: string }> {
  const reconf = await dns.reconfigureDns(ctx.client, ctx.dnsBackend);
  if (!writeOk(reconf)) return { ok: false, verified: false, detail: `DNS reconfigure failed: ${JSON.stringify(reconf.data).slice(0, 200)}` };
  const after = await readHosts(ctx);
  if (after === null) return { ok: true, verified: false, detail: 'applied; verification read unavailable' };
  for (const want of expect) {
    const match = after.some((r) => r.name === want.name && r.ip === want.ip && (want.domain === undefined || r.domain === want.domain));
    if (!match) return { ok: false, verified: false, detail: `entry ${want.name}${want.domain ? `.${want.domain}` : ''} → ${want.ip} not present after reconfigure` };
  }
  return { ok: true, verified: true, detail: 'verified by re-read' };
}

/** Normalizes a raw row's domain field (unbound only; dnsmasq has none). */
function normDomain(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined;
  const d = v.trim().toLowerCase().replace(/\.$/, '');
  return d === '' ? undefined : d;
}

// --- dns.set --------------------------------------------------------------------

export const dnsSetAction: ActionDescriptor = {
  id: INTENT_DNS_SET,
  label: 'Add/update static DNS entry (hostname → IP)',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname (RFC 1123; stored lowercase by UNM)' },
    ip: { type: 'string' as const, required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'IPv4 or IPv6 address the hostname resolves to (record type A/AAAA is derived from the shape)' },
    // Unbound host overrides split a record into bare hostname + separate domain;
    // dnsmasq has no such field (ignored there).
    domain: { type: 'string' as const, required: false, maxLength: 253, description: 'Optional domain suffix — persisted on unbound backends (native field), ignored on dnsmasq' },
    // Unbound host overrides carry a native free-text `description` and persist
    // it; dnsmasq rows have no such field (ignored there).
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Optional note — persisted on unbound backends (native field), ignored on dnsmasq' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = String(input.ip ?? '').trim();
    if (!name || !ip) return { success: false, error: 'both `name` and `ip` are required' };
    // Domain only exists on the unbound backend — dnsmasq records have none.
    const rawDomain = typeof input.domain === 'string' ? input.domain.trim().toLowerCase().replace(/\.$/, '') : '';
    const domain = ctx.dnsBackend === 'unbound' && rawDomain !== '' ? rawDomain : undefined;

    // Raw rows — we need the uuids for in-place updates (parseHostRecordRows drops them).
    let rawRows: Array<Record<string, unknown>> = [];
    try {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      if (!res.ok || !res.data) return { success: false, error: 'could not read current DNS host records — state unknown, refusing to write' };
      rawRows = ((res.data as { rows?: unknown[] }).rows ?? []).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
    } catch (e) {
      return { success: false, error: `DNS host read failed: ${e instanceof Error ? e.message : String(e)}` };
    }
    const rowName = (r: Record<string, unknown>): string =>
      typeof r['name'] === 'string' ? r['name'].trim().toLowerCase() : typeof r['hostname'] === 'string' ? (r['hostname'] as string).trim().toLowerCase() : '';
    // dnsmasq rows carry `ip`; unbound override rows carry the address in
    // `server` (verified live on OPNsense 26.4).
    const rowIp = (r: Record<string, unknown>): string =>
      typeof r['ip'] === 'string' && r['ip'].trim() !== '' ? r['ip'].trim()
        : typeof r['server'] === 'string' && r['server'].trim() !== '' ? r['server'].trim()
          : typeof r['address'] === 'string' ? (r['address'] as string).trim() : '';
    const rowDomain = (r: Record<string, unknown>): string | undefined => normDomain(r['domain']);

    // Idempotency — identical entry already present. When no domain is requested
    // (the common UI path), match on name+ip alone so re-setting an unbound entry
    // that carries a domain still skips instead of duplicating it.
    const sameEntry = (r: Record<string, unknown>): boolean =>
      rowName(r) === name && rowIp(r) === ip && (domain === undefined || rowDomain(r) === domain);
    if (rawRows.some(sameEntry)) {
      // The desired state was CONFIRMED present by the live read (verified).
      return { success: true, verified: true, details: { skipped: `entry ${name}${domain ? `.${domain}` : ''} → ${ip} already exists` } };
    }

    const details: Record<string, unknown> = {};
    // Same name with a DIFFERENT address/domain → update in place (delete the
    // rows that do NOT match the desired entry, then add it).
    for (const r of rawRows.filter((r) => rowName(r) === name && !sameEntry(r))) {
      const uuid = typeof r['uuid'] === 'string' ? r['uuid'] : null;
      if (!uuid) continue;
      const del = await dns.deleteHostRecord(ctx.client, ctx.dnsBackend, uuid);
      if (writeOk(del)) details.updatedFrom = rowIp(r);
    }

    // Unbound persists the native domain + description; dnsmasq ignores both.
    const addRes = await dns.addHostRecord(ctx.client, ctx.dnsBackend, { name, ip, ...(domain !== undefined ? { domain } : {}), ...(typeof input.description === 'string' && input.description.trim() !== '' ? { description: input.description.trim() } : {}) });
    if (!writeOk(addRes)) return { success: false, error: `DNS host add failed: ${JSON.stringify(addRes.data).slice(0, 300)}` };

    const v = await applyAndVerify(ctx, [{ name, ip, ...(domain !== undefined ? { domain } : {}) }]);
    if (!v.ok) return { success: false, error: v.detail };
    // `verified` is TOP-LEVEL on ActionResult (SDK contract).
    return { success: true, applied: true, verified: v.verified, details };
  },
};

// --- dns.delete -----------------------------------------------------------------

export const dnsDeleteAction: ActionDescriptor = {
  id: INTENT_DNS_DELETE,
  label: 'Remove static DNS entry (hostname)',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove' },
    ip: { type: 'string' as const, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — when the name maps to several addresses, remove only this one' },
    // Accepted for contract symmetry; deletion matches on name(+ip) only.
    description: { type: 'string' as const, required: false, maxLength: 255, description: 'Accepted for contract symmetry — not used by the delete' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim().toLowerCase();
    const ip = typeof input.ip === 'string' && input.ip.trim() ? input.ip.trim() : null;
    if (!name) return { success: false, error: '`name` is required' };

    // Raw rows (need the uuids — parseHostRecordRows drops them).
    let rawRows: Array<Record<string, unknown>> = [];
    try {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      if (!res.ok || !res.data) return { success: false, error: 'could not read current DNS host records — state unknown, refusing to write' };
      rawRows = ((res.data as { rows?: unknown[] }).rows ?? []).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
    } catch (e) {
      return { success: false, error: `DNS host read failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const rowName = (r: Record<string, unknown>): string =>
      typeof r['name'] === 'string' ? r['name'].trim().toLowerCase() : typeof r['hostname'] === 'string' ? (r['hostname'] as string).trim().toLowerCase() : '';
    // dnsmasq rows carry `ip`; unbound override rows carry the address in
    // `server` (verified live on OPNsense 26.4).
    const rowIp = (r: Record<string, unknown>): string =>
      typeof r['ip'] === 'string' && r['ip'].trim() !== '' ? r['ip'].trim()
        : typeof r['server'] === 'string' && r['server'].trim() !== '' ? r['server'].trim()
          : typeof r['address'] === 'string' ? (r['address'] as string).trim() : '';

    const targets = rawRows.filter((r) => rowName(r) === name && (ip === null || rowIp(r) === ip));
    if (targets.length === 0) {
      // Absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}"${ip ? ` → ${ip}` : ''} on this device` } };
    }

    for (const t of targets) {
      const uuid = typeof t['uuid'] === 'string' ? t['uuid'] : null;
      if (!uuid) return { success: false, error: `entry ${name} has no uuid — cannot address it for deletion` };
      const del = await dns.deleteHostRecord(ctx.client, ctx.dnsBackend, uuid);
      if (!writeOk(del)) return { success: false, error: `DNS host delete failed: ${JSON.stringify(del.data).slice(0, 300)}` };
    }

    // Verification: the name must be gone (or only other addresses of it remain when ip-scoped).
    const reconf = await dns.reconfigureDns(ctx.client, ctx.dnsBackend);
    if (!writeOk(reconf)) return { success: false, error: `DNS reconfigure failed: ${JSON.stringify(reconf.data).slice(0, 200)}` };
    let afterRaw: Array<Record<string, unknown>> | null = [];
    try {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      if (res.ok && res.data) afterRaw = ((res.data as { rows?: unknown[] }).rows ?? []).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
    } catch { afterRaw = null; /* verification read unavailable — applied but unverified */ }
    if (afterRaw !== null) {
      const leftover = ip === null
        ? afterRaw.some((r) => rowName(r) === name)
        : afterRaw.some((r) => rowName(r) === name && rowIp(r) === ip);
      if (leftover) return { success: false, error: `entry ${name}${ip ? ` → ${ip}` : ''} still present after delete` };
    }

    // `verified` is TOP-LEVEL on ActionResult (SDK contract); a failed re-read
    // must not claim verified.
    return { success: true, applied: true, verified: afterRaw !== null, details: { removed: targets.length } };
  },
};

// --- dns.rename -------------------------------------------------------------------

export const dnsRenameAction: ActionDescriptor = {
  id: INTENT_DNS_RENAME,
  label: 'Rename static DNS entry (hostname)',
  description:
    'Renames a static DNS host entry in place — every address of the old name moves to the new name. On unbound backends each record\'s domain and native description are preserved; dnsmasq records carry no such fields. Idempotent — already renamed is a skip.',
  module: 'DNS',
  riskLevel: 'write',
  // Canonical fleet intent — FANS OUT across the batch (one step per appliance).
  deviceCount: 'N' as const,
  timeoutMs: 120_000,
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

    // Raw rows — we need the uuids + per-record domain/description (parseHostRecordRows drops them).
    let rawRows: Array<Record<string, unknown>> = [];
    try {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      if (!res.ok || !res.data) return { success: false, error: 'could not read current DNS host records — state unknown, refusing to write' };
      rawRows = ((res.data as { rows?: unknown[] }).rows ?? []).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
    } catch (e) {
      return { success: false, error: `DNS host read failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const rowName = (r: Record<string, unknown>): string =>
      typeof r['name'] === 'string' ? r['name'].trim().toLowerCase() : typeof r['hostname'] === 'string' ? (r['hostname'] as string).trim().toLowerCase() : '';
    const rowIp = (r: Record<string, unknown>): string =>
      typeof r['ip'] === 'string' && r['ip'].trim() !== '' ? r['ip'].trim()
        : typeof r['server'] === 'string' && r['server'].trim() !== '' ? r['server'].trim()
          : typeof r['address'] === 'string' ? (r['address'] as string).trim() : '';

    const targets = rawRows.filter((r) => rowName(r) === name);
    if (targets.length === 0) {
      // Absence was CONFIRMED by the live read (verified).
      return { success: true, verified: true, details: { skipped: `no DNS entry named "${name}" on this device` } };
    }

    // Collision guard — a DIFFERENT record already holds the new name. Merging
    // would silently mix two logical entries; refuse and let the caller decide.
    const collision = rawRows.find((r) => rowName(r) === newName);
    if (collision) {
      return { success: false, error: `entry "${newName}" already exists on this device (${rowIp(collision)}) — delete or rename it first` };
    }

    // Rename each record in place: delete the old row, re-add with the new name.
    // Unbound records carry a native domain + description — preserve both; dnsmasq
    // rows have neither (the client ignores them there).
    for (const t of targets) {
      const uuid = typeof t['uuid'] === 'string' ? t['uuid'] : null;
      if (!uuid) return { success: false, error: `entry ${name} has no uuid — cannot address it for rename` };
      const del = await dns.deleteHostRecord(ctx.client, ctx.dnsBackend, uuid);
      if (!writeOk(del)) return { success: false, error: `DNS host delete failed: ${JSON.stringify(del.data).slice(0, 300)}` };
      const domain = normDomain(t['domain']);
      const description = typeof t['description'] === 'string' && t['description'].trim() !== '' ? t['description'].trim() : undefined;
      const addRes = await dns.addHostRecord(ctx.client, ctx.dnsBackend, { name: newName, ip: rowIp(t), ...(domain !== undefined ? { domain } : {}), ...(description !== undefined ? { description } : {}) });
      if (!writeOk(addRes)) return { success: false, error: `DNS host re-add as ${newName} failed: ${JSON.stringify(addRes.data).slice(0, 300)}` };
    }

    // Verify by re-read — the old name is gone and every address now sits under
    // the new name (with its domain intact on unbound).
    const v = await applyAndVerify(ctx, targets.map((t) => {
      const d = normDomain(t['domain']);
      return { name: newName, ip: rowIp(t), ...(d !== undefined ? { domain: d } : {}) };
    }));
    if (!v.ok) return { success: false, error: v.detail };
    let afterRaw: Array<Record<string, unknown>> | null = [];
    try {
      const res = await dns.searchHostRecords(ctx.client, ctx.dnsBackend);
      if (res.ok && res.data) afterRaw = ((res.data as { rows?: unknown[] }).rows ?? []).filter((r): r is Record<string, unknown> => !!r && typeof r === 'object');
    } catch { afterRaw = null; /* verification read unavailable — applied but unverified */ }
    if (afterRaw !== null && afterRaw.some((r) => rowName(r) === name)) {
      return { success: false, error: `entry ${name} still present after rename` };
    }

    // `verified` is TOP-LEVEL on ActionResult.
    return { success: true, applied: true, verified: v.verified && afterRaw !== null, details: { renamedFrom: name, records: targets.length } };
  },
};

export const dnsIntentActions: ActionDescriptor[] = [dnsSetAction, dnsDeleteAction, dnsRenameAction];
