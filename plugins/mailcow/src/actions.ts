/**
 * The mailcow action registry — CRUD for domains, mailboxes and aliases through
 * the mailcow REST API (the same endpoints the web UI uses). Serves two entry
 * points (same contract as the other plugins):
 *  - /discover → listCatalog() (the catalog the API persists + validates)
 *  - /config   → getAction(step.actionId).execute(ctx, input) runs one step
 *
 * Idempotency semantics mirror the ix-truenas share actions: "already exists"
 * on create and "not found" on update/delete are reported as success with
 * applied:false (and a note), so re-running a plan never hard-fails. Writes
 * re-read state afterwards to set verified:true — the API only marks a plan
 * `succeeded` when every non-best-effort write step reports verified.
 */

import { ActionDescriptor, ActionResult, createRegistry } from '@unm/plugin-sdk';
import type { AxiosInstance } from 'axios';
import {
  MailcowApiError,
  addAlias,
  addDomain,
  addMailbox,
  deleteAliases,
  deleteDomains,
  deleteMailboxes,
  editAlias,
  editDomain,
  editMailbox,
  getAliases,
  getDomains,
  getMailboxes,
} from './client/mailcowClient';

/** Executor context for one /config step — the API key is already bound into the client. */
export interface MailcowActionContext {
  client: AxiosInstance;
}

// --- small input helpers ------------------------------------------------------

function inStr(input: Record<string, unknown>, key: string): string | undefined {
  const v = input[key];
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function inNum(input: Record<string, unknown>, key: string): number | undefined {
  const v = input[key];
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && v.trim() !== '' && Number.isFinite(Number(v))) return Number(v);
  return undefined;
}

function inBool(input: Record<string, unknown>, key: string): boolean | undefined {
  const v = input[key];
  return typeof v === 'boolean' ? v : undefined;
}

/** MB (MiB) → bytes as mailcow expects for quota fields. */
const mbToBytes = (mb: number): number => Math.round(mb * 1048576);

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/** True when a create failed because the object already exists (mailcow msg varies by release). */
function isAlreadyExists(e: unknown, rows: Record<string, unknown>[], key: string, value: string): boolean {
  if (e instanceof MailcowApiError && /exist|already/i.test(e.message)) return true;
  // Fallback: re-read state — if it's there now, treat as idempotent no-op.
  return rows.some((r) => String(r[key] ?? '') === value);
}

// --- Domains ------------------------------------------------------------------

const domainCreateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.domain.create',
  label: 'Create mail domain',
  description: 'Creates a new domain on the mail server (add/domain). Quotas are given in MB.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    domain: { type: 'string', required: true, minLength: 3, maxLength: 253, description: 'Fully qualified domain name (e.g. mail.example.org)' },
    description: { type: 'string', required: false, maxLength: 500, description: 'Optional domain description' },
    quotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'Total mailbox quota for the whole domain in MB (default from mailcow template)' },
    maxQuotaPerMailboxMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'Maximum quota per single mailbox in MB' },
    defaultQuotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'Default quota pre-filled for new mailboxes in MB' },
    mailboxLimit: { type: 'number', required: false, min: 1, max: 1_000_000, description: 'Maximum number of mailboxes (default from mailcow template)' },
    aliasLimit: { type: 'number', required: false, min: 1, max: 1_000_000, description: 'Maximum number of aliases (default from mailcow template)' },
    backupMx: { type: 'boolean', required: false, default: false, description: 'Relay domain (backup MX) — accepts mail without local delivery' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const domain = inStr(input, 'domain');
    if (!domain) return { success: false, details: { error: '"domain" is required' } };

    const attr: Record<string, unknown> = { domain, active: true };
    const description = inStr(input, 'description');
    if (description !== undefined) attr['description'] = description;
    const quotaMB = inNum(input, 'quotaMB');
    if (quotaMB !== undefined) attr['quota'] = mbToBytes(quotaMB);
    const maxQuotaPerMailboxMB = inNum(input, 'maxQuotaPerMailboxMB');
    if (maxQuotaPerMailboxMB !== undefined) attr['maxquota'] = mbToBytes(maxQuotaPerMailboxMB);
    const defaultQuotaMB = inNum(input, 'defaultQuotaMB');
    if (defaultQuotaMB !== undefined) attr['defquota'] = mbToBytes(defaultQuotaMB);
    const mailboxLimit = inNum(input, 'mailboxLimit');
    if (mailboxLimit !== undefined) attr['mailboxes'] = Math.round(mailboxLimit);
    const aliasLimit = inNum(input, 'aliasLimit');
    if (aliasLimit !== undefined) attr['aliases'] = Math.round(aliasLimit);
    const backupMx = inBool(input, 'backupMx');
    if (backupMx !== undefined) attr['backupmx'] = backupMx;

    try {
      await addDomain(ctx.client, attr);
    } catch (e) {
      let rows: Record<string, unknown>[] = [];
      try { rows = await getDomains(ctx.client); } catch { /* verification best-effort */ }
      if (isAlreadyExists(e, rows, 'domain_name', domain)) return { success: true, applied: false, details: { domain, note: 'Domain already exists' } };
      return { success: false, details: { error: errMsg(e), domain } };
    }

    let verified = false;
    try {
      const rows = await getDomains(ctx.client);
      verified = rows.some((r) => String(r['domain_name'] ?? '') === domain);
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { domain } };
  },
};

const domainUpdateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.domain.update',
  label: 'Edit mail domain',
  description: 'Updates an existing domain (edit/domain) — only the provided fields change.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    domain: { type: 'string', required: true, minLength: 3, maxLength: 253, description: 'Domain to update' },
    active: { type: 'boolean', required: false, description: 'Activate/deactivate the domain' },
    description: { type: 'string', required: false, maxLength: 500, description: 'New description (empty clears it)' },
    quotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'New total domain quota in MB' },
    maxQuotaPerMailboxMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'New per-mailbox maximum quota in MB' },
    defaultQuotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'New default mailbox quota in MB' },
    mailboxLimit: { type: 'number', required: false, min: 1, max: 1_000_000, description: 'New mailbox limit' },
    aliasLimit: { type: 'number', required: false, min: 1, max: 1_000_000, description: 'New alias limit' },
    backupMx: { type: 'boolean', required: false, description: 'Relay domain (backup MX) flag' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const domain = inStr(input, 'domain');
    if (!domain) return { success: false, details: { error: '"domain" is required' } };

    // Resolve existence first — updating a missing domain is an idempotent no-op.
    let rows: Record<string, unknown>[];
    try {
      rows = await getDomains(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), domain } };
    }
    if (!rows.some((r) => String(r['domain_name'] ?? '') === domain)) {
      return { success: true, applied: false, details: { domain, note: 'Domain not found — nothing to update' } };
    }

    const attr: Record<string, unknown> = {};
    const active = inBool(input, 'active');
    if (active !== undefined) attr['active'] = active;
    if ('description' in input) attr['description'] = inStr(input, 'description') ?? '';
    const quotaMB = inNum(input, 'quotaMB');
    if (quotaMB !== undefined) attr['quota'] = mbToBytes(quotaMB);
    const maxQuotaPerMailboxMB = inNum(input, 'maxQuotaPerMailboxMB');
    if (maxQuotaPerMailboxMB !== undefined) attr['maxquota'] = mbToBytes(maxQuotaPerMailboxMB);
    const defaultQuotaMB = inNum(input, 'defaultQuotaMB');
    if (defaultQuotaMB !== undefined) attr['defquota'] = mbToBytes(defaultQuotaMB);
    const mailboxLimit = inNum(input, 'mailboxLimit');
    if (mailboxLimit !== undefined) attr['mailboxes'] = Math.round(mailboxLimit);
    const aliasLimit = inNum(input, 'aliasLimit');
    if (aliasLimit !== undefined) attr['aliases'] = Math.round(aliasLimit);
    const backupMx = inBool(input, 'backupMx');
    if (backupMx !== undefined) attr['backupmx'] = backupMx;

    try {
      await editDomain(ctx.client, domain, attr);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), domain } };
    }

    let verified = true;
    try {
      const after = await getDomains(ctx.client);
      const row = after.find((r) => String(r['domain_name'] ?? '') === domain);
      if (!row) verified = false;
      else if (active !== undefined && Number(row['active']) !== (active ? 1 : 0)) verified = false;
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { domain } };
  },
};

const domainDeleteAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.domain.delete',
  label: 'Delete mail domain(s)',
  description: 'DELETES the selected domains (delete/domain) including their mailboxes and aliases. Irreversible.',
  module: 'Mail',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    domains: { type: 'array', required: true, items: { type: 'string', minLength: 3 }, description: 'Domain names to delete' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const raw = Array.isArray(input['domains']) ? (input['domains'] as unknown[]) : [];
    const domains = raw.filter((d): d is string => typeof d === 'string' && d.length > 0);
    if (domains.length === 0) return { success: false, details: { error: 'No domain names provided' } };

    let existing: Record<string, unknown>[];
    try {
      existing = await getDomains(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e) } };
    }
    const present = new Set(existing.map((r) => String(r['domain_name'] ?? '')));
    const toDelete = domains.filter((d) => present.has(d));
    const missing = domains.filter((d) => !present.has(d)); // already gone — idempotent skip

    if (toDelete.length > 0) {
      try {
        await deleteDomains(ctx.client, toDelete);
      } catch (e) {
        return { success: false, details: { error: errMsg(e), domains: toDelete } };
      }
    }

    let verified = true;
    if (toDelete.length > 0) {
      try {
        const after = await getDomains(ctx.client);
        const stillThere = new Set(after.map((r) => String(r['domain_name'] ?? '')));
        verified = toDelete.every((d) => !stillThere.has(d));
      } catch { /* verification best-effort */ }
    }
    return { success: true, applied: toDelete.length > 0, verified, details: { deleted: toDelete, missing } };
  },
};

// --- Mailboxes ----------------------------------------------------------------

const mailboxCreateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.mailbox.create',
  label: 'Create mailbox',
  description: 'Creates a new mailbox (add/mailbox). The password is set once here — use mail.mailbox.update to change it later.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    localPart: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Left part of the address (e.g. info)' },
    domain: { type: 'string', required: true, minLength: 3, maxLength: 253, description: 'Domain for the mailbox' },
    password: { type: 'string', required: true, minLength: 8, maxLength: 128, description: 'Initial mailbox password (min 8 chars)' },
    name: { type: 'string', required: false, maxLength: 255, description: 'Full name of the mailbox user' },
    quotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'Mailbox quota in MB (default from domain template)' },
    forcePwUpdate: { type: 'boolean', required: false, default: false, description: 'Force the user to change the password on first login' },
    forceTfa: { type: 'boolean', required: false, default: false, description: 'Force 2FA enrollment at next login' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const localPart = inStr(input, 'localPart');
    const domain = inStr(input, 'domain');
    const password = inStr(input, 'password');
    if (!localPart || !domain) return { success: false, details: { error: '"localPart" and "domain" are required' } };
    if (!password) return { success: false, details: { error: '"password" is required' } };

    const username = `${localPart}@${domain}`;
    const attr: Record<string, unknown> = { local_part: localPart, domain, password, password2: password, active: true };
    const name = inStr(input, 'name');
    if (name !== undefined) attr['name'] = name;
    const quotaMB = inNum(input, 'quotaMB');
    if (quotaMB !== undefined) attr['quota'] = mbToBytes(quotaMB);
    const forcePwUpdate = inBool(input, 'forcePwUpdate');
    if (forcePwUpdate !== undefined) attr['force_pw_update'] = forcePwUpdate;
    const forceTfa = inBool(input, 'forceTfa');
    if (forceTfa !== undefined) attr['force_tfa'] = forceTfa;

    try {
      await addMailbox(ctx.client, attr);
    } catch (e) {
      let rows: Record<string, unknown>[] = [];
      try { rows = await getMailboxes(ctx.client); } catch { /* verification best-effort */ }
      if (isAlreadyExists(e, rows, 'username', username)) return { success: true, applied: false, details: { mailbox: username, note: 'Mailbox already exists' } };
      return { success: false, details: { error: errMsg(e), mailbox: username } };
    }

    let verified = false;
    try {
      const rows = await getMailboxes(ctx.client);
      verified = rows.some((r) => String(r['username'] ?? '') === username);
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { mailbox: username } };
  },
};

const mailboxUpdateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.mailbox.update',
  label: 'Edit mailbox',
  description: 'Updates an existing mailbox (edit/mailbox) — only the provided fields change. Set "newPassword" to reset the password.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    username: { type: 'string', required: true, minLength: 5, maxLength: 255, description: 'Full mailbox address (e.g. info@example.org)' },
    name: { type: 'string', required: false, maxLength: 255, description: 'New full name' },
    quotaMB: { type: 'number', required: false, min: 0, max: 10_485_760, description: 'New quota in MB' },
    active: { type: 'boolean', required: false, description: 'Activate/deactivate the mailbox' },
    newPassword: { type: 'string', required: false, minLength: 8, maxLength: 128, description: 'Optional new password (min 8 chars) — omit to keep the current one' },
    forcePwUpdate: { type: 'boolean', required: false, description: 'Force password change on next login' },
    forceTfa: { type: 'boolean', required: false, description: 'Force 2FA enrollment at next login' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const username = inStr(input, 'username');
    if (!username) return { success: false, details: { error: '"username" is required' } };

    let rows: Record<string, unknown>[];
    try {
      rows = await getMailboxes(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), mailbox: username } };
    }
    if (!rows.some((r) => String(r['username'] ?? '') === username)) {
      return { success: true, applied: false, details: { mailbox: username, note: 'Mailbox not found — nothing to update' } };
    }

    const attr: Record<string, unknown> = {};
    const name = inStr(input, 'name');
    if (name !== undefined) attr['name'] = name;
    const quotaMB = inNum(input, 'quotaMB');
    if (quotaMB !== undefined) attr['quota'] = mbToBytes(quotaMB);
    const active = inBool(input, 'active');
    if (active !== undefined) attr['active'] = active;
    const newPassword = inStr(input, 'newPassword');
    if (newPassword) {
      // mailcow requires BOTH password fields to change the password.
      attr['password'] = newPassword;
      attr['password2'] = newPassword;
    }
    const forcePwUpdate = inBool(input, 'forcePwUpdate');
    if (forcePwUpdate !== undefined) attr['force_pw_update'] = forcePwUpdate;
    const forceTfa = inBool(input, 'forceTfa');
    if (forceTfa !== undefined) attr['force_tfa'] = forceTfa;

    try {
      await editMailbox(ctx.client, username, attr);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), mailbox: username } };
    }

    let verified = true;
    try {
      const after = await getMailboxes(ctx.client);
      const row = after.find((r) => String(r['username'] ?? '') === username);
      if (!row) verified = false;
      else if (active !== undefined && Number(row['active']) !== (active ? 1 : 0)) verified = false;
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { mailbox: username } };
  },
};

const mailboxDeleteAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.mailbox.delete',
  label: 'Delete mailbox(es)',
  description: 'DELETES the selected mailboxes (delete/mailbox) including their data. Irreversible.',
  module: 'Mail',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 120_000,
  inputSchema: {
    usernames: { type: 'array', required: true, items: { type: 'string', minLength: 5 }, description: 'Mailbox addresses to delete' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const raw = Array.isArray(input['usernames']) ? (input['usernames'] as unknown[]) : [];
    const usernames = raw.filter((u): u is string => typeof u === 'string' && u.length > 0);
    if (usernames.length === 0) return { success: false, details: { error: 'No mailbox addresses provided' } };

    let existing: Record<string, unknown>[];
    try {
      existing = await getMailboxes(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e) } };
    }
    const present = new Set(existing.map((r) => String(r['username'] ?? '')));
    const toDelete = usernames.filter((u) => present.has(u));
    const missing = usernames.filter((u) => !present.has(u)); // already gone — idempotent skip

    if (toDelete.length > 0) {
      try {
        await deleteMailboxes(ctx.client, toDelete);
      } catch (e) {
        return { success: false, details: { error: errMsg(e), mailboxes: toDelete } };
      }
    }

    let verified = true;
    if (toDelete.length > 0) {
      try {
        const after = await getMailboxes(ctx.client);
        const stillThere = new Set(after.map((r) => String(r['username'] ?? '')));
        verified = toDelete.every((u) => !stillThere.has(u));
      } catch { /* verification best-effort */ }
    }
    return { success: true, applied: toDelete.length > 0, verified, details: { deleted: toDelete, missing } };
  },
};

// --- Aliases ------------------------------------------------------------------

const aliasCreateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.alias.create',
  label: 'Create mail alias',
  description: 'Creates a new address alias (add/alias) forwarding to one or more destinations. Use "@domain.tld" for a catch-all.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    address: { type: 'string', required: true, minLength: 3, maxLength: 255, description: 'Alias address (e.g. info@example.org or @example.org for catch-all)' },
    goto: { type: 'string', required: true, minLength: 5, maxLength: 1000, description: 'Destination address(es), comma separated' },
    sogoVisible: { type: 'boolean', required: false, default: true, description: 'Selectable as sender in SOGo webmail' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const address = inStr(input, 'address');
    const goto = inStr(input, 'goto');
    if (!address || !goto) return { success: false, details: { error: '"address" and "goto" are required' } };

    const attr: Record<string, unknown> = { address, goto, active: true };
    const sogoVisible = inBool(input, 'sogoVisible');
    if (sogoVisible !== undefined) attr['sogo_visible'] = sogoVisible;

    try {
      await addAlias(ctx.client, attr);
    } catch (e) {
      let rows: Record<string, unknown>[] = [];
      try { rows = await getAliases(ctx.client); } catch { /* verification best-effort */ }
      if (isAlreadyExists(e, rows, 'address', address)) return { success: true, applied: false, details: { alias: address, note: 'Alias already exists' } };
      return { success: false, details: { error: errMsg(e), alias: address } };
    }

    let verified = false;
    try {
      const rows = await getAliases(ctx.client);
      verified = rows.some((r) => String(r['address'] ?? '') === address);
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { alias: address } };
  },
};

const aliasUpdateAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.alias.update',
  label: 'Edit mail alias',
  description: 'Updates an existing alias (edit/alias) — only the provided fields change.',
  module: 'Mail',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    id: { type: 'number', required: true, min: 1, description: 'Numeric alias id from the inventory (not the address)' },
    goto: { type: 'string', required: false, minLength: 5, maxLength: 1000, description: 'New destination address(es), comma separated' },
    active: { type: 'boolean', required: false, description: 'Activate/deactivate the alias' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const id = inNum(input, 'id');
    if (id === undefined) return { success: false, details: { error: '"id" is required' } };

    let rows: Record<string, unknown>[];
    try {
      rows = await getAliases(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), aliasId: id } };
    }
    const row = rows.find((r) => Number(r['id']) === id);
    if (!row) {
      return { success: true, applied: false, details: { aliasId: id, note: 'Alias not found — nothing to update' } };
    }

    const attr: Record<string, unknown> = {};
    const goto = inStr(input, 'goto');
    if (goto !== undefined) attr['goto'] = goto;
    const active = inBool(input, 'active');
    if (active !== undefined) attr['active'] = active;

    try {
      await editAlias(ctx.client, id, attr);
    } catch (e) {
      return { success: false, details: { error: errMsg(e), aliasId: id } };
    }

    let verified = true;
    try {
      const after = await getAliases(ctx.client);
      const now = after.find((r) => Number(r['id']) === id);
      if (!now) verified = false;
      else if (active !== undefined && Number(now['active']) !== (active ? 1 : 0)) verified = false;
    } catch { /* verification best-effort */ }
    return { success: true, applied: true, verified, details: { aliasId: id, address: String(row['address'] ?? '') } };
  },
};

const aliasDeleteAction: ActionDescriptor<MailcowActionContext> = {
  id: 'mail.alias.delete',
  label: 'Delete mail alias(es)',
  description: 'DELETES the selected aliases (delete/alias) by their numeric ids.',
  module: 'Mail',
  riskLevel: 'dangerous' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    ids: { type: 'array', required: true, items: { type: 'number', min: 1 }, description: 'Numeric alias ids to delete' },
  },
  async execute(ctx: MailcowActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const raw = Array.isArray(input['ids']) ? (input['ids'] as unknown[]) : [];
    const ids = raw.map((v) => Number(v)).filter((n) => Number.isFinite(n) && n > 0);
    if (ids.length === 0) return { success: false, details: { error: 'No alias ids provided' } };

    let existing: Record<string, unknown>[];
    try {
      existing = await getAliases(ctx.client);
    } catch (e) {
      return { success: false, details: { error: errMsg(e) } };
    }
    const present = new Set(existing.map((r) => Number(r['id'])));
    const toDelete = ids.filter((i) => present.has(i));
    const missing = ids.filter((i) => !present.has(i)); // already gone — idempotent skip

    if (toDelete.length > 0) {
      try {
        await deleteAliases(ctx.client, toDelete);
      } catch (e) {
        return { success: false, details: { error: errMsg(e), aliasIds: toDelete } };
      }
    }

    let verified = true;
    if (toDelete.length > 0) {
      try {
        const after = await getAliases(ctx.client);
        const stillThere = new Set(after.map((r) => Number(r['id'])));
        verified = toDelete.every((i) => !stillThere.has(i));
      } catch { /* verification best-effort */ }
    }
    return { success: true, applied: toDelete.length > 0, verified, details: { deleted: toDelete, missing } };
  },
};

export const registry = createRegistry<MailcowActionContext>([
  domainCreateAction,
  domainUpdateAction,
  domainDeleteAction,
  mailboxCreateAction,
  mailboxUpdateAction,
  mailboxDeleteAction,
  aliasCreateAction,
  aliasUpdateAction,
  aliasDeleteAction,
]);
