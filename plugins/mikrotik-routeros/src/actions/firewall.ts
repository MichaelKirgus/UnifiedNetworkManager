/**
 * Firewall-module actions for RouterOS (verified live on 7.21 LTS).
 *
 * RouterOS firewall rules have NO name field — the `comment` property is the
 * only human-manageable identifier, so every rule this plugin creates carries
 * one and update/toggle/delete address rules by `.id` or by comment.
 *
 * Tables (all verified): /ip/firewall/filter, /ip/firewall/nat,
 * /ip/firewall/address-list (fields: `list`, `address`). Writes apply
 * IMMEDIATELY — there is no staged model; every write is verified by re-read.
 */

import { rosNumber, rosString } from '../routerosClient';
import type { ActionContext, ActionDescriptor } from './types';

type Row = Record<string, unknown>;

const RULE_TABLES: Array<{ table: string; kind: 'filter' | 'nat' }> = [
  { table: '/ip/firewall/filter', kind: 'filter' },
  { table: '/ip/firewall/nat', kind: 'nat' },
];

/** Normalizes one raw rule row to the unified shape. */
function normalizeRule(row: Row, kind: 'filter' | 'nat'): Record<string, unknown> {
  return {
    ruleId: rosString(row, ['.id']) ?? null,
    table: kind,
    chain: rosString(row, ['chain']) ?? null,
    action: rosString(row, ['action']) ?? null,
    protocol: rosString(row, ['protocol']) ?? '',
    srcAddress: rosString(row, ['src-address', 'src-address-list']) ?? '',
    dstAddress: rosString(row, ['dst-address', 'dst-address-list']) ?? '',
    srcPort: rosString(row, ['src-port']) ?? '',
    dstPort: rosString(row, ['dst-port']) ?? '',
    inInterface: rosString(row, ['in-interface']) ?? '',
    outInterface: rosString(row, ['out-interface']) ?? '',
    toAddresses: rosString(row, ['to-addresses']) ?? '',
    toPorts: rosString(row, ['to-ports']) ?? '',
    comment: rosString(row, ['comment']) ?? '',
    disabled: rosString(row, ['disabled']) === 'true',
  };
}

/** Finds a rule by .id or (unique) comment across both tables. */
async function findRule(ctx: ActionContext, ruleId?: string, comment?: string): Promise<{ row: Row; table: string; kind: 'filter' | 'nat' } | null> {
  for (const { table, kind } of RULE_TABLES) {
    const rows = await ctx.client.get<Row[]>(table).catch(() => [] as Row[]);
    if (ruleId) {
      const hit = rows.find((r) => rosString(r, ['.id']) === ruleId);
      if (hit) return { row: hit, table, kind };
    } else if (comment) {
      const hits = rows.filter((r) => rosString(r, ['comment']) === comment);
      if (hits.length >= 1) return { row: hits[0], table, kind };
    }
  }
  return null;
}

// --- firewall.rules.read ---------------------------------------------------------------------------

export const firewallRulesReadAction: ActionDescriptor = {
  id: 'firewall.rules.read',
  label: 'Read firewall rules (filter + NAT)',
  description: "Lists all filter and NAT rules (/ip/firewall/filter, /ip/firewall/nat) with matchers, actions and enabled state.",
  module: 'Firewall',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const results = await Promise.all(RULE_TABLES.map(({ table }) => ctx.client.get<Row[]>(table).catch(() => [] as Row[])));
    const rules: Array<Record<string, unknown>> = [];
    results.forEach((rows, i) => {
      for (const r of rows) rules.push(normalizeRule(r, RULE_TABLES[i].kind));
    });
    return { success: true, details: { rules } };
  },
};

// --- firewall.rule.add -------------------------------------------------------------------------------

/** Maps the flat input schema onto RouterOS rule fields. */
function buildRuleBody(input: Record<string, unknown>): { body: Record<string, unknown> } | { error: string } {
  const chain = String(input.chain ?? '').trim();
  const action = String(input.action ?? '').trim();
  if (!chain || !action) return { error: 'Both `chain` and `action` are required.' };

  const body: Record<string, unknown> = { chain, action };
  const strFields: Array<[string, string]> = [
    ['protocol', 'protocol'],
    ['srcAddress', 'src-address'],
    ['dstAddress', 'dst-address'],
    ['srcPort', 'src-port'],
    ['dstPort', 'dst-port'],
    ['inInterface', 'in-interface'],
    ['outInterface', 'out-interface'],
    ['toAddresses', 'to-addresses'],
    ['toPorts', 'to-ports'],
  ];
  for (const [key, rosKey] of strFields) {
    const v = typeof input[key] === 'string' ? (input[key] as string).trim() : '';
    if (v) body[rosKey] = v;
  }

  // NAT sanity — dst-nat needs a target.
  if (action === 'dst-nat' && !body['to-addresses']) return { error: "NAT action `dst-nat` requires `toAddresses`." };
  if (action === 'src-nat' && body['to-ports']) return { error: '`toPorts` is only valid for dst-nat rules.' };

  const comment = typeof input.comment === 'string' ? input.comment.trim() : '';
  if (!comment) return { error: '`comment` is required — RouterOS firewall rules have no name field; the comment is how UNM identifies this rule later.' };
  body['comment'] = comment;

  if (input.disabled === true) body['disabled'] = true;
  return { body };
}

export const firewallRuleAddAction: ActionDescriptor = {
  id: 'firewall.rule.add',
  label: 'Add a firewall rule (filter or NAT)',
  description: "Adds one filter or NAT rule. The `comment` is REQUIRED and doubles as the rule's identity — an existing rule with the same comment is left untouched (idempotent). New rules are appended at the END of the chain; use update to change matchers.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    table: { type: 'string', required: true, enum: ['filter', 'nat'], description: "Which firewall — `filter` (packet filter) or `nat`" },
    chain: { type: 'string', required: true, description: "Chain name (filter: input/forward/output; nat: prerouting/dstnat/srcnat/postrouting)" },
    action: { type: 'string', required: true, description: "Action — accept | drop | reject | dst-nat | src-nat | ..." },
    protocol: { type: 'string', description: "Protocol (tcp/udp/icmp or number)" },
    srcAddress: { type: 'string', description: "Source address/CIDR or address-list name" },
    dstAddress: { type: 'string', description: "Destination address/CIDR or address-list name" },
    srcPort: { type: 'string', description: "Source port(s)" },
    dstPort: { type: 'string', description: "Destination port(s)" },
    inInterface: { type: 'string', description: "Incoming interface (filter only)" },
    outInterface: { type: 'string', description: "Outgoing interface (filter only)" },
    toAddresses: { type: 'string', description: "NAT target address(es) (dst-nat/src-nat)" },
    toPorts: { type: 'string', description: "NAT target port(s) (dst-nat only)" },
    comment: { type: 'string', required: true, minLength: 1, maxLength: 256, description: "Rule identity — unique per device; used by update/toggle/delete" },
    disabled: { type: 'boolean', description: 'Add the rule in a disabled state' },
  },
  execute: async (ctx, input) => {
    const table = String(input.table ?? '').trim();
    const entry = RULE_TABLES.find((t) => t.kind === table);
    if (!entry) return { success: false, error: "`table` must be 'filter' or 'nat'." };

    const built = buildRuleBody(input);
    if ('error' in built) return { success: false, error: built.error };
    const body = built.body;
    const comment = String(body['comment']);

    // Idempotency — same comment already exists.
    const rows = await ctx.client.get<Row[]>(entry.table).catch(() => [] as Row[]);
    const existing = rows.find((r) => rosString(r, ['comment']) === comment);
    if (existing) {
      return { success: true, applied: false, details: { skipped: `rule with comment "${comment}" already exists (${entry.table} .id ${rosString(existing, ['.id'])})` } };
    }

    try {
      await ctx.client.put(entry.table, body);
    } catch (e) {
      return { success: false, error: `Adding firewall rule failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>(entry.table).catch(() => [] as Row[])).find((r) => rosString(r, ['comment']) === comment);
    if (!after) return { success: false, error: `Verification failed — rule "${comment}" not present after create.` };
    return { success: true, applied: true, details: normalizeRule(after, entry.kind) } as const;
  },
};

// --- firewall.rule.update -------------------------------------------------------------------------------

export const firewallRuleUpdateAction: ActionDescriptor = {
  id: 'firewall.rule.update',
  label: 'Update a firewall rule',
  description: "Updates an existing filter/NAT rule's matchers or action. Identify the rule by `ruleId` (from rules.read) or its unique `comment`. Only the fields you provide are changed.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    ruleId: { type: 'string', description: "Rule .id (preferred — from firewall.rules.read)" },
    comment: { type: 'string', description: "Unique rule comment (alternative to ruleId)" },
    action: { type: 'string', description: "New action" },
    protocol: { type: 'string', description: "New protocol matcher" },
    srcAddress: { type: 'string', description: "New source matcher" },
    dstAddress: { type: 'string', description: "New destination matcher" },
    srcPort: { type: 'string', description: "New source port matcher" },
    dstPort: { type: 'string', description: "New destination port matcher" },
    inInterface: { type: 'string', description: "New incoming interface matcher" },
    outInterface: { type: 'string', description: "New outgoing interface matcher" },
    toAddresses: { type: 'string', description: "New NAT target address(es)" },
    toPorts: { type: 'string', description: "New NAT target port(s)" },
  },
  execute: async (ctx, input) => {
    const ruleId = typeof input.ruleId === 'string' && input.ruleId.trim() ? input.ruleId.trim() : undefined;
    const comment = typeof input.comment === 'string' && input.comment.trim() ? input.comment.trim() : undefined;
    if (!ruleId && !comment) return { success: false, error: "Identify the rule by `ruleId` or its unique `comment`." };

    const found = await findRule(ctx, ruleId, comment);
    if (!found) return { success: false, error: `No firewall rule found (ruleId=${ruleId ?? '-'} comment=${comment ?? '-'}) — run firewall.rules.read to list them.` };

    const body: Record<string, unknown> = {};
    const strFields: Array<[string, string]> = [
      ['action', 'action'],
      ['protocol', 'protocol'],
      ['srcAddress', 'src-address'],
      ['dstAddress', 'dst-address'],
      ['srcPort', 'src-port'],
      ['dstPort', 'dst-port'],
      ['inInterface', 'in-interface'],
      ['outInterface', 'out-interface'],
      ['toAddresses', 'to-addresses'],
      ['toPorts', 'to-ports'],
    ];
    for (const [key, rosKey] of strFields) {
      const v = typeof input[key] === 'string' ? (input[key] as string).trim() : '';
      if (v) body[rosKey] = v;
    }
    if (Object.keys(body).length === 0) return { success: false, error: 'Nothing to update — provide at least one field.' };

    const id = rosString(found.row, ['.id']);
    if (!id) return { success: false, error: `Rule has no .id — cannot update it.` };
    try {
      await ctx.client.patch(`${found.table}/${id}`, body);
    } catch (e) {
      return { success: false, error: `Updating firewall rule failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>(found.table).catch(() => [] as Row[])).find((r) => rosString(r, ['.id']) === id);
    if (!after) return { success: false, error: 'Verification failed — rule vanished after update.' };
    for (const [key, rosKey] of strFields) {
      const v = body[rosKey];
      if (typeof v === 'string' && rosString(after, [rosKey]) !== v) {
        return { success: false, error: `Verification failed — ${rosKey} is "${rosString(after, [rosKey])}" after update.` };
      }
    }
    return { success: true, applied: true, details: normalizeRule(after, found.kind) } as const;
  },
};

// --- firewall.rule.toggle -------------------------------------------------------------------------------

export const firewallRuleToggleAction: ActionDescriptor = {
  id: 'firewall.rule.toggle',
  label: "Enable/disable a firewall rule",
  description: "Toggles the `disabled` flag of one filter/NAT rule (identified by `ruleId` or unique `comment`). Idempotent — an already-disabled/enabled rule is left untouched.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    ruleId: { type: 'string', description: "Rule .id (preferred)" },
    comment: { type: 'string', description: "Unique rule comment (alternative to ruleId)" },
    disabled: { type: 'boolean', required: true, description: 'true = disable the rule, false = enable it' },
  },
  execute: async (ctx, input) => {
    const ruleId = typeof input.ruleId === 'string' && input.ruleId.trim() ? input.ruleId.trim() : undefined;
    const comment = typeof input.comment === 'string' && input.comment.trim() ? input.comment.trim() : undefined;
    if (!ruleId && !comment) return { success: false, error: "Identify the rule by `ruleId` or its unique `comment`." };

    const found = await findRule(ctx, ruleId, comment);
    if (!found) return { success: false, error: `No firewall rule found (ruleId=${ruleId ?? '-'} comment=${comment ?? '-'}) — run firewall.rules.read to list them.` };

    const wantDisabled = input.disabled === true;
    const currentlyDisabled = rosString(found.row, ['disabled']) === 'true';
    if (currentlyDisabled === wantDisabled) {
      return { success: true, applied: false, details: { skipped: `rule already ${wantDisabled ? 'disabled' : 'enabled'}`, ruleId: rosString(found.row, ['.id']) } };
    }

    const id = rosString(found.row, ['.id']);
    if (!id) return { success: false, error: `Rule has no .id — cannot toggle it.` };
    try {
      await ctx.client.patch(`${found.table}/${id}`, { disabled: wantDisabled });
    } catch (e) {
      return { success: false, error: `Toggling firewall rule failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>(found.table).catch(() => [] as Row[])).find((r) => rosString(r, ['.id']) === id);
    if (!after || rosString(after, ['disabled']) === 'true' !== wantDisabled) {
      return { success: false, error: 'Verification failed — rule state unchanged.' };
    }
    return { success: true, applied: true, details: normalizeRule(after, found.kind) } as const;
  },
};

// --- firewall.rule.delete -------------------------------------------------------------------------------

export const firewallRuleDeleteAction: ActionDescriptor = {
  id: 'firewall.rule.delete',
  label: 'Delete a firewall rule',
  description: "Removes one filter/NAT rule by `ruleId` or unique `comment`. Idempotent — an unknown rule is a no-op.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    ruleId: { type: 'string', description: "Rule .id (preferred)" },
    comment: { type: 'string', description: "Unique rule comment (alternative to ruleId)" },
  },
  execute: async (ctx, input) => {
    const ruleId = typeof input.ruleId === 'string' && input.ruleId.trim() ? input.ruleId.trim() : undefined;
    const comment = typeof input.comment === 'string' && input.comment.trim() ? input.comment.trim() : undefined;
    if (!ruleId && !comment) return { success: false, error: "Identify the rule by `ruleId` or its unique `comment`." };

    const found = await findRule(ctx, ruleId, comment);
    if (!found) return { success: true, applied: false, details: { skipped: `no firewall rule (ruleId=${ruleId ?? '-'} comment=${comment ?? '-'})` } };

    const id = rosString(found.row, ['.id']);
    if (!id) return { success: false, error: `Rule has no .id — cannot remove it.` };
    try {
      await ctx.client.delete(`${found.table}/${id}`);
    } catch (e) {
      return { success: false, error: `Deleting firewall rule failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>(found.table).catch(() => [] as Row[])).find((r) => rosString(r, ['.id']) === id);
    if (after) return { success: false, error: 'Verification failed — rule still present.' };
    return { success: true, applied: true, details: { deleted: comment ?? id, table: found.kind } };
  },
};

// --- firewall aliases (/ip/firewall/address-list) -----------------------------------------------------------

export const firewallAliasesReadAction: ActionDescriptor = {
  id: 'firewall.aliases.read',
  label: 'Read address lists (aliases)',
  description: "Lists all firewall address lists (/ip/firewall/address-list) — name → member addresses.",
  module: 'Firewall',
  riskLevel: 'read',
  deviceCount: 1,
  inputSchema: {},
  execute: async (ctx) => {
    const rows = await ctx.client.get<Row[]>('/ip/firewall/address-list').catch(() => [] as Row[]);
    const lists: Record<string, string[]> = {};
    for (const r of rows) {
      const listName = rosString(r, ['list']) ?? '';
      const addr = rosString(r, ['address']) ?? '';
      if (!listName || !addr) continue;
      (lists[listName] ??= []).push(addr);
    }
    return { success: true, details: { lists } };
  },
};

/**
 * RouterOS stores an IPv4 `/32` entry as the BARE host (the prefix is dropped —
 * verified live on 7.21 LTS), so exact-string comparisons against stored rows
 * must normalize both sides or every /32 add "fails verification" and its
 * delete can never find it.
 */
function normalizeAddressListEntry(addr: string): string {
  const t = addr.trim();
  return /^(\d{1,3}(?:\.\d{1,3}){3})\/32$/.test(t) ? t.slice(0, -3) : t;
}

export const firewallAliasAddAction: ActionDescriptor = {
  id: 'firewall.alias.add',
  label: "Add an address to a list (alias)",
  description: "Adds one address to a named firewall address list (/ip/firewall/address-list) — the RouterOS equivalent of an alias. Idempotent — an identical entry is left untouched.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: "List (alias) name — created on first use" },
    address: { type: 'string', required: true, description: "Address or CIDR to add (e.g. 10.0.0.5/32)" },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const address = normalizeAddressListEntry(String(input.address ?? ''));

    const rows = await ctx.client.get<Row[]>('/ip/firewall/address-list').catch(() => [] as Row[]);
    if (rows.some((r) => rosString(r, ['list']) === name && normalizeAddressListEntry(rosString(r, ['address']) ?? '') === address)) {
      return { success: true, applied: false, details: { skipped: `${name} already contains ${address}` } };
    }

    try {
      await ctx.client.put('/ip/firewall/address-list', { list: name, address });
    } catch (e) {
      return { success: false, error: `Adding ${address} to "${name}" failed: ${e instanceof Error ? e.message : String(e)}` };
    }

    const after = (await ctx.client.get<Row[]>('/ip/firewall/address-list').catch(() => [] as Row[])).find((r) => rosString(r, ['list']) === name && normalizeAddressListEntry(rosString(r, ['address']) ?? '') === address);
    if (!after) return { success: false, error: `Verification failed — ${address} not in "${name}" after add.` };
    return { success: true, applied: true, details: { list: name, added: address } };
  },
};

export const firewallAliasDeleteAction: ActionDescriptor = {
  id: 'firewall.alias.delete',
  label: "Remove an address from a list (alias)",
  description: "Removes one address from a named firewall address list. Idempotent — nothing matching is a no-op.",
  module: 'Firewall',
  riskLevel: 'write',
  deviceCount: 1,
  inputSchema: {
    name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: "List (alias) name" },
    address: { type: 'string', required: true, description: "Address or CIDR to remove" },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    const address = normalizeAddressListEntry(String(input.address ?? ''));

    const rows = await ctx.client.get<Row[]>('/ip/firewall/address-list').catch(() => [] as Row[]);
    const mine = rows.filter((r) => rosString(r, ['list']) === name && normalizeAddressListEntry(rosString(r, ['address']) ?? '') === address);
    if (mine.length === 0) return { success: true, applied: false, details: { skipped: `${name} does not contain ${address}` } };

    let removed = 0;
    for (const r of mine) {
      const id = rosString(r, ['.id']);
      if (!id) continue;
      await ctx.client.delete(`/ip/firewall/address-list/${id}`).catch(() => undefined);
      removed += 1;
    }

    const after = (await ctx.client.get<Row[]>('/ip/firewall/address-list').catch(() => [] as Row[])).filter((r) => rosString(r, ['list']) === name && normalizeAddressListEntry(rosString(r, ['address']) ?? '') === address);
    if (after.length > 0) return { success: false, error: `Verification failed — ${address} still in "${name}".` };
    return { success: true, applied: true, details: { list: name, removed } };
  },
};

export const firewallActions: ActionDescriptor[] = [
  firewallRulesReadAction,
  firewallRuleAddAction,
  firewallRuleUpdateAction,
  firewallRuleToggleAction,
  firewallRuleDeleteAction,
  firewallAliasesReadAction,
  firewallAliasAddAction,
  firewallAliasDeleteAction,
];
