/**
 * The zabbix action registry — two write actions served to the plans system:
 *   - zabbix.host.sync    → reconcile UNM's host inventory into Zabbix (the
 *                           'inventorySync' capability): create/update/delete.
 *   - zabbix.host.create  → register a single explicit host in Zabbix by hand
 *                           (no inventory involved).
 *
 * Both are IDEMPOTENT: re-running never hard-fails ("already exists" is a no-op),
 * and writes re-read state afterwards to set verified:true. The sync action is the
 * one that makes UNM→Zabbix mirroring work; it reads its mapping rules from the
 * plugin options (see resolveSyncConfig) so every rule is user-tunable.
 */

import { ActionDescriptor, ActionResult, createRegistry, isTransientTransportError } from '@unm/plugin-sdk';
import type { ZabbixClient } from './client/zabbixClient';
import { ZabbixApiError } from './client/zabbixClient';
import { runSync, resolveSyncConfig, SyncResult } from './sync';

/** Executor context for one /config step — the client is already bound + authenticated. */
export interface ZabbixActionContext {
  client: ZabbixClient;
  /** Effective plugin settings (defaults ⊕ per-device overrides). */
  settings: Record<string, unknown>;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Classifies a failure into an ActionResult. A ZabbixApiError means the server
 * ANSWERED (bad token, missing template, …) — hard/final. A transport-level error
 * (server down / not ready yet) is marked retryable so the plan executor re-dispatches
 * per the plan's retry policy. This mirrors the /config catch in index.ts but runs
 * INSIDE the action because runSync makes its own Zabbix calls after the snapshot fetch.
 */
function failureResult(err: unknown): ActionResult {
  const retryable = !(err instanceof ZabbixApiError) && isTransientTransportError(err);
  return { success: false, error: errMsg(err), ...(retryable ? { retryable: true } : {}) };
}

/** Serializes a SyncResult into the ActionResult `details` map. */
function syncDetails(r: SyncResult): Record<string, unknown> {
  return {
    totalInScope: r.totalInScope,
    createdCount: r.created.length,
    updatedCount: r.updated.length,
    deletedCount: r.deleted.length,
    adoptedCount: r.adopted.length,
    migratedCount: r.migrated,
    unchanged: r.unchanged,
    errorCount: r.errors.length,
    conflictCount: r.conflicts.length,
    created: r.created.map((c) => c.name),
    updated: r.updated.map((u) => `${u.name} (${u.changes.join(', ')})`),
    deleted: r.deleted.map((d) => d.name),
    adopted: r.adopted.map((a) => a.name),
    errors: r.errors.map((e) => `${e.name}: ${e.error}`),
    conflicts: r.conflicts.map((c) => `${c.zbxName}: ${c.detail}`),
  };
}

const hostSyncAction: ActionDescriptor<ZabbixActionContext> = {
  id: 'zabbix.host.sync',
  label: 'Sync UNM inventory into Zabbix',
  description:
    'Reconciles UNM\'s host inventory (documented hosts + optionally live observations) with this Zabbix server: creates missing hosts, updates status/IPs of changed ones and — only when the "delete orphans" option is enabled — removes UNM-managed hosts that are no longer in scope. Ownership is tracked by a marker tag whose value is the UNM host id, so ONLY hosts created/claimed by this sync are ever touched; untagged Zabbix hosts are left alone (or claimed when "adopt existing hosts" is on). Mapping rules (name template, groups, template link, tag filter) come from the plugin options.',
  module: 'Inventory Sync',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 300_000, // a large fleet can take a while — well above the 60s default
  inputSchema: {
    deleteOrphans: {
      type: 'boolean',
      required: false,
      description:
        'Override for this run only: when true, UNM-managed Zabbix hosts that are no longer in the inventory snapshot are DELETED. Absent = use the plugin option (default off).',
    },
  },
  async execute(ctx: ZabbixActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const cfg = resolveSyncConfig(ctx.settings);
    if (typeof input['deleteOrphans'] === 'boolean') cfg.deleteOrphans = input['deleteOrphans'];

    try {
      const result = await runSync(ctx.client, cfg);
      // Per-host errors are NOT a hard failure — the sync applied everything it could.
      return {
        success: true,
        applied: result.created.length + result.updated.length + result.deleted.length > 0,
        verified: true,
        details: syncDetails(result),
      };
    } catch (err) {
      // A snapshot fetch failure or a missing template aborts the whole run. Transport-level
      // failures (Zabbix down / not ready yet) are retryable; API-level ones are final.
      return failureResult(err);
    }
  },
};

const hostCreateAction: ActionDescriptor<ZabbixActionContext> = {
  id: 'zabbix.host.create',
  label: 'Create Zabbix host',
  description:
    'Registers a single host in this Zabbix server (host.create) with the given IP addresses, groups and optional template. Idempotent — an existing technical name is reported as already present.',
  module: 'Inventory Sync',
  riskLevel: 'write' as const,
  deviceCount: 1 as const,
  timeoutMs: 60_000,
  inputSchema: {
    hostName: { type: 'string', required: true, minLength: 1, maxLength: 255, description: 'Zabbix technical name (unique, e.g. "web-01" or the FQDN)' },
    displayName: { type: 'string', required: false, maxLength: 255, description: 'Display name shown in Zabbix UI (defaults to the technical name)' },
    ips: {
      type: 'array',
      required: true,
      items: { type: 'string' as const },
      description: 'IP addresses to monitor (the first becomes the main interface)',
    },
    groups: {
      type: 'array',
      required: false,
      items: { type: 'string' as const },
      description: 'Zabbix group names (auto-created when missing and "auto-create groups" is enabled)',
    },
    template: { type: 'string', required: false, maxLength: 255, description: 'Template name to link onto the host (must already exist)' },
    disabled: { type: 'boolean', required: false, default: false, description: 'Create the host in a disabled state' },
  },
  async execute(ctx: ZabbixActionContext, input: Record<string, unknown>): Promise<ActionResult> {
    const hostName = typeof input['hostName'] === 'string' ? input['hostName'].trim() : '';
    if (!hostName) return { success: false, error: '"hostName" is required' };
    const ipsRaw = Array.isArray(input['ips']) ? (input['ips'] as unknown[]) : [];
    const ips = ipsRaw.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => v.trim());
    if (ips.length === 0) return { success: false, error: '"ips" must contain at least one address' };

    // Idempotency: an existing technical name is a no-op.
    const existing = await ctx.client.getHosts();
    const found = existing.find((h) => h.host === hostName);
    if (found) {
      return { success: true, applied: false, verified: true, details: { host: hostName, note: 'Host already exists in Zabbix' } };
    }

    // Resolve groups.
    const cfg = resolveSyncConfig(ctx.settings);
    const groupNamesRaw = Array.isArray(input['groups']) ? (input['groups'] as unknown[]) : [];
    const groupNames = groupNamesRaw.filter((v): v is string => typeof v === 'string' && v.trim() !== '').map((v) => v.trim());
    let groupIds: string[] = [];
    if (groupNames.length > 0) {
      const existingGroups = await ctx.client.getHostGroups();
      for (const g of groupNames) {
        const id = existingGroups.get(g);
        if (id) groupIds.push(id);
        else if (cfg.autoCreateGroups) groupIds.push(await ctx.client.createHostGroup(g));
        else return { success: false, error: `Zabbix group "${g}" does not exist and "auto-create groups" is disabled` };
      }
    }

    // Resolve the optional template.
    let templateId: string | null = null;
    const templateName = typeof input['template'] === 'string' ? input['template'].trim() : '';
    if (templateName) {
      templateId = await ctx.client.findTemplate(templateName);
      if (!templateId) return { success: false, error: `Zabbix template "${templateName}" not found` };
    }

    const hostid = await ctx.client.createHost({
      host: hostName,
      name: typeof input['displayName'] === 'string' && input['displayName'].trim() ? input['displayName'].trim() : hostName,
      status: input['disabled'] === true ? 1 : 0,
      groupIds,
      ips,
    });
    if (templateId) await ctx.client.addTemplate([hostid], templateId);

    // Verify.
    let verified = false;
    try {
      const after = await ctx.client.getHosts();
      verified = after.some((h) => h.host === hostName);
    } catch { /* verification best-effort */ }

    return { success: true, applied: true, verified, details: { host: hostName, hostid, ips, groups: groupNames, template: templateName || null } };
  },
};

export const registry = createRegistry<ZabbixActionContext>([hostSyncAction, hostCreateAction]);
