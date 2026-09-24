/**
 * The inventory-sync engine — the WRITE half of the 'inventorySync' capability.
 *
 * Reconciles UNM's host inventory (fetched from the API's internal brokered read,
 * GET /plugin/inventory/hosts) against the Zabbix server and applies create /
 * update / delete so that the external monitoring system mirrors what UNM knows:
 *   - a host collected or created in UNM  → appears in Zabbix (host.create),
 *   - a host disabled in UNM              → its Zabbix host is disabled,
 *   - an IP change                        → the interface set is replaced,
 *   - a host removed from scope           → deleted (only when deleteOrphans is on).
 *
 * Ownership model (what keeps foreign hosts safe):
 *   - Every host the sync creates carries a marker tag whose VALUE is the UNM
 *     host id (`unm-managed=<unmHostId>`). Matching and orphan detection are
 *     keyed on that value, so ownership survives name-template changes.
 *   - Legacy hosts from earlier versions (marker value "managed") are matched by
 *     their technical name against the snapshot and re-tagged with the host id —
 *     a one-time automatic migration, no manual work needed.
 *   - Hosts WITHOUT the marker tag are never touched. When `adoptExisting` is on,
 *     an untagged Zabbix host whose technical name matches a rendered UNM name is
 *     CLAIMED (marker written) instead of failing with "already exists".
 */

import { createApiClient } from '@unm/plugin-sdk';
import type { InventoryHost, InventorySnapshot } from '@unm/plugin-sdk';
import { ZabbixClient, ZabbixApiError } from './client/zabbixClient';

/** The plugin-option keys that drive the sync mapping (single source of truth). */
export const SYNC_OPTION_KEYS = {
  scope: 'syncScope',
  tag: 'syncTag',
  markerTag: 'markerTag',
  nameTemplate: 'nameTemplate',
  groups: 'groups',
  autoCreateGroups: 'autoCreateGroups',
  template: 'template',
  ipMode: 'ipMode',
  deleteOrphans: 'deleteOrphans',
  inactiveAsDisabled: 'inactiveAsDisabled',
  adoptExisting: 'adoptExisting',
} as const;

/** The marker value written by pre-hardening versions — matched + migrated automatically. */
export const LEGACY_MARKER_VALUE = 'managed';

/** Effective sync configuration (resolved from plugin options + action input). */
export interface SyncConfig {
  /** Which UNM hosts are in scope: 'documented' = user-documented only, 'all' = + live observations. */
  scope: 'documented' | 'all';
  /** Only sync UNM hosts carrying this tag ('' = all in-scope hosts). */
  syncTag: string;
  /** Zabbix host tag marking a host as UNM-managed (drives orphan detection + matching). */
  markerTag: string;
  /** Placeholder template for the Zabbix technical name. Placeholders: {dns0} {friendlyName} {ip0}. */
  nameTemplate: string;
  /** Comma-separated Zabbix group names to place synced hosts into (auto-created when missing). */
  groups: string[];
  /** Create missing groups instead of failing. */
  autoCreateGroups: boolean;
  /** Optional template name linked onto every synced host ('' = none). */
  template: string;
  /** Which UNM addresses become Zabbix IP interfaces: 'all' or only the first ('primary'). */
  ipMode: 'all' | 'primary';
  /** Delete UNM-managed Zabbix hosts that are no longer in the snapshot. OFF by default (safe). */
  deleteOrphans: boolean;
  /** Map UNM isActive=false onto a disabled Zabbix host. */
  inactiveAsDisabled: boolean;
  /** Claim an untagged Zabbix host whose technical name matches a rendered UNM name instead of failing on the duplicate. */
  adoptExisting: boolean;
}

/** One managed (marker-tagged) Zabbix host as loaded for the diff. */
export interface ManagedHost {
  hostid: string;
  /** Technical name — the matching key for legacy hosts and adoption candidates. */
  zbxName: string;
  status: string;
  ips: Set<string>;
  /** The UNM host id encoded in the marker tag value, or null (legacy "managed" / foreign). */
  unmHostId: string | null;
}

/** One untagged Zabbix host that could be adopted by name. */
export interface AdoptionCandidate {
  hostid: string;
  zbxName: string;
  status: string;
  ips: Set<string>;
}

/** One planned change, before it is applied. */
export interface SyncOp {
  kind: 'create' | 'update' | 'delete';
  /** The UNM host id (for create/update). */
  unmHostId?: string;
  zabbixName: string;
  /** Exact Zabbix hostid for update/delete — names alone are ambiguous. */
  zbxHostId?: string;
  /** Human-readable reason for the change. */
  reason: string;
}

/** The outcome of one sync run. */
export interface SyncResult {
  snapshotCollectedAt: string;
  totalInScope: number;
  created: Array<{ name: string; hostid?: string }>;
  updated: Array<{ name: string; changes: string[] }>;
  deleted: Array<{ name: string }>;
  /** Untagged Zabbix hosts claimed by the sync this run (adoptExisting). */
  adopted: Array<{ name: string }>;
  /** Legacy marker hosts re-tagged with their UNM host id this run. */
  migrated: number;
  unchanged: number;
  errors: Array<{ name: string; error: string }>;
  /** Ownership conflicts — a managed Zabbix host is claimed by two different UNM hosts (or vice versa). Never acted on automatically. */
  conflicts: Array<{ zbxName: string; detail: string }>;
}

/** Extracts the UNM host id from a marker tag entry, or null when absent/legacy. */
export function markerValueOf(tags: Array<{ tag: string; value?: string }>, markerTag: string): string | null {
  const t = tags.find((x) => x.tag === markerTag);
  if (!t || !t.value || t.value === LEGACY_MARKER_VALUE) return null;
  return t.value;
}

/** Merges a new/updated marker tag into an existing tag list (full-replacement semantics). */
export function mergeMarkerTag(existing: Array<{ tag: string; value?: string }>, markerTag: string, unmHostId: string): Array<{ tag: string; value?: string }> {
  const rest = existing.filter((t) => t.tag !== markerTag);
  return [{ tag: markerTag, value: unmHostId }, ...rest];
}

/** Resolves the Zabbix technical name for one UNM host from the configured template. */
export function renderHostName(host: InventoryHost, template: string): string {
  const dns0 = host.dnsNames?.[0] ?? '';
  const ip0 = host.addresses?.[0]?.address ?? '';
  let out = (template || '{dns0}').replace(/\{dns0\}/g, dns0).replace(/\{friendlyName\}/g, host.friendlyName ?? '').replace(/\{ip0\}/g, ip0);
  // Fall back to the first DNS name / IP when the template produced nothing usable.
  if (!out.trim()) out = dns0 || ip0;
  return out.trim();
}

/** Selects the UNM addresses that become Zabbix interfaces per ipMode. */
export function selectIps(host: InventoryHost, mode: 'all' | 'primary'): string[] {
  const ips = (host.addresses ?? []).map((a) => a.address).filter(Boolean);
  return mode === 'primary' ? ips.slice(0, 1) : ips;
}

/** Fetches the authoritative UNM host-inventory snapshot from the API broker. */
export async function fetchInventorySnapshot(scope: 'documented' | 'all'): Promise<InventorySnapshot> {
  const api = createApiClient({ timeoutMs: 20_000 });
  const params = new URLSearchParams();
  if (scope === 'documented') params.set('documentedOnly', '1');
  const qs = params.toString();
  const res = await api.get(`/plugin/inventory/hosts${qs ? `?${qs}` : ''}`);
  const snap = res.data?.snapshot;
  if (!snap || !Array.isArray(snap.hosts)) throw new Error('API returned an invalid inventory snapshot');
  return snap as InventorySnapshot;
}

/** Filters the snapshot down to the hosts in sync scope (tag filter). */
export function filterInScope(snapshot: InventorySnapshot, cfg: SyncConfig): InventoryHost[] {
  let hosts = snapshot.hosts ?? [];
  if (cfg.scope === 'documented') hosts = hosts.filter((h) => h.documented);
  if (cfg.syncTag) hosts = hosts.filter((h) => (h.tags ?? []).some((t) => t.toLowerCase() === cfg.syncTag.toLowerCase()));
  return hosts;
}

/** True when two IP sets differ (order-insensitive). */
function ipSetsDiffer(a: Set<string>, b: Set<string>): boolean {
  for (const ip of a) if (!b.has(ip)) return true;
  for (const ip of b) if (!a.has(ip)) return true;
  return false;
}

/** The status change to apply for one host, or null when none is wanted. */
function wantStatusChange(host: InventoryHost, existing: { status: string }, cfg: SyncConfig): number | null {
  if (!cfg.inactiveAsDisabled) return null;
  const want = host.isActive === false ? 1 : 0;
  return Number(existing.status) !== want ? want : null;
}

/**
 * Computes the diff between the in-scope UNM snapshot and the current Zabbix state.
 * Pure function — no I/O beyond what is passed in, so it is unit-testable.
 *
 * Matching order per UNM host: (1) a managed host whose marker VALUE equals the
 * UNM host id — stable across name changes; (2) a legacy managed host (marker
 * value "managed") with an equal technical name — re-tagged on apply; (3) when
 * adoptExisting is on, an untagged candidate with an equal technical name.
 * Anything else → create. Ownership conflicts are reported, never acted on.
 */
export function computeDiff(
  inScope: InventoryHost[],
  managed: ManagedHost[],
  candidates: AdoptionCandidate[],
  cfg: SyncConfig
): { ops: SyncOp[]; unchanged: number; conflicts: Array<{ zbxName: string; detail: string }> } {
  const byId = new Map<string, ManagedHost>();
  for (const m of managed) if (m.unmHostId) byId.set(m.unmHostId, m);

  // Legacy hosts are matched by name — first UNM host wins, the rest conflict.
  const legacyByName = new Map<string, ManagedHost[]>();
  for (const m of managed) {
    if (m.unmHostId) continue;
    const list = legacyByName.get(m.zbxName) ?? [];
    list.push(m);
    legacyByName.set(m.zbxName, list);
  }

  // A candidate is only adoptable when no managed host already owns its name —
  // claiming it would create a duplicate technical name in Zabbix.
  const ownedNames = new Set(managed.map((m) => m.zbxName));
  const adoptable = candidates.filter((c) => !ownedNames.has(c.zbxName));

  const ops: SyncOp[] = [];
  const conflicts: Array<{ zbxName: string; detail: string }> = [];
  let unchanged = 0;
  const claimedManagedIds = new Set<string>(); // managed hostids consumed by an in-scope UNM host
  const consumedLegacy = new Set<string>();    // legacy hostids already matched to another UNM host

  for (const host of inScope) {
    const name = renderHostName(host, cfg.nameTemplate);
    if (!name) continue; // no resolvable identity — skip (surfaced via errors at apply time)
    const ips = selectIps(host, cfg.ipMode);

    let existing: ManagedHost | null = byId.get(host.id) ?? null;
    let legacyMatched = false;
    if (!existing) {
      const legacies = (legacyByName.get(name) ?? []).filter((l) => !consumedLegacy.has(l.hostid));
      if (legacies.length === 1) {
        existing = legacies[0];
        consumedLegacy.add(existing.hostid);
        legacyMatched = true; // re-tagged with this host's id on apply
      } else if (legacies.length > 1) {
        conflicts.push({ zbxName: name, detail: `${legacies.length} legacy UNM-managed Zabbix hosts share the technical name "${name}" — rename or delete all but one in Zabbix` });
        continue; // ambiguous ownership — neither update nor create is safe here
      }
    }
    if (!existing && cfg.adoptExisting) {
      const cand = adoptable.find((c) => c.zbxName === name);
      if (cand) existing = { hostid: cand.hostid, zbxName: cand.zbxName, status: cand.status, ips: cand.ips, unmHostId: null };
    }

    // A managed host whose marker points at a DIFFERENT UNM host is an ownership conflict —
    // never touched (neither updated nor deleted), reported for manual resolution.
    if (existing && existing.unmHostId !== null && existing.unmHostId !== host.id) {
      conflicts.push({ zbxName: existing.zbxName, detail: `Zabbix host "${existing.zbxName}" is already managed by UNM host ${existing.unmHostId} — remove the marker tag in Zabbix or fix the inventory` });
      continue;
    }

    if (!existing) {
      // Name collision with a managed host owned by another UNM host → a create would be
      // rejected by Zabbix anyway. Report it instead of burning an RPC per run.
      const owner = managed.find((m) => m.zbxName === name && m.unmHostId !== null);
      if (owner) {
        conflicts.push({ zbxName: name, detail: `rendered name collides with Zabbix host "${name}" already managed by UNM host ${owner.unmHostId} — change the name template or fix the inventory` });
        continue;
      }
      ops.push({ kind: 'create', unmHostId: host.id, zabbixName: name, reason: `new in UNM (${host.documented ? 'documented' : 'live'})` });
      continue;
    }

    claimedManagedIds.add(existing.hostid);

    const changes: string[] = [];
    if (!existing.unmHostId) changes.push('marker'); // legacy migration or adoption — re-tagged on apply
    // Marker-id match with a stale technical name (name template changed since the host
    // was created) → rename so Zabbix and UNM agree again.
    if (existing.zbxName !== name) changes.push(`name ${existing.zbxName}→${name}`);
    const statusChange = wantStatusChange(host, existing, cfg);
    if (statusChange !== null) changes.push(`status ${existing.status}→${statusChange}`);
    if (ips.length > 0 && ipSetsDiffer(existing.ips, new Set(ips))) {
      changes.push(`interfaces [${[...existing.ips].join(',')}]→[${[...new Set(ips)].join(',')}]`);
    }

    if (changes.length === 0) unchanged++;
    else ops.push({ kind: 'update', unmHostId: host.id, zabbixName: name, zbxHostId: existing.hostid, reason: changes.join('; ') });
  }

  // Orphans: UNM-managed Zabbix hosts no longer claimed by any in-scope host. Only when
  // deleteOrphans is on — the default keeps retired hosts (a monitoring system should not
  // silently lose history). Untagged candidates are NEVER deleted, whatever this option says.
  if (cfg.deleteOrphans) {
    for (const m of managed) {
      if (!claimedManagedIds.has(m.hostid)) ops.push({ kind: 'delete', zabbixName: m.zbxName, zbxHostId: m.hostid, reason: 'no longer in UNM inventory' });
    }
  }

  return { ops, unchanged, conflicts };
}

/**
 * Runs one full sync: fetch snapshot → load Zabbix state (managed + adoption
 * candidates) → diff → apply. Returns a SyncResult; per-host failures are
 * collected (not thrown) so one bad host never aborts the whole run — the plan
 * step reports them in `details`.
 */
export async function runSync(client: ZabbixClient, cfg: SyncConfig): Promise<SyncResult> {
  const snapshot = await fetchInventorySnapshot(cfg.scope);
  const inScope = filterInScope(snapshot, cfg);

  // --- Load current Zabbix state ----------------------------------------------
  // Managed hosts (marker tag present) — ownership is keyed on the marker VALUE.
  const rawManaged = await client.getManagedHosts(cfg.markerTag);
  const managed: ManagedHost[] = [];
  if (rawManaged.length > 0) {
    const interfaces = await client.getHostInterfaces(rawManaged.map((h) => h.hostid));
    for (const h of rawManaged) {
      managed.push({
        hostid: h.hostid,
        zbxName: h.host,
        status: h.status,
        ips: new Set(interfaces.get(h.hostid)?.map((i) => i.ip) ?? []),
        unmHostId: markerValueOf(h.tags, cfg.markerTag),
      });
    }
  }

  // Adoption candidates (untagged hosts) — only when the option is on. A candidate
  // whose name a managed host already owns is dropped in computeDiff.
  let candidates: AdoptionCandidate[] = [];
  if (cfg.adoptExisting) {
    const all = await client.getHosts();
    const managedIds = new Set(managed.map((m) => m.hostid));
    const candRows = all.filter((h) => !managedIds.has(h.hostid));
    if (candRows.length > 0) {
      const interfaces = await client.getHostInterfaces(candRows.map((h) => h.hostid));
      for (const h of candRows) {
        candidates.push({ hostid: h.hostid, zbxName: h.host, status: h.status, ips: new Set(interfaces.get(h.hostid)?.map((i) => i.ip) ?? []) });
      }
    }
  }

  const candidateIds = new Set(candidates.map((c) => c.hostid));
  const { ops, unchanged, conflicts } = computeDiff(inScope, managed, candidates, cfg);

  // --- Resolve groups (auto-create when allowed) ------------------------------
  let groupIds: string[] = [];
  if (cfg.groups.length > 0) {
    const existingGroups = await client.getHostGroups();
    for (const g of cfg.groups) {
      const id = existingGroups.get(g);
      if (id) groupIds.push(id);
      else if (cfg.autoCreateGroups) groupIds.push(await client.createHostGroup(g));
    }
  }

  // --- Resolve the optional template ------------------------------------------
  let templateId: string | null = null;
  if (cfg.template) {
    templateId = await client.findTemplate(cfg.template);
    if (!templateId) throw new ZabbixApiError(`Zabbix template "${cfg.template}" not found — create it or clear the option.`);
  }

  // --- Apply -------------------------------------------------------------------
  const result: SyncResult = {
    snapshotCollectedAt: snapshot.collectedAt,
    totalInScope: inScope.length,
    created: [],
    updated: [],
    deleted: [],
    adopted: [],
    migrated: 0,
    unchanged,
    errors: [],
    conflicts,
  };

  for (const op of ops) {
    try {
      if (op.kind === 'create') {
        const host = inScope.find((h) => h.id === op.unmHostId);
        if (!host) throw new Error('UNM host vanished from snapshot');
        const ips = selectIps(host, cfg.ipMode);
        // Marker value = UNM host id → stable ownership across name changes.
        const tags: Array<{ tag: string; value?: string }> = [{ tag: cfg.markerTag, value: host.id }];
        for (const t of host.tags ?? []) if (t.toLowerCase() !== cfg.syncTag.toLowerCase()) tags.push({ tag: t });
        const hostid = await client.createHost({
          host: op.zabbixName,
          name: host.friendlyName || host.name,
          status: cfg.inactiveAsDisabled && host.isActive === false ? 1 : 0,
          groupIds,
          ips,
          tags,
        });
        if (templateId) await client.addTemplate([hostid], templateId);
        result.created.push({ name: op.zabbixName, hostid });
      } else if (op.kind === 'update') {
        const target = op.zbxHostId ? managed.find((m) => m.hostid === op.zbxHostId) : undefined;
        if (!target) throw new Error('Zabbix host vanished before update');
        const host = inScope.find((h) => h.id === op.unmHostId);
        const changes: string[] = [];

        // Marker (re-)tagging — legacy migration or adoption. Merged with the
        // existing tag list so user tags on the Zabbix side are preserved.
        if (!target.unmHostId) {
          const currentTags = await client.getHostTags(target.hostid);
          await client.updateHost(target.hostid, { tags: mergeMarkerTag(currentTags, cfg.markerTag, host?.id ?? op.unmHostId ?? '') });
          changes.push('marker');
          if (candidateIds.has(target.hostid)) result.adopted.push({ name: target.zbxName }); // untagged before this run
          else result.migrated++; // legacy "managed" value → now the UNM host id
        }

        if (target.zbxName !== op.zabbixName) {
          await client.updateHost(target.hostid, { host: op.zabbixName, name: host?.friendlyName || op.zabbixName });
          changes.push(`name→${op.zabbixName}`);
        }

        if (cfg.inactiveAsDisabled && host) {
          const wantStatus = host.isActive === false ? 1 : 0;
          if (Number(target.status) !== wantStatus) {
            await client.updateHost(target.hostid, { status: wantStatus });
            changes.push(`status→${wantStatus}`);
          }
        }

        // Groups — only for adopted hosts (legacy/managed ones already have them).
        if (!target.unmHostId && groupIds.length > 0) {
          await client.updateHost(target.hostid, { groupIds });
          changes.push('groups');
        }

        if (host) {
          const ips = selectIps(host, cfg.ipMode);
          if (ips.length > 0 && ipSetsDiffer(target.ips, new Set(ips))) {
            await client.replaceInterfaces(target.hostid, ips);
            changes.push('interfaces');
          }
        }

        if (templateId) await client.addTemplate([target.hostid], templateId); // idempotent link
        result.updated.push({ name: target.zbxName, changes });
      } else {
        const target = op.zbxHostId ? managed.find((m) => m.hostid === op.zbxHostId) : undefined;
        if (target) {
          await client.deleteHosts([target.hostid]);
          result.deleted.push({ name: target.zbxName });
        }
      }
    } catch (err) {
      result.errors.push({ name: op.zabbixName, error: err instanceof Error ? err.message : String(err) });
    }
  }

  return result;
}

/**
 * Resolves the effective SyncConfig from the plugin's injected settings. This is
 * where "very flexible configuration" lives — every mapping rule is a plain option
 * the user can tune per device (or globally), so adapting to a different monitoring
 * system's logic never requires code changes.
 */
export function resolveSyncConfig(settings: Record<string, unknown>): SyncConfig {
  const str = (k: string): string => (typeof settings[k] === 'string' ? (settings[k] as string) : '');
  return {
    scope: str(SYNC_OPTION_KEYS.scope) === 'all' ? 'all' : 'documented',
    syncTag: str(SYNC_OPTION_KEYS.tag).trim(),
    markerTag: str(SYNC_OPTION_KEYS.markerTag).trim() || 'unm-managed',
    nameTemplate: str(SYNC_OPTION_KEYS.nameTemplate).trim() || '{dns0}',
    groups: str(SYNC_OPTION_KEYS.groups)
      .split(',')
      .map((g) => g.trim())
      .filter(Boolean),
    autoCreateGroups: settings[SYNC_OPTION_KEYS.autoCreateGroups] !== false,
    template: str(SYNC_OPTION_KEYS.template).trim(),
    ipMode: str(SYNC_OPTION_KEYS.ipMode) === 'primary' ? 'primary' : 'all',
    deleteOrphans: settings[SYNC_OPTION_KEYS.deleteOrphans] === true,
    inactiveAsDisabled: settings[SYNC_OPTION_KEYS.inactiveAsDisabled] !== false,
    adoptExisting: settings[SYNC_OPTION_KEYS.adoptExisting] === true,
  };
}
