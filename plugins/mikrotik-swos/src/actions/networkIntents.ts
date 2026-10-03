/**
 * Canonical fleet intents for SwOS — `network.create` / `network.delete`.
 *
 * A "network" on a MikroTik switch is an entry in the vlan.b table: {id, member
 * port mask, IGMP snooping} (+ name on full SwOS). The switch has NO L3
 * surface of its own (it's a layer-2 box) — so `network.create` here is
 * L2-only: it ensures the VLAN row exists with the requested member ports. An
 * L3 address in the intent inputs is reported as skipped (the router that owns
 * the subnet gets it via ITS plugin).
 *
 * Writes are a non-destructive read-modify-write of vlan.b: GET the current
 * table, upsert ONE row by id, POST the full array back. This differs from the
 * destructive `vlans.table.set` action (which replaces everything) — an intent
 * rollout must never wipe unrelated VLANs on the switch.
 */

import { INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, INTENT_L2_TOPOLOGY_READ } from '@unm/plugin-sdk';
import type { L2Topology, PreflightCapabilities, PreflightPort, PreflightResult, PreflightValue } from '@unm/plugin-sdk';
import { buildPostArray, decodeHexString, decodePortMask, encodeHexString, encodePortMask } from '../swosClient';
import { hasField } from '../platform';
import type { ActionContext, ActionDescriptor } from './types';

// --- vlan.b table model -----------------------------------------------------------------

/** One parsed row of the switch's VLAN table. */
interface VlanRow {
  id: number;
  members: number[]; // 1-based port numbers
  igmpSnooping: boolean;
  name?: string;
}

/** Reads + decodes the full vlan.b table (empty when the endpoint is absent). */
async function readVlanTable(ctx: ActionContext): Promise<VlanRow[]> {
  const map = ctx.platform.map;
  let raw: unknown;
  try {
    raw = await ctx.client.get('vlan.b');
  } catch {
    return []; // endpoint not available on this platform — treat as empty table
  }
  if (!Array.isArray(raw)) return [];
  const portCount = (await ctx.platform.portCount().catch(() => 0)) || 64;
  return raw.map((r) => {
    const row = r as Record<string, unknown>;
    return {
      id: Number(row[map.vlanId] ?? 0),
      members: decodePortMask(row[map.vlanMembers], portCount),
      igmpSnooping: Number(row[map.vlanIgmp] ?? 0) === 1,
      name: hasField(map, 'vlanName') && row[map.vlanName!] ? decodeHexString(row[map.vlanName!]) : undefined,
    };
  }).filter((r) => r.id > 0);
}

/** Encodes one logical row back into the wire shape (only writable fields). */
function encodeVlanRow(ctx: ActionContext, row: VlanRow): Record<string, number | string> {
  const map = ctx.platform.map;
  const entry: Record<string, number | string> = {
    [map.vlanId]: row.id,
    [map.vlanMembers]: encodePortMask(row.members),
    [map.vlanIgmp]: row.igmpSnooping ? 1 : 0,
  };
  if (hasField(map, 'vlanName') && row.name) entry[map.vlanName!] = encodeHexString(row.name);
  return entry;
}

/** POSTs the full table back (the protocol requires the complete array). */
async function postVlanTable(ctx: ActionContext, rows: VlanRow[]): Promise<void> {
  await ctx.client.post('vlan.b', buildPostArray(rows.map((r) => encodeVlanRow(ctx, r))));
}

/** Reads the platform's port-name array (fwd.b), best-effort — empty when absent. */
async function readPortNames(ctx: ActionContext, limit?: number): Promise<string[]> {
  const map = ctx.platform.map;
  try {
    const fwd = (await ctx.client.get('fwd.b')) as Record<string, unknown>;
    if (hasField(map, 'portNames') && Array.isArray(fwd[map.portNames])) {
      return (fwd[map.portNames] as string[]).slice(0, limit || undefined);
    }
  } catch { /* best-effort */ }
  return [];
}

/** Per-port VLAN facts from fwd.b (mode / receive filter / PVID) + LAG groups. */
interface PortVlanDetail {
  /** 1-based port number → trunk flag (carries >1 VLAN or accepts tagged frames). */
  trunk: Map<number, boolean>;
  /** 1-based port number → untagged default VLAN id (PVID), when set. */
  pvid: Map<number, number | null>;
  /** 1-based port number → all VLAN ids the port carries. */
  vlans: Map<number, number[]>;
  /** LAG group id → member port numbers (0 / absent = not in a bundle). */
  lagGroup: Map<number, number>;
}

const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0);

/** Reads fwd.b + lacp.b into per-port VLAN/LAG facts. Best-effort — empty maps when absent. */
async function readPortVlanDetails(ctx: ActionContext, portCount: number): Promise<PortVlanDetail> {
  const map = ctx.platform.map;
  const out: PortVlanDetail = { trunk: new Map(), pvid: new Map(), vlans: new Map(), lagGroup: new Map() };

  try {
    const fwd = (await ctx.client.get('fwd.b')) as Record<string, unknown>;
    const modesRaw = hasField(map, 'vlanPortMode') ? fwd[map.vlanPortMode] : undefined;
    if (Array.isArray(modesRaw)) {
      const recvRaw = hasField(map, 'vlanPortReceive') ? (fwd[map.vlanPortReceive] as unknown[] | undefined) : undefined;
      const defRaw = hasField(map, 'vlanPortDefaultId') ? (fwd[map.vlanPortDefaultId] as unknown[] | undefined) : undefined;
      for (let i = 0; i < modesRaw.length && i < portCount; i++) {
        const p = i + 1;
        const modeName = map.vlanPortModes[num((modesRaw as unknown[])[i])] ?? '';
        // Receive filter: 'Any' | 'Only Tagged' | 'Only Untagged' (index into the
        // platform's wire enum — same table monitoring.ts uses).
        const recvIdx = recvRaw ? num(recvRaw[i]) : 0;
        const onlyUntagged = recvIdx === 2; // VLAN_RECEIVE[2] = 'Only Untagged'
        const disabled = modeName.toLowerCase() === 'disabled';
        out.pvid.set(p, defRaw && typeof defRaw[i] === 'number' ? (defRaw[i] as number) : null);
        if (!disabled && !onlyUntagged) out.trunk.set(p, true); // tagged frames accepted
      }
    }
  } catch { /* best-effort */ }

  try {
    const lag = (await ctx.client.get('lacp.b')) as Record<string, unknown>;
    if (hasField(map, 'lagGroup') && Array.isArray(lag[map.lagGroup])) {
      for (let i = 0; i < (lag[map.lagGroup] as unknown[]).length && i < portCount; i++) {
        const g = num((lag[map.lagGroup] as unknown[])[i]);
        if (g > 0) out.lagGroup.set(i + 1, g);
      }
    }
  } catch { /* best-effort */ }

  // VLAN membership from the table: a port in >1 VLAN row is a trunk even when
  // its receive filter says 'Any' (e.g. untagged PVID + one tagged domain).
  const rows = await readVlanTable(ctx);
  for (const r of rows) {
    for (const m of r.members) {
      const set = out.vlans.get(m) ?? [];
      if (!set.includes(r.id)) set.push(r.id);
      out.vlans.set(m, set);
      if ((out.vlans.get(m)?.length ?? 0) > 1) out.trunk.set(m, true);
    }
  }

  return out;
}

/** Builds the L2 topology from the VLAN table + port count (+ trunk/LAG facts). */
async function readSwosL2Topology(ctx: ActionContext): Promise<L2Topology> {
  const map = ctx.platform.map;
  const portCount = (await ctx.platform.portCount().catch(() => 0)) || 0;
  const rows = await readVlanTable(ctx);

  // Port names when the platform exposes them (fwd.b / sys.b identity).
  const portNames = await readPortNames(ctx, portCount || undefined);

  const details = await readPortVlanDetails(ctx, Math.max(portCount, portNames.length));

  const physicalPorts: L2Topology['physicalPorts'] = [];
  for (let p = 1; p <= Math.max(portCount, portNames.length); p++) {
    physicalPorts.push({
      name: portNames[p - 1] || `Port ${p}`,
      assignment: String(p),
      trunk: details.trunk.get(p) ?? false,
      pvid: details.pvid.has(p) ? (details.pvid.get(p) ?? null) : undefined,
      vlans: details.vlans.get(p)?.length ? details.vlans.get(p) : undefined,
    });
  }

  // Each VLAN is an L2 domain — its member ports are the bridge members.
  const bridges = rows.map((r) => ({
    name: r.name ? `${r.name} (VLAN ${r.id})` : `VLAN ${r.id}`,
    members: r.members.map((m) => portNames[m - 1] || String(m)),
  }));

  // LAG bundles — group ports by their lagGroup id so the UI can show one entry.
  const groups = new Map<number, number[]>();
  for (const [port, g] of details.lagGroup) {
    const arr = groups.get(g) ?? [];
    arr.push(port);
    groups.set(g, arr);
  }
  const bundles = [...groups.entries()].map(([g, members]) => ({
    name: `LAG ${g}`,
    protocol: 'LACP' as string | null,
    members: members.map((m) => portNames[m - 1] || String(m)),
  }));

  return { physicalPorts, bridges, bundles, l3Interfaces: {}, uplinks: [] };
}

/** Normalizes a `vlanPorts` input (numbers and/or port names) to 1-based port numbers. */
function normalizeVlanPortInput(raw: unknown[], portNames: string[]): number[] {
  const byName = new Map<string, number>();
  portNames.forEach((n, i) => { if (n) byName.set(n.toUpperCase(), i + 1); });
  const out: number[] = [];
  for (const item of raw) {
    let p: number | null = null;
    if (typeof item === 'number' && Number.isInteger(item)) p = item;
    else if (typeof item === 'string') {
      const t = item.trim();
      if (/^\d+$/.test(t)) p = Number(t);
      else { const named = byName.get(t.toUpperCase()); if (named) p = named; }
    }
    if (p !== null && p >= 1 && !out.includes(p)) out.push(p);
  }
  return out.sort((a, b) => a - b);
}

// --- network.create -------------------------------------------------------------------

const NETWORK_CREATE_INPUTS = {
  name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (stored in the VLAN row on full SwOS; Lite has no name field)' },
  vlanId: { type: 'number' as const, min: 1, max: 4094, required: true, description: 'VLAN ID — a row is upserted into the switch\'s VLAN table (L2-only; switches carry no L3 addresses)' },
  // Canonical contract is string[] (port names); this plugin ALSO accepts
  // 1-based numbers. validateInput does not type-check array items, so both
  // shapes pass — normalizeVlanPortInput coerces at runtime.
  vlanPorts: { type: 'array' as const, items: { type: 'string' } as const, description: 'Member ports carrying this VLAN — port names (e.g. ["Port 1"]) or 1-based numbers. When omitted the row is created with NO members — add them via vlan.port.set.' },
} as const;

/**
 * Ensures one VLAN row exists on the switch. Idempotent by id: an existing row
 * keeps its member mask unless `vlanPorts` is given explicitly (then it's
 * replaced). L3 inputs are reported skipped — a switch has no IP surface.
 */
export const networkCreateAction: ActionDescriptor = {
  id: INTENT_NETWORK_CREATE,
  label: 'Create network (VLAN row)',
  description:
    'Upserts one VLAN into the switch\'s vlan.b table (non-destructive read-modify-write — unrelated rows are preserved). L2-only: a requested L3 address is reported as skipped because switches carry no IP addresses.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: { ...NETWORK_CREATE_INPUTS },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!name) return { success: false, error: 'Network name is required' };
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;
    if (vlanId === null || vlanId < 1 || vlanId > 4094) {
      return { success: false, error: '`vlanId` is required for a switch network (1..4094)' };
    }
    // Port names AND 1-based numbers are accepted (canonical contract = string[]).
    let membersRaw: number[] | null = null;
    if (Array.isArray(input.vlanPorts)) {
      const portCount = (await ctx.platform.portCount().catch(() => 0)) || 0;
      const portNames = await readPortNames(ctx, portCount || undefined);
      membersRaw = normalizeVlanPortInput(input.vlanPorts as unknown[], portNames);
    }

    // L3 inputs are not applicable to a layer-2 switch — reported, never applied.
    const details: Record<string, unknown> = {};
    if (typeof input.cidr === 'string' && String(input.cidr).trim()) details.l3Skipped = `switches carry no IP addresses — ${String(input.cidr)} is not applied here`;
    if (typeof input.cidrV6 === 'string' && String(input.cidrV6).trim()) details.l3SkippedV6 = `switches carry no IPv6 addresses — ${String(input.cidrV6)} is not applied here`;

    // 1. Live table.
    const rows = await readVlanTable(ctx);
    const existing = rows.find((r) => r.id === vlanId);

    // 2. Idempotency / upsert decision.
    if (existing && membersRaw === null) {
      return { success: true, applied: false, verified: true, details: { skipped: `VLAN ${vlanId} already exists with ports [${existing.members.join(', ')}]`, ...details } };
    }

    const next = [...rows];
    if (existing) {
      existing.name = name; // refresh the name on full SwOS (no-op on Lite)
      if (membersRaw !== null) existing.members = membersRaw;
    } else {
      next.push({ id: vlanId, members: membersRaw ?? [], igmpSnooping: false, name });
    }

    // 3. POST the full table back + verify by re-read.
    await postVlanTable(ctx, next);
    const after = await readVlanTable(ctx);
    const finalRow = after.find((r) => r.id === vlanId);
    if (!finalRow) return { success: false, error: `verification failed — VLAN ${vlanId} not present after write` };
    if (membersRaw !== null && !wireEqualMembers(finalRow.members, membersRaw)) {
      return { success: false, error: `verification failed — VLAN ${vlanId} member ports do not match after write` };
    }

    return { success: true, applied: true, verified: true, details: { vlanId, name, members: finalRow.members, ...details } };
  },
};

// --- network.delete -------------------------------------------------------------------

/**
 * Removes one VLAN row (id-addressed via the intent's `vlanId`, idempotent).
 * The full table is re-POSTed without that row — unrelated rows are preserved.
 */
export const networkDeleteAction: ActionDescriptor = {
  id: INTENT_NETWORK_DELETE,
  label: 'Delete network (VLAN row)',
  description: 'Removes one VLAN from the switch\'s vlan.b table (non-destructive — other rows are preserved). Idempotent — a missing id is a no-op.',
  module: 'Network',
  riskLevel: 'write',
  deviceCount: 'N' as const,
  timeoutMs: 60_000,
  inputSchema: {
    name: { type: 'string' as const, required: true, minLength: 1, maxLength: 64, description: 'Network name (matched against the VLAN row name on full SwOS)' },
    vlanId: { type: 'number' as const, min: 1, max: 4094, description: 'VLAN ID to remove — takes precedence over the name match when set' },
  },
  execute: async (ctx, input) => {
    const name = String(input.name ?? '').trim();
    if (!name) return { success: false, error: 'Network name is required' };
    const vlanId = typeof input.vlanId === 'number' ? Math.floor(input.vlanId as number) : null;

    const rows = await readVlanTable(ctx);
    // Resolve the target row: explicit id wins, else a name match (full SwOS).
    let target = vlanId !== null ? rows.find((r) => r.id === vlanId) : undefined;
    if (!target && vlanId === null) {
      const needle = name.toUpperCase();
      target = rows.find((r) => (r.name ?? '').toUpperCase() === needle);
    }
    if (!target) return { success: true, applied: false, verified: true, details: { skipped: `no VLAN ${vlanId !== null ? vlanId : `named "${name}"`} on this switch` } };

    const next = rows.filter((r) => r.id !== target!.id);
    await postVlanTable(ctx, next);
    const after = await readVlanTable(ctx);
    if (after.some((r) => r.id === target!.id)) {
      return { success: false, error: `verification failed — VLAN ${target.id} still present after delete` };
    }
    return { success: true, applied: true, verified: true, details: { removed: target.id, name: target.name ?? undefined } };
  },
};

// --- l2.topology.read -------------------------------------------------------------------

/** The switch's L2 hierarchy (ports + VLAN domains). */
export const l2TopologyReadAction: ActionDescriptor = {
  id: INTENT_L2_TOPOLOGY_READ,
  label: 'Read L2 topology',
  description: 'Physical ports and the VLAN table as L2 domains — the member-port source for network.create preflight.',
  module: 'Network',
  riskLevel: 'read',
  deviceCount: 'N' as const,
  inputSchema: {},
  execute: async (ctx) => {
    const topo = await readSwosL2Topology(ctx);
    return { success: true, details: { topology: topo } };
  },
};

export const networkIntentActions: ActionDescriptor[] = [networkCreateAction, networkDeleteAction, l2TopologyReadAction];

// --- Preflight --------------------------------------------------------------------------

/**
 * Preflight resolver for `network.create` on one switch. Read-only: the vlan.b
 * table yields reuse hints + a member-port suggestion (copy an existing VLAN's
 * ports when no explicit list is given).
 */
export async function preflightNetworkCreate(ctx: ActionContext, inputs: Record<string, unknown>): Promise<PreflightResult> {
  const values: PreflightValue[] = [];
  try {
    const rows = await readVlanTable(ctx);
    const name = typeof inputs.name === 'string' ? String(inputs.name).trim() : '';
    const vlanId = typeof inputs.vlanId === 'number' ? Math.floor(inputs.vlanId as number) : null;
    // Port list + trunk flags for the dialog's quick selects (All / Trunk only /
    // Select ports). Rides along with the preflight — no extra round-trip.
    const portCount = (await ctx.platform.portCount().catch(() => 0)) || 0;
    const portNames = await readPortNames(ctx, portCount || undefined);
    const details = await readPortVlanDetails(ctx, Math.max(portCount, portNames.length));
    const ports: PreflightPort[] = [];
    for (let p = 1; p <= Math.max(portCount, portNames.length); p++) {
      ports.push({ name: portNames[p - 1] || `Port ${p}`, trunk: details.trunk.get(p) ?? false, pvid: details.pvid.has(p) ? (details.pvid.get(p) ?? null) : undefined });
    }
    const capabilities: PreflightCapabilities = { vlanPorts: true };
    if (vlanId !== null) {
      const existing = rows.find((r) => r.id === vlanId);
      values.push(
        existing
          ? { key: 'vlanId', value: vlanId, confidence: 'high', note: `VLAN ${vlanId} already exists with ports [${existing.members.join(', ')}] — left untouched unless member ports are given` }
          : { key: 'vlanId', value: vlanId, confidence: 'medium', note: `no VLAN ${vlanId} yet — a row will be added to the table` },
      );

      // Member-port suggestion: copy an existing VLAN's port list (the switch's
      // current tagging convention) when the user didn't specify ports. Suggested
      // as NAMES (canonical string[]) — network.create accepts names or numbers.
      const hasPorts = Array.isArray(inputs.vlanPorts) && (inputs.vlanPorts as unknown[]).length > 0;
      if (!hasPorts) {
        const donor = rows.find((r) => r.members.length > 0);
        if (donor) values.push({ key: 'vlanPorts', value: donor.members.map((m) => portNames[m - 1] || `Port ${m}`), confidence: 'medium', note: `suggested member ports copied from VLAN ${donor.id} [${donor.members.join(', ')}] — override per device` });
      }
    }

    if (name && vlanId === null) {
      const byName = rows.find((r) => (r.name ?? '').toUpperCase() === name.toUpperCase());
      values.push(
        byName
          ? { key: 'vlanId', value: byName.id, confidence: 'high', note: `VLAN named "${name}" already exists as id ${byName.id}` }
          : { key: 'vlanId', value: null, confidence: 'low', note: 'no vlanId given — a switch network needs one (1..4094)' },
      );
    }

    return { deviceId: ctx.deviceId ?? '', values, ports, capabilities };
  } catch (e) {
    return { deviceId: ctx.deviceId ?? '', values, degraded: true, error: e instanceof Error ? e.message : String(e) };
  }
}

/** Registry of preflight resolvers per canonical intent id. */
export const PREFLIGHT_RESOLVERS: Record<string, (ctx: ActionContext, inputs: Record<string, unknown>) => Promise<PreflightResult>> = {
  [INTENT_NETWORK_CREATE]: preflightNetworkCreate,
};

// --- Small helpers ------------------------------------------------------------------------

/** Order-insensitive member-list equality. */
function wireEqualMembers(a: number[], b: number[]): boolean {
  if (a.length !== b.length) return false;
  const sa = [...a].sort((x, y) => x - y);
  const sb = [...b].sort((x, y) => x - y);
  return sa.every((v, i) => v === sb[i]);
}
