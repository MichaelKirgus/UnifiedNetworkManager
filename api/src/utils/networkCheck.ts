import { db } from '../db';
import * as schema from '../db/schema';
import { cidrsOverlap, ipScope, ipv4ToInt, splitCidr } from '@unm/plugin-sdk';
import { mergeNetworkRows } from '../routes/networks';
import { getEffectiveValues } from '../systemSettings';

/**
 * Server-side network-overlap checks for the fleet rollout wizard.
 *
 * The webapp used to compute these client-side against GET /networks; this is
 * the authoritative copy — it runs on EVERY plan-creation path (webapp, API
 * clients, plans) and feeds both the advisory warnings (preflight response)
 * and the optional blocking mode (POST /plans rejects in strict mode).
 *
 * Checks are deliberately ADVISORY by default: NAT'd remote sites legitimately
 * reuse names/subnets/VLAN ids. The `rolloutOverlapMode` system setting
 * ("warn" | "block") decides whether a hit blocks plan creation.
 */

/** One overlap finding — machine-readable kind + human message. */
export interface NetworkCheckWarning {
  /** 'name' | 'subnet' | 'vlan' — stable id for UI grouping / tests. */
  kind: 'name' | 'subnet' | 'vlan';
  /** Human-readable explanation (shown verbatim in the dialog). */
  message: string;
  /** The live network row this finding refers to (its GET /networks key). */
  networkKey: string;
}

/** Per-device rollout outcome — drives the step-2 diff summary table. */
export interface NetworkCheckDeviceStatus {
  deviceId: string;
  deviceName: string;
  /** 'deployed' = live inventory already shows this network on the device (no-op). */
  status: 'deployed' | 'new';
}

/** Free-range suggestions computed from gaps in the live inventory. */
export interface NetworkCheckSuggestions {
  /** Next free /24 after the highest observed v4 subnet, or null when none fits. */
  nextFreeSubnetV4: string | null;
  /** Lowest unused VLAN id (1..4094) not present in the live inventory. */
  lowestFreeVlanId: number | null;
}

export interface NetworkCheckResult {
  warnings: NetworkCheckWarning[];
  devices: NetworkCheckDeviceStatus[];
  suggestions: NetworkCheckSuggestions;
}

/** The shared intent inputs we care about (canonical network.create shape). */
interface CheckInputs {
  name?: string;
  vlanId?: number | null;
  cidr?: string;
}

/** True for subnets that do not identify a real network (loopback/link-local). */
function isNonNetworkSubnet(subnet: string): boolean {
  const [addr, prefix] = subnet.split('/');
  if (prefix === undefined) return false;
  const scope = ipScope(addr);
  return scope === 'loopback' || scope === 'link-local';
}

/**
 * Loads the merged live-network inventory. No freshness filter — the telemetry
 * worker sweeps rows not refreshed within its window, so what is in the table
 * IS the current view (same data GET /networks renders).
 */
async function loadLiveNetworks() {
  const rows = await db.query.networks.findMany();
  return mergeNetworkRows(rows);
}

/** One documented network row as used by the name-collision check. */
export interface DocumentedNetRef {
  id: string;
  name: string;
  subnets: string[];
  isActive: boolean;
}

/** Loads all documented networks (the user-maintained registry). */
async function loadDocumentedNetworks(): Promise<DocumentedNetRef[]> {
  const rows = await db.query.documentedNetworks.findMany();
  return rows.map((r) => ({
    id: r.id,
    name: r.name,
    subnets: parseJsonArray(r.subnets),
    isActive: r.isActive,
  }));
}

function parseJsonArray(raw: string | null): string[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed.filter((s): s is string => typeof s === 'string') : [];
  } catch {
    return [];
  }
}

/** Device display names for the given ids (missing devices fall back to the id). */
async function loadDeviceNames(deviceIds: string[]): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  if (deviceIds.length === 0) return map;
  const devices = await db.query.devices.findMany({ where: (d, { inArray }) => inArray(d.id, deviceIds) });
  for (const d of devices) map.set(d.id, d.name);
  return map;
}

/**
 * Runs the overlap checks. Pure with respect to its inputs — `live` is passed
 * in so callers can reuse one inventory load across several checks.
 */
export function runNetworkChecks(
  inputs: CheckInputs,
  deviceIds: string[],
  live: Array<{ key: string; name: string; subnets: string[]; vlanId: number | null; devices: Array<{ deviceId: string }> }>,
  documented?: DocumentedNetRef[],
): { warnings: NetworkCheckWarning[]; devices: NetworkCheckDeviceStatus[] } {
  const out: NetworkCheckWarning[] = [];
  const seen = new Set<string>();
  const push = (w: NetworkCheckWarning) => {
    if (!seen.has(w.kind + w.networkKey)) {
      seen.add(w.kind + w.networkKey);
      out.push(w);
    }
  };

  const name = (inputs.name ?? '').trim();
  const tCidr = (inputs.cidr ?? '').trim();
  const v = inputs.vlanId;
  const hasVlan = Number.isInteger(v as number) && (v as number) >= 1 && (v as number) <= 4094;

  // 1. Name collision — same name, different network.
  if (name) {
    const nm = name.toLowerCase();
    for (const n of live) {
      // With a CIDR the subnet check below is the precise one; without it the
      // name match alone flags a possible duplicate.
      if (tCidr || n.name.toLowerCase() !== nm) continue;
      const where =
        n.subnets.join(', ') || `VLAN ${n.vlanId ?? '?'} on ${Array.from(new Set(n.devices.map((d) => d.deviceId))).slice(0, 3).join(', ')}…`;
      push({ kind: 'name', networkKey: `live:${n.key}`, message: `Name "${n.name}" already exists in the live inventory (${where}).` });
    }
    // Documented networks carry real user names — a collision there is almost
    // always a duplicate entry (or an intentional rename), so flag it even when
    // a CIDR is given.
    for (const d of documented ?? []) {
      if (d.name.toLowerCase() !== nm) continue;
      push({ kind: 'name', networkKey: `doc:${d.id}`, message: `Documented network "${d.name}" already uses this name${d.subnets.length > 0 ? ` (${d.subnets.join(', ')})` : ''}${!d.isActive ? ' (stale)' : ''}.` });
    }
  }

  // 2. Subnet overlap — the target CIDR intersects an existing live subnet.
  if (tCidr) {
    for (const n of live) {
      const hit = n.subnets.find((s) => s.includes('/') && !isNonNetworkSubnet(s) && cidrsOverlap(tCidr, s));
      if (!hit) continue;
      const devs = Array.from(new Set(n.devices.map((d) => d.deviceId))).slice(0, 4).join(', ');
      push({ kind: 'subnet', networkKey: n.key, message: `Subnet ${tCidr} overlaps existing live network "${n.name}" (${hit}) on ${devs}. Fine for NAT'd remote sites — otherwise pick a free range.` });
    }
  }

  // 3. VLAN reuse — same VLAN ID, different (non-overlapping) subnet.
  if (hasVlan) {
    for (const n of live) {
      if (n.vlanId !== v) continue;
      const sameSubnet = tCidr ? n.subnets.some((s) => s.includes('/') && cidrsOverlap(tCidr, s)) : false;
      if (!sameSubnet) push({ kind: 'vlan', networkKey: n.key, message: `VLAN ${v} is already used by live network "${n.name}" (${n.subnets.join(', ') || 'no subnet known'}) — extending it on more devices is usually intended; a different subnet with the same VLAN ID will not route between sites.` });
    }
  }

  // Per-device status: "deployed" when the live inventory already shows this
  // network on that device (the intent step will be a no-op there).
  const devices: NetworkCheckDeviceStatus[] = [];
  for (const id of deviceIds) {
    let deployed = false;
    for (const n of live) {
      if (!n.devices.some((m) => m.deviceId === id)) continue;
      if (tCidr && n.subnets.some((s) => s.includes('/') && cidrsOverlap(tCidr, s))) { deployed = true; break; }
      if (!tCidr && hasVlan && n.vlanId === v) { deployed = true; break; }
    }
    devices.push({ deviceId: id, deviceName: '', status: deployed ? 'deployed' : 'new' });
  }

  return { warnings: out.slice(0, 12), devices };
}

/**
 * Suggests free ranges from gaps in the live inventory.
 *   - nextFreeSubnetV4: the /24 directly after the highest observed v4 subnet
 *     (skipping loopback/link-local/multicast/reserved space).
 *   - lowestFreeVlanId: the smallest VLAN id 1..4094 not present in inventory.
 */
export function suggestFreeRanges(
  live: Array<{ subnets: string[]; vlanId: number | null }>,
): NetworkCheckSuggestions {
  // --- next free /24 ---------------------------------------------------------
  // Find the exclusive upper bound of the highest observed v4 subnet, then walk
  // forward to the next /24 boundary that lands in routable (private/public) space.
  let highestEnd = -1; // exclusive upper bound as a 32-bit int
  for (const n of live) {
    for (const s of n.subnets) {
      if (!s.includes('/') || s.includes(':')) continue;
      const scope = ipScope(s);
      if (scope === 'loopback' || scope === 'link-local' || scope === 'multicast' || scope === 'reserved') continue;
      const split = splitCidr(s);
      if (!split) continue;
      const netInt = ipv4ToInt(split.net);
      if (netInt === null) continue;
      const mask = split.prefix === 0 ? 0 : (~0 << (32 - split.prefix)) >>> 0;
      const size = ((~mask) >>> 0) + 1; // number of addresses in the block
      const endExclusive = (((netInt & mask) + size) >>> 0);
      if (endExclusive > highestEnd) highestEnd = endExclusive;
    }
  }

  let nextFreeSubnetV4: string | null = null;
  if (highestEnd >= 0) {
    // Align the candidate up to a /24 boundary, then scan forward (bounded —
    // at most one full v4 space walk, which is 16M iterations worst case but
    // in practice stops within a few blocks).
    let base = highestEnd >>> 0;
    const misalign = base & 0x000000ff;
    if (misalign !== 0) base = (base + (256 - misalign)) >>> 0;
    for (let i = 0; i < 1_048_576; i++) { // at most 1M /24 blocks (a full /8 per octet step is far less)
      const a = (base >>> 24) & 255, b = (base >>> 16) & 255, c = (base >>> 8) & 255, d = base & 255;
      if (a !== 0 && a < 224) { // skip 0/8 and multicast/reserved space
        const cidrStr = `${a}.${b}.${c}.${d}/24`;
        const scope = ipScope(cidrStr);
        if (scope === 'private' || scope === 'public') { nextFreeSubnetV4 = cidrStr; break; }
      }
      base = (base + 0x100) >>> 0; // step one /24 forward
    }
  }

  // --- lowest free VLAN id ----------------------------------------------------
  const used = new Set<number>();
  for (const n of live) if (n.vlanId !== null && Number.isInteger(n.vlanId)) used.add(n.vlanId);
  let lowestFreeVlanId: number | null = null;
  for (let id = 1; id <= 4094; id++) {
    if (!used.has(id)) { lowestFreeVlanId = id; break; }
  }

  return { nextFreeSubnetV4, lowestFreeVlanId };
}

/**
 * Full check for one rollout: warnings + per-device status + free-range
 * suggestions. `deviceIds` are the target devices (for the deployed/new table).
 */
export async function networkCheck(
  inputs: Record<string, unknown>,
  deviceIds: string[],
): Promise<NetworkCheckResult> {
  const parsed = parseCheckInputs(inputs);
  const [live, documented] = await Promise.all([loadLiveNetworks(), loadDocumentedNetworks()]);
  const { warnings, devices } = runNetworkChecks(parsed, deviceIds, live, documented);
  const names = await loadDeviceNames(deviceIds);
  for (const d of devices) d.deviceName = names.get(d.deviceId) ?? d.deviceId;

  return { warnings, devices, suggestions: suggestFreeRanges(live) };
}

/** Per-device check result (deployed flag + this device's overlap warnings). */
export interface DeviceCheckResult {
  deployed: boolean;
  warnings: NetworkCheckWarning[];
}

function parseCheckInputs(inputs: Record<string, unknown>): CheckInputs {
  const parsed: CheckInputs = {};
  if (typeof inputs.name === 'string') parsed.name = inputs.name;
  if (inputs.vlanId !== undefined && inputs.vlanId !== null) parsed.vlanId = Number(inputs.vlanId);
  if (typeof inputs.cidr === 'string') parsed.cidr = inputs.cidr;
  return parsed;
}

/**
 * Per-device checks for a batch of devices — ONE inventory load, then each
 * device is checked against the live rows that include it. Used by the
 * preflight fan-out so N devices cost one query instead of N.
 */
export async function networkChecksForDevices(
  inputs: Record<string, unknown>,
  deviceIds: string[],
): Promise<Record<string, DeviceCheckResult>> {
  const parsed = parseCheckInputs(inputs);
  const live = await loadLiveNetworks();
  const out: Record<string, DeviceCheckResult> = {};
  for (const id of deviceIds) {
    // Only rows that include this device are relevant for its status/warnings.
    const scoped = live.filter((n) => n.devices.some((m) => m.deviceId === id));
    const { warnings, devices } = runNetworkChecks(parsed, [id], scoped);
    out[id] = { deployed: (devices[0]?.status ?? 'new') === 'deployed', warnings };
  }
  return out;
}

/** Convenience: the same check restricted to one device's live rows. */
export async function networkCheckForDevice(
  inputs: Record<string, unknown>,
  deviceId: string,
): Promise<DeviceCheckResult> {
  const all = await networkChecksForDevices(inputs, [deviceId]);
  return all[deviceId] ?? { deployed: false, warnings: [] };
}

/** One device's effective inputs for the blocking gate. */
export interface DeviceInputs {
  deviceId: string;
  /** Shared intent inputs merged with this device's overrides (already applied). */
  inputs: Record<string, unknown>;
}

/**
 * Blocking-mode gate for POST /plans. Returns an error message when the
 * rollout must be rejected (mode "block" + at least one overlap warning), or
 * null when creation may proceed. Each device is checked with ITS OWN effective
 * inputs (shared + per-device overrides) against the FULL live inventory — a
 * subnet/VLAN collision anywhere in the fleet is relevant, not just on the
 * target devices. Reads the effective `rolloutOverlapMode` setting; any lookup
 * failure degrades to "warn" (never blocks on a DB hiccup).
 */
export async function assertRolloutAllowed(
  intentActionId: string,
  perDevice: DeviceInputs[],
): Promise<string | null> {
  if (intentActionId !== 'network.create') return null; // only the rollout intent is gated

  let mode = 'warn';
  try {
    const values = await getEffectiveValues();
    const raw = values['rolloutOverlapMode'];
    if (raw === 'block' || raw === 'warn') mode = raw;
  } catch {
    return null; // settings unavailable → advisory only
  }
  if (mode !== 'block') return null;

  // Documented-name collisions block too — a duplicate of a user-maintained
  // network name is exactly what strict mode exists to catch.
  const [live, documented] = await Promise.all([loadLiveNetworks(), loadDocumentedNetworks()]);
  const allWarnings: NetworkCheckWarning[] = [];
  for (const d of perDevice) {
    const { warnings } = runNetworkChecks(parseCheckInputs(d.inputs), [d.deviceId], live, documented);
    for (const w of warnings) if (!allWarnings.some((x) => x.kind === w.kind && x.networkKey === w.networkKey)) allWarnings.push(w);
  }
  if (allWarnings.length === 0) return null;
  const list = allWarnings.slice(0, 3).map((w) => w.message).join(' ');
  return `Network overlap check blocked this rollout (strict mode): ${list} — change the network or set "Rollout overlap mode" to "warn" in Settings.`;
}
