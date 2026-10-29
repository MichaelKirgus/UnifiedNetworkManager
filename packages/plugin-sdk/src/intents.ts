/**
 * Canonical fleet intents — the cross-vendor abstraction layer for rolling out
 * whole networks (VLANs, optionally with a WLAN SSID) across a site or tag.
 *
 * The idea: one INTENT ("create network XY with VLAN 42 on every router at
 * site H") maps to ONE canonical action id + input schema per vendor plugin.
 * Each plugin implements the intent against its own config surface (LCOS CLI
 * tables, OPNsense staged API, RouterOS API, …) under the SAME id and a
 * COMPATIBLE subset of this schema, so:
 *   - the UNM plan machinery fans the intent out per device unchanged
 *     (POST /plans with devices[] — one step per device),
 *   - the webapp's Network Rollout dialog can target a site/tag once and let
 *     every router plugin that implements the intent pick it up,
 *   - later tunnel intents (WireGuard/IPsec/OpenSSL) reuse the same pattern.
 *
 * A plugin MAY implement only a subset of an intent's optional fields — its
 * catalog entry advertises exactly what it supports via its own inputSchema
 * (validated per-plugin at plan time). The canonical schemas below are the
 * SUPERSET contract; `canonicalIntentIds` is the registry of known intents.
 *
 * Human reference: docs/INTENTS.md — field contracts, naming conventions,
 * implementation matrix and documented deviations. Keep both in sync.
 */

import type { InputSchema } from './types';

/** Canonical intent ids every router plugin SHOULD implement for fleet rollout. */
export const INTENT_NETWORK_CREATE = 'network.create' as const;
export const INTENT_NETWORK_DELETE = 'network.delete' as const;
// Reserved for the tunnel-abstraction round (WireGuard/IPsec/OpenSSL):
//   INTENT_TUNNEL_CREATE = 'tunnel.create', INTENT_TUNNEL_DELETE = 'tunnel.delete'.

/**
 * Canonical intent ids for static DNS host entries (hostname → IP) — the
 * cross-vendor abstraction behind UNM's DNS page: one entry rolled out to every
 * device that keeps a local hosts table (OPNsense dnsmasq/unbound, OpenWrt UCI
 * `dhcp` host sections, RouterOS `/ip/dns/static`, LCOS `Setup/DNS/DNS-List`).
 */
export const INTENT_DNS_SET = 'dns.set' as const;
export const INTENT_DNS_DELETE = 'dns.delete' as const;
/** Rename a static DNS entry in place — every address (and any per-record
 * domain/description) of the old name moves to the new name. */
export const INTENT_DNS_RENAME = 'dns.rename' as const;

/**
 * Canonical intent ids for container image management — the cross-vendor
 * abstraction behind UNM's Containers page: point one or more containers at a
 * different image (a tag bump like `app:v1.4.2` → `app:v1.4.3`, or a whole new
 * image like switching redis providers). Implemented by every plugin that can
 * drive docker workloads (generic Docker Engine API, TrueNAS SCALE apps).
 */
export const INTENT_CONTAINERS_IMAGE_SET = 'containers.image.set' as const;

/** All canonical intent ids, in rollout order. */
export const CANONICAL_INTENTS: readonly string[] = [INTENT_NETWORK_CREATE, INTENT_NETWORK_DELETE, INTENT_DNS_SET, INTENT_DNS_DELETE, INTENT_DNS_RENAME, INTENT_CONTAINERS_IMAGE_SET];

// ---------------------------------------------------------------------------
// L2 topology — the cross-vendor abstraction for interface layering
// ---------------------------------------------------------------------------
/**
 * Canonical READ-ONLY action id for a device's L2 interface hierarchy.
 *
 * Routers layer interfaces in vendor-specific ways (LCOS: ETH-x → LAN-x /
 * BUNDLE-x(LACP) → BRG-x bridges; OPNsense: re0..reN + lagg + vlan; RouterOS:
 * ether → bridge/bonding/vrrp). Fleet intents that attach a network to an
 * interface (`network.create.interface`) must RESOLVE the right layer per
 * device — never hardcode a port. Plugins SHOULD implement this read action so
 * preflight resolvers (and future topology views) can see: which physical
 * ports exist, how they map onto logical interfaces, which bridges/bundles
 * group them, and which interface already carries L3 networks.
 */
export const INTENT_L2_TOPOLOGY_READ = 'l2.topology.read' as const;

/** One physical port of a device (e.g. ETH-1, WAN, SFP-1). */
export interface L2PhysicalPort {
  /** Vendor-local name (e.g. "ETH-4", "WAN"). */
  name: string;
  /** The logical interface this port is assigned to (null = idle/unassigned). */
  assignment: string | null;
  /**
   * Whether the port currently carries traffic for MORE than one VLAN
   * (trunk/uplink semantics). Optional — platforms without a per-port VLAN
   * concept (plain hosts, appliances) omit it. The rollout dialog uses this
   * to offer "Trunk ports only" as a quick select.
   */
  trunk?: boolean;
  /** Untagged default VLAN id of the port (PVID), when the platform reports one. */
  pvid?: number | null;
  /** All VLAN ids this port carries (tagged + untagged), when known. */
  vlans?: number[];
}

/** One bridge group — a layer-2 domain that can carry networks/VLANs. */
export interface L2Bridge {
  /** Vendor-local name (e.g. "BRG-2"). */
  name: string;
  /** Logical interfaces bridged into this group (member ports, bundles, radios…). */
  members: string[];
}

/** One link-aggregation bundle (LACP/802.3ad or static). */
export interface L2Bundle {
  /** Vendor-local name (e.g. "BUNDLE-1"). */
  name: string;
  /** Protocol label ("LACP", "static", …) when known. */
  protocol?: string | null;
  /** Member logical interfaces (e.g. ["LAN-1","LAN-2"]). */
  members: string[];
  /** Whether the bundle is currently operating (false = configured but inactive). Unknown → undefined/null. */
  operating?: boolean | null;
}

/** The full L2 hierarchy of one device — the result of `l2.topology.read`. */
export interface L2Topology {
  physicalPorts: L2PhysicalPort[];
  bridges: L2Bridge[];
  bundles: L2Bundle[];
  /** Logical interfaces that carry an L3 network (interface → network names; several networks may share one ifc). */
  l3Interfaces?: Record<string, string[]>;
  /**
   * Uplink / WAN interfaces — NEVER valid attach points for a new network.
   * Attaching a test or secondary address to the uplink can break the device's
   * own connectivity (and thus the management path). Vendors that know which
   * of their L3-carrying interfaces is the uplink SHOULD list them here so
   * `suggestL2AttachPoint` skips them.
   */
  uplinks?: string[];
}

/**
 * Suggests the best-guess ATTACH POINT for a new network on one device — the
 * single interface a plugin should bind the L3 address to. Preference order is
 * vendor-specific but generally: the bridge carrying existing LAN networks >
 * a bundle carrying them > a plain port carrying them directly > any configured
 * bridge > an active bundle > the first assigned physical port. Returned by
 * preflight resolvers as the suggested `interface` value (with confidence + note).
 */
export function suggestL2AttachPoint(topo: L2Topology, preferred?: string): { attach: string; reason: string } | null {
  if (!topo || (topo.bridges.length === 0 && topo.bundles.length === 0 && Object.keys(topo.l3Interfaces ?? {}).length === 0)) return null;
  const l3 = topo.l3Interfaces ?? {};
  // Uplinks/WAN are never valid attach points — attaching a new address to the
  // uplink can break the device's own connectivity (and the management path).
  const uplinks = new Set(topo.uplinks ?? []);
  // 1. A bridge that already carries L3 networks — the device's main LAN domain.
  //    On LCOS the L3 address binds to the BRIDGE itself (NET_LIST Interface =
  //    BRG-x), so check the bridge name AND its members; other vendors may bind
  //    a member ifc instead.
  for (const b of topo.bridges) {
    const nets = [...new Set([b.name, ...b.members].flatMap((ifc) => l3[ifc] ?? []))];
    if (nets.length > 0) return { attach: b.name, reason: `bridge ${b.name} carries existing L3 networks (${nets.join(', ')})` };
  }
  // 2. A bundle that already carries L3 networks.
  for (const bu of topo.bundles) {
    const nets = l3[bu.name] ?? [];
    if (nets.length > 0) return { attach: bu.name, reason: `bundle ${bu.name} (${(bu.protocol ?? 'LACP').toLowerCase()}) carries existing L3 networks (${nets.join(', ')})` };
  }
  // 3. A plain interface directly carrying L3 networks — no bridge in front of
  //    it and not part of an ACTIVE bundle (a port inside a configured-but-
  //    inactive bundle is just a standalone port; LCOS-verified: WLC01 carries
  //    its LAN on LAN-1 while BUNDLE-1 over it has Operating=No).
  const inActiveAgg = (ifc: string) =>
    topo.bridges.some((b) => b.name === ifc || b.members.includes(ifc)) ||
    topo.bundles.some((bu) => bu.operating !== false && (bu.name === ifc || bu.members.includes(ifc)));
  const direct = Object.entries(topo.l3Interfaces ?? {})
    .filter(([ifc]) => !inActiveAgg(ifc) && !uplinks.has(ifc))
    .sort((a, b) => b[1].length - a[1].length || a[0].localeCompare(b[0]));
  if (direct.length > 0) {
    const [ifc, names] = direct[0];
    return { attach: ifc, reason: `interface ${ifc} carries existing L3 networks (${names.join(', ')})` };
  }
  // 4. Any bridge with members at all (a configured LAN domain).
  for (const b of topo.bridges) {
    if (b.members.length > 0) return { attach: b.name, reason: `bridge ${b.name} is the only configured L2 domain (${b.members.join(', ')})` };
  }
  // 5. An active bundle (operating when the vendor reports it).
  const active = topo.bundles.filter((bu) => bu.members.length > 0 && bu.operating !== false);
  if (active.length > 0) return { attach: active[0].name, reason: `bundle ${active[0].name} (${(active[0].protocol ?? 'LACP').toLowerCase()}) aggregates ${active[0].members.join(', ')}` };
  // 6. Caller's preference or the first physical assignment (never an uplink).
  if (preferred && !uplinks.has(preferred) && topo.physicalPorts.some((p) => p.assignment === preferred)) return { attach: preferred, reason: `requested interface ${preferred} exists on this device` };
  const first = topo.physicalPorts.find((p) => p.assignment && !uplinks.has(p.assignment));
  if (first?.assignment) return { attach: first.assignment, reason: `no bridges/bundles configured — using assigned port ${first.assignment}` };
  return null;
}

/**
 * Suggests the L2 member-port list for a new VLAN network on the given attach
 * point. Convention (LCOS-verified): copy the Ports list of an EXISTING VLAN
 * network whose L3 ifc sits in the same bridge — that is how the device's LAN
 * segment is tagged today. Falls back to the bridge's physical/bundle members,
 * then to the attach point itself.
 */
export function suggestL2VlanPorts(
  topo: L2Topology,
  attach: string,
  existingVlanNetworks: Array<{ name: string; ports: string[] }>,
): string[] {
  const bridge = topo.bridges.find((b) => b.name === attach);
  if (bridge) {
    // The L3 ifcs that belong to this bridge domain (the bridge itself + members).
    const inBridge = new Set([attach, ...bridge.members]);
    // Invert l3Interfaces (ifc → network names) into network name → ifc.
    const l3ByNetwork: Record<string, string> = {};
    for (const [ifc, names] of Object.entries(topo.l3Interfaces ?? {})) for (const n of names) l3ByNetwork[n] = ifc;
    for (const net of existingVlanNetworks) {
      const ifc = l3ByNetwork[net.name];
      if (ifc && inBridge.has(ifc) && net.ports.length > 0) return [...net.ports];
    }
    // No existing VLAN networks on this bridge — use its physical/bundle members.
    const members = bridge.members.filter((m) => /^(LAN-\d+|BUNDLE-\d+)$/i.test(m));
    if (members.length > 0) return members;
  }
  return [attach];
}

/** True when an action id is a canonical fleet intent (plugins implement them). */
export function isCanonicalIntent(id: string): boolean {
  return (CANONICAL_INTENTS as readonly string[]).includes(id);
}

/**
 * Resolves the trunk status of one physical port from an L2 topology.
 *
 * Preference order:
 *   1. The platform's own flag (`port.trunk`) when present — exact data wins.
 *   2. Generic inference: a port is a trunk when it carries >1 VLAN
 *      (`port.vlans.length > 1`) OR its assignment sits in more than one
 *      bridge/bundle group (a member of several L2 domains).
 *
 * Used by preflight resolvers that have per-port data but did not set the
 * explicit flag, and as a fallback for UIs rendering port chips.
 */
export function portTrunkStatus(topo: L2Topology, portName: string): { trunk: boolean; pvid?: number | null; vlans: number[] } {
  const port = topo.physicalPorts.find((p) => p.name === portName);
  if (!port) return { trunk: false, vlans: [] };
  if (typeof port.trunk === 'boolean') return { trunk: port.trunk, pvid: port.pvid ?? null, vlans: port.vlans ?? [] };
  const vlans = port.vlans ?? [];
  // Generic inference from group membership: count distinct bridges/bundles
  // whose members include this port's assignment (or the port name itself).
  const candidates = new Set<string>([port.name]);
  if (port.assignment) candidates.add(port.assignment);
  let groups = 0;
  for (const b of topo.bridges) {
    if ([...candidates].some((c) => c === b.name || b.members.includes(c))) groups += 1;
  }
  for (const bu of topo.bundles) {
    if ([...candidates].some((c) => c === bu.name || bu.members.includes(c))) groups += 1;
  }
  return { trunk: vlans.length > 1 || groups > 1, pvid: port.pvid ?? null, vlans };
}

// ---------------------------------------------------------------------------
// network.create — "create Network XY with VLAN ID on all devices" (+ optional SSID)
// ---------------------------------------------------------------------------

/**
 * Canonical input schema for `network.create`. Every field except `name` is
 * optional so a plugin can advertise the subset it supports:
 *   - LCOS: name, vlanId?, cidr, cidrV6, interface, vlanPorts?, dhcpPool{start,end}, ssid{name}
 *     (no vlanId → no dedicated L2 VLAN row; L3/DHCP bind to default VLAN 1)
 *   - OPNsense: name, vlanId (→ staged vlan.add + reconfigure)
 * `cidr` is the IPv4 L3 address as CIDR — the ONLY v4 form. `cidrV6` is the
 * DUAL-STACK half: an optional IPv6 CIDR that rides alongside `cidr`
 * (both set = dual-stack). A rollout must provide at least one of
 * vlanId / cidr / cidrV6 / ssid so there is something to create.
 *
 * ATTACH POINTS — vendors layer interfaces differently, and the L3 address
 * often sits on a DIFFERENT interface than the VLAN tagging:
 *   - `interface` = where the L3 address (v4/v6) binds — the single
 *     "attach point". On LCOS this is usually a BRIDGE (BRG-x) or BUNDLE,
 *     NOT a physical port. Plugins MUST resolve it per device in preflight
 *     (see INTENT_L2_TOPOLOGY_READ / suggestL2AttachPoint) instead of
 *     hardcoding; the user can override per device.
 *   - `vlanPorts` = optional explicit list of logical ports that carry the
 *     VLAN tag at L2 (LCOS: VLAN/Networks.Ports). When omitted, a plugin uses
 *     its own convention (e.g. LCOS copies the member-port list of existing
 *     VLAN networks on the same bridge).
 */
export const NETWORK_CREATE_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name (unique per device)' },
  vlanId: { type: 'number', min: 1, max: 4094, description: 'VLAN ID to create/attach (optional — omit for an L3-only network on the default VLAN)' },
  cidr: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}/\\d{1,2}$', description: 'L3 address as CIDR (e.g. 10.42.0.1/24)' },
  cidrV6: { type: 'string', pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*/\\d{1,3}$', description: 'Optional IPv6 L3 address as CIDR (e.g. fd00:42::1/64) — dual-stack when set alongside cidr' },
  interface: { type: 'string', maxLength: 64, description: 'L3 attach point — the device-local interface to bind the address to (bridge/bundle/port; resolved per device in preflight)' },
  vlanPorts: { type: 'array', items: { type: 'string' }, description: 'Optional explicit list of logical ports carrying the VLAN tag at L2 (e.g. ["LAN-1","LAN-2"]); plugin convention applies when omitted' },
  dhcpPool: {
    type: 'object',
    description: 'Optional DHCP pool served on this network',
    properties: {
      start: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
      end: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$' },
    },
  },
  ssid: {
    type: 'object',
    description: 'Optional WLAN SSID to expose this network on (devices with local radios only)',
    properties: {
      name: { type: 'string', required: true, minLength: 1, maxLength: 32, description: 'Broadcast SSID name' },
      slot: { type: 'string', description: 'Device-local radio slot to use (vendor-specific; auto-picked when omitted)' },
    },
  },
};

// ---------------------------------------------------------------------------
// network.delete — "remove Network XY from all devices"
// ---------------------------------------------------------------------------

/** Canonical input schema for `network.delete` (name-addressed, idempotent). */
export const NETWORK_DELETE_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 64, description: 'Network name to remove' },
};

// ---------------------------------------------------------------------------
// dns.set / dns.delete — "add/remove static DNS entry NAME → IP on all devices"
// ---------------------------------------------------------------------------

/**
 * Canonical input schema for `dns.set` (idempotent upsert). Vendors keep the
 * entry in different places but all address it by hostname: OPNsense dnsmasq
 * host records / unbound local-zone overrides, OpenWrt UCI `dhcp` `@host`/`@map`
 * sections, RouterOS `/ip/dns/static`, LCOS `Setup/DNS/DNS-List`. A plugin that
 * already has the name with a DIFFERENT address updates it in place.
 */
export const DNS_SET_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'Hostname (RFC 1123; stored lowercase by UNM)' },
  ip: { type: 'string', required: true, pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'IPv4 or IPv6 address the hostname resolves to (record type A/AAAA is derived from the address shape)' },
  ipv6: { type: 'string', required: false, pattern: '^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional second family — write BOTH v4 and v6 into one entry (LCOS DNS-List dual row). Vendors without a per-name multi-address model ignore it.' },
  domain: { type: 'string', required: false, maxLength: 253, description: 'Optional domain suffix. Only vendors that split a record into bare-hostname + domain persist it (OPNsense unbound); other plugins ignore it.' },
  description: { type: 'string', required: false, maxLength: 255, description: 'Optional free-text note for the entry. Only vendors with a native field persist it (RouterOS /ip/dns/static `comment`, OPNsense unbound); other plugins ignore it.' },
};

/** Canonical input schema for `dns.delete` (name-addressed, idempotent). */
export const DNS_DELETE_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'Hostname to remove' },
  ip: { type: 'string', pattern: '^\\d{1,3}(\\.\\d{1,3}){3}$|^[0-9a-fA-F:.]*:[0-9a-fA-F:.]*$', description: 'Optional — when the name maps to several addresses, remove only this one' },
  description: { type: 'string', required: false, maxLength: 255, description: 'Optional — accepted for contract symmetry; deletion is by name(+ip) and never matches on the note.' },
};

/**
 * Canonical input schema for `dns.rename` (name-addressed, idempotent). Renames
 * a static DNS entry IN PLACE: every address of the old name moves to the new
 * name, preserving per-record data the vendor stores alongside it (OPNsense
 * unbound domain + description, RouterOS comment, LCOS dual v4+v6 row). A
 * plugin that already holds `newName` with a different address reports an error
 * rather than merging — the caller must delete or rename that entry first.
 */
export const DNS_RENAME_SCHEMA: InputSchema = {
  name: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'Current hostname to rename (stored lowercase by UNM)' },
  newName: { type: 'string', required: true, minLength: 1, maxLength: 253, description: 'New hostname for the entry' },
};

// ---------------------------------------------------------------------------
// containers.image.set — "point these containers at a different image"
// ---------------------------------------------------------------------------

/**
 * Canonical input schema for `containers.image.set`. One step targets ONE device
 * and carries every mapping that applies to it (the webapp groups its selection
 * per device). Each mapping is matched by the container's CURRENT image ref:
 *   - `from` = the exact ref the container runs today (e.g. "ghcr.io/x/app:v1.4.2")
 *   - `to`   = the new full ref — a tag bump ("…/app:v1.4.3"), a different tag
 *     of the same repo, or an entirely different image ("redis:7" → "valkey:8").
 *   - `name` = optional container/service name to scope the match (a multi-service
 *     app may run several images; omit it to hit every service using `from`).
 * Idempotent by contract: a container already running `to` is skipped, not failed.
 * Vendors implement this natively — TrueNAS rewrites the app's compose config and
 * redeploys (catalog apps are skipped with a note), bare Docker recreates the
 * container via the Engine API preserving its full configuration.
 */
export const CONTAINER_IMAGE_SET_SCHEMA: InputSchema = {
  mappings: {
    type: 'array',
    required: true,
    items: {
      type: 'object',
      properties: {
        name: { type: 'string', required: false, minLength: 1, maxLength: 200, description: 'Optional container/service name to scope the match (omit = every service using `from`)' },
        from: { type: 'string', required: true, minLength: 2, maxLength: 512, description: 'Current image reference of the container(s) to change (exact ref as reported in inventory)' },
        to: { type: 'string', required: true, minLength: 2, maxLength: 512, description: 'New full image reference (tag bump or a different image entirely)' },
      },
    },
    description: 'Image changes to apply on this device — one entry per container/service',
  },
};

/** Canonical intent → input schema lookup (the superset contract). */
export const CANONICAL_INTENT_SCHEMAS: Record<string, InputSchema> = {
  [INTENT_NETWORK_CREATE]: NETWORK_CREATE_SCHEMA,
  [INTENT_NETWORK_DELETE]: NETWORK_DELETE_SCHEMA,
  [INTENT_DNS_SET]: DNS_SET_SCHEMA,
  [INTENT_DNS_DELETE]: DNS_DELETE_SCHEMA,
  [INTENT_DNS_RENAME]: DNS_RENAME_SCHEMA,
  [INTENT_CONTAINERS_IMAGE_SET]: CONTAINER_IMAGE_SET_SCHEMA,
};

// ---------------------------------------------------------------------------
// Preflight — per-device best-guess resolution (the "smart" half of rollout)
// ---------------------------------------------------------------------------
/**
 * The canonical PREFLIGHT contract. Before a fleet intent is planned, the webapp
 * asks every supporting plugin to RESOLVE best-guess values for each target
 * device against its live state — so the user sees and confirms concrete,
 * per-device settings (which interface carries the VLAN on THIS router, which
 * L3 address fits, which SSID slot is free) instead of one generic field.
 *
 * Transport: POST /preflight on the plugin with { intentActionId, device } —
 * the SAME body shape as a single-device step dispatch (host + full credentials
 * incl. bound slots), so resolvers may do READ-ONLY live probes (SNMP walks,
 * CLI `dir`). Resolvers MUST NOT write anything; they return suggestions only.
 *
 * The result is deliberately GENERIC: `values` carries the suggested input
 * fields (a subset of the intent's input schema, keyed by the SAME names —
 * e.g. `interface`, `cidr`, `dhcpPool`, `ssid.slot`) and each field gets a
 * confidence + human note so the UI can show WHY a value was chosen and how
 * sure the plugin is. The webapp renders values generically (string/number/
 * object) and lets the user override any of them; overrides ride back in
 * PlanRequest.deviceInputs.
 */
export type PreflightConfidence = 'high' | 'medium' | 'low';

/** One suggested input field for one device. */
export interface PreflightValue {
  /** The intent input key this value fills (e.g. `interface`, `cidr`). */
  key: string;
  /** Suggested value — same shape as the corresponding intent input field. */
  value: unknown;
  /** How confident the resolver is in this suggestion. */
  confidence: PreflightConfidence;
  /** Human explanation (e.g. "only LAN-1 exists on this device", "row already present — left untouched"). */
  note?: string;
}

/** One physical port entry returned by a preflight resolver for port selection. */
export interface PreflightPort {
  /** Vendor-local port name (the value that goes into `vlanPorts`). */
  name: string;
  /** Whether the port is currently a trunk/uplink (carries >1 VLAN). */
  trunk?: boolean;
  /** Untagged default VLAN id, when known. */
  pvid?: number | null;
}

/** One candidate interface for the `interface` input of network.create. */
export interface PreflightInterfaceOption {
  /** The value that goes into the intent's `interface` input (e.g. `eth1`, `br-lan`, `bond0`). */
  name: string;
  /** What kind of interface it is — drives grouping/labels in the UI. */
  kind?: 'physical' | 'bridge' | 'bundle' | 'vlan';
  /** Short human hint (e.g. "uplink to ISP", "LAN bridge"). */
  note?: string;
}

/** Capability flags a preflight resolver may advertise for one device. */
export interface PreflightCapabilities {
  /** The plugin can assign the new VLAN to an explicit list of ports (`vlanPorts` input). */
  vlanPorts?: boolean;
}

/** The preflight result for ONE device of ONE plugin. */
export interface PreflightResult {
  deviceId: string;
  /** Suggested input fields (merged over the shared intent inputs at plan time). */
  values: PreflightValue[];
  /** True when the resolver could not inspect the device (offline, no creds…). */
  degraded?: boolean;
  /** Why it is degraded (shown in the UI; the device can still be planned with defaults). */
  error?: string;
  /**
   * The device's physical ports with trunk status — lets the rollout dialog
   * offer "All / Trunk only / Select ports" quick selects WITHOUT a separate
   * topology round-trip. Only present for intents that touch ports (network.create).
   */
  ports?: PreflightPort[];
  /**
   * Candidate interfaces for the `interface` input — physical NICs, bridges,
   * LAG/bond bundles (and VLAN sub-interfaces where relevant). Lets the rollout
   * dialog offer a dropdown instead of free text on multi-NIC devices. Only
   * present when the resolver could enumerate them.
   */
  interfaces?: PreflightInterfaceOption[];
  /** What this device supports for the intent (e.g. explicit port lists). */
  capabilities?: PreflightCapabilities;
}

/** Body of POST /preflight on a plugin. */
export interface PreflightRequest {
  intentActionId: string;
  /** The shared intent inputs the user entered (name, vlanId, …) — resolvers use them to tailor suggestions. */
  inputs?: Record<string, unknown>;
  device: { deviceId: string; managementAddress: string; credentials: Record<string, unknown> };
}
