import { forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationNodeDatum } from 'd3-force';
import type { Edge as FlowEdge, Node as FlowNode } from '@xyflow/react';
import type { TopologyEdge as TopoEdge, TopologyNode as TopoNode } from '../../api/client';

/**
 * Force-directed layout for the TOPOLOGY "Hosts" view — every known host as a
 * dot in a net around its segment hub(s), with WLAN clients visibly attached
 * to their AP and switches/APs (the devices that bridge the VLANs) fanned out
 * beside their busiest segment. Deterministic: hubs/satellites are pinned to
 * computed anchors and all initial positions are index-derived (no
 * Math.random), so refetches at the same data produce the same picture
 * instead of reshuffling.
 *
 * Node set is capped (MAX_HOSTS) — ranked by traffic when the overlay has
 * bytes, otherwise in server order (newest-first per segment). The caller
 * shows a "showing N of M" note from the returned counts.
 */

/** Total host cap for the net view (plan: ~200 top-N by traffic). */
export const MAX_HOSTS = 200;

const HUB_R = 34; // hub anchor radius (px) — matches HubNode's 68px circle
const MINI_HUB_R = 20; // empty-segment mini-hub (40px dashed ring)
const AP_R = 26;
const SWITCH_R = 24;
const HOST_MIN_R = 10;
const HOST_MAX_R = 26;
// Cell spacing must exceed a busy hub's host-cloud diameter (~50 hosts spiral
// out to ~200 px + collision spread) or neighboring clouds overlap.
const GRID_X = 640; // horizontal spacing between hub anchors
const GRID_Y = 580;

interface SimNode extends SimulationNodeDatum {
  id: string;
  r: number;
}
interface SimLink {
  source: string | SimNode;
  target: string | SimNode;
  dist: number;
  str: number;
}

export interface HostsNetInput {
  nodes: TopoNode[];
  edges: TopoEdge[];
  /** Original host id → estimated bytes (traffic overlay); ranks the cap + sizes dots. */
  hostBytes?: Map<string, number>;
  /** Focus a single segment (`segment:<key>`), like the logical view's select. */
  segmentFilter?: string;
}

export interface HostsNetResult {
  rfNodes: FlowNode[];
  rfEdges: FlowEdge[];
  totalHosts: number;
  shownHosts: number;
  /** True when the cap ranking used traffic bytes (else server order). */
  rankedByTraffic: boolean;
}

export function layoutHostsNet(input: HostsNetInput): HostsNetResult {
  const allHosts = input.nodes.filter((n): n is TopoNode & { kind: 'host' } => n.kind === 'host');
  const segments = input.nodes.filter((n): n is TopoNode & { kind: 'segment' } => n.kind === 'segment');
  const devices = new Map(input.nodes.filter((n): n is TopoNode & { kind: 'device' } => n.kind === 'device').map((d) => [d.id, d]));

  // --- Cap the host set ------------------------------------------------------
  let rankedByTraffic = false;
  let hosts = allHosts;
  if (allHosts.length > MAX_HOSTS) {
    const hasBytes = input.hostBytes && [...input.hostBytes.values()].some((b) => b > 0);
    if (hasBytes) {
      rankedByTraffic = true;
      hosts = [...hosts].sort((a, b) => (input.hostBytes!.get(b.id) ?? 0) - (input.hostBytes!.get(a.id) ?? 0));
    }
    hosts = hosts.slice(0, MAX_HOSTS);
  }
  const keptHostIds = new Set(hosts.map((h) => h.id));

  // --- Keep the edges that touch kept hosts ----------------------------------
  const membershipEdges = input.edges.filter((e) => e.kind === 'membership' && keptHostIds.has(e.source));
  const wirelessEdges = input.edges.filter((e) => e.kind === 'wireless' && keptHostIds.has(e.target));

  // Device→segment membership (switches/routers bridging VLANs). Read from the
  // RAW input — `membershipEdges` above is filtered to HOST sources only.
  const devSegs = new Map<string, string[]>();
  for (const e of input.edges) {
    if (e.kind !== 'membership' || !e.source.startsWith('device:')) continue;
    let list = devSegs.get(e.source);
    if (!list) {
      list = [];
      devSegs.set(e.source, list);
    }
    list.push(e.target);
  }

  // Hubs: every segment in the grid — including EMPTY ones (no visible host),
  // rendered as a compact dashed mini-hub. A segment qualifies when it has a
  // visible member host OR at least one bridging device, so "this VLAN exists
  // but no visible hosts" stays readable instead of vanishing from the grid.
  let keptSegs = new Set(membershipEdges.map((e) => e.target));
  for (const list of devSegs.values()) for (const s of list) keptSegs.add(s);
  if (input.segmentFilter) {
    keptSegs = input.segmentFilter === 'all' ? keptSegs : new Set([input.segmentFilter].filter((s) => segments.some((x) => x.id === s)));
  }
  const hubs = segments.filter((s) => keptSegs.has(s.id));
  const hubIds = new Set(hubs.map((h) => h.id));

  // Re-filter edges to the visible hubs (a kept host may belong to a dropped one).
  const visMembership = membershipEdges.filter((e) => hubIds.has(e.target));
  const hostsInView = new Set(visMembership.map((e) => e.source));
  // Hosts with ANY segment membership at all — WLAN-only clients (none) stay
  // visible via their AP link even when every one of the AP's segments is filtered out.
  const anyMembershipHosts = new Set(membershipEdges.map((e) => e.source));
  const visWireless = wirelessEdges.filter(
    (e) => devices.has(e.source) && (hostsInView.has(e.target) || !anyMembershipHosts.has(e.target))
  );

  // APs: devices that own a kept wireless edge.
  const apIds = new Set(visWireless.map((e) => e.source));

  if (hubs.length === 0 || hostsInView.size + apIds.size === 0) {
    return { rfNodes: [], rfEdges: [], totalHosts: allHosts.length, shownHosts: 0, rankedByTraffic };
  }

  // --- Deterministic anchors --------------------------------------------------
  // Hubs sit on a grid in VLAN order (numeric ascending; no-VLAN segments by
  // label after them). Content-based clustering was tried and failed: real
  // inventories have multi-homed hosts everywhere, so "shares ≥1 host" chains
  // almost every segment into ONE giant cluster whose ring crams all hubs —
  // and their host clouds — into a single blob. VLAN order is predictable and
  // matches intuition: VLAN 30 beside VLAN 29/31, not beside VLAN 210.
  const hostsBySeg = new Map<string, Set<string>>();
  for (const e of visMembership) {
    let s = hostsBySeg.get(e.target);
    if (!s) {
      s = new Set();
      hostsBySeg.set(e.target, s);
    }
    s.add(e.source);
  }
  const hubSize = (id: string) => hostsBySeg.get(id)?.size ?? 0;
  const ordered = [...hubs].sort((a, b) => {
    const av = a.vlanId ?? Number.MAX_SAFE_INTEGER;
    const bv = b.vlanId ?? Number.MAX_SAFE_INTEGER;
    return av - bv || a.label.localeCompare(b.label);
  });
  const cols = Math.max(1, Math.ceil(Math.sqrt(ordered.length)));
  const rows = Math.max(1, Math.ceil(ordered.length / cols));
  const anchor = new Map<string, { x: number; y: number }>();
  ordered.forEach((h, i) => {
    const col = i % cols;
    const row = Math.floor(i / cols);
    anchor.set(h.id, { x: (col - (cols - 1) / 2) * GRID_X, y: (row - (rows - 1) / 2) * GRID_Y });
  });

  // --- Switches / APs as satellites ------------------------------------------
  // Each bridging device is drawn ONCE — a compact card fanned beside its
  // busiest segment (most visible member hosts) — with faint lines to every
  // VISIBLE hub it belongs to, so "which switch carries which VLANs" stays
  // readable without a hairball.
  const visDevSegs = new Map<string, string[]>();
  for (const [id, list] of devSegs) {
    if (!devices.has(id)) continue;
    const vis = list.filter((s) => hubIds.has(s));
    if (vis.length > 0) visDevSegs.set(id, vis);
  }
  // Primary hub per device — most visible member hosts (ties → first).
  const satPrimary = new Map<string, string>();
  for (const [id, list] of visDevSegs) {
    let best: { seg: string; n: number } | null = null;
    for (const s of list) {
      const n = hubSize(s);
      if (!best || n > best.n) best = { seg: s, n };
    }
    satPrimary.set(id, best?.seg ?? hubs[0]!.id);
  }
  // APs without any membership (pure WLAN-only access points) still get a
  // satellite slot at the first hub — their dashed client links need an anchor.
  for (const id of apIds) if (!satPrimary.has(id)) satPrimary.set(id, hubs[0]!.id);
  const satelliteIds = [...satPrimary.keys()];
  const satsByHub = new Map<string, string[]>();
  for (const [id, segId] of satPrimary) {
    let list = satsByHub.get(segId);
    if (!list) {
      list = [];
      satsByHub.set(segId, list);
    }
    list.push(id);
  }
  // Satellite anchors — a deterministic fan ABOVE their primary hub (APs and
  // switches share the same ring so they never overlap).
  for (const [segId, list] of satsByHub) {
    const a = anchor.get(segId)!;
    list.forEach((id, j) => {
      const ang = (j - (list.length - 1) / 2) * 0.9 - Math.PI / 2; // fan above the hub
      anchor.set(id, { x: a.x + Math.cos(ang) * 230, y: a.y + Math.sin(ang) * 230 });
    });
  }

  // --- Simulation nodes --------------------------------------------------------
  const simNodes: SimNode[] = [
    ...hubs.map((h): SimNode => ({ id: h.id, r: hubSize(h.id) > 0 ? HUB_R : MINI_HUB_R, x: anchor.get(h.id)!.x, y: anchor.get(h.id)!.y, fx: anchor.get(h.id)!.x, fy: anchor.get(h.id)!.y })),
    ...satelliteIds.map((id): SimNode => ({ id, r: apIds.has(id) ? AP_R : SWITCH_R, x: anchor.get(id)!.x, y: anchor.get(id)!.y, fx: anchor.get(id)!.x, fy: anchor.get(id)!.y })),
  ];

  // Host initial positions — golden-angle spiral around their hub so the first
  // ticks start from a spread-out (not exploded) state. Radius by traffic when
  // available (busy hosts get room), uniform otherwise.
  const hostRadius = new Map<string, number>();
  let maxBytes = 0;
  for (const h of allHosts) {
    const b = input.hostBytes?.get(h.id) ?? 0;
    if (b > maxBytes) maxBytes = b;
  }
  // PRIMARY hub per host — the visible segment with the MOST members (ties →
  // first). One spoke per host: multi-segment hosts no longer drag lines
  // across the whole canvas, which is what made the net read as a hairball.
  // WLAN-only clients have NO membership → null (they anchor at their AP and
  // get no fake cross-canvas spoke).
  const primaryHub = new Map<string, string | null>();
  for (const h of hosts) {
    let best: { seg: string; n: number } | null = null;
    for (const m of visMembership) {
      if (m.source !== h.id) continue;
      const n = hubSize(m.target);
      if (!best || n > best.n) best = { seg: m.target, n };
    }
    primaryHub.set(h.id, best?.seg ?? null);
  }

  const perHubIndex = new Map<string, number>();
  for (const h of hosts) {
    // WLAN-only clients anchor at their AP; everyone else at their primary hub.
    let refId = primaryHub.get(h.id) ?? visWireless.find((w) => w.target === h.id)?.source ?? hubs[0]!.id;
    if (!anchor.has(refId)) refId = hubs[0]!.id;
    const i = perHubIndex.get(refId) ?? 0;
    perHubIndex.set(refId, i + 1);
    const a = i * 2.39996323; // golden angle (rad)
    const r = 46 + 20 * Math.sqrt(i);
    const p = anchor.get(refId)!;
    const b = input.hostBytes?.get(h.id) ?? 0;
    const t = maxBytes > 0 && b > 0 ? Math.sqrt(b / maxBytes) : 0;
    hostRadius.set(h.id, HOST_MIN_R + (HOST_MAX_R - HOST_MIN_R) * t);
    simNodes.push({ id: h.id, r: hostRadius.get(h.id)!, x: p.x + Math.cos(a) * r, y: p.y + Math.sin(a) * r });
  }

  const simLinks: SimLink[] = [
    // Primary spokes only — the simulation tethers each host to ONE hub.
    ...[...primaryHub.entries()].filter(([, seg]) => seg !== null).map(([hostId, seg]): SimLink => ({ source: hostId, target: seg!, dist: HUB_R + 78, str: 0.1 })),
    // Satellites tether to their primary hub only (pinned anyway — keeps the
    // fan stable between refetches).
    ...satelliteIds.map((id): SimLink => ({ source: id, target: satPrimary.get(id)!, dist: HUB_R + 90, str: 0.1 })),
    ...visWireless.map((e): SimLink => ({ source: e.source, target: e.target, dist: AP_R + 56, str: 0.12 })),
  ];

  // Hubs/APs are pinned (fx/fy) — only hosts move, so the net converges fast
  // and stays anchored to the grid between refetches.
  const sim = forceSimulation<SimNode>(simNodes)
    .force('link', forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance((l) => l.dist).strength((l) => l.str))
    .force('charge', forceManyBody().strength(-70))
    .force('collide', forceCollide<SimNode>().radius((d) => d.r + 6))
    .stop();
  for (let i = 0; i < 300; i++) sim.tick();

  // --- Emit React Flow nodes/edges ---------------------------------------------
  const simById = new Map(simNodes.map((s) => [s.id, s]));
  // Card sizes per type — the simulation centers on these radii, so subtract
  // half the CARD size to center the rendered node (not just its collision dot).
  const cardHalf = (id: string): { hw: number; hh: number } => {
    if (id.startsWith('segment:')) return hubSize(id) > 0 ? { hw: HUB_R, hh: HUB_R } : { hw: MINI_HUB_R, hh: MINI_HUB_R }; // 68px / 40px circle
    if (apIds.has(id)) return { hw: 32, hh: 26 }; // AP card w-16
    if (devices.has(id)) return { hw: 26, hh: 20 }; // switch card w-[52px]
    const r = hostRadius.get(id) ?? HOST_MIN_R;
    return { hw: r + 4, hh: r + 4 }; // dot + label padding
  };
  const pos = (id: string): { x: number; y: number } => {
    const n = simById.get(id)!;
    const c = cardHalf(id);
    return { x: (n.x ?? 0) - c.hw, y: (n.y ?? 0) - c.hh };
  };

  const rfNodes: FlowNode[] = [];
  for (const h of hubs) {
    const count = hubSize(h.id);
    // Empty segments render as compact dashed mini-hubs — present in the VLAN
    // grid, but not taking a full hub's space.
    rfNodes.push({ id: h.id, type: 'hub', position: pos(h.id), data: { ...h, memberCount: count, variant: count > 0 ? 'hub' : 'mini-hub' } });
  }
  for (const id of satelliteIds) {
    const d = devices.get(id)!;
    if (apIds.has(id)) {
      rfNodes.push({ id, type: 'ap', position: pos(id), data: d });
    } else {
      rfNodes.push({ id, type: 'switch', position: pos(id), data: { ...d, segCount: visDevSegs.get(id)!.length } });
    }
  }
  const shownHostIds = new Set<string>();
  for (const h of hosts) {
    if (!hostsInView.has(h.id) && !visWireless.some((w) => w.target === h.id)) continue; // dropped with its hub
    const bytes = input.hostBytes?.get(h.id);
    rfNodes.push({ id: h.id, type: 'nethost', position: pos(h.id), data: { ...h, r: hostRadius.get(h.id), ...(bytes ? { trafficBytes: bytes } : {}) } });
    shownHostIds.add(h.id);
  }

  // Straight lines — radial spokes read cleaner than beziers in a net view
  // (endpoints come from the nodes' wall handles; see SideHandles).
  // Drawn spokes = primary membership only (one line per host). The full
  // multi-segment list stays in the node popover data.
  const drawnSpokes = new Map<string, { source: string; target: string }>();
  for (const [hostId, seg] of primaryHub) {
    if (!seg || !hostsInView.has(hostId)) continue;
    drawnSpokes.set(hostId, { source: hostId, target: seg });
  }

  const rfEdges: FlowEdge[] = [
    // Faint membership spokes — structure, not the story.
    ...[...drawnSpokes.entries()].map(([hostId, e]) => ({
      id: `spoke-${hostId}`,
      source: e.source,
      target: e.target,
      type: 'straight' as const,
      style: { stroke: 'rgb(var(--topo-cable))', strokeWidth: 1, strokeOpacity: 0.3 },
    })),
    // Device→segment membership — which switch bridges which VLANs (fainter
    // than host spokes; a multi-VLAN switch shows one line per segment).
    ...satelliteIds.flatMap((id) =>
      visDevSegs.get(id)!.map((segId) => ({
        id: `dev-${id}::${segId}`,
        source: id,
        target: segId,
        type: 'straight' as const,
        style: { stroke: 'rgb(var(--topo-cable))', strokeWidth: 1, strokeOpacity: 0.2 },
      }))
    ),
    // WLAN associations — the distinct dashed link (AP → client).
    ...visWireless.map((e) => ({
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'straight' as const,
      style: { stroke: 'rgb(var(--topo-wireless))', strokeWidth: 1.25, strokeDasharray: '2 4' },
    })),
  ];

  return { rfNodes, rfEdges, totalHosts: allHosts.length, shownHosts: shownHostIds.size, rankedByTraffic };
}
