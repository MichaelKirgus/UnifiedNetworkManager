import { forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationNodeDatum } from 'd3-force';
import type { Edge as FlowEdge, Node as FlowNode } from '@xyflow/react';
import type { TopologyEdge as TopoEdge, TopologyNode as TopoNode } from '../../api/client';

/**
 * Force-directed layout for the TOPOLOGY "Hosts" view — every known host as a
 * dot in a net around its segment hub(s), with WLAN clients visibly attached
 * to their AP. Deterministic: hubs/APs are pinned to computed anchors and all
 * initial positions are index-derived (no Math.random), so refetches at the
 * same data produce the same picture instead of reshuffling.
 *
 * Node set is capped (MAX_HOSTS) — ranked by traffic when the overlay has
 * bytes, otherwise in server order (newest-first per segment). The caller
 * shows a "showing N of M" note from the returned counts.
 */

/** Total host cap for the net view (plan: ~200 top-N by traffic). */
export const MAX_HOSTS = 200;

const HUB_R = 34; // hub anchor radius (px) — matches HubNode's 68px circle
const AP_R = 26;
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

  // Hubs: segments with ≥1 kept member host (or the focused one). Empty hubs
  // are dropped — an isolated dot adds no information.
  let keptSegs = new Set(membershipEdges.map((e) => e.target));
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
  const aps = [...apIds].map((id) => devices.get(id)!);

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

  // AP anchors — a ring slot around their hub (first visible segment they're a
  // member of; else the first hub). Deterministic angle per index.
  const apHub = new Map<string, string>();
  for (const apId of apIds) {
    const seg = visMembership.find((m) => m.source === apId)?.target ?? hubs[0].id;
    apHub.set(apId, seg);
  }
  const apsByHub = new Map<string, string[]>();
  for (const apId of apIds) {
    let list = apsByHub.get(apHub.get(apId)!);
    if (!list) {
      list = [];
      apsByHub.set(apHub.get(apId)!, list);
    }
    list.push(apId);
  }
  for (const [segId, list] of apsByHub) {
    const a = anchor.get(segId)!;
    list.forEach((apId, j) => {
      const ang = (j - (list.length - 1) / 2) * 0.9 - Math.PI / 2; // fan above the hub
      anchor.set(apId, { x: a.x + Math.cos(ang) * 230, y: a.y + Math.sin(ang) * 230 });
    });
  }

  // --- Simulation nodes --------------------------------------------------------
  const simNodes: SimNode[] = [
    ...hubs.map((h): SimNode => ({ id: h.id, r: HUB_R, x: anchor.get(h.id)!.x, y: anchor.get(h.id)!.y, fx: anchor.get(h.id)!.x, fy: anchor.get(h.id)!.y })),
    ...aps.map((d): SimNode => ({ id: d.id, r: AP_R, x: anchor.get(d.id)!.x, y: anchor.get(d.id)!.y, fx: anchor.get(d.id)!.x, fy: anchor.get(d.id)!.y })),
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
    if (id.startsWith('segment:')) return { hw: HUB_R, hh: HUB_R }; // 68px circle
    if (devices.has(id)) return { hw: 32, hh: 26 }; // AP card w-16
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
    const count = visMembership.filter((m) => m.target === h.id).length;
    rfNodes.push({ id: h.id, type: 'hub', position: pos(h.id), data: { ...h, memberCount: count } });
  }
  for (const d of aps) {
    rfNodes.push({ id: d.id, type: 'ap', position: pos(d.id), data: d });
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
