import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import {
  Background,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge as FlowEdge,
  type Node as FlowNode,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import clsx from 'clsx';
import { Layout } from '../components/Layout';
import { can } from '../auth/permissions';
import { api, NetworkLayer, TopologyEdge as TopoEdge, TopologyNode as TopoNode } from '../api/client';
import { TimeRangeFilter, resolveTimeRangeIso, type TimeRangeValue } from '../components/TimeRangeFilter';
import { joinHostTraffic, joinPairTraffic, joinSegmentTraffic, maxOf, nodeEmphasis } from '../components/topology/traffic';
import { DeviceNode, setLayerRegistry } from '../components/topology/DeviceNode';
import { SegmentNode } from '../components/topology/SegmentNode';
import { HostNode } from '../components/topology/HostNode';
import { RemoteNode } from '../components/topology/RemoteNode';
import { TrunkEdge } from '../components/topology/TrunkEdge';

const nodeTypes = { device: DeviceNode, segment: SegmentNode, host: HostNode, remote: RemoteNode, band: BandNode };

/** True when the straight segment between two card centers crosses any OTHER
 * card's box (with a small margin). Same-row edges whose direct line passes
 * through an intermediate node must detour around it instead of cutting across
 * the card — that produced phantom "cables" over unrelated nodes. */
function blockedByNode(
  s: { x: number; y: number },
  t: { x: number; y: number },
  boxes: Map<string, { x: number; y: number; width: number; height: number }>,
  sourceId: string,
  targetId: string
): boolean {
  const M = 6;
  const loX = Math.min(s.x, t.x) - M;
  const hiX = Math.max(s.x, t.x) + M;
  const loY = Math.min(s.y, t.y) - M;
  const hiY = Math.max(s.y, t.y) + M;
  for (const [id, b] of boxes) {
    if (id === sourceId || id === targetId) continue;
    if (b.x < hiX && b.x + b.width > loX && b.y < hiY && b.y + b.height > loY) return true;
  }
  return false;
}

/** Pick the wall handles an edge should attach to, from actual layout geometry.
 * Every topology node carries invisible centered anchors on all four walls
 * (ids `ts/tt/rs/rt/bs/bt/ls/lt` — see SideHandles in DeviceNode.tsx):
 * vertical neighbors use top/bottom walls, horizontal ones left/right, so the
 * orthogonal path always travels in its direction of travel and never loops
 * back through a node. Direction is decided from CARD CENTERS (pos + measured
 * size / 2) — top-left positions alone flip for nodes with different heights,
 * which produced Z-shaped paths on same-row bundles.
 *
 * DETOUR: when the direct segment would cross another card, both ends use the
 * BOTTOM wall (or TOP near the diagram's top edge) so the path drops into the
 * empty corridor below/above and travels there — it never cuts through a node. */
function handlesFor(
  e: { source: string; target: string },
  pos: Map<string, { x: number; y: number }>,
  dims: Map<string, { width: number; height: number }>,
  boxes: Map<string, { x: number; y: number; width: number; height: number }>
): { sourceHandle: string; targetHandle: string; corridorY?: number } {
  const s = pos.get(e.source);
  const t = pos.get(e.target);
  if (s && t) {
    const sd = dims.get(e.source);
    const td = dims.get(e.target);
    const scx = s.x + (sd?.width ?? NODE_W) / 2;
    const scy = s.y + (sd?.height ?? 90) / 2;
    const tcx = t.x + (td?.width ?? NODE_W) / 2;
    const tcy = t.y + (td?.height ?? 90) / 2;
    const dx = tcx - scx;
    const dy = tcy - scy;
    if (Math.abs(dy) > Math.abs(dx)) {
      // Vertical neighbors — top/bottom walls.
      return dy > 0
        ? { sourceHandle: 'bs', targetHandle: 'tt' }
        : { sourceHandle: 'ts', targetHandle: 'bt' };
    }
    // Horizontal-dominant. If the straight line crosses another card, detour
    // through a corridor instead of cutting across it. The corridor Y clears
    // EVERY card in the span (intermediate cards can be taller than both ends)
    // plus a small margin so the run never grazes a card edge.
    if (blockedByNode({ x: scx, y: scy }, { x: tcx, y: tcy }, boxes, e.source, e.target)) {
      const below = Math.max(s.y + (sd?.height ?? 90), t.y + (td?.height ?? 90));
      const above = Math.min(s.y, t.y);
      const loX = Math.min(s.x, t.x);
      const hiX = Math.max(s.x + (sd?.width ?? NODE_W), t.x + (td?.width ?? NODE_W));
      let corridorY = below;
      for (const b of boxes.values()) {
        if (b.x < hiX && b.x + b.width > loX) corridorY = Math.max(corridorY, b.y + b.height);
      }
      // Prefer the corridor with more room; default to below.
      if (above > below - ROW_H * 1.2 && above > 40) {
        return { sourceHandle: 'ts', targetHandle: 'tt', corridorY: above - 12 };
      }
      return { sourceHandle: 'bs', targetHandle: 'bt', corridorY: corridorY + 12 };
    }
    if (dx < 0) return { sourceHandle: 'ls', targetHandle: 'rt' };
  }
  return { sourceHandle: 'rs', targetHandle: 'lt' };
}

/** Convert topology edges to React Flow edges. Edges sharing the SAME node
 * pair get a centered perpendicular offset index (0, ±1, ±2…) so parallel
 * cables run as distinct grid-aligned lines instead of overlapping; wall
 * handles come from layout geometry. Tunnels between the same pair collapse
 * into ONE edge with a count label — dozens of individual WireGuard rows would
 * otherwise render as an unreadable dashed fan. */
function assignParallel(
  edges: TopoEdge[],
  posMap: Map<string, { x: number; y: number }>,
  dims: Map<string, { width: number; height: number }>,
  boxes: Map<string, { x: number; y: number; width: number; height: number }>
): FlowEdge[] {
  // Collapse same-pair tunnels into one representative edge (count in data).
  const tunnelCounts = new Map<string, number>();
  for (const e of edges) {
    if (e.kind !== 'tunnel') continue;
    const k = [e.source, e.target].sort().join('|');
    tunnelCounts.set(k, (tunnelCounts.get(k) ?? 0) + 1);
  }
  const out: FlowEdge[] = [];
  const emittedTunnelPair = new Set<string>();
  for (const e of edges) {
    if (e.kind === 'tunnel') {
      const k = [e.source, e.target].sort().join('|');
      if (emittedTunnelPair.has(k)) continue;
      emittedTunnelPair.add(k);
    }
    // Per-pair index in TARGET-ORDER — same-pair cables stay adjacent in the
    // bend distribution below, so they run as a clean ladder instead of
    // interleaving with other pairs' edges.
    const key = [e.source, e.target].sort().join('|');
    const total = tunnelCounts.get(key) ?? 1;
    const h = handlesFor(e, posMap, dims, boxes);
    out.push({
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'trunk',
      data: {
        ...e,
        parallelIndex: 0,
        ...(h.corridorY !== undefined ? { corridorY: h.corridorY } : {}),
        ...(e.kind === 'tunnel' && total > 1 ? { tunnelCount: total } : {}),
      },
      sourceHandle: h.sourceHandle,
      targetHandle: h.targetHandle,
    });
  }
  // Assign pair indices in target order (deterministic ladder).
  const byPair = new Map<string, FlowEdge[]>();
  for (const f of out) {
    const k = [f.source, f.target].sort().join('|');
    let list = byPair.get(k);
    if (!list) {
      list = [];
      byPair.set(k, list);
    }
    list.push(f);
  }
  for (const list of byPair.values()) {
    const n = list.length;
    if (n < 2) continue;
    // Order by the target node's position along the travel axis.
    list.sort((a, b) => {
      const pa = posMap.get(a.target);
      const pb = posMap.get(b.target);
      if (!pa || !pb) return a.id.localeCompare(b.id);
      return Math.abs(pa.y - pb.y) > Math.abs(pa.x - pb.x) ? pa.y - pb.y : pa.x - pb.x;
    });
    list.forEach((f, i) => {
      f.data = { ...(f.data as Record<string, unknown>), parallelIndex: i - (n - 1) / 2 };
    });
  }
  return out;
}
/** Give every orthogonal edge its own jog position so cables never share a
 * line. Same-pair parallel edges already get a perpendicular X/Y offset
 * (assignParallel); without a distinct JOG coordinate their runs sit on the
 * same midpoint and merge into one thick bar, and cross-pair edges in a band
 * corridor each bend at their own midpoint → a tangle.
 *
 * Edges are bucketed by the corridor gap they cross (midpoint / pitch) AND by
 * node pair; within each pair the jog positions are spread in parallel-index
 * order, so same-pair cables form clean ladders and different pairs fan out
 * through the empty corridor instead of stacking. Vertical-dominant edges get
 * `bendOffset` (jog Y), horizontal-dominant ones `bendXOffset` (jog X). */
function withBendOffsets(
  edges: FlowEdge[],
  posMap: Map<string, { x: number; y: number }>,
  dims: Map<string, { width: number; height: number }>
): FlowEdge[] {
  const BEND_SPACING = 14; // px between adjacent jog positions in a corridor
  type Item = { e: FlowEdge; vertical: boolean; lo: number; hi: number; otherLo: number; pairKey: string };
  const items: Item[] = [];
  for (const e of edges) {
    const s = posMap.get(e.source);
    const t = posMap.get(e.target);
    if (!s || !t) continue;
    const sd = dims.get(e.source);
    const td = dims.get(e.target);
    const scx = s.x + (sd?.width ?? NODE_W) / 2;
    const scy = s.y + (sd?.height ?? 90) / 2;
    const tcx = t.x + (td?.width ?? NODE_W) / 2;
    const tcy = t.y + (td?.height ?? 90) / 2;
    const vertical = Math.abs(tcy - scy) > Math.abs(tcx - scx);
    if (!vertical && Math.abs(tcx - scx) < 1) continue; // straight horizontal
    if (vertical && Math.abs(tcx - scx) < 1) continue; // straight vertical
    const pairKey = [e.source, e.target].sort().join('|');
    items.push(
      vertical
        ? { e, vertical, lo: Math.min(scy, tcy), hi: Math.max(scy, tcy), otherLo: Math.min(scx, tcx), pairKey }
        : { e, vertical, lo: Math.min(scx, tcx), hi: Math.max(scx, tcx), otherLo: Math.min(scy, tcy), pairKey }
    );
  }
  // Bucket by corridor gap crossed (midpoint / pitch) — long edges crossing
  // several gaps land in the bucket of their midpoint.
  const byCorridor = new Map<string, Item[]>();
  for (const it of items) {
    const mid = (it.lo + it.hi) / 2;
    const key = `${it.vertical ? 'v' : 'h'}:${Math.round(mid / ROW_H)}`;
    let list = byCorridor.get(key);
    if (!list) {
      list = [];
      byCorridor.set(key, list);
    }
    list.push(it);
  }
  const offsets = new Map<string, number>();
  for (const list of byCorridor.values()) {
    // Per-pair sub-buckets: same-pair cables stay adjacent → ladder order.
    const byPair = new Map<string, Item[]>();
    for (const it of list) {
      let pl = byPair.get(it.pairKey);
      if (!pl) {
        pl = [];
        byPair.set(it.pairKey, pl);
      }
      pl.push(it);
    }
    // Pairs ordered by their position along the cross axis (deterministic).
    const pairs = [...byPair.entries()].sort((a, b) => {
      const alo = Math.min(...a[1].map((x) => x.otherLo));
      const blo = Math.min(...b[1].map((x) => x.otherLo));
      return alo - blo || a[0].localeCompare(b[0]);
    });
    let cursor = 0;
    for (const [, pl] of pairs) {
      if (pl.length < 2) continue; // single edge keeps the midpoint jog
      pl.sort((a, b) => ((a.e.data?.parallelIndex as number) ?? 0) - ((b.e.data?.parallelIndex as number) ?? 0));
      const n = pl.length;
      const minSpan = Math.min(...pl.map((x) => x.hi - x.lo));
      const step = Math.min(BEND_SPACING, (minSpan * 0.6) / (n - 1));
      pl.forEach((it, i) => offsets.set(it.e.id, cursor + (i - (n - 1) / 2) * step));
      cursor += n;
    }
  }
  return edges.map((e) => {
    const off = offsets.get(e.id);
    if (off === undefined || off === 0) return e;
    const it = items.find((x) => x.e === e);
    const field = it?.vertical ? 'bendOffset' : 'bendXOffset';
    return { ...e, data: { ...(e.data as Record<string, unknown>), [field]: off } };
  });
}

// One custom edge renderer handles all kinds (cable/tunnel/membership) — it
// reads the kind + VLAN list from `data` and picks its rendering.
const edgeTypes = { trunk: TrunkEdge };

type ViewMode = 'physical' | 'logical';

/** MiniMap base hues as RGB triplets — mirrors the --topo-* palette in
 * index.css (fixed dark-slate values, identical across all themes), so JS can
 * mix toward the traffic accent without reading computed styles. */
const TOPO_RGB: Record<string, [number, number, number]> = {
  segment: [99, 102, 241], // --topo-segment
  host: [203, 213, 225], // --topo-host
  remote: [165, 180, 252], // --topo-remote
  unassigned: [148, 163, 184], // --topo-unassigned
  node: [51, 65, 85], // --topo-node
};
const TRAFFIC_RGB: [number, number, number] = [56, 189, 248]; // --topo-traffic

/** Mix a base hue toward the traffic accent by `t` (0..1) — MiniMap dots of
 * busy nodes glow sky while idle ones keep their kind color. */
function mixTowardTraffic(base: [number, number, number], t: number): string {
  const k = Math.max(0, Math.min(1, t));
  const c = base.map((b, i) => Math.round(b + (TRAFFIC_RGB[i] - b) * k));
  return `rgb(${c[0]} ${c[1]} ${c[2]})`;
}

type DeviceTopoNode = TopoNode & { kind: 'device' };

/** Shared grid metrics for the physical layout (kept in sync with the node
 * card size — see DeviceNode.tsx, which caps port chips to bound its height). */
const NODE_W = 200;
const GAP_X = 80;
const ROW_H = 170;
const COLS = 4;

/** Band header node — a full-width colored strip above each layer's device row.
 * Purely decorative (no handles); edges only ever attach to device/remote nodes. */
function BandNode({ data }: { data: { label: string; color: string } }) {
  return (
    <div className="pointer-events-none flex items-center gap-2" style={{ width: COLS * NODE_W + (COLS - 1) * GAP_X }}>
      <span className="h-3 w-3 rounded-sm" style={{ backgroundColor: data.color }} />
      <span className="text-[11px] font-bold uppercase tracking-wider" style={{ color: data.color }}>
        {data.label}
      </span>
    </div>
  );
}

/** Deterministic O(n) layout for the PHYSICAL view: one horizontal BAND per
 * network layer (in registry sort order), devices name-sorted within their
 * band, remote tunnel peers in a top strip. Cables between layers travel
 * vertically through the corridor between bands — the diagram reads like a
 * real core/distribution/access/endpoint hierarchy instead of site clusters.
 * Empty bands are skipped; unknown layer ids (defensive) land in an
 * "Unassigned" band so nothing disappears. */
function layoutPhysical(nodes: TopoNode[], layers: NetworkLayer[]): FlowNode[] {
  const layerById = new Map(layers.map((l) => [l.id, l]));

  // Group device nodes by their resolved layer id.
  const byLayer = new Map<string, DeviceTopoNode[]>();
  for (const n of nodes) {
    if (n.kind !== 'device') continue;
    let list = byLayer.get(n.layer);
    if (!list) {
      list = [];
      byLayer.set(n.layer, list);
    }
    list.push(n);
  }

  const orderedLayers: Array<{ id: string; name: string; color: string }> = layers.map((l) => ({
    id: l.id,
    name: l.name,
    color: l.color,
  }));
  for (const id of byLayer.keys()) {
    // Topology canvas palette — centralized in index.css (--topo-*).
    if (!layerById.has(id)) orderedLayers.push({ id, name: 'Unassigned', color: 'rgb(var(--topo-unassigned))' });
  }

  const out: FlowNode[] = [];
  let y = 0;

  // Remote (unmanaged) tunnel peers — one strip above the first band so their
  // dashed tunnel edges have something to attach to.
  const remotes = nodes.filter((n): n is TopoNode & { kind: 'remote' } => n.kind === 'remote');
  if (remotes.length > 0) {
    out.push({ id: '__band-remote', type: 'band', position: { x: 0, y }, data: { label: 'Remote peers', color: 'rgb(var(--topo-tunnel))' } });
    for (let i = 0; i < remotes.length; i++) {
      const col = i % COLS;
      const row = Math.floor(i / COLS);
      out.push({ id: remotes[i].id, type: 'remote', position: { x: col * (NODE_W + GAP_X), y: y + 30 + row * ROW_H }, data: remotes[i] });
    }
    const rows = Math.max(1, Math.ceil(remotes.length / COLS));
    y += 30 + rows * ROW_H + 60; // corridor before the first layer band
  }

  for (const l of orderedLayers) {
    const list = byLayer.get(l.id);
    if (!list || list.length === 0) continue; // skip empty bands
    out.push({ id: `__band-${l.id}`, type: 'band', position: { x: 0, y }, data: { label: l.name, color: l.color } });
    list.sort((a, b) => a.name.localeCompare(b.name));
    for (let i = 0; i < list.length; i++) {
      const col = i % COLS;
      // Row offset — bands with more than COLS devices wrap to a second row
      // instead of stacking overflow nodes on top of the first one.
      const row = Math.floor(i / COLS);
      out.push({ id: list[i].id, type: 'device', position: { x: col * (NODE_W + GAP_X), y: y + 30 + row * ROW_H }, data: list[i] });
    }
    const rows = Math.max(1, Math.ceil(list.length / COLS));
    y += 30 + rows * ROW_H + 90; // band header + rows + cable corridor
  }

  return out;
}

/** Deterministic O(n) layout for the LOGICAL view: one block per segment —
 * the segment node on the left, its member devices in a grid to the right,
 * hosts (when enabled) below them. A device/host that belongs to SEVERAL
 * segments gets its own instance node per block (`<segId>::<nodeId>`) — React
 * Flow requires unique ids; duplicates collapse onto one position and every
 * membership edge from the other blocks converges onto that single spot.
 * Returns a map `${segId}|${nodeId}` → instance id so the caller can point the
 * membership edges at the right copy. */
function layoutLogical(
  segments: TopoNode[],
  membersBySegment: Map<string, { devices: TopoNode[]; hosts: TopoNode[] }>
): { nodes: FlowNode[]; memberSourceIds: Map<string, string> } {
  const NODE_W = 200;
  const GAP_X = 70;
  const ROW_H = 150;
  const COLS = 5;
  let y = 0;
  const nodes: FlowNode[] = [];
  const memberSourceIds = new Map<string, string>();
  for (const seg of segments) {
    if (seg.kind !== 'segment') continue;
    const m = membersBySegment.get(seg.id) ?? { devices: [], hosts: [] };
    nodes.push({ id: seg.id, type: 'segment', position: { x: 0, y: y + 20 }, data: seg });
    const gridX = NODE_W + 160;
    m.devices.forEach((d, i) => {
      const col = i % COLS;
      const row = Math.floor(i / COLS);
      const instId = `${seg.id}::${d.id}`;
      memberSourceIds.set(`${seg.id}|${d.id}`, instId);
      nodes.push({ id: instId, type: 'device', position: { x: gridX + col * (NODE_W + GAP_X), y }, data: d });
    });
    const devRows = Math.max(1, Math.ceil(m.devices.length / COLS));
    m.hosts.forEach((h, i) => {
      const col = i % COLS;
      const row = Math.floor(i / COLS);
      const instId = `${seg.id}::${h.id}`;
      memberSourceIds.set(`${seg.id}|${h.id}`, instId);
      nodes.push({ id: instId, type: 'host', position: { x: gridX + col * (NODE_W + GAP_X), y: y + devRows * ROW_H + row * 90 }, data: h });
    });
    const hostRows = Math.ceil(m.hosts.length / COLS);
    y += Math.max(devRows, 1) * ROW_H + hostRows * 90 + 80; // block spacing
  }
  return { nodes, memberSourceIds };
}

/** Compact tag multi-select for the header — a select that adds/removes tags
 * (AND semantics: a device must carry ALL selected tags). Free-form input is
 * deliberately omitted: tags come from the inventory, and typing an unknown
 * one would silently filter to an empty graph. */
function TagFilter({ allTags, value, onChange }: { allTags: string[]; value: string[]; onChange: (tags: string[]) => void }) {
  const [open, setOpen] = useState(false);
  if (allTags.length === 0) return null; // nothing to filter by — stay out of the way
  const options = [...new Set(allTags.map((t) => t.toLowerCase()))].sort();
  const selectedLower = new Set(value.map((t) => t.toLowerCase()));
  return (
    <div className="relative">
      <select
        value=""
        onChange={(e) => {
          if (!e.target.value) return;
          const tag = e.target.value;
          // Case-insensitive dedupe — "Router" and "router" are the same tag.
          if (value.some((t) => t.toLowerCase() === tag)) onChange(value.filter((t) => t !== tag));
          else onChange([...value, tag]);
        }}
        className="rounded-md border border-border bg-card px-2 py-1 text-xs text-secondary"
      >
        <option value="">Filter by tag…</option>
        {options.map((t) => (
          <option key={t} value={t}>
            {selectedLower.has(t) ? `✓ ${t}` : t}
          </option>
        ))}
      </select>
      {value.length > 0 && (
        <>
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            className="ml-1 rounded-md border border-border bg-muted px-2 py-1 text-xs font-medium text-secondary hover:bg-background"
            title={`${value.length} tag filter${value.length > 1 ? 's' : ''} (AND)`}
          >
            {value.length} tag{value.length > 1 ? 's' : ''}
          </button>
          {open && (
            <div className="absolute left-0 top-full z-20 mt-1 flex max-w-72 flex-wrap gap-1 rounded-md border border-border bg-card p-2 shadow-md">
              {value.map((t) => (
                <span key={t} className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
                  {t}
                  <button type="button" onClick={() => onChange(value.filter((x) => x !== t))} aria-label={`Remove ${t}`} className="text-faint hover:text-danger-fg">
                    ×
                  </button>
                </span>
              ))}
              <button type="button" onClick={() => { onChange([]); setOpen(false); }} className="rounded px-1.5 py-0.5 text-xs text-muted-foreground hover:bg-background">
                Clear all
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default function Topology() {
  const navigate = useNavigate();
  const [view, setView] = useState<ViewMode>('physical');
  const [showHosts, setShowHosts] = useState(false);
  const [showTunnels, setShowTunnels] = useState(true);
  const [siteId, setSiteId] = useState('');
  const [segmentKey, setSegmentKey] = useState('all');
  // Device filters — applied SERVER-SIDE on /topology (segments/edges recompute
  // over the filtered subset). Tags use AND semantics.
  const [tagFilter, setTagFilter] = useState<string[]>([]);
  const [layerFilter, setLayerFilter] = useState('');
  // Traffic overlay — opt-in; relative presets slide with time (resolved inside
  // queryFn, same pattern as the Flows page).
  const [showTraffic, setShowTraffic] = useState(false);
  const [range, setRange] = useState<TimeRangeValue>('24h');

  // Site filter options — only fetched when allowed (API gates on sites:read).
  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: () => api.sites(), enabled: can('sites:read') });
  // Device inventory — feeds the tag filter's option list.
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices, enabled: can('devices:read'), refetchInterval: 300_000 });
  // Layer registry — drives the physical view's bands (names/colors/order).
  const layersQuery = useQuery({ queryKey: ['layers'], queryFn: () => api.layers(), refetchInterval: 60_000 });
  // Feed the layer colors into the device-node chip/border registry.
  useEffect(() => {
    setLayerRegistry(layersQuery.data ?? []);
  }, [layersQuery.data]);
  // includeHosts is only consumed in the logical view; requesting it always
  // keeps a single cache entry per (site, hosts) pair. Tag/layer filters are
  // server-side — they change which devices exist in the graph at all.
  const topoQuery = useQuery({
    queryKey: ['topology', siteId || null, showHosts, tagFilter, layerFilter || null],
    queryFn: () =>
      api.topology({
        siteId: siteId || undefined,
        includeHosts: showHosts,
        tags: tagFilter.length > 0 ? tagFilter : undefined,
        layer: layerFilter || undefined,
      }),
    refetchInterval: 30_000, // matches the telemetry poll cadence
  });

  // --- Traffic overlay data (opt-in; gated on flows:read + toggle) -----------
  // Three rollups feed the overlay: device↔device pairs (edge widths), per-IP
  // + per-network inventory (host/segment badges), and per-device totals
  // (device badges — includes internet egress that pairs can't see). Relative
  // presets slide with time, so resolve INSIDE queryFn on every refetch.
  const trafficEnabled = showTraffic && can('flows:read');
  const windowParams = () => ({ ...resolveTimeRangeIso(range), siteId: siteId || undefined });
  const pairsQuery = useQuery({
    queryKey: ['topo-traffic', 'pairs', range, siteId || null],
    queryFn: () => api.flowsPairs({ limit: 100, ...windowParams() }),
    enabled: trafficEnabled,
    refetchInterval: 60_000,
  });
  const inventoryQuery = useQuery({
    queryKey: ['topo-traffic', 'inventory', range, siteId || null],
    queryFn: () => api.flowsInventory(windowParams()),
    enabled: trafficEnabled,
    refetchInterval: 60_000,
  });
  const devicesTrafficQuery = useQuery({
    queryKey: ['topo-traffic', 'devices', range, siteId || null],
    queryFn: () => api.flowsDevices(windowParams()),
    enabled: trafficEnabled,
    refetchInterval: 60_000,
  });

  // Traffic joins — byte counts keyed by ORIGINAL node/edge ids. Computed once
  // per data change and attached inside the layout memo below (logical-view
  // instance nodes inherit their original's bytes via `data`).
  const traffic = useMemo(() => {
    if (!trafficEnabled || !topoQuery.data) return null;
    const deviceBytes = new Map<string, number>();
    for (const d of devicesTrafficQuery.data?.devices ?? []) deviceBytes.set(d.deviceId, d.estBytes);
    const hostBytes = joinHostTraffic(inventoryQuery.data?.perIp ?? [], topoQuery.data.nodes.filter((n) => n.kind === 'host'));
    const segmentBytes = joinSegmentTraffic(
      inventoryQuery.data?.perNetwork ?? [],
      topoQuery.data.nodes.filter((n) => n.kind === 'segment').map((s) => s.id)
    );
    // Edge widths come from pairs; the scale ceiling is the busiest PAIR so a
    // single dominant link reads as "thick" without distorting the rest. Node
    // kinds get their own ceilings (a 10 GB segment vs a 50 MB host).
    const edgeBytes = joinPairTraffic(pairsQuery.data?.pairs ?? [], topoQuery.data.edges);
    return {
      deviceBytes,
      hostBytes,
      segmentBytes,
      edgeBytes,
      maxEdge: maxOf(edgeBytes),
      maxDevice: maxOf(deviceBytes),
      maxHost: maxOf(hostBytes),
      maxSegment: maxOf(segmentBytes),
    };
  }, [trafficEnabled, topoQuery.data, devicesTrafficQuery.data, inventoryQuery.data, pairsQuery.data]);

  const { rfNodes, rfEdges } = useMemo(() => {
    const data = topoQuery.data;
    if (!data) return { rfNodes: [] as FlowNode[], rfEdges: [] as FlowEdge[] };

    // Display names per node id — wireless edge chips show "AP · WLAN-1 ↔ host".
    const nameById = new Map<string, string>();
    for (const n of data.nodes) {
      if (n.kind === 'device') nameById.set(n.id, n.name);
      else if (n.kind === 'host') nameById.set(n.id, n.hostname || n.mac);
      else if (n.kind === 'remote') nameById.set(n.id, n.label);
    }
    // Attach traffic bytes + the scale ceiling to edge data (no-op when the
    // overlay is off). Wireless edges also carry endpoint display names for
    // their hover chip. Logical-view endpoints are INSTANCE ids (`segId::orig`)
    // — strip the prefix so nameById (keyed by original id) still resolves.
    const origId = (id: string) => (id.includes('::') ? id.slice(id.indexOf('::') + 2) : id);
    const decorateEdges = (fs: FlowEdge[]): FlowEdge[] => {
      if (!traffic) return fs;
      return fs.map((f) => {
        const fd = f.data as Record<string, unknown>;
        const extra: Record<string, unknown> = {};
        const bytes = traffic.edgeBytes.get(f.id);
        if (bytes) {
          extra.trafficBytes = bytes;
          extra.trafficMax = traffic.maxEdge;
        }
        if (fd.kind === 'wireless') {
          extra.sourceLabel = fd.sourceLabel ?? nameById.get(origId(f.source)) ?? '';
          extra.targetLabel = fd.targetLabel ?? nameById.get(origId(f.target)) ?? '';
        }
        return Object.keys(extra).length > 0 ? { ...f, data: { ...fd, ...extra } } : f;
      });
    };

    // Edges attach to the node's centered wall handles (see SideHandles in
    // DeviceNode.tsx); walls come from layout geometry, parallel cables get a
    // deterministic perpendicular offset per node pair.
    const posMap = new Map<string, { x: number; y: number }>();

    if (view === 'physical') {
      let nodes = data.nodes;
      let edges = data.edges;
      // "Show tunnels" off → drop tunnel edges and their remote peer nodes for
      // a physical-only view.
      if (!showTunnels) {
        const remoteIds = new Set(
          edges.filter((e) => e.kind === 'tunnel').map((e) => (e.source.startsWith('remote:') ? e.source : e.target))
        );
        edges = edges.filter((e) => e.kind !== 'tunnel');
        nodes = nodes.filter((n) => !(n.kind === 'remote' && remoteIds.has(n.id)));
      }
      const laidNodes = layoutPhysical(nodes, layersQuery.data ?? []);
      for (const n of laidNodes) posMap.set(n.id, n.position);
      const dims = new Map(laidNodes.map((n) => [n.id, { width: n.measured?.width ?? NODE_W, height: n.measured?.height ?? 90 }]));
      // Card boxes for collision detection (detour routing around nodes).
      const boxes = new Map<string, { x: number; y: number; width: number; height: number }>();
      for (const n of laidNodes) {
        if (n.type === 'band') continue;
        boxes.set(n.id, { x: n.position.x, y: n.position.y, width: dims.get(n.id)!.width, height: dims.get(n.id)!.height });
      }
      // Traffic overlay — attach per-device bytes to device cards (no-op when
      // off). Band nodes are decorative and keep their plain data.
      const rfNodes = traffic
        ? laidNodes.map((n) => {
            if (n.type !== 'device') return n;
            const d = n.data as TopoNode & { kind: 'device' };
            const bytes = traffic.deviceBytes.get(d.id.replace(/^device:/, ''));
            return bytes ? { ...n, data: { ...d, trafficBytes: bytes } } : n;
          })
        : laidNodes;
      // The physical layout places only device + remote nodes — host nodes
      // (incl. WLAN clients) have no position here, so any edge touching an
      // unplaced endpoint is dropped rather than dangling. Cables/tunnels are
      // unaffected (both ends always placed).
      const rfEdges = decorateEdges(
        withBendOffsets(assignParallel(edges.filter((e) => posMap.has(e.source) && posMap.has(e.target)), posMap, dims, boxes), posMap, dims)
      );
      return { rfNodes, rfEdges };
    }

    // Logical view.
    const segments = data.nodes.filter((n): n is TopoNode & { kind: 'segment' } => n.kind === 'segment');
    const visibleSegments = segmentKey === 'all' ? segments : segments.filter((s) => s.id === segmentKey);
    const segIds = new Set(visibleSegments.map((s) => s.id));

    // Membership edges tell us which devices/hosts belong to the visible segments.
    const memberEdges = data.edges.filter(
      (e) => e.kind === 'membership' && segIds.has(e.target)
    );
    const memberNodeIds = new Set(memberEdges.map((e) => e.source));
    const membersBySegment = new Map<string, { devices: TopoNode[]; hosts: TopoNode[] }>();
    for (const s of visibleSegments) membersBySegment.set(s.id, { devices: [], hosts: [] });
    // A node can belong to several segments — add it to each. Dedupe per
    // (segment, member): one device with two VLANs in the same segment has TWO
    // membership edges but must appear as ONE card in that block.
    const addedToSegment = new Set<string>();
    for (const n of data.nodes) {
      if (!memberNodeIds.has(n.id)) continue;
      for (const e of memberEdges) {
        if (e.source !== n.id) continue;
        const pairKey = `${e.target}|${n.id}`;
        if (addedToSegment.has(pairKey)) continue;
        addedToSegment.add(pairKey);
        const bucket = membersBySegment.get(e.target)!;
        if (n.kind === 'device') bucket.devices.push(n);
        else if (n.kind === 'host' && showHosts) bucket.hosts.push(n);
      }
    }

    // WLAN-only clients have NO segment membership of their own (seen only in
    // an AP's station table, on a radio that matches no member interface).
    // Attach them to a visible block so their dashed AP link has somewhere to
    // land — prefer the block containing their AP, else any visible block.
    if (showHosts) {
      const hostById = new Map(data.nodes.filter((n): n is TopoNode & { kind: 'host' } => n.kind === 'host').map((h) => [h.id, h]));
      const apSegs = new Map<string, string[]>(); // AP device id → visible segments containing it
      for (const [segId, m] of membersBySegment) {
        for (const d of m.devices) {
          let list = apSegs.get(d.id);
          if (!list) {
            list = [];
            apSegs.set(d.id, list);
          }
          list.push(segId);
        }
      }
      const placedHostIds = new Set<string>();
      for (const m of membersBySegment.values()) for (const h of m.hosts) placedHostIds.add(h.id);
      for (const e of data.edges) {
        if (e.kind !== 'wireless' || placedHostIds.has(e.target)) continue;
        const host = hostById.get(e.target);
        if (!host) continue;
        const segId = apSegs.get(e.source)?.[0] ?? visibleSegments[0]?.id;
        if (!segId) continue;
        membersBySegment.get(segId)!.hosts.push(host);
        placedHostIds.add(e.target);
      }
    }

    const laid = layoutLogical(visibleSegments, membersBySegment);
    for (const n of laid.nodes) posMap.set(n.id, n.position);
    const dims = new Map(laid.nodes.map((n) => [n.id, { width: n.measured?.width ?? NODE_W, height: n.measured?.height ?? 90 }]));
    // Card boxes for collision detection (detour routing around nodes).
    const boxes = new Map<string, { x: number; y: number; width: number; height: number }>();
    for (const n of laid.nodes) {
      if (n.type === 'band') continue;
      boxes.set(n.id, { x: n.position.x, y: n.position.y, width: dims.get(n.id)!.width, height: dims.get(n.id)!.height });
    }
    // Point each membership edge at the member's instance node in ITS block.
    const remapped = memberEdges.map((e) => ({ ...e, source: laid.memberSourceIds.get(`${e.target}|${e.source}`) ?? e.source }));

    // Traffic overlay — attach bytes to segment cards and to device/host
    // instances (each instance inherits its ORIGINAL node's traffic).
    const rfNodes = traffic
      ? laid.nodes.map((n) => {
          if (n.type === 'segment') {
            const d = n.data as TopoNode & { kind: 'segment' };
            const bytes = traffic.segmentBytes.get(d.id);
            return bytes ? { ...n, data: { ...d, trafficBytes: bytes } } : n;
          }
          if (n.type === 'device') {
            const d = n.data as TopoNode & { kind: 'device' };
            const bytes = traffic.deviceBytes.get(d.id.replace(/^device:/, ''));
            return bytes ? { ...n, data: { ...d, trafficBytes: bytes } } : n;
          }
          if (n.type === 'host') {
            const d = n.data as TopoNode & { kind: 'host' };
            const bytes = traffic.hostBytes.get(d.id);
            return bytes ? { ...n, data: { ...d, trafficBytes: bytes } } : n;
          }
          return n;
        })
      : laid.nodes;

    // WLAN associations — AP and host both exist as per-block INSTANCES here
    // (`<segId>::<origId>`), so re-point each edge at instance copies,
    // preferring the block where BOTH ends live (the client's own segment).
    const instancesOf = new Map<string, string[]>(); // original id → instance ids
    for (const n of laid.nodes) {
      if (!n.id.includes('::')) continue;
      const orig = n.id.slice(n.id.indexOf('::') + 2);
      let list = instancesOf.get(orig);
      if (!list) {
        list = [];
        instancesOf.set(orig, list);
      }
      list.push(n.id);
    }
    const wirelessRemapped: TopoEdge[] = [];
    for (const e of data.edges) {
      if (e.kind !== 'wireless') continue;
      const apInsts = instancesOf.get(e.source) ?? [];
      const hostInsts = instancesOf.get(e.target) ?? [];
      if (apInsts.length === 0 || hostInsts.length === 0) continue; // AP/host not in any visible block
      const segOf = (instId: string) => instId.slice(0, instId.indexOf('::'));
      const shared = apInsts.find((a) => hostInsts.some((h) => segOf(h) === segOf(a)));
      wirelessRemapped.push({ ...e, source: shared ?? apInsts[0], target: hostInsts[0] });
    }

    return {
      rfNodes,
      rfEdges: decorateEdges(withBendOffsets(assignParallel([...remapped, ...wirelessRemapped], posMap, dims, boxes), posMap, dims)),
    };
  }, [topoQuery.data, view, segmentKey, showHosts, showTunnels, layersQuery.data, traffic]);

  const segments = useMemo(
    () => (topoQuery.data?.nodes ?? []).filter((n): n is TopoNode & { kind: 'segment' } => n.kind === 'segment'),
    [topoQuery.data]
  );

  // Overlay hint — shown once the traffic queries have settled and the window
  // produced no flow rows at all (coverage gap, not "no traffic on this link").
  const trafficLoaded = pairsQuery.isSuccess && inventoryQuery.isSuccess && devicesTrafficQuery.isSuccess;
  const noFlowData =
    showTraffic && can('flows:read') && trafficLoaded && (pairsQuery.data?.pairs.length ?? 0) === 0 && (inventoryQuery.data?.perIp.length ?? 0) === 0;

  return (
    <Layout title="Topology">
      <div className="flex h-full flex-col gap-3">
        {/* Header controls */}
        <div className="flex flex-wrap items-center gap-2">

          {/* Physical | Logical toggle */}
          <div className="inline-flex rounded-md border border-border bg-card p-0.5">
            {(['physical', 'logical'] as ViewMode[]).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={clsx(
                  'rounded px-3 py-1 text-xs font-medium capitalize transition-colors',
                  view === v ? 'bg-primary text-white' : 'text-secondary hover:bg-muted'
                )}
              >
                {v}
              </button>
            ))}
          </div>

          {/* Site filter */}
          <select
            value={siteId}
            onChange={(e) => setSiteId(e.target.value)}
            className="rounded-md border border-border bg-card px-2 py-1 text-xs text-secondary"
          >
            <option value="">All sites</option>
            {(sitesQuery.data ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>

          {/* Device filters — server-side on /topology (AND tag semantics). */}
          <TagFilter allTags={(devicesQuery.data ?? []).flatMap((d) => d.tags)} value={tagFilter} onChange={setTagFilter} />
          {layersQuery.data && layersQuery.data.length > 0 && (
            <select
              value={layerFilter}
              onChange={(e) => setLayerFilter(e.target.value)}
              className="rounded-md border border-border bg-card px-2 py-1 text-xs text-secondary"
            >
              <option value="">All layers</option>
              {layersQuery.data.map((l) => (
                <option key={l.id} value={l.id}>
                  Layer: {l.name}
                </option>
              ))}
            </select>
          )}

          {/* Tunnels toggle (physical view only — logical has no tunnels). */}
          {view === 'physical' && (
            <label className="flex cursor-pointer items-center gap-1.5 text-xs text-secondary">
              <input type="checkbox" checked={showTunnels} onChange={(e) => setShowTunnels(e.target.checked)} />
              Show tunnels
            </label>
          )}

          {/* Traffic overlay — opt-in; line width + node badges scale with the
              selected window's estimated bytes (sampling extrapolation). */}
          {can('flows:read') && (
            <>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-secondary">
                <input type="checkbox" checked={showTraffic} onChange={(e) => setShowTraffic(e.target.checked)} />
                Show traffic
              </label>
              {showTraffic && <TimeRangeFilter compact value={range} onChange={setRange} />}
            </>
          )}

          {/* Segment focus (logical view only) */}
          {view === 'logical' && (
            <>
              <select
                value={segmentKey}
                onChange={(e) => setSegmentKey(e.target.value)}
                className="max-w-56 rounded-md border border-border bg-card px-2 py-1 text-xs text-secondary"
              >
                <option value="all">All segments</option>
                {segments.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.vlanId !== null ? `VLAN ${s.vlanId}` : s.label}
                  </option>
                ))}
              </select>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-secondary">
                <input type="checkbox" checked={showHosts} onChange={(e) => setShowHosts(e.target.checked)} />
                Show hosts
              </label>
            </>
          )}

          {/* Legend */}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-muted-foreground">
            {view === 'physical' ? (
              <>
                {(layersQuery.data ?? []).map((l) => (
                  <span key={l.id} className="flex items-center gap-1" title={`Layer: ${l.name}`}>
                    <span className="inline-block h-2 w-2 rounded-sm" style={{ backgroundColor: l.color }} />
                    {l.name}
                  </span>
                ))}
                <span className="flex items-center gap-1">
                  <span className="inline-block h-0.5 w-4 bg-topo-cable" /> cable (inferred)
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-0.5 w-4 border-t-2 border-dashed border-topo-tunnel" /> tunnel
                </span>
              </>
            ) : (
              <span>segment = merged logical network (VLAN/subnet)</span>
            )}
            {showHosts && view === 'logical' && (
              <span className="flex items-center gap-1">
                <span className="inline-block h-0.5 w-4 border-t border-dotted border-topo-wireless" /> WLAN link
              </span>
            )}
            {showTraffic && can('flows:read') && (
              <span className="flex items-center gap-1" title="Line width and node badges scale with estimated bytes in the selected window">
                <span className="inline-block h-0.5 w-2 bg-topo-cable" />
                <span className="inline-block h-1 w-2 rounded-sm bg-topo-cable" /> line ≈ traffic
              </span>
            )}
          </div>
        </div>

        {/* Overlay hint — window has no flow rows at all (coverage gap). */}
        {noFlowData && (
          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            <span className="rounded-md border border-border bg-muted px-2 py-1 text-secondary">
              No flow data in this window — check collectors on the Flows page.
            </span>
          </div>
        )}

        {/* Graph */}
        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-border bg-card">
          {topoQuery.isLoading ? (
            <div className="flex h-full items-center justify-center text-sm text-faint">Computing topology…</div>
          ) : rfNodes.length === 0 || !rfNodes.some((n) => n.type === 'device') ? (
            <div className="flex h-full flex-col items-center justify-center gap-1 text-sm text-faint">
              {tagFilter.length > 0 || layerFilter ? (
                <>
                  <span>No devices match the current filters.</span>
                  <button type="button" onClick={() => { setTagFilter([]); setLayerFilter(''); }} className="text-xs text-secondary underline hover:text-foreground">
                    Clear tag/layer filters
                  </button>
                </>
              ) : (
                'No devices to display.'
              )}
            </div>
          ) : (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
              // Controls/MiniMap/background dots are themed via the --xy-*
              // overrides in index.css (keyed off the html theme classes) —
              // not xyflow's colorMode, which is one fixed dark palette and
              // wouldn't track live theme switches or Black-vs-Slate.
              fitView
              minZoom={0.15}
              maxZoom={2}
              onNodeClick={(event, node) => {
                // Logical-view device nodes carry instance ids (`<segId>::…`) —
                // the original id lives in `data`.
                const d = node.data as TopoNode;
                if (d.kind === 'device') navigate(`/devices/${d.id.replace(/^device:/, '')}`);
              }}
            >
              <Background gap={24} size={1} />
              <Controls showInteractive={false} />
              <MiniMap
                pannable
                zoomable
                // Topology canvas palette — centralized in index.css (--topo-*);
                // TOPO_RGB mirrors those fixed values so JS can mix toward the
                // traffic accent when the overlay is on (busy nodes glow sky).
                nodeColor={(n) => {
                  if (n.type === 'band') return ((n.data as { color?: string }).color ?? 'rgb(var(--topo-unassigned))');
                  const base = n.type === 'segment' ? TOPO_RGB.segment : n.type === 'host' ? TOPO_RGB.host : n.type === 'remote' ? TOPO_RGB.remote : TOPO_RGB.node;
                  const d = n.data as { trafficBytes?: number };
                  if (!traffic || typeof d.trafficBytes !== 'number') return `rgb(${base.join(' ')})`;
                  const max = n.type === 'segment' ? traffic.maxSegment : n.type === 'host' ? traffic.maxHost : traffic.maxDevice;
                  return mixTowardTraffic(base, nodeEmphasis(d.trafficBytes, max));
                }}
              />
            </ReactFlow>
          )}
        </div>
      </div>
    </Layout>
  );
}
