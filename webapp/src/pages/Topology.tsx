import { useMemo, useState } from 'react';
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
import { api, TopologyEdge as TopoEdge, TopologyNode as TopoNode } from '../api/client';
import { DeviceNode } from '../components/topology/DeviceNode';
import { SegmentNode } from '../components/topology/SegmentNode';
import { HostNode } from '../components/topology/HostNode';
import { RemoteNode } from '../components/topology/RemoteNode';
import { TrunkEdge } from '../components/topology/TrunkEdge';

const nodeTypes = { device: DeviceNode, segment: SegmentNode, host: HostNode, remote: RemoteNode };

/** Pick the wall handles an edge should attach to, from actual layout geometry.
 * Every topology node carries invisible centered anchors on all four walls
 * (ids `ts/tt/rs/rt/bs/bt/ls/lt` — see SideHandles in DeviceNode.tsx):
 * vertical neighbors use top/bottom walls, horizontal ones left/right, so the
 * orthogonal path always travels in its direction of travel and never loops
 * back through a node. */
function handlesFor(
  e: { source: string; target: string },
  pos: Map<string, { x: number; y: number }>
): { sourceHandle: string; targetHandle: string } {
  const s = pos.get(e.source);
  const t = pos.get(e.target);
  if (s && t) {
    const dx = t.x - s.x;
    const dy = t.y - s.y;
    if (Math.abs(dy) > Math.abs(dx)) {
      return dy > 0
        ? { sourceHandle: 'bs', targetHandle: 'tt' }
        : { sourceHandle: 'ts', targetHandle: 'bt' };
    }
    if (dx < 0) return { sourceHandle: 'ls', targetHandle: 'rt' };
  }
  return { sourceHandle: 'rs', targetHandle: 'lt' };
}

/** Convert topology edges to React Flow edges. Edges sharing the SAME node
 * pair get a centered perpendicular offset index (0, ±1, ±2…) so parallel
 * cables run as distinct grid-aligned lines instead of overlapping; wall
 * handles come from layout geometry. */
function assignParallel(edges: TopoEdge[], posMap: Map<string, { x: number; y: number }>): FlowEdge[] {
  const counts = new Map<string, number>();
  for (const e of edges) {
    const key = [e.source, e.target].sort().join('|');
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const seen = new Map<string, number>();
  return edges.map((e) => {
    const key = [e.source, e.target].sort().join('|');
    const i = seen.get(key) ?? 0;
    seen.set(key, i + 1);
    const total = counts.get(key)!;
    return {
      id: e.id,
      source: e.source,
      target: e.target,
      type: 'trunk',
      data: { ...e, parallelIndex: i - (total - 1) / 2 },
      ...handlesFor(e, posMap),
    };
  });
}
// One custom edge renderer handles all kinds (cable/tunnel/membership) — it
// reads the kind + VLAN list from `data` and picks its rendering.
const edgeTypes = { trunk: TrunkEdge };

type ViewMode = 'physical' | 'logical';

type DeviceTopoNode = TopoNode & { kind: 'device' };

/** Deterministic O(n) layout for the PHYSICAL view: one grid per site,
 * devices name-sorted within their cluster. No force simulation — stable
 * between refreshes and fast at any scale. */
function layoutPhysical(devices: TopoNode[]): FlowNode[] {
  const bySite = new Map<string, DeviceTopoNode[]>();
  for (const d of devices) {
    if (d.kind !== 'device') continue;
    const key = d.siteId ?? '__none';
    let list = bySite.get(key);
    if (!list) {
      list = [];
      bySite.set(key, list);
    }
    list.push(d);
  }
  // Named sites alphabetically first (by their id — names are resolved in the
  // header), unassigned cluster last.
  const siteKeys = Array.from(bySite.keys()).sort((a, b) => {
    if (a === '__none') return 1;
    if (b === '__none') return -1;
    return a.localeCompare(b);
  });

  const NODE_W = 200;
  const GAP_X = 80;
  const ROW_H = 170;
  const COLS = 4;
  let y = 0;
  const nodes: FlowNode[] = [];
  for (const key of siteKeys) {
    const list = bySite.get(key)!;
    list.sort((a, b) => a.name.localeCompare(b.name));
    for (let i = 0; i < list.length; i++) {
      const col = i % COLS;
      nodes.push({ id: list[i].id, type: 'device', position: { x: col * (NODE_W + GAP_X), y }, data: list[i] });
    }
    const rows = Math.max(1, Math.ceil(list.length / COLS));
    y += rows * ROW_H + 70; // cluster spacing
  }
  // Remote (unmanaged) tunnel peers — one row below the site clusters so their
  // dashed tunnel edges have something to attach to.
  const remotes = devices.filter((d): d is TopoNode & { kind: 'remote' } => d.kind === 'remote');
  if (remotes.length > 0) {
    y += 40;
    for (let i = 0; i < remotes.length; i++) {
      const col = i % COLS;
      const row = Math.floor(i / COLS);
      nodes.push({ id: remotes[i].id, type: 'remote', position: { x: col * (NODE_W + GAP_X), y: y + row * ROW_H }, data: remotes[i] });
    }
  }
  return nodes;
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

export default function Topology() {
  const navigate = useNavigate();
  const [view, setView] = useState<ViewMode>('physical');
  const [showHosts, setShowHosts] = useState(false);
  const [siteId, setSiteId] = useState('');
  const [segmentKey, setSegmentKey] = useState('all');

  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: () => api.sites() });
  // includeHosts is only consumed in the logical view; requesting it always
  // keeps a single cache entry per (site, hosts) pair.
  const topoQuery = useQuery({
    queryKey: ['topology', siteId || null, showHosts],
    queryFn: () => api.topology({ siteId: siteId || undefined, includeHosts: showHosts }),
    refetchInterval: 30_000, // matches the telemetry poll cadence
  });

  const { rfNodes, rfEdges } = useMemo(() => {
    const data = topoQuery.data;
    if (!data) return { rfNodes: [] as FlowNode[], rfEdges: [] as FlowEdge[] };

    // Edges attach to the node's centered wall handles (see SideHandles in
    // DeviceNode.tsx); walls come from layout geometry, parallel cables get a
    // deterministic perpendicular offset per node pair.
    const posMap = new Map<string, { x: number; y: number }>();

    if (view === 'physical') {
      const laidNodes = layoutPhysical(data.nodes);
      for (const n of laidNodes) posMap.set(n.id, n.position);
      return {
        rfNodes: laidNodes,
        rfEdges: assignParallel(data.edges.filter((e) => e.kind === 'cable' || e.kind === 'tunnel'), posMap),
      };
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

    const laid = layoutLogical(visibleSegments, membersBySegment);
    for (const n of laid.nodes) posMap.set(n.id, n.position);
    // Point each membership edge at the member's instance node in ITS block.
    const remapped = memberEdges.map((e) => ({ ...e, source: laid.memberSourceIds.get(`${e.target}|${e.source}`) ?? e.source }));
    return {
      rfNodes: laid.nodes,
      rfEdges: assignParallel(remapped, posMap),
    };
  }, [topoQuery.data, view, segmentKey, showHosts]);

  const segments = useMemo(
    () => (topoQuery.data?.nodes ?? []).filter((n): n is TopoNode & { kind: 'segment' } => n.kind === 'segment'),
    [topoQuery.data]
  );

  return (
    <Layout>
      <div className="flex h-full flex-col gap-3">
        {/* Header controls */}
        <div className="flex flex-wrap items-center gap-2">
          <h1 className="mr-2 text-lg font-bold text-slate-900">Topology</h1>

          {/* Physical | Logical toggle */}
          <div className="inline-flex rounded-md border border-slate-300 bg-white p-0.5">
            {(['physical', 'logical'] as ViewMode[]).map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className={clsx(
                  'rounded px-3 py-1 text-xs font-medium capitalize transition-colors',
                  view === v ? 'bg-slate-900 text-white' : 'text-slate-600 hover:bg-slate-100'
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
            className="rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700"
          >
            <option value="">All sites</option>
            {(sitesQuery.data ?? []).map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </select>

          {/* Segment focus (logical view only) */}
          {view === 'logical' && (
            <>
              <select
                value={segmentKey}
                onChange={(e) => setSegmentKey(e.target.value)}
                className="max-w-56 rounded-md border border-slate-300 bg-white px-2 py-1 text-xs text-slate-700"
              >
                <option value="all">All segments</option>
                {segments.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.vlanId !== null ? `VLAN ${s.vlanId}` : s.label}
                  </option>
                ))}
              </select>
              <label className="flex cursor-pointer items-center gap-1.5 text-xs text-slate-600">
                <input type="checkbox" checked={showHosts} onChange={(e) => setShowHosts(e.target.checked)} />
                Show hosts
              </label>
            </>
          )}

          {/* Legend */}
          <div className="ml-auto flex items-center gap-3 text-[10px] text-slate-500">
            {view === 'physical' ? (
              <>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-0.5 w-4 bg-slate-400" /> cable (inferred)
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-0.5 w-4 border-t-2 border-dashed border-slate-500" /> tunnel
                </span>
                <span className="flex items-center gap-1">
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
                  <span className="inline-block h-1.5 w-1.5 rounded-full bg-orange-500" /> per-VLAN trunk line
                </span>
              </>
            ) : (
              <span>segment = merged logical network (VLAN/subnet)</span>
            )}
          </div>
        </div>

        {/* Graph */}
        <div className="min-h-0 flex-1 overflow-hidden rounded-lg border border-slate-200 bg-white">
          {topoQuery.isLoading ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-400">Computing topology…</div>
          ) : rfNodes.length === 0 ? (
            <div className="flex h-full items-center justify-center text-sm text-slate-400">No devices to display.</div>
          ) : (
            <ReactFlow
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={nodeTypes}
              edgeTypes={edgeTypes}
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
                nodeColor={(n) =>
                  n.type === 'segment'
                    ? '#6366f1'
                    : n.type === 'host'
                      ? '#cbd5e1'
                      : n.type === 'remote'
                        ? '#a5b4fc'
                        : '#334155'
                }
              />
            </ReactFlow>
          )}
        </div>
      </div>
    </Layout>
  );
}
