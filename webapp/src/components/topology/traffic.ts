import type { FlowInventoryIp, FlowInventoryNetwork, FlowPair } from '../../api/client';

/**
 * Traffic-overlay plumbing for the topology page — pure join + scale helpers.
 *
 * The flows rollups are keyed by DEVICE / IP / LOGICAL-NETWORK identity while
 * the topology graph is keyed by node ids (`device:<id>`, `host:<mac>`,
 * `segment:<key>`). These functions bridge the two so Topology.tsx can attach
 * a per-node/per-edge byte count to React Flow's `data` without any query
 * logic. All values are sampling-extrapolated estimates — use them for
 * RELATIVE sizing only and render them as "≈".
 *
 * Colors deliberately live in the components (design tokens / --topo-*), not
 * here: this module returns numbers, never styles.
 */

/** Strip the `device:` prefix from a topology node id; null when it isn't one. */
export function deviceIdOf(nodeId: string): string | null {
  return nodeId.startsWith('device:') ? nodeId.slice('device:'.length) : null;
}

/**
 * Join device↔device pair traffic onto cable/tunnel edges. Pairs are
 * undirected here — a flow A→B and B→A both cross the same physical link, so
 * both directions sum into one edge width. Edges whose endpoints aren't both
 * known devices (remote tunnel peers) get no entry.
 */
export function joinPairTraffic(pairs: FlowPair[], edges: Array<{ id: string; source: string; target: string; kind: string }>): Map<string, number> {
  // Undirected device-pair → summed bytes.
  const byPair = new Map<string, number>();
  for (const p of pairs) {
    if (!p.srcDeviceId || !p.dstDeviceId) continue;
    const key = [p.srcDeviceId, p.dstDeviceId].sort().join('|');
    byPair.set(key, (byPair.get(key) ?? 0) + p.estBytes);
  }
  const out = new Map<string, number>();
  for (const e of edges) {
    if (e.kind !== 'cable' && e.kind !== 'tunnel') continue;
    const a = deviceIdOf(e.source);
    const b = deviceIdOf(e.target);
    if (!a || !b) continue;
    const bytes = byPair.get([a, b].sort().join('|'));
    if (bytes) out.set(e.id, bytes);
  }
  return out;
}

/**
 * Join per-IP traffic onto host nodes via their `ips[]` list. A host seen on
 * several addresses sums all of them (one machine, multiple interfaces).
 */
export function joinHostTraffic(perIp: FlowInventoryIp[], hostNodes: Array<{ id: string; ips?: string[] }>): Map<string, number> {
  const byIp = new Map<string, number>();
  for (const row of perIp) byIp.set(row.ip, (byIp.get(row.ip) ?? 0) + row.srcEstBytes + row.dstEstBytes);
  const out = new Map<string, number>();
  for (const h of hostNodes) {
    let bytes = 0;
    for (const ip of h.ips ?? []) bytes += byIp.get(ip) ?? 0;
    if (bytes > 0) out.set(h.id, bytes);
  }
  return out;
}

/**
 * Join per-network traffic onto segment nodes — the inventory `key` is exactly
 * the suffix of a topology segment id (`segment:<key>`), so the join is direct.
 */
export function joinSegmentTraffic(perNetwork: FlowInventoryNetwork[], segmentIds: string[]): Map<string, number> {
  const byKey = new Map<string, number>();
  for (const row of perNetwork) byKey.set(row.key, row.estBytes);
  const out = new Map<string, number>();
  for (const id of segmentIds) {
    if (!id.startsWith('segment:')) continue;
    const bytes = byKey.get(id.slice('segment:'.length));
    if (bytes && bytes > 0) out.set(id, bytes);
  }
  return out;
}

/** Max value across a join map — the scale ceiling for width/emphasis. */
export function maxOf(map: Map<string, number>): number {
  let m = 0;
  for (const v of map.values()) if (v > m) m = v;
  return m;
}

/** Base cable stroke in px — matches TrunkEdge's resting width. */
export const EDGE_BASE_WIDTH = 2.5;
/** Widest stroke the busiest edge gets (~3× base). */
const EDGE_MAX_WIDTH = 8;

/**
 * Stroke width for an edge carrying `bytes` against the window maximum.
 * Sqrt scale: a 100× busier link is only ~10× wider, so one dominant pair
 * doesn't swallow the diagram. Returns null when there's nothing to show
 * (no traffic in window / no data for this edge) — callers fall back to base.
 */
export function edgeWidth(bytes: number | undefined, maxBytes: number): number | null {
  if (!bytes || bytes <= 0 || !maxBytes || maxBytes <= 0) return null;
  const t = Math.sqrt(Math.min(1, bytes / maxBytes)); // 0..1, sqrt-compressed
  return EDGE_BASE_WIDTH + (EDGE_MAX_WIDTH - EDGE_BASE_WIDTH) * t;
}

/** Normalized emphasis 0..1 for a node's traffic — drives badge/MiniMap tint. */
export function nodeEmphasis(bytes: number | undefined, maxBytes: number): number {
  if (!bytes || bytes <= 0 || !maxBytes || maxBytes <= 0) return 0;
  return Math.sqrt(Math.min(1, bytes / maxBytes));
}
