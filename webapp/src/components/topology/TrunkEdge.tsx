import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath } from '@xyflow/react';
import type { EdgeProps, Position } from '@xyflow/react';

/**
 * Cable edge for the topology graph. A plain link renders as one slate line; a
 * TRUNK port (edge.vlans non-empty) renders ONE thin parallel line per VLAN —
 * each with its own stable hue, so "each VLAN a dedicated line" holds even
 * when several VLANs share the same cable. More than 4 VLANs collapse into a
 * single multi-stop gradient line to keep dense switches readable (the full
 * list stays in the tooltip). Tunnels render dashed; membership edges are thin
 * and neutral.
 *
 * Routing: ORTHOGONAL smooth-step paths along the grid axes — horizontal
 * neighbors connect side-to-side, vertical ones top/bottom — so lines follow
 * the layout's rows/columns instead of cutting diagonally under nodes. No
 * random slots or bezier bows: everything is deterministic and aligned with
 * the node grid. Parallel cables between the SAME node pair are offset
 * perpendicular to their direction (data.parallelIndex) so they run as
 * distinct parallel lines.
 */

const MAX_PARALLEL_LINES = 4;
/** Perpendicular spacing for parallel edges between the same node pair. */
const PARALLEL_OFFSET_PX = 7;

function vlanHue(vlanId: number): number {
  return Math.round((vlanId * 137.508) % 360);
}

/** Orthogonal path + label anchor for one edge, from actual node geometry.
 * `parallelIndex` (0-based, assigned per node-pair in Topology.tsx) shifts the
 * whole route perpendicular to its travel direction so same-pair cables don't
 * draw on top of each other. */
function routeEdge(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  parallelIndex: number
): { line: string; cx: number; cy: number } {
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;

  // Same column (logical view: member directly below/above its segment) —
  // straight vertical line.
  if (Math.abs(dx) < 1 && Math.abs(dy) > 1) {
    return { line: `M ${sourceX} ${sourceY} L ${targetX} ${targetY}`, cx: sourceX, cy: (sourceY + targetY) / 2 };
  }

  // Perpendicular offset for parallel edges between the same pair —
  // `parallelIndex` is centered around 0 by Topology.tsx ((i - (n-1)/2)).
  const off = parallelIndex * PARALLEL_OFFSET_PX;
  let sx = sourceX;
  let sy = sourceY;
  let tx = targetX;
  let ty = targetY;
  let sp: Position;
  let tp: Position;

  if (Math.abs(dx) >= Math.abs(dy)) {
    // Horizontal neighbors — leave/enter the SIDE walls.
    const dir = dx > 0 ? 1 : -1;
    sx += dir * 2;
    tx -= dir * 2;
    sy += off;
    ty += off;
    sp = dir > 0 ? Position.Right : Position.Left;
    tp = dir > 0 ? Position.Left : Position.Right;
  } else {
    // Vertical neighbors — leave/enter the TOP/BOTTOM walls.
    const dir = dy > 0 ? 1 : -1;
    sy += dir * 2;
    ty -= dir * 2;
    sx += off;
    tx += off;
    sp = dir > 0 ? Position.Bottom : Position.Top;
    tp = dir > 0 ? Position.Top : Position.Bottom;
  }

  const [line] = getSmoothStepPath({ sourceX: sx, sourceY: sy, targetX: tx, targetY: ty, sourcePosition: sp, targetPosition: tp });
  return { line, cx: (sx + tx) / 2, cy: (sy + ty) / 2 };
}

export function TrunkEdge({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps) {
  const kind = (data?.kind as string | undefined) ?? 'cable';
  const vlans: number[] = Array.isArray(data?.vlans) ? (data.vlans as number[]) : [];
  const via = (data?.via as string | undefined) ?? '';
  const portA = (data?.portA as string | undefined) ?? null;
  const portB = (data?.portB as string | undefined) ?? null;
  const tunnelType = (data?.type as string | undefined) ?? '';
  const parallelIndex: number = typeof data?.parallelIndex === 'number' ? data.parallelIndex : 0;

  const { line, cx, cy } = routeEdge(sourceX, sourceY, targetX, targetY, parallelIndex);

  // Perpendicular offset for each parallel VLAN line.
  const offsets: number[] = [];
  if (vlans.length > 1 && vlans.length <= MAX_PARALLEL_LINES) {
    const step = 5;
    const total = (vlans.length - 1) * step;
    for (let i = 0; i < vlans.length; i++) offsets.push(i * step - total / 2);
  }

  const strokeFor = (v: number) => `hsl(${vlanHue(v)}, 70%, 45%)`;

  let label = '';
  if (kind === 'cable') {
    label = [portA, portB].filter(Boolean).join(' ↔ ') + (via ? ` (${via})` : '');
  } else if (kind === 'tunnel') {
    label = tunnelType;
  }

  return (
    <>
      {vlans.length > 1 && vlans.length <= MAX_PARALLEL_LINES
        ? vlans.map((v, i) => (
            <BaseEdge key={i} id={`${id}-vlan-${v}`} path={line} style={{ stroke: strokeFor(v), strokeWidth: 2 }} />
          ))
        : vlans.length > MAX_PARALLEL_LINES ? (
            // Collapsed trunk: one line with a multi-stop gradient across the VLAN hues.
            <BaseEdge id={`${id}-trunk`} path={line} style={{ stroke: `url(#${gradId(id)})`, strokeWidth: 3 }} />
          ) : (
            <BaseEdge
              id={id}
              path={line}
              style={{
                stroke: kind === 'tunnel' ? '#64748b' : '#94a3b8',
                strokeWidth: kind === 'cable' ? 2.5 : 1,
                strokeDasharray: kind === 'tunnel' ? '6 4' : undefined,
              }}
            />
          )}

      {vlans.length > MAX_PARALLEL_LINES && (
        <defs>
          <linearGradient id={gradId(id)} x1="0%" y1="0%" x2="100%" y2="0%">
            {vlans.map((v, i) => (
              <stop key={v} offset={`${(i / Math.max(1, vlans.length - 1)) * 100}%`} stopColor={strokeFor(v)} />
            ))}
          </linearGradient>
        </defs>
      )}

      {label && (
        <EdgeLabelRenderer>
          <div
            className="pointer-events-none absolute rounded bg-white/90 px-1 text-[9px] leading-tight text-slate-500"
            style={{ transform: `translate(-50%, -50%) translate(${cx}px, ${cy}px)` }}
          >
            {label}
            {vlans.length > 0 && (
              <span className="ml-1">
                VLAN {vlans.slice(0, 6).join(', ')}
                {vlans.length > 6 ? ` +${vlans.length - 6}` : ''}
              </span>
            )}
          </div>
        </EdgeLabelRenderer>
      )}
    </>
  );
}

/** SVG ids must be unique and valid — sanitize the edge id for gradient refs. */
function gradId(edgeId: string): string {
  return `trunk-grad-${edgeId.replace(/[^a-zA-Z0-9_-]/g, '')}`;
}
