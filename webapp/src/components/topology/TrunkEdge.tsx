import { useState } from 'react';
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, Position } from '@xyflow/react';
import type { EdgeProps } from '@xyflow/react';

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
/** Perpendicular spacing for parallel edges between the same node pair.
 * Must exceed a trunk's per-VLAN fan width (≤3 VLANs × 3px ≈ 9px) so two
 * adjacent bundled cables keep their lines distinct instead of merging into
 * one thick bar. */
const PARALLEL_OFFSET_PX = 24;

function vlanHue(vlanId: number): number {
  return Math.round((vlanId * 137.508) % 360);
}

/** Orthogonal path + label anchor for one edge, from actual node geometry.
 * `parallelIndex` (0-based, assigned per node-pair in Topology.tsx) shifts the
 * whole route perpendicular to its travel direction so same-pair cables don't
 * draw on top of each other. */
/** Rounded orthogonal step path: vertical → horizontal (at bendY) → vertical.
 * Used for vertical-dominant cables so each edge's jog sits at its own height. */
function stepPath(sx: number, sy: number, tx: number, ty: number, bendY: number): string {
  const r = 6;
  const vy1 = Math.sign(bendY - sy) || 1;
  const vy2 = Math.sign(ty - bendY) || 1;
  const vx = Math.sign(tx - sx) || 1;
  return [
    `M ${sx} ${sy}`,
    `L ${sx} ${bendY - vy1 * r}`,
    `Q ${sx} ${bendY} ${sx + vx * r} ${bendY}`,
    `L ${tx - vx * r} ${bendY}`,
    `Q ${tx} ${bendY} ${tx} ${bendY + vy2 * r}`,
    `L ${tx} ${ty}`,
  ].join(' ');
}

/** Rounded orthogonal step path: horizontal → vertical (at bendX) → horizontal.
 * Mirror of stepPath for horizontal-dominant cables. */
function stepPathH(sx: number, sy: number, tx: number, ty: number, bendX: number): string {
  const r = 6;
  const vx1 = Math.sign(bendX - sx) || 1;
  const vx2 = Math.sign(tx - bendX) || 1;
  const vy = Math.sign(ty - sy) || 1;
  return [
    `M ${sx} ${sy}`,
    `L ${bendX - vx1 * r} ${sy}`,
    `Q ${bendX} ${sy} ${bendX} ${sy + vy * r}`,
    `L ${bendX} ${ty - vy * r}`,
    `Q ${bendX} ${ty} ${bendX + vx2 * r} ${ty}`,
    `L ${tx} ${ty}`,
  ].join(' ');
}

/** Orthogonal path + label anchor for one edge, from actual node geometry.
 * `parallelIndex` (0-based, per node-pair) shifts the route perpendicular to its
 * travel so same-pair cables don't overlap; `bendOffset` (per edge, from
 * Topology.tsx withBendOffsets) moves a vertical cable's horizontal jog off the
 * shared midpoint line so bundles read as ladders instead of merging. */
function routeEdge(
  sourceX: number,
  sourceY: number,
  targetX: number,
  targetY: number,
  parallelIndex: number,
  bendOffset: number,
  corridorY?: number | null
): { line: string; cx: number; cy: number } {
  const dx = targetX - sourceX;
  const dy = targetY - sourceY;

  // Same column (logical view / stacked nodes) — straight vertical line.
  if (Math.abs(dx) < 1 && Math.abs(dy) > 1) {
    return { line: `M ${sourceX} ${sourceY} L ${targetX} ${targetY}`, cx: sourceX, cy: (sourceY + targetY) / 2 };
  }

  // Perpendicular offset for parallel edges between the same pair —
  // `parallelIndex` is centered around 0 by Topology.tsx ((i - (n-1)/2)).
  const off = parallelIndex * PARALLEL_OFFSET_PX;

  // Same-wall detour (both ends on bottom or top wall): U-shape through the
  // corridor line so the run clears every intermediate card — a straight
  // segment between two bottom-wall points would still cut across taller cards.
  if (Math.abs(dx) >= Math.abs(dy) && typeof corridorY === 'number') {
    const dir = dy > 0 ? 1 : -1; // both ends below → drop down, above → rise up
    const sy = sourceY + dir * 2;
    const ty = targetY + dir * 2;
    if (Math.abs(sourceX - targetX) < 1) {
      return { line: `M ${sourceX} ${sy} L ${targetX} ${ty}`, cx: sourceX, cy: corridorY };
    }
    // The corridor sits OUTSIDE the endpoint span by design — no clamping.
    const bendY = corridorY;
    return { line: stepPath(sourceX, sy, targetX, ty, bendY), cx: (sourceX + targetX) / 2, cy: bendY };
  }

  if (Math.abs(dx) >= Math.abs(dy)) {
    // Horizontal neighbors — leave/enter the SIDE walls. Each edge gets its
    // own bend X so vertical jogs never share a line; same-pair cables also
    // keep their Y offset → clean ladders.
    const dir = dx > 0 ? 1 : -1;
    const sx = sourceX + dir * 2;
    const tx = targetX - dir * 2;
    const sy = sourceY + off;
    const ty = targetY + off;
    if (Math.abs(sy - ty) < 1) {
      return { line: `M ${sx} ${sy} L ${tx} ${ty}`, cx: (sx + tx) / 2, cy: sy }; // straight
    }
    const lo = Math.min(sx, tx);
    const hi = Math.max(sx, tx);
    let bendX = (sx + tx) / 2 + bendOffset;
    bendX = Math.max(lo + 8, Math.min(hi - 8, bendX)); // keep the jog inside the span
    return { line: stepPathH(sx, sy, tx, ty, bendX), cx: bendX, cy: (sy + ty) / 2 };
  }

  // Vertical neighbors — leave/enter the TOP/BOTTOM walls. Each edge gets its
  // own bend height so horizontal jogs never share a line; same-pair cables
  // also keep their X offset → clean ladders.
  const dir = dy > 0 ? 1 : -1;
  const sx = sourceX + off;
  const tx = targetX + off;
  const sy = sourceY + dir * 2;
  const ty = targetY - dir * 2;
  if (Math.abs(sx - tx) < 1) {
    return { line: `M ${sx} ${sy} L ${tx} ${ty}`, cx: sx, cy: (sy + ty) / 2 }; // straight
  }
  const lo = Math.min(sy, ty);
  const hi = Math.max(sy, ty);
  let bendY = (sy + ty) / 2 + bendOffset;
  bendY = Math.max(lo + 8, Math.min(hi - 8, bendY)); // keep the jog inside the span
  return { line: stepPath(sx, sy, tx, ty, bendY), cx: (sx + tx) / 2, cy: bendY };
}

export function TrunkEdge({ id, sourceX, sourceY, targetX, targetY, data }: EdgeProps) {
  const kind = (data?.kind as string | undefined) ?? 'cable';
  const vlans: number[] = Array.isArray(data?.vlans) ? (data.vlans as number[]) : [];
  const via = (data?.via as string | undefined) ?? '';
  const portA = (data?.portA as string | undefined) ?? null;
  const portB = (data?.portB as string | undefined) ?? null;
  const tunnelType = (data?.type as string | undefined) ?? '';
  const parallelIndex: number = typeof data?.parallelIndex === 'number' ? data.parallelIndex : 0;
  // Per-edge jog position (Topology.tsx withBendOffsets) — keeps jogs on
  // distinct lines so bundles don't merge or tangle. Vertical cables get a
  // bend Y, horizontal ones a bend X.
  const verticalTravel = Math.abs(targetY - sourceY) > Math.abs(targetX - sourceX);
  const rawBend: unknown = verticalTravel ? data?.bendOffset : data?.bendXOffset;
  const bendOffset: number = typeof rawBend === 'number' ? rawBend : 0;
  // Collapsed same-pair tunnels render a count badge instead of N dashed lines.
  const tunnelCount: number = typeof data?.tunnelCount === 'number' ? (data.tunnelCount as number) : 1;
  // Corridor line for same-wall detour edges (Topology.tsx handlesFor).
  const corridorY: number | null = typeof data?.corridorY === 'number' ? (data.corridorY as number) : null;
  const { line, cx, cy } = routeEdge(sourceX, sourceY, targetX, targetY, parallelIndex, bendOffset, corridorY);

  /** Perpendicular spacing between the per-VLAN lines of one trunk — kept
   * tight so a bundled cable's fan stays narrower than PARALLEL_OFFSET_PX. */
  const VLAN_LINE_SPACING_PX = 3;

  const strokeFor = (v: number) => `hsl(${vlanHue(v)}, 70%, 45%)`;

  let label = '';
  if (kind === 'cable') {
    label = [portA, portB].filter(Boolean).join(' ↔ ') + (via ? ` (${via})` : '');
  } else if (kind === 'tunnel') {
    label = tunnelCount > 1 ? `${tunnelType} ×${tunnelCount}` : tunnelType;
  }

  return (
    <>
      {vlans.length > 1 && vlans.length <= MAX_PARALLEL_LINES ? (
        // One thin line per VLAN, fanned perpendicular to the travel direction
        // (the offsets were previously computed but never applied — all lines
        // drew on top of each other and only the last hue was visible).
        <g>
          {vlans.map((v, i) => {
            const total = (vlans.length - 1) * VLAN_LINE_SPACING_PX;
            const off = i * VLAN_LINE_SPACING_PX - total / 2;
            return (
              // Fan perpendicular to travel (same axis as the crossing offset).
              <g key={v} transform={verticalTravel ? `translate(${off}, 0)` : `translate(0, ${off})`}>
                <BaseEdge id={`${id}-vlan-${v}`} path={line} style={{ stroke: strokeFor(v), strokeWidth: 2 }} />
              </g>
            );
          })}
        </g>
      ) : vlans.length > MAX_PARALLEL_LINES ? (
            // Collapsed trunk: one line with a multi-stop gradient across the VLAN hues.
            <BaseEdge id={`${id}-trunk`} path={line} style={{ stroke: `url(#${gradId(id)})`, strokeWidth: 3 }} />
          ) : (
            <BaseEdge
              id={id}
              path={line}
              style={{
                // Topology canvas palette — centralized in index.css (--topo-*).
                stroke: kind === 'tunnel' ? 'rgb(var(--topo-tunnel))' : 'rgb(var(--topo-cable))',
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
          {/* Hover-to-expand: a permanent label per edge would cover the lines
              in dense corridors, so the resting state is a tiny dot marker —
              hovering it grows into the full cable detail. */}
          <EdgeChip cx={cx} cy={cy} full={`${label}${
            vlans.length > 0 ? ` · VLAN ${vlans.slice(0, 6).join(', ')}${vlans.length > 6 ? ` +${vlans.length - 6}` : ''}` : ''
          }`} />
        </EdgeLabelRenderer>
      )}
    </>
  );
}

/** SVG ids must be unique and valid — sanitize the edge id for gradient refs. */
function gradId(edgeId: string): string {
  return `trunk-grad-${edgeId.replace(/[^a-zA-Z0-9_-]/g, '')}`;
}

/** Tiny resting dot that expands to the full cable detail on hover.
 * EdgeLabelRenderer already applies the viewport transform — only the local
 * centering translate lives here. The invisible padding keeps a comfortable
 * hit area around the small marker. */
function EdgeChip({ cx, cy, full }: { cx: number; cy: number; full: string }) {
  const [hover, setHover] = useState(false);
  return (
    <div
      className="pointer-events-auto absolute z-10 flex h-4 w-4 cursor-default items-center justify-center"
      style={{ transform: `translate(-50%, -50%) translate(${cx}px, ${cy}px)` }}
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
    >
      {hover ? (
        <div className="max-w-[300px] whitespace-nowrap rounded border border-border bg-card/95 px-1.5 py-0.5 text-[9px] leading-tight text-secondary shadow-sm">
          {full}
        </div>
      ) : (
        <span className="block h-1.5 w-1.5 rounded-full bg-status-neutral" />
      )}
    </div>
  );
}
