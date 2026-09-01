import type React from 'react';
import { Handle, Position } from '@xyflow/react';
import clsx from 'clsx';
import type { TopologyNode as TopoNode, TopologyPort } from '../../api/client';
import { StatusBadge } from '../StatusBadge';

/**
 * Device node for the topology graph. Shows icon placeholder + name + status;
 * when the device reports port detail (switches/APs), a compact port strip is
 * rendered — trunk ports get one colored dot per VLAN (the same palette the
 * TrunkEdge uses, so dots and lines match).
 */

/** Stable hue for a VLAN id — shared with TrunkEdge via vlanHue(). */
export function vlanHue(vlanId: number): number {
  // Golden-angle spread keeps adjacent VLAN ids visually distinct.
  return Math.round((vlanId * 137.508) % 360);
}

/** Layer id → { name, color } registry for the device chip + border tint.
 * Populated by the Topology page from GET /layers (module-level so plain node
 * components can read it without prop drilling); empty = no styling. */
const layerRegistry = new Map<string, { name: string; color: string }>();
export function setLayerRegistry(layers: Array<{ id: string; name: string; color: string }>): void {
  layerRegistry.clear();
  for (const l of layers) layerRegistry.set(l.id, { name: l.name, color: l.color });
}

function layerInfo(layerId: string | undefined): { name: string; color: string } | null {
  if (!layerId) return null;
  return layerRegistry.get(layerId) ?? null;
}

function PortChip({ port }: { port: TopologyPort }) {
  const down = port.linkUp === 'down';
  return (
    <span
      title={`${port.name}${port.speed ? ` · ${port.speed}` : ''}${port.mode ? ` · ${port.mode}` : ''}${
        port.vlans.length > 0 ? ` · VLAN ${port.vlans.join(', ')}` : ''
      }${down ? ' (link down)' : ''}`}
      className={clsx(
        'flex items-center gap-1 rounded border px-1 py-px text-[9px] leading-tight',
        down ? 'border-slate-200 bg-slate-50 text-slate-400' : 'border-slate-200 bg-white text-slate-600'
      )}
    >
      <span className="font-medium">{port.name}</span>
      {port.vlans.length > 0 && (
        <span className="flex items-center gap-px">
          {port.vlans.slice(0, 8).map((v) => (
            <span key={v} className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: `hsl(${vlanHue(v)}, 70%, 45%)` }} />
          ))}
        </span>
      )}
    </span>
  );
}

/** Invisible anchor handles at the CENTER of each wall — one source AND one
 * target variant per wall (ids `ts/tt/rs/rt/bs/bt/ls/lt`). React Flow requires
 * the handle TYPE to match the edge role, so every wall needs both. They are
 * opacity-0: pure anchor points at fixed grid-aligned positions; the edge
 * mapper picks the walls from actual geometry (so an edge never loops back
 * through its own node) and offsets parallel cables perpendicular to their
 * travel direction in TrunkEdge.
 */
const WALLS: Array<{ id: string; pos: Position }> = [
  { id: 't', pos: Position.Top },
  { id: 'r', pos: Position.Right },
  { id: 'b', pos: Position.Bottom },
  { id: 'l', pos: Position.Left },
];
export function SideHandles() {
  const handles: React.ReactElement[] = [];
  for (const { id, pos } of WALLS) {
    handles.push(<Handle key={`${id}s`} id={`${id}s`} type="source" position={pos} className="!h-1 !w-1 opacity-0" />);
    handles.push(<Handle key={`${id}t`} id={`${id}t`} type="target" position={pos} className="!h-1 !w-1 opacity-0" />);
  }
  return <>{handles}</>;
}

export function DeviceNode({ data }: { data: TopoNode & { kind: 'device' } }) {
  const layer = layerInfo(data.layer);
  return (
    <div className="flex flex-col items-center gap-1">
      <SideHandles />
      <div
        className={clsx(
          'flex w-44 flex-col items-start gap-1 rounded-lg border bg-white px-2.5 py-2 shadow-sm',
          data.status === 'offline' || data.status === 'critical' ? 'border-red-300' : 'border-slate-200'
        )}
        style={layer ? { borderLeft: `3px solid ${layer.color}` } : undefined}
      >
        <div className="flex w-full items-center justify-between gap-1">
          <span className="truncate text-xs font-semibold text-slate-800" title={data.name}>
            {data.name}
          </span>
          <StatusBadge status={data.status} />
        </div>
        {layer && (
          <span
            className="rounded px-1 py-px text-[9px] font-bold uppercase tracking-wide"
            style={{ color: layer.color, backgroundColor: `${layer.color}1a` }}
          >
            {layer.name}
          </span>
        )}
        <span className="text-[10px] text-slate-400">{data.managementAddress}</span>
        {data.ports.length > 0 && (
          <div className="flex w-full flex-wrap gap-0.5">
            {/* Cap at 8 chips: keeps the node height bounded so the
                deterministic grid rows (170/150 px pitch) never overlap,
                even with long interface names that wrap into many rows. */}
            {data.ports.slice(0, 8).map((p) => (
              <PortChip key={p.name} port={p} />
            ))}
            {data.ports.length > 8 && (
              <span className="text-[9px] text-slate-400" title={data.ports.slice(8).map((p) => p.name).join(', ')}>
                +{data.ports.length - 8}
              </span>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
