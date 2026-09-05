import type { TopologyNode as TopoNode } from '../../api/client';
import { SideHandles } from './DeviceNode';

/**
 * Segment node for the LOGICAL view — one merged logical network (VLAN/subnet
 * group). The border color is a stable hue derived from the segment key so the
 * same VLAN always gets the same color across renders.
 */

export function segmentHue(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) % 360;
  return h;
}

export function SegmentNode({ data }: { data: TopoNode & { kind: 'segment' } }) {
  const hue = segmentHue(data.id);
  return (
    <div className="flex flex-col items-center gap-1">
      <SideHandles />
      <div
        className="flex w-48 flex-col items-start gap-0.5 rounded-lg border-2 bg-card px-2.5 py-2 shadow-sm"
        style={{ borderColor: `hsl(${hue}, 65%, 55%)` }}
      >
        <span className="text-[9px] font-semibold uppercase tracking-wide text-faint">Logical network</span>
        <span className="truncate text-xs font-semibold text-foreground" title={data.label}>
          {data.vlanId !== null ? `VLAN ${data.vlanId}` : data.label}
        </span>
        {data.subnets.length > 0 && (
          <span className="break-all text-[10px] leading-tight text-muted-foreground">{data.subnets.join(' · ')}</span>
        )}
      </div>
    </div>
  );
}
