import type { TopologyNode as TopoNode } from '../../api/client';
import { SideHandles } from './DeviceNode';
import { TrafficBadge } from './TrafficBadge';

/** Compact end-host node (logical view only) — hostname or MAC + first IP. */
export function HostNode({ data }: { data: (TopoNode & { kind: 'host' }) & { trafficBytes?: number } }) {
  const label = data.hostname || data.mac;
  return (
    <div className="flex flex-col items-center gap-1">
      <SideHandles />
      <div className="flex w-32 flex-col items-start rounded-md border border-dashed border-border bg-background px-2 py-1">
        <span className="truncate text-[10px] font-medium text-secondary" title={label}>
          {label}
        </span>
        {data.ips.length > 0 && (
          <span className="truncate text-[9px] text-faint" title={data.ips.join(', ')}>
            {data.ips[0]}
            {data.ips.length > 1 ? ` +${data.ips.length - 1}` : ''}
          </span>
        )}
        {/* Traffic overlay — per-IP sum over the window (fits the 90px host pitch). */}
        {typeof data.trafficBytes === 'number' && data.trafficBytes > 0 && <TrafficBadge bytes={data.trafficBytes} />}
      </div>
    </div>
  );
}
