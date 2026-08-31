import type { TopologyNode as TopoNode } from '../../api/client';
import { SideHandles } from './DeviceNode';

/** Compact end-host node (logical view only) — hostname or MAC + first IP. */
export function HostNode({ data }: { data: TopoNode & { kind: 'host' } }) {
  const label = data.hostname || data.mac;
  return (
    <div className="flex flex-col items-center gap-1">
      <SideHandles />
      <div className="flex w-32 flex-col items-start rounded-md border border-dashed border-slate-300 bg-slate-50 px-2 py-1">
        <span className="truncate text-[10px] font-medium text-slate-700" title={label}>
          {label}
        </span>
        {data.ips.length > 0 && (
          <span className="truncate text-[9px] text-slate-400" title={data.ips.join(', ')}>
            {data.ips[0]}
            {data.ips.length > 1 ? ` +${data.ips.length - 1}` : ''}
          </span>
        )}
      </div>
    </div>
  );
}
