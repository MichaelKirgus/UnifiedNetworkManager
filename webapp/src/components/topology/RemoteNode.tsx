import { Handle, Position } from '@xyflow/react';
import type { TopologyNode as TopoNode } from '../../api/client';

/** Remote (unmanaged) tunnel peer — e.g. a WireGuard endpoint on the public
 * internet that is not part of this UNM inventory. */
export function RemoteNode({ data }: { data: TopoNode & { kind: 'remote' } }) {
  return (
    <div className="flex flex-col items-center gap-1">
      <Handle type="target" position={Position.Top} className="!h-1.5 !w-1.5 !border-slate-300 !bg-white" />
      <div className="flex w-40 flex-col items-start rounded-md border border-dashed border-indigo-300 bg-indigo-50 px-2 py-1">
        <span className="truncate text-[10px] font-medium text-indigo-700" title={data.label}>
          {data.label}
        </span>
      </div>
    </div>
  );
}
