import { useState } from 'react';
import type { TopologyNode as TopoNode } from '../../api/client';
import { formatBytes } from '../formatMetric';

/**
 * Node renderers for the TOPOLOGY "Hosts" net view (force-directed):
 *  - HubNode: a segment hub — colored ring in the segment hue with its member
 *    count; the anchor every host dot orbits.
 *  - ApNode: an access point that owns WLAN clients in this view — compact
 *    card so its dashed client links have something to attach to.
 *  - NetHostNode: one host as a traffic-sized dot (radius from layout) with a
 *    short label; click toggles an inline detail popover (MAC, IPs, ≈ bytes).
 */

/** Segment hue — same hash as the logical view's segment cards. */
function hubHue(key: string): number {
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) % 360;
  return h;
}

export function HubNode({ data }: { data: (TopoNode & { kind: 'segment' }) & { memberCount?: number } }) {
  const hue = hubHue(data.id);
  const label = data.vlanId !== null ? `VLAN ${data.vlanId}` : data.label;
  return (
    <div className="flex flex-col items-center gap-0.5">
      <div
        className="flex h-[68px] w-[68px] items-center justify-center rounded-full border-2 bg-card shadow-sm"
        style={{ borderColor: `hsl(${hue}, 65%, 55%)` }}
        title={`${label} — ${data.memberCount ?? 0} hosts`}
      >
        <span className="text-[10px] font-bold leading-tight text-secondary">{data.memberCount ?? 0}</span>
      </div>
      <span className="max-w-28 truncate rounded bg-card/90 px-1 text-[9px] font-semibold" style={{ color: `hsl(${hue}, 65%, 45%)` }} title={label}>
        {label}
      </span>
    </div>
  );
}

export function ApNode({ data }: { data: TopoNode & { kind: 'device' } }) {
  return (
    <div className="flex flex-col items-center gap-0.5">
      <div className="flex h-[42px] w-16 flex-col items-center justify-center rounded-md border border-border bg-card px-1 shadow-sm" title={data.name}>
        <span className="text-[8px] font-bold uppercase tracking-wide text-faint">AP</span>
        <span className="max-w-full truncate text-[9px] font-semibold text-secondary">{data.name}</span>
      </div>
    </div>
  );
}

export function NetHostNode({ data }: { data: (TopoNode & { kind: 'host' }) & { r?: number; trafficBytes?: number } }) {
  const [open, setOpen] = useState(false);
  const label = data.hostname || data.mac;
  const r = data.r ?? 10;
  return (
    <div className="relative flex items-center gap-1.5" onClick={() => setOpen((o) => !o)}>
      {/* Traffic-sized dot — radius comes from the layout's traffic ranking. */}
      <span
        className="block cursor-pointer rounded-full bg-topo-host shadow-sm ring-1 ring-border transition-transform hover:scale-110"
        style={{ width: r * 2, height: r * 2 }}
        title={label}
      />
      <span className="max-w-36 truncate text-[9px] leading-none text-secondary">{label}</span>

      {open && (
        // Inline detail popover — the Hosts page has no focus param, so the
        // deep link stays there; this covers the quick-glance case.
        <div className="absolute left-0 top-full z-20 mt-1 w-56 rounded-md border border-border bg-card p-2 text-[10px] shadow-lg">
          <div className="mb-1 flex items-center justify-between gap-2">
            <span className="truncate font-semibold text-foreground" title={label}>
              {label}
            </span>
            {typeof data.trafficBytes === 'number' && data.trafficBytes > 0 && (
              <span className="shrink-0 rounded bg-topo-traffic/15 px-1 py-px font-semibold tabular-nums text-topo-traffic">≈ {formatBytes(data.trafficBytes)}</span>
            )}
          </div>
          <dl className="space-y-0.5 text-secondary">
            <div className="flex justify-between gap-2">
              <dt className="text-faint">MAC</dt>
              <dd className="truncate font-mono">{data.mac}</dd>
            </div>
            {data.ips.map((ip) => (
              <div key={ip} className="flex justify-between gap-2">
                <dt className="shrink-0 text-faint">IP</dt>
                <dd className="truncate font-mono">{ip}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}
    </div>
  );
}
