/** One device reporting/observing something in a cross-device view (Hosts, Networks).
 * Device name on top; interface names as wrapping mono mini-tags below — long
 * lists (e.g. 30+ VLANs) wrap to new lines instead of stretching the table row. */
export function DeviceChip({
  deviceName,
  managementAddress,
  pluginName,
  siteName,
  extraTooltip = [],
  interfaces,
}: {
  deviceName?: string | null;
  managementAddress?: string | null;
  pluginName?: string | null;
  siteName?: string | null;
  /** Extra tooltip lines (e.g. MAC / status on the Networks page). */
  extraTooltip?: string[];
  interfaces: string[];
}) {
  const title = [
    deviceName,
    managementAddress ? `(${managementAddress})` : '',
    pluginName ?? '',
    siteName ? `site: ${siteName}` : '',
    ...extraTooltip,
  ]
    .filter(Boolean)
    .join(' · ');
  return (
    <span
      title={title}
      className="inline-flex max-w-[260px] flex-col gap-0.5 rounded border border-slate-200 bg-white px-1.5 py-1 text-xs"
    >
      <span className="truncate font-medium text-slate-700">{deviceName ?? '—'}</span>
      {interfaces.length > 0 && (
        <span className="flex flex-wrap gap-x-1 gap-y-0.5">
          {interfaces.map((i) => (
            <span key={i} className="rounded bg-slate-100 px-1 font-mono text-[10px] leading-4 text-slate-600">
              {i}
            </span>
          ))}
        </span>
      )}
    </span>
  );
}
