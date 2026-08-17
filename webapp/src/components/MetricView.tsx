import { MetricDescriptor } from '../api/client';
import { formatValue } from './formatMetric';

/**
 * Generic metric renderer. Renders a single metric according to its
 * descriptor's `visualization` hint (gauge | plot | text | table). This is the
 * extensible UI: the webapp has NO per-plugin or per-metric code — it is driven
 * entirely by the descriptors a plugin declares in /discover.
 *
 *   value     the current value for this metric (from telemetry.metrics)
 *   history   optional time series for 'plot' (oldest → newest)
 */
export function MetricView({
  descriptor,
  value,
  history,
}: {
  descriptor: MetricDescriptor;
  value?: unknown;
  history?: { collectedAt: string; value: number }[];
}) {
  switch (descriptor.visualization) {
    case 'gauge':
      return <Gauge descriptor={descriptor} value={value} />;
    case 'plot':
      return <Plot descriptor={descriptor} history={history} />;
    case 'table':
      return <MetricTable descriptor={descriptor} value={value} />;
    case 'text':
    default:
      return <MetricText descriptor={descriptor} value={value} />;
  }
}

function MetricText({ descriptor, value }: { descriptor: MetricDescriptor; value?: unknown }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
      <p className="text-xs uppercase tracking-wide text-slate-400">{descriptor.label}</p>
      <p className="mt-1 text-2xl font-semibold text-slate-900">{formatValue(value, descriptor.unit, descriptor.format)}</p>
    </div>
  );
}

function Gauge({ descriptor, value }: { descriptor: MetricDescriptor; value?: unknown }) {
  const min = descriptor.min ?? 0;
  const max = descriptor.max ?? 100;
  const num = typeof value === 'number' ? value : 0;
  const clamped = Math.max(min, Math.min(max, num));
  const pct = max > min ? ((clamped - min) / (max - min)) * 100 : 0;
  const color = descriptor.color ?? '#3b82f6';

  return (
    <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-baseline justify-between">
        <p className="text-xs uppercase tracking-wide text-slate-400">{descriptor.label}</p>
        <p className="text-lg font-semibold text-slate-900">{formatValue(value, descriptor.unit, descriptor.format)}</p>
      </div>
      <div className="mt-3 h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${pct}%`, backgroundColor: color }}
        />
      </div>
      <div className="mt-1 flex justify-between text-[10px] text-slate-400">
        <span>{min}</span>
        <span>{max}</span>
      </div>
    </div>
  );
}

function Plot({
  descriptor,
  history,
}: {
  descriptor: MetricDescriptor;
  history?: { collectedAt: string; value: number }[];
}) {
  const points = (history ?? []).filter((p) => typeof p.value === 'number');
  if (points.length === 0) {
    return (
      <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <p className="text-xs uppercase tracking-wide text-slate-400">{descriptor.label}</p>
        <p className="mt-1 text-sm text-slate-400">No history yet</p>
      </div>
    );
  }

  const values = points.map((p) => p.value);
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min || 1;
  const width = 300;
  const height = 80;
  const step = points.length > 1 ? width / (points.length - 1) : width;
  const color = descriptor.color ?? '#3b82f6';

  const path = points
    .map((p, i) => {
      const x = i * step;
      const y = height - ((p.value - min) / range) * height;
      return `${i === 0 ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(' ');

  return (
    <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-baseline justify-between">
        <p className="text-xs uppercase tracking-wide text-slate-400">{descriptor.label}</p>
        <p className="text-lg font-semibold text-slate-900">
          {formatValue(points[points.length - 1].value, descriptor.unit, descriptor.format)}
        </p>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} className="mt-3 h-20 w-full" preserveAspectRatio="none">
        <path d={path} fill="none" stroke={color} strokeWidth={2} />
      </svg>
      <div className="mt-1 flex justify-between text-[10px] text-slate-400">
        <span>{formatValue(min, descriptor.unit, descriptor.format)}</span>
        <span>{formatValue(max, descriptor.unit, descriptor.format)}</span>
      </div>
    </div>
  );
}

function MetricTable({ descriptor, value }: { descriptor: MetricDescriptor; value?: unknown }) {
  // Two table shapes, both driven by the descriptor:
  //  1. MAP form (traffic): value = { wan: { rx, tx } }, descriptor.rows = the
  //     row keys, descriptor.columns = the value fields. First column = row key.
  //  2. ARRAY form (ARP/NDP/interfaces): value = [{ mac, ip, intf, ... }],
  //     descriptor.columns = the object fields to show. No leading row-key col.
  const columns = descriptor.columns ?? [];
  const isMap = !Array.isArray(value) && value && typeof value === 'object';
  const map = isMap ? (value as Record<string, unknown>) : {};
  const mapRows = descriptor.rows ?? (isMap ? Object.keys(map) : []);
  const arrayRows = Array.isArray(value) ? (value as Record<string, unknown>[]) : [];

  const hasRows = isMap ? mapRows.length > 0 : arrayRows.length > 0;

  return (
    <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
      <div className="flex items-baseline justify-between">
        <p className="text-xs uppercase tracking-wide text-slate-400">{descriptor.label}</p>
        {hasRows && <p className="text-[11px] text-slate-400">{isMap ? mapRows.length : arrayRows.length} rows</p>}
      </div>
      {!hasRows ? (
        <p className="mt-1 text-sm text-slate-400">No rows</p>
      ) : (
        <div className="mt-2 max-h-80 overflow-y-auto">
          <table className="w-full text-sm">
            {columns.length > 0 && (
              <thead className="sticky top-0 bg-white">
                <tr className="text-left text-[11px] uppercase tracking-wide text-slate-400">
                  {isMap && <th className="pb-1 pr-3 font-medium">Name</th>}
                  {columns.map((c) => (
                    <th key={c} className="pb-1 pl-3 text-right font-medium">
                      {c}
                    </th>
                  ))}
                </tr>
              </thead>
            )}
            <tbody>
              {isMap
                ? mapRows.map((row) => {
                    const cell = map[row];
                    const cellObj = cell && typeof cell === 'object' ? (cell as Record<string, unknown>) : {};
                    return (
                      <tr key={row} className="border-t border-slate-100 first:border-t-0">
                        <td className="py-1.5 pr-3 font-medium text-slate-700">{row}</td>
                        {columns.map((c) => (
                          <td key={c} className="py-1.5 pl-3 text-right tabular-nums text-slate-900">
                            {formatValue(cellObj[c], descriptor.unit, descriptor.format)}
                          </td>
                        ))}
                      </tr>
                    );
                  })
                : arrayRows.map((obj, i) => (
                    <tr key={i} className="border-t border-slate-100 first:border-t-0">
                      {columns.map((c) => (
                        <td key={c} className="py-1.5 pl-3 text-right tabular-nums text-slate-900">
                          {formatValue(obj[c], descriptor.unit, descriptor.format)}
                        </td>
                      ))}
                    </tr>
                  ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
