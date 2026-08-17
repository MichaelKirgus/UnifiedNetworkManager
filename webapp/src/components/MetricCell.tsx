import { SummaryMetric } from '../api/client';
import { formatValue } from './formatMetric';

/**
 * Renders a single "summary" metric inline in the device overview table.
 * Supports the same visualization hints as the detail view (gauge | plot |
 * text) but in a compact, table-cell form. This is the flexible "most
 * important metrics" hook: a plugin marks its headline metrics with
 * `summary: true` and they appear here automatically — no per-plugin code.
 */
export function MetricCell({ metric }: { metric: SummaryMetric }) {
  switch (metric.visualization) {
    case 'gauge':
      return <MiniGauge metric={metric} />;
    case 'plot':
      return <Sparkline metric={metric} />;
    case 'text':
    default:
      return <InlineText metric={metric} />;
  }
}

function InlineText({ metric }: { metric: SummaryMetric }) {
  return (
    <div className="flex flex-col">
      <span className="text-[10px] uppercase tracking-wide text-slate-400">{metric.label}</span>
      <span className="text-sm font-semibold text-slate-900">
        {formatValue(metric.value, metric.unit, metric.format)}
      </span>
    </div>
  );
}

function MiniGauge({ metric }: { metric: SummaryMetric }) {
  const min = metric.min ?? 0;
  const max = metric.max ?? 100;
  const num = typeof metric.value === 'number' ? metric.value : 0;
  const clamped = Math.max(min, Math.min(max, num));
  const pct = max > min ? ((clamped - min) / (max - min)) * 100 : 0;
  const color = metric.color ?? '#3b82f6';
  return (
    <div className="flex min-w-[90px] flex-col gap-1">
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] uppercase tracking-wide text-slate-400">{metric.label}</span>
        <span className="text-xs font-semibold text-slate-900">
          {formatValue(metric.value, metric.unit, metric.format)}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-slate-100">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

/**
 * Compact sparkline for a 'plot' summary metric. The overview table only has
 * the current value (no history), so it renders a single point as a dot on a
 * baseline — a visual cue that this metric is a time series. When a value is
 * present it shows the value; the detail view carries the full history.
 */
function Sparkline({ metric }: { metric: SummaryMetric }) {
  const hasValue = typeof metric.value === 'number';
  const color = metric.color ?? '#3b82f6';
  return (
    <div className="flex min-w-[90px] flex-col gap-1">
      <div className="flex items-baseline justify-between">
        <span className="text-[10px] uppercase tracking-wide text-slate-400">{metric.label}</span>
        <span className="text-xs font-semibold text-slate-900">
          {formatValue(metric.value, metric.unit, metric.format)}
        </span>
      </div>
      <div className="flex h-3 items-center">
        <div className="h-px w-full bg-slate-200" />
        {hasValue && <div className="h-2 w-2 -translate-x-1/2 rounded-full" style={{ backgroundColor: color }} />}
      </div>
    </div>
  );
}
