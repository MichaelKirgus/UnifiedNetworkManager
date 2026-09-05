import { SummaryMetric } from '../api/client';
import { formatValue } from './formatMetric';

/**
 * Renders a single "summary" metric inline in the device overview table.
 * Supports the same visualization hints as the detail view (gauge | plot |
 * text) but in a compact, table-cell form: gauges keep their bar; plot and
 * text metrics render as label + value because the table only carries the
 * current value (no history for sparklines). This is the flexible "most
 * important metrics" hook: a plugin marks its headline metrics with
 * `summary: true` and they appear here automatically — no per-plugin code.
 */
export function MetricCell({ metric }: { metric: SummaryMetric }) {
  switch (metric.visualization) {
    case 'gauge':
      return <MiniGauge metric={metric} />;
    // 'plot' metrics (latency, throughput, ...) have no history in the overview
    // table — a sparkline would be a single dot on an empty baseline. Render
    // them as plain label + value; the detail view carries the real chart.
    case 'plot':
    case 'text':
    default:
      return <InlineText metric={metric} />;
  }
}

function InlineText({ metric }: { metric: SummaryMetric }) {
  // Same footprint as MiniGauge (min-w + label over value) so text/plot metrics
  // line up with gauges in the Metrics column instead of collapsing to content
  // width and wrapping their labels.
  return (
    <div className="flex min-w-[90px] flex-col gap-1">
      <span className="text-[10px] uppercase tracking-wide text-faint">{metric.label}</span>
      <span className="text-xs font-semibold text-foreground">
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
        <span className="text-[10px] uppercase tracking-wide text-faint">{metric.label}</span>
        <span className="text-xs font-semibold text-foreground">
          {formatValue(metric.value, metric.unit, metric.format)}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
