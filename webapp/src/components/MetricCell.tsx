import { SummaryMetric } from '../api/client';
import { formatValue, niceCeil } from './formatMetric';

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
  // width and wrapping their labels. The value sits on its OWN row — never
  // sharing a line with the label — so long labels ("BANDWIDTH RX") and wide
  // values can't collide regardless of what the plugin reports.
  return (
    <div className="flex min-w-[120px] flex-col gap-1">
      <span className="min-w-0 truncate text-[10px] uppercase tracking-wide text-faint" title={metric.label}>
        {metric.label}
      </span>
      <span className="text-xs font-semibold text-foreground">
        {formatValue(metric.value, metric.unit, metric.format)}
      </span>
    </div>
  );
}

function MiniGauge({ metric }: { metric: SummaryMetric }) {
  const min = metric.min ?? 0;
  // Explicit max wins; otherwise auto-scale to a "nice" bound above the current
  // value so unbounded gauges (e.g. bandwidth in bits/sec) render a meaningful bar.
  const num = typeof metric.value === 'number' ? metric.value : 0;
  const max = metric.max ?? Math.max(niceCeil(num), min + 1);
  const clamped = Math.max(min, Math.min(max, num));
  const pct = max > min ? ((clamped - min) / (max - min)) * 100 : 0;
  // Default gauge hue — centralized status token (blue).
  const color = metric.color ?? 'rgb(var(--status-info))';
  return (
    <div className="flex min-w-[120px] flex-col gap-1">
      {/* Label and value are stacked, NOT on one line: with justify-between a
          long label ("BANDWIDTH RX") and a wide value collide in narrow cells.
          Stacking guarantees clearance for any label/value combination; the
          label truncates (full text in the tooltip) if it still overflows. */}
      <span className="min-w-0 truncate text-[10px] uppercase tracking-wide text-faint" title={metric.label}>
        {metric.label}
      </span>
      <span className="text-xs font-semibold text-foreground">
        {formatValue(metric.value, metric.unit, metric.format)}
      </span>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-muted">
        <div className="h-full rounded-full" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}
