import { formatBytes } from '../formatMetric';

/**
 * Compact traffic badge for topology nodes when the overlay is active.
 * "≈" marks the value as a sampling-extrapolated estimate (see traffic.ts) —
 * it's for relative sizing, not an exact meter. The sky accent (--topo-traffic)
 * matches the MiniMap tint so "bright node = bright dot" holds across views.
 */
export function TrafficBadge({ bytes }: { bytes: number }) {
  return (
    <span
      className="rounded bg-topo-traffic/15 px-1 py-px text-[9px] font-semibold tabular-nums text-topo-traffic"
      title={`≈ ${formatBytes(bytes)} in window (sampling estimate)`}
    >
      ≈ {formatBytes(bytes)}
    </span>
  );
}
