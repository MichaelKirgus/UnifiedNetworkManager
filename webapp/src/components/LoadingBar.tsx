import clsx from 'clsx';

interface LoadingBarProps {
  /** Known progress 0..1 → determinate fill; omit for the indeterminate marquee sweep. */
  progress?: number | null;
  /** Optional caption rendered to the right of the line (e.g. "Loading…"). */
  label?: string;
  className?: string;
}

/**
 * LoadingBar — thin reusable loading-indicator line for tab/section content.
 * Without `progress` it runs an indeterminate marquee sweep (keyframes in
 * index.css); with a 0..1 value the fill tracks that percentage instead. Use
 * at the top of a pane while its initial data is still fetching so large
 * tables never sit empty without feedback (e.g. Flows tabs on big databases).
 */
export function LoadingBar({ progress, label, className }: LoadingBarProps) {
  const pct = progress != null ? Math.round(Math.min(1, Math.max(0, progress)) * 100) : null;
  return (
    <div role="progressbar" aria-busy="true" aria-valuenow={pct ?? undefined} className={clsx('flex items-center gap-2', className)}>
      <span className="relative h-1 min-w-0 flex-1 overflow-hidden rounded-full bg-muted">
        {pct != null ? (
          <span
            className="absolute inset-y-0 left-0 rounded-full bg-primary transition-[width] duration-300"
            style={{ width: `${pct}%` }}
          />
        ) : (
          <span className="loading-bar-indeterminate absolute inset-y-0 w-1/3 rounded-full bg-primary" />
        )}
      </span>
      {label && <span className="shrink-0 text-xs text-secondary">{label}</span>}
    </div>
  );
}
