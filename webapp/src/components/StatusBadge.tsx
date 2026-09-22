import { clsx } from 'clsx';

const STATUS_STYLES: Record<string, string> = {
  online: 'bg-success text-success-fg border-success-border',
  ok: 'bg-success text-success-fg border-success-border',
  degraded: 'bg-warning text-warning-fg border-warning-border',
  warning: 'bg-warning text-warning-fg border-warning-border',
  offline: 'bg-danger text-danger-fg border-danger-border',
  critical: 'bg-danger text-danger-fg border-danger-border',
  queued: 'bg-muted text-foreground border-border',
  running: 'bg-info text-info-fg border-info-border',
  succeeded: 'bg-success text-success-fg border-success-border',
  failed: 'bg-danger text-danger-fg border-danger-border',
  pending: 'bg-background text-secondary border-border',
  // Plan-level "skipped" (a due schedule was skipped per policy) and step-level
  // "skipped" (not run — dependency failed / cancelled) share this style.
  skipped: 'bg-muted text-muted-foreground border-border line-through',
  ready: 'bg-info text-info-fg border-info-border',
  scheduled: 'bg-primary/15 text-primary border-primary/40',
  executing: 'bg-info text-info-fg border-info-border',
  cancelled: 'bg-muted text-secondary border-border',
  // Applied without error, but the plugin could not confirm the resulting state.
  unverified: 'bg-warning text-warning-fg border-warning-border',
  // Tunnel states (Tunnels page): live up/down vs. config-level enabled/disabled.
  up: 'bg-success text-success-fg border-success-border',
  down: 'bg-danger text-danger-fg border-danger-border',
  enabled: 'bg-info text-info-fg border-info-border',
  disabled: 'bg-muted text-muted-foreground border-border line-through',
  // Service states (Services page) — `running`/`failed` reuse the plan-step
  // styles above; only `stopped` needs a dedicated entry.
  stopped: 'bg-muted text-secondary border-border',
  // Route states (Routes page): installed/active vs. configured-but-inactive.
  active: 'bg-success text-success-fg border-success-border',
  inactive: 'bg-muted text-muted-foreground border-border line-through',
  // Storage states (Storage page): ZFS pool/dataset + disk health.
  healthy: 'bg-success text-success-fg border-success-border',
  faulted: 'bg-danger text-danger-fg border-danger-border',
  unavail: 'bg-danger text-danger-fg border-danger-border',
  unknown: 'bg-muted text-secondary border-border',
};

export function StatusBadge({ status }: { status: string }) {
  const style = STATUS_STYLES[status] ?? STATUS_STYLES.unknown;
  return (
    <span
      className={clsx(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium capitalize',
        style
      )}
    >
      {status}
    </span>
  );
}
