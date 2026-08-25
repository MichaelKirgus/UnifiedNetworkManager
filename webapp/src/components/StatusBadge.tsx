import { clsx } from 'clsx';

const STATUS_STYLES: Record<string, string> = {
  online: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  ok: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  degraded: 'bg-amber-100 text-amber-800 border-amber-300',
  warning: 'bg-amber-100 text-amber-800 border-amber-300',
  offline: 'bg-red-100 text-red-800 border-red-300',
  critical: 'bg-red-100 text-red-800 border-red-300',
  queued: 'bg-slate-100 text-slate-800 border-slate-300',
  running: 'bg-blue-100 text-blue-800 border-blue-300',
  succeeded: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  failed: 'bg-red-100 text-red-800 border-red-300',
  pending: 'bg-slate-50 text-slate-600 border-slate-200',
  skipped: 'bg-slate-100 text-slate-500 border-slate-300 line-through',
  ready: 'bg-blue-50 text-blue-800 border-blue-200',
  executing: 'bg-blue-100 text-blue-800 border-blue-300',
  cancelled: 'bg-slate-100 text-slate-600 border-slate-300',
  // Tunnel states (Tunnels page): live up/down vs. config-level enabled/disabled.
  up: 'bg-emerald-100 text-emerald-800 border-emerald-300',
  down: 'bg-red-100 text-red-800 border-red-300',
  enabled: 'bg-blue-100 text-blue-800 border-blue-300',
  disabled: 'bg-slate-100 text-slate-500 border-slate-300 line-through',
  unknown: 'bg-slate-100 text-slate-600 border-slate-300',
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
