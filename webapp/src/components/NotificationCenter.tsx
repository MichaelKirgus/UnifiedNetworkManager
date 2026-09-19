import { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import clsx from 'clsx';
import { Bell, CheckCheck, Info, Link as LinkIcon, OctagonX, Settings2, TriangleAlert, X } from 'lucide-react';
import { api, Notification, NotificationSeverity } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Top-right notification bell with an unread badge + dropdown panel.
 * Mounted in the app shell (Layout) so it is visible on every page. The badge
 * counts OPEN notifications that pass the user's personal visibility prefs;
 * the panel lists them newest-first with per-row acknowledge/resolve actions.
 * Hidden entirely without `notifications:read` (the API would 403 anyway).
 */

const SEVERITY_ICON: Record<NotificationSeverity, typeof Info> = {
  info: Info,
  warning: TriangleAlert,
  critical: OctagonX,
};

const SEVERITY_COLOR: Record<NotificationSeverity, string> = {
  info: 'text-status-info',
  warning: 'text-status-warn',
  critical: 'text-danger-fg',
};

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

export function NotificationCenter() {
  const [open, setOpen] = useState(false);
  const anchorRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  // Badge count — refetched on an interval so the bell stays fresh. Only runs
  // for users who may read notifications (the route is permission-gated).
  const allowed = can('notifications:read');
  const countQuery = useQuery({
    queryKey: ['notificationCount'],
    queryFn: api.notificationCount,
    refetchInterval: 30_000,
    enabled: allowed,
  });

  // Panel rows — only fetched while open (cheap to re-open).
  const listQuery = useQuery({
    queryKey: ['notifications', 'panel'],
    queryFn: () => api.notifications({ status: 'open,acknowledged', limit: 30 }),
    enabled: open,
    refetchInterval: open ? 15_000 : false,
  });

  const invalidate = () => {
    void queryClient.invalidateQueries({ queryKey: ['notificationCount'] });
    void queryClient.invalidateQueries({ queryKey: ['notifications'] });
  };

  const ackMut = useMutation({
    mutationFn: (arg: { ids?: string[]; all?: boolean }) => api.acknowledgeNotifications(arg.ids, arg.all),
    onSuccess: invalidate,
  });
  const resolveMut = useMutation({
    mutationFn: (id: string) => api.resolveNotification(id),
    onSuccess: invalidate,
  });

  // Close on outside click / Escape.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (anchorRef.current && !anchorRef.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') setOpen(false);
    }
    document.addEventListener('mousedown', onDown);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('mousedown', onDown);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  if (!allowed) return null;

  const count = countQuery.data?.count ?? 0;
  const rows: Notification[] = listQuery.data ?? [];

  return (
    <div className="relative" ref={anchorRef}>
      <button
        type="button"
        aria-label={`Notifications${count > 0 ? ` (${count} open)` : ''}`}
        title="Notification center"
        onClick={() => setOpen((v) => !v)}
        className="relative flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-secondary"
      >
        <Bell className="h-5 w-5" />
        {count > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-status-critical px-1 text-[10px] font-bold leading-none text-white">
            {count > 99 ? '99+' : count}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-2 w-[420px] overflow-hidden rounded-lg border border-border bg-card shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <span className="text-sm font-semibold text-foreground">Notifications</span>
            <div className="flex items-center gap-1">
              {count > 0 && (
                <button
                  type="button"
                  onClick={() => ackMut.mutate({ all: true })}
                  disabled={ackMut.isPending}
                  title="Mark all as seen"
                  aria-label="Mark all as seen"
                  className="flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-secondary disabled:opacity-50"
                >
                  <CheckCheck className="h-3.5 w-3.5" /> Mark all seen
                </button>
              )}
              <a
                href="/notifications"
                onClick={() => setOpen(false)}
                title="Open the full Notifications page (all history + filters)"
                aria-label="Open notifications page"
                className="flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-secondary"
              >
                <Settings2 className="h-3.5 w-3.5" /> View all
              </a>
            </div>
          </div>

          {/* Rows */}
          <div className="max-h-[420px] overflow-y-auto">
            {listQuery.isLoading && (
              <div className="px-3 py-6 text-center text-sm text-faint">Loading…</div>
            )}
            {!listQuery.isLoading && rows.length === 0 && (
              <div className="flex flex-col items-center gap-2 px-3 py-8 text-center">
                <Bell className="h-6 w-6 text-faint" />
                <span className="text-sm text-faint">No open notifications</span>
              </div>
            )}
            {rows.map((n) => {
              const Icon = SEVERITY_ICON[n.severity] ?? Info;
              return (
                <div
                  key={n.id}
                  className={clsx(
                    'group flex items-start gap-2.5 border-b border-border px-3 py-2.5 hover:bg-background',
                    n.status === 'acknowledged' && 'opacity-60'
                  )}
                >
                  <Icon className={clsx('mt-0.5 h-4 w-4 shrink-0', SEVERITY_COLOR[n.severity])} />
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium text-foreground" title={n.title}>
                      {n.title}
                    </p>
                    {n.message && (
                      <p className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{n.message}</p>
                    )}
                    <div className="mt-1 flex items-center gap-2 text-[11px] text-faint">
                      <span>{timeAgo(n.lastSeenAt)}</span>
                      {n.occurrences > 1 && (
                        <span className="rounded bg-muted px-1 font-medium text-muted-foreground">×{n.occurrences}</span>
                      )}
                      {n.deviceName && (
                        <a href={`/devices/${n.deviceId}`} onClick={() => setOpen(false)} className="flex items-center gap-0.5 hover:text-secondary">
                          <LinkIcon className="h-3 w-3" /> {n.deviceName}
                        </a>
                      )}
                    </div>
                  </div>
                  {/* Row actions (visible on hover) */}
                  <div className="flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover:opacity-100">
                    {n.status === 'open' && (
                      <button
                        type="button"
                        title="Mark as seen"
                        aria-label="Mark as seen"
                        onClick={() => ackMut.mutate({ ids: [n.id] })}
                        className="rounded p-1 text-faint hover:bg-muted hover:text-secondary"
                      >
                        <CheckCheck className="h-3.5 w-3.5" />
                      </button>
                    )}
                    <button
                      type="button"
                      title="Resolve (condition fixed)"
                      aria-label="Resolve notification"
                      onClick={() => resolveMut.mutate(n.id)}
                      className="rounded p-1 text-faint hover:bg-muted hover:text-success-fg"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
