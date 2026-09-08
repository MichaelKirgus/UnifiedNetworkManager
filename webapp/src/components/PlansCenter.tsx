import { useEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import clsx from 'clsx';
import { CheckCircle2, CircleDashed, ListChecks, Loader2, OctagonX, Settings2 } from 'lucide-react';
import { api, Plan } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Top-bar plans icon (next to the notification bell) with an overview panel.
 * Mounted in the app shell (Layout) so it is visible on every page — this is
 * the single place that surfaces plan execution, so individual pages no longer
 * need their own banners/spinners for background-executed plans.
 *
 * Badge: count of executing + queued (ready/draft) plans. The panel lists them
 * with live step progress; recently-finished plans (terminal status within the
 * 5-minute window, via `recentlyFinishedAt`) stay listed with a green tick and
 * fade out on their own when the window expires.
 */

const RECENT_WINDOW_MS = 300_000; // must match the API default

function timeAgo(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return `${Math.floor(s)}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

/** Icon + tint for a plan row, by status. */
function statusIcon(p: Plan) {
  switch (p.status) {
    case 'executing':
      return <Loader2 className="h-4 w-4 shrink-0 animate-spin text-info-fg" />;
    case 'succeeded':
      // The "little green tick" for successfully executed plans.
      return <CheckCircle2 className="h-4 w-4 shrink-0 text-success-fg" />;
    case 'failed':
      return <OctagonX className="h-4 w-4 shrink-0 text-danger-fg" />;
    case 'cancelled':
      return <CircleDashed className="h-4 w-4 shrink-0 text-muted-foreground" />;
    default: // draft | ready — queued, waiting to be executed.
      return <CircleDashed className="h-4 w-4 shrink-0 text-secondary" />;
  }
}

export function PlansCenter() {
  const [open, setOpen] = useState(false);
  const anchorRef = useRef<HTMLDivElement>(null);

  // Hidden entirely without `plans:read` (the API would 403 anyway).
  const allowed = can('plans:read');

  // Badge + panel rows — one feed covers both. Polls while there is activity;
  // when the list empties it slows down so a quiet system costs nothing.
  const query = useQuery({
    queryKey: ['planActivity'],
    queryFn: () => api.planActivity(RECENT_WINDOW_MS),
    refetchInterval: (q) => {
      const rows = q.state.data ?? [];
      return rows.some((p) => p.status === 'executing') ? 5_000 : 15_000;
    },
    enabled: allowed,
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

  const rows: Plan[] = query.data ?? [];
  // Badge counts in-flight work only (executing + queued). Recently-finished
  // plans are visible in the panel but don't keep a badge on the icon.
  const activeCount = rows.filter((p) => p.status === 'executing' || p.status === 'ready' || p.status === 'draft').length;

  return (
    <div className="relative" ref={anchorRef}>
      <button
        type="button"
        aria-label={`Plans${activeCount > 0 ? ` (${activeCount} active)` : ''}`}
        title="Plan activity"
        onClick={() => setOpen((v) => !v)}
        className="relative flex h-9 w-9 items-center justify-center rounded-md text-muted-foreground hover:bg-muted hover:text-secondary"
      >
        <ListChecks className="h-5 w-5" />
        {activeCount > 0 && (
          <span className="absolute -right-0.5 -top-0.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-blue-500 px-1 text-[10px] font-bold leading-none text-white">
            {activeCount > 99 ? '99+' : activeCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 top-full z-50 mt-2 w-[420px] overflow-hidden rounded-lg border border-border bg-card shadow-xl">
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <span className="text-sm font-semibold text-foreground">Plan activity</span>
            <a
              href="/plans"
              onClick={() => setOpen(false)}
              title="Open the full Plans page (all history)"
              aria-label="Open plans page"
              className="flex items-center gap-1 rounded px-2 py-1 text-xs font-medium text-muted-foreground hover:bg-muted hover:text-secondary"
            >
              <Settings2 className="h-3.5 w-3.5" /> View all
            </a>
          </div>

          {/* Rows */}
          <div className="max-h-[420px] overflow-y-auto">
            {query.isLoading && (
              <div className="px-3 py-6 text-center text-sm text-faint">Loading…</div>
            )}
            {!query.isLoading && rows.length === 0 && (
              <div className="flex flex-col items-center gap-2 px-3 py-8 text-center">
                <ListChecks className="h-6 w-6 text-faint" />
                <span className="text-sm text-faint">No active or recent plans</span>
              </div>
            )}
            {rows.map((p) => {
              const done = p.stepsDone ?? 0;
              const total = p.stepCount ?? 0;
              return (
                <a
                  key={p.id}
                  href={`/plans/${p.id}`}
                  onClick={() => setOpen(false)}
                  className="flex items-start gap-2.5 border-b border-border px-3 py-2.5 hover:bg-background"
                >
                  {statusIcon(p)}
                  <div className="min-w-0 flex-1">
                    <p className="truncate text-sm font-medium capitalize text-foreground" title={p.intentActionId}>
                      {p.intentActionId}
                    </p>
                    <div className="mt-1 flex items-center gap-2 text-[11px] text-faint">
                      <span className="capitalize">{p.status}</span>
                      {(p.status === 'executing' || p.status === 'succeeded' || p.status === 'failed') && total > 0 && (
                        <span className="tabular-nums text-secondary">
                          {done}/{total} steps
                        </span>
                      )}
                      <span>{timeAgo(p.updatedAt)}</span>
                    </div>
                    {p.status === 'failed' && p.error && (
                      <p className="mt-0.5 line-clamp-2 text-xs text-danger-fg">{p.error}</p>
                    )}
                  </div>
                </a>
              );
            })}
          </div>

          {/* Footer hint — the green tick is explained once, quietly. */}
          {rows.some((p) => p.status === 'succeeded') && (
            <div className={clsx('border-t border-border px-3 py-1.5 text-[11px] text-faint')}>
              Recently finished plans stay listed for a few minutes, then disappear on their own.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
