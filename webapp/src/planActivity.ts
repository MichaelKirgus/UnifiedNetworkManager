import { useEffect } from 'react';
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { api } from './api/client';
import { onPlanMutated } from './planActivityBus';

/** Shared query key for the plan-activity feed — one cache entry no matter how
 * many components (top-bar icon, sidebar badge, Plans page chip) subscribe. */
export const PLAN_ACTIVITY_KEY = ['planActivity'] as const;

const RECENT_WINDOW_MS = 300_000; // must match the API default

// Module-level subscription: ONE bus listener for all mounted consumers, so a
// mutation invalidates each query client exactly once (coalesced — bulk
// actions fire many mutations in one tick).
const clients = new Set<QueryClient>();
let invalidateTimer: number | undefined;
onPlanMutated(() => {
  if (invalidateTimer !== undefined) return;
  invalidateTimer = window.setTimeout(() => {
    invalidateTimer = undefined;
    for (const qc of clients) {
      void qc.invalidateQueries({ queryKey: PLAN_ACTIVITY_KEY });
      // The sidebar's other badges come from /counts — keep the plans one in
      // sync too so a stale 30 s poll can't show a ghost count.
      void qc.invalidateQueries({ queryKey: ['navCounts'] });
    }
  }, 0);
});

/** In-flight count for badges — executing + queued (ready/draft/scheduled).
 * Recently-finished plans are visible in the panel but don't keep a badge. */
export function activePlanCount(rows: Array<{ status: string }> | undefined): number {
  return (rows ?? []).filter(
    (p) => p.status === 'executing' || p.status === 'ready' || p.status === 'draft' || p.status === 'scheduled'
  ).length;
}

/**
 * Shared plan-activity feed. Polls fast while anything is executing, slow when
 * quiet — and any local plan mutation (create/execute/retry/schedule/cancel/
 * delete) invalidates it IMMEDIATELY via the bus in api/client.ts, so the
 * indicators update without waiting for a poll tick after the user acts.
 */
export function usePlanActivity(enabled: boolean) {
  const qc = useQueryClient();

  // Register this client with the module-level mutation listener (see above).
  useEffect(() => {
    clients.add(qc);
    return () => {
      clients.delete(qc);
    };
  }, [qc]);

  return useQuery({
    queryKey: PLAN_ACTIVITY_KEY,
    queryFn: () => api.planActivity(RECENT_WINDOW_MS),
    refetchInterval: (q) => {
      const rows = q.state.data ?? [];
      return rows.some((p) => p.status === 'executing') ? 5_000 : 15_000;
    },
    enabled,
  });
}
