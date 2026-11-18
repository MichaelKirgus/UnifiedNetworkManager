/**
 * Tiny pub/sub fired after any plan-MUTATING API call succeeds (create,
 * execute, retry, schedule, cancel, delete — see the emitPlanMutated calls in
 * api/client.ts). Subscribers invalidate their plan-activity queries so the
 * top-bar badge, sidebar badge and Plans-page chip update IMMEDIATELY instead
 * of waiting for the next poll tick. Plain module (no React) so client.ts can
 * import it without pulling react-query into the API layer.
 */

type Listener = () => void;

const listeners = new Set<Listener>();

/** Subscribe to plan mutations. Returns an unsubscribe function. */
export function onPlanMutated(fn: Listener): () => void {
  listeners.add(fn);
  return () => {
    listeners.delete(fn);
  };
}

/** Notify all subscribers that a plan mutation succeeded. Never throws — a
 * broken listener must not break the API call that triggered it. */
export function emitPlanMutated(): void {
  if (listeners.size === 0) return;
  for (const l of [...listeners]) {
    try {
      l();
    } catch {
      /* listener bug — ignore */
    }
  }
}
