/**
 * Post-apply verification helpers.
 *
 * UNM's plan executor distinguishes "the device acknowledged the change" from
 * "UNM confirmed the resulting state". A plugin proves the latter by re-reading
 * device state AFTER applying and reporting it via `ActionResult.verified`:
 *
 *   1. capture the BEFORE state (optional — store it in details as `before`);
 *   2. apply the change;
 *   3. pollUntil(...) until the target state is observed (bounded!);
 *   4. return { success, applied: true, verified, details: { before, after } }.
 *
 * The API then marks the plan `succeeded` only when every non-best-effort
 * write step reported `verified: true`; otherwise it lands in the intermediate
 * terminal status `unverified` (applied, but not confirmed). Read-only actions
 * are exempt — a read is its own confirmation.
 */

export interface PollUntilOptions {
  /** Hard deadline for the whole poll loop (default 30 s). */
  timeoutMs?: number;
  /** Delay between probes (default 2 s). */
  intervalMs?: number;
}

export interface PollUntilResult<T> {
  /** True when `isDone` returned true before the deadline. */
  ok: boolean;
  /** Last observed value (present even on timeout — useful for diagnostics). */
  value?: T;
  /** Number of probes performed. */
  attempts: number;
}

/**
 * Polls `probe()` until `isDone(value)` is true or the deadline elapses.
 * Probe errors are swallowed and treated as "not done yet" — a flaky read must
 * not abort verification, only the bounded timeout decides. Returns the last
 * observed value so callers can report what they actually saw (`after`).
 */
export async function pollUntil<T>(
  probe: () => Promise<T>,
  isDone: (value: T) => boolean,
  opts: PollUntilOptions = {}
): Promise<PollUntilResult<T>> {
  const timeoutMs = Math.max(1_000, opts.timeoutMs ?? 30_000);
  const intervalMs = Math.max(250, opts.intervalMs ?? 2_000);
  const deadline = Date.now() + timeoutMs;

  let attempts = 0;
  let last: T | undefined;
  for (;;) {
    attempts++;
    try {
      last = await probe();
    } catch {
      // Transient read failure — keep polling until the deadline.
    }
    if (last !== undefined && isDone(last)) return { ok: true, value: last, attempts };
    if (Date.now() >= deadline) break;
    await new Promise((resolve) => setTimeout(resolve, intervalMs));
  }
  return { ok: false, value: last, attempts };
}

/**
 * Convenience wrapper for the common "state must equal X" check.
 */
export function stateEquals<T>(expected: T): (value: T) => boolean {
  return (value) => value === expected;
}
