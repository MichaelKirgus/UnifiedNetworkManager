import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

/**
 * Global execution mode — the top-bar toggle that decides what happens when a
 * page triggers an action. Ordered from safest to most dangerous:
 *
 *  - `readonly`: NO actions are executed or saved. A banner informs the user;
 *    any attempted action is rejected with a clear error.
 *  - `plan`: the plan is created but NOT executed — it lands in the Plans
 *    center as draft/ready and can be executed later by the user (or scheduled).
 *  - `execute` (default): actions run immediately through the plan workflow
 *    (create plan + execute), exactly as before.
 *
 * The mode is persisted per browser (localStorage) so it survives reloads.
 * Pages that have no plan-based actions render the toggle DISABLED — see
 * `useExecutionMode().applicable` / `setApplicable`.
 */

export type ExecutionMode = 'readonly' | 'plan' | 'execute';

const STORAGE_KEY = 'unm-execution-mode';

interface ExecutionModeContextValue {
  mode: ExecutionMode;
  setMode: (mode: ExecutionMode) => void;
  /** Whether the current page has plan-based actions. Drives the toggle's
   *  enabled/disabled state in the top bar. */
  applicable: boolean;
  setApplicable: (v: boolean) => void;
}

const ExecutionModeContext = createContext<ExecutionModeContextValue | null>(null);

function readStored(): ExecutionMode {
  try {
    const v = localStorage.getItem(STORAGE_KEY);
    if (v === 'readonly' || v === 'plan') return v;
    return 'execute';
  } catch {
    return 'execute';
  }
}

export function ExecutionModeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ExecutionMode>(readStored);
  const [applicable, setApplicable] = useState(false);

  const setMode = useCallback((m: ExecutionMode) => {
    setModeState(m);
    try {
      localStorage.setItem(STORAGE_KEY, m);
    } catch {
      /* private mode — in-memory only */
    }
  }, []);

  const value = useMemo(
    () => ({ mode, setMode, applicable, setApplicable }),
    [mode, setMode, applicable]
  );

  return <ExecutionModeContext.Provider value={value}>{children}</ExecutionModeContext.Provider>;
}

export function useExecutionMode(): ExecutionModeContextValue {
  const ctx = useContext(ExecutionModeContext);
  if (!ctx) throw new Error('useExecutionMode must be used inside <ExecutionModeProvider>');
  return ctx;
}

/** Shared user-facing message for a blocked read-only action. */
export const READONLY_MESSAGE =
  'Read-only mode is active — no actions can be executed or saved. Switch to Plan or Execute in the top bar.';

/** Error thrown when an action is attempted while in Read-Only mode. */
export class ReadOnlyError extends Error {
  constructor() {
    super(READONLY_MESSAGE);
    this.name = 'ReadOnlyError';
  }
}

/**
 * Shared action runner — the single place where "execute now" vs. "save as plan"
 * diverges. In `plan` mode it returns the created (unexecuted) plan id so pages
 * can surface a friendly notice instead of tracking execution progress for a
 * plan that will never run on its own. In `readonly` mode NOTHING is created —
 * it rejects with {@link ReadOnlyError} before any API call.
 */
export async function runAction(
  create: () => Promise<{ id: string }>,
  execute: (planId: string) => Promise<unknown>,
  mode: ExecutionMode,
): Promise<string> {
  if (mode === 'readonly') throw new ReadOnlyError();
  const plan = await create();
  if (mode === 'execute') {
    try {
      await execute(plan.id);
    } catch (err) {
      // The plan EXISTS even though execution was rejected — annotate the error
      // with its id so callers can tell the user where to pick it up. The
      // original error is rethrown UNCHANGED: a 401 must still reach the
      // caller's two-factor revalidation flow (err instanceof ApiError check).
      if (err && typeof err === 'object') {
        try {
          Object.assign(err, { planId: plan.id });
        } catch {
          /* frozen error — nothing to annotate */
        }
      }
      throw err;
    }
  }
  return plan.id;
}

/** True when an action error carries a saved (unexecuted) plan id. */
export function savedPlanIdOf(err: unknown): string | undefined {
  if (err && typeof err === 'object' && 'planId' in err) {
    const v = (err as { planId?: unknown }).planId;
    return typeof v === 'string' ? v : undefined;
  }
  return undefined;
}
