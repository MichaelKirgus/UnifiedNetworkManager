import clsx from 'clsx';

/**
 * Plan step progress indicators.
 *
 * Two shapes, one data source (plan steps):
 *  - {@link StepSegments}: one segment per step, colored by that step's status —
 *    used where the full step list is loaded (expanded payload row, plan detail).
 *  - {@link StepRatioBar}: a thin done/total bar for list rows, where only the
 *    aggregate `stepCount`/`stepsDone` are available.
 *
 * Colors use the solid status hues (--status-*) — theme-independent by design,
 * same convention as device LEDs and dots elsewhere in the app.
 */

/** Solid hue per plan-step state (see PlanStep.status). */
const STEP_SEGMENT: Record<string, string> = {
  succeeded: 'bg-status-ok',
  running: 'bg-status-info',
  failed: 'bg-status-critical',
  skipped: 'bg-muted',
  pending: 'bg-muted/60',
};

/** One segment per step — the plan's execution state at a glance. */
export function StepSegments({ steps, className }: { steps: { id: string; status: string }[]; className?: string }) {
  if (steps.length === 0) return null;
  const done = steps.filter((s) => s.status === 'succeeded').length;
  return (
    <div
      className={clsx('flex items-center gap-0.5', className)}
      role="img"
      aria-label={`${done} of ${steps.length} steps succeeded`}
    >
      {steps.map((s) => (
        <span key={s.id} title={`Step: ${s.status}`} className={clsx('h-1.5 min-w-[6px] flex-1 rounded-full', STEP_SEGMENT[s.status] ?? 'bg-muted')} />
      ))}
    </div>
  );
}

/** Fill tone for the ratio bar, derived from the plan-level outcome. */
export function stepBarTone(planStatus: string): 'ok' | 'warn' | 'critical' | 'info' | 'neutral' {
  switch (planStatus) {
    case 'succeeded': return 'ok';
    case 'unverified': return 'warn';
    case 'failed': return 'critical';
    case 'cancelled':
    case 'skipped': return 'neutral';
    default: return 'info'; // draft / ready / scheduled / executing — in flight or not started
  }
}

const TONE_FILL = {
  ok: 'bg-status-ok',
  warn: 'bg-status-warn',
  critical: 'bg-status-critical',
  info: 'bg-status-info',
  neutral: 'bg-muted',
} as const;

/** Thin done/total bar for list rows (no per-step statuses available there). */
export function StepRatioBar({ total, done, tone = 'info' }: { total: number; done: number; tone?: keyof typeof TONE_FILL }) {
  if (!total) return null;
  const pct = Math.min(100, Math.round((done / total) * 100));
  return (
    <div className="h-1 w-full min-w-[64px] overflow-hidden rounded-full bg-muted/50" title={`${done}/${total} steps done`}>
      <div className={clsx('h-full rounded-full transition-all duration-300', TONE_FILL[tone])} style={{ width: `${pct}%` }} />
    </div>
  );
}
