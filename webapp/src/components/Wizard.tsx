import { ReactNode } from 'react';
import clsx from 'clsx';
import { Check, X } from 'lucide-react';
import { Layout } from './Layout';

/**
 * Reusable multi-step wizard shell.
 *
 * Any page that walks the user through a staged task (network rollout today;
 * WiFi rollout, plugin-driven wizards later) composes this instead of hand-
 * rolling its own header + stepper + exit chrome. It renders the app Layout
 * (sidebar/top bar/session/mode toggle) and a horizontal step indicator above
 * the active step's content.
 */

/** One entry in the step indicator — just a short label. */
export interface WizardStep {
  label: string;
}

interface StepperProps {
  steps: WizardStep[];
  /** 0-based index of the active step. */
  current: number;
}

/** Horizontal step indicator: completed (check) → active (filled) → upcoming (muted). */
export function Stepper({ steps, current }: StepperProps) {
  return (
    <ol className="flex flex-wrap items-center gap-y-2">
      {steps.map((s, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li key={s.label} className="flex items-center">
            <span className="flex items-center gap-2">
              <span
                className={clsx(
                  'flex h-6 w-6 shrink-0 items-center justify-center rounded-full border text-xs font-semibold',
                  done && 'border-success bg-success/15 text-success',
                  active && 'border-primary bg-primary text-white',
                  !done && !active && 'border-border bg-background text-faint'
                )}
              >
                {done ? <Check className="h-3.5 w-3.5" /> : i + 1}
              </span>
              <span className={clsx('text-sm', active ? 'font-semibold text-foreground' : done ? 'text-secondary' : 'text-faint')}>
                {s.label}
              </span>
            </span>
            {i < steps.length - 1 && (
              <span aria-hidden className={clsx('mx-3 h-px w-8 sm:w-12', i < current ? 'bg-success/50' : 'bg-border')} />
            )}
          </li>
        );
      })}
    </ol>
  );
}

interface WizardLayoutProps {
  /** Page title shown in the top bar (left). */
  title: ReactNode;
  /** Optional icon rendered before the title. */
  icon?: ReactNode;
  steps: WizardStep[];
  /** 0-based index of the active step. */
  current: number;
  /** Called by the "Cancel" button in the top bar (and Escape). */
  onExit: () => void;
  /** Hide the built-in Cancel button — for MANDATORY wizards that cannot be
   *  abandoned (e.g. first-run setup, which must finish before use). */
  hideCancel?: boolean;
  /** Extra top-bar actions rendered to the LEFT of Cancel (e.g. a primary CTA). */
  actions?: ReactNode;
  children: ReactNode;
}

/** Full-page wizard: app shell + step indicator + content column. */
export function WizardLayout({ title, icon, steps, current, onExit, hideCancel, actions, children }: WizardLayoutProps) {
  return (
    <Layout
      title={
        <>
          {icon && <span className="mr-2 inline-flex align-middle">{icon}</span>}
          {title}
        </>
      }
      actions={
        <>
          {actions}
          {!hideCancel && (
            <button
              type="button"
              onClick={onExit}
              className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted"
            >
              <X className="h-4 w-4" /> Cancel
            </button>
          )}
        </>
      }
    >
      <div className="space-y-4">
        <Stepper steps={steps} current={current} />
        {children}
      </div>
    </Layout>
  );
}
