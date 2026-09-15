import { ClipboardList, EyeOff, Play } from 'lucide-react';
import clsx from 'clsx';
import { useExecutionMode } from '../executionMode';

/**
 * Global Read-Only / Plan / Execute toggle — sits in the shared top bar between
 * the theme switcher and the plans icon. Ordered from safest to most dangerous:
 *
 *  - Read-Only: no action is executed or saved; a banner informs the user.
 *  - Plan: actions are saved as (unexecuted) plans for later execution/scheduling.
 *  - Execute: actions run immediately through the plan workflow.
 *
 * On pages without plan-based actions it renders DISABLED with a hint, so the
 * control is always visible but clearly not applicable there.
 */

const MODES = [
  { id: 'readonly', label: 'Read-Only', icon: EyeOff },
  { id: 'plan', label: 'Plan', icon: ClipboardList },
  { id: 'execute', label: 'Execute', icon: Play },
] as const;

const MODE_TITLES: Record<(typeof MODES)[number]['id'], string> = {
  readonly: 'Read-Only — no actions are executed or saved. Switch to Plan or Execute to make changes.',
  plan: 'Plan — actions are saved in the Plans center without executing. Switch to Execute to run them immediately.',
  execute: 'Execute — actions run immediately. Switch to Plan to save them without executing, or Read-Only to disable all actions.',
};

export function ExecutionModeToggle() {
  const { mode, setMode, applicable } = useExecutionMode();

  return (
    <div
      className={clsx('inline-flex items-center rounded-md border p-0.5', !applicable && 'opacity-40')}
      title={applicable ? MODE_TITLES[mode] : 'No actions on this page use the plan workflow — toggle disabled here.'}
    >
      {MODES.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          type="button"
          aria-label={`${label} mode`}
          aria-pressed={mode === id}
          title={MODE_TITLES[id]}
          onClick={() => setMode(id)}
          disabled={!applicable}
          className={clsx(
            'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors',
            mode === id ? 'bg-primary text-white' : 'text-secondary hover:bg-muted',
            !applicable && 'cursor-not-allowed'
          )}
        >
          <Icon className="h-3 w-3" /> {label}
        </button>
      ))}
    </div>
  );
}
