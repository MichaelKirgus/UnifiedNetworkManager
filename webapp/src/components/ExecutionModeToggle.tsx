import { ClipboardList, Play } from 'lucide-react';
import clsx from 'clsx';
import { useExecutionMode } from '../executionMode';

/**
 * Global Execute / Plan toggle — sits in the shared top bar between the theme
 * switcher and the plans icon. It decides whether page actions run immediately
 * or are saved as (unexecuted) plans for later execution/scheduling.
 *
 * On pages without plan-based actions it renders DISABLED with a hint, so the
 * control is always visible but clearly not applicable there.
 */
export function ExecutionModeToggle() {
  const { mode, setMode, applicable } = useExecutionMode();

  return (
    <div
      className={clsx('inline-flex items-center rounded-md border p-0.5', !applicable && 'opacity-40')}
      title={
        applicable
          ? mode === 'execute'
            ? 'Actions run immediately — switch to Plan to save them without executing.'
            : 'Actions are saved as plans without executing — switch to Execute to run them immediately.'
          : 'No actions on this page use the plan workflow — toggle disabled here.'
      }
    >
      <button
        type="button"
        aria-label="Execute mode: run actions immediately"
        title="Execute — actions run immediately"
        onClick={() => setMode('execute')}
        disabled={!applicable}
        className={clsx(
          'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors',
          mode === 'execute' ? 'bg-primary text-white' : 'text-secondary hover:bg-muted',
          !applicable && 'cursor-not-allowed'
        )}
      >
        <Play className="h-3 w-3" /> Execute
      </button>
      <button
        type="button"
        aria-label="Plan mode: save actions as plans without executing"
        title="Plan — actions are saved in the Plans center without executing"
        onClick={() => setMode('plan')}
        disabled={!applicable}
        className={clsx(
          'inline-flex items-center gap-1 rounded px-2 py-1 text-xs font-medium transition-colors',
          mode === 'plan' ? 'bg-primary text-white' : 'text-secondary hover:bg-muted',
          !applicable && 'cursor-not-allowed'
        )}
      >
        <ClipboardList className="h-3 w-3" /> Plan
      </button>
    </div>
  );
}
