import { FormEvent, useMemo, useState } from 'react';
import clsx from 'clsx';
import { CalendarClock, X } from 'lucide-react';
import { api, ApiError, Plan } from '../api/client';
import { useTimeFormat } from '../utils/time';

/**
 * Reusable "schedule this plan" dialog — used by the Plans list (single + bulk)
 * and the PlanDetail page. Lets the user pick a due time RELATIVE ("in 15
 * minutes") or ABSOLUTE (date + time), plus the policy for what happens when
 * the plugin cannot be reached at the due instant:
 *   - run-asap: retry as soon as possible (backoff) until it succeeds.
 *   - skip:     mark the plan skipped — do not execute it.
 */

type Kind = 'relative' | 'absolute';
type Policy = 'run-asap' | 'skip';

const RELATIVE_PRESETS: Array<{ label: string; minutes: number }> = [
  { label: 'In 5 minutes', minutes: 5 },
  { label: 'In 15 minutes', minutes: 15 },
  { label: 'In 30 minutes', minutes: 30 },
  { label: 'In 1 hour', minutes: 60 },
  { label: 'In 2 hours', minutes: 120 },
  { label: 'Tomorrow (same time)', minutes: 1440 },
];

/** Local-time value for <input type="datetime-local"> from an ISO string. */
function toLocalInputValue(iso?: string | null): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** <input type="datetime-local"> value → ISO (interpreted as local time). */
function fromLocalInputValue(v: string): string | null {
  if (!v) return null;
  const d = new Date(v);
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

export interface ScheduleDialogProps {
  /** The plan to schedule (single-plan mode). */
  plan?: Plan | null;
  /** Bulk mode: schedule every one of these plans at the same time. */
  plans?: Plan[];
  onClose: () => void;
  /** Called after a successful save (list refetch, etc.). */
  onSaved?: (scheduledCount: number) => void;
}

export function ScheduleDialog({ plan, plans = [], onClose, onSaved }: ScheduleDialogProps) {
  const { formatDateTime, zone } = useTimeFormat();
  const browserZoneName = useMemo(() => {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'; } catch { return 'UTC'; }
  }, []);
  const targets = useMemo(() => (plan ? [plan] : plans), [plan, plans]);
  // Exactly one target renders in single-plan mode (title + intent line).
  const isBulk = targets.length > 1;

  const [kind, setKind] = useState<Kind>('relative');
  const [presetMinutes, setPresetMinutes] = useState(15);
  const [customMinutes, setCustomMinutes] = useState('30');
  // Absolute: default to one hour from now.
  const [absoluteValue, setAbsoluteValue] = useState(() => toLocalInputValue(new Date(Date.now() + 60 * 60_000).toISOString()));
  const [policy, setPolicy] = useState<Policy>('run-asap');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  function dueIso(): string | number | null {
    if (kind === 'relative') {
      const mins = presetMinutes > 0 && RELATIVE_PRESETS.some((p) => p.minutes === presetMinutes) ? presetMinutes : Math.round(Number(customMinutes));
      if (!Number.isFinite(mins) || mins < 1) return null;
      return Date.now() + mins * 60_000; // ms — converted below
    }
    const iso = fromLocalInputValue(absoluteValue);
    if (!iso) return null;
    return new Date(iso).getTime();
  }

  function describeDue(): string {
    const dueMs = dueIso();
    if (typeof dueMs !== 'number' || Number.isNaN(dueMs)) return '';
    const d = new Date(dueMs);
    const when = d.toLocaleString(undefined, { weekday: 'short', year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    const diffMin = Math.round((dueMs - Date.now()) / 60_000);
    return diffMin >= 1 ? `in ~${diffMin} min` : '';
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const due = dueIso();
    if (typeof due !== 'number' || Number.isNaN(due)) {
      setError('Pick a valid future time.');
      return;
    }
    setBusy(true);
    try {
      let ok = 0;
      for (const p of targets) {
        await api.schedulePlan(p.id, { at: new Date(due).toISOString(), policy });
        ok += 1;
      }
      onSaved?.(ok);
      onClose();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError(`${err.message} — sign in again to complete two-factor authentication.`);
      } else {
        setError(err instanceof Error ? err.message : String(err));
      }
    } finally {
      setBusy(false);
    }
  }

  const dueMs = dueIso();
  const validDue = typeof dueMs === 'number' && !Number.isNaN(dueMs) && dueMs > Date.now() - 60_000;

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        className="mt-8 w-full max-w-lg rounded-lg border border-border bg-card p-5 shadow-xl"
      >
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <CalendarClock className="h-4 w-4 text-primary" />
            {isBulk ? `Schedule ${plans.length} plans` : 'Schedule plan'}
          </h2>
          <button type="button" onClick={onClose} aria-label="Close" className="rounded p-1 text-faint hover:bg-muted hover:text-secondary">
            <X className="h-4 w-4" />
          </button>
        </div>

        {!isBulk && targets[0] && (
          <p className="mb-3 truncate rounded border border-border bg-background px-2.5 py-1.5 text-xs text-secondary" title={targets[0].intentActionId}>
            {targets[0].intentActionId} · <StatusText status={targets[0].status} />
          </p>
        )}

        {/* Due time: relative or absolute */}
        <div className="mb-4">
          <label className="mb-1.5 block text-sm font-medium text-secondary">When</label>
          <div className="mb-2 flex gap-1 rounded-md border border-border p-0.5">
            {(['relative', 'absolute'] as Kind[]).map((k) => (
              <button
                key={k}
                type="button"
                onClick={() => setKind(k)}
                className={clsx(
                  'flex-1 rounded px-2 py-1 text-xs font-medium capitalize transition-colors',
                  kind === k ? 'bg-primary text-white' : 'text-secondary hover:bg-muted'
                )}
              >
                {k === 'relative' ? 'Relative (in …)' : 'Absolute (date & time)'}
              </button>
            ))}
          </div>

          {kind === 'relative' ? (
            <div className="space-y-2">
              <div className="grid grid-cols-3 gap-1.5">
                {RELATIVE_PRESETS.map((p) => (
                  <button
                    key={p.minutes}
                    type="button"
                    onClick={() => setPresetMinutes(p.minutes)}
                    className={clsx(
                      'rounded border px-2 py-1.5 text-xs font-medium',
                      presetMinutes === p.minutes ? 'border-primary bg-primary/10 text-primary' : 'border-border text-secondary hover:bg-muted'
                    )}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
              <label className="flex items-center gap-2 text-sm text-secondary">
                Or custom:
                <input
                  type="number"
                  min={1}
                  max={525600}
                  value={customMinutes}
                  onChange={(e) => setCustomMinutes(e.target.value)}
                  className="w-24 rounded-md border border-border bg-background px-2 py-1 text-sm"
                />
                minutes from now
              </label>
            </div>
          ) : (
            <input
              type="datetime-local"
              value={absoluteValue}
              onChange={(e) => setAbsoluteValue(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
            />
          )}

          {validDue && (
            <p className="mt-1.5 text-xs text-faint">
              Due: {formatDateTime(dueMs as number)} {describeDue() ? `(${describeDue()})` : ''}
              {/* The native datetime picker always works in the browser's zone; flag it when
                  the user's display timezone differs so the shown wall time isn't mistaken for
                  what the picker shows. */}
              {zone === browserZoneName ? ' — local time' : ` — ${zone} (picker uses your browser's clock)`}
            </p>
          )}
        </div>

        {/* Policy: what happens if the plugin is unreachable at the due instant */}
        <div className="mb-4">
          <label className="mb-1.5 block text-sm font-medium text-secondary">If UNM or the plugin is down when it's due</label>
          <div className="space-y-1.5">
            {(
              [
                { value: 'run-asap', title: 'Run as soon as possible', desc: 'Keep retrying (with backoff) until the plan executes successfully.' },
                { value: 'skip', title: 'Skip execution', desc: 'Mark the plan “skipped” — do not execute it. You can re-schedule it later.' },
              ] as Array<{ value: Policy; title: string; desc: string }>
            ).map((opt) => (
              <label
                key={opt.value}
                className={clsx(
                  'flex cursor-pointer items-start gap-2.5 rounded-md border px-3 py-2',
                  policy === opt.value ? 'border-primary bg-primary/10' : 'border-border hover:bg-muted'
                )}
              >
                <input type="radio" name="schedule-policy" checked={policy === opt.value} onChange={() => setPolicy(opt.value)} className="mt-0.5 h-4 w-4 accent-current" />
                <span>
                  <span className="block text-sm font-medium text-foreground">{opt.title}</span>
                  <span className="block text-xs text-secondary">{opt.desc}</span>
                </span>
              </label>
            ))}
          </div>
        </div>

        {error && (
          <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{error}</div>
        )}

        <div className="flex items-center justify-end gap-2">
          <button type="button" onClick={onClose} className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted">
            Cancel
          </button>
          <button
            type="submit"
            disabled={busy || !validDue}
            className="flex items-center gap-1.5 rounded-md bg-primary px-4 py-1.5 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            <CalendarClock className="h-4 w-4" />
            {busy ? 'Scheduling…' : isBulk ? `Schedule ${plans.length} plans` : 'Schedule'}
          </button>
        </div>
      </form>
    </div>
  );
}

function StatusText({ status }: { status: string }) {
  return <span className="capitalize">{status}</span>;
}
