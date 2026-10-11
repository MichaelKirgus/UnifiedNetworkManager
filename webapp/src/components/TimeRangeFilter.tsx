import { useEffect, useState } from 'react';
import clsx from 'clsx';

/**
 * TimeRangeFilter — a reusable start/end time-range selector for filter bars.
 *
 * Two modes:
 *   - PRESET (relative): "All time" or a fixed lookback window (15 min → 30 days).
 *     Relative presets SLIDE with the current time, so a page that refetches on an
 *     interval keeps "last hour" meaning the last hour — resolve inside queryFn.
 *   - CUSTOM (absolute): explicit start and/or end via datetime-local inputs,
 *     from a few minutes ago to weeks/months back. Either bound may be left empty
 *     (empty = unbounded on that side).
 *
 * The selection is `TimeRangeValue` — either a preset id string or a custom object.
 * Pages keep it in state (and their react-query key) and call `resolveTimeRangeIso`
 * inside the query function to get API-ready `{ from?, to? }` ISO bounds.
 *
 * Controlled (`value` + `onChange`) or uncontrolled (`defaultValue`). The default
 * may be relative (a preset id like '24h') or absolute ({ custom, from, to }).
 */

export interface TimeRangePreset {
  id: string;
  label: string;
  /** Lookback window in ms. `undefined` = unbounded ("All time"). */
  ms?: number;
}

const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;

/** Preset lookback windows — a few minutes to a month. Extend freely. */
export const TIME_RANGE_PRESETS: TimeRangePreset[] = [
  { id: 'all', label: 'All time' },
  { id: '15m', label: 'Last 15 minutes', ms: 15 * MIN },
  { id: '1h', label: 'Last hour', ms: HOUR },
  { id: '6h', label: 'Last 6 hours', ms: 6 * HOUR },
  { id: '24h', label: 'Last 24 hours', ms: DAY },
  { id: '7d', label: 'Last 7 days', ms: 7 * DAY },
  { id: '30d', label: 'Last 30 days', ms: 30 * DAY },
];

/** Sentinel preset id for the "Custom range…" option in the select. */
export const CUSTOM_RANGE_ID = '__custom__';

/** A time-range selection: a preset id, or an explicit absolute window. */
export type TimeRangeValue = string | { custom: true; from?: string; to?: string };

/** Resolved bounds as epoch ms (undefined = unbounded on that side). */
export interface ResolvedTimeRange {
  fromMs?: number;
  toMs?: number;
}

/** Resolve a selection into epoch-ms bounds. Relative presets slide with `now`. */
export function resolveTimeRange(value: TimeRangeValue, now: number = Date.now()): ResolvedTimeRange {
  if (typeof value === 'object' && value !== null) {
    const fromMs = value.from ? new Date(value.from).getTime() : undefined;
    const toMs = value.to ? new Date(value.to).getTime() : undefined;
    return { fromMs: Number.isNaN(fromMs as number) ? undefined : fromMs, toMs: Number.isNaN(toMs as number) ? undefined : toMs };
  }
  const preset = TIME_RANGE_PRESETS.find((p) => p.id === value);
  if (!preset || preset.ms === undefined) return {}; // "All time" / unknown → unbounded
  return { fromMs: now - preset.ms, toMs: now };
}

/** Resolve a selection into ISO-8601 bounds for API calls (undefined = unbounded). */
export function resolveTimeRangeIso(value: TimeRangeValue, now: number = Date.now()): { from?: string; to?: string } {
  const r = resolveTimeRange(value, now);
  return {
    from: r.fromMs !== undefined ? new Date(r.fromMs).toISOString() : undefined,
    to: r.toMs !== undefined ? new Date(r.toMs).toISOString() : undefined,
  };
}

/** True when the selection is a custom (absolute) window. */
export function isCustomRange(value: TimeRangeValue): value is { custom: true; from?: string; to?: string } {
  return typeof value === 'object' && value !== null;
}

// --- datetime-local <-> ISO helpers (local-time interpretation) ---------------

function isoToLocalInput(iso?: string): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localInputToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v); // datetime-local parses as LOCAL time
  if (Number.isNaN(d.getTime())) return undefined;
  return d.toISOString();
}

interface TimeRangeFilterProps {
  /** Controlled selection. Omit for uncontrolled mode (use `defaultValue`). */
  value?: TimeRangeValue;
  onChange?: (value: TimeRangeValue) => void;
  /** Uncontrolled initial selection — relative preset id or absolute custom object. */
  defaultValue?: TimeRangeValue;
  /** Optional visible label rendered above the controls. */
  label?: string;
  className?: string;
}

export function TimeRangeFilter({ value, onChange, defaultValue = '24h', label, className }: TimeRangeFilterProps) {
  const controlled = value !== undefined && onChange !== undefined;
  const [internal, setInternal] = useState<TimeRangeValue>(defaultValue);
  // Keep internal state in sync when used as a controlled component.
  useEffect(() => {
    if (controlled) setInternal(value as TimeRangeValue);
  }, [value, controlled]);

  const current: TimeRangeValue = controlled ? (value as TimeRangeValue) : internal;
  function emit(next: TimeRangeValue) {
    if (!controlled) setInternal(next);
    onChange?.(next);
  }

  const custom = isCustomRange(current);
  // The select shows the active preset, or CUSTOM_RANGE_ID when in custom mode.
  const selectValue = custom ? CUSTOM_RANGE_ID : current;

  function onPresetChange(id: string) {
    if (id === CUSTOM_RANGE_ID) emit({ custom: true });
    else emit(id);
  }

  return (
    <div className={className}>
      {label && <label className="mb-1 block text-xs font-medium text-secondary">{label}</label>}
      <div className="flex flex-wrap items-center gap-2">
        <select
          className="rounded-md border border-border bg-background px-2.5 py-1.5 text-sm"
          value={selectValue}
          onChange={(e) => onPresetChange(e.target.value)}
        >
          {TIME_RANGE_PRESETS.map((p) => (
            <option key={p.id} value={p.id}>
              {p.label}
            </option>
          ))}
          <option value={CUSTOM_RANGE_ID}>Custom range…</option>
        </select>

        {custom && (
          <>
            <input
              type="datetime-local"
              aria-label="Range start"
              className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={isoToLocalInput(current.from)}
              onChange={(e) => emit({ custom: true, from: localInputToIso(e.target.value), to: current.to })}
            />
            <span className="text-xs text-faint">→</span>
            <input
              type="datetime-local"
              aria-label="Range end"
              className="rounded-md border border-border bg-background px-2 py-1.5 text-sm"
              value={isoToLocalInput(current.to)}
              onChange={(e) => emit({ custom: true, from: current.from, to: localInputToIso(e.target.value) })}
            />
          </>
        )}
      </div>
    </div>
  );
}
