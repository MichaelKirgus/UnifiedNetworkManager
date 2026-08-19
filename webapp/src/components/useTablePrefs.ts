import { useCallback, useEffect, useState } from 'react';

export interface TableSortState {
  key: string;
  dir: 'asc' | 'desc';
}

export interface TablePrefs {
  sort: TableSortState | null;
  hiddenKeys: string[];
  widths: Record<string, number>;
}

const DEFAULT_PREFS: TablePrefs = { sort: null, hiddenKeys: [], widths: {} };

function storageKeyFor(storageKey?: string): string | null {
  return storageKey ? `unm:datatable:${storageKey}` : null;
}

function normalizeSort(value: unknown): TableSortState | null {
  if (!value || typeof value !== 'object') return null;
  const s = value as Record<string, unknown>;
  if (typeof s.key !== 'string' || (s.dir !== 'asc' && s.dir !== 'desc')) return null;
  return { key: s.key, dir: s.dir };
}

function normalizeHiddenKeys(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((k): k is string => typeof k === 'string') : [];
}

function normalizeWidths(value: unknown): Record<string, number> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (typeof v === 'number' && Number.isFinite(v)) out[k] = v;
  }
  return out;
}

function loadPrefs(key: string | null): TablePrefs {
  if (!key) return DEFAULT_PREFS;
  try {
    const raw = window.localStorage.getItem(key);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Record<string, unknown>;
    return {
      sort: normalizeSort(parsed.sort),
      hiddenKeys: normalizeHiddenKeys(parsed.hiddenKeys),
      widths: normalizeWidths(parsed.widths),
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

/**
 * Per-table layout preferences (sort state, hidden columns, column widths).
 * When a stable `storageKey` is provided the prefs are persisted to
 * localStorage under `unm:datatable:<key>` so each table keeps its own
 * layout across reloads. Without a key they live in memory only.
 *
 * Note: `storageKey` is expected to be stable for the lifetime of the
 * component (each page passes a constant string).
 */
export function useTablePrefs(storageKey?: string) {
  const key = storageKeyFor(storageKey);
  const [prefs, setPrefs] = useState<TablePrefs>(() => loadPrefs(key));

  useEffect(() => {
    if (!key) return;
    try {
      window.localStorage.setItem(key, JSON.stringify(prefs));
    } catch {
      // Storage may be unavailable (private mode / quota); prefs stay in memory.
    }
  }, [key, prefs]);

  const reset = useCallback(() => setPrefs(DEFAULT_PREFS), []);

  return { prefs, setPrefs, reset };
}
