import { MouseEvent as ReactMouseEvent, ReactNode, useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';
import { RotateCcw, SlidersHorizontal } from 'lucide-react';
import { useTablePrefs } from './useTablePrefs';

export interface DataTableColumn<T> {
  header: string;
  key: string;
  render?: (row: T) => ReactNode;
  /** Whether the column can be sorted by clicking its header. Defaults to true. */
  sortable?: boolean;
  /** Optional accessor for sort values (e.g. dates). Falls back to `row[key]`. */
  sortAccessor?: (row: T) => string | number | null | undefined;
  /** Default width in px when the user has not resized this column. Defaults to 160. */
  width?: number;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  emptyMessage?: string;
  rowKey: (row: T) => string;
  /** Stable key for persisting layout prefs (sort/hidden/widths) to localStorage. */
  storageKey?: string;
}

const MIN_COL_WIDTH = 80;
const MAX_COL_WIDTH = 640;
const DEFAULT_COL_WIDTH = 160;

function clampWidth(w: number): number {
  return Math.min(MAX_COL_WIDTH, Math.max(MIN_COL_WIDTH, w));
}

function isEmptyValue(v: unknown): boolean {
  return v === null || v === undefined || (typeof v === 'string' && v.trim() === '');
}

/** Compare two sort values; empty/nullish values are handled by the caller. */
function compareValues(a: unknown, b: unknown): number {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  // `numeric: true` makes "item2" < "item10", which reads naturally for IDs/versions.
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

function sortRows<T>(rows: T[], columns: DataTableColumn<T>[], sortKey: string, dir: 'asc' | 'desc'): T[] {
  const col = columns.find((c) => c.key === sortKey);
  if (!col || col.sortable === false) return rows;
  const accessor = (row: T): unknown => (col.sortAccessor ? col.sortAccessor(row) : (row as Record<string, unknown>)[col.key]);
  const factor = dir === 'asc' ? 1 : -1;
  return [...rows].sort((a, b) => {
    const va = accessor(a);
    const vb = accessor(b);
    // Empty values always sink to the bottom regardless of direction.
    if (isEmptyValue(va) && isEmptyValue(vb)) return 0;
    if (isEmptyValue(va) !== isEmptyValue(vb)) return isEmptyValue(va) ? 1 : -1;
    return compareValues(va, vb) * factor;
  });
}

export function DataTable<T>({ columns, rows = [], emptyMessage = 'No data available.', rowKey, storageKey }: DataTableProps<T>) {
  const { prefs, setPrefs, reset } = useTablePrefs(storageKey);
  const [menuOpen, setMenuOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  // Close the column picker on outside click or Escape.
  useEffect(() => {
    if (!menuOpen) return;
    function onPointerDown(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) setMenuOpen(false);
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') setMenuOpen(false);
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [menuOpen]);

  const visibleColumns = useMemo(
    () => columns.filter((c) => !prefs.hiddenKeys.includes(c.key)),
    [columns, prefs.hiddenKeys]
  );

  const sortedRows = useMemo(() => {
    if (!prefs.sort) return rows;
    return sortRows(rows, columns, prefs.sort.key, prefs.sort.dir);
  }, [rows, columns, prefs.sort]);

  /** Explicit width for a column (user-resized or declared by the page), if any. */
  function explicitWidth(key: string): number | undefined {
    const w = prefs.widths[key] ?? columns.find((c) => c.key === key)?.width;
    return typeof w === 'number' ? clampWidth(w) : undefined;
  }

  /** Clicking a header cycles asc -> desc -> off. */
  function cycleSort(key: string) {
    setPrefs((p) => {
      if (!p.sort || p.sort.key !== key) return { ...p, sort: { key, dir: 'asc' } };
      if (p.sort.dir === 'asc') return { ...p, sort: { key, dir: 'desc' } };
      return { ...p, sort: null };
    });
  }

  function toggleColumn(key: string) {
    setPrefs((p) => {
      const hidden = p.hiddenKeys.includes(key);
      if (hidden) {
        return { ...p, hiddenKeys: p.hiddenKeys.filter((k) => k !== key) };
      }
      // Never allow hiding the last visible column.
      const remainingVisible = columns.length - p.hiddenKeys.length;
      if (remainingVisible <= 1) return p;
      return { ...p, hiddenKeys: [...p.hiddenKeys, key] };
    });
  }

  function startResize(e: ReactMouseEvent<HTMLSpanElement>, key: string) {
    e.preventDefault();
    const startX = e.clientX;
    // Columns without an explicit width are sized by the browser's table layout;
    // measure their rendered width as the resize starting point.
    const th = (e.currentTarget as HTMLElement).closest('th');
    const startWidth = explicitWidth(key) ?? (th ? Math.round(th.getBoundingClientRect().width) : DEFAULT_COL_WIDTH);
    let lastWidth = startWidth;
    function onMove(ev: MouseEvent) {
      lastWidth = clampWidth(startWidth + (ev.clientX - startX));
      setPrefs((p) => ({ ...p, widths: { ...p.widths, [key]: lastWidth } }));
    }
    function onUp() {
      window.removeEventListener('mousemove', onMove);
      window.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    }
    window.addEventListener('mousemove', onMove);
    window.addEventListener('mouseup', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }

  if (!rows || rows.length === 0) {
    return <div className="rounded-md border border-slate-200 bg-white p-6 text-center text-sm text-slate-500">{emptyMessage}</div>;
  }

  const sortKey = prefs.sort?.key ?? null;

  return (
    <div className="overflow-hidden rounded-md border border-slate-200 bg-white shadow-sm">
      {/* Toolbar: column visibility picker */}
      <div className="relative flex items-center justify-end gap-2 border-b border-slate-200 px-3 py-1.5" ref={menuRef}>
        <button
          type="button"
          onClick={() => setMenuOpen((v) => !v)}
          aria-haspopup="true"
          aria-expanded={menuOpen}
          aria-label="Toggle visible columns"
          title="Columns"
          className="flex items-center gap-1.5 rounded-md border border-slate-300 px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50"
        >
          <SlidersHorizontal className="h-3.5 w-3.5" />
          Columns
        </button>
        {menuOpen && (
          <div className="absolute right-3 z-20 mt-1 w-52 rounded-md border border-slate-200 bg-white p-2 shadow-lg">
            <p className="mb-1 px-1 text-[11px] font-semibold uppercase tracking-wide text-slate-400">Visible columns</p>
            {columns.map((col) => {
              const hidden = prefs.hiddenKeys.includes(col.key);
              const isLastVisible = !hidden && visibleColumns.length === 1;
              return (
                <label
                  key={col.key}
                  className={clsx(
                    'flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm text-slate-700 hover:bg-slate-50',
                    isLastVisible && 'cursor-not-allowed opacity-40'
                  )}
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                    checked={!hidden}
                    disabled={isLastVisible}
                    onChange={() => toggleColumn(col.key)}
                  />
                  {col.header}
                </label>
              );
            })}
            <div className="mt-1 border-t border-slate-200 pt-1">
              <button
                type="button"
                onClick={reset}
                className="flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-left text-xs font-medium text-slate-500 hover:bg-slate-50 hover:text-slate-700"
              >
                <RotateCcw className="h-3.5 w-3.5" />
                Reset layout
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full table-fixed divide-y divide-slate-200 text-sm">
          {/* Only columns with an explicit width (resized or declared) are pinned;
              the rest share the remaining space, so the table fits its container
              and no horizontal scrollbar appears unless the user resizes wider. */}
          <colgroup>
            {visibleColumns.map((col) => {
              const w = explicitWidth(col.key);
              return <col key={col.key} style={w ? { width: w } : undefined} />;
            })}
          </colgroup>
          <thead className="bg-slate-50">
            <tr>
              {visibleColumns.map((col) => {
                const sortable = col.sortable !== false;
                const active = sortKey === col.key && prefs.sort ? prefs.sort.dir : null;
                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={sortable ? (active === 'asc' ? 'ascending' : active === 'desc' ? 'descending' : 'none') : undefined}
                    className="relative select-none border-r border-slate-200 px-4 py-2 text-left font-semibold text-slate-600 last:border-r-0"
                  >
                    {sortable ? (
                      <button type="button" onClick={() => cycleSort(col.key)} className="group flex w-full items-center gap-1.5 text-left">
                        <span className="truncate">{col.header}</span>
                        <span aria-hidden="true" className={clsx('text-[10px] leading-none', active ? 'text-slate-700' : 'text-transparent group-hover:text-slate-400')}>
                          {active === 'asc' ? '▲' : active === 'desc' ? '▼' : '↕'}
                        </span>
                      </button>
                    ) : (
                      <span className="block truncate">{col.header}</span>
                    )}
                    {/* Resize grip on the right edge of the header cell */}
                    <span
                      role="separator"
                      aria-orientation="vertical"
                      title="Drag to resize column"
                      onMouseDown={(e) => startResize(e, col.key)}
                      className="absolute -right-1 top-0 h-full w-2 cursor-col-resize rounded hover:bg-slate-300/70 active:bg-slate-400"
                    />
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100">
            {sortedRows.map((row) => (
              <tr key={rowKey(row)} className="hover:bg-slate-50">
                {visibleColumns.map((col) => (
                  <td key={col.key} className="overflow-hidden px-4 py-2 text-slate-700">
                    {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
