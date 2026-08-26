import { MouseEvent as ReactMouseEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';
import { Download, Filter, RotateCcw, Search, SlidersHorizontal, X } from 'lucide-react';
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
  /** Whether a per-column filter input is offered for this column. Defaults to true. */
  filterable?: boolean;
  /** Explicit value used by CSV/JSON export (and quick search). Falls back to sortAccessor, then row[key]. */
  exportValue?: (row: T) => string | number | null | undefined;
  /** Exclude this column from CSV/JSON exports (e.g. Actions columns). */
  excludeFromExport?: boolean;
}

/** A bulk action offered in the selection bar when `selectable` is set. */
export interface DataTableBulkAction<T> {
  label: string;
  /** Optional confirmation dialog text; receives the number of selected rows. */
  confirm?: (count: number) => string;
  /** Called with the currently selected rows (resolved from the full row list). */
  onClick: (rows: T[]) => void | Promise<void>;
}

interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  rows: T[];
  emptyMessage?: string;
  rowKey: (row: T) => string;
  /** Stable key for persisting layout prefs (sort/hidden/widths) to localStorage. */
  storageKey?: string;
  /** Placeholder for the quick-search input (session-only, not persisted). */
  searchPlaceholder?: string;
  /** Adds a leading checkbox column + select-all + selection bar with bulk actions. */
  selectable?: boolean;
  /** Bulk action buttons rendered in the selection bar (requires `selectable`). */
  bulkActions?: DataTableBulkAction<T>[];
  /** Called when the pointer enters a row, or leaves the table body entirely.
   * Used e.g. by the WiFi page to highlight matching spectrum bars on hover. */
  onRowHover?: (row: T | null) => void;
  /** Fill the parent's height (parent must have a definite height, e.g. the
   * WiFi table pane behind the splitter). Without it the card grows with its
   * content up to a viewport-based cap; either way the header + filter rows
   * stay pinned while the body scrolls internally. */
  fillHeight?: boolean;
}

const MIN_COL_WIDTH = 80;
const MAX_COL_WIDTH = 640;
const DEFAULT_COL_WIDTH = 160;
const SELECT_COL_WIDTH = 40;

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

/** Machine-readable value of a cell: exportValue → sortAccessor → row[key]. */
function cellValue<T>(col: DataTableColumn<T>, row: T): unknown {
  if (col.exportValue) return col.exportValue(row);
  if (col.sortAccessor) return col.sortAccessor(row);
  return (row as Record<string, unknown>)[col.key];
}

/** Human-readable text of a cell for search matching. */
function searchText<T>(col: DataTableColumn<T>, row: T): string {
  const v = cellValue(col, row);
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  try {
    return JSON.stringify(v);
  } catch {
    return '';
  }
}

/** RFC-4180 CSV cell escaping. */
function csvCell(v: unknown): string {
  if (v === null || v === undefined) return '';
  const s = typeof v === 'string' ? v : typeof v === 'number' || typeof v === 'boolean' ? String(v) : JSON.stringify(v);
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

function toCsv<T>(columns: DataTableColumn<T>[], rows: T[]): string {
  const cols = columns.filter((c) => !c.excludeFromExport);
  const lines = [cols.map((c) => csvCell(c.header)).join(',')];
  for (const row of rows) lines.push(cols.map((c) => csvCell(cellValue(c, row))).join(','));
  return '\uFEFF' + lines.join('\r\n'); // BOM so Excel opens UTF-8 correctly
}

function toJson<T>(columns: DataTableColumn<T>[], rows: T[]): string {
  const cols = columns.filter((c) => !c.excludeFromExport);
  return JSON.stringify(rows.map((row) => Object.fromEntries(cols.map((c): [string, unknown] => [c.key, cellValue(c, row)]))), null, 2);
}

function downloadFile(filename: string, content: string, mime: string): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function DataTable<T>({
  columns,
  rows = [],
  emptyMessage = 'No data available.',
  rowKey,
  storageKey,
  searchPlaceholder = 'Search…',
  selectable = false,
  bulkActions,
  onRowHover,
  fillHeight = false,
}: DataTableProps<T>) {
  const { prefs, setPrefs, reset } = useTablePrefs(storageKey);
  const [menuOpen, setMenuOpen] = useState(false); // column visibility picker
  const [exportOpen, setExportOpen] = useState(false); // export dropdown
  const menuRef = useRef<HTMLDivElement>(null);
  const [searchText_, setSearchText_] = useState('');
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());

  // Rows currently passing search + column filters (pre-sort) — used by select-all.
  const filteredRef = useRef<T[]>([]);
  // Native checkbox indeterminate state is not a React prop; set it via ref callback.
  const selectAllRef = useCallback(
    (el: HTMLInputElement | null) => {
      if (el) el.indeterminate = selectedKeys.size > 0 && filteredRef.current.length > 0 && selectedKeys.size < filteredRef.current.length;
    },
    [selectedKeys]
  );

  // Close the column picker / export menu on outside click or Escape.
  useEffect(() => {
    if (!menuOpen && !exportOpen) return;
    function onPointerDown(e: MouseEvent) {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuOpen(false);
        setExportOpen(false);
      }
    }
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') {
        setMenuOpen(false);
        setExportOpen(false);
      }
    }
    document.addEventListener('mousedown', onPointerDown);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onPointerDown);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, [menuOpen, exportOpen]);

  const visibleColumns = useMemo(
    () => columns.filter((c) => !prefs.hiddenKeys.includes(c.key)),
    [columns, prefs.hiddenKeys]
  );

  // Row pipeline: search (visible cols) → per-column filters (AND) → sort.
  const viewRows = useMemo(() => {
    let out = rows;
    const q = searchText_.trim().toLowerCase();
    if (q) {
      out = out.filter((row) => visibleColumns.some((col) => searchText(col, row).toLowerCase().includes(q)));
    }
    for (const col of visibleColumns) {
      const f = (colFilters[col.key] ?? '').trim().toLowerCase();
      if (!f) continue;
      out = out.filter((row) => searchText(col, row).toLowerCase().includes(f));
    }
    filteredRef.current = out;
    return prefs.sort ? sortRows(out, columns, prefs.sort.key, prefs.sort.dir) : out;
  }, [rows, visibleColumns, colFilters, searchText_, prefs.sort, columns]);

  // Drop selected keys whose rows disappeared from the dataset (e.g. deleted).
  useEffect(() => {
    if (!selectable || selectedKeys.size === 0) return;
    const current = new Set(rows.map(rowKey));
    for (const k of Array.from(selectedKeys)) {
      if (!current.has(k)) setSelectedKeys((prev) => { const n = new Set(prev); n.delete(k); return n; });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, selectable]);

  const hasActiveNarrowing = searchText_.trim() !== '' || Object.values(colFilters).some((f) => (f ?? '').trim() !== '');
  const activeFilterCols = visibleColumns.filter((c) => (colFilters[c.key] ?? '').trim() !== '');

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

  function clearNarrowing() {
    setSearchText_('');
    setColFilters({});
  }

  /* ------------------------------ selection ------------------------------ */

  const allSelected = filteredRef.current.length > 0 && filteredRef.current.every((r) => selectedKeys.has(rowKey(r)));

  function toggleSelectAll() {
    setSelectedKeys(() => (allSelected ? new Set() : new Set(filteredRef.current.map(rowKey))));
  }

  function toggleRow(key: string) {
    setSelectedKeys((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  function clearSelection() {
    setSelectedKeys(new Set());
  }

  async function runBulkAction(action: DataTableBulkAction<T>) {
    const selected = rows.filter((r) => selectedKeys.has(rowKey(r)));
    if (selected.length === 0) return;
    if (action.confirm && !window.confirm(action.confirm(selected.length))) return;
    await action.onClick(selected);
  }

  /* ------------------------------- export -------------------------------- */

  function handleExport(format: 'csv' | 'json') {
    const base = storageKey ?? 'export';
    if (format === 'csv') downloadFile(`${base}.csv`, toCsv(visibleColumns, viewRows), 'text/csv;charset=utf-8');
    else downloadFile(`${base}.json`, toJson(visibleColumns, viewRows), 'application/json');
    setExportOpen(false);
  }

  /* ------------------------------ resizing ------------------------------- */

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
    // NOTE: no overflow-hidden here — the toolbar dropdowns are absolutely
    // positioned and must be allowed to extend beyond the card's edges.
    // Flex column with a viewport-based cap: tall tables scroll INTERNALLY so
    // the toolbar, status line and (sticky) header rows never leave the screen.
    // With fillHeight the parent's height is authoritative (no viewport cap);
    // otherwise tall tables are capped so they scroll internally on normal pages.
    <div className={clsx('flex flex-col rounded-md border border-slate-200 bg-white shadow-sm', fillHeight ? 'h-full' : 'max-h-[calc(100vh-200px)]')}>
      {/* Toolbar: quick search + filter toggle | column picker + export */}
      <div className="relative flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-200 px-3 py-1.5" ref={menuRef}>
        <div className="relative min-w-[180px] flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-400" />
          <input
            type="text"
            value={searchText_}
            onChange={(e) => setSearchText_(e.target.value)}
            placeholder={searchPlaceholder}
            aria-label="Quick search rows"
            className="w-full rounded-md border border-slate-300 py-1 pl-7 pr-2 text-xs text-slate-700 focus:border-slate-400 focus:outline-none"
          />
        </div>

        <button
          type="button"
          onClick={() => setShowFilters((v) => !v)}
          aria-pressed={showFilters}
          title="Toggle per-column filters"
          className={clsx(
            'flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium',
            showFilters || activeFilterCols.length > 0
              ? 'border-slate-400 bg-slate-100 text-slate-800'
              : 'border-slate-300 text-slate-600 hover:bg-slate-50'
          )}
        >
          <Filter className="h-3.5 w-3.5" />
          Filter
          {activeFilterCols.length > 0 && (
            <span className="rounded-full bg-slate-700 px-1.5 text-[10px] font-semibold leading-4 text-white">{activeFilterCols.length}</span>
          )}
        </button>

        <div className="ml-auto flex items-center gap-2">
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
          <div className="relative">
            <button
              type="button"
              onClick={() => setExportOpen((v) => !v)}
              aria-haspopup="true"
              aria-expanded={exportOpen}
              title="Export the current view as CSV or JSON"
              className="flex items-center gap-1.5 rounded-md border border-slate-300 px-2 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50"
            >
              <Download className="h-3.5 w-3.5" />
              Export
            </button>
            {exportOpen && (
              // top-full: anchor below the button — without an explicit top, an
              // abspos child of a flex row is vertically CENTERED on it and gets
              // clipped by anything with overflow hidden.
              <div className="absolute right-0 top-full z-20 mt-1 w-44 rounded-md border border-slate-200 bg-white p-1 shadow-lg">
                <p className="px-1.5 pb-1 pt-0.5 text-[11px] font-semibold uppercase tracking-wide text-slate-400">
                  Export {viewRows.length} row{viewRows.length === 1 ? '' : 's'} (current view)
                </p>
                <button type="button" onClick={() => handleExport('csv')} className="block w-full rounded px-1.5 py-1 text-left text-sm text-slate-700 hover:bg-slate-50">
                  CSV
                </button>
                <button type="button" onClick={() => handleExport('json')} className="block w-full rounded px-1.5 py-1 text-left text-sm text-slate-700 hover:bg-slate-50">
                  JSON
                </button>
              </div>
            )}
          </div>
        </div>
        {menuOpen && (
          // top-full: open below the toolbar (see export menu note above).
          <div className="absolute right-3 top-full z-20 mt-1 w-52 rounded-md border border-slate-200 bg-white p-2 shadow-lg">
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

      {/* Status line: row count + active filter chips (only when narrowing) */}
      {hasActiveNarrowing && (
        <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-slate-200 bg-slate-50/60 px-3 py-1 text-xs text-slate-500">
          <span>
            {viewRows.length} of {rows.length} rows
          </span>
          {searchText_.trim() !== '' && (
            <button
              type="button"
              onClick={() => setSearchText_('')}
              className="flex items-center gap-1 rounded-full border border-slate-300 bg-white px-2 py-0.5 text-slate-600 hover:bg-slate-100"
            >
              search: “{searchText_.trim()}” <X className="h-3 w-3" />
            </button>
          )}
          {activeFilterCols.map((col) => (
            <button
              key={col.key}
              type="button"
              onClick={() => setColFilters((f) => ({ ...f, [col.key]: '' }))}
              className="flex items-center gap-1 rounded-full border border-slate-300 bg-white px-2 py-0.5 text-slate-600 hover:bg-slate-100"
            >
              {col.header}: “{(colFilters[col.key] ?? '').trim()}” <X className="h-3 w-3" />
            </button>
          ))}
          <button type="button" onClick={clearNarrowing} className="ml-auto font-medium text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline">
            Clear all
          </button>
        </div>
      )}

      {/* Selection bar with bulk actions */}
      {selectable && selectedKeys.size > 0 && (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-slate-200 bg-blue-50/60 px-3 py-1.5 text-sm">
          <span className="font-medium text-slate-700">{selectedKeys.size} selected</span>
          {(bulkActions ?? []).map((action) => (
            <button
              key={action.label}
              type="button"
              onClick={() => void runBulkAction(action)}
              className="rounded-md border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50"
            >
              {action.label} ({selectedKeys.size})
            </button>
          ))}
          <button type="button" onClick={clearSelection} className="ml-auto text-xs font-medium text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline">
            Clear selection
          </button>
        </div>
      )}

      {viewRows.length === 0 ? (
        <div className="p-6 text-center text-sm text-slate-500">
          No rows match the current search/filters.{' '}
          <button type="button" onClick={clearNarrowing} className="font-medium text-slate-700 underline-offset-2 hover:underline">
            Clear
          </button>
        </div>
      ) : (
        // The ONLY scroll container of the card — header rows below are sticky
        // inside it, so they stay visible while the body scrolls.
        <div className="min-h-0 flex-1 overflow-auto">
        <table className="min-w-full table-fixed text-sm">
          {/* Only columns with an explicit width (resized or declared) are pinned;
              the rest share the remaining space, so the table fits its container
              and no horizontal scrollbar appears unless the user resizes wider. */}
          <colgroup>
            {selectable && <col key="__select" style={{ width: SELECT_COL_WIDTH }} />}
            {visibleColumns.map((col) => {
              const w = explicitWidth(col.key);
              return <col key={col.key} style={w ? { width: w } : undefined} />;
            })}
          </colgroup>
          <thead className="bg-slate-50">
            <tr>
                {selectable && (
                  <th scope="col" className="border-r border-slate-200 px-3 py-2">
                    <input
                      ref={selectAllRef}
                      type="checkbox"
                      aria-label="Select all visible rows"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      className="h-3.5 w-3.5 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                    />
                  </th>
                )}
              {visibleColumns.map((col) => {
                const sortable = col.sortable !== false;
                const active = sortKey === col.key && prefs.sort ? prefs.sort.dir : null;
                return (
                  <th
                    key={col.key}
                    scope="col"
                    aria-sort={sortable ? (active === 'asc' ? 'ascending' : active === 'desc' ? 'descending' : 'none') : undefined}
                    // sticky pins the header to the top of the scroll container;
                    // opaque bg is required so rows don't show through. The
                    // border-b replaces the old table-level divide-y (which would
                    // scroll away under the pinned header).
                    className="sticky top-0 z-10 select-none border-b border-r border-slate-200 bg-slate-50 px-4 py-2 text-left font-semibold text-slate-600 last:border-r-0"
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
              {showFilters && (
                <tr className="bg-white">
                  {/* top-[37px] = header row height (py-2 + 20px line-height +
                      1px border) — keeps the filter inputs pinned directly
                      under the header with no gap or overlap. */}
                  {selectable && <td className="sticky top-[37px] z-10 border-b border-r border-slate-200 bg-white" />}
                  {visibleColumns.map((col) => (
                    <td key={col.key} className="sticky top-[37px] z-10 border-b border-r border-slate-200 bg-white px-2 py-1 last:border-r-0">
                      {col.filterable !== false ? (
                        <input
                          type="text"
                          value={colFilters[col.key] ?? ''}
                          onChange={(e) => setColFilters((f) => ({ ...f, [col.key]: e.target.value }))}
                          placeholder={`Filter ${col.header.toLowerCase()}`}
                          aria-label={`Filter by ${col.header}`}
                          className="w-full rounded border border-slate-200 px-1.5 py-0.5 text-xs text-slate-700 focus:border-slate-400 focus:outline-none"
                        />
                      ) : (
                        <span />
                      )}
                    </td>
                  ))}
                </tr>
              )}
          </thead>
          <tbody
            className="divide-y divide-slate-100"
            onMouseLeave={() => onRowHover?.(null)}
          >
            {viewRows.map((row) => {
              const key = rowKey(row);
              return (
                <tr
                  key={key}
                  className={clsx('hover:bg-slate-50', selectable && selectedKeys.has(key) && 'bg-blue-50/40')}
                  onMouseEnter={() => onRowHover?.(row)}
                >
                  {selectable && (
                    <td className="px-3 py-2">
                      <input
                        type="checkbox"
                        aria-label={`Select row ${key}`}
                        checked={selectedKeys.has(key)}
                        onChange={() => toggleRow(key)}
                        className="h-3.5 w-3.5 rounded border-slate-300 text-slate-900 focus:ring-slate-400"
                      />
                    </td>
                  )}
                  {visibleColumns.map((col) => (
                    <td key={col.key} className="overflow-hidden px-4 py-2 text-slate-700">
                      {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                    </td>
                  ))}
                </tr>
              );
            })}
          </tbody>
        </table>
        </div>
      )}
    </div>
  );
}
