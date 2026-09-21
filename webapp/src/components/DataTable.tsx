import { Fragment, MouseEvent as ReactMouseEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import clsx from 'clsx';
import { ChevronDown, ChevronRight, Download, Filter, RefreshCw, RotateCcw, Search, SlidersHorizontal, X } from 'lucide-react';
import { useTablePrefs } from './useTablePrefs';

/** Context handed to `expandable.renderChild` for one child row. The page uses
 * this to build a FULL `<tr>` (one cell per visible column) so expanded children
 * stay aligned with the header columns — not a single full-width detail cell. */
export interface ExpandChildContext {
  /** Nesting level (0 = direct child of a top-level row). */
  depth: number;
  /** True when the child itself has children (recursive expansion possible). */
  hasChildren: boolean;
  /** Current expanded state of THIS child — only meaningful when hasChildren. */
  expanded: boolean;
  /** Toggles the child's own expanded state — only meaningful when hasChildren. */
  onToggle?: () => void;
  /** True when the table has a leading checkbox column (selectable). Child rows
   * must render an EMPTY selection cell after their chevron to stay aligned with
   * the header and parent rows — children themselves are not selectable. */
  selectable?: boolean;
  /** The currently visible columns (same order/widths as the header) so the
   * page can render one aligned `<td>` per column for each child row. */
  columns: DataTableColumn<never>[];
}

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
  exportValue?: (row: T) => string | number | null | undefined;  /** Custom text used ONLY for quick-search / column-filter matching. Lets a
   * parent row be found by data that lives in its children (e.g. a device row
   * matched by one of its package names). Falls back to exportValue/sortAccessor/row[key]. */
  searchText?: (row: T) => string;  /** Exclude this column from CSV/JSON exports (e.g. Actions columns). */
  excludeFromExport?: boolean;
  /** Hidden on first render — useful for secondary/diagnostic data that is
   * available but not worth the default screen space. Users can still enable it
   * via the Columns picker; once they change ANY column visibility (or reset
   * the layout) their explicit choice wins over this default. */
  hiddenByDefault?: boolean;
}

/** A bulk action offered in the selection bar when `selectable` is set. */
export interface DataTableBulkAction<T> {
  label: string;
  /** Optional confirmation dialog text; receives the number of selected rows. */
  confirm?: (count: number) => string;
  /** Called with the currently selected rows (resolved from the full row list). */
  onClick: (rows: T[]) => void | Promise<void>;
  /** When set, the button is disabled unless this returns true for the current selection. */
  enabled?: (rows: T[]) => boolean;
}

/** Minimal shape of an auto-refreshing query — satisfied by any useQuery() result.
 * Methods are optional because the query-result union includes placeholder/error
 * variants that don't carry them. */
export interface AutoRefreshable {
  setRefetchInterval?: (interval: false | number) => void;
  refetch?: () => unknown;
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
  /** Optional extra CSS classes for one data row (e.g. dimming stale rows).
   * Applied to the `<tr>` after the default hover/selection classes. */
  rowClassName?: (row: T) => string | undefined;
  /** Imperative selection handle — when provided, `ref.current(keys)` selects
   * exactly those row keys (replaces any current selection). Used e.g. to
   * select all duplicate rows of a host with one click before merging them. */
  selectionRef?: React.MutableRefObject<((keys: string[]) => void) | null>;
  /** Called when the pointer enters a row, or leaves the table body entirely.
   * Used e.g. by the WiFi page to highlight matching spectrum bars on hover. */
  onRowHover?: (row: T | null) => void;  /** Optional detail content rendered in a full-width row directly under each
   * data row (e.g. per-plugin self-metrics on the Plugins page). */
  renderRowDetail?: (row: T) => ReactNode;
  /** Optional expandable rows (e.g. ZFS datasets nested hierarchically under
   * their pool on the Storage page). When set, a leading chevron column appears;
   * rows whose `childrenOf` returns a non-empty array are toggleable and render
   * each child via `renderChild`. Children can be nested recursively — a child
   * that itself has children gets its own chevron. Expansion state is
   * session-only (not persisted) and children are excluded from search/export
   * like renderRowDetail. */
  expandable?: {
    /** Child rows for one parent; empty array = not expandable. */
    childrenOf: (row: T) => T[];
    /** Renders ONE child as a full `<tr>` under the expanded parent — a leading
     * cell for its own chevron plus one cell per visible column (see
     * `ctx.columns`) so it stays aligned with the header. The `ctx` carries
     * nesting depth and, when the child itself has children, an `onToggle`
     * so the page can draw a working chevron for recursive expansion. */
    renderChild: (child: T, parent: T, ctx: ExpandChildContext) => ReactNode;
  };  /** Fill the parent's height (parent must have a definite height, e.g. the
   * WiFi table pane behind the splitter). Without it the card grows with its
   * content up to a viewport-based cap; either way the header + filter rows
   * stay pinned while the body scrolls internally. */
  fillHeight?: boolean;
  /** When provided, adds a Live/Paused toggle to the toolbar that pauses or resumes
   * background refetching of the page's polling queries. The choice is persisted per
   * table (via `storageKey`); resuming triggers an immediate refresh and restores
   * `intervalMs`. */
  autoRefresh?: {
    /** Base refresh cadence in ms, restored when toggled back on. */
    intervalMs: number;
    /** The page's auto-refreshing queries (any useQuery result works). */
    queries: AutoRefreshable[];
  };
}

const MIN_COL_WIDTH = 80;
const MAX_COL_WIDTH = 640;
const DEFAULT_COL_WIDTH = 160;
const SELECT_COL_WIDTH = 40;
const EXPAND_COL_WIDTH = 36;

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

/** Flattens a row's full subtree (self + all descendants, depth-first) so that
 * search and per-column filters can match against nested expandable children —
 * e.g. finding an app by one of its containers' images or volume mounts. */
function collectSubtree<T>(root: T, childrenOf: (r: T) => T[]): T[] {
  const out: T[] = [root];
  const stack: T[] = [...childrenOf(root)];
  while (stack.length > 0) {
    const n = stack.pop() as T;
    out.push(n);
    for (const c of childrenOf(n)) stack.push(c);
  }
  return out;
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
  if (col.searchText) return col.searchText(row);
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
  rowClassName,
  selectionRef,
  onRowHover,
  renderRowDetail,
  expandable,
  fillHeight = false,
  autoRefresh,
}: DataTableProps<T>) {
  const { prefs, setPrefs, reset } = useTablePrefs(storageKey);
  const [menuOpen, setMenuOpen] = useState(false); // column visibility picker
  const [exportOpen, setExportOpen] = useState(false); // export dropdown
  const menuRef = useRef<HTMLDivElement>(null);
  const [searchText_, setSearchText_] = useState('');
  const [colFilters, setColFilters] = useState<Record<string, string>>({});
  const [showFilters, setShowFilters] = useState(false);
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set());
  // Expanded parent rows (expandable prop) — session-only like selection.
  const [expandedKeys, setExpandedKeys] = useState<Set<string>>(new Set());

  // Imperative selection handle for the owning page (see `selectionRef`).
  useEffect(() => {
    if (!selectionRef) return;
    selectionRef.current = (keys: string[]) => setSelectedKeys(new Set(keys));
    return () => {
      selectionRef.current = null;
    };
  }, [selectionRef]);

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

  // Auto-refresh toggle state lives in the persisted table prefs so each page
  // remembers its choice across reloads (default: on). The queries are kept in a
  // ref — the prop is an inline object whose identity changes every render, and we
  // only want to touch the query timers when the toggle actually flips.
  const autoRefreshOn = prefs.autoRefreshOn !== false;
  const autoRefreshRef = useRef(autoRefresh);
  useEffect(() => {
    autoRefreshRef.current = autoRefresh;
  });
  useEffect(() => {
    const ar = autoRefreshRef.current;
    if (!ar) return;
    for (const q of ar.queries) q.setRefetchInterval?.(autoRefreshOn ? ar.intervalMs : false);
  }, [autoRefreshOn]);

  function toggleAutoRefresh() {
    const next = !autoRefreshOn;
    setPrefs((p) => ({ ...p, autoRefreshOn: next }));
    // Resume with an immediate refresh so the data isn't stale by a full interval.
    if (next && autoRefresh) for (const q of autoRefresh.queries) void q.refetch?.();
  }

  // Columns a page marks `hiddenByDefault` stay hidden until the user has
  // explicitly customized visibility (or reset to defaults) — so new
  // default-hidden columns also apply for users with pre-existing saved prefs.
  const visibleColumns = useMemo(
    () =>
      columns.filter((c) => {
        if (prefs.hiddenKeys.includes(c.key)) return false;
        if (!prefs.visibilityTouched && c.hiddenByDefault) return false;
        return true;
      }),
    [columns, prefs.hiddenKeys, prefs.visibilityTouched]
  );

  // Row pipeline: search (visible cols) → per-column filters (AND) → sort. With
  // expandable rows, matching also considers each row's nested children so an
  // app is found by any of its containers' images/volumes/networks.
  const viewRows = useMemo(() => {
    let out = rows;
    const kidsOf = expandable ? (r: T) => expandable.childrenOf(r) : () => [] as T[];
    const q = searchText_.trim().toLowerCase();
    if (q) {
      out = out.filter((row) =>
        visibleColumns.some((col) => collectSubtree(row, kidsOf).some((n) => searchText(col, n).toLowerCase().includes(q)))
      );
    }
    for (const col of visibleColumns) {
      const f = (colFilters[col.key] ?? '').trim().toLowerCase();
      if (!f) continue;
      out = out.filter((row) => collectSubtree(row, kidsOf).some((n) => searchText(col, n).toLowerCase().includes(f)));
    }
    filteredRef.current = out;
    return prefs.sort ? sortRows(out, columns, prefs.sort.key, prefs.sort.dir) : out;
  }, [rows, visibleColumns, colFilters, searchText_, prefs.sort, columns, expandable]);

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

  /** Effective hidden state of a column — saved prefs PLUS any `hiddenByDefault`
   * flag while the user has not yet customized visibility. */
  function isColHidden(p: { hiddenKeys: string[]; visibilityTouched?: boolean }, key: string): boolean {
    if (p.hiddenKeys.includes(key)) return true;
    const col = columns.find((c) => c.key === key);
    return !p.visibilityTouched && !!col?.hiddenByDefault;
  }

  function toggleColumn(key: string) {
    setPrefs((p) => {
      // On the FIRST explicit change, adopt the current effective state (which
      // includes any `hiddenByDefault` columns) as the saved baseline — so
      // toggling one column doesn't suddenly reveal other default-hidden ones.
      let baseHidden: string[];
      if (!p.visibilityTouched) {
        const eff = new Set(p.hiddenKeys);
        for (const c of columns) if (c.hiddenByDefault) eff.add(c.key);
        baseHidden = [...eff];
      } else {
        baseHidden = p.hiddenKeys;
      }
      const hidden = baseHidden.includes(key);
      if (hidden) {
        return { ...p, visibilityTouched: true, hiddenKeys: baseHidden.filter((k) => k !== key) };
      }
      // Never allow hiding the last visible column.
      const remainingVisible = columns.length - baseHidden.length;
      if (remainingVisible <= 1) return p;
      return { ...p, visibilityTouched: true, hiddenKeys: [...baseHidden, key] };
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

  // Recursive renderer for expanded children (expandable prop). A child that
  // itself has children gets its own chevron and renders ITS children below —
  // this is what makes the Storage page's ZFS tree nest to arbitrary depth.
  // `renderChild` returns a full `<tr>` with one cell per visible column, so
  // expanded rows stay aligned with the header (not a single wide detail row).
  const renderChildRows = (parent: T, parentKey: string, depth: number): ReactNode => {
    if (!expandable) return null;
    const kids = expandable.childrenOf(parent);
    if (kids.length === 0) return null;
    return kids.map((child) => {
      const ckey = rowKey(child);
      const childKids = expandable.childrenOf(child);
      const hasChildren = childKids.length > 0;
      const childExpanded = expandedKeys.has(ckey);
      const ctx: ExpandChildContext = {
        depth,
        hasChildren,
        expanded: childExpanded,
        onToggle: hasChildren ? () => setExpandedKeys((prev) => {
          const next = new Set(prev);
          if (next.has(ckey)) next.delete(ckey); else next.add(ckey);
          return next;
        }) : undefined,
        selectable: selectable ?? false,
        columns: visibleColumns as DataTableColumn<never>[],
      };
      return (
        <Fragment key={`${parentKey}>${ckey}`}>
          {expandable.renderChild(child, parent, ctx)}
          {childExpanded && hasChildren ? renderChildRows(child, ckey, depth + 1) : null}
        </Fragment>
      );
    });
  };

  if (!rows || rows.length === 0) {
    return <div className="rounded-md border border-border bg-card p-6 text-center text-sm text-muted-foreground">{emptyMessage}</div>;
  }

  const sortKey = prefs.sort?.key ?? null;

  return (
    // NOTE: no overflow-hidden here — the toolbar dropdowns are absolutely
    // positioned and must be allowed to extend beyond the card's edges.
    // Flex column with a viewport-based cap: tall tables scroll INTERNALLY so
    // the toolbar, status line and (sticky) header rows never leave the screen.
    // With fillHeight the parent's height is authoritative (no viewport cap);
    // otherwise tall tables are capped so they scroll internally on normal pages.
    <div className={clsx('flex flex-col rounded-md border border-border bg-card shadow-sm', fillHeight ? 'h-full' : 'max-h-[calc(100vh-200px)]')}>
      {/* Toolbar: quick search + filter toggle | column picker + export */}
      <div className="relative flex shrink-0 flex-wrap items-center gap-2 border-b border-border px-3 py-1.5" ref={menuRef}>
        <div className="relative min-w-[180px] flex-1 sm:max-w-xs">
          <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-faint" />
          <input
            type="text"
            value={searchText_}
            onChange={(e) => setSearchText_(e.target.value)}
            placeholder={searchPlaceholder}
            aria-label="Quick search rows"
            className="w-full rounded-md border border-border py-1 pl-7 pr-2 text-xs text-secondary focus:border-focus-ring focus:outline-none"
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
              ? 'border-focus-ring bg-muted text-foreground'
              : 'border-border text-secondary hover:bg-background'
          )}
        >
          <Filter className="h-3.5 w-3.5" />
          Filter
          {activeFilterCols.length > 0 && (
            <span className="rounded-full bg-primary-hover px-1.5 text-[10px] font-semibold leading-4 text-white">{activeFilterCols.length}</span>
          )}
        </button>

        {autoRefresh && (
          <button
            type="button"
            onClick={toggleAutoRefresh}
            aria-pressed={autoRefreshOn}
            title={
              autoRefreshOn
                ? `Refreshing every ${Math.round(autoRefresh.intervalMs / 1000)} s — click to pause`
                : 'Auto-refresh paused — click to resume'
            }
            className={clsx(
              'flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium',
              autoRefreshOn
                ? 'border-success-border bg-success text-success-fg'
                : 'border-border text-secondary hover:bg-background'
            )}
          >
            <RefreshCw className={clsx('h-3.5 w-3.5', autoRefreshOn && 'animate-spin [animation-duration:2s]')} />
            {autoRefreshOn ? 'Live' : 'Paused'}
          </button>
        )}

        <div className="ml-auto flex items-center gap-2">
        <button
          type="button"
          onClick={() => setMenuOpen((v) => !v)}
          aria-haspopup="true"
          aria-expanded={menuOpen}
          aria-label="Toggle visible columns"
          title="Columns"
          className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-background"
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
              className="flex items-center gap-1.5 rounded-md border border-border px-2 py-1 text-xs font-medium text-secondary hover:bg-background"
            >
              <Download className="h-3.5 w-3.5" />
              Export
            </button>
            {exportOpen && (
              // top-full: anchor below the button — without an explicit top, an
              // abspos child of a flex row is vertically CENTERED on it and gets
              // clipped by anything with overflow hidden.
              <div className="absolute right-0 top-full z-20 mt-1 w-44 rounded-md border border-border bg-card p-1 shadow-lg">
                <p className="px-1.5 pb-1 pt-0.5 text-[11px] font-semibold uppercase tracking-wide text-faint">
                  Export {viewRows.length} row{viewRows.length === 1 ? '' : 's'} (current view)
                </p>
                <button type="button" onClick={() => handleExport('csv')} className="block w-full rounded px-1.5 py-1 text-left text-sm text-secondary hover:bg-background">
                  CSV
                </button>
                <button type="button" onClick={() => handleExport('json')} className="block w-full rounded px-1.5 py-1 text-left text-sm text-secondary hover:bg-background">
                  JSON
                </button>
              </div>
            )}
          </div>
        </div>
        {menuOpen && (
          // top-full: open below the toolbar (see export menu note above).
          <div className="absolute right-3 top-full z-20 mt-1 w-52 rounded-md border border-border bg-card p-2 shadow-lg">
            <p className="mb-1 px-1 text-[11px] font-semibold uppercase tracking-wide text-faint">Visible columns</p>
            {columns.map((col) => {
              // Effective state — a `hiddenByDefault` column reads as unchecked
              // even before the user has customized anything.
              const hidden = isColHidden(prefs, col.key);
              const isLastVisible = !hidden && visibleColumns.length === 1;
              return (
                <label
                  key={col.key}
                  className={clsx(
                    'flex cursor-pointer items-center gap-2 rounded px-1.5 py-1 text-sm text-secondary hover:bg-background',
                    isLastVisible && 'cursor-not-allowed opacity-40'
                  )}
                >
                  <input
                    type="checkbox"
                    className="h-3.5 w-3.5 rounded border-border text-foreground focus:ring-focus-ring"
                    checked={!hidden}
                    disabled={isLastVisible}
                    onChange={() => toggleColumn(col.key)}
                  />
                  {col.header}
                </label>
              );
            })}
            <div className="mt-1 border-t border-border pt-1">
              <button
                type="button"
                onClick={reset}
                className="flex w-full items-center gap-1.5 rounded px-1.5 py-1 text-left text-xs font-medium text-muted-foreground hover:bg-background hover:text-secondary"
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
        <div className="flex shrink-0 flex-wrap items-center gap-1.5 border-b border-border bg-background/60 px-3 py-1 text-xs text-muted-foreground">
          <span>
            {viewRows.length} of {rows.length} rows
          </span>
          {searchText_.trim() !== '' && (
            <button
              type="button"
              onClick={() => setSearchText_('')}
              className="flex items-center gap-1 rounded-full border border-border bg-card px-2 py-0.5 text-secondary hover:bg-muted"
            >
              search: “{searchText_.trim()}” <X className="h-3 w-3" />
            </button>
          )}
          {activeFilterCols.map((col) => (
            <button
              key={col.key}
              type="button"
              onClick={() => setColFilters((f) => ({ ...f, [col.key]: '' }))}
              className="flex items-center gap-1 rounded-full border border-border bg-card px-2 py-0.5 text-secondary hover:bg-muted"
            >
              {col.header}: “{(colFilters[col.key] ?? '').trim()}” <X className="h-3 w-3" />
            </button>
          ))}
          <button type="button" onClick={clearNarrowing} className="ml-auto font-medium text-muted-foreground underline-offset-2 hover:text-secondary hover:underline">
            Clear all
          </button>
        </div>
      )}

      {/* Selection bar with bulk actions */}
      {selectable && selectedKeys.size > 0 && (
        <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-border bg-info/60 px-3 py-1.5 text-sm">
          <span className="font-medium text-secondary">{selectedKeys.size} selected</span>
          {(bulkActions ?? []).map((action) => {
            const selectedRows = rows.filter((r) => selectedKeys.has(rowKey(r)));
            const enabled = action.enabled ? action.enabled(selectedRows) : true;
            return (
              <button
                key={action.label}
                type="button"
                disabled={!enabled}
                onClick={() => void runBulkAction(action)}
                className="rounded-md border border-border bg-card px-2.5 py-1 text-xs font-medium text-secondary hover:bg-background disabled:cursor-not-allowed disabled:opacity-40"
              >
                {action.label} ({selectedKeys.size})
              </button>
            );
          })}
          <button type="button" onClick={clearSelection} className="ml-auto text-xs font-medium text-muted-foreground underline-offset-2 hover:text-secondary hover:underline">
            Clear selection
          </button>
        </div>
      )}

      {viewRows.length === 0 ? (
        <div className="p-6 text-center text-sm text-muted-foreground">
          No rows match the current search/filters.{' '}
          <button type="button" onClick={clearNarrowing} className="font-medium text-secondary underline-offset-2 hover:underline">
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
            {expandable && <col key="__expand" style={{ width: EXPAND_COL_WIDTH }} />}
            {selectable && <col key="__select" style={{ width: SELECT_COL_WIDTH }} />}
            {visibleColumns.map((col) => {
              const w = explicitWidth(col.key);
              return <col key={col.key} style={w ? { width: w } : undefined} />;
            })}
          </colgroup>
          <thead className="bg-background">
            <tr>
                {expandable && (
                  // sticky like the data-column headers — without it these two
                  // cells scroll away vertically while the rest of the header row stays pinned.
                  <th scope="col" aria-label="Expand" className="sticky top-0 z-10 border-b border-r border-border bg-background px-1 py-2" />
                )}
                {selectable && (
                  <th scope="col" className="sticky top-0 z-10 border-b border-r border-border bg-background px-3 py-2">
                    <input
                      ref={selectAllRef}
                      type="checkbox"
                      aria-label="Select all visible rows"
                      checked={allSelected}
                      onChange={toggleSelectAll}
                      className="h-3.5 w-3.5 rounded border-border text-foreground focus:ring-focus-ring"
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
                    className="sticky top-0 z-10 select-none border-b border-r border-border bg-background px-4 py-2 text-left font-semibold text-secondary last:border-r-0"
                  >
                    {sortable ? (
                      <button type="button" onClick={() => cycleSort(col.key)} className="group flex w-full items-center gap-1.5 text-left">
                        <span className="truncate">{col.header}</span>
                        <span aria-hidden="true" className={clsx('text-[10px] leading-none', active ? 'text-secondary' : 'text-transparent group-hover:text-faint')}>
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
                      className="absolute -right-1 top-0 h-full w-2 cursor-col-resize rounded hover:bg-status-neutral/70 active:bg-faint"
                    />
                  </th>
                );
              })}
            </tr>
              {showFilters && (
                <tr className="bg-card">
                  {/* top-[37px] = header row height (py-2 + 20px line-height +
                      1px border) — keeps the filter inputs pinned directly
                      under the header with no gap or overlap. */}
                  {expandable && <td className="sticky top-[37px] z-10 border-b border-r border-border bg-card" />}
                  {selectable && <td className="sticky top-[37px] z-10 border-b border-r border-border bg-card" />}
                  {visibleColumns.map((col) => (
                    <td key={col.key} className="sticky top-[37px] z-10 border-b border-r border-border bg-card px-2 py-1 last:border-r-0">
                      {col.filterable !== false ? (
                        <input
                          type="text"
                          value={colFilters[col.key] ?? ''}
                          onChange={(e) => setColFilters((f) => ({ ...f, [col.key]: e.target.value }))}
                          placeholder={`Filter ${col.header.toLowerCase()}`}
                          aria-label={`Filter by ${col.header}`}
                          className="w-full rounded border border-border px-1.5 py-0.5 text-xs text-secondary focus:border-focus-ring focus:outline-none"
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
            className="divide-y divide-border"
            onMouseLeave={() => onRowHover?.(null)}
          >
            {viewRows.map((row) => {
              const key = rowKey(row);
              const detail = renderRowDetail ? renderRowDetail(row) : null;
              // Expandable rows: children are computed per visible parent (cheap —
              // the page's childrenOf is a Map lookup). Expansion state survives
              // search/sort because it is keyed by rowKey. Children can nest
              // recursively — each child with its own children gets a chevron too.
              const children = expandable ? expandable.childrenOf(row) : [];
              const expanded = expandedKeys.has(key);
              return (
                <Fragment key={key}>
                  <tr
                    className={clsx('hover:bg-background', selectable && selectedKeys.has(key) && 'bg-info/40', rowClassName?.(row))}
                    onMouseEnter={() => onRowHover?.(row)}
                  >
                    {expandable && (
                      <td className="px-1 py-2">
                        {children.length > 0 ? (
                          <button
                            type="button"
                            onClick={() => setExpandedKeys((prev) => {
                              const next = new Set(prev);
                              if (next.has(key)) next.delete(key); else next.add(key);
                              return next;
                            })}
                            aria-expanded={expanded}
                            title={expanded ? 'Collapse' : `Show ${children.length} item${children.length === 1 ? '' : 's'}`}
                            className="flex h-6 w-6 items-center justify-center rounded text-faint hover:bg-muted hover:text-secondary"
                          >
                            {expanded ? <ChevronDown size={18} /> : <ChevronRight size={18} />}
                          </button>
                        ) : (
                          <span className="inline-block h-6 w-6" />
                        )}
                      </td>
                    )}
                    {selectable && (
                      <td className="px-3 py-2">
                        <input
                          type="checkbox"
                          aria-label={`Select row ${key}`}
                          checked={selectedKeys.has(key)}
                          onChange={() => toggleRow(key)}
                          className="h-3.5 w-3.5 rounded border-border text-foreground focus:ring-focus-ring"
                        />
                      </td>
                    )}
                    {visibleColumns.map((col) => (
                      <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">
                        {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                      </td>
                    ))}
                  </tr>
                  {/* Expanded children — each is a full <tr> built from the same
                      visible columns (see renderChildRows), so it stays aligned
                      with the header. Children nest recursively: a child with its
                      own children gets a chevron and renders ITS children below. */}
                  {expanded && expandable && renderChildRows(row, key, 0)}
                  {/* Full-width detail row directly under the data row. */}
                  {detail !== null && detail !== undefined && (
                    <tr className="bg-background/70">
                      <td colSpan={visibleColumns.length + (selectable ? 1 : 0) + (expandable ? 1 : 0)} className="px-4 py-2 text-xs text-secondary">
                        {detail}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
        </div>
      )}
    </div>
  );
}
