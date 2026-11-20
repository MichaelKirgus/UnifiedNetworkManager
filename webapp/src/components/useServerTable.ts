import { useEffect, useRef, useState } from 'react';
import { keepPreviousData, useQuery } from '@tanstack/react-query';

/** Sort state for server-paginated tables. `key` is a COLUMN KEY — the owning page
 * maps it to an API sort field inside its fetcher (DataTable never sees API names). */
export interface ServerTableSort {
  key: string;
  dir: 'asc' | 'desc';
}

/** Sentinel pageSize meaning "return everything in one response" (no pagination).
 * The fetcher maps it to whatever its API calls unpaginated (e.g. `all=true`). */
export const ALL_PAGES = 0;

/** Params handed to the fetcher: the caller's extra filters + table controls. */
export type ServerTableParams<TExtra extends object> = TExtra & {
  page: number;
  pageSize: number;
  q?: string;
  sort?: ServerTableSort | null;
  /** Committed per-column filter values (COLUMN KEY → text), non-empty only —
   * the fetcher maps keys to API params exactly like it does for `sort`. */
  filters?: Record<string, string>;
};

/** Stable JSON with sorted object keys — used for change detection + query cache
 * so `{a:'x',b:''}` and `{b:'',a:'x'}` are the same state. */
function stableStringify(v: unknown): string {
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    return `{${Object.keys(obj).sort().map((k) => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
  }
  return JSON.stringify(v);
}

interface PersistedPrefs {
  pageSize?: number;
  sort?: ServerTableSort | null;
}

function loadPersisted(storageKey?: string): PersistedPrefs {
  if (!storageKey) return {};
  try {
    const raw = localStorage.getItem(`unm-server-table:${storageKey}`);
    if (!raw) return {};
    const v: unknown = JSON.parse(raw);
    return v && typeof v === 'object' ? (v as PersistedPrefs) : {};
  } catch {
    return {};
  }
}

/**
 * State + query wiring for a DataTable in server-pagination mode. Owns page,
 * pageSize, committed search text and sort; the caller owns its own filter
 * params (`extra`) — any change to them resets the table to page 1.
 *
 * Non-breaking by design: pages that don't use this keep their hand-rolled state;
 * DataTable's client-side pipeline is untouched for non-server tables.
 */
export function useServerTable<TExtra extends object, TRow>(opts: {
  /** Fetch one page given the full param set (extra + page/pageSize/q/sort). */
  fetcher: (params: ServerTableParams<TExtra>) => Promise<{ rows: TRow[]; total: number }>;
  /** Caller-controlled filter params. Pass a STABLE object (useMemo) — its JSON
   * is the change-detection key for the page-1 reset and the query cache. */
  extra: TExtra;
  /** When set, pageSize + sort persist across reloads in localStorage. */
  storageKey?: string;
  /** Background refetch cadence (default 30 s). `false` disables it. */
  refetchIntervalMs?: number | false;
}): {
  data: { rows: TRow[]; total: number } | undefined;
  isFetching: boolean;
  isError: boolean;
  error: Error | null;
  page: number;
  setPage: (page: number) => void;
  /** Current rows-per-page — ALL_PAGES (0) means "everything, unpaginated". */
  pageSize: number;
  /** Set rows-per-page; pass ALL_PAGES for the unpaginated view. Resets to page 1. */
  setPageSize: (size: number) => void;
  /** Committed search text — wire to DataTable's `onSearch` + `externalSearch`. */
  q: string;
  setQ: (q: string) => void;
  /** Committed per-column filters (COLUMN KEY → non-empty text). Wire the map to
   * DataTable's serverPagination.filters and this setter to onFiltersChange. */
  filters: Record<string, string>;
  /** Full replacement of the column-filter map — resets to page 1 when it changes. */
  setFilters: (next: Record<string, string>) => void;
  sort: ServerTableSort | null;
  /** Wire to DataTable's serverPagination.onSortChange. Resets to page 1 on change. */
  setSort: (sort: ServerTableSort | null) => void;
  /** Refetch controls — pass the hook result in DataTable's autoRefresh.queries so
   * the Live/Paused toggle works for server tables too. */
  setRefetchInterval: (interval: false | number) => void;
  refetch: () => unknown;
} {
  // Read persisted prefs once per mount (lazy — before first render).
  const persisted = useRef<PersistedPrefs>(loadPersisted(opts.storageKey)).current;

  const [page, setPageRaw] = useState(1);
  const [pageSize, setPageSizeRaw] = useState(persisted.pageSize ?? 50);
  const [q, setQRaw] = useState('');
  const [sort, setSortRaw] = useState<ServerTableSort | null>(persisted.sort ?? null);
  // Committed per-column filters (COLUMN KEY → text). Session-only like `q` —
  // not persisted: a reload starts with a clean table.
  const [filters, setFiltersRaw] = useState<Record<string, string>>({});

  // Any caller-filter change goes back to page 1 (search/sort/filter resets are inline below).
  const extraKey = JSON.stringify(opts.extra);
  useEffect(() => {
    setPageRaw(1);
  }, [extraKey]);

  function setQ(v: string) {
    setQRaw(v);
    setPageRaw(1);
  }
  /** Full replacement of the column-filter map (mirrors client-mode colFilters).
   * Empty/whitespace values are stripped; a no-op change does NOT reset the page. */
  function setFilters(next: Record<string, string>) {
    const clean: Record<string, string> = {};
    for (const [k, v] of Object.entries(next)) if (v.trim() !== '') clean[k] = v;
    if (stableStringify(clean) === stableStringify(filters)) return;
    setFiltersRaw(clean);
    setPageRaw(1);
  }
  function setSort(s: ServerTableSort | null) {
    setSortRaw(s);
    setPageRaw(1);
  }
  function setPageSize(n: number) {
    setPageSizeRaw(n);
    setPageRaw(1);
  }

  const filterKey = stableStringify(filters);
  const query = useQuery({
    // In ALL_PAGES mode the page is irrelevant — pin it out of the key so the cache stays stable.
    queryKey: ['serverTable', opts.storageKey ?? 'default', extraKey, q, filterKey, sort?.key ?? null, sort?.dir ?? null, pageSize === ALL_PAGES ? null : page, pageSize],
    queryFn: () => opts.fetcher({ ...(opts.extra as object), page: pageSize === ALL_PAGES ? 1 : page, pageSize, q: q || undefined, sort, filters } as ServerTableParams<TExtra>),
    // Keep the previous page visible while a new one loads — no flash to empty.
    placeholderData: keepPreviousData,
    refetchInterval: opts.refetchIntervalMs === false ? false : (opts.refetchIntervalMs ?? 30_000),
  });

  // Clamp the page when the filtered total shrinks under it (e.g. advisories pruned).
  // ALL_PAGES mode has no pages to clamp.
  const total = query.data?.total ?? 0;
  useEffect(() => {
    if (pageSize === ALL_PAGES) return;
    if (total > 0 && (page - 1) * pageSize >= total) {
      setPageRaw(Math.max(1, Math.ceil(total / pageSize)));
    }
  }, [total, page, pageSize]);

  // Persist pageSize + sort so the user's layout survives reloads.
  useEffect(() => {
    if (!opts.storageKey) return;
    try {
      localStorage.setItem(`unm-server-table:${opts.storageKey}`, JSON.stringify({ pageSize, sort }));
    } catch { /* storage full/blocked — non-fatal */ }
  }, [pageSize, sort, opts.storageKey]);

  // The v5 result union only carries these on some variants — optional-call.
  const controls = query as { setRefetchInterval?: (i: false | number) => void; refetch?: () => unknown };

  return {
    data: query.data,
    isFetching: query.isFetching,
    isError: query.isError,
    error: (query.error as Error | null) ?? null,
    page,
    setPage: setPageRaw,
    pageSize,
    setPageSize,
    q,
    setQ,
    filters,
    setFilters,
    sort,
    setSort,
    setRefetchInterval: (interval: false | number) => controls.setRefetchInterval?.(interval),
    refetch: () => controls.refetch?.(),
  };
}
