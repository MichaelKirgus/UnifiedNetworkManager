import { useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
import { TimeRangeFilter, resolveTimeRangeIso, type TimeRangeValue } from '../components/TimeRangeFilter';
import { ALL_PAGES, useServerTable } from '../components/useServerTable';
import { api, LogEntry } from '../api/client';
import { useTimeFormat } from '../utils/time';

/** Small colored pill for the log level. */
const LEVEL_STYLES: Record<LogEntry['level'], string> = {
  debug: 'bg-muted text-muted-foreground',
  info: 'bg-info text-info-fg',
  warn: 'bg-warning text-warning-fg',
  error: 'bg-danger text-danger-fg',
};

function LevelBadge({ level }: { level: LogEntry['level'] }) {
  return (
    <span className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${LEVEL_STYLES[level] ?? 'bg-muted text-secondary'}`}>
      {level}
    </span>
  );
}

/**
 * Global plugin log view. Rows are pushed by plugins via the API's internal
 * POST /plugin/logs endpoint (see docs/PLUGIN-DEVELOPMENT.md §8 Logging) and
 * kept for LOG_RETENTION_DAYS (default 7). Gated by `logs:read` — logs can
 * carry critical details, so the nav item is hidden without the permission.
 */
export default function Logs() {
  const { formatDateTime } = useTimeFormat();
  const [level, setLevel] = useState('');
  const [pluginId, setPluginId] = useState('');
  const [deviceId, setDeviceId] = useState('');
  // Filter-bar search draft — debounced into the table's committed `q` below.
  const [searchDraft, setSearchDraft] = useState('');
  const [range, setRange] = useState<TimeRangeValue>('24h');

  // Options for the filter selects.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // Page-owned filters; any change resets the table to page 1 (hook behavior).
  const extra = useMemo(() => ({ level, pluginId, deviceId, range }), [level, pluginId, deviceId, range]);

  // Server-side pagination — rows are fetched per page by the API. The `from`
  // bound is computed at fetch time so "last hour" keeps sliding on refetch.
  const table = useServerTable<{ level: string; pluginId: string; deviceId: string; range: TimeRangeValue }, LogEntry>({
    fetcher: async (p) => {
      // Relative presets slide with the current time; custom ranges are absolute.
      const { from, to } = resolveTimeRangeIso(p.range);
      const res = await api.logs({
        level: (p.level || undefined) as LogEntry['level'] | undefined,
        pluginId: p.pluginId || undefined,
        deviceId: p.deviceId || undefined,
        search: p.q,
        from,
        to,
        page: p.pageSize === ALL_PAGES ? undefined : p.page,
        pageSize: p.pageSize === ALL_PAGES ? undefined : p.pageSize,
        all: p.pageSize === ALL_PAGES || undefined,
        sort: p.sort?.key === 'emittedAt' ? 'emittedAt' : undefined,
        dir: p.sort?.dir,
      });
      // Paged mode always returns the envelope; guard for safety.
      return Array.isArray(res) ? { rows: res, total: res.length } : { rows: res.rows, total: res.total };
    },
    extra,
    storageKey: 'logs',
  });

  // Debounce the filter-bar search into the committed server query (300 ms).
  useEffect(() => {
    const t = setTimeout(() => table.setQ(searchDraft.trim()), 300);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchDraft]);

  const plugins = useMemo(() => (pluginsQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [pluginsQuery.data]);
  const devices = useMemo(() => (devicesQuery.data ?? []).slice().sort((a, b) => a.name.localeCompare(b.name)), [devicesQuery.data]);

  // Rows whose context is currently expanded (by row id).
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  function toggleContext(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const columns: DataTableColumn<LogEntry>[] = [
    {
      header: 'Time',
      key: 'emittedAt',
      width: 180,
      sortAccessor: (row) => new Date(row.emittedAt).getTime(),
      render: (row) => <span className="font-mono text-xs">{formatDateTime(row.emittedAt)}</span>,
    },
    {
      header: 'Level',
      key: 'level',
      width: 90,
      sortable: false, // server only sorts by emittedAt
      render: (row) => <LevelBadge level={row.level} />,
    },
    {
      header: 'Plugin',
      key: 'pluginName',
      width: 200,
      sortable: false,
      exportValue: (row) => row.pluginName ?? row.pluginId,
      render: (row) => (
        <span className="text-sm text-secondary" title={row.pluginId}>
          {row.pluginName ?? '—'}
        </span>
      ),
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 240,
      sortable: false,
      exportValue: (row) => row.deviceName ?? '',
      render: (row) =>
        row.deviceId ? (
          <DeviceChip deviceName={row.deviceName} managementAddress={null} pluginName={null} siteName={null} interfaces={[]} />
        ) : (
          <span className="text-xs text-faint">plugin-level</span>
        ),
    },
    {
      header: 'Message',
      key: 'message',
      width: 520,
      sortable: false,
      render: (row) => (
        <div className="flex flex-col gap-1">
          <span className="break-words text-sm text-foreground">{row.message}</span>
          {row.context && Object.keys(row.context).length > 0 && (
            <>
              <button
                type="button"
                onClick={() => toggleContext(row.id)}
                className="self-start text-xs font-medium text-info-fg hover:underline"
              >
                {expanded.has(row.id) ? 'Hide details' : `Details (${Object.keys(row.context).length})`}
              </button>
              {expanded.has(row.id) && (
                <pre className="max-h-48 overflow-auto rounded bg-code-bg p-2 font-mono text-[11px] leading-relaxed text-code-fg">
                  {JSON.stringify(row.context, null, 2)}
                </pre>
              )}
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <Layout title="Logs">

      {/* Filter bar */}
      <div className="mb-4 grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-3 shadow-sm sm:grid-cols-5">
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Level</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={level} onChange={(e) => setLevel(e.target.value)}>
            <option value="">All levels</option>
            <option value="debug">Debug</option>
            <option value="info">Info</option>
            <option value="warn">Warn</option>
            <option value="error">Error</option>
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Plugin</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={pluginId} onChange={(e) => setPluginId(e.target.value)}>
            <option value="">All plugins</option>
            {plugins.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Device</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
            <option value="">All devices</option>
            {devices.map((d) => (
              <option key={d.id} value={d.id}>
                {d.name}
              </option>
            ))}
          </select>
        </div>
        <TimeRangeFilter label="Time range" value={range} onChange={setRange} />
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Search</label>
          <input
            type="text"
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm"
            placeholder="Message or context…"
            value={searchDraft}
            onChange={(e) => setSearchDraft(e.target.value)}
          />
        </div>
      </div>

      {table.isError && (
        <p className="text-sm text-danger-fg">Failed to load logs: {table.error?.message}</p>
      )}
      <DataTable
        columns={columns}
        rows={table.data?.rows ?? []}
        rowKey={(row) => row.id}
        storageKey="logs"
        isFetching={table.isFetching}
        showSearch={false} // the filter bar above owns search (debounced into table.q)
        onSearch={table.setQ}
        externalSearch={table.q || null}
        serverPagination={{
          total: table.data?.total ?? 0,
          page: table.page,
          pageSize: table.pageSize,
          onPageChange: table.setPage,
          onPageSizeChange: table.setPageSize,
          // pageSizeOptions omitted → global `tablePageSizeOptions` setting + built-in "All".
          sort: table.sort,
          onSortChange: table.setSort,
        }}
        autoRefresh={{ intervalMs: 30_000, queries: [table] }}
        emptyMessage="No log entries in this range yet — plugins ship failures and state changes here (poll errors, config/plan results)."
      />
    </Layout>
  );
}
