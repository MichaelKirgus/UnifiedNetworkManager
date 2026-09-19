import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { DeviceChip } from '../components/DeviceChip';
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

/** Time-range presets for the filter bar (v1: presets only, no custom pickers). */
const TIME_RANGES = [
  { value: 'all', label: 'All time' },
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
] as const;

type TimeRange = (typeof TIME_RANGES)[number]['value'];

const RANGE_MS: Record<Exclude<TimeRange, 'all'>, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

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
  const [search, setSearch] = useState('');
  const [range, setRange] = useState<TimeRange>('24h');

  // Options for the filter selects.
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // The `from` bound is computed at fetch time so "last hour" keeps sliding as
  // the page refetches. Newest-first, capped by the API (default 500 rows).
  const logsQuery = useQuery({
    queryKey: ['logs', level, pluginId, deviceId, search, range],
    queryFn: () => {
      const from = range === 'all' ? undefined : new Date(Date.now() - RANGE_MS[range]).toISOString();
      return api.logs({
        level: (level || undefined) as LogEntry['level'] | undefined,
        pluginId: pluginId || undefined,
        deviceId: deviceId || undefined,
        search: search.trim() || undefined,
        from,
      });
    },
    refetchInterval: 30_000,
  });

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
      key: 'timestamp',
      width: 180,
      sortAccessor: (row) => new Date(row.timestamp).getTime(),
      render: (row) => <span className="font-mono text-xs">{formatDateTime(row.timestamp)}</span>,
    },
    {
      header: 'Level',
      key: 'level',
      width: 90,
      render: (row) => <LevelBadge level={row.level} />,
    },
    {
      header: 'Plugin',
      key: 'pluginName',
      width: 200,
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
                <pre className="max-h-48 overflow-auto rounded bg-primary p-2 font-mono text-[11px] leading-relaxed text-code-fg">
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
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Time range</label>
          <select className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm" value={range} onChange={(e) => setRange(e.target.value as TimeRange)}>
            {TIME_RANGES.map((r) => (
              <option key={r.value} value={r.value}>
                {r.label}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="mb-1 block text-xs font-medium text-secondary">Search</label>
          <input
            type="text"
            className="w-full rounded-md border border-border px-2.5 py-1.5 text-sm"
            placeholder="Message or context…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {logsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading logs...</p>}
      {logsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load logs: {(logsQuery.error as Error).message}</p>
      )}
      {logsQuery.data && (
        <DataTable
          columns={columns}
          rows={logsQuery.data}
          rowKey={(row) => row.id}
          storageKey="logs"
          autoRefresh={{ intervalMs: 30_000, queries: [logsQuery] }}
          searchPlaceholder="Search logs…"
          emptyMessage="No log entries in this range yet — plugins ship failures and state changes here (poll errors, config/plan results)."
        />
      )}
    </Layout>
  );
}
