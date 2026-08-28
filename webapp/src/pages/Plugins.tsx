import { ReactNode, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { OptionForm } from '../components/OptionForm';
import { api, Plugin, PluginSelfMetricsSample } from '../api/client';

// A plugin is considered online if it was seen within the last 5 minutes.
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

function isOnline(plugin: Plugin): boolean {
  if (!plugin.lastSeenAt) return false;
  return Date.now() - new Date(plugin.lastSeenAt).getTime() < ONLINE_WINDOW_MS;
}

/** Human-readable byte size (MB with one decimal, GB above 1024 MB). */
function formatBytes(bytes: number | null): string {
  if (bytes === null || !Number.isFinite(bytes)) return '—';
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) return `${(mb / 1024).toFixed(2)} GB`;
  return `${mb.toFixed(1)} MB`;
}

/** Human-readable duration in ms. */
function formatMs(ms: number | null): string {
  if (ms === null || !Number.isFinite(ms)) return '—';
  if (ms >= 1000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.round(ms)} ms`;
}

/** Human-readable uptime. */
function formatUptime(seconds: number | null): string {
  if (seconds === null || !Number.isFinite(seconds)) return '—';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m`;
  return `${Math.floor(seconds)}s`;
}

/** Minimal inline SVG sparkline — no chart lib needed for a single series. */
function Sparkline({ values, width = 120, height = 28 }: { values: number[]; width?: number; height?: number }) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const stepX = width / (values.length - 1);
  const points = values
    .map((v, i) => `${(i * stepX).toFixed(1)},${(height - 2 - ((v - min) / span) * (height - 4)).toFixed(1)}`)
    .join(' ');
  return (
    <svg width={width} height={height} className="block" aria-hidden="true">
      <polyline points={points} fill="none" stroke="#6366f1" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

/**
 * Compact self-metrics strip rendered under each plugin row: runtime health of
 * the plugin process (CPU/memory/lag/poll stats), sampled by the API every 30s.
 * Fetches its own data lazily per row; refreshes while mounted.
 */
function PluginMetricsRow({ plugin }: { plugin: Plugin }) {
  const query = useQuery({
    queryKey: ['pluginSelfMetrics', plugin.id],
    queryFn: () => api.pluginSelfMetrics(plugin.id),
    refetchInterval: 30_000,
  });

  const latest = query.data?.latest ?? null;

  // History is newest-first — reverse for chronological sparklines, drop nulls.
  const series = (pick: (s: PluginSelfMetricsSample) => number | null): number[] =>
    ((query.data?.history ?? []).slice().reverse() as PluginSelfMetricsSample[])
      .map(pick)
      .filter((v): v is number => v !== null && Number.isFinite(v));

  if (!latest) {
    return (
      <span className="text-slate-400">
        {query.isLoading ? 'Loading self-metrics…' : 'No self-metrics yet — plugin offline or predates the /metrics endpoint.'}
      </span>
    );
  }

  const stat = (label: string, value: string, spark?: number[]): ReactNode => (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-slate-400">{label}</span>
      <span className="font-mono font-medium text-slate-800">{value}</span>
      {spark && spark.length > 1 && <Sparkline values={spark} width={72} height={16} />}
    </span>
  );

  return (
    <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
      {stat('CPU', latest.cpuPercent !== null ? `${latest.cpuPercent}%` : '—', series((s) => s.cpuPercent))}
      {stat('Heap', formatBytes(latest.heapUsedBytes), series((s) => s.heapUsedBytes))}
      {stat('RSS', formatBytes(latest.rssBytes), series((s) => s.rssBytes))}
      {stat('Lag', latest.eventLoopLagMs !== null ? `${latest.eventLoopLagMs} ms` : '—')}
      {stat('In-flight', latest.inFlight !== null ? String(latest.inFlight) : '—')}
      {stat('Last poll', formatMs(latest.lastPollMs), series((s) => s.lastPollMs))}
      {stat('Errors (20)', latest.errorRatePercent !== null ? `${latest.errorRatePercent}%` : '—')}
      {stat(
        'Metrics/poll',
        latest.emittedMetricsCount !== null
          ? plugin.declaredMetricCount != null
            ? `${latest.emittedMetricsCount}/${plugin.declaredMetricCount}`
            : String(latest.emittedMetricsCount)
          : '—'
      )}
      {stat('Log queue', latest.logQueueDepth !== null ? String(latest.logQueueDepth) : 'n/a')}
      {stat('Uptime', formatUptime(latest.uptimeSeconds))}
    </div>
  );
}

export default function Plugins() {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Plugin whose settings form is open in the modal (null = closed).
  const [configureId, setConfigureId] = useState<string | null>(null);

  const columns: DataTableColumn<Plugin>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Version', key: 'version' },
    { header: 'Vendors', key: 'vendors', render: (row) => row.vendors.join(', ') },
    { header: 'Capabilities', key: 'capabilities', render: (row) => row.capabilities.join(', ') },
    {
      header: 'Metrics',
      key: 'declaredMetricCount',
      width: 90,
      sortAccessor: (row) => row.declaredMetricCount ?? null,
      render: (row) =>
        row.declaredMetricCount !== null && row.declaredMetricCount !== undefined ? (
          <span className="text-slate-600">{row.declaredMetricCount} declared</span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    { header: 'Endpoint', key: 'endpoint', width: 240, render: (row) => <span className="font-mono text-xs">{row.endpoint}</span> },
    {
      header: 'Status',
      key: 'status',
      // Sort by recency of last seen; offline plugins sink to the bottom.
      sortAccessor: (row) => (row.lastSeenAt ? new Date(row.lastSeenAt).getTime() : null),
      render: (row) =>
        isOnline(row) ? (
          <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
            online
          </span>
        ) : (
          <span className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
            offline
          </span>
        ),
    },
    {
      header: 'Actions',
      key: 'actions',
      excludeFromExport: true,
      width: 110,
      sortable: false,
      render: (row) => (
        <button
          type="button"
          aria-label={`Configure ${row.name}`}
          title="Configure plugin settings"
          className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
          onClick={() => setConfigureId(row.id)}
        >
          <Settings className="h-4 w-4" />
        </button>
      ),
    },
  ];

  const configurePlugin = configureId ? (pluginsQuery.data ?? []).find((p) => p.id === configureId) : null;

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Plugins</h1>
        <p className="text-sm text-slate-500">Automatically discovered via mDNS / polling</p>
      </div>

      {pluginsQuery.isLoading && <p className="text-sm text-slate-500">Loading plugins...</p>}
      {pluginsQuery.isError && (
        <p className="text-sm text-red-600">Failed to load plugins: {(pluginsQuery.error as Error).message}</p>
      )}
      {pluginsQuery.data && (
        <DataTable
          columns={columns}
          rows={pluginsQuery.data}
          rowKey={(row) => row.id}
          storageKey="plugins"
          emptyMessage="No plugins discovered yet."
          // Runtime health of each plugin process, shown directly under its row.
          renderRowDetail={(row) => <PluginMetricsRow plugin={row} />}
        />
      )}

      {/* Plugin settings modal — generic form rendered from the plugin's option descriptors. */}
      {configurePlugin && (
        <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-4 sm:items-center" onClick={() => setConfigureId(null)}>
          <div
            className="w-full max-w-lg rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h2 className="text-base font-semibold text-slate-900">
                Settings — {configurePlugin.name}
                <span className="ml-2 text-xs font-normal text-slate-400">{configurePlugin.version}</span>
              </h2>
              <button
                type="button"
                aria-label="Close settings"
                onClick={() => setConfigureId(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <OptionForm pluginId={configurePlugin.id} />
          </div>
        </div>
      )}
    </Layout>
  );
}