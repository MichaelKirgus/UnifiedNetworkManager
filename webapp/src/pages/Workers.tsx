import { ReactNode, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, PostgresTableStat, SystemEvent, WorkerRuntime } from '../api/client';
import { can } from '../auth/permissions';
import { Activity, Cpu, Database, Gauge, Save, ServerCog, TimerReset } from 'lucide-react';

/** Human-friendly duration (ms → "1.2 s" / "340 ms"). */
function fmtMs(ms?: number | null): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/** Uptime in compact form ("3 d 4 h"). */
function fmtUptime(seconds: number): string {
  const d = Math.floor(seconds / 86_400);
  const h = Math.floor((seconds % 86_400) / 3_600);
  const m = Math.floor((seconds % 3_600) / 60);
  if (d > 0) return `${d} d ${h} h`;
  if (h > 0) return `${h} h ${m} m`;
  return `${m} m`;
}

const EVENT_STYLES: Record<SystemEvent['type'], string> = {
  'leadership-acquired': 'bg-emerald-100 text-emerald-800',
  'leadership-lost': 'bg-amber-100 text-amber-800',
  'worker-started': 'bg-blue-100 text-blue-700',
  'beat-error': 'bg-red-100 text-red-700',
};

/** Small stat card used in the telemetry + Postgres sections. */
function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="rounded-md border border-slate-200 bg-white px-4 py-3 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-lg font-semibold text-slate-900">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-slate-500">{sub}</div>}
    </div>
  );
}

/**
 * Workers / HA monitoring page (gated by `system:read`).
 *
 * Shows THIS instance's view of the worker infrastructure: per-worker
 * leadership state + beat stats, telemetry poll-cycle counters, recent
 * leadership/error events, a read-only Postgres snapshot (version,
 * connections, table sizes), and the admin-tunable HA settings (poll cadence
 * + concurrency — live effect on the next beat, no restart).
 */
export default function Workers() {
  const queryClient = useQueryClient();

  // Status auto-refreshes every 10 s so leadership changes + beat stats stay current.
  const statusQuery = useQuery({
    queryKey: ['system-status'],
    queryFn: api.systemStatus,
    refetchInterval: 10_000,
  });

  // Settings form state (initialized from the effective values once loaded).
  const settingsQuery = useQuery({
    queryKey: ['system-settings'],
    queryFn: api.systemSettings,
  });

  const [intervalMs, setIntervalMs] = useState<number | null>(null);
  const [concurrency, setConcurrency] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const effectiveInterval = intervalMs ?? settingsQuery.data?.telemetryPollIntervalMs ?? 30_000;
  const effectiveConcurrency = concurrency ?? settingsQuery.data?.telemetryMaxConcurrency ?? 64;

  const saveMutation = useMutation({
    mutationFn: api.saveSystemSettings,
    onSuccess: (data) => {
      queryClient.setQueryData(['system-settings'], data);
      setIntervalMs(null); // re-sync the form to the saved values
      setConcurrency(null);
      setSaveError(null);
    },
    onError: (err: Error) => setSaveError(err.message),
  });

  const status = statusQuery.data;
  const canWrite = can('system:write');

  const workerColumns: DataTableColumn<WorkerRuntime>[] = [
    {
      header: 'Worker',
      key: 'name',
      width: 190,
      render: (row) => (
        <div>
          <div className="text-sm font-medium text-slate-800">{row.name}</div>
          <div className="font-mono text-[11px] text-slate-400">key {row.leaderKey === -1 ? 'n/a (all replicas)' : row.leaderKey}</div>
        </div>
      ),
    },
    {
      header: 'Leadership',
      key: 'isLeader',
      width: 220,
      sortAccessor: (row) => (row.isLeader ? 1 : 0),
      render: (row) =>
        row.leaderKey === -1 ? (
          <span className="inline-flex rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">runs on every replica</span>
        ) : row.isLeader ? (
          <div>
            <span className="inline-flex items-center gap-1 rounded bg-emerald-100 px-2 py-0.5 text-xs font-semibold text-emerald-800">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" /> leader
            </span>
            {row.becameLeaderAt && (
              <div className="mt-0.5 text-[11px] text-slate-400">since {new Date(row.becameLeaderAt).toLocaleTimeString()}</div>
            )}
          </div>
        ) : (
          <span className="inline-flex rounded bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500">standby</span>
        ),
    },
    {
      header: 'Beats',
      key: 'beatsCompleted',
      width: 90,
      sortAccessor: (row) => row.beatsCompleted,
      render: (row) => <span className="font-mono text-sm">{row.beatsCompleted}</span>,
    },
    {
      header: 'Last beat',
      key: 'lastBeatDurationMs',
      width: 120,
      sortAccessor: (row) => row.lastBeatDurationMs ?? -1,
      render: (row) => <span className="font-mono text-sm">{fmtMs(row.lastBeatDurationMs)}</span>,
    },
    {
      header: 'Errors',
      key: 'beatErrors',
      width: 80,
      sortAccessor: (row) => row.beatErrors,
      render: (row) =>
        row.beatErrors > 0 ? (
          <span className="inline-flex rounded bg-red-100 px-2 py-0.5 text-xs font-semibold text-red-700">{row.beatErrors}</span>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    {
      header: 'Last error',
      key: 'lastError',
      width: 320,
      filterable: false,
      render: (row) =>
        row.lastError ? <span className="block truncate text-xs text-red-600" title={row.lastError}>{row.lastError}</span> : <span className="text-slate-400">—</span>,
    },
  ];

  const tableColumns: DataTableColumn<PostgresTableStat>[] = [
    { header: 'Table', key: 'name', width: 200, render: (row) => <span className="font-mono text-sm">{row.name}</span> },
    {
      header: 'Rows (approx)',
      key: 'approxRows',
      width: 140,
      sortAccessor: (row) => row.approxRows,
      render: (row) => <span className="font-mono text-sm">{row.approxRows.toLocaleString()}</span>,
    },
    {
      header: 'Size',
      key: 'totalSizeBytes',
      width: 120,
      sortAccessor: (row) => row.totalSizeBytes,
      render: (row) => <span className="font-mono text-sm">{row.totalSizePretty}</span>,
    },
  ];

  const pg = status?.postgres;
  const connPct = pg && pg.maxConnections > 0 ? Math.min(100, Math.round((pg.connectionsTotal / pg.maxConnections) * 100)) : 0;

  return (
    <Layout
      title="Workers & HA"
      actions={
        status && (
          <div className="flex items-center gap-4 rounded-md border border-slate-200 bg-white px-3 py-1.5 shadow-sm">
            <span className="flex items-center gap-1.5 text-xs text-slate-600" title={`PID ${status.instance.pid}`}>
              <ServerCog className="h-4 w-4 text-slate-400" />
              {status.instance.hostname}
            </span>
            <span className="flex items-center gap-1.5 text-xs text-slate-600">
              <TimerReset className="h-4 w-4 text-slate-400" />
              up {fmtUptime(status.instance.uptimeSeconds)}
            </span>
            <span className="text-[11px] text-slate-400">{status.instance.nodeVersion}</span>
          </div>
        )
      }
    >
      <div className="space-y-4">

        {/* Workers table */}
        <section className="rounded-md border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3">
            <Activity className="h-4 w-4 text-slate-500" />
            <h2 className="text-sm font-semibold text-slate-800">Workers</h2>
            <span className="ml-auto text-xs text-slate-400">refreshes every 10 s</span>
          </div>
          <DataTable<WorkerRuntime>
            columns={workerColumns}
            rows={status?.workers ?? []}
            rowKey={(row) => row.name}
            storageKey="unm:table:workers"
            autoRefresh={{ intervalMs: 10_000, queries: [statusQuery] }}
            emptyMessage="No workers registered yet (API still starting up)"
          />
        </section>

        {/* Telemetry cycle stats */}
        {status && (
          <section className="grid grid-cols-2 gap-3 md:grid-cols-5">
            <Stat label="Poll cycles" value={status.telemetry.cyclesCompleted.toLocaleString()} sub="completed since start" />
            <Stat
              label="Skipped beats"
              value={status.telemetry.cyclesSkippedOverlap}
              sub="cycle guard (overlap)"
            />
            <Stat
              label="Last cycle"
              value={`${status.telemetry.devicesPolledLastCycle} dev / ${status.telemetry.assignmentsPolledLastCycle} plugins`}
              sub={`took ${fmtMs(status.telemetry.lastCycleDurationMs)}`}
            />
            <Stat label="Poll interval" value={`${Math.round(effectiveInterval / 1000)} s`} sub="effective (settings ⊕ env)" />
            <Stat label="Max concurrency" value={effectiveConcurrency} sub="in-flight polls per cycle" />
          </section>
        )}

        {/* HA & worker settings */}
        <section className="rounded-md border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3">
            <Gauge className="h-4 w-4 text-slate-500" />
            <h2 className="text-sm font-semibold text-slate-800">HA & worker settings</h2>
            {!canWrite && (
              <span className="ml-auto rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-500">read-only — requires system:write</span>
            )}
          </div>
          <div className="grid gap-4 p-4 md:grid-cols-2">
            <label className="block">
              <span className="text-sm font-medium text-slate-700">Telemetry poll interval (seconds)</span>
              <input
                type="number"
                min={5}
                max={3600}
                step={5}
                disabled={!canWrite || saveMutation.isPending}
                value={Math.round(effectiveInterval / 1000)}
                onChange={(e) => setIntervalMs(Number(e.target.value) * 1000)}
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none disabled:bg-slate-50"
              />
              <span className="mt-1 block text-xs text-slate-400">
                Beat between poll cycles. Longer beat for large fleets, or raise concurrency instead. Takes effect on the next cycle — no restart.
              </span>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-slate-700">Max concurrent polls</span>
              <input
                type="number"
                min={1}
                max={2000}
                step={8}
                disabled={!canWrite || saveMutation.isPending}
                value={effectiveConcurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                className="mt-1 w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none disabled:bg-slate-50"
              />
              <span className="mt-1 block text-xs text-slate-400">
                In-flight /monitoring calls per cycle. Keeps the burst flat regardless of fleet size; raise for fast fleets.
              </span>
            </label>
          </div>
          {canWrite && (
            <div className="flex items-center gap-3 border-t border-slate-200 px-4 py-3">
              <button
                onClick={() => saveMutation.mutate({ telemetryPollIntervalMs: effectiveInterval, telemetryMaxConcurrency: effectiveConcurrency })}
                disabled={saveMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
              >
                <Save className="h-4 w-4" />
                {saveMutation.isPending ? 'Saving…' : 'Apply settings'}
              </button>
              {saveError && <span className="text-sm text-red-600">{saveError}</span>}
            </div>
          )}
        </section>

        {/* Postgres */}
        {pg && (
          <section className="rounded-md border border-slate-200 bg-white shadow-sm">
            <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3">
              <Database className="h-4 w-4 text-slate-500" />
              <h2 className="text-sm font-semibold text-slate-800">Postgres</h2>
              <span className="ml-auto max-w-md truncate font-mono text-xs text-slate-400" title={pg.version}>
                {pg.version}
              </span>
            </div>
            <div className="grid grid-cols-2 gap-3 p-4 md:grid-cols-4">
              <Stat label="Database" value={pg.databaseName} sub={pg.databaseSizePretty ? `total ${pg.databaseSizePretty}` : undefined} />
              <Stat
                label="Connections"
                value={`${pg.connectionsTotal} / ${pg.maxConnections}`}
                sub={`${pg.connectionsActive} active · ${pg.connectionsIdle} idle`}
              />
              <div className="col-span-2">
                <div className="mb-1 flex items-center justify-between text-xs text-slate-500">
                  <span>Connection usage</span>
                  <span>{connPct}%</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-100">
                  <div
                    className={`h-full rounded-full ${connPct > 85 ? 'bg-red-500' : connPct > 60 ? 'bg-amber-400' : 'bg-emerald-500'}`}
                    style={{ width: `${Math.max(2, connPct)}%` }}
                  />
                </div>
              </div>
            </div>
            <DataTable<PostgresTableStat>
              columns={tableColumns}
              rows={pg.tables}
              rowKey={(row) => row.name}
              storageKey="unm:table:pg-tables"
              emptyMessage="No tracked tables found"
            />
          </section>
        )}

        {/* Recent events */}
        <section className="rounded-md border border-slate-200 bg-white shadow-sm">
          <div className="flex items-center gap-2 border-b border-slate-200 px-4 py-3">
            <Cpu className="h-4 w-4 text-slate-500" />
            <h2 className="text-sm font-semibold text-slate-800">Recent events</h2>
            <span className="ml-auto text-xs text-slate-400">leadership transitions + beat errors (last 200)</span>
          </div>
          {status && status.events.length > 0 ? (
            <ul className="divide-y divide-slate-100">
              {status.events.slice(0, 30).map((event) => (
                <li key={event.id} className="flex items-center gap-3 px-4 py-2 text-sm">
                  <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium uppercase ${EVENT_STYLES[event.type] ?? 'bg-slate-100 text-slate-600'}`}>
                    {event.type}
                  </span>
                  <span className="shrink-0 font-mono text-xs text-slate-400">{new Date(event.at).toLocaleTimeString()}</span>
                  <span className="truncate text-slate-700" title={event.message}>{event.message}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="px-4 py-6 text-center text-sm text-slate-400">No events recorded yet</div>
          )}
        </section>
      </div>
    </Layout>
  );
}
