import { ReactNode, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn, ExpandChildContext } from '../components/DataTable';
import { api, PostgresTableStat, SystemEvent, WorkerRuntime } from '../api/client';
import { useTimeFormat } from '../utils/time';
import { can } from '../auth/permissions';
import { Activity, ChevronDown, ChevronRight, Cpu, Database, Gauge, Save, ServerCog, TimerReset } from 'lucide-react';

/** Human-friendly duration (ms → "1.2 s" / "340 ms"). */
function fmtMs(ms?: number | null): string {
  if (ms === null || ms === undefined) return '—';
  if (ms < 1000) return `${Math.round(ms)} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

/** Window duration in compact form (ms → "15 min" / "2 h" / "90 s"). */
function fmtWindow(ms?: number | null): string {
  if (ms === null || ms === undefined) return '—';
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s} s`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  return `${h} h`;
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
  'leadership-acquired': 'bg-success text-success-fg',
  'leadership-lost': 'bg-warning text-warning-fg',
  'worker-started': 'bg-info text-info-fg',
  'beat-error': 'bg-danger text-danger-fg',
};

/** Small stat card used in the telemetry + Postgres sections. */
function Stat({ label, value, sub }: { label: string; value: ReactNode; sub?: string }) {
  return (
    <div className="rounded-md border border-border bg-card px-4 py-3 shadow-sm">
      <div className="text-xs font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 text-lg font-semibold text-foreground">{value}</div>
      {sub && <div className="mt-0.5 text-xs text-muted-foreground">{sub}</div>}
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
  const { formatTime } = useTimeFormat();
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
  const [inventoryWindowMs, setInventoryWindowMs] = useState<number | null>(null);
  const [concurrency, setConcurrency] = useState<number | null>(null);
  const [jitterPercent, setJitterPercent] = useState<number | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);

  const effectiveInterval = intervalMs ?? settingsQuery.data?.telemetryPollIntervalMs ?? 30_000;
  const effectiveInventoryWindow = inventoryWindowMs ?? settingsQuery.data?.telemetryInventoryWindowMs ?? 15 * 60_000;
  const effectiveConcurrency = concurrency ?? settingsQuery.data?.telemetryMaxConcurrency ?? 64;
  const effectiveJitter = jitterPercent ?? settingsQuery.data?.telemetryJitterPercent ?? 20;

  const saveMutation = useMutation({
    mutationFn: api.saveSystemSettings,
    onSuccess: (data) => {
      queryClient.setQueryData(['system-settings'], data);
      setIntervalMs(null); // re-sync the form to the saved values
      setInventoryWindowMs(null);
      setConcurrency(null);
      setJitterPercent(null);
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
          <div className="text-sm font-medium text-foreground">{row.name}</div>
          <div className="font-mono text-[11px] text-faint">key {row.leaderKey === -1 ? 'n/a (all replicas)' : row.leaderKey}</div>
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
          <span className="inline-flex rounded bg-muted px-2 py-0.5 text-xs font-medium text-secondary">runs on every replica</span>
        ) : row.isLeader ? (
          <div>
            <span className="inline-flex items-center gap-1 rounded bg-success px-2 py-0.5 text-xs font-semibold text-success-fg">
              <span className="h-1.5 w-1.5 rounded-full bg-status-ok" /> leader
            </span>
            {row.becameLeaderAt && (
              <div className="mt-0.5 text-[11px] text-faint">since {formatTime(row.becameLeaderAt)}</div>
            )}
          </div>
        ) : (
          <span className="inline-flex rounded bg-muted px-2 py-0.5 text-xs font-medium text-muted-foreground">standby</span>
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
          <span className="inline-flex rounded bg-danger px-2 py-0.5 text-xs font-semibold text-danger-fg">{row.beatErrors}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    {
      header: 'Last error',
      key: 'lastError',
      width: 320,
      filterable: false,
      render: (row) =>
        row.lastError ? <span className="block truncate text-xs text-danger-fg" title={row.lastError}>{row.lastError}</span> : <span className="text-faint">—</span>,
    },
  ];

  const tableColumns: DataTableColumn<PostgresTableStat>[] = [
    { header: 'Table', key: 'name', width: 240, render: (row) => <span className="font-mono text-sm">{row.name}</span> },
    {
      // Partition status — count + PARTITION BY key for partitioned parents.
      header: 'Partitioned',
      key: 'isPartitioned',
      width: 170,
      sortAccessor: (row) => (row.isPartitioned ? row.partitionCount ?? 0 : -1),
      render: (row) =>
        row.isPartitioned ? (
          <span className="inline-flex items-center gap-1.5">
            <span className="rounded bg-info px-1.5 py-0.5 text-[11px] font-medium text-info-fg">{row.partitionCount}</span>
            {row.partitionKey && (
              <span className="font-mono text-[11px] text-faint" title={row.partitionKey}>{row.partitionKey}</span>
            )}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
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
    {
      // Only meaningful for partition child rows — hidden by default, enable via the Columns picker.
      header: 'Bound',
      key: 'bound',
      width: 280,
      filterable: false,
      hiddenByDefault: true,
      render: (row) => (row.bound ? <span className="font-mono text-xs">{row.bound}</span> : <span className="text-faint">—</span>),
    },
  ];

  // Cell content for one partition child row, aligned to the visible columns.
  const partitionCell = (key: string, part: PostgresTableStat): ReactNode => {
    switch (key) {
      case 'name': return <span className="font-mono text-xs">{part.name}</span>;
      case 'isPartitioned': return <span className="text-[11px] text-faint">partition</span>;
      case 'approxRows': return <span className="font-mono text-sm">{part.approxRows.toLocaleString()}</span>;
      case 'totalSizeBytes': return <span className="font-mono text-sm">{part.totalSizePretty}</span>;
      case 'bound': return part.bound ? <span className="font-mono text-xs">{part.bound}</span> : <span className="text-faint">—</span>;
      default: return null;
    }
  };

  function PgPartitionRow({ child, ctx }: { child: PostgresTableStat; ctx: ExpandChildContext }) {
    return (
      <tr className="bg-accent-sky/40 dark:bg-muted/70">
        <td className="px-1 py-2 align-middle"><span className="inline-block h-6 w-6" /></td>
        {ctx.selectable && <td className="px-3 py-2" />}
        {ctx.columns.map((col) => (
          <td key={col.key} className="overflow-hidden px-4 py-2 text-secondary">{partitionCell(col.key, child)}</td>
        ))}
      </tr>
    );
  }

  const pg = status?.postgres;
  const connPct = pg && pg.maxConnections > 0 ? Math.min(100, Math.round((pg.connectionsTotal / pg.maxConnections) * 100)) : 0;

  return (
    <Layout
      title="Workers & HA"
      actions={
        status && (
          <div className="flex items-center gap-4 rounded-md border border-border bg-card px-3 py-1.5 shadow-sm">
            <span className="flex items-center gap-1.5 text-xs text-secondary" title={`PID ${status.instance.pid}`}>
              <ServerCog className="h-4 w-4 text-faint" />
              {status.instance.hostname}
            </span>
            <span className="flex items-center gap-1.5 text-xs text-secondary">
              <TimerReset className="h-4 w-4 text-faint" />
              up {fmtUptime(status.instance.uptimeSeconds)}
            </span>
            <span className="text-[11px] text-faint">{status.instance.nodeVersion}</span>
          </div>
        )
      }
    >
      <div className="space-y-4">

        {/* Workers table */}
        <section className="rounded-md border border-border bg-card shadow-sm">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <Activity className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold text-foreground">Workers</h2>
            <span className="ml-auto text-xs text-faint">refreshes every 10 s</span>
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

        {/* Telemetry dispatcher stats */}
        {status && (
          <section className="grid grid-cols-2 gap-3 md:grid-cols-6">
            <Stat label="Polls completed" value={status.telemetry.cyclesCompleted.toLocaleString()} sub={`last took ${fmtMs(status.telemetry.lastPollDurationMs)}`} />
            <Stat
              label="In flight"
              value={status.telemetry.pollsInFlight ?? 0}
              sub={`of ${effectiveConcurrency} max concurrent`}
            />
            <Stat label="Poll rate" value={`${status.telemetry.pollsPerMinute ?? 0}/min`} sub="trailing 60 s" />
            <Stat
              label="Waiting on budget"
              value={status.telemetry.overdueWaiting ?? 0}
              sub="overdue, queued for a slot"
            />
            <Stat label="Metrics window" value={`${Math.round(effectiveInterval / 1000)} s`} sub="effective (settings ⊕ env)" />
            <Stat
              label="Inventory window"
              value={fmtWindow(effectiveInventoryWindow)}
              sub={`jitter ±${effectiveJitter}%`}
            />
          </section>
        )}

        {/* HA & worker settings */}
        <section className="rounded-md border border-border bg-card shadow-sm">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <Gauge className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold text-foreground">HA & worker settings</h2>
            {!canWrite && (
              <span className="ml-auto rounded bg-muted px-2 py-0.5 text-xs text-muted-foreground">read-only — requires system:write</span>
            )}
          </div>
          <div className="grid gap-4 p-4 md:grid-cols-2">
            <label className="block">
              <span className="text-sm font-medium text-secondary">Metrics poll window (seconds)</span>
              <input
                type="number"
                min={5}
                max={3600}
                step={5}
                disabled={!canWrite || saveMutation.isPending}
                value={Math.round(effectiveInterval / 1000)}
                onChange={(e) => setIntervalMs(Number(e.target.value) * 1000)}
                className="mt-1 w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
              />
              <span className="mt-1 block text-xs text-faint">
                Every device is polled at least once within this window — deadlines are staggered, so polls spread out instead of bursting. Takes effect immediately — no restart.
              </span>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-secondary">Inventory refresh window (seconds)</span>
              <input
                type="number"
                min={30}
                max={43200}
                step={30}
                disabled={!canWrite || saveMutation.isPending}
                value={Math.round(effectiveInventoryWindow / 1000)}
                onChange={(e) => setInventoryWindowMs(Number(e.target.value) * 1000)}
                className="mt-1 w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
              />
              <span className="mt-1 block text-xs text-faint">
                How often the slow/static collection (networks, routes, WiFi clients, storage…) runs. Metrics-only polls in between are cheap.
              </span>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-secondary">Max concurrent polls</span>
              <input
                type="number"
                min={1}
                max={2000}
                step={8}
                disabled={!canWrite || saveMutation.isPending}
                value={effectiveConcurrency}
                onChange={(e) => setConcurrency(Number(e.target.value))}
                className="mt-1 w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
              />
              <span className="mt-1 block text-xs text-faint">
                Global in-flight /monitoring budget across all devices. Keeps the burst flat regardless of fleet size; raise for fast fleets.
              </span>
            </label>
            <label className="block">
              <span className="text-sm font-medium text-secondary">Deadline jitter (percent)</span>
              <input
                type="number"
                min={0}
                max={90}
                step={5}
                disabled={!canWrite || saveMutation.isPending}
                value={effectiveJitter}
                onChange={(e) => setJitterPercent(Number(e.target.value))}
                className="mt-1 w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none disabled:bg-background"
              />
              <span className="mt-1 block text-xs text-faint">
                Random spread (±%) applied to each rescheduled deadline so devices don't re-align into synchronized bursts.
              </span>
            </label>
          </div>
          {canWrite && (
            <div className="flex items-center gap-3 border-t border-border px-4 py-3">
              <button
                onClick={() =>
                  saveMutation.mutate({
                    telemetryPollIntervalMs: effectiveInterval,
                    telemetryInventoryWindowMs: effectiveInventoryWindow,
                    telemetryMaxConcurrency: effectiveConcurrency,
                    telemetryJitterPercent: effectiveJitter,
                  })
                }
                disabled={saveMutation.isPending}
                className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                <Save className="h-4 w-4" />
                {saveMutation.isPending ? 'Saving…' : 'Apply settings'}
              </button>
              {saveError && <span className="text-sm text-danger-fg">{saveError}</span>}
            </div>
          )}
        </section>

        {/* Postgres */}
        {pg && (
          <section className="rounded-md border border-border bg-card shadow-sm">
            <div className="flex items-center gap-2 border-b border-border px-4 py-3">
              <Database className="h-4 w-4 text-muted-foreground" />
              <h2 className="text-sm font-semibold text-foreground">Postgres</h2>
              <span className="ml-auto max-w-md truncate font-mono text-xs text-faint" title={pg.version}>
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
                <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
                  <span>Connection usage</span>
                  <span>{connPct}%</span>
                </div>
                <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                  <div
                    className={`h-full rounded-full ${connPct > 85 ? 'bg-status-critical' : connPct > 60 ? 'bg-status-warn' : 'bg-status-ok'}`}
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
              emptyMessage="No user tables found"
              expandable={{
                childrenOf: (row) => pg.partitions.filter((p) => p.parent === row.name),
                renderChild: (child, _parent, ctx) => <PgPartitionRow child={child} ctx={ctx} />,
              }}
            />
          </section>
        )}

        {/* Recent events */}
        <section className="rounded-md border border-border bg-card shadow-sm">
          <div className="flex items-center gap-2 border-b border-border px-4 py-3">
            <Cpu className="h-4 w-4 text-muted-foreground" />
            <h2 className="text-sm font-semibold text-foreground">Recent events</h2>
            <span className="ml-auto text-xs text-faint">leadership transitions + beat errors (last 200)</span>
          </div>
          {status && status.events.length > 0 ? (
            <ul className="divide-y divide-border">
              {status.events.slice(0, 30).map((event) => (
                <li key={event.id} className="flex items-center gap-3 px-4 py-2 text-sm">
                  <span className={`shrink-0 rounded px-1.5 py-0.5 text-[11px] font-medium uppercase ${EVENT_STYLES[event.type] ?? 'bg-muted text-secondary'}`}>
                    {event.type}
                  </span>
                  <span className="shrink-0 font-mono text-xs text-faint">{formatTime(event.at)}</span>
                  <span className="truncate text-secondary" title={event.message}>{event.message}</span>
                </li>
              ))}
            </ul>
          ) : (
            <div className="px-4 py-6 text-center text-sm text-faint">No events recorded yet</div>
          )}
        </section>
      </div>
    </Layout>
  );
}
