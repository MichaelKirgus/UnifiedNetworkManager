import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Globe, Radio, ArrowLeftRight, Server } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { formatBytes, formatNumber } from '../components/formatMetric';
import { api, FlowTalker, FlowInternetDevice, FlowPair } from '../api/client';

/** Time-range presets (v1: presets only — the API resolves `from`/`to`). */
const TIME_RANGES = [
  { value: '1h', label: 'Last hour' },
  { value: '24h', label: 'Last 24 hours' },
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
] as const;

type TimeRange = (typeof TIME_RANGES)[number]['value'];

const RANGE_MS: Record<TimeRange, number> = {
  '1h': 60 * 60 * 1000,
  '24h': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
  '30d': 30 * 24 * 60 * 60 * 1000,
};

/** Minimal inline SVG sparkline — no chart lib needed for a single series. */
function Sparkline({ values, width = 160, height = 32 }: { values: number[]; width?: number; height?: number }) {
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
      <polyline points={points} fill="none" stroke="rgb(var(--accent-solid))" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

/** Classification pill for a talker IP (internal vs internet/unknown). */
function ClassPill({ internal }: { internal: boolean }) {
  return (
    <span
      className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${
        internal ? 'bg-accent-teal text-accent-teal-fg' : 'bg-muted text-secondary'
      }`}
    >
      {internal ? 'internal' : 'external'}
    </span>
  );
}

function orDash(v?: string | null): string {
  return v && v.trim() !== '' ? v : '—';
}

/**
 * Flows — sFlow/NetFlow traffic visibility. Shows who talks to the internet and
 * which devices talk to each other, aggregated from flow-collector plugin
 * samples (5-minute / hourly rollups). Gated by `flows:read`.
 */
export default function Flows() {
  const [range, setRange] = useState<TimeRange>('24h');

  // The `from` bound is computed at fetch time so "last hour" keeps sliding as
  // the page refetches. Rollups land every 5 minutes — refresh on that cadence.
  const windowParams = () => {
    const to = new Date();
    const from = new Date(Date.now() - RANGE_MS[range]);
    return { from: from.toISOString(), to: to.toISOString() };
  };

  const talkersQuery = useQuery({
    queryKey: ['flows', 'top-talkers', range],
    queryFn: () => api.flowsTopTalkers({ ...windowParams(), limit: 20 }),
    refetchInterval: 60_000,
  });
  const internetQuery = useQuery({
    queryKey: ['flows', 'internet', range],
    queryFn: () => api.flowsInternet(windowParams()),
    refetchInterval: 60_000,
  });
  const pairsQuery = useQuery({
    queryKey: ['flows', 'pairs', range],
    queryFn: () => api.flowsPairs({ ...windowParams(), limit: 20 }),
    refetchInterval: 60_000,
  });
  // Internet egress over time — the page's headline chart. Hourly buckets for
  // multi-day ranges keep the point count sane; 5-minute otherwise.
  const seriesQuery = useQuery({
    queryKey: ['flows', 'timeseries', range],
    queryFn: () => api.flowsTimeseries({ ...windowParams(), bucket: range === '7d' || range === '30d' ? '1h' : '5m', class: 'internet' }),
    refetchInterval: 60_000,
  });
  const collectorsQuery = useQuery({
    queryKey: ['flows', 'collectors'],
    queryFn: () => api.flowCollectors(),
    refetchInterval: 30_000,
  });

  const talkerColumns: DataTableColumn<FlowTalker>[] = [
    {
      header: 'IP',
      key: 'ip',
      width: 150,
      render: (row) => <span className="font-mono text-xs">{row.ip}</span>,
    },
    {
      header: 'Class',
      key: 'internal',
      width: 90,
      sortAccessor: (row) => (row.internal ? 1 : 0),
      render: (row) => <ClassPill internal={row.internal} />,
    },
    {
      header: 'Device',
      key: 'deviceName',
      width: 200,
      exportValue: (row) => row.deviceName ?? '',
      render: (row) => (row.deviceName ? <span className="text-sm">{row.deviceName}</span> : <span className="text-faint">—</span>),
    },
    {
      header: 'Est. Bytes',
      key: 'estBytes',
      width: 120,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Reported',
      key: 'reportedBytes',
      width: 120,
      hiddenByDefault: true,
      sortAccessor: (row) => row.reportedBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.reportedBytes)}</span>,
    },
  ];

  const internetColumns: DataTableColumn<FlowInternetDevice>[] = [
    {
      header: 'Device',
      key: 'deviceName',
      width: 240,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.deviceName)}</span>,
    },
    {
      header: 'Egress to Internet',
      key: 'estBytes',
      width: 160,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Distinct Destinations',
      key: 'distinctDestinations',
      width: 160,
      sortAccessor: (row) => row.distinctDestinations,
      render: (row) => <span className="font-mono text-xs">{formatNumber(row.distinctDestinations)}</span>,
    },
  ];

  const pairColumns: DataTableColumn<FlowPair>[] = [
    {
      header: 'Source',
      key: 'srcName',
      width: 240,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.srcName)}</span>,
    },
    {
      header: 'Destination',
      key: 'dstName',
      width: 240,
      render: (row) => <span className="font-medium text-foreground">{orDash(row.dstName)}</span>,
    },
    {
      header: 'Est. Bytes',
      key: 'estBytes',
      width: 140,
      sortAccessor: (row) => row.estBytes,
      render: (row) => <span className="font-mono text-xs">{formatBytes(row.estBytes)}</span>,
    },
    {
      header: 'Distinct IP Pairs',
      key: 'distinctPairs',
      width: 140,
      sortAccessor: (row) => row.distinctPairs,
      render: (row) => <span className="font-mono text-xs">{formatNumber(row.distinctPairs)}</span>,
    },
  ];

  const seriesValues = (seriesQuery.data?.points ?? []).map((p) => p.estBytes);
  const topSource = talkersQuery.data?.sources[0];
  const topPair = pairsQuery.data?.pairs[0];
  const collectors = collectorsQuery.data?.collectors ?? [];
  const ingest = collectorsQuery.data?.ingest;

  return (
    <Layout title="Flows">
      {/* Filter bar — time-range preset. */}
      <div className="mb-3 flex shrink-0 items-center gap-2">
        <select
          className="w-full max-w-xs rounded-md border border-border px-2.5 py-1.5 text-sm"
          value={range}
          onChange={(e) => setRange(e.target.value as TimeRange)}
        >
          {TIME_RANGES.map((r) => (
            <option key={r.value} value={r.value}>
              {r.label}
            </option>
          ))}
        </select>
      </div>

      {/* Summary strip — internet egress total, top talker, busiest pair. */}
      {internetQuery.data && (
        <div className="mb-3 flex shrink-0 flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border border-border bg-card px-4 py-2 text-xs">
          <span className="flex items-center gap-2 text-secondary">
            <Globe size={13} className="text-accent-solid" />
            {formatBytes(internetQuery.data.total.estBytes)} to internet ·{' '}
            {formatNumber(internetQuery.data.total.distinctDestinations)} destinations
          </span>
          {topSource && (
            <span className="flex items-center gap-2 text-secondary">
              <Radio size={13} className="text-muted-foreground" />
              top talker: <span className="font-mono">{topSource.ip}</span> ({formatBytes(topSource.estBytes)})
            </span>
          )}
          {topPair && (
            <span className="flex items-center gap-2 text-secondary">
              <ArrowLeftRight size={13} className="text-muted-foreground" />
              busiest pair: {orDash(topPair.srcName)} → {orDash(topPair.dstName)} ({formatBytes(topPair.estBytes)})
            </span>
          )}
        </div>
      )}

      {/* Internet egress over time — headline chart. */}
      <div className="mb-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="text-xs font-medium text-secondary">Internet egress over time</p>
        {seriesQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!seriesQuery.isLoading && seriesValues.length > 0 && (
          <div className="flex items-end gap-4">
            <Sparkline values={seriesValues} width={560} height={48} />
            <span className="font-mono text-xs text-secondary">{formatBytes(Math.max(...seriesValues))} peak</span>
          </div>
        )}
        {!seriesQuery.isLoading && seriesValues.length > 0 && Math.max(...seriesValues) === 0 && (
          <p className="mt-1 text-sm text-faint">No internet egress in this window.</p>
        )}
      </div>

      {/* Internet egress per device. */}
      {internetQuery.data && (
        <DataTable
          columns={internetColumns}
          rows={internetQuery.data.perDevice}
          rowKey={(row) => row.deviceId}
          storageKey="flows-internet"
          searchPlaceholder="Search devices…"
          emptyMessage="No internet egress recorded in this window — assign the flow-collector plugin to a device and point an sFlow exporter at it."
        />
      )}

      {/* Top talkers — sources and destinations side by side. */}
      <div className="mt-3 grid shrink-0 grid-cols-1 gap-3 xl:grid-cols-2">
        {talkersQuery.data && (
          <DataTable
            columns={talkerColumns}
            rows={talkersQuery.data.sources}
            rowKey={(row) => `s|${row.ip}`}
            storageKey="flows-talkers-src"
            searchPlaceholder="Search source IPs…"
            emptyMessage="No traffic recorded in this window."
          />
        )}
        {talkersQuery.data && (
          <DataTable
            columns={talkerColumns}
            rows={talkersQuery.data.destinations}
            rowKey={(row) => `d|${row.ip}`}
            storageKey="flows-talkers-dst"
            searchPlaceholder="Search destination IPs…"
            emptyMessage="No traffic recorded in this window."
          />
        )}
      </div>

      {/* Device-to-device pairs. */}
      {pairsQuery.data && (
        <DataTable
          columns={pairColumns}
          rows={pairsQuery.data.pairs}
          rowKey={(row) => `${row.srcDeviceId}|${row.dstDeviceId}`}
          storageKey="flows-pairs"
          searchPlaceholder="Search device pairs…"
          emptyMessage="No internal device-to-device traffic recorded in this window."
        />
      )}

      {/* Collector health — live plugin stats + API ingest queue. */}
      <div className="mt-3 shrink-0 rounded-lg border border-border bg-card px-4 py-2">
        <p className="flex items-center gap-2 text-xs font-medium text-secondary">
          <Server size={13} /> Collectors &amp; ingest
        </p>
        {collectorsQuery.isLoading && <p className="mt-1 text-sm text-muted-foreground">Loading…</p>}
        {!collectorsQuery.isLoading && collectors.length === 0 && (
          <p className="mt-1 text-sm text-faint">No flow-collector plugins registered — add one via the Plugins page.</p>
        )}
        {collectors.map((c) => (
          <div key={c.id} className="mt-1 flex flex-wrap items-center gap-x-4 gap-y-0.5 text-xs">
            <span className={`font-medium ${c.reachable ? 'text-success-fg' : 'text-danger-fg'}`}>
              {orDash(c.name)} ({c.reachable ? 'online' : 'offline'})
            </span>
            <span className="font-mono text-secondary">{formatNumber(c.samplesPerSec, 'samples/s')}</span>
            <span className="font-mono text-secondary">queue {formatNumber(c.queueDepth)}</span>
            <span className={`font-mono ${c.droppedTuplesTotal > 0 ? 'text-warning-fg' : 'text-secondary'}`}>
              dropped {formatNumber(c.droppedTuplesTotal)}
            </span>
          </div>
        ))}
        {ingest && (
          <p className="mt-1 text-xs text-faint">
            API ingest queue: depth {formatNumber(ingest.queueDepth)} · enqueued {formatNumber(ingest.enqueuedTotal)} · dropped{' '}
            {formatNumber(ingest.droppedTotal)} · inserted {formatNumber(ingest.insertedTotal)}
            {ingest.lastError && <span className="text-danger-fg"> · last error: {ingest.lastError}</span>}
          </p>
        )}
      </div>
    </Layout>
  );
}
