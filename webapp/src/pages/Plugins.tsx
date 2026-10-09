import { ReactNode, useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { BookOpen, Check, ExternalLink, RefreshCw, Settings } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { OptionForm } from '../components/OptionForm';
import { Markdown } from '../components/Markdown';
import { DialogShell } from '../components/DialogShell';
import { api, DeviceSupportProfile, Plugin, PluginSelfMetricsSample, SupportCondition } from '../api/client';
import { formatMs } from '../components/formatMetric';
import { can } from '../auth/permissions';

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
      {/* Sparkline hue — centralized accent token (indigo). */}
      <polyline points={points} fill="none" stroke="rgb(var(--accent-solid))" strokeWidth="1.5" strokeLinejoin="round" />
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
      <span className="text-faint">
        {query.isLoading ? 'Loading self-metrics…' : 'No self-metrics yet — plugin offline or predates the /metrics endpoint.'}
      </span>
    );
  }

  const stat = (label: string, value: string, spark?: number[]): ReactNode => (
    <span className="inline-flex items-center gap-1.5">
      <span className="text-faint">{label}</span>
      <span className="font-mono font-medium text-foreground">{value}</span>
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

/** Human-readable label for one support-matrix profile row. */
function profileLabel(p: DeviceSupportProfile): string {
  const parts: string[] = [];
  if (p.vendor) parts.push(p.vendor);
  if (p.model) parts.push(p.model);
  else if (!p.vendor) parts.push('any model');
  if (p.minFirmware || p.maxFirmware) parts.push(`firmware ${p.minFirmware ?? '*'}–${p.maxFirmware ?? '*'}`);
  return parts.join(' / ');
}

/** Short tooltip text for a grant's gating conditions. */
function conditionSummary(c?: SupportCondition): string {
  if (!c) return '';
  const bits: string[] = [];
  if (c.requiresFeatures?.length) bits.push(`requires feature(s): ${c.requiresFeatures.join(', ')}`);
  if (c.requiredSlots?.length) bits.push(`requires slot(s): ${c.requiredSlots.join(', ')}`);
  if (c.minFirmware) bits.push(`firmware >= ${c.minFirmware}`);
  if (c.maxFirmware) bits.push(`firmware <= ${c.maxFirmware}`);
  return bits.join('; ');
}

/**
 * Plugin details modal — license, help URL, built-in markdown documentation
 * (fetched through the API's asset proxy and rendered safely), and the
 * standardized supported-device matrix (profiles → capabilities + intents).
 */
function PluginDetailsModal({ pluginId, onClose }: { pluginId: string; onClose: () => void }) {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const plugin = (pluginsQuery.data ?? []).find((p) => p.id === pluginId);
  // Which text asset is open in the viewer pane ('doc' | 'license' | null).
  const [asset, setAsset] = useState<'doc' | 'license' | null>(null);

  if (!plugin?.deviceSupport) return null;
  const support = plugin.deviceSupport;

  const assetPath =
    asset === 'doc' ? support.docPath : asset === 'license' ? (support.license?.file ?? null) : null;
  const assetQuery = useQuery({
    queryKey: ['pluginAsset', pluginId, assetPath],
    queryFn: () => api.pluginAsset(pluginId, assetPath),
    enabled: !!assetPath,
  });

  return (
    <DialogShell
      title={plugin.name}
      subtitle={plugin.buildTag ? `${plugin.version} · build ${plugin.buildTag}` : plugin.version}
      onClose={onClose}
      zIndex="z-40"
      maxWidth="max-w-2xl"
      bodyMaxHeight="70vh"
    >
          {/* License + help row */}
          <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
            {support.license && (
              <span className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs font-medium" title={support.license.url ?? ''}>
                License: {support.license.name}
              </span>
            )}
            {support.helpUrl && (
              <a href={support.helpUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-xs text-accent-indigo underline">
                Help <ExternalLink className="h-3 w-3" />
              </a>
            )}
            {support.docPath && (
              <button
                type="button"
                onClick={() => setAsset(asset === 'doc' ? null : 'doc')}
                className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${
                  asset === 'doc' ? 'bg-accent-indigo/60 text-accent-indigo-fg' : 'bg-muted hover:bg-border'
                }`}
              >
                <BookOpen className="h-3 w-3" /> Documentation
              </button>
            )}
            {support.license?.file && (
              <button
                type="button"
                onClick={() => setAsset(asset === 'license' ? null : 'license')}
                className={`inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium ${
                  asset === 'license' ? 'bg-accent-indigo/60 text-accent-indigo-fg' : 'bg-muted hover:bg-border'
                }`}
              >
                License full text
              </button>
            )}
          </div>

          {/* Built-in documentation / license viewer */}
          {asset && assetPath && (
            <div className="mb-4 max-h-80 overflow-y-auto rounded-md border border-border bg-muted/30 p-3">
              {assetQuery.isLoading && <p className="text-sm text-faint">Loading…</p>}
              {assetQuery.isError && <p className="text-sm text-danger-fg">{(assetQuery.error as Error).message}</p>}
              {assetQuery.data && <Markdown text={assetQuery.data} />}
            </div>
          )}

          {/* Default capabilities (effective on every device of this plugin) */}
          {(support.defaultCapabilities?.length ?? 0) > 0 && (
            <section className="mb-4">
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-faint">Default capabilities</h3>
              <div className="flex flex-wrap gap-1.5">
                {support.defaultCapabilities!.map((g) => (
                  <span key={g.name} title={conditionSummary(g.conditions)} className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs">
                    {g.label ?? g.name}
                  </span>
                ))}
              </div>
            </section>
          )}

          {/* Supported-device matrix */}
          {(support.profiles?.length ?? 0) > 0 && (
            <section className="mb-2">
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-faint">Supported devices</h3>
              <div className="space-y-2">
                {support.profiles!.map((p, i) => (
                  <div key={i} className="rounded-md border border-border p-2.5">
                    <p className="mb-1.5 text-sm font-medium">{profileLabel(p)}</p>
                    <div className="flex flex-wrap gap-1.5">
                      {p.capabilities.map((g) => (
                        <span key={g.name} title={conditionSummary(g.conditions)} className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs">
                          {g.label ?? g.name}
                        </span>
                      ))}
                      {(p.intents ?? []).map((g) => (
                        <span
                          key={g.actionId}
                          title={`Intent ${g.actionId}${conditionSummary(g.conditions) ? ' — ' + conditionSummary(g.conditions) : ''}`}
                          className="inline-flex items-center rounded-full bg-accent-indigo/40 px-2 py-0.5 text-xs"
                        >
                          {g.label ?? g.actionId}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}
    </DialogShell>
  );
}

/**
 * "Re-enroll mTLS" action for one plugin: forces a fresh CA-issued leaf (new
 * serial) under the same ACME account — rotation, not revocation. The old leaf
 * stays valid until its expiry; the registry row refreshes on the next metrics poll.
 */
function RenewTlsButton({ plugin }: { plugin: Plugin }) {
  const queryClient = useQueryClient();
  const [confirming, setConfirming] = useState(false);
  useEffect(() => {
    if (!confirming) return;
    const t = setTimeout(() => setConfirming(false), 4000);
    return () => clearTimeout(t);
  }, [confirming]);

  const mutation = useMutation({
    mutationFn: () => api.renewPluginTls(plugin.id),
    onSuccess: () => {
      setConfirming(false);
      void queryClient.invalidateQueries({ queryKey: ['plugins'] });
      void queryClient.invalidateQueries({ queryKey: ['certificates'] });
    },
  });

  if (mutation.isSuccess) {
    return (
      <span className="inline-flex items-center gap-1 text-xs font-medium text-success-fg" title={`New mTLS leaf issued for ${plugin.name}`}>
        <Check className="h-4 w-4" /> renewed
      </span>
    );
  }

  return (
    <>
      {confirming ? (
        <button
          type="button"
          aria-label={`Confirm re-enrollment for ${plugin.name}`}
          title="Click again to confirm — issues a NEW mTLS leaf (the old one stays valid until expiry)"
          onClick={() => mutation.mutate()}
          disabled={mutation.isPending}
          className="rounded-md bg-danger px-2 py-1.5 text-xs font-medium text-white hover:opacity-90 disabled:opacity-50"
        >
          {mutation.isPending ? 'Renewing…' : 'Confirm'}
        </button>
      ) : (
        <button
          type="button"
          aria-label={`Re-enroll mTLS for ${plugin.name}`}
          title={
            plugin.tlsLive
              ? 'Issue a fresh mTLS leaf for this plugin (rotation — the current one stays valid until expiry)'
              : 'This plugin is not serving mTLS yet — re-enrollment will fail until its listener is live'
          }
          onClick={() => setConfirming(true)}
          className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
        >
          <RefreshCw className={`h-4 w-4 ${mutation.isPending ? 'animate-spin' : ''}`} />
        </button>
      )}
      {mutation.isError && (
        <span title={(mutation.error as Error).message} className="text-xs text-danger-fg">
          {(mutation.error as Error).message}
        </span>
      )}
    </>
  );
}

export default function Plugins() {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Plugin whose settings form is open in the modal (null = closed).
  const [configureId, setConfigureId] = useState<string | null>(null);
  // Plugin whose details (license/help/docs/support matrix) are open (null = closed).
  const [detailsId, setDetailsId] = useState<string | null>(null);

  const columns: DataTableColumn<Plugin>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Version', key: 'version' },
    {
      // Build tag baked into the image at CI build time (branch/release); null = local/dev.
      header: 'Build',
      key: 'buildTag',
      width: 120,
      render: (row) =>
        row.buildTag ? (
          <span className="font-mono text-xs">{row.buildTag}</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    { header: 'Vendors', key: 'vendors', render: (row) => row.vendors.join(', ') },
    { header: 'Capabilities', key: 'capabilities', render: (row) => row.capabilities.join(', ') },
    {
      header: 'Metrics',
      key: 'declaredMetricCount',
      width: 90,
      sortAccessor: (row) => row.declaredMetricCount ?? null,
      render: (row) =>
        row.declaredMetricCount !== null && row.declaredMetricCount !== undefined ? (
          <span className="text-secondary">{row.declaredMetricCount} declared</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    { header: 'Endpoint', key: 'endpoint', width: 240, render: (row) => <span className="font-mono text-xs">{row.endpoint}</span> },
    {
      header: 'Status',
      key: 'status',
      // Sort by recency of last seen; offline plugins sink to the bottom.
      sortAccessor: (row) => (row.lastSeenAt ? new Date(row.lastSeenAt).getTime() : null),
      render: (row) => (
        <div className="flex flex-wrap items-center gap-1">
          {isOnline(row) ? (
            <span className="inline-flex items-center rounded-full bg-success px-2 py-0.5 text-xs font-medium text-success-fg">
              online
            </span>
          ) : (
            <span className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
              offline
            </span>
          )}
          {row.tlsLive && (
            <span
              title="Serving its internal API over mTLS with a UNM CA-issued leaf"
              className="inline-flex items-center rounded-full bg-accent-violet px-2 py-0.5 text-xs font-medium text-accent-violet-fg"
            >
              mTLS
            </span>
          )}
        </div>
      ),
    },
    {
      header: 'Actions',
      key: 'actions',
      excludeFromExport: true,
      width: 220,
      sortable: false,
      render: (row) => (
        <div className="inline-flex items-center gap-1">
          {row.deviceSupport && (
            <button
              type="button"
              aria-label={`Details for ${row.name}`}
              title="License, documentation & supported devices"
              className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
              onClick={() => setDetailsId(row.id)}
            >
              <BookOpen className="h-4 w-4" />
            </button>
          )}
          {can('plugins:manage') && (
            <button
              type="button"
              aria-label={`Configure ${row.name}`}
              title="Configure plugin settings"
              className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
              onClick={() => setConfigureId(row.id)}
            >
              <Settings className="h-4 w-4" />
            </button>
          )}
          {can('ca:manage') && (
            <RenewTlsButton plugin={row} />
          )}
        </div>
      ),
    },
  ];

  const configurePlugin = configureId ? (pluginsQuery.data ?? []).find((p) => p.id === configureId) : null;

  return (
    <Layout title="Plugins">

      {pluginsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading plugins...</p>}
      {pluginsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load plugins: {(pluginsQuery.error as Error).message}</p>
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
        <DialogShell
          title={`Settings — ${configurePlugin.name}`}
          subtitle={configurePlugin.buildTag ? `${configurePlugin.version} · build ${configurePlugin.buildTag}` : configurePlugin.version}
          onClose={() => setConfigureId(null)}
          zIndex="z-40"
        >
          <OptionForm pluginId={configurePlugin.id} />
        </DialogShell>
      )}

      {/* Plugin details modal — license / help / built-in docs / support matrix. */}
      {detailsId && <PluginDetailsModal pluginId={detailsId} onClose={() => setDetailsId(null)} />}
    </Layout>
  );
}