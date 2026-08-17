import { useMemo } from 'react';
import { useParams, Link } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { MetricView } from '../components/MetricView';
import { api, MetricDescriptor } from '../api/client';

/**
 * Resolves the current value for a metric descriptor from a telemetry metrics
 * map. Handles both flat keys (`cpu.load`) and table metrics (`traffic` with
 * per-row keys like `traffic.rx.wan`).
 */
function resolveValue(descriptor: MetricDescriptor, metrics: Record<string, unknown>): unknown {
  // Table metrics are emitted as a nested object keyed by row (e.g.
  // { traffic: { wan: { rx, tx } } }); everything else is a flat key.
  return metrics[descriptor.key];
}

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();

  const monitoringQuery = useQuery({
    queryKey: ['monitoring', deviceId],
    queryFn: () => api.monitoring(deviceId as string),
    enabled: Boolean(deviceId),
    refetchInterval: 15_000,
  });

  const devicesQuery = useQuery({
    queryKey: ['devices'],
    queryFn: api.devices,
    enabled: Boolean(deviceId),
  });

  const device = (devicesQuery.data ?? []).find((d) => d.id === deviceId);
  const pluginId = device?.pluginId;

  const metricsQuery = useQuery({
    queryKey: ['pluginMetrics', pluginId],
    queryFn: () => api.pluginMetrics(pluginId as string),
    enabled: Boolean(pluginId),
  });

  const telemetryQuery = useQuery({
    queryKey: ['deviceTelemetry', deviceId],
    queryFn: () => api.deviceTelemetry(deviceId as string, 30),
    enabled: Boolean(deviceId),
    refetchInterval: 30_000,
  });

  // Prefer the descriptors carried by the latest monitoring snapshot (they are
  // built dynamically from the data the appliance actually returned, so they
  // always match — including the traffic table). Fall back to the plugin's
  // static descriptors from /discover when no telemetry has been collected yet.
  const descriptors =
    monitoringQuery.data?.metricDescriptors?.length
      ? monitoringQuery.data.metricDescriptors
      : metricsQuery.data?.metrics ?? [];
  const currentMetrics = monitoringQuery.data?.metrics ?? {};
  const history = telemetryQuery.data?.history ?? [];

  const groups = useMemo(() => {
    const map = new Map<string, MetricDescriptor[]>();
    for (const d of descriptors) {
      const g = d.group ?? 'Metrics';
      if (!map.has(g)) map.set(g, []);
      map.get(g)!.push(d);
    }
    return Array.from(map.entries());
  }, [descriptors]);

  function historyFor(descriptor: MetricDescriptor) {
    if (descriptor.visualization !== 'plot') return undefined;
    return history
      .map((h) => {
        const v = resolveValue(descriptor, h.metrics);
        return typeof v === 'number' ? { collectedAt: h.collectedAt, value: v } : null;
      })
      .filter((p): p is { collectedAt: string; value: number } => p !== null);
  }

  return (
    <Layout>
      <div className="mb-4">
        <Link to="/devices" className="text-sm text-slate-500 hover:underline">
          &larr; Back to devices
        </Link>
      </div>

      <div className="mb-6 flex items-center gap-3">
        <h1 className="text-xl font-bold text-slate-900">{device?.name ?? deviceId}</h1>
        {monitoringQuery.data && <StatusBadge status={monitoringQuery.data.health} />}
      </div>

      {monitoringQuery.isLoading && <p className="text-sm text-slate-500">Loading telemetry...</p>}
      {monitoringQuery.isError && (
        <p className="text-sm text-red-600">Failed to load telemetry: {(monitoringQuery.error as Error).message}</p>
      )}

      {descriptors.length === 0 && monitoringQuery.data && (
        <p className="mb-4 text-sm text-slate-500">
          This plugin does not declare metric descriptors. Raw metrics: {JSON.stringify(monitoringQuery.data.metrics)}
        </p>
      )}

      {groups.map(([group, descs]) => (
        <div key={group} className="mb-6">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">{group}</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {descs.map((d) => (
              <MetricView
                key={d.key}
                descriptor={d}
                value={resolveValue(d, currentMetrics)}
                history={historyFor(d)}
              />
            ))}
          </div>
        </div>
      ))}

      {monitoringQuery.data && (
        <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <p className="text-xs uppercase text-slate-400">Last Collected</p>
          <p className="text-sm text-slate-700">{new Date(monitoringQuery.data.collectedAt).toLocaleString()}</p>
        </div>
      )}
    </Layout>
  );
}
