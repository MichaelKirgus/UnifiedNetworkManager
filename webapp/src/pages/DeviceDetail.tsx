import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import clsx from 'clsx';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Copy, Power, Plus, Settings, Settings2, Star, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { StatusBadge } from '../components/StatusBadge';
import { MetricView } from '../components/MetricView';
import { OptionForm } from '../components/OptionForm';
import { DeviceIcon } from '../components/DeviceIcon';
import { PluginAssignmentBuilder } from '../components/PluginAssignmentBuilder';
import { api, DeviceAddress, LogEntry, DevicePluginAssignmentInput, MetricDescriptor, Plugin } from '../api/client';
import { can } from '../auth/permissions';
import { isValidAddress, addressError } from '../utils/address';

/** Resolves the current value for a metric descriptor from a metrics map. */
function resolveValue(descriptor: MetricDescriptor, metrics: Record<string, unknown>): unknown {
  return metrics[descriptor.key];
}

export default function DeviceDetail() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Write gating — the page needs devices:read (route guard); mutating actions
  // additionally need their own permission. Reference data for the add-plugin
  // modal is only fetched when the user may actually write.
  const canWriteDevices = can('devices:write');
  const canManagePlugins = can('plugins:manage');

  // Which assignment's settings are being edited (null = closed).
  const [settingsPluginId, setSettingsPluginId] = useState<string | null>(null);
  const [showAddPlugin, setShowAddPlugin] = useState(false);

  // Secondary IP management.
  const [showAddIp, setShowAddIp] = useState(false);
  const [newIpInput, setNewIpInput] = useState('');
  const [ipError, setIpError] = useState<string | null>(null);

  // Device deletion (409 while plans reference the device).
  const deleteDevice = useMutation({
    mutationFn: (id: string) => api.deleteDevice(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      navigate('/devices');
    },
  });

  // Telemetry polling toggle — disabled devices keep their historical data +
  // last metrics; re-enabling resumes polling.
  const [toggleError, setToggleError] = useState<string | null>(null);
  const toggleEnabled = useMutation({
    mutationFn: (enabled: boolean) => api.updateDevice(deviceId as string, { enabled }),
    onSuccess: () => {
      setToggleError(null);
      invalidateDevice();
    },
    onError: (err: Error) => setToggleError(err.message),
  });

  // Clone reuses all settings; the Devices page opens its edit form for the
  // clone (?edit=<id>) so the user can change the IP or other values.
  const [cloneError, setCloneError] = useState<string | null>(null);
  const cloneDevice = useMutation({
    mutationFn: () => api.cloneDevice(deviceId as string),
    onSuccess: (cloned) => {
      setCloneError(null);
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      navigate(`/devices?edit=${encodeURIComponent(cloned.id)}`);
    },
    onError: (err: Error) => setCloneError(err.message),
  });

  const devicesQuery = useQuery({
    queryKey: ['devices'],
    queryFn: api.devices,
    enabled: Boolean(deviceId),
  });

  // pluginsQuery feeds the header icon + add-plugin modal; secretsQuery only
  // the modal. Both are gated on their read permissions (the API enforces them).
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins, enabled: Boolean(deviceId) && can('plugins:read') });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets, enabled: Boolean(deviceId) && canWriteDevices && can('secrets:read') });

  const monitoringQuery = useQuery({
    queryKey: ['monitoring', deviceId],
    queryFn: () => api.monitoring(deviceId as string),
    enabled: Boolean(deviceId),
    refetchInterval: 15_000,
  });

  const telemetryQuery = useQuery({
    queryKey: ['deviceTelemetry', deviceId],
    queryFn: () => api.deviceTelemetry(deviceId as string, 30),
    enabled: Boolean(deviceId),
    refetchInterval: 30_000,
  });

  // Per-device plugin log entries (gated by logs:read — logs can carry critical
  // details). Newest first; the API caps at 500 rows, which is plenty for a
  // single device's recent activity.
  const [logLevelFilter, setLogLevelFilter] = useState('');
  const logsQuery = useQuery({
    queryKey: ['deviceLogs', deviceId, logLevelFilter],
    queryFn: () => api.logs({ deviceId: deviceId as string, level: (logLevelFilter || undefined) as LogEntry['level'] | undefined }),
    enabled: Boolean(deviceId) && can('logs:read'),
    refetchInterval: 15_000,
  });

  const device = (devicesQuery.data ?? []).find((d) => d.id === deviceId);
  const assignments = useMemo(
    () => [...(device?.plugins ?? [])].sort((a, b) => Number(b.isPrimary) - Number(a.isPrimary)),
    [device]
  );

  // Primary plugin (first after the sort above) as a full Plugin row — needed
  // for its icon + model catalog in the header.
  // The Config page is available when ANY assigned plugin advertises the
  // 'deviceState' capability (live device state + actions via plans).
  const hasDeviceConfig = useMemo(
    () =>
      assignments.some((a) => {
        if (a.pluginCapabilities?.includes('deviceState')) return true;
        const p = (pluginsQuery.data ?? []).find((x) => x.id === a.pluginId);
        return p?.capabilities?.includes('deviceState') ?? false;
      }),
    [assignments, pluginsQuery.data]
  );

  const primaryPlugin: Plugin | null = useMemo(() => {
    if (assignments.length === 0) return null;
    return (pluginsQuery.data ?? []).find((p) => p.id === assignments[0].pluginId) ?? null;
  }, [assignments, pluginsQuery.data]);

  // Static descriptors (from /discover) as a fallback for plugins that have
  // not reported live descriptors yet. Needs plugins:read (API-gated).
  const [fallbackDescriptors, setFallbackDescriptors] = useState<Record<string, MetricDescriptor[]>>({});
  useEffect(() => {
    if (!can('plugins:read')) return;
    let cancelled = false;
    Promise.all(
      assignments.map(async (a) => {
        try {
          return [a.pluginId, (await api.pluginMetrics(a.pluginId)).metrics] as const;
        } catch {
          return [a.pluginId, []] as const;
        }
      })
    ).then((entries) => {
      if (!cancelled) setFallbackDescriptors(Object.fromEntries(entries));
    });
    return () => {
      cancelled = true;
    };
  }, [assignments]);

  function invalidateDevice() {
    queryClient.invalidateQueries({ queryKey: ['devices'] });
    queryClient.invalidateQueries({ queryKey: ['monitoring', deviceId] });
  }

  const removeAssignment = useMutation({
    mutationFn: (pluginId: string) => api.removeDevicePlugin(deviceId as string, pluginId),
    onSuccess: invalidateDevice,
  });

  const setPrimary = useMutation({
    mutationFn: (pluginId: string) => api.setPrimaryPlugin(deviceId as string, pluginId),
    onSuccess: invalidateDevice,
  });

  const addAssignments = useMutation({
    mutationFn: async (inputs: DevicePluginAssignmentInput[]) => {
      for (const input of inputs) {
        await api.addDevicePlugin(deviceId as string, input);
      }
    },
    onSuccess: () => {
      invalidateDevice();
      setShowAddPlugin(false);
    },
  });

  const addIp = useMutation({
    mutationFn: (address: string) => api.addDeviceIp(deviceId as string, address),
    onSuccess: () => {
      invalidateDevice();
      setShowAddIp(false);
      setNewIpInput('');
      setIpError(null);
    },
  });

  const removeIp = useMutation({
    mutationFn: (ipId: string) => api.removeDeviceIp(deviceId as string, ipId),
    onSuccess: invalidateDevice,
  });

  const history = telemetryQuery.data?.history ?? [];
  function historyFor(pluginId: string, descriptor: MetricDescriptor) {
    if (descriptor.visualization !== 'plot') return undefined;
    return history
      .filter((h) => h.pluginId === pluginId)
      .map((h) => {
        const v = resolveValue(descriptor, h.metrics);
        return typeof v === 'number' ? { collectedAt: h.collectedAt, value: v } : null;
      })
      .filter((p): p is { collectedAt: string; value: number } => p !== null);
  }

  const snapshots = monitoringQuery.data?.snapshots ?? [];
  const settingsAssignment = assignments.find((a) => a.pluginId === settingsPluginId);

  // --- Identity rows (firmware + serial) ----------------------------------
  // Plugins report these under different metric keys:
  //   lancom-lx/lcos/sx → system.swVersion, mikrotik-swos → system.detectedFirmwareVersion,
  //   opnsense → version. Serial is system.serialNumber (lancom-*, swos).
  const FIRMWARE_METRIC_KEYS = ['system.swVersion', 'system.detectedFirmwareVersion', 'version'];
  const SERIAL_METRIC_KEYS = ['system.serialNumber'];

  /** First non-empty value across the snapshots; the primary plugin's snapshot wins. */
  function firstMetricValue(keys: string[]): { value: string; pluginName?: string } | null {
    const ordered = [...snapshots].sort(
      (a, b) => Number(b.pluginId === primaryPlugin?.id) - Number(a.pluginId === primaryPlugin?.id)
    );
    for (const snap of ordered) {
      for (const k of keys) {
        const v = snap.metrics[k];
        if (typeof v === 'string' && v.trim() !== '') {
          return { value: v, pluginName: assignments.find((a) => a.pluginId === snap.pluginId)?.pluginName };
        }
      }
    }
    return null;
  }

  const firmwareInfo = firstMetricValue(FIRMWARE_METRIC_KEYS);
  const serialInfo = firstMetricValue(SERIAL_METRIC_KEYS);

  function IdentityRow({ label, info }: { label: string; info: { value: string; pluginName?: string } | null }) {
    return (
      <div className="flex items-center gap-3 py-2 first:pt-0 last:pb-0">
        <dt className="w-40 shrink-0 text-sm font-medium text-slate-500">{label}</dt>
        <dd className="min-w-0 flex-1">
          {info ? (
            <span className="flex items-baseline gap-2">
              <span className="break-all font-mono text-xs text-slate-800">{info.value}</span>
              {snapshots.length > 1 && info.pluginName && (
                <span className="shrink-0 text-[11px] text-slate-400">via {info.pluginName}</span>
              )}
            </span>
          ) : (
            <span className="text-sm text-slate-400">—</span>
          )}
        </dd>
      </div>
    );
  }

  return (
    <Layout
      title={device?.name ?? deviceId}
      actions={
        <>
          {monitoringQuery.data && <StatusBadge status={monitoringQuery.data.health} />}
          {device?.enabled === false && (
            <span
              title="Telemetry polling disabled — historical data and last metrics are preserved"
              className="rounded-full bg-slate-200 px-2.5 py-1 text-xs font-semibold uppercase tracking-wide text-slate-600"
            >
              disabled
            </span>
          )}
          {device && hasDeviceConfig && (
            <Link
              to={`/devices/${device.id}/config`}
              className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700"
            >
              <Settings2 className="h-4 w-4" />
              Config
            </Link>
          )}
          {device && canWriteDevices && (
          <div className="flex items-center gap-2">
            <button
              onClick={() => {
                const next = device.enabled === false;
                if (window.confirm(next ? `Resume polling "${device.name}"?` : `Stop polling "${device.name}"?\nIts historical data and last metrics are preserved.`)) {
                  toggleEnabled.mutate(next);
                }
              }}
              disabled={toggleEnabled.isPending}
              className={`flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-sm font-medium disabled:opacity-50 ${
                device.enabled === false
                  ? 'border-green-200 text-green-700 hover:bg-green-50'
                  : 'border-slate-300 text-slate-600 hover:bg-slate-50'
              }`}
            >
              <Power className="h-4 w-4" />
              {device.enabled === false ? 'Enable polling' : 'Disable polling'}
            </button>
            <button
              onClick={() => {
                if (window.confirm(`Clone device "${device.name}"?\nAll plugin assignments, credentials, secondary IPs and per-device settings are reused. The edit form opens so you can change the IP or other settings.`)) {
                  cloneDevice.mutate();
                }
              }}
              disabled={cloneDevice.isPending}
              className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50 disabled:opacity-50"
            >
              <Copy className="h-4 w-4" />
              Clone
            </button>
            <button
              onClick={() => {
                if (window.confirm(`Delete device "${device.name}"?\nIts plugin assignments, secondary IPs and telemetry history are removed. Plans referencing it must be deleted first.`)) {
                  deleteDevice.mutate(device.id);
                }
              }}
              disabled={deleteDevice.isPending}
              className="flex items-center gap-1.5 rounded-md border border-red-200 px-3 py-1.5 text-sm font-medium text-red-600 hover:bg-red-50 disabled:opacity-50"
            >
              <Trash2 className="h-4 w-4" />
              Delete device
            </button>
          </div>
          )}
        </>
      }
    >
      <div className="mb-4 flex items-center gap-3">
        <Link to="/devices" className="text-sm text-slate-500 hover:underline">
          &larr; Back to devices
        </Link>
        <DeviceIcon plugin={primaryPlugin} model={device?.model} size="lg" />
        {device && (device.model || device.firmwareVersion) && (
          <p className="text-xs text-slate-400">
            {[device.vendor, ...(device.deviceTypes ?? []), device.model, device.firmwareVersion].filter(Boolean).join(' · ')}
          </p>
        )}
      </div>

      {(toggleError || cloneError) && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {toggleError ?? cloneError}
        </div>
      )}

      {deleteDevice.error && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
          {(deleteDevice.error as Error).message}
        </div>
      )}

      {/* --- Identity: firmware + serial (from the plugins' monitoring data) */}
      <section className="mb-8 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-500">Identity</h2>
        <dl className="divide-y divide-slate-100">
          <IdentityRow label="Firmware version" info={firmwareInfo} />
          <IdentityRow label="Serial number" info={serialInfo} />
        </dl>
      </section>

      {/* --- Plugin assignments ------------------------------------------- */}
      <section className="mb-8 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Plugins</h2>
          {canWriteDevices && (
            <button
              onClick={() => setShowAddPlugin(true)}
              className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
            >
              <Plus className="h-4 w-4" />
              Add plugin
            </button>
          )}
        </div>

        {assignments.length === 0 ? (
          <p className="text-sm text-slate-500">No plugins assigned to this device yet.</p>
        ) : (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-400">
                <th className="py-2 pr-3 font-medium">Plugin</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">Credentials</th>
                <th className="py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {assignments.map((a) => (
                <tr key={a.id} className="border-b border-slate-100 last:border-0">
                  <td className="py-2 pr-3">
                    <span className="font-medium text-slate-800">{a.pluginName ?? a.pluginId}</span>
                    {a.isPrimary && (
                      <span className="ml-2 rounded-full bg-slate-900 px-2 py-0.5 text-xs font-medium text-white">
                        primary
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-3">
                    {a.pluginOnline ? (
                      <span className="inline-flex items-center gap-1.5 text-green-600">
                        <span className="h-2 w-2 rounded-full bg-green-500" /> online
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-slate-400">
                        <span className="h-2 w-2 rounded-full bg-slate-300" /> offline
                      </span>
                    )}
                  </td>
                  <td className="py-2 pr-3">
                    <span className="text-slate-600">{a.secretLabel ?? '—'}</span>
                    {a.credentialSlots && a.credentialSlots.length > 0 && (
                      <div className="mt-1 flex flex-wrap gap-1">
                        {a.credentialSlots.map((slot) => (
                          <span
                            key={slot.name}
                            title={`${slot.description ?? `Credential slot "${slot.name}"`} (${slot.secretType})`}
                            className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs ${
                              slot.secretId
                                ? 'bg-indigo-50 text-indigo-700'
                                : 'bg-slate-100 text-slate-400'
                            }`}
                          >
                            {slot.name}: {slot.secretLabel ?? (slot.secretId ? '' : 'not set')}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="py-2 text-right">
                    <div className="inline-flex items-center gap-1">
                      {canWriteDevices && !a.isPrimary && (
                        <button
                          aria-label={`Make ${a.pluginName ?? a.pluginId} primary`}
                          title="Make primary plugin"
                          disabled={setPrimary.isPending}
                          onClick={() => setPrimary.mutate(a.pluginId)}
                          className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900 disabled:opacity-50"
                        >
                          <Star className="h-4 w-4" />
                        </button>
                      )}
                      {canManagePlugins && (
                        <button
                          aria-label={`Settings for ${a.pluginName ?? a.pluginId}`}
                          title="Device settings"
                          onClick={() => setSettingsPluginId(a.pluginId)}
                          className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                        >
                          <Settings className="h-4 w-4" />
                        </button>
                      )}
                      {canWriteDevices && (
                        <button
                          aria-label={`Remove ${a.pluginName ?? a.pluginId}`}
                          title="Remove assignment"
                          disabled={removeAssignment.isPending}
                          onClick={() => {
                            if (window.confirm(`Remove ${a.pluginName ?? 'this plugin'} from this device?`)) {
                              removeAssignment.mutate(a.pluginId);
                            }
                          }}
                          className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 disabled:opacity-50"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      {/* --- IP addresses (primary + secondaries) -------------------------- */}
      <section className="mb-8 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <div className="mb-3 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">IP addresses</h2>
          {canWriteDevices && (
            <button
              onClick={() => { setShowAddIp(true); setNewIpInput(''); setIpError(null); }}
              className="flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
            >
              <Plus className="h-4 w-4" />
              Add IP
            </button>
          )}
        </div>

        {device?.ips && device.ips.length > 0 ? (
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-xs uppercase tracking-wide text-slate-400">
                <th className="py-2 pr-3 font-medium">Address</th>
                <th className="py-2 pr-3 font-medium">Role</th>
                <th className="py-2 text-right font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {device.ips.map((ip: DeviceAddress) => (
                <tr key={ip.id ?? ip.address} className="border-b border-slate-100 last:border-0">
                  <td className="py-2 pr-3 font-mono text-xs">{ip.address}</td>
                  <td className="py-2 pr-3">
                    {ip.isPrimary ? (
                      <span className="rounded-full bg-slate-900 px-2 py-0.5 text-xs font-medium text-white">primary</span>
                    ) : (
                      <span className="text-slate-500">secondary</span>
                    )}
                  </td>
                  <td className="py-2 text-right">
                    {canWriteDevices && !ip.isPrimary && ip.id && (
                      <button
                        aria-label={`Remove ${ip.address}`}
                        title="Remove this IP"
                        disabled={removeIp.isPending}
                        onClick={() => {
                          if (window.confirm(`Remove ${ip.address} from this device?`)) {
                            removeIp.mutate(ip.id as string);
                          }
                        }}
                        className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 disabled:opacity-50"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p className="text-sm text-slate-500">No IP addresses registered yet.</p>
        )}
      </section>

      {/* --- Per-plugin metrics ------------------------------------------- */}
      {monitoringQuery.isLoading && <p className="text-sm text-slate-500">Loading telemetry...</p>}
      {monitoringQuery.isError && (
        <p className="text-sm text-red-600">Failed to load telemetry: {(monitoringQuery.error as Error).message}</p>
      )}

      {snapshots.map((snapshot) => {
        const assignment = assignments.find((a) => a.pluginId === snapshot.pluginId);
        const descriptors =
          snapshot.metricDescriptors?.length ?? 0 > 0
            ? snapshot.metricDescriptors!
            : fallbackDescriptors[snapshot.pluginId] ?? [];

        const groups: [string, MetricDescriptor[]][] = (() => {
          const map = new Map<string, MetricDescriptor[]>();
          for (const d of descriptors) {
            const g = d.group ?? 'Metrics';
            if (!map.has(g)) map.set(g, []);
            map.get(g)!.push(d);
          }
          return Array.from(map.entries());
        })();

        return (
          <section key={snapshot.pluginId} className="mb-8">
            <div className="mb-3 flex items-center gap-2">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">
                {assignment?.pluginName ?? snapshot.pluginId}
              </h2>
              <StatusBadge status={snapshot.health} />
            </div>

            {descriptors.length === 0 ? (
              <p className="text-sm text-slate-500">
                This plugin has not reported metric descriptors yet. Raw metrics:{' '}
                <code className="break-all rounded bg-slate-100 px-1 py-0.5 text-xs">{JSON.stringify(snapshot.metrics)}</code>
              </p>
            ) : (
              groups.map(([group, descs]) => (
                <div key={group} className="mb-6">
                  {groups.length > 1 && (
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-400">{group}</h3>
                  )}
                  <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                    {descs.map((d) => (
                      <MetricView
                        key={d.key}
                        descriptor={d}
                        value={resolveValue(d, snapshot.metrics)}
                        history={historyFor(snapshot.pluginId, d)}
                      />
                    ))}
                  </div>
                </div>
              ))
            )}

            {snapshot.collectedAt && (
              <p className="text-xs text-slate-400">Last collected: {new Date(snapshot.collectedAt).toLocaleString()}</p>
            )}
          </section>
        );
      })}

      {/* --- Plugin logs (gated by logs:read) ------------------------------ */}
      {can('logs:read') && (
        <section className="mb-8">
          <div className="mb-3 flex items-center justify-between gap-2">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-slate-500">Logs</h2>
            <select
              className="rounded-md border border-slate-300 px-2 py-1 text-xs"
              value={logLevelFilter}
              onChange={(e) => setLogLevelFilter(e.target.value)}
            >
              <option value="">All levels</option>
              <option value="debug">Debug</option>
              <option value="info">Info</option>
              <option value="warn">Warn</option>
              <option value="error">Error</option>
            </select>
          </div>

          {logsQuery.isLoading && <p className="text-sm text-slate-500">Loading logs...</p>}
          {logsQuery.isError && (
            <p className="text-sm text-red-600">Failed to load logs: {(logsQuery.error as Error).message}</p>
          )}
          {logsQuery.data &&
            (logsQuery.data.length === 0 ? (
              <p className="text-sm text-slate-500">
                No log entries for this device yet — plugins ship failures and state changes here.
              </p>
            ) : (
              <div className="overflow-x-auto rounded-md border border-slate-200 bg-white shadow-sm">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-slate-200 bg-slate-50 text-xs uppercase tracking-wide text-slate-500">
                    <tr>
                      <th className="px-3 py-2">Time</th>
                      <th className="px-3 py-2">Level</th>
                      <th className="px-3 py-2">Plugin</th>
                      <th className="px-3 py-2">Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {logsQuery.data.map((entry) => (
                      <tr key={entry.id} className="border-b border-slate-100 last:border-0">
                        <td className="whitespace-nowrap px-3 py-2 font-mono text-xs text-slate-500">
                          {new Date(entry.timestamp).toLocaleString()}
                        </td>
                        <td className="px-3 py-2">
                          <span
                            className={`inline-flex rounded px-1.5 py-0.5 text-xs font-medium uppercase ${
                              entry.level === 'error'
                                ? 'bg-red-100 text-red-700'
                                : entry.level === 'warn'
                                  ? 'bg-amber-100 text-amber-800'
                                  : entry.level === 'debug'
                                    ? 'bg-slate-100 text-slate-500'
                                    : 'bg-blue-100 text-blue-700'
                            }`}
                          >
                            {entry.level}
                          </span>
                        </td>
                        <td className="whitespace-nowrap px-3 py-2 text-xs text-slate-600">{entry.pluginName ?? entry.pluginId}</td>
                        <td className="px-3 py-2">
                          <div className="flex flex-col gap-1">
                            <span className="break-words text-slate-800">{entry.message}</span>
                            {entry.context && Object.keys(entry.context).length > 0 && (
                              <details className="text-xs">
                                <summary className="cursor-pointer font-medium text-blue-600 hover:underline">Details</summary>
                                <pre className="mt-1 max-h-48 overflow-auto rounded bg-slate-900 p-2 font-mono text-[11px] leading-relaxed text-slate-100">
                                  {JSON.stringify(entry.context, null, 2)}
                                </pre>
                              </details>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ))}
        </section>
      )}

      {/* --- Add plugin modal --------------------------------------------- */}
      {showAddPlugin && (
        <div
          className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-6"
          onClick={() => setShowAddPlugin(false)}
        >
          <div
            className="mt-10 w-full max-w-lg rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-slate-800">Add plugin to {device?.name ?? 'device'}</h3>
              <button aria-label="Close" onClick={() => setShowAddPlugin(false)} className="rounded-md p-1 text-slate-400 hover:bg-slate-100">
                <X className="h-4 w-4" />
              </button>
            </header>
            <div className="p-4">
              {addAssignments.isError && (
                <div className="mb-3 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {(addAssignments.error as Error).message}
                </div>
              )}
              <PluginAssignmentBuilder
                plugins={pluginsQuery.data ?? []}
                secrets={secretsQuery.data ?? []}
                excludedPluginIds={assignments.map((a) => a.pluginId)}
                onSubmit={(inputs) => addAssignments.mutate(inputs)}
                submitLabel="Add"
                busy={addAssignments.isPending}
              />
            </div>
          </div>
        </div>
      )}

      {/* --- Add IP modal -------------------------------------------------- */}
      {showAddIp && (
        <div
          className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-6"
          onClick={() => setShowAddIp(false)}
        >
          <form
            onSubmit={(e) => {
              e.preventDefault();
              const v = newIpInput.trim();
              if (!v) return;
              if (!isValidAddress(v)) { setIpError(addressError(v)); return; }
              addIp.mutate(v);
            }}
            className="mt-10 w-full max-w-md rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-slate-800">Add IP to {device?.name ?? 'device'}</h3>
              <button type="button" aria-label="Close" onClick={() => setShowAddIp(false)} className="rounded-md p-1 text-slate-400 hover:bg-slate-100">
                <X className="h-4 w-4" />
              </button>
            </header>
            <div className="space-y-3 p-4">
              {addIp.isError && (
                <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
                  {(addIp.error as Error).message}
                </div>
              )}
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">IP address</label>
                <input
                  autoFocus
                  className={`w-full rounded-md border px-3 py-2 text-sm ${ipError ? 'border-red-400' : 'border-slate-300'}`}
                  value={newIpInput}
                  onChange={(e) => { setNewIpInput(e.target.value); setIpError(null); }}
                  placeholder="10.0.0.2 or 2001:db8::1"
                />
                {ipError && <p className="mt-1 text-xs text-red-600">{ipError}</p>}
              </div>
            </div>
            <footer className="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3">
              <button
                type="button"
                onClick={() => setShowAddIp(false)}
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={addIp.isPending}
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
              >
                Add IP
              </button>
            </footer>
          </form>
        </div>
      )}

      {/* --- Per-device settings modal ------------------------------------- */}
      {settingsAssignment && (
        <div
          className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-6"
          onClick={() => setSettingsPluginId(null)}
        >
          <div
            className="mt-10 w-full max-w-lg rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-slate-800">
                Settings — {settingsAssignment.pluginName ?? settingsAssignment.pluginId} on {device?.name ?? 'this device'}
              </h3>
              <button aria-label="Close" onClick={() => setSettingsPluginId(null)} className="rounded-md p-1 text-slate-400 hover:bg-slate-100">
                <X className="h-4 w-4" />
              </button>
            </header>
            <div className="p-4">
              <OptionForm pluginId={settingsAssignment.pluginId} deviceId={deviceId as string} onSaved={invalidateDevice} />
            </div>
          </div>
        </div>
      )}
    </Layout>
  );
}
