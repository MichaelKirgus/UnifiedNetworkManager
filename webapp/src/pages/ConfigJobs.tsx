import { FormEvent, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Plus, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { api, ConfigJob, Device } from '../api/client';
import { can } from '../auth/permissions';
import { useTimeFormat } from '../utils/time';

const ACTIONS = [
  { value: 'applyConfig', label: 'Apply configuration' },
  { value: 'rollbackConfig', label: 'Rollback configuration' },
  { value: 'syncState', label: 'Sync state' },
] as const;

export default function ConfigJobs() {
  const { formatDateTime } = useTimeFormat();
  // Submitting a job needs configs:apply (+2FA server-side); the page itself
  // only requires config-jobs:read.
  const canApply = can('configs:apply');
  const jobsQuery = useQuery({
    queryKey: ['config-jobs'],
    queryFn: api.allConfigJobs,
    refetchInterval: 10_000,
  });

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });

  // --- New job form state -------------------------------------------------
  const [showForm, setShowForm] = useState(false);
  const [deviceId, setDeviceId] = useState('');
  const [pluginId, setPluginId] = useState('');
  const [action, setAction] = useState<string>('applyConfig');
  const [formError, setFormError] = useState<string | null>(null);

  const devices: Device[] = useMemo(() => devicesQuery.data ?? [], [devicesQuery.data]);
  const selectedDevice = devices.find((d) => d.id === deviceId);
  // Assignments for the chosen device (primary first).
  const assignments = useMemo(
    () => [...(selectedDevice?.plugins ?? [])].sort((a, b) => Number(b.isPrimary) - Number(a.isPrimary)),
    [selectedDevice]
  );

  function handleDeviceChange(id: string) {
    setDeviceId(id);
    const dev = devices.find((d) => d.id === id);
    // Preselect the primary assignment (falls back to the first).
    const sorted = [...(dev?.plugins ?? [])].sort((a, b) => Number(b.isPrimary) - Number(a.isPrimary));
    setPluginId(sorted[0]?.pluginId ?? '');
  }

  const submitJob = useMutation({
    mutationFn: (body: { pluginId: string; action: string; payload: Record<string, unknown> }) =>
      api.configJobs(deviceId, body),
    onSuccess: () => {
      setShowForm(false);
      setDeviceId('');
      setPluginId('');
      setAction('applyConfig');
      setFormError(null);
      jobsQuery.refetch();
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!deviceId || !pluginId) return;
    submitJob.mutate({ pluginId, action, payload: {} });
  }

  const columns: DataTableColumn<ConfigJob>[] = [
    { header: 'Job ID', key: 'id', render: (row) => <span className="font-mono text-xs">{row.id}</span> },
    { header: 'Device', key: 'deviceId', render: (row) => <span className="font-mono text-xs">{row.deviceId}</span> },
    {
      header: 'Plugin',
      key: 'pluginId',
      sortable: false,
      render: (row) => {
        const name = devices.find((d) => d.id === row.deviceId)?.plugins?.find((p) => p.pluginId === row.pluginId)?.pluginName;
        return name ? <span className="text-secondary">{name}</span> : <span className="font-mono text-xs text-faint">{row.pluginId ?? '—'}</span>;
      },
    },
    { header: 'Action', key: 'action' },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Created',
      key: 'createdAt',
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => formatDateTime(row.createdAt),
    },
    {
      header: 'Finished',
      key: 'finishedAt',
      width: 180,
      sortAccessor: (row) => (row.finishedAt ? new Date(row.finishedAt).getTime() : null),
      render: (row) => (row.finishedAt ? formatDateTime(row.finishedAt) : '—'),
    },
  ];

  return (
    <Layout
      title="Config Jobs"
      actions={
        canApply && (
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
            onClick={() => setShowForm((v) => !v)}
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? 'Cancel' : 'New Job'}
          </button>
        )
      }
    >

      {canApply && showForm && (
        <form
          onSubmit={handleSubmit}
          className="mb-6 grid grid-cols-1 gap-3 rounded-md border border-border bg-card p-4 shadow-sm sm:grid-cols-3"
        >
          {formError && (
            <div className="col-span-full rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
              {formError}
            </div>
          )}
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Device</label>
            <select
              required
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={deviceId}
              onChange={(e) => handleDeviceChange(e.target.value)}
            >
              <option value="" disabled>
                Select a device
              </option>
              {devices.map((d) => (
                <option key={d.id} value={d.id}>
                  {d.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Plugin (applies the change)</label>
            <select
              required
              disabled={!deviceId}
              className="w-full rounded-md border border-border px-3 py-2 text-sm disabled:opacity-50"
              value={pluginId}
              onChange={(e) => setPluginId(e.target.value)}
            >
              <option value="" disabled>
                Select a plugin
              </option>
              {assignments.map((a) => (
                <option key={a.id} value={a.pluginId}>
                  {a.pluginName ?? a.pluginId}
                  {a.isPrimary ? ' (primary)' : ''}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-secondary">Action</label>
            <select
              required
              className="w-full rounded-md border border-border px-3 py-2 text-sm"
              value={action}
              onChange={(e) => setAction(e.target.value)}
            >
              {ACTIONS.map((a) => (
                <option key={a.value} value={a.value}>
                  {a.label}
                </option>
              ))}
            </select>
          </div>
          <div className="col-span-full">
            <button
              type="submit"
              disabled={submitJob.isPending || !deviceId || !pluginId}
              className="rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              {submitJob.isPending ? 'Submitting…' : 'Submit Job'}
            </button>
          </div>
        </form>
      )}

      {jobsQuery.isLoading && <p className="text-sm text-muted-foreground">Loading config jobs...</p>}
      {jobsQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load config jobs: {(jobsQuery.error as Error).message}</p>
      )}
      {jobsQuery.data && (
        <DataTable columns={columns} rows={jobsQuery.data} rowKey={(row) => row.id} storageKey="config-jobs" autoRefresh={{ intervalMs: 10_000, queries: [jobsQuery] }} emptyMessage="No config jobs have been submitted yet." />
      )}
    </Layout>
  );
}
