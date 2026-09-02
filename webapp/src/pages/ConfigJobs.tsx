import { FormEvent, useMemo, useState } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { Plus, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { api, ConfigJob, Device } from '../api/client';
import { can } from '../auth/permissions';

const ACTIONS = [
  { value: 'applyConfig', label: 'Apply configuration' },
  { value: 'rollbackConfig', label: 'Rollback configuration' },
  { value: 'syncState', label: 'Sync state' },
] as const;

export default function ConfigJobs() {
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
        return name ? <span className="text-slate-600">{name}</span> : <span className="font-mono text-xs text-slate-400">{row.pluginId ?? '—'}</span>;
      },
    },
    { header: 'Action', key: 'action' },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Created',
      key: 'createdAt',
      sortAccessor: (row) => new Date(row.createdAt).getTime(),
      render: (row) => new Date(row.createdAt).toLocaleString(),
    },
    {
      header: 'Finished',
      key: 'finishedAt',
      width: 180,
      sortAccessor: (row) => (row.finishedAt ? new Date(row.finishedAt).getTime() : null),
      render: (row) => (row.finishedAt ? new Date(row.finishedAt).toLocaleString() : '—'),
    },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Config Jobs</h1>
        {canApply && (
          <button
            className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
            onClick={() => setShowForm((v) => !v)}
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? 'Cancel' : 'New Job'}
          </button>
        )}
      </div>

      {canApply && showForm && (
        <form
          onSubmit={handleSubmit}
          className="mb-6 grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-3"
        >
          {formError && (
            <div className="col-span-full rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {formError}
            </div>
          )}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Device</label>
            <select
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Plugin (applies the change)</label>
            <select
              required
              disabled={!deviceId}
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm disabled:opacity-50"
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Action</label>
            <select
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
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
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {submitJob.isPending ? 'Submitting…' : 'Submit Job'}
            </button>
          </div>
        </form>
      )}

      {jobsQuery.isLoading && <p className="text-sm text-slate-500">Loading config jobs...</p>}
      {jobsQuery.isError && (
        <p className="text-sm text-red-600">Failed to load config jobs: {(jobsQuery.error as Error).message}</p>
      )}
      {jobsQuery.data && (
        <DataTable columns={columns} rows={jobsQuery.data} rowKey={(row) => row.id} storageKey="config-jobs" autoRefresh={{ intervalMs: 10_000, queries: [jobsQuery] }} emptyMessage="No config jobs have been submitted yet." />
      )}
    </Layout>
  );
}
