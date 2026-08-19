import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { api, ConfigJob } from '../api/client';

export default function ConfigJobs() {
  const jobsQuery = useQuery({
    queryKey: ['config-jobs'],
    queryFn: api.allConfigJobs,
    refetchInterval: 10_000,
  });

  const columns: DataTableColumn<ConfigJob>[] = [
    { header: 'Job ID', key: 'id', render: (row) => <span className="font-mono text-xs">{row.id}</span> },
    { header: 'Device', key: 'deviceId', render: (row) => <span className="font-mono text-xs">{row.deviceId}</span> },
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
      <h1 className="mb-4 text-xl font-bold text-slate-900">Config Jobs</h1>

      {jobsQuery.isLoading && <p className="text-sm text-slate-500">Loading config jobs...</p>}
      {jobsQuery.isError && (
        <p className="text-sm text-red-600">Failed to load config jobs: {(jobsQuery.error as Error).message}</p>
      )}
      {jobsQuery.data && (
        <DataTable columns={columns} rows={jobsQuery.data} rowKey={(row) => row.id} storageKey="config-jobs" emptyMessage="No config jobs have been submitted yet." />
      )}
    </Layout>
  );
}
