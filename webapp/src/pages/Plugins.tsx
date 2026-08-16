import { useQuery } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Plugin } from '../api/client';

// A plugin is considered online if it was seen within the last 5 minutes.
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

function isOnline(plugin: Plugin): boolean {
  if (!plugin.lastSeenAt) return false;
  return Date.now() - new Date(plugin.lastSeenAt).getTime() < ONLINE_WINDOW_MS;
}

export default function Plugins() {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });

  const columns: DataTableColumn<Plugin>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Version', key: 'version' },
    { header: 'Vendors', key: 'vendors', render: (row) => row.vendors.join(', ') },
    { header: 'Capabilities', key: 'capabilities', render: (row) => row.capabilities.join(', ') },
    { header: 'Endpoint', key: 'endpoint', render: (row) => <span className="font-mono text-xs">{row.endpoint}</span> },
    {
      header: 'Status',
      key: 'status',
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
  ];

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
        <DataTable columns={columns} rows={pluginsQuery.data} rowKey={(row) => row.id} emptyMessage="No plugins discovered yet." />
      )}
    </Layout>
  );
}