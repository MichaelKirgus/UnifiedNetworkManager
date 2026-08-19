import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { OptionForm } from '../components/OptionForm';
import { api, Plugin } from '../api/client';

// A plugin is considered online if it was seen within the last 5 minutes.
const ONLINE_WINDOW_MS = 5 * 60 * 1000;

function isOnline(plugin: Plugin): boolean {
  if (!plugin.lastSeenAt) return false;
  return Date.now() - new Date(plugin.lastSeenAt).getTime() < ONLINE_WINDOW_MS;
}

export default function Plugins() {
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  // Plugin whose settings form is open in the modal (null = closed).
  const [configureId, setConfigureId] = useState<string | null>(null);

  const columns: DataTableColumn<Plugin>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Version', key: 'version' },
    { header: 'Vendors', key: 'vendors', render: (row) => row.vendors.join(', ') },
    { header: 'Capabilities', key: 'capabilities', render: (row) => row.capabilities.join(', ') },
    { header: 'Endpoint', key: 'endpoint', width: 240, render: (row) => <span className="font-mono text-xs">{row.endpoint}</span> },
    {
      header: 'Status',
      key: 'status',
      // Sort by recency of last seen; offline plugins sink to the bottom.
      sortAccessor: (row) => (row.lastSeenAt ? new Date(row.lastSeenAt).getTime() : null),
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
    {
      header: 'Actions',
      key: 'actions',
      width: 110,
      sortable: false,
      render: (row) => (
        <button
          type="button"
          aria-label={`Configure ${row.name}`}
          title="Configure plugin settings"
          className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
          onClick={() => setConfigureId(row.id)}
        >
          <Settings className="h-4 w-4" />
        </button>
      ),
    },
  ];

  const configurePlugin = configureId ? (pluginsQuery.data ?? []).find((p) => p.id === configureId) : null;

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
        <DataTable columns={columns} rows={pluginsQuery.data} rowKey={(row) => row.id} storageKey="plugins" emptyMessage="No plugins discovered yet." />
      )}

      {/* Plugin settings modal — generic form rendered from the plugin's option descriptors. */}
      {configurePlugin && (
        <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-4 sm:items-center" onClick={() => setConfigureId(null)}>
          <div
            className="w-full max-w-lg rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h2 className="text-base font-semibold text-slate-900">
                Settings — {configurePlugin.name}
                <span className="ml-2 text-xs font-normal text-slate-400">{configurePlugin.version}</span>
              </h2>
              <button
                type="button"
                aria-label="Close settings"
                onClick={() => setConfigureId(null)}
                className="rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <OptionForm pluginId={configurePlugin.id} />
          </div>
        </div>
      )}
    </Layout>
  );
}