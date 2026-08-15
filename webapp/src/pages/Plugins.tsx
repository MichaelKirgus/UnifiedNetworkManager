import { FormEvent, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Plugin } from '../api/client';

const emptyForm = {
  name: '',
  version: '1.0.0',
  vendors: 'opnsense',
  capabilities: 'monitoring,configuration,inventory',
  endpoint: 'http://localhost:4001',
  authType: 'none',
};

export default function Plugins() {
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);

  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });

  const createPlugin = useMutation({
    mutationFn: api.createPlugin,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['plugins'] });
      setShowForm(false);
      setForm(emptyForm);
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    createPlugin.mutate({
      name: form.name,
      version: form.version,
      vendors: form.vendors.split(',').map((v) => v.trim()).filter(Boolean),
      capabilities: form.capabilities.split(',').map((c) => c.trim()).filter(Boolean),
      endpoint: form.endpoint,
      authType: form.authType,
    });
  }

  const columns: DataTableColumn<Plugin>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Version', key: 'version' },
    { header: 'Vendors', key: 'vendors', render: (row) => row.vendors.join(', ') },
    { header: 'Capabilities', key: 'capabilities', render: (row) => row.capabilities.join(', ') },
    { header: 'Endpoint', key: 'endpoint', render: (row) => <span className="font-mono text-xs">{row.endpoint}</span> },
    { header: 'Auth', key: 'authType' },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Plugins</h1>
        <button
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? 'Cancel' : 'Register Plugin'}
        </button>
      </div>

      {showForm && (
        <form
          onSubmit={handleSubmit}
          className="mb-6 grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-2"
        >
          {formError && (
            <div className="col-span-full rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
              {formError}
            </div>
          )}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Name</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Version</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.version}
              onChange={(e) => setForm({ ...form, version: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Vendors (comma separated)</label>
            <input
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.vendors}
              onChange={(e) => setForm({ ...form, vendors: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Capabilities (comma separated)</label>
            <input
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.capabilities}
              onChange={(e) => setForm({ ...form, capabilities: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Endpoint</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.endpoint}
              onChange={(e) => setForm({ ...form, endpoint: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Auth Type</label>
            <select
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.authType}
              onChange={(e) => setForm({ ...form, authType: e.target.value })}
            >
              <option value="none">none</option>
              <option value="token">token</option>
              <option value="mTLS">mTLS</option>
            </select>
          </div>
          <div className="col-span-full">
            <button
              type="submit"
              disabled={createPlugin.isPending}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {createPlugin.isPending ? 'Saving...' : 'Save Plugin'}
            </button>
          </div>
        </form>
      )}

      {pluginsQuery.isLoading && <p className="text-sm text-slate-500">Loading plugins...</p>}
      {pluginsQuery.isError && (
        <p className="text-sm text-red-600">Failed to load plugins: {(pluginsQuery.error as Error).message}</p>
      )}
      {pluginsQuery.data && (
        <DataTable columns={columns} rows={pluginsQuery.data} rowKey={(row) => row.id} emptyMessage="No plugins registered yet." />
      )}
    </Layout>
  );
}
