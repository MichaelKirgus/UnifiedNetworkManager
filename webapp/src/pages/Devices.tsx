import { FormEvent, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { api, Device, Plugin } from '../api/client';

const emptyForm = {
  name: '',
  vendor: 'opnsense',
  deviceType: 'firewall',
  pluginId: '',
  managementAddress: '',
  credentialsRef: 'default',
  site: '',
};

export default function Devices() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });

  const createDevice = useMutation({
    mutationFn: api.createDevice,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setShowForm(false);
      setForm(emptyForm);
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    createDevice.mutate(form);
  }

  const columns: DataTableColumn<Device>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Vendor', key: 'vendor' },
    { header: 'Type', key: 'deviceType' },
    { header: 'Site', key: 'site', render: (row) => row.site ?? '—' },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Actions',
      key: 'actions',
      render: (row) => (
        <button
          className="text-sm font-medium text-slate-700 hover:underline"
          onClick={() => navigate(`/devices/${row.id}`)}
        >
          View
        </button>
      ),
    },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Devices</h1>
        <button
          className="rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? 'Cancel' : 'Register Device'}
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Vendor</label>
            <select
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.vendor}
              onChange={(e) => setForm({ ...form, vendor: e.target.value })}
            >
              <option value="opnsense">opnsense</option>
              <option value="mikrotik">mikrotik</option>
              <option value="openwrt">openwrt</option>
              <option value="other">other</option>
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Device Type</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.deviceType}
              onChange={(e) => setForm({ ...form, deviceType: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Plugin</label>
            <select
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.pluginId}
              onChange={(e) => setForm({ ...form, pluginId: e.target.value })}
            >
              <option value="" disabled>
                Select a plugin
              </option>
              {(pluginsQuery.data ?? []).map((plugin: Plugin) => (
                <option key={plugin.id} value={plugin.id}>
                  {plugin.name} ({plugin.version})
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Management Address</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.managementAddress}
              onChange={(e) => setForm({ ...form, managementAddress: e.target.value })}
              placeholder="https://10.0.0.1"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Site</label>
            <input
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.site}
              onChange={(e) => setForm({ ...form, site: e.target.value })}
            />
          </div>
          <div className="col-span-full">
            <button
              type="submit"
              disabled={createDevice.isPending}
              className="rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {createDevice.isPending ? 'Saving...' : 'Save Device'}
            </button>
          </div>
        </form>
      )}

      {devicesQuery.isLoading && <p className="text-sm text-slate-500">Loading devices...</p>}
      {devicesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load devices: {(devicesQuery.error as Error).message}</p>
      )}
      {devicesQuery.data && (
        <DataTable columns={columns} rows={devicesQuery.data} rowKey={(row) => row.id} emptyMessage="No devices registered yet." />
      )}
    </Layout>
  );
}
