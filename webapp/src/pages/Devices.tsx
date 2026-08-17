import { FormEvent, useState, useEffect, useMemo } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCell } from '../components/MetricCell';
import { api, Device, Plugin } from '../api/client';

const emptyForm = {
  name: '',
  vendor: '',
  deviceType: 'firewall',
  pluginId: '',
  managementAddress: '',
  credentialsRef: '',
  site: '',
};

// Derive the list of selectable vendors from the discovered plugins so that
// adding/renaming a plugin is reflected in the GUI without code changes.
function vendorOptions(plugins: Plugin[]): string[] {
  const vendors = plugins.flatMap((p) => p.vendors ?? []);
  return Array.from(new Set(vendors)).sort();
}

export default function Devices() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(emptyForm);
  const [formError, setFormError] = useState<string | null>(null);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets });
  const [requiredType, setRequiredType] = useState<string | null>(null);

  // When a plugin is chosen, look up the secret type it expects so the
  // credentials dropdown only offers compatible secrets.
  useEffect(() => {
    if (!form.pluginId) {
      setRequiredType(null);
      return;
    }
    let cancelled = false;
    api
      .requiredSecretType(form.pluginId)
      .then((res) => {
        if (!cancelled) setRequiredType(res.requiredSecretType);
      })
      .catch(() => {
        if (!cancelled) setRequiredType(null);
      });
    return () => {
      cancelled = true;
    };
  }, [form.pluginId]);

  // Secrets compatible with the selected plugin (by required type), or all
  // secrets when the plugin declares no requirement.
  const compatibleSecrets = useMemo(() => {
    const all = secretsQuery.data ?? [];
    if (!requiredType) return all;
    return all.filter((s) => s.type === requiredType);
  }, [secretsQuery.data, requiredType]);

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

  // When a plugin is chosen, auto-select its first vendor so the vendor
  // dropdown always reflects a valid plugin vendor.
  function handlePluginChange(pluginId: string) {
    const plugin = (pluginsQuery.data ?? []).find((p) => p.id === pluginId);
    const vendor = plugin?.vendors?.[0] ?? '';
    setForm({ ...form, pluginId, vendor });
  }

  const columns: DataTableColumn<Device>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Vendor', key: 'vendor' },
    { header: 'Type', key: 'deviceType' },
    { header: 'Site', key: 'site', render: (row) => row.site ?? '—' },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Metrics',
      key: 'metrics',
      render: (row) => {
        const metrics = row.summaryMetrics ?? [];
        if (metrics.length === 0) return <span className="text-slate-400">—</span>;
        return (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {metrics.map((m) => (
              <MetricCell key={m.key} metric={m} />
            ))}
          </div>
        );
      },
    },
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
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={form.vendor}
              onChange={(e) => setForm({ ...form, vendor: e.target.value })}
            >
              <option value="" disabled>
                Select a vendor
              </option>
              {vendorOptions(pluginsQuery.data ?? []).map((vendor) => (
                <option key={vendor} value={vendor}>
                  {vendor}
                </option>
              ))}
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
              onChange={(e) => handlePluginChange(e.target.value)}
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
             <label className="mb-1 block text-sm font-medium text-slate-700">
               Credentials Reference{requiredType ? ` (${requiredType})` : ''}
             </label>
             <select
               required
               className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
               value={form.credentialsRef}
               onChange={(e) => setForm({ ...form, credentialsRef: e.target.value })}
             >
               <option value="" disabled>
                 Select a saved secret
               </option>
               {compatibleSecrets.map((secret) => (
                 <option key={secret.id} value={secret.id}>
                   {secret.label || secret.id} [{secret.type}]
                 </option>
               ))}
             </select>
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
