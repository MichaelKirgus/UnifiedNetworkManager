import { FormEvent, useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Eye, Pencil, Plus, Save, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCell } from '../components/MetricCell';
import { PluginAssignmentBuilder } from '../components/PluginAssignmentBuilder';
import { api, Device, DeviceCreateRequest, DevicePluginAssignmentInput, Plugin } from '../api/client';

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
  const [formError, setFormError] = useState<string | null>(null);

  // Edit (rename / change address) of an existing device.
  const [editDevice, setEditDevice] = useState<Device | null>(null);
  const [editForm, setEditForm] = useState({ name: '', vendor: '', deviceType: '', managementAddress: '', site: '' });
  const [editError, setEditError] = useState<string | null>(null);

  // Device identity fields (plugins are managed by the assignment builder).
  const emptyIdentity = { name: '', vendor: '', deviceType: 'firewall', managementAddress: '', site: '' };
  const [identity, setIdentity] = useState(emptyIdentity);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets });

  const createDevice = useMutation({
    mutationFn: (body: DeviceCreateRequest) => api.createDevice(body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setShowForm(false);
      setIdentity(emptyIdentity);
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function handleSubmit(assignments: DevicePluginAssignmentInput[]) {
    createDevice.mutate({ ...identity, plugins: assignments });
  }

  const updateDevice = useMutation({
    mutationFn: (body: Record<string, unknown>) => api.updateDevice(editDevice!.id, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['devices'] });
      setEditDevice(null);
      setEditError(null);
    },
    onError: (err: unknown) => setEditError((err as Error).message),
  });

  function openEdit(device: Device) {
    setEditForm({
      name: device.name,
      vendor: device.vendor,
      deviceType: device.deviceType,
      managementAddress: device.managementAddress,
      site: device.site ?? '',
    });
    setEditError(null);
    setEditDevice(device);
  }

  function handleEditSubmit(e: FormEvent) {
    e.preventDefault();
    if (!editForm.name.trim() || !editForm.vendor || !editForm.managementAddress.trim()) {
      setEditError('Name, vendor and management address are required.');
      return;
    }
    updateDevice.mutate({
      name: editForm.name.trim(),
      vendor: editForm.vendor,
      deviceType: editForm.deviceType.trim() || 'firewall',
      managementAddress: editForm.managementAddress.trim(),
      site: editForm.site.trim() || null,
    });
  }

  const columns: DataTableColumn<Device>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Vendor', key: 'vendor' },
    { header: 'Type', key: 'deviceType' },
    { header: 'Site', key: 'site', render: (row) => row.site ?? '—' },
    {
      header: 'Plugins',
      key: 'plugins',
      width: 200,
      sortable: false,
      render: (row) => {
        const plugins = row.plugins ?? [];
        if (plugins.length === 0) return <span className="text-slate-400">—</span>;
        return (
          <div className="flex flex-wrap gap-1">
            {plugins.map((p) => (
              <span
                key={p.id}
                title={`${p.pluginName ?? p.pluginId}${p.isPrimary ? ' (primary)' : ''}`}
                className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                  p.isPrimary ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'
                }`}
              >
                {p.pluginName ?? p.pluginId}
              </span>
            ))}
          </div>
        );
      },
    },
    { header: 'Status', key: 'status', render: (row) => <StatusBadge status={row.status} /> },
    {
      header: 'Metrics',
      key: 'metrics',
      width: 320,
      sortable: false,
      render: (row) => {
        const metrics = row.summaryMetrics ?? [];
        if (metrics.length === 0) return <span className="text-slate-400">—</span>;
        return (
          <div className="flex flex-wrap items-center gap-x-5 gap-y-2">
            {metrics.map((m, i) => (
              <MetricCell key={`${m.key}-${i}`} metric={m} />
            ))}
          </div>
        );
      },
    },
    {
      header: 'Actions',
      key: 'actions',
      width: 120,
      sortable: false,
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`View ${row.name}`}
            title="View details"
            className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
            onClick={() => navigate(`/devices/${row.id}`)}
          >
            <Eye className="h-4 w-4" />
          </button>
          <button
            aria-label={`Edit ${row.name}`}
            title="Rename / change address"
            className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
            onClick={() => openEdit(row)}
          >
            <Pencil className="h-4 w-4" />
          </button>
        </div>
      ),
    },
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Devices</h1>
        <button
          className="flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-semibold text-white hover:bg-slate-800"
          onClick={() => setShowForm((v) => !v)}
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? 'Cancel' : 'Register Device'}
        </button>
      </div>

      {showForm && (
        <div
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
              value={identity.name}
              onChange={(e) => setIdentity({ ...identity, name: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Vendor</label>
            <select
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={identity.vendor}
              onChange={(e) => setIdentity({ ...identity, vendor: e.target.value })}
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
              value={identity.deviceType}
              onChange={(e) => setIdentity({ ...identity, deviceType: e.target.value })}
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Management Address</label>
            <input
              required
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={identity.managementAddress}
              onChange={(e) => setIdentity({ ...identity, managementAddress: e.target.value })}
              placeholder="https://10.0.0.1"
            />
          </div>
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-700">Site</label>
            <input
              className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
              value={identity.site}
              onChange={(e) => setIdentity({ ...identity, site: e.target.value })}
            />
          </div>

          <div className="col-span-full">
            <label className="mb-1 block text-sm font-medium text-slate-700">
              Plugins (each with its own credentials — the first becomes primary)
            </label>
            <PluginAssignmentBuilder
              plugins={pluginsQuery.data ?? []}
              secrets={secretsQuery.data ?? []}
              onSubmit={(assignments) => {
                if (!identity.name.trim() || !identity.vendor || !identity.managementAddress.trim()) {
                  setFormError('Please fill in name, vendor and management address before saving.');
                  return;
                }
                handleSubmit(assignments);
              }}
              submitLabel="Save Device"
              busy={createDevice.isPending}
            />
          </div>
        </div>
      )}

      {devicesQuery.isLoading && <p className="text-sm text-slate-500">Loading devices...</p>}
      {devicesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load devices: {(devicesQuery.error as Error).message}</p>
      )}
      {devicesQuery.data && (
        <DataTable columns={columns} rows={devicesQuery.data} rowKey={(row) => row.id} storageKey="devices" emptyMessage="No devices registered yet." />
      )}

      {/* --- Edit device modal --------------------------------------------- */}
      {editDevice && (
        <div
          className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-slate-900/40 p-6"
          onClick={() => setEditDevice(null)}
        >
          <form
            onSubmit={handleEditSubmit}
            className="mt-10 w-full max-w-md rounded-md border border-slate-200 bg-white shadow-xl"
            onClick={(e) => e.stopPropagation()}
          >
            <header className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
              <h3 className="text-sm font-semibold text-slate-800">Edit {editDevice.name}</h3>
              <button type="button" aria-label="Close" onClick={() => setEditDevice(null)} className="rounded-md p-1 text-slate-400 hover:bg-slate-100">
                <X className="h-4 w-4" />
              </button>
            </header>
            <div className="space-y-3 p-4">
              {editError && (
                <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{editError}</div>
              )}
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Name</label>
                <input
                  required
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  value={editForm.name}
                  onChange={(e) => setEditForm({ ...editForm, name: e.target.value })}
                />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-sm font-medium text-slate-700">Vendor</label>
                  <input
                    required
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    value={editForm.vendor}
                    onChange={(e) => setEditForm({ ...editForm, vendor: e.target.value })}
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm font-medium text-slate-700">Device Type</label>
                  <input
                    required
                    className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                    value={editForm.deviceType}
                    onChange={(e) => setEditForm({ ...editForm, deviceType: e.target.value })}
                  />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Management Address</label>
                <input
                  required
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  value={editForm.managementAddress}
                  onChange={(e) => setEditForm({ ...editForm, managementAddress: e.target.value })}
                  placeholder="https://10.0.0.1"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Site</label>
                <input
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                  value={editForm.site}
                  onChange={(e) => setEditForm({ ...editForm, site: e.target.value })}
                />
              </div>
            </div>
            <footer className="flex items-center justify-end gap-2 border-t border-slate-200 px-4 py-3">
              <button
                type="button"
                onClick={() => setEditDevice(null)}
                className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={updateDevice.isPending}
                className="flex items-center gap-1.5 rounded-md bg-slate-900 px-4 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
              >
                <Save className="h-4 w-4" />
                {updateDevice.isPending ? 'Saving…' : 'Save Changes'}
              </button>
            </footer>
          </form>
        </div>
      )}
    </Layout>
  );
}
