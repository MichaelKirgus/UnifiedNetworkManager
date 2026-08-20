import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { Eye, Pencil, Plus, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCell } from '../components/MetricCell';
import { PluginAssignmentBuilder } from '../components/PluginAssignmentBuilder';
import { api, Device, DeviceCreateRequest, DevicePluginAssignmentInput, DevicePluginAssignment, Plugin } from '../api/client';
import { OptionForm } from '../components/OptionForm';
import { isValidAddress, addressError } from '../utils/address';

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

  // When non-null the form is in EDIT mode for that device.
  const [editingId, setEditingId] = useState<string | null>(null);
  // Original secondary IPs (with row ids) captured when entering edit mode,
  // used to diff on save (add new / remove deleted).
  const [originalSecondaryIps, setOriginalSecondaryIps] = useState<{ id: string; address: string }[]>([]);

  // Device identity fields (shared between create and edit modes).
  const emptyIdentity = { name: '', vendor: '', deviceType: 'firewall', managementAddress: '', site: '' };
  const [identity, setIdentity] = useState(emptyIdentity);

  // Secondary IPs (creation list or existing secondaries in edit mode).
  const [additionalIps, setAdditionalIps] = useState<string[]>([]);
  const [newIpInput, setNewIpInput] = useState('');
  const [ipError, setIpError] = useState<string | null>(null);

  // Existing plugin assignments captured when entering edit mode.
  const [initialAssignments, setInitialAssignments] = useState<DevicePluginAssignment[]>([]);

  const devicesQuery = useQuery({ queryKey: ['devices'], queryFn: api.devices });
  const pluginsQuery = useQuery({ queryKey: ['plugins'], queryFn: api.plugins });
  const secretsQuery = useQuery({ queryKey: ['secrets'], queryFn: api.secrets });

  const createDevice = useMutation({
    mutationFn: (body: DeviceCreateRequest) => api.createDevice(body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const updateDevice = useMutation({
    mutationFn: async (assignments?: DevicePluginAssignmentInput[]) => {
      // PATCH identity fields.
      await api.updateDevice(editingId!, {
        name: identity.name.trim(),
        vendor: identity.vendor,
        deviceType: identity.deviceType.trim() || 'firewall',
        managementAddress: identity.managementAddress.trim(),
        site: identity.site.trim() || null,
      });
      // Diff secondary IPs: add new, remove deleted.
      const toAdd = additionalIps.filter((ip) => !originalSecondaryIps.some((o) => o.address === ip));
      const toRemove = originalSecondaryIps.filter((o) => !additionalIps.includes(o.address));
      for (const ip of toAdd) await api.addDeviceIp(editingId!, ip);
      for (const row of toRemove) await api.removeDeviceIp(editingId!, row.id);

      // Diff plugin assignments: add new, remove deleted, update changed.
      if (assignments) {
        const desiredIds = new Set(assignments.map((a) => a.pluginId));
        const removed = initialAssignments.filter((a) => !desiredIds.has(a.pluginId));
        for (const r of removed) await api.removeDevicePlugin(editingId!, r.pluginId);

        // Add plugins that weren't assigned before.
        const existingById = new Map(initialAssignments.map((a) => [a.pluginId, a]));
        for (const a of assignments) {
          const prev = existingById.get(a.pluginId);
          if (!prev) {
            await api.addDevicePlugin(editingId!, a);
          } else {
            // Already assigned — persist credential / primary changes.
            const secretChanged = (a.secretId ?? null) !== (prev.secretId ?? null);
            const primaryChanged = a.isPrimary !== prev.isPrimary;
            if (secretChanged || primaryChanged) {
              await api.updateDevicePlugin(editingId!, a.pluginId, {
                ...(secretChanged ? { secretId: a.secretId ?? null } : {}),
                ...(primaryChanged ? { isPrimary: a.isPrimary } : {}),
              });
            }
          }
        }
      }
    },
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetForm() {
    queryClient.invalidateQueries({ queryKey: ['devices'] });
    setShowForm(false);
    setEditingId(null);
    setIdentity(emptyIdentity);
    setAdditionalIps([]);
    setOriginalSecondaryIps([]);
    setInitialAssignments([]);
    setNewIpInput('');
    setIpError(null);
    setFormError(null);
  }

  function handleSubmit(assignments: DevicePluginAssignmentInput[]) {
    if (editingId) {
      updateDevice.mutate(assignments);
    } else {
      createDevice.mutate({ ...identity, ips: additionalIps.length > 0 ? additionalIps : undefined, plugins: assignments });
    }
  }

  /** Adds a secondary IP to the creation list (validated inline). */
  function addSecondaryIp() {
    const v = newIpInput.trim();
    if (!v) return;
    if (!isValidAddress(v)) { setIpError(addressError(v)); return; }
    if (additionalIps.some((ip) => ip.toLowerCase() === v.toLowerCase())) {
      setIpError('This address is already in the list.');
      return;
    }
    setAdditionalIps([...additionalIps, v]);
    setNewIpInput('');
    setIpError(null);
  }

  /** Prefills the inline form with a device's values and switches to edit mode. */
  function openEdit(device: Device) {
    setIdentity({
      name: device.name,
      vendor: device.vendor,
      deviceType: device.deviceType,
      managementAddress: device.managementAddress,
      site: device.site ?? '',
    });
    const secondaries = (device.ips ?? []).filter((ip) => !ip.isPrimary);
    setAdditionalIps(secondaries.map((s) => s.address));
    setOriginalSecondaryIps(
      secondaries.filter((s): s is typeof s & { id: string } => s.id != null).map((s) => ({ id: s.id as string, address: s.address }))
    );
    setInitialAssignments(device.plugins ?? []);
    setNewIpInput('');
    setIpError(null);
    setFormError(null);
    setEditingId(device.id);
    setShowForm(true);
  }

  const columns: DataTableColumn<Device>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Vendor', key: 'vendor' },
    { header: 'Type', key: 'deviceType' },
    { header: 'Site', key: 'site', render: (row) => row.site ?? '—' },
    {
      header: 'IP',
      key: 'managementAddress',
      width: 160,
      sortable: true,
      sortAccessor: (row) => row.managementAddress,
      render: (row) => {
        const secondaryCount = (row.ips ?? []).filter((ip) => !ip.isPrimary).length;
        return (
          <span className="font-mono text-xs">
            {row.managementAddress}
            {secondaryCount > 0 && (
              <span className="ml-1 rounded-full bg-slate-100 px-1.5 py-0.5 text-[10px] font-medium text-slate-600">+{secondaryCount}</span>
            )}
          </span>
        );
      },
    },
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
            title="Edit device"
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
          onClick={() => { setShowForm((v) => !v); if (showForm) resetForm(); }}
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? 'Cancel' : editingId ? 'Edit Device' : 'Register Device'}
        </button>
      </div>

      {showForm && (
        <div
          className="mb-6 grid grid-cols-1 gap-3 rounded-md border border-slate-200 bg-white p-4 shadow-sm sm:grid-cols-2"
        >
          <h2 className="col-span-full text-sm font-semibold uppercase tracking-wide text-slate-500">
            {editingId ? `Edit device` : 'Register device'}
          </h2>
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Primary IP / Address</label>
            <input
              required
              className={`w-full rounded-md border px-3 py-2 text-sm ${
                identity.managementAddress.trim() && !isValidAddress(identity.managementAddress)
                  ? 'border-red-400'
                  : 'border-slate-300'
              }`}
              value={identity.managementAddress}
              onChange={(e) => setIdentity({ ...identity, managementAddress: e.target.value })}
              placeholder="10.0.0.1 or gw.local"
            />
            {identity.managementAddress.trim() && !isValidAddress(identity.managementAddress) && (
              <p className="mt-1 text-xs text-red-600">{addressError(identity.managementAddress)}</p>
            )}
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
            <label className="mb-1 block text-sm font-medium text-slate-700">Additional IPs (optional)</label>
            <div className="flex gap-2">
              <input
                className={`w-full rounded-md border px-3 py-2 text-sm ${ipError ? 'border-red-400' : 'border-slate-300'}`}
                value={newIpInput}
                onChange={(e) => { setNewIpInput(e.target.value); setIpError(null); }}
                onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); addSecondaryIp(); } }}
                placeholder="10.0.0.2 or 2001:db8::1"
              />
              <button
                type="button"
                onClick={addSecondaryIp}
                className="rounded-md border border-slate-300 px-3 py-2 text-sm font-medium text-slate-600 hover:bg-slate-50"
              >
                Add
              </button>
            </div>
            {ipError && <p className="mt-1 text-xs text-red-600">{ipError}</p>}
            {additionalIps.length > 0 && (
              <div className="mt-2 flex flex-wrap gap-1">
                {additionalIps.map((ip) => (
                  <span key={ip} className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-700">
                    {ip}
                    <button
                      type="button"
                      aria-label={`Remove ${ip}`}
                      onClick={() => setAdditionalIps(additionalIps.filter((x) => x !== ip))}
                      className="text-slate-400 hover:text-red-600"
                    >
                      <X className="h-3 w-3" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="col-span-full">
            <label className="mb-1 block text-sm font-medium text-slate-700">
              Plugins (each with its own credentials — the first becomes primary)
            </label>
            <PluginAssignmentBuilder
              plugins={pluginsQuery.data ?? []}
              secrets={secretsQuery.data ?? []}
              initial={editingId ? initialAssignments.map((a) => ({ pluginId: a.pluginId, secretId: a.secretId ?? null, isPrimary: a.isPrimary })) : undefined}
              onSubmit={(assignments) => {
                if (!identity.name.trim() || !identity.vendor || !identity.managementAddress.trim()) {
                  setFormError('Please fill in name, vendor and primary IP before saving.');
                  return;
                }
                if (!isValidAddress(identity.managementAddress)) {
                  setFormError(`Primary IP: ${addressError(identity.managementAddress)}`);
                  return;
                }
                handleSubmit(assignments);
              }}
              submitLabel={editingId ? 'Save Changes' : 'Create Device'}
              busy={createDevice.isPending || updateDevice.isPending}
            />
          </div>

          {/* Per-plugin parameters — editable in edit mode only */}
          {editingId && initialAssignments.length > 0 && (
            <div className="col-span-full space-y-4">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-slate-400">Plugin settings (per-device overrides)</h3>
              {initialAssignments.map((a) => (
                <div key={a.pluginId} className="rounded-md border border-slate-200 bg-white p-3">
                  <p className="mb-2 text-sm font-medium text-slate-700">{a.pluginName ?? a.pluginId}</p>
                  <OptionForm pluginId={a.pluginId} deviceId={editingId!} onSaved={() => queryClient.invalidateQueries({ queryKey: ['devices'] })} />
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {devicesQuery.isLoading && <p className="text-sm text-slate-500">Loading devices...</p>}
      {devicesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load devices: {(devicesQuery.error as Error).message}</p>
      )}
      {devicesQuery.data && (
        <DataTable columns={columns} rows={devicesQuery.data} rowKey={(row) => row.id} storageKey="devices" emptyMessage="No devices registered yet." />
      )}

    </Layout>
  );
}
