import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Pencil, Plus, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Site, SiteCreateRequest } from '../api/client';
import { can } from '../auth/permissions';

const emptySite = { name: '', description: '', address: '', country: '', timezone: '' };

/** IANA timezones for the picker (Node 18+/modern browsers support this). */
function timezoneOptions(): string[] {
  try {
    const values = (Intl as unknown as { supportedValuesOf?: (k: string) => string[] }).supportedValuesOf?.('timeZone');
    if (Array.isArray(values) && values.length > 0) return values;
  } catch {
    /* fall through */
  }
  // Fallback list for older runtimes.
  return [
    'UTC',
    'Europe/Berlin',
    'Europe/London',
    'Europe/Paris',
    'America/New_York',
    'America/Chicago',
    'America/Denver',
    'America/Los_Angeles',
    'Asia/Tokyo',
    'Asia/Singapore',
    'Australia/Sydney',
  ];
}

export default function Sites() {
  const queryClient = useQueryClient();
  const canWrite = can('sites:write');

  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [site, setSite] = useState(emptySite);

  const sitesQuery = useQuery({ queryKey: ['sites'], queryFn: api.sites });

  const createSite = useMutation({
    mutationFn: (body: SiteCreateRequest) => api.createSite(body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const updateSite = useMutation({
    mutationFn: (body: Partial<SiteCreateRequest>) => api.updateSite(editingId!, body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteSite = useMutation({
    mutationFn: (id: string) => api.deleteSite(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['sites'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetForm() {
    queryClient.invalidateQueries({ queryKey: ['sites'] });
    setShowForm(false);
    setEditingId(null);
    setSite(emptySite);
    setFormError(null);
  }

  function handleSubmit() {
    const body = {
      name: site.name.trim(),
      description: site.description.trim() || undefined,
      address: site.address.trim() || undefined,
      country: site.country.trim() || undefined,
      timezone: site.timezone || undefined,
    };
    if (editingId) updateSite.mutate(body);
    else createSite.mutate(body);
  }

  function openEdit(row: Site) {
    setSite({
      name: row.name,
      description: row.description ?? '',
      address: row.address ?? '',
      country: row.country ?? '',
      timezone: row.timezone ?? '',
    });
    setEditingId(row.id);
    setShowForm(true);
    setFormError(null);
  }

  function handleDelete(row: Site) {
    if (!window.confirm(`Delete site "${row.name}"? Devices referencing it must be unassigned first.`)) return;
    deleteSite.mutate(row.id);
  }

  const columns: DataTableColumn<Site>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Description', key: 'description', render: (row) => row.description || <span className="text-slate-400">—</span> },
    { header: 'Address', key: 'address', render: (row) => row.address || <span className="text-slate-400">—</span> },
    { header: 'Country', key: 'country', render: (row) => row.country || <span className="text-slate-400">—</span> },
    { header: 'Timezone', key: 'timezone', render: (row) => row.timezone ?? <span className="text-slate-400">—</span> },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 110,
            sortable: false as const,
            render: (row: Site) => (
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={`Edit ${row.name}`}
                  title="Edit site"
                  className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  onClick={() => openEdit(row)}
                >
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  aria-label={`Delete ${row.name}`}
                  title="Delete site"
                  className="rounded-md p-1.5 text-slate-600 hover:bg-red-50 hover:text-red-700"
                  onClick={() => handleDelete(row)}
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Sites</h1>
        {canWrite && !showForm && (
          <button
            type="button"
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700"
          >
            <Plus className="h-4 w-4" /> New site
          </button>
        )}
      </div>

      {formError && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
      )}

      {/* Inline create/edit panel */}
      {showForm && canWrite && (
        <div className="mb-4 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-900">{editingId ? 'Edit site' : 'New site'}</h2>
            <button type="button" aria-label="Close form" onClick={resetForm} className="rounded p-1 text-slate-400 hover:bg-slate-100">
              <X className="h-4 w-4" />
            </button>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleSubmit();
            }}
            className="grid grid-cols-1 gap-3 sm:grid-cols-2"
          >
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">Name *</label>
              <input
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                value={site.name}
                onChange={(e) => setSite({ ...site, name: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">Country</label>
              <input
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                value={site.country}
                onChange={(e) => setSite({ ...site, country: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <label className="mb-1 block text-sm font-medium text-slate-700">Address</label>
              <input
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                value={site.address}
                onChange={(e) => setSite({ ...site, address: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <label className="mb-1 block text-sm font-medium text-slate-700">Description</label>
              <textarea
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                rows={2}
                value={site.description}
                onChange={(e) => setSite({ ...site, description: e.target.value })}
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-700">Timezone</label>
              <select
                className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm"
                value={site.timezone}
                onChange={(e) => setSite({ ...site, timezone: e.target.value })}
              >
                <option value="">— none —</option>
                {timezoneOptions().map((tz) => (
                  <option key={tz} value={tz}>
                    {tz}
                  </option>
                ))}
              </select>
            </div>

            <div className="flex items-center gap-2 sm:col-span-2">
              <button
                type="submit"
                disabled={createSite.isPending || updateSite.isPending}
                className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
              >
                {editingId ? 'Save changes' : 'Create site'}
              </button>
              <button type="button" onClick={resetForm} className="rounded-md px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100">
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {sitesQuery.isLoading && <p className="text-sm text-slate-500">Loading sites...</p>}
      {sitesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load sites: {(sitesQuery.error as Error).message}</p>
      )}
      {sitesQuery.data && (
        <DataTable columns={columns} rows={sitesQuery.data} rowKey={(row) => row.id} storageKey="sites" emptyMessage="No sites yet." />
      )}
    </Layout>
  );
}
