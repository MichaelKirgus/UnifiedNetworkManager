import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Pencil, Plus, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Site, SiteCreateRequest } from '../api/client';
import { can } from '../auth/permissions';
import { COUNTRIES, countryName } from '../utils/countries';

// Latitude/longitude are kept as strings in form state (number inputs) and
// parsed on submit; empty string = not set.
const emptySite = { name: '', description: '', address: '', country: '', timezone: '', latitude: '', longitude: '' };

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
    // GPS location is all-or-nothing — reject a single coordinate client-side.
    if (Boolean(site.latitude.trim()) !== Boolean(site.longitude.trim())) {
      setFormError('Provide both latitude and longitude, or neither.');
      return;
    }

    const body: SiteCreateRequest = {
      name: site.name.trim(),
      description: site.description.trim() || undefined,
      address: site.address.trim() || undefined,
      country: site.country || undefined,
      timezone: site.timezone || undefined,
    };
    // GPS location is all-or-nothing (the API rejects a single coordinate).
    const lat = site.latitude.trim();
    const lng = site.longitude.trim();
    if (lat && lng) {
      body.latitude = Number(lat);
      body.longitude = Number(lng);
    } else if (editingId && rowHasLocation()) {
      // Location was cleared in the form → send explicit nulls to remove it.
      body.latitude = null;
      body.longitude = null;
    }
    if (editingId) updateSite.mutate(body);
    else createSite.mutate(body);
  }

  function rowHasLocation(): boolean {
    const row = sitesQuery.data?.find((s) => s.id === editingId);
    return Boolean(row && (row.latitude != null || row.longitude != null));
  }

  function openEdit(row: Site) {
    setSite({
      name: row.name,
      description: row.description ?? '',
      address: row.address ?? '',
      country: row.country ?? '',
      timezone: row.timezone ?? '',
      latitude: row.latitude != null ? String(row.latitude) : '',
      longitude: row.longitude != null ? String(row.longitude) : '',
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
    { header: 'Description', key: 'description', render: (row) => row.description || <span className="text-faint">—</span> },
    { header: 'Address', key: 'address', render: (row) => row.address || <span className="text-faint">—</span> },
    {
      header: 'Country',
      key: 'country',
      render: (row) => (row.country ? countryName(row.country) : <span className="text-faint">—</span>),
    },
    { header: 'Timezone', key: 'timezone', render: (row) => row.timezone ?? <span className="text-faint">—</span> },
    {
      header: 'GPS',
      key: 'gps',
      sortable: false as const,
      render: (row) =>
        row.latitude != null && row.longitude != null ? (
          <span className="font-mono text-xs text-muted-foreground">
            {row.latitude.toFixed(4)}, {row.longitude.toFixed(4)}
          </span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 110,
            sortable: false as const,
            excludeFromExport: true,
            render: (row: Site) => (
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={`Edit ${row.name}`}
                  title="Edit site"
                  className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                  onClick={() => openEdit(row)}
                >
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  aria-label={`Delete ${row.name}`}
                  title="Delete site"
                  className="rounded-md p-1.5 text-secondary hover:bg-danger hover:text-danger-fg"
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
    <Layout
      title="Sites"
      actions={
        canWrite && !showForm && (
          <button
            type="button"
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            <Plus className="h-4 w-4" /> New site
          </button>
        )
      }
    >

      {formError && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
      )}

      {/* Inline create/edit panel */}
      {showForm && canWrite && (
        <div className="mb-4 rounded-md border border-border bg-card p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground">{editingId ? 'Edit site' : 'New site'}</h2>
            <button type="button" aria-label="Close form" onClick={resetForm} className="rounded p-1 text-faint hover:bg-muted">
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
              <label className="mb-1 block text-sm font-medium text-secondary">Name *</label>
              <input
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
                value={site.name}
                onChange={(e) => setSite({ ...site, name: e.target.value })}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Country</label>
              <select
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
                value={site.country}
                onChange={(e) => setSite({ ...site, country: e.target.value })}
              >
                <option value="">— none —</option>
                {COUNTRIES.map((c) => (
                  <option key={c.code} value={c.code}>
                    {c.name} ({c.code})
                  </option>
                ))}
              </select>
            </div>
            <div className="sm:col-span-2">
              <label className="mb-1 block text-sm font-medium text-secondary">Address</label>
              <input
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
                value={site.address}
                onChange={(e) => setSite({ ...site, address: e.target.value })}
              />
            </div>
            <div className="sm:col-span-2">
              <label className="mb-1 block text-sm font-medium text-secondary">Description</label>
              <textarea
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
                rows={2}
                value={site.description}
                onChange={(e) => setSite({ ...site, description: e.target.value })}
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Timezone</label>
              <select
                className="w-full rounded-md border border-border px-3 py-2 text-sm"
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

            {/* GPS location (all-or-nothing; stored for a future map view). */}
            <fieldset className="rounded-md border border-border p-3 sm:col-span-2">
              <legend className="px-1 text-sm font-medium text-secondary">GPS location</legend>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Latitude (−90…90)</label>
                  <input
                    type="number"
                    step="0.000001"
                    min={-90}
                    max={90}
                    className="w-full rounded-md border border-border px-3 py-2 text-sm"
                    value={site.latitude}
                    onChange={(e) => setSite({ ...site, latitude: e.target.value })}
                    placeholder="51.165691"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">Longitude (−180…180)</label>
                  <input
                    type="number"
                    step="0.000001"
                    min={-180}
                    max={180}
                    className="w-full rounded-md border border-border px-3 py-2 text-sm"
                    value={site.longitude}
                    onChange={(e) => setSite({ ...site, longitude: e.target.value })}
                    placeholder="10.451526"
                  />
                </div>
              </div>
            </fieldset>

            <div className="flex items-center gap-2 sm:col-span-2">
              <button
                type="submit"
                disabled={createSite.isPending || updateSite.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                {editingId ? 'Save changes' : 'Create site'}
              </button>
              <button type="button" onClick={resetForm} className="rounded-md px-4 py-2 text-sm font-medium text-secondary hover:bg-muted">
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {sitesQuery.isLoading && <p className="text-sm text-muted-foreground">Loading sites...</p>}
      {sitesQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load sites: {(sitesQuery.error as Error).message}</p>
      )}
      {sitesQuery.data && (
        <DataTable
          columns={columns}
          rows={sitesQuery.data}
          rowKey={(row) => row.id}
          storageKey="sites"
          emptyMessage="No sites yet."
          selectable={canWrite}
          bulkActions={
            canWrite
              ? [
                  {
                    label: 'Delete selected',
                    confirm: (count) => `Delete ${count} site${count === 1 ? '' : 's'}? Devices referencing them must be unassigned first.`,
                    onClick: async (selected: Site[]) => {
                      const errors: string[] = [];
                      for (const s of selected) {
                        try {
                          await api.deleteSite(s.id);
                        } catch (err) {
                          errors.push(`${s.name}: ${(err as Error).message}`);
                        }
                      }
                      queryClient.invalidateQueries({ queryKey: ['sites'] });
                      if (errors.length > 0) setFormError(`Deleted ${selected.length - errors.length} of ${selected.length}. ${errors.join(' | ')}`);
                    },
                  },
                ]
              : undefined
          }
        />
      )}
    </Layout>
  );
}
