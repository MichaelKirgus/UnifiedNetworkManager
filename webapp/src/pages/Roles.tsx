import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Pencil, Plus, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, Role } from '../api/client';
import { can } from '../auth/permissions';

const emptyRole = { name: '', description: '' };

export default function Roles() {
  const queryClient = useQueryClient();
  const canWrite = can('users:write');

  const [showForm, setShowForm] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [editingName, setEditingName] = useState<string | null>(null);
  const [role, setRole] = useState(emptyRole);
  const [draftPermissions, setDraftPermissions] = useState<string[]>([]);

  const rolesQuery = useQuery({ queryKey: ['roles'], queryFn: api.roles });
  const catalogQuery = useQuery({ queryKey: ['permissions-catalog'], queryFn: api.permissionCatalog });

  const createRole = useMutation({
    mutationFn: (body: { name: string; description?: string; permissions: string[] }) => api.createRole(body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const updateRole = useMutation({
    mutationFn: (body: { description?: string | null; permissions?: string[] }) => api.updateRole(editingName!, body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteRole = useMutation({
    mutationFn: (name: string) => api.deleteRole(name),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['roles'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetForm() {
    queryClient.invalidateQueries({ queryKey: ['roles'] });
    setShowForm(false);
    setEditingName(null);
    setRole(emptyRole);
    setDraftPermissions([]);
    setFormError(null);
  }

  function openEdit(row: Role) {
    setRole({ name: row.name, description: row.description ?? '' });
    setDraftPermissions([...row.permissions]);
    setEditingName(row.name);
    setShowForm(true);
    setFormError(null);
  }

  function handleSubmit() {
    if (editingName) {
      updateRole.mutate({ description: role.description.trim() || null, permissions: draftPermissions });
    } else {
      createRole.mutate({ name: role.name.trim(), description: role.description.trim() || undefined, permissions: draftPermissions });
    }
  }

  function handleDelete(row: Role) {
    if (!window.confirm(`Delete role "${row.name}"? Users carrying it must be updated first.`)) return;
    deleteRole.mutate(row.name);
  }

  const catalog = catalogQuery.data;

  const columns: DataTableColumn<Role>[] = [
    { header: 'Name', key: 'name' },
    { header: 'Description', key: 'description', render: (row) => row.description || <span className="text-slate-400">—</span> },
    {
      header: 'Permissions',
      key: 'permissions',
      render: (row) =>
        row.permissions.length > 0 ? (
          <div className="flex max-w-md flex-wrap gap-1">
            {row.permissions.map((p) => (
              <span key={p} className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                {p}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 110,
            sortable: false as const,
            render: (row: Role) => (
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={`Edit ${row.name}`}
                  title="Edit role"
                  className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  onClick={() => openEdit(row)}
                >
                  <Pencil className="h-4 w-4" />
                </button>
                {/* The built-in admin role can never be deleted (server 409s it too). */}
                {row.name !== 'admin' && (
                  <button
                    type="button"
                    aria-label={`Delete ${row.name}`}
                    title="Delete role"
                    className="rounded-md p-1.5 text-slate-600 hover:bg-red-50 hover:text-red-700"
                    onClick={() => handleDelete(row)}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                )}
              </div>
            ),
          },
        ]
      : []),
  ];

  return (
    <Layout>
      <div className="mb-4 flex items-center justify-between">
        <h1 className="text-xl font-bold text-slate-900">Roles</h1>
        {canWrite && !showForm && (
          <button
            type="button"
            onClick={() => setShowForm(true)}
            className="inline-flex items-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-medium text-white hover:bg-slate-700"
          >
            <Plus className="h-4 w-4" /> New role
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
            <h2 className="text-base font-semibold text-slate-900">{editingName ? `Edit role — ${editingName}` : 'New role'}</h2>
            <button type="button" aria-label="Close form" onClick={resetForm} className="rounded p-1 text-slate-400 hover:bg-slate-100">
              <X className="h-4 w-4" />
            </button>
          </div>

          {catalog && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleSubmit();
              }}
              className="grid grid-cols-1 gap-4 sm:grid-cols-2"
            >
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Name *</label>
                <input
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={role.name}
                  onChange={(e) => setRole({ ...role, name: e.target.value })}
                  disabled={Boolean(editingName)}
                  required
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Description</label>
                <input
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={role.description}
                  onChange={(e) => setRole({ ...role, description: e.target.value })}
                />
              </div>

              <fieldset className="sm:col-span-2">
                <legend className="mb-2 text-sm font-medium text-slate-700">Permissions</legend>
                <p className="mb-2 text-xs text-slate-400">
                  Users with this role get these permissions in addition to their explicit grants (applied at next login).
                </p>
                <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
                  {catalog.permissions.map((p) => (
                    <label key={p.id} title={p.description} className="flex items-start gap-2 py-1 text-sm text-slate-700">
                      <input
                        type="checkbox"
                        className="mt-0.5"
                        checked={draftPermissions.includes(p.id)}
                        onChange={() =>
                          setDraftPermissions((prev) => (prev.includes(p.id) ? prev.filter((x) => x !== p.id) : [...prev, p.id]))
                        }
                      />
                      <span>
                        {p.id}
                        <span className="block text-xs font-normal text-slate-400">{p.description}</span>
                      </span>
                    </label>
                  ))}
                </div>
              </fieldset>

              <div className="flex items-center gap-2 sm:col-span-2">
                <button
                  type="submit"
                  disabled={createRole.isPending || updateRole.isPending}
                  className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
                >
                  {editingName ? 'Save changes' : 'Create role'}
                </button>
                <button type="button" onClick={resetForm} className="rounded-md px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100">
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {rolesQuery.isLoading && <p className="text-sm text-slate-500">Loading roles...</p>}
      {rolesQuery.isError && (
        <p className="text-sm text-red-600">Failed to load roles: {(rolesQuery.error as Error).message}</p>
      )}
      {rolesQuery.data && (
        <DataTable columns={columns} rows={rolesQuery.data} rowKey={(row) => row.name} storageKey="roles" emptyMessage="No roles yet." />
      )}
    </Layout>
  );
}
