import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Pencil, Trash2, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { api, User } from '../api/client';
import { can } from '../auth/permissions';

export default function Users() {
  const queryClient = useQueryClient();
  const canWrite = can('users:write');

  const [editingId, setEditingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  // Draft state for the user being edited.
  const [draftRoles, setDraftRoles] = useState<string[]>([]);
  const [draftPermissions, setDraftPermissions] = useState<string[]>([]);

  const usersQuery = useQuery({ queryKey: ['users'], queryFn: api.users });
  const catalogQuery = useQuery({ queryKey: ['permissions-catalog'], queryFn: api.permissionCatalog });

  const updateUser = useMutation({
    mutationFn: (body: { roles?: string[]; permissions?: string[] }) => api.updateUser(editingId!, body),
    onSuccess: () => resetForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteUser = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetForm() {
    queryClient.invalidateQueries({ queryKey: ['users'] });
    setEditingId(null);
    setDraftRoles([]);
    setDraftPermissions([]);
    setFormError(null);
  }

  function openEdit(row: User) {
    setDraftRoles([...row.roles]);
    setDraftPermissions([...row.permissions]);
    setEditingId(row.id);
    setFormError(null);
  }

  function handleSubmit() {
    updateUser.mutate({ roles: draftRoles, permissions: draftPermissions });
  }

  function handleDelete(row: User) {
    if (!window.confirm(`Delete user "${row.username}"? This cannot be undone.`)) return;
    deleteUser.mutate(row.id);
  }

  const catalog = catalogQuery.data;
  const editingUser = usersQuery.data?.find((u) => u.id === editingId) ?? null;

  function toggleRole(role: string) {
    setDraftRoles((prev) => (prev.includes(role) ? prev.filter((r) => r !== role) : [...prev, role]));
  }

  function togglePermission(perm: string) {
    setDraftPermissions((prev) => (prev.includes(perm) ? prev.filter((p) => p !== perm) : [...prev, perm]));
  }

  const columns: DataTableColumn<User>[] = [
    { header: 'Username', key: 'username' },
    {
      header: 'Roles',
      key: 'roles',
      render: (row) =>
        row.roles.length > 0 ? (
          <div className="flex flex-wrap gap-1">
            {row.roles.map((r) => (
              <span key={r} className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${r === 'admin' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'}`}>
                {r}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-slate-400">—</span>
        ),
    },
    { header: 'Permissions', key: 'permissions', render: (row) => `${row.permissions.length} granted` },
    ...(canWrite
      ? [
          {
            header: 'Actions',
            key: 'actions',
            width: 110,
            sortable: false as const,
            render: (row: User) => (
              <div className="flex gap-1">
                <button
                  type="button"
                  aria-label={`Edit ${row.username}`}
                  title="Edit roles & permissions"
                  className="rounded-md p-1.5 text-slate-600 hover:bg-slate-100 hover:text-slate-900"
                  onClick={() => openEdit(row)}
                >
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  type="button"
                  aria-label={`Delete ${row.username}`}
                  title="Delete user"
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
      <div className="mb-4">
        <h1 className="text-xl font-bold text-slate-900">Users</h1>
        <p className="mt-1 text-sm text-slate-500">Manage user roles and permissions.</p>
      </div>

      {formError && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
      )}

      {/* Inline edit panel */}
      {editingUser && canWrite && (
        <div className="mb-4 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-slate-900">Edit — {editingUser.username}</h2>
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
              {/* Roles */}
              <fieldset>
                <legend className="mb-2 text-sm font-medium text-slate-700">Roles</legend>
                {catalog.roles.map((role) => (
                  <label key={role} className="flex items-center gap-2 py-1 text-sm text-slate-700">
                    <input type="checkbox" checked={draftRoles.includes(role)} onChange={() => toggleRole(role)} />
                    {role}
                  </label>
                ))}
              </fieldset>

              {/* Permissions */}
              <fieldset>
                <legend className="mb-2 text-sm font-medium text-slate-700">Permissions</legend>
                <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
                  {catalog.permissions.map((p) => (
                    <label key={p.id} title={p.description} className="flex items-start gap-2 py-1 text-sm text-slate-700">
                      <input type="checkbox" className="mt-0.5" checked={draftPermissions.includes(p.id)} onChange={() => togglePermission(p.id)} />
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
                  disabled={updateUser.isPending}
                  className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
                >
                  Save changes
                </button>
                <button type="button" onClick={resetForm} className="rounded-md px-4 py-2 text-sm font-medium text-slate-600 hover:bg-slate-100">
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {usersQuery.isLoading && <p className="text-sm text-slate-500">Loading users...</p>}
      {usersQuery.isError && (
        <p className="text-sm text-red-600">Failed to load users: {(usersQuery.error as Error).message}</p>
      )}
      {usersQuery.data && (
        <DataTable columns={columns} rows={usersQuery.data} rowKey={(row) => row.id} storageKey="users" emptyMessage="No users." />
      )}
    </Layout>
  );
}
