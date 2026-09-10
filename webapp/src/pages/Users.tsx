import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { Globe, KeyRound, Pencil, Plus, ShieldOff, Trash2, UserCheck, UserX, X } from 'lucide-react';
import { Layout } from '../components/Layout';
import { DataTable, DataTableColumn } from '../components/DataTable';
import { TotpEnrollmentDialog } from '../components/TotpEnrollmentDialog';
import { PasskeyManager } from '../components/PasskeyManager';
import { PolicyEditor } from '../components/PolicyEditor';
import { DeviceScopeEditor } from '../components/DeviceScopeEditor';
import { api, User, TotpEnrollment, CredentialPolicy, DeviceScope } from '../api/client';
import { can, getUsername } from '../auth/permissions';

/** Username of the initial seeded admin — protected from deletion/demotion. */
const INITIAL_ADMIN_USERNAME = 'admin';

interface EnrollmentState {
  username: string;
  enrollment: TotpEnrollment;
}

export default function Users() {
  const queryClient = useQueryClient();
  const canWrite = can('users:write');
  const canCreate = can('users:create');
  const selfUsername = getUsername();

  // --- Roles/permissions edit state -----------------------------------------
  const [editingId, setEditingId] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [draftRoles, setDraftRoles] = useState<string[]>([]);
  const [draftPermissions, setDraftPermissions] = useState<string[]>([]);
  const [draftScope, setDraftScope] = useState<DeviceScope>({});

  // --- User creation state ----------------------------------------------------
  const [showCreate, setShowCreate] = useState(false);
  const [createUsername, setCreateUsername] = useState('');
  const [createPassword, setCreatePassword] = useState('');
  const [createRoles, setCreateRoles] = useState<string[]>([]);
  const [createPermissions, setCreatePermissions] = useState<string[]>([]);
  const [createScope, setCreateScope] = useState<DeviceScope>({});
  const [enrollment, setEnrollment] = useState<EnrollmentState | null>(null);

  // --- Credential management state (password reset + 2FA) ---------------------
  const [credsId, setCredsId] = useState<string | null>(null);
  const [newPassword, setNewPassword] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');

  const usersQuery = useQuery({ queryKey: ['users'], queryFn: api.users });
  const catalogQuery = useQuery({ queryKey: ['permissions-catalog'], queryFn: api.permissionCatalog });

  const updateUser = useMutation({
    mutationFn: (body: { roles?: string[]; permissions?: string[]; deviceScope?: DeviceScope }) => api.updateUser(editingId!, body),
    onSuccess: () => resetEditForm(),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const deleteUser = useMutation({
    mutationFn: (id: string) => api.deleteUser(id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  // Enable/disable an account (requires users:write). Disabling rejects the user
  // at login and terminates their live sessions; re-enabling restores access.
  const toggleStatus = useMutation({
    mutationFn: ({ id, disabled }: { id: string; disabled: boolean }) => api.setUserStatus(id, disabled),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const createUser = useMutation({
    mutationFn: (body: { username: string; password: string; roles?: string[]; permissions?: string[]; deviceScope?: DeviceScope }) =>
      api.createUser(body),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      resetCreateForm();
      setEnrollment({ username: res.user.username, enrollment: res.enrollment });
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const resetPassword = useMutation({
    mutationFn: (body: { newPassword: string; currentPassword?: string }) => api.resetUserPassword(credsId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setNewPassword('');
      setCurrentPassword('');
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const enrollTotp = useMutation({
    mutationFn: () => api.enrollTotp(credsId!),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['users'] });
      setEnrollment({ username: res.user.username, enrollment: res.enrollment });
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const disableTotp = useMutation({
    mutationFn: () => api.disableTotp(credsId!),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['users'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  // Per-user credential policy override (requires auth:policies:write).
  const canEditPolicies = can('auth:policies:write');
  const userPolicyQuery = useQuery({
    queryKey: ['user-policy', credsId],
    queryFn: () => api.userCredentialPolicy(credsId!),
    enabled: Boolean(credsId) && canEditPolicies,
  });

  const saveUserPolicy = useMutation({
    mutationFn: (body: Partial<CredentialPolicy>) => api.setUserCredentialPolicy(credsId!, body),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-policy', credsId] });
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const clearUserPolicy = useMutation({
    mutationFn: () => api.clearUserCredentialPolicy(credsId!),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['user-policy', credsId] });
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  function resetEditForm() {
    queryClient.invalidateQueries({ queryKey: ['users'] });
    setEditingId(null);
    setDraftRoles([]);
    setDraftPermissions([]);
    setDraftScope({});
    setFormError(null);
  }

  function openEdit(row: User) {
    setDraftRoles([...row.roles]);
    setDraftPermissions([...row.permissions]);
    setDraftScope(row.deviceScope ?? {});
    setEditingId(row.id);
    setFormError(null);
  }

  function handleDelete(row: User) {
    if (!window.confirm(`Delete user "${row.username}"? This cannot be undone.`)) return;
    deleteUser.mutate(row.id);
  }

  // --- Creation helpers -------------------------------------------------------
  function resetCreateForm() {
    setShowCreate(false);
    setCreateUsername('');
    setCreatePassword('');
    setCreateRoles([]);
    setCreatePermissions([]);
    setCreateScope({});
    setFormError(null);
  }

  function handleCreateSubmit() {
    if (createPassword.length < 8) {
      setFormError('Password must be at least 8 characters.');
      return;
    }
    createUser.mutate({
      username: createUsername.trim(),
      password: createPassword,
      roles: createRoles,
      permissions: createPermissions,
      deviceScope: createScope,
    });
  }

  // --- Credential helpers -----------------------------------------------------
  function openCreds(row: User) {
    setCredsId(row.id);
    setNewPassword('');
    setCurrentPassword('');
    setFormError(null);
  }

  function closeCreds() {
    setCredsId(null);
    setNewPassword('');
    setCurrentPassword('');
    setFormError(null);
  }

  const catalog = catalogQuery.data;
  const editingUser = usersQuery.data?.find((u) => u.id === editingId) ?? null;

  // Effective permission set (explicit grants + role-derived, same union the
  // API computes at login). Used to flag service-only accounts — users without
  // `auth:interactive-login` cannot sign into the web UI.
  const effectivePermissions = (row: User): Set<string> => {
    const perms = new Set(row.permissions);
    for (const role of row.roles) {
      for (const p of catalog?.roles.find((r) => r.name === role)?.permissions ?? []) perms.add(p);
    }
    return perms;
  };
  const isServiceOnly = (row: User): boolean =>
    Boolean(catalog) && !effectivePermissions(row).has('auth:interactive-login');
  // A user is device-restricted when their effective scope carries any rule AND
  // they lack the devices:all bypass — same union the API enforces.
  const isDeviceRestricted = (row: User): boolean => {
    if (effectivePermissions(row).has('devices:all')) return false;
    const s = row.deviceScope ?? {};
    return Boolean(s.siteIds?.length || s.tags?.length || s.deviceIds?.length);
  };
  const credsUser = usersQuery.data?.find((u) => u.id === credsId) ?? null;
  // Self-credential ops need users:self-credentials; other-user ops need users:manage-credentials.
  const canManageCredsOf = (row: User): boolean => {
    if (selfUsername && row.username === selfUsername) return can('users:self-credentials');
    return can('users:manage-credentials');
  };

  function toggleInList(list: string[], value: string, set: (v: string[]) => void) {
    set(list.includes(value) ? list.filter((x) => x !== value) : [...list, value]);
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
              <span key={r} className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${r === 'admin' ? 'bg-primary text-white' : 'bg-muted text-secondary'}`}>
                {r}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    { header: 'Permissions', key: 'permissions', render: (row) => `${row.permissions.length} granted` },
    {
      header: 'Status',
      key: 'disabled',
      sortable: false as const,
      render: (row) => (
        <div className="flex flex-wrap gap-1">
          {row.disabled ? (
            <span className="inline-flex items-center rounded-full bg-danger px-2 py-0.5 text-xs font-medium text-danger-fg">disabled</span>
          ) : (
            <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">active</span>
          )}
          {isServiceOnly(row) && (
            <span
              title="No auth:interactive-login — this account cannot sign in to the web UI (API tokens only)."
              className="inline-flex items-center gap-1 rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary"
            >
              <ShieldOff className="h-3 w-3" />
              service-only
            </span>
          )}
          {isDeviceRestricted(row) && (
            <span
              title={`Limited to ${row.deviceScope!.siteIds?.length ?? 0} site(s), ${row.deviceScope!.tags?.length ?? 0} tag(s), ${row.deviceScope!.deviceIds?.length ?? 0} device(s).`}
              className="inline-flex items-center gap-1 rounded-full bg-info px-2 py-0.5 text-xs font-medium text-info-fg"
            >
              <Globe className="h-3 w-3" />
              device-restricted
            </span>
          )}
        </div>
      ),
    },
    {
      header: '2FA',
      key: 'twoFactorEnabled',
      sortable: false as const,
      render: (row) =>
        row.twoFactorEnabled ? (
          <span className="inline-flex items-center rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">enabled</span>
        ) : (
          <span className="text-faint">—</span>
        ),
    },
    ...(canWrite || canCreate || selfUsername
      ? [
          {
            header: 'Actions',
            key: 'actions',
            excludeFromExport: true,
            width: 130,
            sortable: false as const,
            render: (row: User) => (
              <div className="flex gap-1">
                {(canWrite || canManageCredsOf(row)) && (
                  <button
                    type="button"
                    aria-label={`Edit ${row.username}`}
                    title="Edit roles & permissions"
                    className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                    onClick={() => openEdit(row)}
                  >
                    <Pencil className="h-4 w-4" />
                  </button>
                )}
                {canManageCredsOf(row) && (
                  <button
                    type="button"
                    aria-label={`Credentials for ${row.username}`}
                    title={selfUsername === row.username ? 'Change own password / 2FA' : 'Reset password / manage 2FA'}
                    className="rounded-md p-1.5 text-secondary hover:bg-muted hover:text-foreground"
                    onClick={() => openCreds(row)}
                  >
                    <KeyRound className="h-4 w-4" />
                  </button>
                )}
                {/* Enable/disable — the initial admin can never be disabled (server 409s it too). */}
                {canWrite && row.username !== INITIAL_ADMIN_USERNAME && (
                  <button
                    type="button"
                    aria-label={row.disabled ? `Enable ${row.username}` : `Disable ${row.username}`}
                    title={row.disabled ? 'Re-enable account' : 'Disable account (blocks login + ends sessions)'}
                    className={`rounded-md p-1.5 hover:bg-muted ${row.disabled ? 'text-green-700' : 'text-secondary hover:text-foreground'}`}
                    onClick={() => {
                      if (!window.confirm(row.disabled ? `Re-enable "${row.username}"?` : `Disable "${row.username}"? They will be signed out and blocked from logging in.`)) return;
                      toggleStatus.mutate({ id: row.id, disabled: !row.disabled });
                    }}
                  >
                    {row.disabled ? <UserCheck className="h-4 w-4" /> : <UserX className="h-4 w-4" />}
                  </button>
                )}
                {/* The initial admin can never be deleted (server 409s it too). */}
                {canWrite && row.username !== INITIAL_ADMIN_USERNAME && (
                  <button
                    type="button"
                    aria-label={`Delete ${row.username}`}
                    title="Delete user"
                    className="rounded-md p-1.5 text-secondary hover:bg-danger hover:text-danger-fg"
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
    <Layout
      title="Users"
      actions={
        canCreate && !showCreate && (
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-white hover:bg-primary-hover"
          >
            <Plus className="h-4 w-4" /> New user
          </button>
        )
      }
    >

      {formError && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
      )}

      {/* Inline create panel */}
      {showCreate && canCreate && catalog && (
        <div className="mb-4 rounded-md border border-border bg-card p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground">New user</h2>
            <button type="button" aria-label="Close form" onClick={resetCreateForm} className="rounded p-1 text-faint hover:bg-muted">
              <X className="h-4 w-4" />
            </button>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault();
              handleCreateSubmit();
            }}
            className="grid grid-cols-1 gap-4 sm:grid-cols-2"
          >
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Username *</label>
              <input
                className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                value={createUsername}
                onChange={(e) => setCreateUsername(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-secondary">Initial password * (min 8 chars)</label>
              <input
                type="password"
                className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                value={createPassword}
                onChange={(e) => setCreatePassword(e.target.value)}
                required
              />
            </div>

            <fieldset>
              <legend className="mb-2 text-sm font-medium text-secondary">Roles</legend>
              {catalog.roles.map((role) => (
                <label key={role.name} title={role.description ?? undefined} className="flex items-center gap-2 py-1 text-sm text-secondary">
                  <input type="checkbox" checked={createRoles.includes(role.name)} onChange={() => toggleInList(createRoles, role.name, setCreateRoles)} />
                  {role.name}
                </label>
              ))}
            </fieldset>

            <fieldset>
              <legend className="mb-2 text-sm font-medium text-secondary">Permissions</legend>
              <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
                {catalog.permissions.map((p) => (
                  <label key={p.id} title={p.description} className="flex items-start gap-2 py-1 text-sm text-secondary">
                    <input type="checkbox" className="mt-0.5" checked={createPermissions.includes(p.id)} onChange={() => toggleInList(createPermissions, p.id, setCreatePermissions)} />
                    <span>
                      {p.id}
                      <span className="block text-xs font-normal text-faint">{p.description}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>

            {/* Device-level access control */}
            <fieldset className="sm:col-span-2">
              <legend className="mb-2 text-sm font-medium text-secondary">Device access</legend>
              <p className="mb-3 text-xs text-faint">
                Restrict which devices this account can see and manage (by site, tag or specific device). Role-level scopes are unioned on top.
              </p>
              <DeviceScopeEditor value={createScope} onChange={setCreateScope} />
            </fieldset>

            <div className="flex items-center gap-2 sm:col-span-2">
              <button
                type="submit"
                disabled={createUser.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                Create user
              </button>
              <button type="button" onClick={resetCreateForm} className="rounded-md px-4 py-2 text-sm font-medium text-secondary hover:bg-muted">
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Inline credentials panel (password reset + 2FA) */}
      {credsUser && canManageCredsOf(credsUser) && (
        <div className="mb-4 rounded-md border border-border bg-card p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground">Credentials — {credsUser.username}</h2>
            <button type="button" aria-label="Close panel" onClick={closeCreds} className="rounded p-1 text-faint hover:bg-muted">
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
            {/* Password reset */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                if (newPassword.length < 8) {
                  setFormError('New password must be at least 8 characters.');
                  return;
                }
                const isSelf = selfUsername === credsUser.username;
                resetPassword.mutate({ newPassword, ...(isSelf ? { currentPassword } : {}) });
              }}
              className="space-y-3"
            >
              <h3 className="text-sm font-semibold text-secondary">Reset password</h3>
              {selfUsername === credsUser.username && (
                <div>
                  <label className="mb-1 block text-sm font-medium text-secondary">Current password *</label>
                  <input
                    type="password"
                    className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                  />
                </div>
              )}
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">New password * (min 8 chars)</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                />
              </div>
              <button
                type="submit"
                disabled={resetPassword.isPending}
                className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
              >
                {selfUsername === credsUser.username ? 'Change my password' : 'Reset password'}
              </button>
            </form>

            {/* 2FA management */}
            <div className="space-y-3">
              <h3 className="text-sm font-semibold text-secondary">Two-factor authentication</h3>
              {credsUser.twoFactorEnabled ? (
                <>
                  <p className="flex items-center gap-2 text-sm text-green-700">
                    <span className="inline-flex h-2 w-2 rounded-full bg-green-500" /> 2FA is enabled for this user.
                  </p>
                  <div className="flex flex-wrap gap-2">
                    <button
                      type="button"
                      disabled={enrollTotp.isPending}
                      onClick={() => enrollTotp.mutate()}
                      className="rounded-md border border-border px-4 py-2 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50"
                    >
                      Re-enroll (new QR code)
                    </button>
                    <button
                      type="button"
                      disabled={disableTotp.isPending}
                      onClick={() => {
                        if (!window.confirm(`Disable 2FA for "${credsUser.username}"?`)) return;
                        disableTotp.mutate();
                      }}
                      className="inline-flex items-center gap-1.5 rounded-md border border-danger-border px-4 py-2 text-sm font-medium text-danger-fg hover:bg-danger disabled:opacity-50"
                    >
                      <ShieldOff className="h-4 w-4" /> Disable 2FA
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <p className="text-sm text-muted-foreground">No TOTP secret is enrolled for this user.</p>
                  <button
                    type="button"
                    disabled={enrollTotp.isPending}
                    onClick={() => enrollTotp.mutate()}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                  >
                    Enroll 2FA (show QR code)
                  </button>
                </>
              )}
            </div>
          </div>

          {/* Passkeys — admin can add/remove any user's passkeys */}
          <div className="mt-6 border-t border-border pt-4">
            <h3 className="mb-2 text-sm font-semibold text-secondary">Passkeys</h3>
            <p className="mb-3 text-xs text-faint">
              This user can sign in with any enrolled passkey. Removing one revokes that device immediately.
            </p>
            <PasskeyManager userId={credsUser.id} username={credsUser.username} />
          </div>

          {/* Per-user credential policy override */}
          {canEditPolicies && (
            <div className="mt-6 border-t border-border pt-4">
              <h3 className="mb-2 text-sm font-semibold text-secondary">Credential policy</h3>
              {userPolicyQuery.isLoading ? (
                <p className="text-sm text-faint">Loading policy…</p>
              ) : userPolicyQuery.data ? (
                <div className="space-y-3">
                  <p className="text-xs text-muted-foreground">
                    Effective source:{' '}
                    <span className="font-medium text-secondary">{userPolicyQuery.data.source}</span>
                    {userPolicyQuery.data.source === 'global' && ' (no per-user override yet — saving creates one)'}
                  </p>
                  <PolicyEditor
                    value={userPolicyQuery.data.policy}
                    override={userPolicyQuery.data.override ?? null}
                    onChange={(body) => saveUserPolicy.mutate(body)}
                  />
                  {userPolicyQuery.data.source === 'user' && (
                    <button
                      type="button"
                      disabled={clearUserPolicy.isPending}
                      onClick={() => {
                        if (!window.confirm(`Clear the per-user policy override for "${credsUser.username}"? The global default applies again.`)) return;
                        clearUserPolicy.mutate();
                      }}
                      className="ml-2 rounded-md border border-border px-4 py-2 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50"
                    >
                      Use global default
                    </button>
                  )}
                </div>
              ) : (
                <p className="text-sm text-danger-fg">Failed to load policy: {(userPolicyQuery.error as Error).message}</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* Inline edit panel */}
      {editingUser && canWrite && (
        <div className="mb-4 rounded-md border border-border bg-card p-4 shadow-sm">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold text-foreground">Edit — {editingUser.username}</h2>
            <button type="button" aria-label="Close form" onClick={resetEditForm} className="rounded p-1 text-faint hover:bg-muted">
              <X className="h-4 w-4" />
            </button>
          </div>

          {catalog && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                updateUser.mutate({ roles: draftRoles, permissions: draftPermissions, deviceScope: draftScope });
              }}
              className="grid grid-cols-1 gap-4 sm:grid-cols-2"
            >
              {/* Roles — the initial admin can never lose its admin role. */}
              <fieldset>
                <legend className="mb-2 text-sm font-medium text-secondary">Roles</legend>
                {catalog.roles.map((role) => (
                  <label key={role.name} title={role.description ?? undefined} className="flex items-center gap-2 py-1 text-sm text-secondary">
                    <input
                      type="checkbox"
                      checked={draftRoles.includes(role.name)}
                      disabled={editingUser.username === INITIAL_ADMIN_USERNAME && role.name === 'admin'}
                      onChange={() => toggleInList(draftRoles, role.name, setDraftRoles)}
                    />
                    {role.name}
                  </label>
                ))}
              </fieldset>

              {/* Permissions */}
              <fieldset>
                <legend className="mb-2 text-sm font-medium text-secondary">Permissions</legend>
                <div className="max-h-64 space-y-1 overflow-y-auto pr-1">
                  {catalog.permissions.map((p) => (
                    <label key={p.id} title={p.description} className="flex items-start gap-2 py-1 text-sm text-secondary">
                      <input type="checkbox" className="mt-0.5" checked={draftPermissions.includes(p.id)} onChange={() => toggleInList(draftPermissions, p.id, setDraftPermissions)} />
                      <span>
                        {p.id}
                        <span className="block text-xs font-normal text-faint">{p.description}</span>
                      </span>
                    </label>
                  ))}
                </div>
                {/* Effective-set hint: explicit grants alone can hide role-derived
                    permissions, so show the union that login actually uses. */}
                {(() => {
                  const eff = effectivePermissions(editingUser);
                  return !eff.has('auth:interactive-login') ? (
                    <p className="mt-2 rounded-md border border-warning-border bg-warning px-3 py-2 text-xs text-amber-900">
                      This account is <strong>service-only</strong>: it cannot sign in to the web UI. Grant{' '}
                      <code className="rounded bg-card px-1">auth:interactive-login</code> (directly or via a role) to restore
                      interactive login.
                    </p>
                  ) : null;
                })()}
              </fieldset>

              {/* Device-level access control */}
              <fieldset className="sm:col-span-2">
                <legend className="mb-2 text-sm font-medium text-secondary">Device access</legend>
                <p className="mb-3 text-xs text-faint">
                  Restrict which devices this account can see and manage (by site, tag or specific device). Role-level scopes are unioned on top.
                </p>
                <DeviceScopeEditor value={draftScope} onChange={setDraftScope} />
              </fieldset>

              <div className="flex items-center gap-2 sm:col-span-2">
                <button
                  type="submit"
                  disabled={updateUser.isPending}
                  className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                >
                  Save changes
                </button>
                <button type="button" onClick={resetEditForm} className="rounded-md px-4 py-2 text-sm font-medium text-secondary hover:bg-muted">
                  Cancel
                </button>
              </div>
            </form>
          )}
        </div>
      )}

      {usersQuery.isLoading && <p className="text-sm text-muted-foreground">Loading users...</p>}
      {usersQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load users: {(usersQuery.error as Error).message}</p>
      )}
      {usersQuery.data && (
        <DataTable columns={columns} rows={usersQuery.data} rowKey={(row) => row.id} storageKey="users" emptyMessage="No users." />
      )}

      {/* TOTP enrollment QR dialog (after create / re-enroll) */}
      {enrollment && (
        <TotpEnrollmentDialog username={enrollment.username} enrollment={enrollment.enrollment} onClose={() => setEnrollment(null)} />
      )}
    </Layout>
  );
}
