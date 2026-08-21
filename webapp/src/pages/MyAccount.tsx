import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { ShieldCheck, ShieldOff } from 'lucide-react';
import { Layout } from '../components/Layout';
import { TotpEnrollmentDialog } from '../components/TotpEnrollmentDialog';
import { api, TotpEnrollment } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Self-service portal — visible to every signed-in user. Shows the account's
 * own profile and (when `users:self-credentials` is granted) password change +
 * 2FA management for oneself. Future self-service features land here too.
 */
export default function MyAccount() {
  const queryClient = useQueryClient();
  const canSelfCreds = can('users:self-credentials');

  const [formError, setFormError] = useState<string | null>(null);
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [enrollment, setEnrollment] = useState<TotpEnrollment | null>(null);

  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });

  const changePassword = useMutation({
    mutationFn: (body: { newPassword: string; currentPassword: string }) => api.resetUserPassword(meQuery.data!.id, body),
    onSuccess: () => {
      setCurrentPassword('');
      setNewPassword('');
      setFormError(null);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const enrollTotp = useMutation({
    mutationFn: () => api.enrollTotp(meQuery.data!.id),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setEnrollment(res.enrollment);
    },
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const disableTotp = useMutation({
    mutationFn: () => api.disableTotp(meQuery.data!.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const me = meQuery.data;

  return (
    <Layout>
      <div className="mb-4">
        <h1 className="text-xl font-bold text-slate-900">My Account</h1>
        <p className="mt-1 text-sm text-slate-500">Your profile and self-service settings.</p>
      </div>

      {formError && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
      )}

      {meQuery.isLoading && <p className="text-sm text-slate-500">Loading profile...</p>}
      {meQuery.isError && (
        <p className="text-sm text-red-600">Failed to load profile: {(meQuery.error as Error).message}</p>
      )}

      {me && (
        <div className="space-y-4">
          {/* Profile summary */}
          <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
            <h2 className="mb-3 text-base font-semibold text-slate-900">Profile</h2>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">Username</dt>
                <dd className="mt-0.5 text-sm font-medium text-slate-900">{me.username}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">Roles</dt>
                <dd className="mt-0.5 flex flex-wrap gap-1">
                  {me.roles.length > 0 ? (
                    me.roles.map((r) => (
                      <span key={r} className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${r === 'admin' ? 'bg-slate-900 text-white' : 'bg-slate-100 text-slate-600'}`}>
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-slate-400">—</span>
                  )}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">Effective permissions (this session)</dt>
                <dd className="mt-1 flex max-h-32 flex-wrap gap-1 overflow-y-auto pr-1">
                  {me.effectivePermissions.length > 0 ? (
                    me.effectivePermissions.map((p) => (
                      <span key={p} className="inline-flex items-center rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-slate-400">—</span>
                  )}
                </dd>
              </div>
            </dl>
          </div>

          {/* Credential self-service */}
          {canSelfCreds ? (
            <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
              <h2 className="mb-3 text-base font-semibold text-slate-900">Credentials</h2>

              <div className="grid grid-cols-1 gap-6 sm:grid-cols-2">
                {/* Password change */}
                <form
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (newPassword.length < 8) {
                      setFormError('New password must be at least 8 characters.');
                      return;
                    }
                    changePassword.mutate({ newPassword, currentPassword });
                  }}
                  className="space-y-3"
                >
                  <h3 className="text-sm font-semibold text-slate-700">Change my password</h3>
                  <div>
                    <label className="mb-1 block text-sm font-medium text-slate-700">Current password *</label>
                    <input
                      type="password"
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                      value={currentPassword}
                      onChange={(e) => setCurrentPassword(e.target.value)}
                      required
                    />
                  </div>
                  <div>
                    <label className="mb-1 block text-sm font-medium text-slate-700">New password * (min 8 chars)</label>
                    <input
                      type="password"
                      className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                      value={newPassword}
                      onChange={(e) => setNewPassword(e.target.value)}
                      required
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={changePassword.isPending}
                    className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
                  >
                    Change password
                  </button>
                </form>

                {/* 2FA management */}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-slate-700">Two-factor authentication</h3>
                  {me.twoFactorEnabled ? (
                    <>
                      <p className="flex items-center gap-2 text-sm text-green-700">
                        <ShieldCheck className="h-4 w-4" /> 2FA is enabled on your account.
                      </p>
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          disabled={enrollTotp.isPending}
                          onClick={() => enrollTotp.mutate()}
                          className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-100 disabled:opacity-50"
                        >
                          Re-enroll (new QR code)
                        </button>
                        <button
                          type="button"
                          disabled={disableTotp.isPending}
                          onClick={() => {
                            if (!window.confirm('Disable 2FA on your account?')) return;
                            disableTotp.mutate();
                          }}
                          className="inline-flex items-center gap-1.5 rounded-md border border-red-300 px-4 py-2 text-sm font-medium text-red-700 hover:bg-red-50 disabled:opacity-50"
                        >
                          <ShieldOff className="h-4 w-4" /> Disable 2FA
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-sm text-slate-500">No TOTP secret is enrolled on your account.</p>
                      <button
                        type="button"
                        disabled={enrollTotp.isPending}
                        onClick={() => enrollTotp.mutate()}
                        className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
                      >
                        Enroll 2FA (show QR code)
                      </button>
                    </>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-md border border-slate-200 bg-white p-4 text-sm text-slate-500 shadow-sm">
              Password and 2FA self-service requires the <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-xs">users:self-credentials</code>{' '}
              permission. Ask an administrator to grant it if you need to manage your own credentials here.
            </div>
          )}
        </div>
      )}

      {/* TOTP enrollment QR dialog (self re-enroll) */}
      {enrollment && me && <TotpEnrollmentDialog username={me.username} enrollment={enrollment} onClose={() => setEnrollment(null)} />}
    </Layout>
  );
}
