import { useState } from 'react';
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query';
import { ShieldCheck, ShieldOff } from 'lucide-react';
import { Layout } from '../components/Layout';
import { TotpEnrollmentDialog } from '../components/TotpEnrollmentDialog';
import { PasskeyManager } from '../components/PasskeyManager';
import { TimePreferencesCard } from '../components/TimePreferencesCard';
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
    <Layout title="My Account">

      {formError && (
        <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{formError}</div>
      )}

      {meQuery.isLoading && <p className="text-sm text-muted-foreground">Loading profile...</p>}
      {meQuery.isError && (
        <p className="text-sm text-danger-fg">Failed to load profile: {(meQuery.error as Error).message}</p>
      )}

      {me && (
        <div className="space-y-4">
          {/* Profile summary */}
          <div className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="mb-3 text-base font-semibold text-foreground">Profile</h2>
            <dl className="grid grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-2">
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-faint">Username</dt>
                <dd className="mt-0.5 text-sm font-medium text-foreground">{me.username}</dd>
              </div>
              <div>
                <dt className="text-xs font-medium uppercase tracking-wide text-faint">Roles</dt>
                <dd className="mt-0.5 flex flex-wrap gap-1">
                  {me.roles.length > 0 ? (
                    me.roles.map((r) => (
                      <span key={r} className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${r === 'admin' ? 'bg-primary text-white' : 'bg-muted text-secondary'}`}>
                        {r}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-faint">—</span>
                  )}
                </dd>
              </div>
              <div className="sm:col-span-2">
                <dt className="text-xs font-medium uppercase tracking-wide text-faint">Effective permissions (this session)</dt>
                <dd className="mt-1 flex max-h-32 flex-wrap gap-1 overflow-y-auto pr-1">
                  {me.effectivePermissions.length > 0 ? (
                    me.effectivePermissions.map((p) => (
                      <span key={p} className="inline-flex items-center rounded-full bg-muted px-2 py-0.5 text-xs font-medium text-secondary">
                        {p}
                      </span>
                    ))
                  ) : (
                    <span className="text-sm text-faint">—</span>
                  )}
                </dd>
              </div>
            </dl>
          </div>

          {/* Date & time display preferences — visible to every user */}
          <TimePreferencesCard />

          {/* Credential self-service */}
          {canSelfCreds ? (
            <div className="rounded-md border border-border bg-card p-4 shadow-sm">
              <h2 className="mb-3 text-base font-semibold text-foreground">Credentials</h2>

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
                  <h3 className="text-sm font-semibold text-secondary">Change my password</h3>
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
                    disabled={changePassword.isPending}
                    className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                  >
                    Change password
                  </button>
                </form>

                {/* TOTP management */}
                <div className="space-y-3">
                  <h3 className="text-sm font-semibold text-secondary">Authenticator app (TOTP)</h3>
                  {me.totpEnabled ? (
                    <>
                      <p className="flex items-center gap-2 text-sm text-green-700">
                        <ShieldCheck className="h-4 w-4" /> TOTP is enrolled on your account.
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
                            if (!window.confirm('Disable TOTP on your account?')) return;
                            disableTotp.mutate();
                          }}
                          className="inline-flex items-center gap-1.5 rounded-md border border-danger-border px-4 py-2 text-sm font-medium text-danger-fg hover:bg-danger disabled:opacity-50"
                        >
                          <ShieldOff className="h-4 w-4" /> Disable TOTP
                        </button>
                      </div>
                    </>
                  ) : (
                    <>
                      <p className="text-sm text-muted-foreground">No TOTP secret is enrolled on your account.</p>
                      <button
                        type="button"
                        disabled={enrollTotp.isPending}
                        onClick={() => enrollTotp.mutate()}
                        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
                      >
                        Enroll TOTP (show QR code)
                      </button>
                    </>
                  )}
                </div>
              </div>

              {/* Passkeys (multiple allowed — one per device) */}
              <div className="mt-6 border-t border-border pt-4">
                <h3 className="mb-2 text-sm font-semibold text-secondary">Passkeys</h3>
                <p className="mb-3 text-xs text-faint">
                  Sign in with your device's built-in authenticator instead of a TOTP code. You can enroll one per
                  device — all of them work for this account.
                </p>
                <PasskeyManager userId={me.id} username={me.username} />
              </div>
            </div>
          ) : (
            <div className="rounded-md border border-border bg-card p-4 text-sm text-muted-foreground shadow-sm">
              Password and 2FA self-service requires the <code className="rounded bg-muted px-1 py-0.5 font-mono text-xs">users:self-credentials</code>{' '}
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
