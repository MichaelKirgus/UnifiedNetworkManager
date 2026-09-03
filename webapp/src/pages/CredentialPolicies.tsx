import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { ShieldCheck } from 'lucide-react';
import { Layout } from '../components/Layout';
import { PolicyEditor } from '../components/PolicyEditor';
import { api, CredentialPolicy } from '../api/client';
import { can } from '../auth/permissions';

/**
 * Global credential policy + per-user overrides.
 *
 * The global default applies to every user; a per-user override (managed on the
 * Users page) wins over it for that account. Editing requires auth:policies:write —
 * everyone else sees read-only state.
 */
export default function CredentialPolicies() {
  const queryClient = useQueryClient();
  const canEdit = can('auth:policies:write');

  const globalPolicyQuery = useQuery({
    queryKey: ['global-credential-policy'],
    queryFn: api.globalCredentialPolicy,
  });

  const usersQuery = useQuery({
    queryKey: ['users'],
    queryFn: api.users,
    enabled: can('users:read'),
  });

  // Per-user overrides — one policy fetch per user (fine at this scale).
  const overrideQueries = useQuery({
    queryKey: ['user-policies-all', usersQuery.data?.map((u) => u.id)],
    queryFn: async () => {
      const results = await Promise.all(
        (usersQuery.data ?? []).map(async (u) => ({ user: u, policy: await api.userCredentialPolicy(u.id) }))
      );
      return results;
    },
    enabled: Boolean(usersQuery.data?.length),
  });

  const saveGlobal = useMutation({
    mutationFn: (body: Partial<CredentialPolicy>) => api.setGlobalCredentialPolicy(body),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['global-credential-policy'] }),
    onError: (err: unknown) => setFormError((err as Error).message),
  });

  const [formError, setFormError] = useState<string | null>(null);

  const globalPolicy = globalPolicyQuery.data?.policy;
  const overrides = (overrideQueries.data ?? []).filter((r) => r.policy.source === 'user');

  return (
    <Layout title="Credential Policies">

      {formError && (
        <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{formError}</div>
      )}

      {/* Global default */}
      <div className="rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="mb-1 flex items-center gap-2 text-base font-semibold text-slate-900">
          <ShieldCheck className="h-4 w-4" /> Global default policy
        </h2>
        <p className="mb-4 text-xs text-slate-400">
          Applies to every user without a per-user override. Changes take effect immediately for all existing sessions
          (the gate is evaluated live on each privileged request).
        </p>

        {globalPolicyQuery.isLoading ? (
          <p className="text-sm text-slate-500">Loading policy…</p>
        ) : globalPolicy ? (
          canEdit ? (
            <PolicyEditor value={globalPolicy} onChange={(body) => saveGlobal.mutate(body)} />
          ) : (
            <ReadOnlyPolicy policy={globalPolicy} />
          )
        ) : (
          <p className="text-sm text-red-600">Failed to load policy: {(globalPolicyQuery.error as Error).message}</p>
        )}

        {!canEdit && (
          <p className="mt-3 text-xs text-slate-400">
            Editing requires the{' '}
            <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px]">auth:policies:write</code>{' '}
            permission.
          </p>
        )}
      </div>

      {/* Per-user overrides */}
      <div className="mt-4 rounded-md border border-slate-200 bg-white p-4 shadow-sm">
        <h2 className="mb-1 text-base font-semibold text-slate-900">Per-user overrides</h2>
        <p className="mb-3 text-xs text-slate-400">
          Users with an individual policy — manage these on the{' '}
          <a href="/users" className="text-slate-600 underline hover:text-slate-900">Users</a>{' '}
          page (Credentials panel → Credential policy).
        </p>

        {can('users:read') ? (
          overrideQueries.isLoading || usersQuery.isLoading ? (
            <p className="text-sm text-slate-500">Loading overrides…</p>
          ) : overrides.length === 0 ? (
            <p className="text-sm text-slate-500">No per-user overrides — everyone uses the global default.</p>
          ) : (
            <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
              {overrides.map(({ user, policy }) => (
                <li key={user.id} className="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
                  <span className="text-sm font-medium text-slate-800">{user.username}</span>
                  <ReadOnlyPolicyInline policy={policy.policy} />
                </li>
              ))}
            </ul>
          )
        ) : (
          <p className="text-sm text-slate-500">
            Viewing overrides requires the{' '}
            <code className="rounded bg-slate-100 px-1 py-0.5 font-mono text-[11px]">users:read</code> permission.
          </p>
        )}
      </div>
    </Layout>
  );
}

function ReadOnlyPolicy({ policy }: { policy: CredentialPolicy }) {
  return (
    <dl className="grid grid-cols-1 gap-3 sm:grid-cols-2">
      <div>
        <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">Required second factor at login</dt>
        <dd className="mt-1 flex flex-wrap gap-1">
          {policy.requiredMethods.length === 0 ? (
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-700">none (password only)</span>
          ) : (
            policy.requiredMethods.map((m) => (
              <span key={m} className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600">
                {m === 'totp' ? 'TOTP' : 'Passkey'}
              </span>
            ))
          )}
        </dd>
      </div>
      <div>
        <dt className="text-xs font-medium uppercase tracking-wide text-slate-400">Satisfies privileged-action gate</dt>
        <dd className="mt-1 flex flex-wrap gap-1">
          {policy.gateAmrs.map((m) => (
            <span key={m} className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
              {m === 'totp' ? 'TOTP sessions' : m === 'webauthn' ? 'Passkey sessions' : m}
            </span>
          ))}
        </dd>
      </div>
    </dl>
  );
}

function ReadOnlyPolicyInline({ policy }: { policy: CredentialPolicy }) {
  return (
    <span className="flex flex-wrap items-center gap-1 text-xs">
      <span className="text-slate-400">login:</span>
      {policy.requiredMethods.length === 0 ? (
        <span className="rounded-full bg-amber-100 px-2 py-0.5 font-medium text-amber-700">none</span>
      ) : (
        policy.requiredMethods.map((m) => (
          <span key={m} className="rounded-full bg-slate-100 px-2 py-0.5 font-medium text-slate-600">
            {m === 'totp' ? 'TOTP' : 'Passkey'}
          </span>
        ))
      )}
      <span className="ml-2 text-slate-400">gate:</span>
      {policy.gateAmrs.map((m) => (
        <span key={m} className="rounded-full bg-green-100 px-2 py-0.5 font-medium text-green-700">
          {m === 'totp' ? 'TOTP' : m === 'webauthn' ? 'Passkey' : m}
        </span>
      ))}
    </span>
  );
}
