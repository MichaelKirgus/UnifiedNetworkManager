import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { KeyRound, Loader2, Plus, Trash2 } from 'lucide-react';
import { api } from '../api/client';
import { toCreationOptions } from '../utils/webauthn';

/**
 * Manages the passkeys (WebAuthn credentials) of one user — multiple allowed,
 * one per device. Used by My Account (self-service) and the Users page
 * (admin managing another account). The two-step enrollment flow:
 *   1. POST /users/:id/passkeys → registration options + nonce
 *   2. navigator.credentials.create() → browser/platform prompt
 *   3. POST /users/:id/passkeys/verify → attestation verified, credential stored
 */
export function PasskeyManager({ userId, username }: { userId: string; username: string }) {
  const queryClient = useQueryClient();

  const passkeysQuery = useQuery({
    queryKey: ['passkeys', userId],
    queryFn: () => api.passkeys(userId),
  });

  // Enrollment state machine: idle → prompting (options fetched) → done.
  const [enrolling, setEnrolling] = useState(false);
  const [label, setLabel] = useState('');
  const [error, setError] = useState<string | null>(null);

  const startEnrollment = useMutation({
    mutationFn: () => api.startPasskeyEnrollment(userId),
    onSuccess: async ({ options, nonce }) => {
      try {
        const credential = await navigator.credentials.create({
          // Convert base64url challenge/user.id to binary before the prompt.
          publicKey: toCreationOptions(options),
        });
        if (!credential) {
          setError('No passkey was created. Try again.');
          return;
        }
        await api.completePasskeyEnrollment(userId, { nonce, response: credential, label: label.trim() || undefined });
        queryClient.invalidateQueries({ queryKey: ['passkeys', userId] });
        queryClient.invalidateQueries({ queryKey: ['me'] });
        queryClient.invalidateQueries({ queryKey: ['users'] });
        setLabel('');
      } catch (err) {
        const name = err instanceof DOMException ? err.name : '';
        if (name === 'NotAllowedError') setError('Passkey enrollment was cancelled.');
        else if (name === 'InvalidStateError' || name === 'SecurityError') {
          setError('This browser/device does not support passkeys. Try a different device or use TOTP instead.');
        } else {
          setError(`Passkey enrollment failed: ${(err as Error).message}`);
        }
      } finally {
        setEnrolling(false);
      }
    },
    onError: (err: unknown) => setError((err as Error).message),
  });

  const deletePasskey = useMutation({
    mutationFn: (credentialId: string) => api.deletePasskey(userId, credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['passkeys', userId] });
      queryClient.invalidateQueries({ queryKey: ['me'] });
      queryClient.invalidateQueries({ queryKey: ['users'] });
    },
    onError: (err: unknown) => setError((err as Error).message),
  });

  const passkeys = passkeysQuery.data ?? [];

  return (
    <div className="space-y-3">
      {error && (
        <div className="rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">{error}</div>
      )}

      {/* Enrolled passkeys */}
      {passkeysQuery.isLoading ? (
        <p className="text-sm text-slate-400">Loading passkeys…</p>
      ) : passkeys.length === 0 ? (
        <p className="text-sm text-slate-500">No passkeys enrolled for this account.</p>
      ) : (
        <ul className="divide-y divide-slate-100 rounded-md border border-slate-200">
          {passkeys.map((pk) => (
            <li key={pk.id} className="flex items-center justify-between gap-3 px-3 py-2">
              <div className="min-w-0">
                <p className="flex items-center gap-1.5 truncate text-sm font-medium text-slate-800">
                  <KeyRound className="h-3.5 w-3.5 shrink-0 text-slate-400" />
                  {pk.label || 'Passkey'}
                </p>
                <p className="text-xs text-slate-400">
                  {(pk.transports ?? []).join(', ') || 'unknown transport'} · added{' '}
                  {new Date(pk.createdAt).toLocaleDateString()}
                </p>
              </div>
              <button
                type="button"
                aria-label={`Delete passkey ${pk.label ?? ''}`}
                title="Delete this passkey"
                disabled={deletePasskey.isPending}
                onClick={() => {
                  if (!window.confirm(`Remove the passkey "${pk.label || 'Passkey'}"?`)) return;
                  deletePasskey.mutate(pk.credentialId);
                }}
                className="rounded-md p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-600 disabled:opacity-50"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </li>
          ))}
        </ul>
      )}

      {/* Add passkey */}
      {enrolling ? (
        <div className="space-y-2 rounded-md border border-slate-200 bg-slate-50 p-3">
          <p className="text-sm text-slate-600">
            A prompt will appear — approve it with your device's built-in authenticator (fingerprint, face or PIN).
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              disabled={startEnrollment.isPending}
              onClick={() => startEnrollment.mutate()}
              className="inline-flex items-center gap-1.5 rounded-md bg-slate-900 px-3 py-1.5 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
            >
              {startEnrollment.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
              Continue enrollment
            </button>
            <button
              type="button"
              onClick={() => setEnrolling(false)}
              className="rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-white"
            >
              Cancel
            </button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <input
            className="w-48 rounded-md border border-slate-300 px-3 py-1.5 text-sm focus:border-slate-500 focus:outline-none"
            placeholder="Label (e.g. MacBook)"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
          />
          <button
            type="button"
            onClick={() => {
              setError(null);
              setEnrolling(true);
            }}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-300 px-3 py-1.5 text-sm font-medium text-slate-700 hover:bg-slate-100"
          >
            <Plus className="h-4 w-4" /> Add passkey
          </button>
        </div>
      )}

      {passkeys.length === 0 && !enrolling && (
        <p className="text-xs text-slate-400">
          Passkeys work on this device and any other where you enroll one — each device gets its own passkey.
        </p>
      )}
    </div>
  );
}
