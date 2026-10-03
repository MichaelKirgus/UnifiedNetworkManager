import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { KeyRound, Loader2, ShieldCheck } from 'lucide-react';
import clsx from 'clsx';
import { api, ApiError, RevalidateChallenge, setAccessToken } from '../api/client';
import { toRequestOptions } from '../utils/webauthn';
import { DialogShell } from './DialogShell';

/**
 * ReauthDialog — in-session two-factor re-validation. Shown when a privileged
 * action (plan create/execute) is rejected with 401 because the session's 2FA
 * `amr` has expired or is missing, per the user's credential policy. Instead of
 * forcing a full re-login, it re-proves TOTP or a passkey against a fresh
 * challenge and mints a new access token (stored via setAccessToken), then calls
 * onSuccess so the caller can retry the action — WITHOUT navigating away. The
 * password is never re-entered; only the second factor is asserted.
 */

interface ReauthDialogProps {
  /** Short label of what triggered the revalidation (e.g. "Stop 3 containers"). */
  contextLabel?: string;
  onClose: () => void;
  /** Called with nothing after a fresh token is stored — retry the action now. */
  onSuccess: () => void | Promise<void>;
}

export function ReauthDialog({ contextLabel, onClose, onSuccess }: ReauthDialogProps) {
  const [challenge, setChallenge] = useState<RevalidateChallenge | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Fetch a revalidation challenge for the caller on open.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const c = await api.revalidateChallenge();
        if (!cancelled) setChallenge(c);
      } catch (err) {
        if (!cancelled) setError(err instanceof Error ? err.message : String(err));
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  async function complete(res: { accessToken: string }) {
    setAccessToken(res.accessToken);
    await onSuccess();
  }

  async function handleTotp(e: FormEvent) {
    e.preventDefault();
    if (!challenge || !totpCode.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const res = await api.verifyRevalidateTotp({ challengeToken: challenge.challengeToken, totpCode: totpCode.trim() });
      await complete(res);
    } catch (err) {
      // A bad/expired code invalidates the challenge — fetch a fresh one.
      setError(err instanceof Error ? err.message : String(err));
      try {
        const c = await api.revalidateChallenge();
        setChallenge(c);
      } catch {
        /* keep the existing error */
      }
    } finally {
      setLoading(false);
    }
  }

  async function handlePasskey() {
    if (!challenge) return;
    setError(null);
    setLoading(true);
    try {
      const { options, nonce } = await api.revalidateWebauthnOptions(challenge.challengeToken, challenge.userId);
      let assertion: unknown;
      try {
        assertion = await navigator.credentials.get({ publicKey: toRequestOptions(options) });
      } catch (credErr) {
        const name = credErr instanceof DOMException ? credErr.name : '';
        if (name === 'NotAllowedError') setError('Passkey sign-in was cancelled.');
        else if (name === 'InvalidStateError' || name === 'SecurityError') {
          setError('No passkey is available on this device. Use your TOTP code instead.');
        } else {
          setError(`Passkey sign-in failed: ${(credErr as Error).message}`);
        }
        setLoading(false);
        return;
      }
      if (!assertion) {
        setError('No passkey was presented. Try again or use your TOTP code.');
        setLoading(false);
        return;
      }
      const res = await api.verifyRevalidateWebauthn({ challengeToken: challenge.challengeToken, response: assertion, nonce });
      await complete(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  return (
    <DialogShell title="Two-factor required" icon={<ShieldCheck className="h-4 w-4 text-primary" />} onClose={onClose} zIndex="z-[60]" maxWidth="max-w-sm">
      <div>
          {contextLabel && (
            <p className="mb-3 text-xs text-muted-foreground">
              “{contextLabel}” needs a fresh two-factor check before it can run.
            </p>
          )}

          {!challenge && !error && (
            <div className="flex items-center gap-2 py-4 text-sm text-secondary">
              <Loader2 className="h-4 w-4 animate-spin" /> Preparing…
            </div>
          )}

          {error && (
            <div className="mb-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-xs text-danger-fg">{error}</div>
          )}

          {challenge && (
            <form onSubmit={handleTotp} className="space-y-4">
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary" htmlFor="reauth-totp">
                  Authenticator code
                </label>
                <input
                  id="reauth-totp"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm tracking-widest focus:border-focus-ring focus:outline-none"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value)}
                  maxLength={6}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  placeholder="••••••"
                />
              </div>

              {challenge.supportsPasskey && (
                <button
                  type="button"
                  onClick={handlePasskey}
                  disabled={loading}
                  className="flex w-full items-center justify-center gap-2 rounded-md border border-border px-3 py-2 text-sm font-medium text-secondary hover:bg-background disabled:opacity-50"
                >
                  <KeyRound className="h-4 w-4" /> Use a passkey instead
                </button>
              )}

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={onClose}
                  disabled={loading}
                  className="rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-background disabled:opacity-40"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading || totpCode.trim().length === 0}
                  className={clsx(
                    'inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium text-white disabled:opacity-40',
                    'bg-primary hover:bg-primary-hover'
                  )}
                >
                  {loading && <Loader2 className="h-3.5 w-3.5 animate-spin" />}
                  Verify &amp; continue
                </button>
              </div>
            </form>
          )}
      </div>
    </DialogShell>
  );
}
