import { useEffect, useState } from 'react';
import type { FormEvent } from 'react';
import { Hourglass, KeyRound, Loader2, ShieldCheck, X } from 'lucide-react';
import clsx from 'clsx';
import { api, ApiError, RevalidateChallenge, setAccessToken } from '../api/client';
import { toRequestOptions } from '../utils/webauthn';

/**
 * ExtendSessionDialog — extends the current session by re-proving a second
 * factor (TOTP code or passkey) against a fresh challenge. Extending is NEVER
 * possible without this: an unauthenticated refresh would let anyone holding a
 * stolen token keep minting new ones forever, and users with no enrolled
 * second factor cannot extend at all (the server enforces both). The password
 * is never re-entered; only the second factor is asserted. Shown from the
 * amber "session ending soon" banner in the top bar.
 */

interface ExtendSessionDialogProps {
  onClose: () => void;
  /** Called after a fresh token has been stored — refresh the countdown. */
  onSuccess: () => void | Promise<void>;
}

export function ExtendSessionDialog({ onClose, onSuccess }: ExtendSessionDialogProps) {
  const [challenge, setChallenge] = useState<RevalidateChallenge | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Fetch an extension challenge on open. A 403 means the policy denies
  // extension or no second factor is enrolled — surface that and stop.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const c = await api.sessionExtendChallenge();
        if (!cancelled) setChallenge(c);
      } catch (err) {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 403) {
          setError(
            err.code === 'extension_disabled'
              ? 'Session extension is disabled for your account by its credential policy. Your session will end at its expiry.'
              : 'Extending a session requires an enrolled second factor (TOTP or passkey). Enroll one in My Account, or sign in again when the session ends.'
          );
        } else {
          setError(err instanceof Error ? err.message : String(err));
        }
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
      const res = await api.verifySessionExtendTotp({ challengeToken: challenge.challengeToken, totpCode: totpCode.trim() });
      await complete(res);
    } catch (err) {
      // A bad/expired code invalidates the challenge — fetch a fresh one.
      setError(err instanceof Error ? err.message : String(err));
      try {
        setChallenge(await api.sessionExtendChallenge());
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
      const { options, nonce } = await api.sessionExtendWebauthnOptions(challenge.challengeToken, challenge.userId);
      let assertion: unknown;
      try {
        assertion = await navigator.credentials.get({ publicKey: toRequestOptions(options) });
      } catch (credErr) {
        const name = credErr instanceof DOMException ? credErr.name : '';
        if (name === 'NotAllowedError') setError('Passkey verification was cancelled.');
        else if (name === 'InvalidStateError' || name === 'SecurityError') {
          setError('No passkey is available on this device. Use your TOTP code instead.');
        } else {
          setError(`Passkey verification failed: ${(credErr as Error).message}`);
        }
        setLoading(false);
        return;
      }
      if (!assertion) {
        setError('No passkey was presented. Try again or use your TOTP code.');
        setLoading(false);
        return;
      }
      const res = await api.verifySessionExtendWebauthn({ challengeToken: challenge.challengeToken, response: assertion, nonce });
      await complete(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-[60] flex items-start justify-center overflow-y-auto bg-primary/40 p-6" onClick={onClose}>
      <div className="mt-16 w-full max-w-sm rounded-md border border-border bg-card shadow-xl" onClick={(e) => e.stopPropagation()}>
        <header className="flex items-center justify-between border-b border-border px-4 py-3">
          <div className="flex items-center gap-2">
            <Hourglass className="h-4 w-4 text-warning-fg" />
            <h2 className="text-base font-semibold text-foreground">Extend session</h2>
          </div>
          <button type="button" aria-label="Close dialog" onClick={onClose} className="rounded p-1 text-faint hover:bg-muted">
            <X className="h-4 w-4" />
          </button>
        </header>

        <div className="p-4">
          <p className="mb-3 text-xs text-muted-foreground">
            Your session is about to expire. Verify a second factor to extend it — no password needed.
          </p>

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
                <label className="mb-1 block text-sm font-medium text-secondary" htmlFor="extend-totp">
                  Authenticator code
                </label>
                <input
                  id="extend-totp"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm tracking-widest focus:border-slate-500 focus:outline-none"
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
                  <ShieldCheck className="h-3.5 w-3.5" /> Verify &amp; extend
                </button>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}
