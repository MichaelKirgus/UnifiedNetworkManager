import { FormEvent, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowRight, ExternalLink, KeyRound, Loader2, ShieldCheck } from 'lucide-react';
import { api, ApiError } from '../api/client';
import { setPermissions, setUsername } from '../auth/permissions';
import { toRequestOptions } from '../utils/webauthn';

type Flow = 'password' | 'oauth2' | 'ldap' | 'saml' | 'unknown';

/** Human-friendly label for the external sign-in button, per flow. */
function flowLabel(flow: Flow): string {
  switch (flow) {
    case 'oauth2':
      return 'Sign in with your identity provider';
    case 'ldap':
      return 'Sign in with your directory';
    case 'saml':
      return 'Sign in with SSO';
    default:
      return 'Continue with single sign-on';
  }
}

export default function Login() {
  const navigate = useNavigate();

  // The active identity provider's flow, resolved from the API on mount.
  const [flow, setFlow] = useState<Flow | null>(null);
  const [supportsPasskey, setSupportsPasskey] = useState(false);
  const [flowError, setFlowError] = useState<string | null>(null);

  // Password-flow state.
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  // Forced password change: the login reported `passwordExpired`, so after the
  // (2FA) sign-in completes we hold the user on a "set a new password" step.
  const [forceChange, setForceChange] = useState(false);
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // Bounced here by the client's auto-logout: either a disabled account (401
  // user_disabled) or a session that reached its timeout while the UI was open.
  useEffect(() => {
    const reason = new URLSearchParams(window.location.search).get('reason');
    if (reason === 'disabled') {
      setError('Your account has been disabled. Contact an administrator to be re-enabled.');
    } else if (reason === 'expired') {
      setError('Your session expired — please sign in again.');
    }
  }, []);

  // Determine how the active identity provider wants us to authenticate.
  useEffect(() => {
    let cancelled = false;
    api
      .authFlow()
      .then((res) => {
        if (!cancelled) {
          setFlow((res.flow as Flow) ?? 'password');
          setSupportsPasskey(Boolean(res.supportsPasskey));
        }
      })
      .catch((err) => {
        if (!cancelled) {
          // If we can't determine the flow, fall back to the password form so
          // the user is never locked out.
          setFlow('password');
          setFlowError((err as Error).message);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function handleCredentials(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.login({ username, password });
      setChallengeToken(res.challengeToken);
      // Remember whether the policy says this password must be rotated — we act
      // on it once sign-in (incl. 2FA) has actually completed below.
      setForceChange(Boolean(res.passwordExpired));
    } catch (err) {
      if (err instanceof ApiError && err.code === 'no_2fa_enrolled') {
        setError(
          'Your account requires a second factor that is not enrolled yet. Enroll TOTP or a passkey in My Account, or ask an administrator to adjust your credential policy.'
        );
      } else if (err instanceof ApiError && err.code === 'user_disabled') {
        setError('Your account has been disabled. Contact an administrator to be re-enabled.');
      } else if (err instanceof ApiError && err.code === 'no_interactive_login') {
        setError(
          'This account is service-only and cannot sign in to the web UI. Use its API token instead, or ask an administrator to restore interactive login.'
        );
      } else {
        setError((err as Error).message);
      }
    } finally {
      setLoading(false);
    }
  }

  /** Store the freshly minted session, then either enter the app or (when the
   *  policy flagged an expired password) hold on a forced-change step. */
  function finishSignIn(res: { accessToken: string; permissions?: string[]; username?: string }) {
    localStorage.setItem('accessToken', res.accessToken);
    setPermissions(res.permissions ?? []);
    if (res.username) setUsername(res.username);
    if (forceChange) {
      // Stay on the login screen — the user must rotate their password first.
      return;
    }
    navigate('/devices');
  }

  async function handleForceChange(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      if (newPassword.length < 8) {
        setError('New password must be at least 8 characters.');
        return;
      }
      if (newPassword !== confirmPassword) {
        setError('The two new passwords do not match.');
        return;
      }
      await api.changeOwnPassword({ currentPassword: password, newPassword });
      setForceChange(false);
      navigate('/devices');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  // Passkey (WebAuthn) step-2: fetch assertion options for the pending
  // challenge, run the platform authenticator prompt, verify the response.
  async function handlePasskeySignin() {
    if (!challengeToken) return;
    setError(null);
    setLoading(true);
    try {
      const { options, nonce } = await api.webauthnAssertionOptions(challengeToken);

      let assertion: unknown;
      try {
        assertion = await navigator.credentials.get({
          // Convert base64url challenge/allowCredentials to binary before the prompt.
          publicKey: toRequestOptions(options),
        });
      } catch (credErr) {
        // User cancelled the prompt or no passkey is available on this device.
        const name = credErr instanceof DOMException ? credErr.name : '';
        if (name === 'NotAllowedError') setError('Passkey sign-in was cancelled.');
        else if (name === 'InvalidStateError' || name === 'SecurityError') {
          setError('No passkey is available on this device. Enroll one in My Account, or use your TOTP code.');
        } else {
          setError(`Passkey sign-in failed: ${(credErr as Error).message}`);
        }
        return;
      }

      if (!assertion) {
        setError('No passkey was presented. Try again or use your TOTP code.');
        return;
      }

      const res = await api.verifyWebauthn({ challengeToken, response: assertion, nonce });
      finishSignIn(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  async function handleVerify(e: FormEvent) {
    e.preventDefault();
    if (!challengeToken) return;
    setError(null);
    setLoading(true);
    try {
      const res = await api.verify2fa({ challengeToken, totpCode });
      finishSignIn(res);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  // External flow (OAuth2 / SAML / LDAP web login): ask the API for the URL to
  // redirect the browser to, then navigate there.
  async function handleExternalSignIn() {
    setError(null);
    setLoading(true);
    try {
      const res = await api.authRedirect();
      window.location.assign(res.redirectUrl);
    } catch (err) {
      setError((err as Error).message);
      setLoading(false);
    }
  }

  // Still resolving the flow.
  if (flow === null) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-background">
        <div className="w-full max-w-sm rounded-lg border border-border bg-card p-8 text-center shadow-sm">
          <h1 className="mb-1 text-xl font-bold text-foreground">UnifiedNetworkManager</h1>
          <p className="text-sm text-muted-foreground">Preparing sign-in…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-background">
      <div className="w-full max-w-sm rounded-lg border border-border bg-card p-8 shadow-sm">
        <h1 className="mb-1 text-xl font-bold text-foreground">UnifiedNetworkManager</h1>
        <p className="mb-6 text-sm text-muted-foreground">Sign in to manage your network.</p>

        {flowError && (
          <div className="mb-4 rounded-md border border-warning-border bg-warning px-3 py-2 text-sm text-warning-fg">
            {flowError}
          </div>
        )}

        {error && (
          <div className="mb-4 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">
            {error}
          </div>
        )}

        {flow === 'password' ? (
          forceChange && challengeToken ? (
            // Sign-in completed but the policy flagged an expired password —
            // hold the user here until they set a new one.
            <form className="space-y-4" onSubmit={handleForceChange}>
              <div>
                <h2 className="text-sm font-semibold text-secondary">Password change required</h2>
                <p className="mt-1 text-xs text-faint">
                  Your password has reached its maximum age. Set a new one to continue — your current session is
                  already active, so this only updates the stored credential.
                </p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">New password * (min 8 chars)</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Confirm new password *</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {loading ? 'Saving…' : 'Set new password & continue'}
              </button>
            </form>
          ) : !challengeToken ? (
            <form className="space-y-4" onSubmit={handleCredentials}>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Username</label>
                <input
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Password</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
                {loading ? 'Signing in...' : 'Continue'}
              </button>
            </form>
          ) : (
            <form className="space-y-4" onSubmit={handleVerify}>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">
                  Two-factor authentication code
                </label>
                <input
                  className="w-full rounded-md border border-border px-3 py-2 text-sm tracking-widest focus:border-slate-500 focus:outline-none"
                  value={totpCode}
                  maxLength={6}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="000000"
                />
                <p className="mt-1 text-xs text-faint">
                  Enter the 6-digit code from your authenticator app. Accounts without an
                  enrolled TOTP secret can complete sign-in with any 6-digit value (dev mode only).
                </p>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {loading ? 'Verifying...' : 'Verify & Sign in'}
              </button>
              {supportsPasskey && (
                <>
                  <div className="flex items-center gap-3">
                    <div className="h-px flex-1 bg-muted" />
                    <span className="text-xs uppercase tracking-wide text-faint">or</span>
                    <div className="h-px flex-1 bg-muted" />
                  </div>
                  <button
                    type="button"
                    onClick={handlePasskeySignin}
                    disabled={loading}
                    className="flex w-full items-center justify-center gap-2 rounded-md border border-border bg-card px-3 py-2 text-sm font-semibold text-secondary hover:bg-background disabled:opacity-50"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                    Sign in with passkey
                  </button>
                </>
              )}
              <button
                type="button"
                className="flex w-full items-center justify-center gap-1.5 text-sm text-muted-foreground hover:underline"
                onClick={() => setChallengeToken(null)}
              >
                <ArrowLeft className="h-3.5 w-3.5" />
                Back
              </button>
            </form>
          )
        ) : (
          // External identity provider (OAuth2 / SAML / LDAP web login).
          <div className="space-y-4">
            <p className="text-sm text-secondary">
              This deployment uses an external identity provider. You will be redirected to
              complete sign-in.
            </p>
            <button
              type="button"
              onClick={handleExternalSignIn}
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ExternalLink className="h-4 w-4" />}
              {loading ? 'Redirecting…' : flowLabel(flow)}
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
