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
    } catch (err) {
      if (err instanceof ApiError && err.code === 'no_2fa_enrolled') {
        setError(
          'Your account requires a second factor that is not enrolled yet. Enroll TOTP or a passkey in My Account, or ask an administrator to adjust your credential policy.'
        );
      } else {
        setError((err as Error).message);
      }
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
      localStorage.setItem('accessToken', res.accessToken);
      setPermissions(res.permissions ?? []);
      if (res.username) setUsername(res.username);
      navigate('/devices');
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
      localStorage.setItem('accessToken', res.accessToken);
      setPermissions(res.permissions ?? []);
      if (res.username) setUsername(res.username);
      navigate('/devices');
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
      <div className="flex min-h-screen items-center justify-center bg-slate-50">
        <div className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-8 text-center shadow-sm">
          <h1 className="mb-1 text-xl font-bold text-slate-900">UnifiedNetworkManager</h1>
          <p className="text-sm text-slate-500">Preparing sign-in…</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
        <h1 className="mb-1 text-xl font-bold text-slate-900">UnifiedNetworkManager</h1>
        <p className="mb-6 text-sm text-slate-500">Sign in to manage your network.</p>

        {flowError && (
          <div className="mb-4 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-700">
            {flowError}
          </div>
        )}

        {error && (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        {flow === 'password' ? (
          !challengeToken ? (
            <form className="space-y-4" onSubmit={handleCredentials}>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Username</label>
                <input
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  autoComplete="username"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">Password</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm focus:border-slate-500 focus:outline-none"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  autoComplete="current-password"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ArrowRight className="h-4 w-4" />}
                {loading ? 'Signing in...' : 'Continue'}
              </button>
            </form>
          ) : (
            <form className="space-y-4" onSubmit={handleVerify}>
              <div>
                <label className="mb-1 block text-sm font-medium text-slate-700">
                  Two-factor authentication code
                </label>
                <input
                  className="w-full rounded-md border border-slate-300 px-3 py-2 text-sm tracking-widest focus:border-slate-500 focus:outline-none"
                  value={totpCode}
                  maxLength={6}
                  onChange={(e) => setTotpCode(e.target.value)}
                  placeholder="000000"
                />
                <p className="mt-1 text-xs text-slate-400">
                  Enter the 6-digit code from your authenticator app. Accounts without an
                  enrolled TOTP secret can complete sign-in with any 6-digit value (dev mode only).
                </p>
              </div>
              <button
                type="submit"
                disabled={loading}
                className="flex w-full items-center justify-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
                {loading ? 'Verifying...' : 'Verify & Sign in'}
              </button>
              {supportsPasskey && (
                <>
                  <div className="flex items-center gap-3">
                    <div className="h-px flex-1 bg-slate-200" />
                    <span className="text-xs uppercase tracking-wide text-slate-400">or</span>
                    <div className="h-px flex-1 bg-slate-200" />
                  </div>
                  <button
                    type="button"
                    onClick={handlePasskeySignin}
                    disabled={loading}
                    className="flex w-full items-center justify-center gap-2 rounded-md border border-slate-300 bg-white px-3 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-50 disabled:opacity-50"
                  >
                    {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <KeyRound className="h-4 w-4" />}
                    Sign in with passkey
                  </button>
                </>
              )}
              <button
                type="button"
                className="flex w-full items-center justify-center gap-1.5 text-sm text-slate-500 hover:underline"
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
            <p className="text-sm text-slate-600">
              This deployment uses an external identity provider. You will be redirected to
              complete sign-in.
            </p>
            <button
              type="button"
              onClick={handleExternalSignIn}
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
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
