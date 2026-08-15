import { FormEvent, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';

export default function Login() {
  const navigate = useNavigate();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleCredentials(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const res = await api.login({ username, password });
      setChallengeToken(res.challengeToken);
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
      navigate('/devices');
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-50">
      <div className="w-full max-w-sm rounded-lg border border-slate-200 bg-white p-8 shadow-sm">
        <h1 className="mb-1 text-xl font-bold text-slate-900">UnifiedNetworkManager</h1>
        <p className="mb-6 text-sm text-slate-500">Sign in to manage your network.</p>

        {error && (
          <div className="mb-4 rounded-md border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700">
            {error}
          </div>
        )}

        {!challengeToken ? (
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
              className="w-full rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
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
              className="w-full rounded-md bg-slate-900 px-3 py-2 text-sm font-semibold text-white hover:bg-slate-800 disabled:opacity-50"
            >
              {loading ? 'Verifying...' : 'Verify & Sign in'}
            </button>
            <button
              type="button"
              className="w-full text-sm text-slate-500 hover:underline"
              onClick={() => setChallengeToken(null)}
            >
              Back
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
