import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { ArrowRight, CheckCircle2, KeyRound, Loader2, Server, Sparkles, Wand2 } from 'lucide-react';
import { WizardLayout } from '../components/Wizard';
import { PasskeyManager } from '../components/PasskeyManager';
import { api } from '../api/client';
import { can } from '../auth/permissions';

/**
 * First-run setup wizard for the initial admin account.
 *
 * Triggered automatically (see App.tsx) when the seeded `admin` user signs in
 * and has not yet completed onboarding (`users.onboardedAt IS NULL`). Walks
 * through securing the default credentials, naming the instance, and pointing
 * at a first device — then stamps `onboardedAt` so it never re-appears. The
 * built-in "Cancel" leaves without completing (so it can prompt again); the
 * top-bar "Skip setup" completes + exits immediately.
 */

const STEPS = [
  { label: 'Security' },
  { label: 'Instance name' },
  { label: 'First device' },
  { label: 'Done' },
];

export default function OnboardingPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);

  // Step 1 — password rotation.
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNew, setConfirmNew] = useState('');
  const [pwError, setPwError] = useState<string | null>(null);

  // Step 2 — instance name.
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });
  const [instanceName, setInstanceName] = useState('');
  const [nameTouched, setNameTouched] = useState(false);
  useEffect(() => {
    if (meQuery.data && !nameTouched) setInstanceName(meQuery.data.instanceName ?? 'UnifiedNetworkManager');
  }, [meQuery.data, nameTouched]);

  // Non-admins should not be here — bounce to the app.
  useEffect(() => {
    if (meQuery.data && meQuery.data.username !== 'admin') navigate('/', { replace: true });
  }, [meQuery.data, navigate]);

  const changePassword = useMutation({
    mutationFn: () => api.changeOwnPassword({ currentPassword, newPassword }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setPwError(null);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmNew('');
      setStep(1);
    },
    onError: (err) => setPwError((err as Error).message),
  });

  const saveName = useMutation({
    mutationFn: () => api.updateSetting('instanceName', instanceName.trim()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setStep(2);
    },
  });

  const completeOnboarding = useMutation({
    mutationFn: () => api.onboardingComplete(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
  });

  /** Finish + leave the wizard (used by "Skip setup" and the Done step). */
  function finishAndExit() {
    completeOnboarding.mutate(undefined, {
      onSuccess: () => navigate('/', { replace: true }),
    });
  }

  const me = meQuery.data;
  if (!me) return null; // guard + data not ready yet

  const canWriteSettings = can('system:write');

  function handlePasswordSubmit(e: React.FormEvent) {
    e.preventDefault();
    setPwError(null);
    if (newPassword.length < 8) {
      setPwError('New password must be at least 8 characters.');
      return;
    }
    if (newPassword !== confirmNew) {
      setPwError('The two new passwords do not match.');
      return;
    }
    changePassword.mutate();
  }

  function handleNameSubmit(e: React.FormEvent) {
    e.preventDefault();
    const v = instanceName.trim();
    if (!v || v.length > 64) return;
    saveName.mutate();
  }

  return (
    <WizardLayout
      title="Setup"
      icon={<Wand2 className="h-5 w-5 text-primary" />}
      steps={STEPS}
      current={step}
      onExit={() => navigate('/', { replace: true })}
      actions={
        <button
          type="button"
          onClick={finishAndExit}
          disabled={completeOnboarding.isPending}
          className="flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50"
        >
          {completeOnboarding.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
          Skip setup
        </button>
      }
    >
      {/* ---------------------------------------------------------- Step 1 */}
      {step === 0 && (
        <div className="space-y-5">
          <div className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
              <KeyRound className="h-4 w-4 text-primary" /> Secure your account
            </h2>
            <p className="mt-1 text-sm text-secondary">
              You signed in with the default credentials. Set a strong password before you start managing devices — this is
              the one step we strongly recommend not skipping.
            </p>

            {me.totpEnabled && (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-success-border bg-success/10 px-3 py-2 text-sm text-success">
                <CheckCircle2 className="h-4 w-4" /> Two-factor authentication is enrolled — you used it to sign in.
              </div>
            )}

            {pwError && (
              <div className="mt-3 rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{pwError}</div>
            )}

            <form className="mt-4 space-y-3" onSubmit={handlePasswordSubmit}>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Current password</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  autoComplete="current-password"
                />
                <p className="mt-1 text-xs text-faint">The default password is <code>admin</code>.</p>
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">New password (min 8 chars)</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Confirm new password</label>
                <input
                  type="password"
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                  value={confirmNew}
                  onChange={(e) => setConfirmNew(e.target.value)}
                  autoComplete="new-password"
                />
              </div>
              <div className="flex items-center gap-4">
                <button
                  type="submit"
                  disabled={changePassword.isPending || !currentPassword}
                  className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                >
                  {changePassword.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Set password & continue
                </button>
                <button type="button" onClick={() => setStep(1)} className="text-sm text-secondary underline-offset-2 hover:underline">
                  I&apos;ll handle my password later →
                </button>
              </div>
            </form>
          </div>

          {/* Optional passkey enrollment — reuses the shared manager. */}
          <div className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h3 className="text-sm font-semibold text-secondary">Passkeys (optional)</h3>
            <p className="mb-2 mt-1 text-xs text-faint">Add a platform passkey for faster, phishing-resistant sign-in.</p>
            <PasskeyManager userId={me.id} username={me.username} />
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------- Step 2 */}
      {step === 1 && (
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <Sparkles className="h-4 w-4 text-primary" /> Name this instance
          </h2>
          <p className="mt-1 text-sm text-secondary">
            This label appears in the browser tab title and helps you tell instances apart when several are open side by side.
          </p>

          {canWriteSettings ? (
            <form className="mt-4 space-y-3" onSubmit={handleNameSubmit}>
              <div>
                <label className="mb-1 block text-sm font-medium text-secondary">Instance name</label>
                <input
                  type="text"
                  maxLength={64}
                  className="w-full rounded-md border border-border px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                  value={instanceName}
                  onChange={(e) => {
                    setInstanceName(e.target.value);
                    setNameTouched(true);
                  }}
                />
              </div>
              <div className="flex items-center gap-4">
                <button
                  type="submit"
                  disabled={saveName.isPending || !instanceName.trim()}
                  className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                >
                  {saveName.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Save & continue
                </button>
                <button type="button" onClick={() => setStep(2)} className="text-sm text-secondary underline-offset-2 hover:underline">
                  Skip →
                </button>
              </div>
            </form>
          ) : (
            <div className="mt-4 space-y-3">
              <p className="rounded-md border border-border bg-muted px-3 py-2 text-sm text-secondary">
                You don&apos;t have permission to change system settings, so the instance name stays as-is.
              </p>
              <button
                type="button"
                onClick={() => setStep(2)}
                className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover"
              >
                Continue <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------------- Step 3 */}
      {step === 2 && (
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <Server className="h-4 w-4 text-primary" /> Register your first device
          </h2>
          <p className="mt-1 text-sm text-secondary">
            UNM works by polling devices through plugins. Add the first appliance you want to monitor — or come back to it
            any time from the Devices page.
          </p>
          <div className="mt-4 flex items-center gap-4">
            <button
              type="button"
              onClick={() => {
                completeOnboarding.mutate(undefined, { onSuccess: () => navigate('/devices?new=1', { replace: true }) });
              }}
              disabled={completeOnboarding.isPending}
              className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              <Server className="h-4 w-4" /> Register a device now
            </button>
            <button type="button" onClick={() => setStep(3)} className="text-sm text-secondary underline-offset-2 hover:underline">
              Set up later →
            </button>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------- Step 4 */}
      {step === 3 && (
        <div className="space-y-5">
          <div className="rounded-md border border-success-border bg-success/10 p-4 text-sm text-success">
            <CheckCircle2 className="mb-1 h-5 w-5" /> You&apos;re all set. Your instance is ready to manage devices.
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {[
              { label: 'Devices', desc: 'Register & monitor appliances', to: '/devices' },
              { label: 'Plugins', desc: 'See what UNM can talk to', to: '/plugins' },
              { label: 'Settings', desc: 'Tune retention, sessions & more', to: '/settings' },
            ].map((c) => (
              <button
                key={c.to}
                type="button"
                onClick={() => navigate(c.to)}
                className="rounded-md border border-border bg-card p-3 text-left shadow-sm transition-colors hover:bg-muted"
              >
                <div className="text-sm font-semibold text-foreground">{c.label}</div>
                <div className="mt-0.5 text-xs text-faint">{c.desc}</div>
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => navigate('/', { replace: true })}
            className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover"
          >
            Go to dashboard <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </WizardLayout>
  );
}
