import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import QRCode from 'react-qr-code';
import { ArchiveRestore, ArrowRight, CalendarClock, CheckCircle2, KeyRound, Loader2, Server, ShieldCheck, Sparkles, Upload, Wand2 } from 'lucide-react';
import { WizardLayout } from '../components/Wizard';
import { PasskeyManager } from '../components/PasskeyManager';
import { TimePreferencesCard } from '../components/TimePreferencesCard';
import { useTimeFormat } from '../utils/time';
import { api, BackupEntry, BackupManifest, SectionMergeReport, TotpEnrollment } from '../api/client';
import { can } from '../auth/permissions';

/**
 * First-run setup wizard for the initial admin account.
 *
 * Triggered automatically (see App.tsx) when the seeded `admin` user signs in
 * and has not yet completed onboarding (`users.onboardedAt IS NULL`). The first
 * sign-in is password-only (no TOTP secret is seeded, so there is nothing to
 * prompt for), which is exactly why this wizard is MANDATORY: it forces a new
 * password AND enrollment of a second factor (TOTP or passkey) before the user
 * can do anything else. There is no Cancel and no Skip — the only way out is to
 * finish, after which `onboardedAt` is stamped and the account's credential
 * policy re-enables 2FA for every future login.
 */

const STEPS = [
  { label: 'Security' },
  { label: 'Instance & display' },
  { label: 'Restore data' },
  { label: 'Auto backup' },
  { label: 'First device' },
  { label: 'Done' },
];

export default function OnboardingPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [step, setStep] = useState(0);

  // Step 1 — password rotation (mandatory).
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmNew, setConfirmNew] = useState('');
  const [pwError, setPwError] = useState<string | null>(null);

  // Step 1 — second factor (mandatory): TOTP confirm or passkey enrollment.
  const [twoFactorDone, setTwoFactorDone] = useState(false);
  const [totpEnrollment, setTotpEnrollment] = useState<TotpEnrollment | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [totpError, setTotpError] = useState<string | null>(null);

  // Step 2 — instance name.
  const meQuery = useQuery({ queryKey: ['me'], queryFn: api.me });
  const [instanceName, setInstanceName] = useState('');
  const [nameTouched, setNameTouched] = useState(false);
  useEffect(() => {
    if (meQuery.data && !nameTouched) setInstanceName(meQuery.data.instanceName ?? 'UnifiedNetworkManager');
  }, [meQuery.data, nameTouched]);

  // Step 3 — optional restore from a previous backup (file upload or stored row).
  const [restoreSource, setRestoreSource] = useState<'none' | 'upload' | 'stored'>('none');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [stagedUpload, setStagedUpload] = useState<{ pendingId: string; manifest: BackupManifest } | null>(null);
  const [restoreBackupId, setRestoreBackupId] = useState('');
  const [selectedSections, setSelectedSections] = useState<Set<string>>(new Set());
  const [restoreError, setRestoreError] = useState<string | null>(null);
  const [restoreReport, setRestoreReport] = useState<SectionMergeReport[] | null>(null);

  // Step 4 — optional scheduled auto-backup.
  const [autoEnabled, setAutoEnabled] = useState(false);
  const [autoInterval, setAutoInterval] = useState(1440);
  const [autoPreset, setAutoPreset] = useState('config');
  const [autoDestination, setAutoDestination] = useState<'local' | 'repo'>('local');
  const [autoProviderId, setAutoProviderId] = useState('');

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
    },
    onError: (err) => setPwError((err as Error).message),
  });

  const enrollTotp = useMutation({
    mutationFn: () => api.enrollTotp(meQuery.data!.id),
    onSuccess: (res) => {
      queryClient.invalidateQueries({ queryKey: ['me'] });
      setTotpEnrollment(res.enrollment);
      setTotpError(null);
    },
    onError: (err) => setTotpError((err as Error).message),
  });

  const confirmTotp = useMutation({
    mutationFn: () => api.confirmTotp(meQuery.data!.id, totpCode.trim()),
    onSuccess: (res) => {
      if (!res.valid) {
        setTotpError('That code did not match. Check the entry in your authenticator app and try again.');
        return;
      }
      setTotpError(null);
      setTwoFactorDone(true);
    },
    onError: (err) => setTotpError((err as Error).message),
  });

  const saveName = useMutation({
    mutationFn: () => api.updateSetting('instanceName', instanceName.trim()),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setStep(2);
    },
  });

  // Step 3 — restore data (optional).
  const backupsQuery = useQuery({ queryKey: ['backups'], queryFn: api.listBackups });
  const providersQuery = useQuery({ queryKey: ['fileRepoProviders'], queryFn: api.repoFileProviders });

  const stageUpload = useMutation({
    mutationFn: (file: File) => api.uploadBackupForRestore(file),
    onSuccess: (res) => {
      setStagedUpload(res);
      setSelectedSections(new Set(Object.keys(res.manifest.sections ?? {})));
      setRestoreError(null);
    },
    onError: (err) => setRestoreError((err as Error).message),
  });

  const applyRestore = useMutation({
    mutationFn: () =>
      api.applyBackupRestore(
        restoreSource === 'upload'
          ? { pendingId: stagedUpload!.pendingId, sections: [...selectedSections] }
          : { backupId: restoreBackupId, sections: [...selectedSections] },
      ),
    onSuccess: (res) => {
      setRestoreReport(res.report);
      setStagedUpload(null); // server deleted the pending file on apply
      setRestoreError(null);
    },
    onError: (err) => setRestoreError((err as Error).message),
  });

  // An un-applied staged upload is discarded when leaving the wizard.
  useEffect(() => {
    const pendingId = stagedUpload?.pendingId;
    return () => {
      if (pendingId) void api.discardPendingRestore(pendingId).catch(() => {});
    };
  }, [stagedUpload]);

  // Step 4 — auto-backup settings (one key per updateSetting call, chained).
  const saveAutoBackup = useMutation({
    mutationFn: async () => {
      await api.updateSetting('autoBackupEnabled', autoEnabled);
      if (autoEnabled) {
        await api.updateSetting('autoBackupIntervalMinutes', autoInterval);
        await api.updateSetting('autoBackupPreset', autoPreset);
        await api.updateSetting('autoBackupDestination', autoDestination);
        await api.updateSetting('autoBackupProviderId', autoDestination === 'repo' ? autoProviderId : '');
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['settings'] });
      setStep(4);
    },
  });

  const completeOnboarding = useMutation({
    mutationFn: () => api.onboardingComplete(),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['me'] }),
  });

  // A second factor already enrolled (e.g. re-running the wizard after a prior
  // partial setup) satisfies the requirement without re-enrolling.
  useEffect(() => {
    if (!twoFactorDone && meQuery.data && (meQuery.data.totpEnabled || (meQuery.data.passkeyCount ?? 0) > 0)) setTwoFactorDone(true);
  }, [meQuery.data, twoFactorDone]);

  const { formatDateTime } = useTimeFormat();

  /** Parse a stored backup's sections (JSON string or array, depending on the row). */
  function sectionsOf(b: BackupEntry): string[] {
    if (Array.isArray(b.sections)) return b.sections;
    try {
      const v = JSON.parse(b.sections);
      return Array.isArray(v) ? v.filter((s) => typeof s === 'string') : [];
    } catch {
      return [];
    }
  }

  const me = meQuery.data;
  if (!me) return null; // guard + data not ready yet

  const canWriteSettings = can('system:write');
  const hasBackupPermission = can('instance:backup');

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

  /** Finish + leave the wizard (used by "Register a device now" and Done). */
  function finishAndExit(to: string) {
    completeOnboarding.mutate(undefined, { onSuccess: () => navigate(to, { replace: true }) });
  }

  const passwordChanged = changePassword.isSuccess;
  const securityComplete = passwordChanged && twoFactorDone;

  return (
    <WizardLayout
      title="Setup"
      icon={<Wand2 className="h-5 w-5 text-primary" />}
      steps={STEPS}
      current={step}
      onExit={() => navigate('/', { replace: true })}
      hideCancel
    >
      {/* ---------------------------------------------------------- Step 1 */}
      {step === 0 && (
        <div className="space-y-5">
          {/* Password rotation — mandatory. */}
          <div className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
              <KeyRound className="h-4 w-4 text-primary" /> Set a strong password
            </h2>
            <p className="mt-1 text-sm text-secondary">
              You signed in with the default credentials. Choose a new password before you start managing devices — this
              step is required.
            </p>

            {passwordChanged ? (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-success-border bg-success/10 px-3 py-2 text-sm text-success">
                <CheckCircle2 className="h-4 w-4" /> Password updated.
              </div>
            ) : (
              <>
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
                  <button
                    type="submit"
                    disabled={changePassword.isPending || !currentPassword || newPassword.length < 8 || newPassword !== confirmNew}
                    className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                  >
                    {changePassword.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                    Set password
                  </button>
                </form>
              </>
            )}
          </div>

          {/* Second factor — mandatory (TOTP or passkey). */}
          <div className="rounded-md border border-border bg-card p-4 shadow-sm">
            <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
              <ShieldCheck className="h-4 w-4 text-primary" /> Add a second factor
            </h2>
            <p className="mt-1 text-sm text-secondary">
              Two-factor authentication is required before you can continue. Enroll an authenticator app (TOTP) or a
              passkey — either one works for signing in from now on.
            </p>

            {twoFactorDone ? (
              <div className="mt-3 flex items-center gap-2 rounded-md border border-success-border bg-success/10 px-3 py-2 text-sm text-success">
                <CheckCircle2 className="h-4 w-4" /> Second factor enrolled — you&apos;re protected.
              </div>
            ) : (
              <div className="mt-4 space-y-5">
                {/* TOTP path */}
                {!totpEnrollment ? (
                  <button
                    type="button"
                    disabled={enrollTotp.isPending}
                    onClick={() => enrollTotp.mutate()}
                    className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                  >
                    {enrollTotp.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                    Enroll authenticator app (TOTP) — show QR code
                  </button>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm text-secondary">Scan this QR code with your authenticator app, then enter the 6-digit code it shows to confirm.</p>
                    <div className="flex flex-col items-start gap-4 sm:flex-row">
                      <div className="rounded-md border border-border bg-card p-3">
                        <QRCode value={totpEnrollment.otpauthUri} size={150} />
                      </div>
                      <div className="w-full space-y-2">
                        <label className="mb-1 block text-sm font-medium text-secondary">6-digit code</label>
                        <input
                          className="w-full rounded-md border border-border px-3 py-2 text-sm tracking-widest focus:border-focus-ring focus:outline-none"
                          value={totpCode}
                          maxLength={6}
                          inputMode="numeric"
                          onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ''))}
                          placeholder="000000"
                        />
                        <button
                          type="button"
                          disabled={confirmTotp.isPending || totpCode.length !== 6}
                          onClick={() => confirmTotp.mutate()}
                          className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                        >
                          {confirmTotp.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                          Confirm code
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {totpError && (
                  <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{totpError}</div>
                )}

                {/* Passkey path */}
                <div className="border-t border-border pt-4">
                  <h3 className="text-sm font-semibold text-secondary">Or add a passkey</h3>
                  <p className="mb-2 mt-1 text-xs text-faint">Use your device&apos;s built-in authenticator instead of an app.</p>
                  <PasskeyManager userId={me.id} username={me.username} />
                </div>
              </div>
            )}
          </div>

          {/* Advance — only once BOTH password and 2FA are done. */}
          <button
            type="button"
            disabled={!securityComplete || completeOnboarding.isPending}
            onClick={() => setStep(1)}
            className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            Continue <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* ---------------------------------------------------------- Step 2 */}
      {step === 1 && (
        <div className="space-y-5">
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

        {/* Date & time display — the same self-service card as on My Account. */}
        <TimePreferencesCard />
        </div>
      )}

      {/* ---------------------------------------------------------- Step 3 */}
      {step === 2 && (
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <ArchiveRestore className="h-4 w-4 text-primary" /> Restore from a previous backup
          </h2>
          <p className="mt-1 text-sm text-secondary">
            This instance is new — if you have an archive from another UNM (or an earlier install), restore it now. You can
            also do this any time later from the Backups page.
          </p>

          {restoreReport ? (
            <div className="mt-4 space-y-3">
              <div className="flex items-center gap-2 rounded-md border border-success-border bg-success/10 px-3 py-2 text-sm text-success">
                <CheckCircle2 className="h-4 w-4" /> Restore complete — the selected sections were merged into this instance.
              </div>
              <table className="w-full text-left text-sm">
                <thead>
                  <tr className="border-b border-border text-xs uppercase tracking-wide text-faint">
                    <th className="py-1.5 pr-3">Section</th>
                    <th className="py-1.5 pr-3">Tables</th>
                    <th className="py-1.5 pr-3">Created</th>
                    <th className="py-1.5">Updated</th>
                  </tr>
                </thead>
                <tbody>
                  {restoreReport.map((r) => (
                    <tr key={r.section} className="border-b border-border/50">
                      <td className="py-1.5 pr-3 font-medium text-secondary">{r.section}</td>
                      <td className="py-1.5 pr-3 tabular-nums text-faint">{r.tables.length}</td>
                      <td className="py-1.5 pr-3 tabular-nums text-success">{r.tables.reduce((s, t) => s + t.created, 0)}</td>
                      <td className="py-1.5 tabular-nums text-secondary">{r.tables.reduce((s, t) => s + t.updated, 0)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {restoreReport.some((r) => r.warnings.length > 0) && (
                <ul className="list-inside list-disc text-xs text-warning">
                  {restoreReport.flatMap((r) => r.warnings).map((w, i) => (<li key={i}>{w}</li>))}
                </ul>
              )}
              <button
                type="button"
                onClick={() => setStep(3)}
                className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
              >
                Continue <ArrowRight className="h-4 w-4" />
              </button>
            </div>
          ) : (
            <div className="mt-4 space-y-4">
              {/* Source picker */}
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                {([
                  { value: 'none', label: 'Start fresh', hint: 'No restore — continue with an empty instance' },
                  { value: 'upload', label: 'Upload a file', hint: 'A .unmbak.gz archive from another UNM' },
                  { value: 'stored', label: 'Stored backup', hint: 'An archive already on this instance (volume or file repo)' },
                ] as const).map((opt) => (
                  <label
                    key={opt.value}
                    className={`flex cursor-pointer flex-col gap-0.5 rounded-md border px-3 py-2 text-sm transition-colors ${
                      restoreSource === opt.value ? 'border-primary bg-muted' : 'border-border hover:bg-muted/50'
                    }`}
                  >
                    <span className="flex items-center gap-2 font-medium text-secondary">
                      <input
                        type="radio"
                        name="restore-source"
                        checked={restoreSource === opt.value}
                        onChange={() => {
                          setRestoreSource(opt.value);
                          setSelectedSections(new Set());
                          setRestoreError(null);
                        }}
                        className="accent-[var(--color-primary)]"
                      />
                      {opt.label}
                    </span>
                    <span className="pl-5 text-xs text-faint">{opt.hint}</span>
                  </label>
                ))}
              </div>

              {/* Upload path */}
              {restoreSource === 'upload' && (
                <div className="space-y-3">
                  {!stagedUpload ? (
                    <button
                      type="button"
                      disabled={stageUpload.isPending || !hasBackupPermission}
                      onClick={() => fileInputRef.current?.click()}
                      className="flex items-center gap-2 rounded-md border border-dashed border-border bg-muted/40 px-3 py-2 text-sm font-medium text-secondary hover:bg-muted disabled:opacity-50"
                    >
                      <Upload className="h-4 w-4" />
                      {stageUpload.isPending ? 'Reading archive…' : 'Choose a .unmbak.gz file'}
                    </button>
                  ) : (
                    <div className="space-y-2 rounded-md border border-border bg-muted/30 p-3">
                      <p className="text-sm font-medium text-secondary">
                        {stagedUpload.manifest.instanceName ?? 'Unknown instance'} · exported{' '}
                        {formatDateTime(stagedUpload.manifest.exportedAt)}
                      </p>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(stagedUpload.manifest.sections ?? {}).map(([key, info]) => (
                          <label key={key} className="flex cursor-pointer items-center gap-1.5 rounded-md border border-border bg-card px-2 py-1 text-xs font-medium text-secondary">
                            <input
                              type="checkbox"
                              checked={selectedSections.has(key)}
                              onChange={(e) => {
                                const next = new Set(selectedSections);
                                if (e.target.checked) next.add(key); else next.delete(key);
                                setSelectedSections(next);
                              }}
                              className="accent-[var(--color-primary)]"
                            />
                            {key} <span className="text-faint">({info.rowCount})</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  )}
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".unmbak.gz,.gz,application/gzip"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) stageUpload.mutate(f);
                      e.target.value = '';
                    }}
                  />
                </div>
              )}

              {/* Stored-backup path */}
              {restoreSource === 'stored' && (
                <div className="space-y-2">
                  {(backupsQuery.data?.backups ?? []).length === 0 ? (
                    <p className="rounded-md border border-border bg-muted px-3 py-2 text-sm text-faint">
                      No stored backups on this instance yet — pick “Upload a file” instead.
                    </p>
                  ) : (
                    (backupsQuery.data?.backups ?? []).slice(0, 10).map((b) => {
                      const secs = sectionsOf(b);
                      return (
                        <label
                          key={b.id}
                          className={`flex cursor-pointer flex-wrap items-center gap-x-3 gap-y-1 rounded-md border px-3 py-2 text-sm transition-colors ${
                            restoreBackupId === b.id ? 'border-primary bg-muted' : 'border-border hover:bg-muted/50'
                          }`}
                        >
                          <input
                            type="radio"
                            name="restore-stored"
                            checked={restoreBackupId === b.id}
                            onChange={() => {
                              setRestoreBackupId(b.id);
                              setSelectedSections(new Set(secs));
                              setRestoreError(null);
                            }}
                            className="accent-[var(--color-primary)]"
                          />
                          <span className="font-medium text-secondary">{b.name}</span>
                          <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-faint">{b.scope}</span>
                          <span className="text-xs tabular-nums text-faint">{(Number(b.sizeBytes) / 1024).toFixed(0)} KiB</span>
                          <span className="text-xs text-faint">{formatDateTime(b.createdAt)}</span>
                          {b.source === 'repo' && b.providerName ? (
                            <span className="rounded bg-muted px-1.5 py-0.5 text-xs text-faint">{b.providerName}</span>
                          ) : null}
                        </label>
                      );
                    })
                  )}
                </div>
              )}

              {restoreError && (
                <div className="rounded-md border border-danger-border bg-danger px-3 py-2 text-sm text-danger-fg">{restoreError}</div>
              )}

              <div className="flex items-center gap-4">
                <button
                  type="button"
                  disabled={
                    applyRestore.isPending || !hasBackupPermission || restoreSource === 'none' || selectedSections.size === 0
                  }
                  onClick={() => applyRestore.mutate()}
                  className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
                >
                  {applyRestore.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                  Apply restore
                </button>
                <button type="button" onClick={() => setStep(3)} className="text-sm text-secondary underline-offset-2 hover:underline">
                  Skip →
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ---------------------------------------------------------- Step 4 */}
      {step === 3 && (
        <div className="rounded-md border border-border bg-card p-4 shadow-sm">
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <CalendarClock className="h-4 w-4 text-primary" /> Scheduled auto-backups
          </h2>
          <p className="mt-1 text-sm text-secondary">
            Optionally let UNM create a backup automatically on an interval — stored on the local volume or in a file-repo
            instance. You can change this any time from Settings.
          </p>

          <label className="mt-4 flex cursor-pointer items-center gap-2 text-sm font-medium text-secondary">
            <input
              type="checkbox"
              checked={autoEnabled}
              onChange={(e) => setAutoEnabled(e.target.checked)}
              className="accent-[var(--color-primary)]"
            />
            Enable scheduled backups
          </label>

          {autoEnabled && (
            <div className="mt-4 grid grid-cols-1 gap-6 sm:grid-cols-3">
              {/* Interval */}
              <div className="space-y-2">
                <span className="block text-sm font-semibold text-secondary">Interval</span>
                <select
                  value={autoInterval}
                  onChange={(e) => setAutoInterval(Number(e.target.value))}
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                >
                  <option value={60}>Every hour</option>
                  <option value={360}>Every 6 hours</option>
                  <option value={720}>Every 12 hours</option>
                  <option value={1440}>Daily</option>
                  <option value={4320}>Weekly</option>
                </select>
              </div>

              {/* Preset */}
              <div className="space-y-1.5">
                <span className="block text-sm font-semibold text-secondary">What to back up</span>
                {([
                  { value: 'config', label: 'Config', hint: 'Identity, settings & devices' },
                  { value: 'planned', label: 'Planned', hint: 'Documented networks/hosts + plans' },
                  { value: 'all', label: 'All', hint: 'Everything incl. live inventory' },
                ] as const).map((opt) => (
                  <label key={opt.value} className={`flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors ${autoPreset === opt.value ? 'border-primary bg-muted' : 'border-border hover:bg-muted/50'}`}>
                    <input type="radio" name="auto-preset" checked={autoPreset === opt.value} onChange={() => setAutoPreset(opt.value)} className="accent-[var(--color-primary)]" />
                    <span className="font-medium text-secondary">{opt.label}</span>
                    <span className="text-xs text-faint">{opt.hint}</span>
                  </label>
                ))}
              </div>

              {/* Destination */}
              <div className="space-y-2">
                <span className="block text-sm font-semibold text-secondary">Destination</span>
                {([
                  { value: 'local', label: 'Local volume (unm-backups)' },
                  { value: 'repo', label: 'File-repo instance' },
                ] as const).map((opt) => (
                  <label key={opt.value} className={`flex cursor-pointer items-center gap-2 rounded-md border px-3 py-1.5 text-sm transition-colors ${autoDestination === opt.value ? 'border-primary bg-muted' : 'border-border hover:bg-muted/50'}`}>
                    <input type="radio" name="auto-destination" checked={autoDestination === opt.value} onChange={() => setAutoDestination(opt.value)} className="accent-[var(--color-primary)]" />
                    <span className="font-medium text-secondary">{opt.label}</span>
                  </label>
                ))}
                {autoDestination === 'repo' && (
                  (providersQuery.data?.providers ?? []).filter((p) => p.online).length > 0 ? (
                    <select
                      value={autoProviderId}
                      onChange={(e) => setAutoProviderId(e.target.value)}
                      className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm focus:border-focus-ring focus:outline-none"
                    >
                      <option value="">Choose an instance…</option>
                      {(providersQuery.data?.providers ?? []).filter((p) => p.online).map((p) => (
                        <option key={p.id} value={p.id}>{p.name}</option>
                      ))}
                    </select>
                  ) : (
                    <p className="text-xs text-faint">No online file-repo instance is registered — pick the local volume or register one first.</p>
                  )
                )}
              </div>
            </div>
          )}

          <div className="mt-5 flex items-center gap-4">
            <button
              type="button"
              disabled={saveAutoBackup.isPending || (autoEnabled && autoDestination === 'repo' && !autoProviderId)}
              onClick={() => saveAutoBackup.mutate()}
              className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              {saveAutoBackup.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
              Save &amp; continue
            </button>
            <button type="button" onClick={() => setStep(4)} className="text-sm text-secondary underline-offset-2 hover:underline">
              Skip →
            </button>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------- Step 5 */}
      {step === 4 && (
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
              onClick={() => finishAndExit('/devices?new=1')}
              disabled={completeOnboarding.isPending}
              className="flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
            >
              <Server className="h-4 w-4" /> Register a device now
            </button>
            <button type="button" onClick={() => setStep(5)} className="text-sm text-secondary underline-offset-2 hover:underline">
              Set up later →
            </button>
          </div>
        </div>
      )}

      {/* ---------------------------------------------------------- Step 6 */}
      {step === 5 && (
        <div className="space-y-5">
          <div className="rounded-md border border-success-border bg-success/10 p-4 text-sm text-success">
            <CheckCircle2 className="mb-1 h-5 w-5" /> You&apos;re all set. Your account is secured and your instance is ready to manage devices.
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
            onClick={() => finishAndExit('/')}
            disabled={completeOnboarding.isPending}
            className="flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-white hover:bg-primary-hover disabled:opacity-50"
          >
            {completeOnboarding.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
            Go to dashboard <ArrowRight className="h-4 w-4" />
          </button>
        </div>
      )}
    </WizardLayout>
  );
}
