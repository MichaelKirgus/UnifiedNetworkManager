import { useEffect, useState } from 'react';
import clsx from 'clsx';
import { KeyRound, Loader2 } from 'lucide-react';
import { api, SessionCredentialCandidate, SessionPurpose } from '../api/client';
import { ResizableDialog } from './ResizableDialog';

/**
 * Credential picker for interactive sessions (SSH console / SFTP file access).
 *
 * Shown when the API answers a session-open with 409 `credential_selection_required`
 * — i.e. the user has MORE THAN ONE eligible secret and no stored default for this
 * device+purpose. The list comes from GET /devices/:id/session-credentials (the
 * caller may pass the candidates already carried by the error to skip a round-trip).
 *
 * "Remember as my default" persists an ORDERED preference via PUT — first entry is
 * auto-used on future sessions, so the picker only appears when the user changes
 * their mind or adds new credentials.
 */

export interface CredentialPickerProps {
  deviceId: string;
  purpose: SessionPurpose;
  /** Candidates carried by the triggering error (skips a fresh fetch). */
  initialCandidates?: SessionCredentialCandidate[];
  /** The stored default among them, if any. */
  initialDefaultId?: string | null;
  title?: string;
  subtitle?: string;
  /** Called with the chosen secret id + whether to persist it as the device default. */
  onPick: (secretId: string, rememberAsDefault: boolean) => void;
  onClose: () => void;
}

/** Human label for a purpose (used in copy). */
function purposeText(purpose: SessionPurpose): string {
  return purpose === 'console' ? 'SSH console session' : 'file-access session';
}

export function CredentialPicker({
  deviceId,
  purpose,
  initialCandidates,
  initialDefaultId,
  title,
  subtitle,
  onPick,
  onClose,
}: CredentialPickerProps) {
  const [candidates, setCandidates] = useState<SessionCredentialCandidate[] | null>(initialCandidates ?? null);
  const [defaultId, setDefaultId] = useState<string | null>(initialDefaultId ?? null);
  const [selected, setSelected] = useState<string>('');
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  // No candidates handed in → fetch the current options (also yields the default).
  useEffect(() => {
    if (initialCandidates && initialCandidates.length > 0) return;
    let disposed = false;
    api
      .sessionCredentials(deviceId, purpose)
      .then((o) => {
        if (disposed) return;
        setCandidates(o.candidates);
        setDefaultId(o.defaultSecretId);
        setSelected((s) => s || o.defaultSecretId || o.candidates[0]?.id || '');
      })
      .catch((err) => !disposed && setError(err instanceof Error ? err.message : String(err)));
    return () => {
      disposed = true;
    };
  }, [deviceId, purpose, initialCandidates]);

  // Preselect: stored default first, else the first candidate.
  useEffect(() => {
    if (!candidates) return;
    setSelected((s) => (s && candidates.some((c) => c.id === s) ? s : defaultId || candidates[0]?.id || ''));
  }, [candidates, defaultId]);

  const submit = async () => {
    if (!selected || saving) return;
    setSaving(true);
    try {
      if (remember && selected !== defaultId) {
        // Persist the ordered preference: chosen first, then the rest in list order.
        const rest = candidates?.filter((c) => c.id !== selected).map((c) => c.id) ?? [];
        await api.setSessionCredentials(deviceId, purpose, [selected, ...rest]);
      }
      onPick(selected, remember);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  };

  return (
    <ResizableDialog
      title={title ?? 'Choose a credential'}
      subtitle={subtitle}
      icon={<KeyRound size={16} />}
      onClose={onClose}
      defaultSize={{ w: 520, h: 480 }}
      footer={
        <div className="flex items-center justify-between gap-3">
          <label className="flex cursor-pointer items-center gap-2 text-xs text-secondary">
            <input type="checkbox" checked={remember} onChange={(e) => setRemember(e.target.checked)} />
            Remember as my default for this device
          </label>
          <div className="flex items-center gap-2">
            <button type="button" onClick={onClose} className="rounded border border-border px-3 py-1.5 text-xs font-semibold hover:bg-muted">
              Cancel
            </button>
            <button
              type="button"
              disabled={!selected || saving}
              onClick={() => void submit()}
              className="flex items-center gap-1.5 rounded bg-primary px-3 py-1.5 text-xs font-semibold text-white hover:bg-primary/90 disabled:opacity-50"
            >
              {saving && <Loader2 size={12} className="animate-spin" />}
              Connect with this credential
            </button>
          </div>
        </div>
      }
    >
      {error && (
        <div className="mb-3 rounded border border-danger-border bg-danger px-3 py-2 text-sm text-white">{error}</div>
      )}

      {!candidates ? (
        <div className="flex items-center justify-center gap-2 py-10 text-sm text-secondary">
          <Loader2 size={16} className="animate-spin" /> Loading available credentials…
        </div>
      ) : candidates.length === 0 ? (
        <div className="py-8 text-center text-sm text-secondary">
          No credential is available for {purposeText(purpose)} on this device. Create a username/password or SSH key-pair
          secret with the matching usage flag enabled on the Secrets page — or ask an administrator to provide one.
        </div>
      ) : (
        <div className="space-y-1.5">
          <p className="mb-2 text-xs text-secondary">
            Several credentials are available for this {purposeText(purpose)}. Pick which one to use — the choice is only
            used for THIS session{remember ? ' and saved as your default' : ''}.
          </p>
          {candidates.map((c) => (
            <label
              key={c.id}
              className={clsx(
                'flex cursor-pointer items-center gap-3 rounded border px-3 py-2 transition-colors',
                selected === c.id ? 'border-primary bg-primary/5' : 'border-border hover:bg-muted'
              )}
            >
              <input type="radio" name="session-credential" checked={selected === c.id} onChange={() => setSelected(c.id)} />
              <span className="min-w-0 flex-1">
                <span className="block truncate text-sm font-medium">{c.label || c.id}</span>
                <span className="block text-[11px] text-secondary capitalize">{c.type.replace(/([A-Z])/g, ' $1').trim()}</span>
              </span>
              {defaultId === c.id && (
                <span className="rounded-full bg-muted px-2 py-0.5 text-[10px] font-semibold text-secondary">current default</span>
              )}
              {!c.own && (
                <span title="Provided by an administrator" className="rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-semibold text-indigo-800">
                  shared
                </span>
              )}
            </label>
          ))}
        </div>
      )}
    </ResizableDialog>
  );
}
