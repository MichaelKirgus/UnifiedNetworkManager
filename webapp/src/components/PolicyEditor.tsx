import { useEffect, useState } from 'react';
import type { CredentialPolicy } from '../api/client';

/**
 * Checkbox editor for a credential policy: which 2nd factors are required at
 * login (requiredMethods) and which session AMRs satisfy the privileged-action
 * gate (gateAmrs). Purely presentational — the parent owns fetching/saving.
 */
export function PolicyEditor({
  value,
  onChange,
}: {
  value: CredentialPolicy;
  onChange: (next: Partial<CredentialPolicy>) => void;
}) {
  const [draftRequired, setDraftRequired] = useState<Set<string>>(new Set(value.requiredMethods));
  const [draftGate, setDraftGate] = useState<Set<string>>(new Set(value.gateAmrs));

  // Resync the draft when the saved value changes (after a save round-trip or
  // when the parent switches to another user's policy).
  useEffect(() => {
    setDraftRequired(new Set(value.requiredMethods));
    setDraftGate(new Set(value.gateAmrs));
  }, [value]);

  function toggle(set: Set<string>, key: string, isGate: boolean, apply: (s: Set<string>) => void) {
    const next = new Set(set);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    // gateAmrs must never be empty — the gate would lock out every session.
    if (isGate && next.size === 0) return;
    apply(next);
  }

  // Compare sorted so checkbox order never shows a phantom "dirty" state.
  const requiredChanged = [...draftRequired].sort().join(',') !== value.requiredMethods.slice().sort().join(',');
  const gateChanged = [...draftGate].sort().join(',') !== value.gateAmrs.slice().sort().join(',');
  const dirty = requiredChanged || gateChanged;

  return (
    <div className="space-y-4">
      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-slate-700">Required second factor at login</legend>
        <p className="mb-2 text-xs text-slate-400">
          The user must complete sign-in with one of the enrolled methods below. Leave both unchecked to allow
          password-only sign-in (no 2FA). If none is enrolled, login is blocked until enrollment.
        </p>
        <div className="flex flex-wrap gap-4">
          {(['totp', 'webauthn'] as const).map((m) => (
            <label key={m} className="inline-flex cursor-pointer items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={draftRequired.has(m)}
                onChange={() => {
                  toggle(draftRequired, m, false, setDraftRequired);
                }}
                className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-500"
              />
              {m === 'totp' ? 'Authenticator app (TOTP)' : 'Passkey (WebAuthn)'}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-slate-700">Satisfies the privileged-action gate</legend>
        <p className="mb-2 text-xs text-slate-400">
          Sessions completed with one of these methods may submit configuration jobs and execute plans (the 2FA-gated
          endpoints). At least one must stay checked.
        </p>
        <div className="flex flex-wrap gap-4">
          {(['totp', 'webauthn'] as const).map((m) => (
            <label key={m} className="inline-flex cursor-pointer items-center gap-2 text-sm text-slate-700">
              <input
                type="checkbox"
                checked={draftGate.has(m)}
                onChange={() => {
                  toggle(draftGate, m, true, setDraftGate);
                }}
                className="h-4 w-4 rounded border-slate-300 text-slate-900 focus:ring-slate-500"
              />
              {m === 'totp' ? 'TOTP sessions' : 'Passkey sessions'}
            </label>
          ))}
        </div>
      </fieldset>

      <button
        type="button"
        disabled={!dirty}
        onClick={() =>
          onChange({
            requiredMethods: [...draftRequired].sort() as CredentialPolicy['requiredMethods'],
            gateAmrs: [...draftGate].sort(),
          })
        }
        className="rounded-md bg-slate-900 px-4 py-2 text-sm font-medium text-white hover:bg-slate-700 disabled:opacity-50"
      >
        Save policy
      </button>
    </div>
  );
}
