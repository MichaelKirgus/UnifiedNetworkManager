import { useEffect, useState } from 'react';
import type { CredentialPolicy } from '../api/client';

/**
 * Editor for a credential policy: which 2nd factors are required at login
 * (requiredMethods), which session AMRs satisfy the privileged-action gate
 * (gateAmrs), plus the password/session rules — minimum length, forced rotation
 * after N days, auto-disable after N idle days, and a per-user session-timeout cap.
 *
 * Purely presentational — the parent owns fetching/saving. Two modes:
 *   - `global`  (no `override` prop): edits the global default row directly; an
 *     empty numeric field means "unset" (built-in default / rule off).
 *   - `perUser`: edits a user's EFFECTIVE policy. Saving stores it as the full
 *     override row, so inherited values are sent explicitly and the result
 *     matches what was shown. An empty numeric field means "inherit global".
 */

type NumField = 'minPasswordLength' | 'passwordMaxAgeDays' | 'inactiveDisableAfterDays' | 'sessionTimeoutSeconds';

const NUM_FIELDS: { key: NumField; label: string; unit: string; hint: (mode: Mode) => string }[] = [
  {
    key: 'minPasswordLength',
    label: 'Minimum password length',
    unit: 'chars',
    hint: () => 'Applies to every new or reset password. Leave empty for the built-in default of 8.',
  },
  {
    key: 'passwordMaxAgeDays',
    label: 'Force password change after',
    unit: 'days',
    hint: (m) =>
      m === 'perUser'
        ? 'Users must set a new password at their next login once it is older than this. Leave empty to inherit the global rule.'
        : 'Users must set a new password at their next login once it is older than this. Leave empty to turn forced rotation off.',
  },
  {
    key: 'inactiveDisableAfterDays',
    label: 'Auto-disable after inactivity',
    unit: 'days',
    hint: (m) =>
      m === 'perUser'
        ? 'The account is disabled if the user has not logged on for this long. Leave empty to inherit the global rule.'
        : 'Accounts are disabled automatically when a user has not logged on for this long. Leave empty to turn auto-disable off.',
  },
  {
    key: 'sessionTimeoutSeconds',
    label: 'Session timeout override',
    unit: 's',
    hint: (m) =>
      m === 'perUser'
        ? "Caps THIS user's session lifetime below the global setting (they get logged out sooner). Leave empty to inherit the global timeout."
        : "Caps this user's session lifetime below the global setting. Must be at least 300 s and shorter than the global timeout to have any effect.",
  },
];

type Mode = 'global' | 'perUser';

export function PolicyEditor({
  value,
  override,
  onChange,
}: {
  /** The effective policy (what is actually in force). */
  value: CredentialPolicy;
  /** The raw per-user override row — present only when editing a user's policy. */
  override?: CredentialPolicy | null;
  /** Persist the edited policy (the full desired effective policy). */
  onChange: (next: Partial<CredentialPolicy>) => void;
}) {
  const mode: Mode = override === undefined ? 'global' : 'perUser';

  const [draftRequired, setDraftRequired] = useState<Set<string>>(new Set(value.requiredMethods));
  const [draftGate, setDraftGate] = useState<Set<string>>(new Set(value.gateAmrs));
  // Numeric drafts use '' for "unset/inherit" and a string of the number otherwise.
  const [draftNums, setDraftNums] = useState<Record<NumField, string>>(emptyNums());
  // Session-extension kill switch (true by default — pre-migration rows allow it).
  const [draftAllowExtension, setDraftAllowExtension] = useState(true);

  function emptyNums(): Record<NumField, string> {
    return { minPasswordLength: '', passwordMaxAgeDays: '', inactiveDisableAfterDays: '', sessionTimeoutSeconds: '' };
  }

  // Seed the numeric drafts from the right source: in per-user mode an existing
  // override row is authoritative (its nulls mean "inherit"); without one we
  // start from the effective (= global) values so editing shows real numbers.
  /** The source row for the extension flag: per-user override when present, else the effective policy. */
  function seedAllowExtension(): boolean {
    const src = (mode === 'perUser' && override) || value;
    return src.allowSessionExtension !== false; // undefined/true = allowed
  }

  function seedNums(): Record<NumField, string> {
    const src = mode === 'perUser' && override ? override : value;
    return {
      minPasswordLength: src.minPasswordLength == null ? '' : String(src.minPasswordLength),
      passwordMaxAgeDays: src.passwordMaxAgeDays == null ? '' : String(src.passwordMaxAgeDays),
      inactiveDisableAfterDays: src.inactiveDisableAfterDays == null ? '' : String(src.inactiveDisableAfterDays),
      sessionTimeoutSeconds: src.sessionTimeoutSeconds == null ? '' : String(src.sessionTimeoutSeconds),
    };
  }

  // Resync the drafts when the saved value changes (after a save round-trip or
  // when the parent switches to another user's policy).
  useEffect(() => {
    setDraftRequired(new Set(value.requiredMethods));
    setDraftGate(new Set(value.gateAmrs));
    setDraftNums(seedNums());
    setDraftAllowExtension(seedAllowExtension());
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [value, override]);

  function toggle(set: Set<string>, key: string, isGate: boolean, apply: (s: Set<string>) => void) {
    const next = new Set(set);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    // gateAmrs must never be empty — the gate would lock out every session.
    if (isGate && next.size === 0) return;
    apply(next);
  }

  function setNum(field: NumField, raw: string) {
    const cleaned = raw.trim();
    setDraftNums((prev) => ({ ...prev, [field]: cleaned === '' ? '' : String(Math.max(0, Math.round(Number(cleaned)))) }));
  }

  // Dirty check — compare the drafts against what saving would produce.
  function buildNext(): Partial<CredentialPolicy> {
    const nums: Record<NumField, number | null> = {} as Record<NumField, number | null>;
    for (const f of NUM_FIELDS) {
      const raw = draftNums[f.key];
      nums[f.key] = raw === '' ? null : Math.round(Number(raw));
    }
    return {
      requiredMethods: [...draftRequired].sort() as CredentialPolicy['requiredMethods'],
      gateAmrs: [...draftGate].sort(),
      minPasswordLength: nums.minPasswordLength,
      passwordMaxAgeDays: nums.passwordMaxAgeDays,
      inactiveDisableAfterDays: nums.inactiveDisableAfterDays,
      sessionTimeoutSeconds: nums.sessionTimeoutSeconds,
      allowSessionExtension: draftAllowExtension,
    };
  }

  const next = buildNext();
  const dirty =
    [...draftRequired].sort().join(',') !== value.requiredMethods.slice().sort().join(',') ||
    [...draftGate].sort().join(',') !== value.gateAmrs.slice().sort().join(',') ||
    NUM_FIELDS.some((f) => (next[f.key] ?? null) !== (value[f.key] ?? null)) ||
    draftAllowExtension !== (value.allowSessionExtension !== false);

  return (
    <div className="space-y-4">
      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-secondary">Required second factor at login</legend>
        <p className="mb-2 text-xs text-faint">
          The user must complete sign-in with one of the enrolled methods below. Leave both unchecked to allow
          password-only sign-in (no 2FA). If none is enrolled, login is blocked until enrollment.
        </p>
        <div className="flex flex-wrap gap-4">
          {(['totp', 'webauthn'] as const).map((m) => (
            <label key={m} className="inline-flex cursor-pointer items-center gap-2 text-sm text-secondary">
              <input
                type="checkbox"
                checked={draftRequired.has(m)}
                onChange={() => {
                  toggle(draftRequired, m, false, setDraftRequired);
                }}
                className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring"
              />
              {m === 'totp' ? 'Authenticator app (TOTP)' : 'Passkey (WebAuthn)'}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-secondary">Satisfies the privileged-action gate</legend>
        <p className="mb-2 text-xs text-faint">
          Sessions completed with one of these methods may submit configuration jobs and execute plans (the 2FA-gated
          endpoints). At least one must stay checked.
        </p>
        <div className="flex flex-wrap gap-4">
          {(['totp', 'webauthn'] as const).map((m) => (
            <label key={m} className="inline-flex cursor-pointer items-center gap-2 text-sm text-secondary">
              <input
                type="checkbox"
                checked={draftGate.has(m)}
                onChange={() => {
                  toggle(draftGate, m, true, setDraftGate);
                }}
                className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring"
              />
              {m === 'totp' ? 'TOTP sessions' : 'Passkey sessions'}
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-secondary">Password &amp; session rules</legend>
        <p className="mb-2 text-xs text-faint">
          {mode === 'perUser'
            ? 'Per-user overrides — an empty field inherits the global default for that rule.'
            : 'Global defaults applied to every user without a per-user override. An empty field turns the rule off (or uses the built-in minimum).'}
        </p>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {NUM_FIELDS.map((f) => (
            <label key={f.key} className="block">
              <span className="mb-1 flex items-center justify-between text-xs font-medium text-secondary">
                {f.label}
                <span className="text-faint">{f.unit}</span>
              </span>
              <input
                type="number"
                min={0}
                step={1}
                placeholder={mode === 'perUser' ? 'inherit global' : f.key === 'minPasswordLength' ? 'default 8' : 'off'}
                value={draftNums[f.key]}
                onChange={(e) => setNum(f.key, e.target.value)}
                className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-focus-ring focus:outline-none"
              />
              <span className="mt-1 block text-[11px] leading-snug text-faint">{f.hint(mode)}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend className="mb-1.5 text-sm font-semibold text-secondary">Session extension</legend>
        <p className="mb-2 text-xs text-faint">
          When allowed, a signed-in user can extend their own session from the top bar — but only by re-proving an
          enrolled second factor (TOTP or passkey); users without one never see the option. Turn this off to harden
          security: sessions then always end at their timeout and require a full sign-in.
        </p>
        <label className="inline-flex cursor-pointer items-center gap-2 text-sm text-secondary">
          <input
            type="checkbox"
            checked={draftAllowExtension}
            onChange={() => setDraftAllowExtension((v) => !v)}
            className="h-4 w-4 rounded border-border text-foreground focus:ring-focus-ring"
          />
          Allow users to extend their session (2FA revalidation required)
        </label>
      </fieldset>

      <button
        type="button"
        disabled={!dirty}
        onClick={() => onChange(next)}
        className="rounded-md bg-primary px-4 py-2 text-sm font-medium text-white hover:bg-primary-hover disabled:opacity-50"
      >
        Save policy
      </button>
    </div>
  );
}
