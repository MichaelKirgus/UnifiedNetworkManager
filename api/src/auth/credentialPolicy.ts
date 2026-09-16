import { eq, isNull } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/**
 * Credential policy engine.
 *
 * A credential policy controls:
 *   1. `requiredMethods` — which enrolled 2nd factors satisfy login step 2
 *      ('totp' | 'webauthn'). Empty array = no 2FA required at all. If none of
 *      the allowed methods is enrolled, login is blocked with a distinct error
 *      so the UI can point to enrollment (and an admin can unblock by clearing
 *      the policy or enrolling a method).
 *   2. `gateAmrs` — which JWT `amr` values satisfy require2FA (privileged
 *      endpoints like config-job submission). Evaluated LIVE per request, so
 *      admin changes apply immediately to existing sessions.
 *   3. Password rules — `minPasswordLength` (floor for new/reset passwords),
 *      `passwordMaxAgeDays` (force rotation after N days; null = off) and
 *      `inactiveDisableAfterDays` (auto-disable after N days without a login;
 *      null = off).
 *   4. `sessionTimeoutSeconds` — an optional per-user CAP on the global session
 *      timeout, so one account can be forced to expire sooner than everyone else.
 *   5. `allowSessionExtension` — whether a signed-in user may extend their own
 *      session (the web UI "Extend" button). Extension always requires re-proving
 *      a second factor; this flag is the admin's kill switch for security
 *      hardening (false = sessions can never be extended, they end at expiry).
 *
 * Resolution: a per-user row (unique on userId) OVERRIDES the GLOBAL row
 * (`userId IS NULL`) FIELD BY FIELD — each rule is resolved independently and an
 * override only needs to carry the fields it changes (the rest inherit from
 * global). When neither exists we fall back to DEFAULT_CREDENTIAL_POLICY.
 */

export type SecondFactorMethod = 'totp' | 'webauthn';

/** AMR values a session can carry after completing authentication. */
export const KNOWN_AMRS = ['pwd', 'totp', 'webauthn'] as const;
export type AmrValue = (typeof KNOWN_AMRS)[number];

const SECOND_FACTOR_METHODS: SecondFactorMethod[] = ['totp', 'webauthn'];

/** Built-in floor for password length when a policy leaves it unset. */
export const BUILTIN_MIN_PASSWORD_LENGTH = 8;

/** Built-in fallback when no policy row exists at all. */
export const DEFAULT_CREDENTIAL_POLICY: CredentialPolicy = {
  requiredMethods: ['totp'],
  gateAmrs: ['totp'],
  minPasswordLength: BUILTIN_MIN_PASSWORD_LENGTH,
  passwordMaxAgeDays: null,
  inactiveDisableAfterDays: null,
  sessionTimeoutSeconds: null,
  allowSessionExtension: true,
};

export interface CredentialPolicy {
  /** Enrolled methods that satisfy login step 2 (empty = no 2FA). */
  requiredMethods: SecondFactorMethod[];
  /** Session AMRs that satisfy require2FA. */
  gateAmrs: AmrValue[];
  /** Minimum characters for any new/reset password (null = built-in default of 8). */
  minPasswordLength: number | null;
  /** Force a password change after this many days (null = no forced rotation). */
  passwordMaxAgeDays: number | null;
  /** Auto-disable the account if it has not logged on for this many days (null = off). */
  inactiveDisableAfterDays: number | null;
  /** Per-user cap on session lifetime in seconds — sessions expire at min(global, this) (null = inherit global). */
  sessionTimeoutSeconds: number | null;
  /** Whether the user may extend their own session via a 2FA revalidation. False = hardening kill switch. */
  allowSessionExtension: boolean;
}

interface PolicyRow extends CredentialPolicy {
  id: string;
  userId: string | null;
  updatedAt: string;
}

/** The effective minimum password length for a policy (built-in floor when unset). */
export function effectiveMinPasswordLength(policy: Pick<CredentialPolicy, 'minPasswordLength'>): number {
  return typeof policy.minPasswordLength === 'number' && policy.minPasswordLength > 0
    ? policy.minPasswordLength
    : BUILTIN_MIN_PASSWORD_LENGTH;
}

/** Coerce a nullable integer column into `number | null` (null/invalid = null). */
function parseNullableInt(raw: unknown): number | null {
  if (raw === null || raw === undefined) return null;
  const n = Number(raw);
  return Number.isFinite(n) ? Math.round(n) : null;
}

function parseStringArray<T extends string>(raw: string, allowed: readonly T[]): T[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return [];
  }
  if (!Array.isArray(parsed)) return [];
  return parsed.filter((v): v is T => typeof v === 'string' && (allowed as readonly string[]).includes(v));
}

function toPolicy(row: typeof schema.credentialPolicies.$inferSelect): PolicyRow {
  return {
    id: row.id,
    userId: row.userId,
    requiredMethods: parseStringArray<SecondFactorMethod>(row.requiredMethods, SECOND_FACTOR_METHODS),
    gateAmrs: parseStringArray<AmrValue>(row.gateAmrs, KNOWN_AMRS),
    minPasswordLength: parseNullableInt(row.minPasswordLength),
    passwordMaxAgeDays: parseNullableInt(row.passwordMaxAgeDays),
    inactiveDisableAfterDays: parseNullableInt(row.inactiveDisableAfterDays),
    sessionTimeoutSeconds: parseNullableInt(row.sessionTimeoutSeconds),
    allowSessionExtension: row.allowSessionExtension !== false, // NULL/missing = allowed (pre-migration rows)
    updatedAt: row.updatedAt,
  };
}

/** The global default policy (the `userId IS NULL` row). */
export async function getGlobalPolicy(): Promise<PolicyRow> {
  const row = await db.query.credentialPolicies.findFirst({
    where: isNull(schema.credentialPolicies.userId),
  });
  return row ? toPolicy(row) : { ...DEFAULT_CREDENTIAL_POLICY, id: '', userId: null, updatedAt: '' };
}

/** The per-user policy override for one user (null when unset). */
export async function getUserPolicy(userId: string): Promise<PolicyRow | null> {
  const row = await db.query.credentialPolicies.findFirst({
    where: eq(schema.credentialPolicies.userId, userId),
  });
  return row ? toPolicy(row) : null;
}

/**
 * Merges a per-user override onto the global policy FIELD BY FIELD. A field is
 * taken from the user row only when it carries an explicit value — array fields
 * are "explicit" whenever the row exists (an empty requiredMethods array is a
 * meaningful "no 2FA"), while nullable integer fields fall back to the global
 * value when null (null = "inherit"). This lets an override change just one
 * rule without re-specifying the rest.
 */
export function mergePolicy(global: CredentialPolicy, user: PolicyRow | null): CredentialPolicy {
  if (!user) return { ...global };
  return {
    requiredMethods: [...user.requiredMethods],
    gateAmrs: [...user.gateAmrs],
    minPasswordLength: user.minPasswordLength ?? global.minPasswordLength,
    passwordMaxAgeDays: user.passwordMaxAgeDays ?? global.passwordMaxAgeDays,
    inactiveDisableAfterDays: user.inactiveDisableAfterDays ?? global.inactiveDisableAfterDays,
    sessionTimeoutSeconds: user.sessionTimeoutSeconds ?? global.sessionTimeoutSeconds,
    // Boolean field — the per-user row is authoritative whenever it exists
    // (false is a meaningful "deny", so there is no null/inherit state).
    allowSessionExtension: user.allowSessionExtension,
  };
}

/**
 * Resolves the effective policy for a user: per-user override merged onto the
 * global default (field by field — see mergePolicy). Never throws — falls back
 * to DEFAULT_CREDENTIAL_POLICY when no rows exist (e.g. before initDb seeding).
 */
export async function resolveCredentialPolicy(userId: string): Promise<PolicyRow> {
  const [userRow, globalRow] = await Promise.all([getUserPolicy(userId), getGlobalPolicy()]);
  return { ...mergePolicy(globalRow, userRow), id: '', userId: null, updatedAt: '' };
}

/**
 * The effective session lifetime (seconds) for a user: the global setting capped
 * by any per-user `sessionTimeoutSeconds` override. Returns the global value
 * unchanged when no cap applies.
 */
export function effectiveSessionTtl(globalSeconds: number, policy: Pick<CredentialPolicy, 'sessionTimeoutSeconds'>): number {
  const cap = policy.sessionTimeoutSeconds;
  if (typeof cap === 'number' && cap > 0) return Math.min(globalSeconds, cap);
  return globalSeconds;
}

/**
 * True when the user's password is older than `passwordMaxAgeDays` and must be
 * rotated. A NULL/missing `passwordChangedAt` means "unknown age" — treated as
 * fresh so existing accounts are not locked out on first deploy.
 */
export function isPasswordExpired(policy: Pick<CredentialPolicy, 'passwordMaxAgeDays'>, passwordChangedAt: string | null): boolean {
  if (typeof policy.passwordMaxAgeDays !== 'number' || policy.passwordMaxAgeDays <= 0) return false;
  if (!passwordChangedAt) return false;
  const changed = Date.parse(passwordChangedAt);
  if (Number.isNaN(changed)) return false;
  return Date.now() - changed > policy.passwordMaxAgeDays * 24 * 60 * 60 * 1000;
}

/** True when a user has not logged on within `inactiveDisableAfterDays`. */
export function isInactiveDisabled(policy: Pick<CredentialPolicy, 'inactiveDisableAfterDays'>, lastLoginAt: string | null): boolean {
  if (typeof policy.inactiveDisableAfterDays !== 'number' || policy.inactiveDisableAfterDays <= 0) return false;
  const ref = lastLoginAt ? Date.parse(lastLoginAt) : NaN;
  // Never disable an account that has never logged on — it would lock out a
  // freshly created user before their first sign-in.
  if (Number.isNaN(ref)) return false;
  return Date.now() - ref > policy.inactiveDisableAfterDays * 24 * 60 * 60 * 1000;
}

/** Validates a policy body from the API. Returns an error message or null. */
export function validatePolicyBody(body: unknown): string | null {
  if (!body || typeof body !== 'object' || Array.isArray(body)) {
    return 'Request body must be an object';
  }
  const obj = body as Record<string, unknown>;

  for (const key of ['requiredMethods', 'gateAmrs'] as const) {
    const value = obj[key];
    if (value === undefined) continue; // partial updates allowed
    if (!Array.isArray(value)) return `${key} must be an array`;
    for (const item of value) {
      if (typeof item !== 'string') return `${key} entries must be strings`;
      const allowed = (key === 'requiredMethods' ? SECOND_FACTOR_METHODS : KNOWN_AMRS) as readonly string[];
      if (!allowed.includes(item)) {
        return `Invalid ${key} entry: "${item}" (allowed: ${allowed.join(', ')})`;
      }
    }
  }

  // gateAmrs must never be empty — the require2FA gate would then reject every
  // session, locking out privileged actions entirely.
  if (Array.isArray(obj.gateAmrs) && obj.gateAmrs.length === 0) {
    return 'gateAmrs must contain at least one AMR value';
  }

  for (const key of ['minPasswordLength', 'passwordMaxAgeDays', 'inactiveDisableAfterDays', 'sessionTimeoutSeconds'] as const) {
    const value = obj[key];
    if (value === undefined || value === null) continue; // omitted/null = inherit / clear
    if (typeof value !== 'number' || !Number.isFinite(value)) return `${key} must be a number or null`;
  }

  if (obj.allowSessionExtension !== undefined && typeof obj.allowSessionExtension !== 'boolean') {
    return 'allowSessionExtension must be a boolean';
  }

  for (const key of ['minPasswordLength', 'passwordMaxAgeDays', 'inactiveDisableAfterDays'] as const) {
    const value = obj[key];
    if (typeof value === 'number' && value < 1) return `${key} must be at least 1`;
  }

  // A per-user session cap that is LONGER than the global timeout would be a no-op
  // (sessions expire at min(global, cap)); reject it so the UI never stores a
  // misleading "override" that does nothing.
  if (typeof obj.sessionTimeoutSeconds === 'number' && obj.sessionTimeoutSeconds < 300) {
    return 'sessionTimeoutSeconds must be at least 300';
  }

  return null;
}

/** Serializes a policy row for the public API (no internal id/updatedAt noise). */
export function serializePolicy(row: PolicyRow): CredentialPolicy & { userId: string | null } {
  return {
    userId: row.userId,
    requiredMethods: [...row.requiredMethods],
    gateAmrs: [...row.gateAmrs],
    minPasswordLength: row.minPasswordLength,
    passwordMaxAgeDays: row.passwordMaxAgeDays,
    inactiveDisableAfterDays: row.inactiveDisableAfterDays,
    sessionTimeoutSeconds: row.sessionTimeoutSeconds,
    allowSessionExtension: row.allowSessionExtension !== false,
  };
}
