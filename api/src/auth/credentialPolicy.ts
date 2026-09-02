import { eq, isNull } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';

/**
 * Credential policy engine.
 *
 * A credential policy controls two things:
 *   1. `requiredMethods` — which enrolled 2nd factors satisfy login step 2
 *      ('totp' | 'webauthn'). Empty array = no 2FA required at all. If none of
 *      the allowed methods is enrolled, login is blocked with a distinct error
 *      so the UI can point to enrollment (and an admin can unblock by clearing
 *      the policy or enrolling a method).
 *   2. `gateAmrs` — which JWT `amr` values satisfy require2FA (privileged
 *      endpoints like config-job submission). Evaluated LIVE per request, so
 *      admin changes apply immediately to existing sessions.
 *
 * Resolution: a per-user row (unique on userId) overrides the GLOBAL row
 * (`userId IS NULL`) entirely — user policy wins over global. When neither
 * exists we fall back to the built-in default (TOTP required + gate).
 */

export type SecondFactorMethod = 'totp' | 'webauthn';

/** AMR values a session can carry after completing authentication. */
export const KNOWN_AMRS = ['pwd', 'totp', 'webauthn'] as const;
export type AmrValue = (typeof KNOWN_AMRS)[number];

const SECOND_FACTOR_METHODS: SecondFactorMethod[] = ['totp', 'webauthn'];

/** Built-in fallback when no policy row exists at all. */
export const DEFAULT_CREDENTIAL_POLICY: CredentialPolicy = {
  requiredMethods: ['totp'],
  gateAmrs: ['totp'],
};

export interface CredentialPolicy {
  /** Enrolled methods that satisfy login step 2 (empty = no 2FA). */
  requiredMethods: SecondFactorMethod[];
  /** Session AMRs that satisfy require2FA. */
  gateAmrs: AmrValue[];
}

interface PolicyRow extends CredentialPolicy {
  id: string;
  userId: string | null;
  updatedAt: string;
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
 * Resolves the effective policy for a user: per-user override wins over the
 * global default. Never throws — falls back to DEFAULT_CREDENTIAL_POLICY when
 * no rows exist (e.g. before initDb seeding).
 */
export async function resolveCredentialPolicy(userId: string): Promise<PolicyRow> {
  const [userRow, globalRow] = await Promise.all([getUserPolicy(userId), getGlobalPolicy()]);
  if (userRow) return userRow;
  if (globalRow.userId === null && globalRow.id) return globalRow;
  return { ...DEFAULT_CREDENTIAL_POLICY, id: '', userId: null, updatedAt: '' };
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

  return null;
}

/** Serializes a policy row for the public API (no internal id/updatedAt noise). */
export function serializePolicy(row: PolicyRow): CredentialPolicy & { userId: string | null } {
  return {
    userId: row.userId,
    requiredMethods: [...row.requiredMethods],
    gateAmrs: [...row.gateAmrs],
  };
}
