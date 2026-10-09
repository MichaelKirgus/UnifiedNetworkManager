import { Router, Request, Response } from 'express';
import { eq, isNull } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import {
  getGlobalPolicy,
  getUserPolicy,
  resolveCredentialPolicy,
  serializePolicy,
  validatePolicyBody,
} from '../auth/credentialPolicy';

/**
 * Credential policy routes.
 *
 *   GET    /auth/policies/global      — the global default policy (any authed user)
 *   PUT    /auth/policies/global      — update it (auth:policies:write)
 *   GET    /users/:id/policy          — effective + override for one user
 *   PUT    /users/:id/policy          — set a per-user override (auth:policies:write)
 *   DELETE /users/:id/policy          — clear the override, revert to global (auth:policies:write)
 *
 * A per-user row OVERRIDES the global one FIELD BY FIELD (each rule is resolved
 * independently; an override only carries the fields it changes). The require2FA
 * gate and session-timeout cap read these rows LIVE on every request.
 */

const router = Router();

/** Maps a validated policy body onto the columns it sets (partial updates ok). */
function policyColumns(body: Record<string, unknown>): Record<string, unknown> {
  const cols: Record<string, unknown> = {};
  if (body.requiredMethods !== undefined) cols.requiredMethods = JSON.stringify(body.requiredMethods);
  if (body.gateAmrs !== undefined) cols.gateAmrs = JSON.stringify(body.gateAmrs);
  for (const key of ['minPasswordLength', 'passwordMaxAgeDays', 'inactiveDisableAfterDays', 'sessionTimeoutSeconds'] as const) {
    if (body[key] !== undefined) cols[key] = body[key]; // number or null (null clears the rule)
  }
  if (body.allowSessionExtension !== undefined) cols.allowSessionExtension = body.allowSessionExtension; // boolean
  return cols;
}

/** Applies a validated policy body to a row, creating it when absent. */
async function upsertPolicyRow(userId: string | null, body: Record<string, unknown>) {
  const now = new Date().toISOString();
  const where = userId === null ? isNull(schema.credentialPolicies.userId) : eq(schema.credentialPolicies.userId, userId);

  const existing = await db.query.credentialPolicies.findFirst({ where });
  if (existing) {
    await db.update(schema.credentialPolicies)
      .set({ ...policyColumns(body), updatedAt: now })
      .where(eq(schema.credentialPolicies.id, existing.id));
  } else {
    await db.insert(schema.credentialPolicies).values({
      id: uuidv4(),
      userId,
      requiredMethods: JSON.stringify(body.requiredMethods ?? ['totp']),
      gateAmrs: JSON.stringify(body.gateAmrs ?? ['totp']),
      ...policyColumns(body),
      updatedAt: now,
    });
  }

  return userId === null ? getGlobalPolicy() : getUserPolicy(userId);
}

// GET /auth/policies/global — the global default policy.
router.get('/auth/policies/global', requireAuth, async (_req: Request, res: Response) => {
  const row = await getGlobalPolicy();
  res.status(200).json({ policy: serializePolicy(row), override: null });
});

// PUT /auth/policies/global — update the global default (partial updates ok).
router.put('/auth/policies/global', requireAuth, requirePermission('auth:policies:write'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const invalid = validatePolicyBody(body);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }

  try {
    const row = await upsertPolicyRow(null, body);
    if (!row) {
      res.status(500).json({ error: 'Failed to update global credential policy' });
      return;
    }
    res.status(200).json({ policy: serializePolicy(row), override: null });
  } catch (error) {
    console.error('Error updating global credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /users/:id/policy — the EFFECTIVE policy for one user (per-user override
// merged onto the global default, field by field) plus the raw override row.
router.get('/users/:id/policy', requireAuth, async (req: Request, res: Response) => {
  // Express 5 types params as string | string[] — coerce.
  const targetId = String(req.params.id ?? '');
  const [userRow, effective] = await Promise.all([getUserPolicy(targetId), resolveCredentialPolicy(targetId)]);

  if (userRow) {
    res.status(200).json({ policy: serializePolicy(effective), override: serializePolicy(userRow), source: 'user' });
    return;
  }
  // No per-user row — the effective policy IS the global default.
  res.status(200).json({ policy: serializePolicy(effective), override: null, source: 'global' });
});

// PUT /users/:id/policy — set (or update) a per-user override.
router.put('/users/:id/policy', requireAuth, requirePermission('auth:policies:write'), async (req: Request, res: Response) => {
  // Express 5 types params as string | string[] — coerce.
  const targetId = String(req.params.id ?? '');
  const body = (req.body ?? {}) as Record<string, unknown>;

  const invalid = validatePolicyBody(body);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }

  try {
    await upsertPolicyRow(targetId, body);
    const [userRow, effective] = await Promise.all([getUserPolicy(targetId), resolveCredentialPolicy(targetId)]);
    res.status(200).json({ policy: serializePolicy(effective), override: userRow ? serializePolicy(userRow) : null, source: 'user' });
  } catch (error) {
    console.error('Error updating user credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /users/:id/policy — clear the per-user override (revert to global).
router.delete('/users/:id/policy', requireAuth, requirePermission('auth:policies:write'), async (req: Request, res: Response) => {
  // Express 5 types params as string | string[] — coerce.
  const targetId = String(req.params.id ?? '');
  try {
    await db.delete(schema.credentialPolicies).where(eq(schema.credentialPolicies.userId, targetId));
    const effective = await resolveCredentialPolicy(targetId);
    res.status(200).json({ policy: serializePolicy(effective), override: null, source: 'global' });
  } catch (error) {
    console.error('Error clearing user credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
