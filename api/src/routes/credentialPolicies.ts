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
 *   GET    /users/:id/policy          — effective policy for one user + its source
 *   PUT    /users/:id/policy          — set a per-user override (auth:policies:write)
 *   DELETE /users/:id/policy          — clear the override, revert to global (auth:policies:write)
 *
 * A per-user row overrides the global one entirely (user policy wins). The
 * require2FA gate reads these rows LIVE on every privileged request.
 */

const router = Router();

/** Applies a validated `{requiredMethods?, gateAmrs?}` body to a policy row. */
async function upsertPolicyRow(userId: string | null, body: Record<string, unknown>) {
  const now = new Date().toISOString();

  if (userId === null) {
    // Global row — unique by userId IS NULL; update in place when present.
    const existing = await db.query.credentialPolicies.findFirst({ where: isNull(schema.credentialPolicies.userId) });
    if (existing) {
      const updates: Record<string, unknown> = { updatedAt: now };
      if (body.requiredMethods !== undefined) updates.requiredMethods = JSON.stringify(body.requiredMethods);
      if (body.gateAmrs !== undefined) updates.gateAmrs = JSON.stringify(body.gateAmrs);
      await db.update(schema.credentialPolicies).set(updates).where(eq(schema.credentialPolicies.id, existing.id));
    } else {
      await db.insert(schema.credentialPolicies).values({
        id: uuidv4(),
        userId: null,
        requiredMethods: JSON.stringify(body.requiredMethods ?? ['totp']),
        gateAmrs: JSON.stringify(body.gateAmrs ?? ['totp']),
        updatedAt: now,
      });
    }
  } else {
    const existing = await db.query.credentialPolicies.findFirst({ where: eq(schema.credentialPolicies.userId, userId) });
    if (existing) {
      const updates: Record<string, unknown> = { updatedAt: now };
      if (body.requiredMethods !== undefined) updates.requiredMethods = JSON.stringify(body.requiredMethods);
      if (body.gateAmrs !== undefined) updates.gateAmrs = JSON.stringify(body.gateAmrs);
      await db.update(schema.credentialPolicies).set(updates).where(eq(schema.credentialPolicies.id, existing.id));
    } else {
      await db.insert(schema.credentialPolicies).values({
        id: uuidv4(),
        userId,
        requiredMethods: JSON.stringify(body.requiredMethods ?? ['totp']),
        gateAmrs: JSON.stringify(body.gateAmrs ?? ['totp']),
        updatedAt: now,
      });
    }
  }

  return userId === null ? getGlobalPolicy() : getUserPolicy(userId);
}

// GET /auth/policies/global — the global default policy.
router.get('/auth/policies/global', requireAuth, async (_req: Request, res: Response) => {
  const row = await getGlobalPolicy();
  res.status(200).json({ policy: serializePolicy(row) });
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
    res.status(200).json({ policy: serializePolicy(row) });
  } catch (error) {
    console.error('Error updating global credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /users/:id/policy — the effective policy for one user + where it comes from.
router.get('/users/:id/policy', requireAuth, async (req: Request, res: Response) => {
  const targetId = req.params.id;
  const [userRow, globalRow] = await Promise.all([getUserPolicy(targetId), getGlobalPolicy()]);

  if (userRow) {
    res.status(200).json({ policy: serializePolicy(userRow), source: 'user' });
    return;
  }
  // No per-user row — fall back to the global one (or the built-in default when
  // even that is missing, e.g. before initDb seeding).
  if (globalRow.id) {
    res.status(200).json({ policy: serializePolicy(globalRow), source: 'global' });
    return;
  }
  const effective = await resolveCredentialPolicy(targetId);
  res.status(200).json({ policy: serializePolicy(effective), source: 'default' });
});

// PUT /users/:id/policy — set (or update) a per-user override.
router.put('/users/:id/policy', requireAuth, requirePermission('auth:policies:write'), async (req: Request, res: Response) => {
  const targetId = req.params.id;
  const body = (req.body ?? {}) as Record<string, unknown>;

  const invalid = validatePolicyBody(body);
  if (invalid) {
    res.status(400).json({ error: invalid });
    return;
  }

  try {
    const row = await upsertPolicyRow(targetId, body);
    res.status(200).json({ policy: serializePolicy(row!), source: 'user' });
  } catch (error) {
    console.error('Error updating user credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /users/:id/policy — clear the per-user override (revert to global).
router.delete('/users/:id/policy', requireAuth, requirePermission('auth:policies:write'), async (req: Request, res: Response) => {
  const targetId = req.params.id;
  try {
    await db.delete(schema.credentialPolicies).where(eq(schema.credentialPolicies.userId, targetId));
    const globalRow = await getGlobalPolicy();
    res.status(200).json({ policy: serializePolicy(globalRow), source: 'global' });
  } catch (error) {
    console.error('Error clearing user credential policy:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

export default router;
