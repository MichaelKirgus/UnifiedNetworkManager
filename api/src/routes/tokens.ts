import { Router, Request, Response } from 'express';
import { requireAuth, requirePermission } from '../auth/middleware';
import { createApiToken, listApiTokens, revokeApiToken } from '../auth/apiTokens';

/**
 * API token management (self-service + admin).
 *
 * Tokens are long-lived bearer credentials for agents/scripts (e.g. the MCP
 * server). Managing your OWN tokens requires `tokens:manage`; users with
 * `users:read` can additionally list every user's tokens, and users with
 * `users:write` can revoke any token — mirroring the Users page's permission
 * model. The raw token value is returned exactly once (POST response); only
 * its hash is stored.
 */

const router = Router();

// GET /tokens - own tokens (requires tokens:manage); ?all=true lists every
// user's tokens (additionally requires users:read).
router.get('/tokens', requireAuth, requirePermission('tokens:manage'), async (req: Request, res: Response) => {
  const all = req.query.all === 'true';
  if (all && !req.user?.permissions?.includes('users:read')) {
    res.status(403).json({ error: 'Missing required permission: users:read' });
    return;
  }
  try {
    const tokens = await listApiTokens(req.user!.sub, { all });
    res.status(200).json(tokens);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /tokens - create a token for the CALLER. Requires tokens:manage.
// Body (all optional): label, permissions[] (subset of the target user's
// effective set; [] = inherit all), expiresAt (ISO timestamp or null), and
// userId — mint on behalf of ANOTHER user (requires users:write). That is how
// admins provision API tokens for service-only accounts that cannot sign into
// the web UI. Response carries `rawToken` exactly once.
router.post('/tokens', requireAuth, requirePermission('tokens:manage'), async (req: Request, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  try {
    let targetUserId = req.user!.sub;
    if (body.userId !== undefined) {
      if (typeof body.userId !== 'string' || body.userId.trim().length === 0) {
        res.status(400).json({ error: '"userId" must be a non-empty string' });
        return;
      }
      targetUserId = body.userId.trim();
      // Minting for someone else is an admin-level action.
      if (targetUserId !== req.user!.sub && !req.user?.permissions?.includes('users:write')) {
        res.status(403).json({ error: 'Missing required permission: users:write' });
        return;
      }
    }
    const label = typeof body.label === 'string' ? body.label : undefined;
    if (label !== undefined && label.trim().length > 120) {
      res.status(400).json({ error: '"label" must be at most 120 characters' });
      return;
    }
    let permissions: string[] | undefined;
    if (body.permissions !== undefined) {
      if (!Array.isArray(body.permissions) || body.permissions.some((p) => typeof p !== 'string')) {
        res.status(400).json({ error: '"permissions" must be an array of permission ids' });
        return;
      }
      permissions = body.permissions as string[];
    }
    let expiresAt: string | null | undefined;
    if (body.expiresAt !== undefined) {
      // null is a valid value ("no expiry") — the webapp sends it when the
      // optional field is left empty. (typeof null === 'object', so it must be
      // checked BEFORE the string check.)
      if (body.expiresAt === null) {
        expiresAt = null;
      } else if (typeof body.expiresAt !== 'string' || Number.isNaN(Date.parse(body.expiresAt))) {
        res.status(400).json({ error: '"expiresAt" must be an ISO timestamp or null' });
        return;
      } else {
        expiresAt = body.expiresAt;
      }
    }

    // Note: createApiToken validates the grant against the TARGET user's
    // effective set — a token can never exceed what its owner has.
    const created = await createApiToken({ userId: targetUserId, label, permissions, expiresAt });
    res.status(201).json(created);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /tokens/:id - revoke. Revoking your OWN token requires tokens:manage;
// revoking ANY user's token requires users:write (which also covers your own).
router.delete('/tokens/:id', requireAuth, async (req: Request, res: Response) => {
  const perms = req.user?.permissions ?? [];
  const canManageOwn = perms.includes('tokens:manage');
  const canRevokeAny = perms.includes('users:write');
  if (!canManageOwn && !canRevokeAny) {
    res.status(403).json({ error: 'Missing required permission: tokens:manage' });
    return;
  }
  try {
    await revokeApiToken(String(req.params.id ?? ''), req.user!.sub, { admin: canRevokeAny });
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
