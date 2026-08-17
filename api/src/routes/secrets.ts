import { Router } from 'express';
import { inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import { createSecret, listSecrets, deleteSecret } from '../secretsProvider';

const router = Router();

interface SecretMeta {
  id: string;
  label: string | null;
  userId: string;
  expiresAt: string | null;
  createdAt: string;
}

/**
 * Public secrets routes.
 *
 * The API is a pure broker: it does NOT encrypt/decrypt or manage secrets
 * itself. It delegates to the active secrets provider plugin (selected via
 * `SECRETS_PLUGIN_ID`, falling back to the built-in secrets-provider plugin).
 * The plugin owns the crypto (MASTER_KEY) and the management logic; the API
 * keeps the `secrets` table.
 *
 * The public contract is unchanged:
 *   GET    /secrets      -> metadata list
 *   POST   /secrets      -> { id, createdAt }
 *   DELETE /secrets/:id  -> 204
 */

// GET /secrets - List all secrets (metadata only)
router.get('/', requireAuth, requirePermission('secrets:read'), async (_req, res) => {
  try {
    const secrets = (await listSecrets()) as SecretMeta[];

    // Resolve userId -> username (the API owns the users table).
    const userIds = [...new Set(secrets.map((s) => s.userId))];
    const userMap = new Map<string, string>();
    if (userIds.length > 0) {
      const users = await db.query.users.findMany({
        where: (users, { inArray }) => inArray(users.id, userIds),
      });
      users.forEach((u) => userMap.set(u.id, u.username));
    }

    const sanitized = secrets.map((s) => ({
      id: s.id,
      label: s.label,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      username: userMap.get(s.userId) ?? 'Unknown',
    }));

    res.status(200).json(sanitized);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /secrets - Create a new secret
router.post('/', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { apiKey, apiSecret, label, expiresAt } = req.body ?? {};

  if (!apiKey || !apiSecret) {
    res.status(400).json({ error: 'apiKey and apiSecret are required' });
    return;
  }

  const userId = req.user?.sub;
  if (!userId || typeof userId !== 'string') {
    res.status(401).json({ error: 'User ID not found in token' });
    return;
  }

  try {
    const result = await createSecret({ apiKey, apiSecret, label, expiresAt, userId });
    res.status(201).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /secrets/:id - Remove a secret
router.delete('/:id', requireAuth, requirePermission('secrets:delete'), async (req, res) => {
  const { id } = req.params;
  try {
    await deleteSecret(id);
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
