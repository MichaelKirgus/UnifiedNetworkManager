import { Router } from 'express';
import { inArray } from 'drizzle-orm';
import { db } from '../db';
import * as schema from '../db/schema';
import { requireAuth, requirePermission } from '../auth/middleware';
import {
  createSecret,
  listSecrets,
  deleteSecret,
  listSecretProviders,
  generateSecret,
  getSecretFields,
  updateSecret,
  invalidateSecretCache,
  regenerateSecret,
} from '../secretsProvider';

const router = Router();

interface SecretMeta {
  id: string;
  label: string | null;
  type: string;
  providerId: string | null;
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
 * The public contract:
 *   GET    /secrets            -> metadata list (incl. type + providerId)
 *   GET    /secrets/providers  -> registered providers + their secret types
 *   POST   /secrets            -> { type, providerId?, fields, label?, expiresAt? } -> { id, createdAt }
 *   GET    /secrets/:id        -> decrypted fields (for the edit form)
 *   PATCH  /secrets/:id        -> { fields?, label?, expiresAt? } — update in place (all types)
 *   DELETE /secrets/:id        -> 204
 */

// GET /secrets/providers - List registered secrets providers + their secret types
router.get('/providers', requireAuth, requirePermission('secrets:read'), async (_req, res) => {
  try {
    const providers = await listSecretProviders();
    res.status(200).json(providers);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

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
      type: s.type,
      providerId: s.providerId,
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

// POST /secrets - Create a new secret (typed, provider-routed)
router.post('/', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { type, providerId, fields, label, expiresAt } = req.body ?? {};

  if (!type || typeof type !== 'string') {
    res.status(400).json({ error: 'type is required' });
    return;
  }
  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    res.status(400).json({ error: 'fields object is required' });
    return;
  }

  const userId = req.user?.sub;
  if (!userId || typeof userId !== 'string') {
    res.status(401).json({ error: 'User ID not found in token' });
    return;
  }

  try {
    const result = await createSecret({
      type,
      providerId: typeof providerId === 'string' ? providerId : undefined,
      fields,
      label,
      expiresAt,
      userId,
    });
    res.status(201).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /secrets/generate - Generate a new secret of a generatable type.
// The provider creates the key material itself (X25519 pair, PSK, CA+cert
// bundle) and stores it — no human types any keys. Registered before the
// `/:id` routes so "generate" is not treated as an id.
router.post('/generate', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { type, providerId, fields, label, expiresAt } = req.body ?? {};

  if (!type || typeof type !== 'string') {
    res.status(400).json({ error: 'type is required' });
    return;
  }

  const userId = req.user?.sub;
  if (!userId || typeof userId !== 'string') {
    res.status(401).json({ error: 'User ID not found in token' });
    return;
  }

  try {
    const result = await generateSecret({
      type,
      providerId: typeof providerId === 'string' ? providerId : undefined,
      fields: (fields && typeof fields === 'object' ? fields : {}) as Record<string, unknown>,
      label,
      expiresAt,
      userId,
    });
    res.status(201).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /secrets/:id/regenerate - Re-roll a generatable secret's key material in
// place (same id preserved) so references keep working.
router.post('/:id/regenerate', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await regenerateSecret(id);
    invalidateSecretCache(id); // rotated key material must not be served from cache
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// GET /secrets/:id - Retrieve a secret's decrypted fields (for the edit form).
// Routed to the provider that created it; never served from cache.
router.get('/:id', requireAuth, requirePermission('secrets:read'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await getSecretFields(id);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PATCH /secrets/:id - Update a secret's fields IN PLACE (same id preserved, so
// assignments and plans referencing it keep working). Works for ALL secret
// types — the owning provider re-encrypts the new field values. `fields` is a
// full replacement of the type's field map; label/expiresAt are optional.
router.patch('/:id', requireAuth, requirePermission('secrets:write'), async (req, res) => {
  const { id } = req.params;
  const { fields, label, expiresAt } = req.body ?? {};

  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    res.status(400).json({ error: 'fields object is required' });
    return;
  }

  try {
    const result = await updateSecret(id, {
      fields,
      ...(typeof label === 'string' ? { label } : {}),
      ...(typeof expiresAt === 'string' || expiresAt === null ? { expiresAt } : {}),
    });
    invalidateSecretCache(id); // edited values must not be served from cache
    res.status(200).json(result);
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
    invalidateSecretCache(id); // deleted secret must not be served from cache
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
