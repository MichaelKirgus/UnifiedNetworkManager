import { Router } from 'express';
import { eq, inArray } from 'drizzle-orm';
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
  interactiveLoginAllowed?: boolean;
  fileAccessAllowed?: boolean;
  createdAt: string;
}

/** The caller's effective permission set (JWT claim). */
function permsOf(req: { user?: { permissions?: string[] } }): Set<string> {
  return new Set(req.user?.permissions ?? []);
}

/** True when the caller may manage ANY secret (global writer). */
function isGlobalWriter(perms: Set<string>): boolean {
  return perms.has('secrets:write');
}

/**
 * May this user see/manage a specific secret? Global writers (`secrets:write`)
 * can; owners always can their own (the personal-secret area); everyone else
 * cannot. Used by the detail/update/delete routes when the caller lacks the
 * global read/write permission.
 */
function mayManageSecret(perms: Set<string>, userId: string, secretUserId: string): boolean {
  if (isGlobalWriter(perms)) return true;
  return perms.has('secrets:self-write') && secretUserId === userId;
}

/**
 * Which secrets is this caller allowed to SEE? Global readers (`secrets:read`)
 * see everything. A user with only the personal permission sees their OWN
 * secrets plus any created by a global writer (the shared pool — e.g. admin-
 * provisioned SSH credentials) so they can use them for interactive sessions.
 */
function visibleTo(perms: Set<string>, userId: string, s: SecretMeta): boolean {
  if (perms.has('secrets:read')) return true;
  if (!perms.has('secrets:self-write')) return false;
  return s.userId === userId || isGlobalWriterUser(s.userId);
}

/**
 * Is the CREATING user of a secret a global writer? We cannot know another
 * user's live permissions from metadata alone, so approximate: secrets created
 * by users who hold `secrets:write` are "shared". The API resolves this at list
 * time (see below) — this helper is the per-row predicate given that map.
 */
function isGlobalWriterUser(userId: string): boolean {
  return globalWriterUserIds.has(userId);
}

/** Populated by GET /secrets before filtering — user ids holding secrets:write. */
const globalWriterUserIds = new Set<string>();

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

// GET /secrets - List secrets (metadata only).
// Global readers (`secrets:read`) see everything. A user with ONLY the personal
// permission sees their own secrets + those created by global writers (the shared
// pool) — enough to pick credentials for interactive sessions without exposing
// other users' private material.
router.get('/', requireAuth, async (req, res) => {
  const perms = permsOf(req);
  if (!perms.has('secrets:read') && !perms.has('secrets:self-write')) {
    res.status(403).json({ error: 'Missing required permission: secrets:read or secrets:self-write' });
    return;
  }

  try {
    const all = (await listSecrets()) as SecretMeta[];
    const userId = req.user?.sub ?? '';

    // Resolve userId -> username + whether the creator is a global writer.
    const userIds = [...new Set(all.map((s) => s.userId))];
    const userMap = new Map<string, string>();
    globalWriterUserIds.clear();
    if (userIds.length > 0) {
      const users = await db.query.users.findMany({
        where: (users, { inArray }) => inArray(users.id, userIds),
      });
      for (const u of users) {
        userMap.set(u.id, u.username);
        let p: string[] = [];
        try { p = JSON.parse(u.permissions); } catch { /* empty */ }
        if (Array.isArray(p) && p.includes('secrets:write')) globalWriterUserIds.add(u.id);
      }
    }

    const visible = all.filter((s) => visibleTo(perms, userId, s));

    const sanitized = visible.map((s) => ({
      id: s.id,
      label: s.label,
      type: s.type,
      providerId: s.providerId,
      createdAt: s.createdAt,
      expiresAt: s.expiresAt,
      interactiveLoginAllowed: !!s.interactiveLoginAllowed,
      fileAccessAllowed: !!s.fileAccessAllowed,
      username: userMap.get(s.userId) ?? 'Unknown',
    }));

    res.status(200).json(sanitized);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// POST /secrets - Create a new secret (typed, provider-routed).
// Requires `secrets:write` (global) OR `secrets:self-write` (personal area — the
// secret is always owned by the CALLER). The two usage flags opt the secret in
// for interactive SSH console / SFTP file sessions.
router.post('/', requireAuth, async (req, res) => {
  const perms = permsOf(req);
  if (!perms.has('secrets:write') && !perms.has('secrets:self-write')) {
    res.status(403).json({ error: 'Missing required permission: secrets:write or secrets:self-write' });
    return;
  }

  const { type, providerId, fields, label, expiresAt, interactiveLoginAllowed, fileAccessAllowed } = req.body ?? {};

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
      interactiveLoginAllowed: typeof interactiveLoginAllowed === 'boolean' ? interactiveLoginAllowed : false,
      fileAccessAllowed: typeof fileAccessAllowed === 'boolean' ? fileAccessAllowed : false,
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
  const id = String(req.params.id ?? '');
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
// Routed to the provider that created it; never served from cache. Global readers
// may fetch any; personal-area users only their own.
router.get('/:id', requireAuth, async (req, res) => {
  const perms = permsOf(req);
  if (!perms.has('secrets:read') && !perms.has('secrets:self-write')) {
    res.status(403).json({ error: 'Missing required permission: secrets:read or secrets:self-write' });
    return;
  }

  const id = String(req.params.id ?? '');
  try {
    if (!perms.has('secrets:read')) {
      const row = await db.query.secrets.findFirst({ where: eq(schema.secrets.id, id) });
      if (!row || !mayManageSecret(perms, req.user?.sub ?? '', row.userId)) {
        res.status(403).json({ error: 'Not allowed to view this secret' });
        return;
      }
    }
    const result = await getSecretFields(id);
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// PATCH /secrets/:id - Update a secret's fields IN PLACE (same id preserved, so
// assignments and plans referencing it keep working). Works for ALL secret types.
// `fields` is a full replacement of the type's field map; label/expiresAt/flags are
// optional. Global writers may update any secret; personal-area users only their own.
router.patch('/:id', requireAuth, async (req, res) => {
  const perms = permsOf(req);
  if (!perms.has('secrets:write') && !perms.has('secrets:self-write')) {
    res.status(403).json({ error: 'Missing required permission: secrets:write or secrets:self-write' });
    return;
  }

  const id = String(req.params.id ?? '');
  const { fields, label, expiresAt, interactiveLoginAllowed, fileAccessAllowed } = req.body ?? {};

  if (!fields || typeof fields !== 'object' || Array.isArray(fields)) {
    res.status(400).json({ error: 'fields object is required' });
    return;
  }

  try {
    if (!perms.has('secrets:write')) {
      const row = await db.query.secrets.findFirst({ where: eq(schema.secrets.id, id) });
      if (!row || !mayManageSecret(perms, req.user?.sub ?? '', row.userId)) {
        res.status(403).json({ error: 'Not allowed to update this secret' });
        return;
      }
    }
    const result = await updateSecret(id, {
      fields,
      ...(typeof label === 'string' ? { label } : {}),
      ...(typeof expiresAt === 'string' || expiresAt === null ? { expiresAt } : {}),
      ...(typeof interactiveLoginAllowed === 'boolean' ? { interactiveLoginAllowed } : {}),
      ...(typeof fileAccessAllowed === 'boolean' ? { fileAccessAllowed } : {}),
    });
    invalidateSecretCache(id); // edited values must not be served from cache
    res.status(200).json(result);
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

// DELETE /secrets/:id - Remove a secret. Global deleters (`secrets:delete`) may
// remove any; personal-area users may remove their own.
router.delete('/:id', requireAuth, async (req, res) => {
  const perms = permsOf(req);
  if (!perms.has('secrets:delete') && !perms.has('secrets:self-write')) {
    res.status(403).json({ error: 'Missing required permission: secrets:delete or secrets:self-write' });
    return;
  }

  const id = String(req.params.id ?? '');
  try {
    if (!perms.has('secrets:delete')) {
      const row = await db.query.secrets.findFirst({ where: eq(schema.secrets.id, id) });
      if (!row || !mayManageSecret(perms, req.user?.sub ?? '', row.userId)) {
        res.status(403).json({ error: 'Not allowed to delete this secret' });
        return;
      }
    }
    await deleteSecret(id);
    invalidateSecretCache(id); // deleted secret must not be served from cache
    res.status(204).send();
  } catch (err) {
    const e = err as { status?: number; message?: string };
    res.status(e.status ?? 500).json({ error: e.message ?? 'Internal server error' });
  }
});

export default router;
