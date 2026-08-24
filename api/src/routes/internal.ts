import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { db } from '../db';
import { eq, desc } from 'drizzle-orm';
import { v4 as uuidv4 } from 'uuid';
import * as schema from '../db/schema';

/**
 * Internal, plugin-facing routes.
 *
 * These are NOT part of the public OpenAPI surface. They let identity provider
 * plugins (and other plugins) read/write platform data through the API instead
 * of each plugin owning its own database connection. All routes are gated by
 * the shared `x-plugin-api-key` header (see `pluginAuth`).
 *
 * IMPORTANT: every path is namespaced under /plugin/* — user data included.
 * This router mounts BEFORE the OpenAPI validator, so any path that overlaps a
 * public route (e.g. POST /users) would shadow it and 403 webapp requests with
 * "Invalid plugin API key". The /plugin prefix keeps internal paths disjoint
 * from the public surface (same convention as /plugin/secrets).
 *
 * The user-data endpoints are the "flexible" data access layer for identity
 * providers: the basic-auth plugin uses them to look up users for credential
 * verification, and future plugins (or admin tooling) can create/update users
 * the same way.
 */
export function internalRouter() {
  const router = require('express').Router();

  // Middleware to authenticate plugins
  const pluginAuth = (req: Request, res: Response, next: (err?: any) => void) => {
    const apiKey = req.headers['x-plugin-api-key'];
    if (apiKey !== process.env.PLUGIN_API_KEY) {
      return res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
    }
    next();
  };

  // --- User data under /plugin/users (identity provider access) ------------

  // Serialize a user row for plugin consumption. `roles`/`permissions` are
  // returned as stored (JSON strings) to match the column shape; the plugin
  // parses them.
  function serializeUser(row: typeof schema.users.$inferSelect) {
    return {
      id: row.id,
      username: row.username,
      passwordHash: row.passwordHash,
      totpSecret: row.totpSecret,
      roles: row.roles,
      permissions: row.permissions,
      createdAt: row.createdAt,
    };
  }

  // GET /plugin/users/username/:username - look up a user by username (login step 1).
  router.get('/plugin/users/username/:username', pluginAuth, async (req: Request, res: Response) => {
    const { username } = req.params;
    try {
      const row = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.username, username),
      });
      if (!row) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(serializeUser(row));
    } catch (error) {
      console.error('Error looking up user by username:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /plugin/users/:id - look up a user by id (login step 2 / TOTP verify).
  router.get('/plugin/users/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      const row = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.id, id),
      });
      if (!row) {
        return res.status(404).json({ error: 'User not found' });
      }
      res.json(serializeUser(row));
    } catch (error) {
      console.error('Error looking up user by id:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /plugin/users - create a user. `password` is hashed server-side; the
  // plugin never stores or transmits a raw password hash it computed itself.
  router.post('/plugin/users', pluginAuth, async (req: Request, res: Response) => {
    const { username, password, totpSecret, roles, permissions } = req.body ?? {};
    if (!username || !password) {
      return res.status(400).json({ error: 'username and password are required' });
    }
    try {
      const existing = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.username, username),
      });
      if (existing) {
        return res.status(409).json({ error: 'Username already exists' });
      }

      const passwordHash = bcrypt.hashSync(String(password), 10);

      const id = uuidv4();
      await db.insert(schema.users).values({
        id,
        username: String(username),
        passwordHash,
        totpSecret: totpSecret ?? null,
        roles: JSON.stringify(Array.isArray(roles) ? roles : []),
        permissions: JSON.stringify(Array.isArray(permissions) ? permissions : []),
        createdAt: new Date().toISOString(),
      });

      const row = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.id, id),
      });
      res.status(201).json(serializeUser(row!));
    } catch (error) {
      console.error('Error creating user:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /plugin/users/:id - update a user (password, totpSecret, roles, permissions).
  router.patch('/plugin/users/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { password, totpSecret, roles, permissions } = req.body ?? {};
    try {
      const existing = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.id, id),
      });
      if (!existing) {
        return res.status(404).json({ error: 'User not found' });
      }

      const updates: Record<string, unknown> = {};
      if (password !== undefined) {
        updates.passwordHash = bcrypt.hashSync(String(password), 10);
      }
      if (totpSecret !== undefined) {
        updates.totpSecret = totpSecret;
      }
      if (roles !== undefined) {
        updates.roles = JSON.stringify(Array.isArray(roles) ? roles : []);
      }
      if (permissions !== undefined) {
        updates.permissions = JSON.stringify(Array.isArray(permissions) ? permissions : []);
      }

      if (Object.keys(updates).length > 0) {
        await db.update(schema.users).set(updates).where(eq(schema.users.id, id));
      }

      const row = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.id, id),
      });
      res.json(serializeUser(row!));
    } catch (error) {
      console.error('Error updating user:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /plugin/users/:id - remove a user.
  router.delete('/plugin/users/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      const existing = await db.query.users.findFirst({
        where: (users, { eq }) => eq(users.id, id),
      });
      if (!existing) {
        return res.status(404).json({ error: 'User not found' });
      }
      await db.delete(schema.users).where(eq(schema.users.id, id));
      res.status(204).send();
    } catch (error) {
      console.error('Error deleting user:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Secrets data (secrets provider access) ------------------------------
  //
  // The API owns the `secrets` table. The secrets provider plugin stores
  // ciphertext here and reads it back; the plugin does the encrypt/decrypt
  // (it owns the MASTER_KEY). These endpoints are namespaced under
  // `/plugin/secrets` so they do not collide with the public `/secrets` routes.

  // GET /plugin/secrets - list secret metadata (no ciphertext).
  router.get('/plugin/secrets', pluginAuth, async (_req: Request, res: Response) => {
    try {
      const rows = await db.query.secrets.findMany({
        orderBy: (secrets, { desc }) => [desc(secrets.createdAt)],
      });
      res.json(
        rows.map((s) => ({
          id: s.id,
          label: s.label,
          type: s.type,
          providerId: s.providerId,
          userId: s.userId,
          expiresAt: s.expiresAt,
          createdAt: s.createdAt,
        }))
      );
    } catch (error) {
      console.error('Error listing secrets:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /plugin/secrets - store a secret (ciphertext).
  router.post('/plugin/secrets', pluginAuth, async (req: Request, res: Response) => {
    const { type, providerId, label, encryptedValue, userId, expiresAt } = req.body ?? {};
    if (!encryptedValue || !userId) {
      return res.status(400).json({ error: 'encryptedValue and userId are required' });
    }
    try {
      const id = uuidv4();
      const createdAt = new Date().toISOString();
      await db.insert(schema.secrets).values({
        id,
        type: type ?? 'apiKey',
        providerId: providerId ?? null,
        label: label ?? null,
        encryptedValue: String(encryptedValue),
        userId: String(userId),
        expiresAt: expiresAt ?? null,
        createdAt,
      });
      res.status(201).json({ id, createdAt });
    } catch (error) {
      console.error('Error storing secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // GET /plugin/secrets/:id - fetch a secret (ciphertext).
  router.get('/plugin/secrets/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      const row = await db.query.secrets.findFirst({
        where: (secrets, { eq }) => eq(secrets.id, id),
      });
      if (!row) {
        return res.status(404).json({ error: 'Secret not found' });
      }
      res.json({
        id: row.id,
        label: row.label,
        type: row.type,
        providerId: row.providerId,
        encryptedValue: row.encryptedValue,
        userId: row.userId,
        expiresAt: row.expiresAt,
        createdAt: row.createdAt,
      });
    } catch (error) {
      console.error('Error retrieving secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /plugin/secrets/:id - update a secret IN PLACE (same id). Used for key
  // rotation/regeneration so assignments + plans referencing the id keep working.
  // The provider re-encrypts and sends the new ciphertext; only encryptedValue
  // (and optionally label) are updatable — type/providerId/userId are immutable.
  router.patch('/plugin/secrets/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { encryptedValue, label } = req.body ?? {};
    if (!encryptedValue || typeof encryptedValue !== 'string') {
      return res.status(400).json({ error: 'encryptedValue (string) is required' });
    }
    try {
      const existing = await db.query.secrets.findFirst({
        where: (secrets, { eq }) => eq(secrets.id, id),
      });
      if (!existing) {
        return res.status(404).json({ error: 'Secret not found' });
      }

      const patch: Record<string, unknown> = { encryptedValue };
      if (typeof label === 'string') patch.label = label;
      await db.update(schema.secrets).set(patch).where(eq(schema.secrets.id, id));
      res.status(200).json({ id });
    } catch (error) {
      console.error('Error updating secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // DELETE /plugin/secrets/:id - remove a secret.
  router.delete('/plugin/secrets/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    try {
      await db.delete(schema.secrets).where(eq(schema.secrets.id, id));
      res.status(204).send();
    } catch (error) {
      console.error('Error deleting secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}