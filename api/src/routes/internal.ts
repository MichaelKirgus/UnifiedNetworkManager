import { Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { db } from '../db';
import { and, eq, desc, sql } from 'drizzle-orm';
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

  // True when the shared x-plugin-api-key matches (plugins + secrets provider).
  const pluginAuthSync = (req: Request, res: Response): boolean => {
    const apiKey = req.headers['x-plugin-api-key'];
    if (apiKey !== process.env.PLUGIN_API_KEY) {
      res.status(403).json({ error: 'Forbidden: Invalid plugin API key' });
      return false;
    }
    return true;
  };

  // Middleware to authenticate plugins
  const pluginAuth = (req: Request, res: Response, next: (err?: any) => void) => {
    if (!pluginAuthSync(req, res)) return;
    next();
  };

  // --- CA trust bundle (mTLS enrollment, Stage 1) ---------------------------

  // GET /plugin/ca/bundle - the CA root + intermediate PEMs. Plugins never mount
  // the PKI volume; they fetch this at boot (and on renewal) to build their
  // https.Agent trust anchor for ACME calls and mTLS client connections.
  router.get('/plugin/ca/bundle', pluginAuth, async (_req: Request, res: Response) => {
    try {
      const pem = await require('../ca/stepCaAdmin').getCaBundlePem();
      res.status(200).json({ pem });
    } catch (error) {
      console.error('Error fetching CA bundle:', error);
      res.status(503).json({ error: 'CA trust bundle unavailable' });
    }
  });

  // POST /plugin/ca/register - mirror ONE of UNM's own CA-issued leaves into the
  // ca_certificates registry (Certificates page, "mtls" rows). Plugins report
  // their leaf via GET /metrics instead; this route exists for client-only
  // services like the MCP server that have no plugin-metrics poll. Body:
  // { subject, source?, serial, sans[], issuer, notBefore, notAfter }.
  // Auth: EITHER the shared x-plugin-api-key (plugins) OR a valid bearer token
  // (the MCP uses its UNM_API_TOKEN). Registering your OWN leaf is idempotent +
  // low-risk, so any authenticated caller may do it.
  const registerAuth = async (req: Request, res: Response, next: (err?: unknown) => void): Promise<void> => {
    // Plugin key path — only when the header is actually present (the MCP has
    // no plugin key and must fall through to bearer-token auth).
    if (req.headers['x-plugin-api-key'] !== undefined) {
      if (!pluginAuthSync(req, res)) return;
      next();
      return;
    }
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      res.status(403).json({ error: 'Forbidden: plugin key or bearer token required' });
      return;
    }
    const token = header.slice('Bearer '.length).trim();
    let ok = false;
    try {
      // Short-lived JWT first, then long-lived API tokens.
      require('../auth/jwt').verifyToken(token);
      ok = true;
    } catch {
      const payload = await require('../auth/apiTokens').resolveApiTokenPayload(token).catch(() => null);
      ok = !!payload;
    }
    if (!ok) {
      res.status(403).json({ error: 'Forbidden: invalid token' });
      return;
    }
    next();
  };

  router.post('/plugin/ca/register', registerAuth, async (req: Request, res: Response) => {
    try {
      const body = (req.body ?? {}) as Record<string, unknown>;
      const serial = typeof body.serial === 'string' ? body.serial.trim() : '';
      const subject = typeof body.subject === 'string' ? body.subject.trim() : '';
      const notBefore = typeof body.notBefore === 'string' ? body.notBefore : '';
      const notAfter = typeof body.notAfter === 'string' ? body.notAfter : '';
      if (!serial || !subject || !notBefore || !notAfter) {
        res.status(400).json({ error: '"serial", "subject", "notBefore" and "notAfter" are required' });
        return;
      }
      const source = body.source === 'api' ? 'api' : body.source === 'mcp' ? 'mcp' : 'plugin';
      await require('../ca/registry').registerLeaf({
        serial,
        subject,
        source,
        sans: Array.isArray(body.sans) ? (body.sans as unknown[]).filter((s): s is string => typeof s === 'string') : [],
        issuer: typeof body.issuer === 'string' ? body.issuer : '',
        notBefore,
        notAfter,
      });
      res.status(200).json({ ok: true, serial, subject });
    } catch (error) {
      console.error('Error registering CA leaf:', error);
      res.status(500).json({ error: 'Failed to register CA leaf' });
    }
  });

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
          interactiveLoginAllowed: s.interactiveLoginAllowed,
          fileAccessAllowed: s.fileAccessAllowed,
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
    const { type, providerId, label, encryptedValue, userId, expiresAt, interactiveLoginAllowed, fileAccessAllowed } = req.body ?? {};
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
        interactiveLoginAllowed: typeof interactiveLoginAllowed === 'boolean' ? interactiveLoginAllowed : false,
        fileAccessAllowed: typeof fileAccessAllowed === 'boolean' ? fileAccessAllowed : false,
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
        interactiveLoginAllowed: row.interactiveLoginAllowed,
        fileAccessAllowed: row.fileAccessAllowed,
        createdAt: row.createdAt,
      });
    } catch (error) {
      console.error('Error retrieving secret:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /plugin/secrets/:id - update a secret IN PLACE (same id). Used for key
  // rotation/regeneration and field edits so assignments + plans referencing the
  // id keep working. The provider re-encrypts and sends the new ciphertext; only
  // encryptedValue, label, expiresAt and the two usage flags are updatable —
  // type/providerId/userId are immutable. `expiresAt: null` clears the expiry
  // (absence leaves it); flag absence also leaves them untouched.
  router.patch('/plugin/secrets/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const body = req.body ?? {};
    const { encryptedValue, label, interactiveLoginAllowed, fileAccessAllowed } = body;
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
      if ('expiresAt' in body) {
        patch.expiresAt = typeof body.expiresAt === 'string' ? body.expiresAt : null;
      }
      if (typeof interactiveLoginAllowed === 'boolean') patch.interactiveLoginAllowed = interactiveLoginAllowed;
      if (typeof fileAccessAllowed === 'boolean') patch.fileAccessAllowed = fileAccessAllowed;
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

  // --- WebAuthn credential data (identity provider access) ------------------
  //
  // The API owns the webauthn_credentials table; the basic-auth plugin reads a
  // user's enrolled credentials to verify login assertions and bumps the
  // signature counter after success. Same shared-key convention as /plugin/users.

  // GET /plugin/webauthn/user/:userId - all passkeys of one user (login step 2).
  router.get('/plugin/webauthn/user/:userId', pluginAuth, async (req: Request, res: Response) => {
    const { userId } = req.params;
    try {
      const rows = await db.query.webauthnCredentials.findMany({
        where: eq(schema.webauthnCredentials.userId, userId),
      });
      res.json(
        rows.map((c) => ({
          id: c.id,
          credentialId: c.credentialId,
          publicKey: c.publicKey,
          counter: Number(c.counter ?? 0),
          transports: c.transports ? JSON.parse(c.transports) : null,
        }))
      );
    } catch (error) {
      console.error('Error listing webauthn credentials:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // PATCH /plugin/webauthn/credentials/:id - bump the signature counter after a
  // successful assertion (replay protection; SimpleWebAuthn requires the stored
  // counter to be <= the reported one).
  router.patch('/plugin/webauthn/credentials/:id', pluginAuth, async (req: Request, res: Response) => {
    const { id } = req.params;
    const { counter } = req.body ?? {};
    if (!Number.isInteger(counter) || counter < 0) {
      return res.status(400).json({ error: 'counter must be a non-negative integer' });
    }
    try {
      await db.update(schema.webauthnCredentials)
        .set({ counter })
        .where(eq(schema.webauthnCredentials.id, id));
      res.json({ id });
    } catch (error) {
      console.error('Error updating webauthn credential counter:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Plugin log ingestion -------------------------------------------------
  //
  // Plugins push structured log entries in batches (see the SDK's
  // createPluginLogger). The sender self-reports its pluginId (its effective
  // UUID); there is no per-plugin identity on this shared-key channel, so the
  // id is validated against the plugins table. Entries are capped to keep a
  // chatty or buggy plugin from flooding the database: max 100 entries per
  // request (excess dropped), message truncated at ~2KB, context JSON at ~8KB.

  const LOG_LEVELS = new Set(['debug', 'info', 'warn', 'error']);
  const MAX_LOG_ENTRIES_PER_REQUEST = 100;
  const MAX_MESSAGE_LENGTH = 2048;
  const MAX_CONTEXT_BYTES = 8192;

  // POST /plugin/logs - accept a batch of log entries from one plugin.
  router.post('/plugin/logs', pluginAuth, async (req: Request, res: Response) => {
    const { pluginId, entries } = req.body ?? {};
    if (!pluginId || typeof pluginId !== 'string') {
      return res.status(400).json({ error: 'pluginId is required' });
    }
    if (!Array.isArray(entries)) {
      return res.status(400).json({ error: 'entries must be an array' });
    }

    try {
      const plugin = await db.query.plugins.findFirst({
        where: (plugins, { eq }) => eq(plugins.id, pluginId),
      });
      if (!plugin) {
        return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
      }

      let accepted = 0;
      const batch = entries.slice(0, MAX_LOG_ENTRIES_PER_REQUEST);
      if (entries.length > MAX_LOG_ENTRIES_PER_REQUEST) {
        // eslint-disable-next-line no-console
        console.warn(
          `[logs] plugin ${pluginId} sent ${entries.length} entries in one request; ` +
            `dropping the last ${entries.length - MAX_LOG_ENTRIES_PER_REQUEST}`
        );
      }

      const now = new Date().toISOString();
      const rows = batch.map((e: Record<string, unknown>) => {
        let context: string | null = null;
        if (e.context !== undefined && e.context !== null) {
          try {
            const serialized = JSON.stringify(e.context);
            context = serialized.length > MAX_CONTEXT_BYTES ? serialized.slice(0, MAX_CONTEXT_BYTES) : serialized;
          } catch {
            context = null; // non-serializable context: drop it rather than fail the batch
          }
        }
        return {
          id: uuidv4(),
          pluginId,
          deviceId: typeof e.deviceId === 'string' && e.deviceId ? e.deviceId : null,
          level: LOG_LEVELS.has(String(e.level)) ? String(e.level) : 'info',
          message: String(e.message ?? '').slice(0, MAX_MESSAGE_LENGTH),
          context,
          timestamp: typeof e.timestamp === 'string' && e.timestamp ? e.timestamp : now,
        };
      });

      if (rows.length > 0) {
        await db.insert(schema.pluginLogs).values(rows);
        accepted = rows.length;
      }
      res.status(201).json({ accepted });
    } catch (error) {
      console.error('Error ingesting plugin logs:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /plugin/flows - accept a batch of pre-aggregated flow tuples from the
  // flow-collector plugin (sFlow/NetFlow feature). The collector receives UDP
  // samples, aggregates them per ~5s window into (srcIp,dstIp,proto) tuples and
  // pushes batches here. This handler does NO database work — it validates and
  // enqueues into the flows worker's bounded in-memory queue (see
  // workers/flows.ts), which batch-inserts into flow_micro off-band. That is
  // what keeps high-volume flow traffic from ever stalling the main API.
  const MAX_FLOW_SAMPLES_PER_REQUEST = 20_000;
  router.post('/plugin/flows', pluginAuth, async (req: Request, res: Response) => {
    const { enqueueFlowRows } = await import('../workers/flows');
    const body = req.body ?? {};
    const pluginId = typeof body.pluginId === 'string' ? body.pluginId : '';
    if (!pluginId) {
      return res.status(400).json({ error: 'pluginId is required' });
    }
    const samples = Array.isArray(body.samples) ? body.samples : null;
    if (!samples || samples.length === 0) {
      return res.status(400).json({ error: '"samples" array with at least one entry is required' });
    }

    try {
      const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
      if (!plugin) {
        return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
      }

      // Compact wire shape per sample: { s: srcIp, d: dstIp, p: proto,
      // sp: srcPort, dp: dstPort, b: bytes, k: packets, n: sampleCount,
      // r: sampleRate, a: agentIp (best-observation exporter), ac: distinct
      // exporter count } — small keys keep the payloads compact at high tuple
      // counts. Ports + agent fields are optional (older collectors don't
      // send them → 0/NULL).
      const rows = [];
      for (const e of samples.slice(0, MAX_FLOW_SAMPLES_PER_REQUEST)) {
        if (!e || typeof e !== 'object') continue;
        const srcIp = String(e.s ?? '').trim();
        const dstIp = String(e.d ?? '').trim();
        if (!srcIp || !dstIp) continue; // unparseable endpoint — drop the tuple
        rows.push({
          ts: typeof e.ts === 'string' && e.ts ? e.ts : new Date().toISOString(),
          collectorId: pluginId,
          srcIp,
          dstIp,
          proto: Number.isFinite(Number(e.p)) ? Math.max(0, Math.min(255, Number(e.p))) : 0,
          srcPort: Number.isFinite(Number(e.sp)) ? Math.max(0, Math.min(65_535, Number(e.sp))) : 0,
          dstPort: Number.isFinite(Number(e.dp)) ? Math.max(0, Math.min(65_535, Number(e.dp))) : 0,
          bytes: Number.isFinite(Number(e.b)) ? Math.max(0, Number(e.b)) : 0,
          packets: Number.isFinite(Number(e.k)) ? Math.max(0, Number(e.k)) : 0,
          sampleCount: Number.isFinite(Number(e.n)) ? Math.max(1, Number(e.n)) : 1,
          sampleRate: Number.isFinite(Number(e.r)) ? Math.max(1, Number(e.r)) : 1,
          agentIp: typeof e.a === 'string' && e.a.trim() !== '' ? String(e.a).trim() : null,
          agentCount: Number.isFinite(Number(e.ac)) ? Math.max(0, Math.min(65_535, Number(e.ac))) : 0,
        });
      }

      enqueueFlowRows(rows);
      res.status(202).json({ accepted: rows.length });
    } catch (error) {
      console.error('Error ingesting flow samples:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // POST /plugin/notifications - accept notification pushes from one plugin.
  // Body: { pluginId, notifications?: [ {severity?, title, message?, dedupeKey?, deviceId?, context?} ],
  //         resolve?: string[] } — `resolve` lists (plugin-prefixed) dedupe keys
  // whose conditions have cleared on the appliance; those rows auto-resolve.
  // Plugins use this to surface appliance-level events (e.g. TrueNAS alerts);
  // device-state mirroring happens API-side from telemetry instead.
  router.post('/plugin/notifications', pluginAuth, async (req: Request, res: Response) => {
    const { emitNotification, resolveNotificationsByDedupeKeys } = await import('../notifications');
    const body = req.body ?? {};
    const pluginId = typeof body.pluginId === 'string' ? body.pluginId : '';
    if (!pluginId) {
      return res.status(400).json({ error: 'pluginId is required' });
    }

    // Either a notifications batch OR resolve keys (or both) — plugins that
    // only clear conditions send an empty/absent list.
    let items: unknown[] = [];
    if (Array.isArray(body.notifications)) items = body.notifications.slice(0, 100);
    else if (body.notification && typeof body.notification === 'object') items = [body.notification];
    const hasResolve = Array.isArray(body.resolve) && body.resolve.length > 0;
    if (items.length === 0 && !hasResolve) {
      return res.status(400).json({ error: '"notifications" array or "resolve" keys are required' });
    }

    try {
      const plugin = await db.query.plugins.findFirst({ where: eq(schema.plugins.id, pluginId) });
      if (!plugin) {
        return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
      }

      let accepted = 0;
      for (const item of items) {
        const n = item as Record<string, unknown>;
        if (!n || typeof n.title !== 'string' || !n.title.trim()) continue;
        const id = await emitNotification({
          severity: (['info', 'warning', 'critical'].includes(String(n.severity)) ? String(n.severity) : 'info') as never,
          source: 'plugin',
          title: n.title,
          message: typeof n.message === 'string' ? n.message : '',
          dedupeKey: typeof n.dedupeKey === 'string' && n.dedupeKey ? `plugin:${pluginId}:${n.dedupeKey}` : null,
          pluginId,
          deviceId: typeof n.deviceId === 'string' && n.deviceId ? n.deviceId : null,
          context: n.context && typeof n.context === 'object' ? (n.context as Record<string, unknown>) : null,
        });
        if (id) accepted++;
      }

      // Conditions that cleared on the appliance → resolve their live rows.
      let resolved = 0;
      const resolveKeys: string[] = Array.isArray(body.resolve)
        ? (body.resolve as unknown[]).filter((k): k is string => typeof k === 'string' && k.length > 0).slice(0, 200)
        : [];
      if (resolveKeys.length > 0) {
        resolved = await resolveNotificationsByDedupeKeys(resolveKeys.map((k) => `plugin:${pluginId}:${k}`));
      }

      res.status(201).json({ accepted, resolved });
    } catch (error) {
      console.error('Error ingesting plugin notifications:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Inventory snapshot (capability 'inventorySync') -----------------------
  //
  // Serves UNM's host inventory to plugins that keep an EXTERNAL monitoring
  // subsystem in step with it (Zabbix first — see the zabbix plugin). The API
  // is a pure broker: it assembles the authoritative snapshot from the
  // user-maintained `documented_hosts` (+ their IPs) merged with recent live
  // observations from the `hosts` table, and hands it over verbatim. How the
  // snapshot maps onto the external system (host names, groups, templates,
  // status semantics) is entirely plugin-owned — this endpoint never
  // interprets monitoring-system concepts.
  //
  // GET /plugin/inventory/hosts[?documentedOnly=1&activeOnly=1&search=<text>]

  /** Strips MAC separators — the canonical comparison key (mirrors documentedHosts.ts). */
  function macKey(value: string): string {
    return value.toLowerCase().replace(/[^0-9a-f]/g, '');
  }

  /** Parses a stored JSON string array defensively (bad data → []). */
  function readJsonStringArray(raw: unknown): string[] {
    let arr: unknown = raw;
    if (typeof raw === 'string') {
      try { arr = JSON.parse(raw); } catch { return []; }
    }
    if (!Array.isArray(arr)) return [];
    const out: string[] = [];
    for (const v of arr) {
      if (typeof v !== 'string' && typeof v !== 'number') continue;
      const t = String(v).trim();
      if (t !== '' && !out.includes(t)) out.push(t);
    }
    return out;
  }

  router.get('/plugin/inventory/hosts', pluginAuth, async (req: Request, res: Response) => {
    try {
      const q = req.query ?? {};
      const documentedOnly = q['documentedOnly'] === '1' || q['documentedOnly'] === 'true';
      const activeOnly = q['activeOnly'] === '1' || q['activeOnly'] === 'true';
      const search = typeof q['search'] === 'string' ? q['search'].trim().toLowerCase() : '';

      // --- Load the two sources ---------------------------------------------
      const docRows = await db.query.documentedHosts.findMany();
      const docIpRows = await db.query.documentedHostIps.findMany();
      // The live table is swept after 24h by the telemetry worker, so every row
      // present counts as a recent observation.
      const liveRows = documentedOnly ? [] : await db.query.hosts.findMany();

      // --- Merge live observations per MAC ----------------------------------
      interface LiveObs {
        mac: string;            // compact hex key
        hostname: string | null;
        ips: Map<string, { mac: string | null }>; // ip -> first-seen mac (colon form)
        lastSeenAt: string;
      }
      const liveByMac = new Map<string, LiveObs>();
      for (const r of liveRows) {
        const key = macKey(r.mac);
        let obs = liveByMac.get(key);
        if (!obs) {
          obs = { mac: key, hostname: null, ips: new Map(), lastSeenAt: r.lastSeenAt };
          liveByMac.set(key, obs);
        }
        if (r.hostname && !obs.hostname) obs.hostname = r.hostname;
        if (r.ip !== '') {
          const existing = obs.ips.get(r.ip);
          // Prefer a non-empty MAC for the address row.
          if (!existing || (existing.mac === null && r.mac)) obs.ips.set(r.ip, { mac: r.mac });
        }
        if (r.lastSeenAt > obs.lastSeenAt) obs.lastSeenAt = r.lastSeenAt;
      }

      // --- Assemble documented hosts -----------------------------------------
      const ipsByHost = new Map<string, typeof docIpRows>();
      for (const ip of docIpRows) {
        const list = ipsByHost.get(ip.hostId) ?? [];
        list.push(ip);
        ipsByHost.set(ip.hostId, list);
      }

      // MACs referenced by documented addresses — live observations matching one
      // are MERGED into the documented host instead of becoming a new entry.
      const claimedMacs = new Set<string>();
      const hosts: Record<string, unknown>[] = [];

      for (const d of docRows) {
        if (activeOnly && !d.isActive) continue;
        const dnsNames = readJsonStringArray(d.dnsNames);
        const name = dnsNames[0] || d.friendlyName || `host-${d.id.slice(0, 8)}`;

        // Merge live observations whose MAC matches a documented address MAC.
        let lastSeenAt: string | null = null;
        const extraIps: { address: string; mac: string | null }[] = [];
        for (const ipRow of ipsByHost.get(d.id) ?? []) {
          if (!ipRow.mac) continue;
          const key = macKey(ipRow.mac);
          claimedMacs.add(key);
          const obs = liveByMac.get(key);
          if (!obs) continue;
          if (obs.lastSeenAt > (lastSeenAt ?? '')) lastSeenAt = obs.lastSeenAt;
          for (const [addr, info] of obs.ips) {
            // Skip the documented address itself — it is already in the list below.
            if (addr === ipRow.address) continue;
            extraIps.push({ address: addr, mac: info.mac });
          }
        }

        const addresses = [
          ...(ipsByHost.get(d.id) ?? []).map((ipRow) => ({
            address: ipRow.address,
            mac: ipRow.mac ?? null,
            networkLabel: ipRow.networkLabel ?? null,
            vlanId: ipRow.vlanId ?? null,
          })),
          ...extraIps.map((e) => ({ address: e.address, mac: e.mac, networkLabel: null, vlanId: null })),
        ];

        if (search && !hostMatchesSearch({ name, dnsNames, addresses }, search)) continue;

        hosts.push({
          id: d.id,
          name,
          dnsNames,
          friendlyName: d.friendlyName ?? null,
          description: d.description ?? null,
          tags: readJsonStringArray(d.tags),
          siteId: d.siteId ?? null,
          layerId: d.layerId ?? null,
          isActive: d.isActive,
          documented: true,
          addresses,
          lastSeenAt,
        });
      }

      // --- Live-only hosts (MAC not claimed by any documented address) --------
      if (!documentedOnly) {
        for (const obs of liveByMac.values()) {
          if (claimedMacs.has(obs.mac)) continue;
          const ips = [...obs.ips.entries()].map(([address, info]) => ({
            address,
            mac: info.mac ?? null,
            networkLabel: null,
            vlanId: null,
          }));
          if (ips.length === 0) continue; // MAC-only observation without any IP — nothing to monitor
          const name = obs.hostname || ips[0].address;
          if (search && !hostMatchesSearch({ name, dnsNames: [], addresses: ips }, search)) continue;
          hosts.push({
            id: `live:${obs.mac}`,
            name,
            dnsNames: [],
            friendlyName: null,
            description: null,
            tags: [],
            siteId: null,
            layerId: null,
            isActive: true,
            documented: false,
            addresses: ips,
            lastSeenAt: obs.lastSeenAt,
          });
        }
      }

      // Deterministic order for stable diffs on the plugin side.
      hosts.sort((a, b) => String(a['name']).localeCompare(String(b['name'])));

      res.status(200).json({
        snapshot: {
          collectedAt: new Date().toISOString(),
          hosts,
        },
      });
    } catch (error) {
      console.error('Error building inventory snapshot:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  // --- Generic plugin state store -------------------------------------------
  //
  // A small, generic key/value store so plugins can persist opaque JSON blobs
  // ACROSS polls and container restarts without owning a database connection or
  // a local volume. The natural key is (pluginId, namespace, key): `namespace`
  // groups one feature's state ("file-integrity"), `key` is the plugin-chosen
  // stable identity within it ("<host>|/etc/passwd"). `value` is an opaque JSON
  // blob owned entirely by the plugin — the API never interprets it. This is the
  // foundation for any future "remember this between polls" need (baselines,
  // counters, TOFU fingerprints, …). All routes are gated by x-plugin-api-key and
  // validate the self-reported pluginId against the plugins table (same as logs).

  const MAX_STATE_VALUE_BYTES = 65_536; // one blob — baselines/counters are tiny
  const MAX_STATE_ENTRIES_PER_REQUEST = 200;

  /** Validate a self-reported plugin id, returning the row or null. */
  async function knownPlugin(pluginId: string) {
    if (!pluginId || typeof pluginId !== 'string') return null;
    return db.query.plugins.findFirst({ where: (plugins, { eq }) => eq(plugins.id, pluginId) });
  }

  /** Parse a stored JSON blob back to an object for the response. */
  function parseStateValue(raw: string): unknown {
    try {
      return JSON.parse(raw);
    } catch {
      return raw; // non-JSON (shouldn't happen — we only store serialized JSON)
    }
  }

  /** GET /plugin/state/:pluginId?namespace=&deviceId= - list a plugin's state rows. */
  router.get('/plugin/state/:pluginId', pluginAuth, async (req: Request, res: Response) => {
    const { pluginId } = req.params;
    try {
      if (!(await knownPlugin(pluginId))) return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
      const namespace = typeof req.query.namespace === 'string' ? (req.query.namespace as string) : null;
      const deviceId = typeof req.query.deviceId === 'string' ? (req.query.deviceId as string) : null;

      let rows = await db.query.pluginState.findMany({ where: eq(schema.pluginState.pluginId, pluginId) });
      if (namespace) rows = rows.filter((r) => r.namespace === namespace);
      if (deviceId) rows = rows.filter((r) => r.deviceId === deviceId);

      res.status(200).json({
        rows: rows.map((r) => ({
          namespace: r.namespace,
          key: r.key,
          value: parseStateValue(r.value),
          deviceId: r.deviceId,
          updatedAt: r.updatedAt,
        })),
      });
    } catch (error) {
      console.error('Error listing plugin state:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /** PUT /plugin/state - upsert a batch of state rows for one plugin.
   *  Body: { pluginId, entries: [{ namespace, key, value, deviceId? }] }. */
  router.put('/plugin/state', pluginAuth, async (req: Request, res: Response) => {
    const { pluginId, entries } = req.body ?? {};
    if (!(await knownPlugin(pluginId))) return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
    if (!Array.isArray(entries)) return res.status(400).json({ error: 'entries must be an array' });

    try {
      const now = new Date().toISOString();
      let upserted = 0;
      for (const e of entries.slice(0, MAX_STATE_ENTRIES_PER_REQUEST)) {
        if (!e || typeof e !== 'object') continue;
        const namespace = typeof e.namespace === 'string' ? (e.namespace as string).trim() : '';
        const key = typeof e.key === 'string' ? (e.key as string).trim() : '';
        if (!namespace || !key) continue; // both are part of the PK
        let value: string;
        try {
          value = JSON.stringify(e.value ?? {});
        } catch {
          continue; // non-serializable blob — skip rather than fail the batch
        }
        if (value.length > MAX_STATE_VALUE_BYTES) continue; // oversized blob — skip
        const deviceId = typeof e.deviceId === 'string' && e.deviceId ? (e.deviceId as string) : null;

        await db.insert(schema.pluginState).values({ pluginId, namespace, key, value, deviceId, updatedAt: now }).onConflictDoUpdate({
          target: [schema.pluginState.pluginId, schema.pluginState.namespace, schema.pluginState.key],
          set: { value: sql`excluded."value"`, deviceId: sql`excluded."deviceId"`, updatedAt: sql`excluded."updatedAt"` },
        });
        upserted++;
      }
      res.status(200).json({ upserted });
    } catch (error) {
      console.error('Error upserting plugin state:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  /** DELETE /plugin/state/:pluginId?namespace=&deviceId= - delete a plugin's rows.
   *  With `keys` (array) in the body, deletes exactly those keys within the
   *  namespace; otherwise deletes every row matching namespace/deviceId filters. */
  router.delete('/plugin/state/:pluginId', pluginAuth, async (req: Request, res: Response) => {
    const { pluginId } = req.params;
    try {
      if (!(await knownPlugin(pluginId))) return res.status(400).json({ error: `Unknown plugin id: ${pluginId}` });
      const namespace = typeof req.query.namespace === 'string' ? (req.query.namespace as string) : null;
      const deviceId = typeof req.query.deviceId === 'string' ? (req.query.deviceId as string) : null;
      const keys = Array.isArray((req.body ?? {}).keys) ? ((req.body ?? {}).keys as unknown[]).filter((k): k is string => typeof k === 'string') : null;

      let rows = await db.query.pluginState.findMany({ where: eq(schema.pluginState.pluginId, pluginId) });
      if (namespace) rows = rows.filter((r) => r.namespace === namespace);
      if (deviceId) rows = rows.filter((r) => r.deviceId === deviceId);
      if (keys) {
        const keySet = new Set(keys);
        rows = rows.filter((r) => keySet.has(r.key));
      }

      let deleted = 0;
      for (const r of rows) {
        await db.delete(schema.pluginState).where(and(
          eq(schema.pluginState.pluginId, pluginId),
          eq(schema.pluginState.namespace, r.namespace),
          eq(schema.pluginState.key, r.key),
        ));
        deleted++;
      }
      res.status(200).json({ deleted });
    } catch (error) {
      console.error('Error deleting plugin state:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
  });

  return router;
}

/** Case-insensitive substring match on a host's name, DNS names and addresses. */
function hostMatchesSearch(host: { name: string; dnsNames: string[]; addresses: Array<{ address: string }> }, search: string): boolean {
  if (host.name.toLowerCase().includes(search)) return true;
  for (const n of host.dnsNames) if (n.toLowerCase().includes(search)) return true;
  for (const a of host.addresses) if (a.address.toLowerCase().includes(search)) return true;
  return false;
}